package interceptor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	svrTypes "alpha/x/alpha/types"

	gogoproto "github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	googleproto "google.golang.org/protobuf/proto"
)

var (
	ErrNotStarted   = errors.New("client not started or already closed")
	ErrClosed       = errors.New("client closed")
	ErrBackpressure = errors.New("send queue is full")
	ErrTimeout      = errors.New("request timeout")
)

type Client struct {
	addr         string
	dialTimeout  time.Duration
	writeTimeout time.Duration

	mu        sync.Mutex
	conn      net.Conn
	once      sync.Once
	close     chan struct{}
	connReady chan struct{}

	outq chan []byte

	// decoder -> dispatcher -> waiters
	waitersMu sync.Mutex
	waiters   map[string]chan *svrTypes.ResponseMessage // key: sender_id

	logMu sync.RWMutex
	logf  func(format string, args ...any)
}

func (c *Client) SetLogger(f func(format string, args ...any)) {
	c.logMu.Lock()
	c.logf = f
	c.logMu.Unlock()
}

func (c *Client) dbg(format string, args ...any) {
	c.logMu.RLock()
	lf := c.logf
	c.logMu.RUnlock()
	if lf != nil {
		lf(format, args...)
	}
}

func NewClient(addr string) *Client {
	return &Client{
		addr:         addr,
		dialTimeout:  500 * time.Millisecond,
		writeTimeout: 300 * time.Millisecond,
		close:        make(chan struct{}),
		connReady:    make(chan struct{}),
		outq:         make(chan []byte, 256),
		waiters:      make(map[string]chan *svrTypes.ResponseMessage),
	}
}

func (c *Client) Start() {
	c.once.Do(func() {
		go c.run()
		go c.writePump()
	})
}

func (c *Client) run() {
	backoff := 200 * time.Millisecond
	maxBackoff := 2 * time.Second

	for {
		if err := c.connect(); err != nil {
			select {
			case <-time.After(backoff):
				if backoff < maxBackoff {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}
				continue
			case <-c.close:
				return
			}
		}
		backoff = 200 * time.Millisecond

		errCh := make(chan error, 1)
		go c.readPump(errCh)

		select {
		case <-c.close:
			c.closeConn()
			return
		case <-errCh:
			c.closeConn()
		}
	}
}

func (c *Client) connect() error {
	d := net.Dialer{Timeout: c.dialTimeout}
	conn, err := d.Dial("tcp", c.addr)
	if err != nil {
		c.dbg("[client] connect error: %v", err)
		return err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	c.dbg("[client] connected to %s", c.addr)
	return nil
}

func (c *Client) closeConn() {
	c.mu.Lock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	c.mu.Unlock()
	c.dbg("[client] connection closed")

	// risveglia eventuali waiter rimasti appesi
	c.waitersMu.Lock()
	for sender, ch := range c.waiters {
		close(ch)
		delete(c.waiters, sender)
	}
	c.waitersMu.Unlock()

	// reset readiness (se la usi altrove)
	c.connReady = make(chan struct{})
}

// --------------------- W ---------------------

func (c *Client) SendBytes(payload []byte) error {
	return c.enqueue(frame(payload))
}

func (c *Client) SendProto(m any) error {
	var (
		b   []byte
		err error
	)
	switch v := m.(type) {
	case googleproto.Message:
		b, err = googleproto.Marshal(v)
	case gogoproto.Message:
		b, err = gogoproto.Marshal(v)
	default:
		return fmt.Errorf("unsupported proto type %T", m)
	}
	if err != nil {
		return err
	}
	return c.enqueue(frame(b))
}

func (c *Client) enqueue(b []byte) error {
	select {
	case <-c.close:
		return ErrClosed
	default:
	}
	select {
	case c.outq <- b:
		return nil
	default:
		return ErrBackpressure
	}
}

func (c *Client) writePump() {
	for {
		select {
		case <-c.close:
			return
		case msg := <-c.outq:
			if err := c.writeWithDeadline(msg); err != nil {
				// best-effort light retry
				select {
				case <-time.After(50 * time.Millisecond):
				case <-c.close:
					return
				}
				select {
				case c.outq <- msg:
				default:
				}
			}
		}
	}
}

func (c *Client) writeWithDeadline(b []byte) error {
	c.mu.Lock()
	conn := c.conn
	timeout := c.writeTimeout
	c.mu.Unlock()

	if conn == nil {
		c.dbg("[client] write error: no connection")
		return errors.New("no connection")
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	n, err := writeAll(conn, b)
	if err != nil {
		c.dbg("[client] write error after %d bytes: %v", n, err)
		return err
	}
	c.dbg("[client] wrote frame bytes=%d", n)
	return nil
}

func writeAll(w io.Writer, b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n, err := w.Write(b)
		total += n
		if err != nil {
			return total, err
		}
		b = b[n:]
	}
	return total, nil
}

func frame(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[:4], uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

// --------------------- R/DECODE + DISPATCH ---------------------

func (c *Client) readPump(errCh chan<- error) {
	for {
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn == nil {
			errCh <- errors.New("no conn")
			return
		}

		hdr := make([]byte, 4)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			c.dbg("[client] read header error: %v", err)
			errCh <- err
			return
		}
		n := binary.BigEndian.Uint32(hdr)
		c.dbg("[client] read header len=%d", n)
		if n == 0 {
			continue
		}

		payload := make([]byte, n)
		if _, err := io.ReadFull(conn, payload); err != nil {
			c.dbg("[client] read payload error: %v", err)
			errCh <- err
			return
		}

		var pkt svrTypes.CosmosPacket
		if err := gogoproto.Unmarshal(payload, &pkt); err != nil {
			c.dbg("[client] unmarshal error: %v", err)
			errCh <- fmt.Errorf("unmarshal: %w", err)
			return
		}

		if resp := pkt.GetResponseMessage(); resp != nil {
			c.dbg("[client] <- Response request_id=%s ok=%v msg=%q",
				pkt.GetRequestId(), resp.Success, resp.Message)

			requestID := pkt.GetRequestId()
			c.waitersMu.Lock()
			ch, ok := c.waiters[requestID]
			c.waitersMu.Unlock()
			if ok {
				select {
				case ch <- resp:
				default:
					c.dbg("[client] waiter channel full for %s (dropping)", requestID)
					c.waitersMu.Lock()
					close(ch)
					delete(c.waiters, requestID)
					c.waitersMu.Unlock()
				}
			} else {
				c.dbg("[client] no waiter for request_id=%s (late or unexpected resp)", requestID)
			}
		} else if pkt.GetAuthMessage() != nil {
			c.dbg("[client] <- AuthMessage (unexpected on client side)")
		} else {
			c.dbg("[client] <- Unknown packet oneof")
		}
	}
}

// --------------------- API SYNC: RequestAuth ---------------------

func (c *Client) RequestAuth(sender, operation string, timeout time.Duration) (bool, string, error) {
	ch := make(chan *svrTypes.ResponseMessage, 1)
	var reqID string = uuid.NewString()
	c.waitersMu.Lock()
	if prev, exists := c.waiters[reqID]; exists {
		close(prev)
	}
	c.waiters[reqID] = ch
	c.waitersMu.Unlock()
	start := time.Now()

	defer func() {
		c.waitersMu.Lock()
		if cur, exists := c.waiters[reqID]; exists && cur == ch {
			delete(c.waiters, reqID)
			close(ch)
		}
		c.waitersMu.Unlock()
	}()

	req := &svrTypes.CosmosPacket{
		RequestId: reqID,
		Msg: &svrTypes.CosmosPacket_AuthMessage{
			AuthMessage: &svrTypes.AuthMessage{
				Address:   sender,
				Operation: operation,
			},
		},
	}
	c.dbg("[client] -> Auth sender=%s op=%s request_id=%s", sender, operation, req.RequestId)
	if err := c.SendProto(req); err != nil {
		c.dbg("[client] send error: %v", err)
		return false, "", err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case resp, ok := <-ch:
		rtt := time.Since(start)
		if !ok || resp == nil {
			c.dbg("[client] waiter closed (sender=%s) after %s", sender, rtt)
			return false, "", errors.New("connection closed or waiter canceled")
		}

		c.dbg("[client] RTT=%s sender=%s ok=%v msg=%q", rtt, sender, resp.Success, resp.Message)
		return resp.Success, resp.Message, nil

	case <-timer.C:
		c.dbg("[client] !! TIMEOUT sender=%s op=%s after %s", sender, operation, time.Since(start))
		return false, "", ErrTimeout

	case <-c.close:
		c.dbg("[client] closed while waiting sender=%s", sender)
		return false, "", ErrClosed
	}
}
