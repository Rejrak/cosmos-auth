# syntax=docker/dockerfile:1
FROM golang:1.25-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# costruisce il tuo binary (adatta se il tuo Makefile usa un target diverso)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/alphad ./cmd/alphad

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates bash jq && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/alphad /usr/local/bin/alphad

# entrypoint
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV ALPHA_HOME=/root/.alpha \
    CHAIN_ID=alpha-1 \
    MONIKER=val \
    KEYRING_BACKEND=test \
    VALIDATOR_KEY=alice \
    VALIDATOR_BOND=100000000stake \
    GENESIS_ACCOUNTS="alice:5000000token,100000000stake bob:50000000token,100000stake" \
    MINIMUM_GAS_PRICES="0stake"

# porte tipiche (adatta se il tuo app usa altre)
EXPOSE 26656 26657 1317 9090 9091

VOLUME ["/root/.alpha"]
ENTRYPOINT ["/entrypoint.sh"]
CMD ["start"]
