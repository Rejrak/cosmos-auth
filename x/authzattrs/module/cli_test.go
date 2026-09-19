package authzattrs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
)

func cliBatch() *types.AuthorizationBatch {
	return &types.AuthorizationBatch{
		SignDoc: &types.AuthorizationBatchSignDoc{
			Domain: "transport-only", ChainId: "alpha-test", BatchId: 7,
			PolicyId: "unsigned-by-cli", PolicyHash: []byte{0, 1, 2, 3}, IssuerSetId: 9,
			Records: []*types.AuthorizationRecord{
				{AuthorizationId: "record-b", Subject: "subject-b", MsgTypeUrl: "type-b"},
				{AuthorizationId: "record-a", Subject: "subject-a", MsgTypeUrl: "type-a"},
			},
		},
		Signatures: []*types.BatchSignature{
			{IssuerId: "issuer-b", Signature: []byte{9, 8, 7}},
			{IssuerId: "issuer-a", Signature: []byte{6, 5, 4}},
		},
	}
}

func writeBatchFile(t *testing.T, batch *types.AuthorizationBatch) string {
	t.Helper()
	bz, err := batch.Marshal()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "batch.pb")
	require.NoError(t, os.WriteFile(path, bz, 0o600))
	return path
}

func TestBuildBatchUpsertMessagePreservesSignedBatch(t *testing.T) {
	batch := cliBatch()
	original := proto.Clone(batch)
	from := sdk.AccAddress(bytes.Repeat([]byte{0x7a}, 20))
	msg, err := buildBatchUpsertMessage(client.Context{}.WithFromAddress(from), writeBatchFile(t, batch))
	require.NoError(t, err)
	require.Equal(t, from.String(), msg.Submitter)
	require.Equal(t, original, msg.Batch)
	require.Equal(t, []byte{0, 1, 2, 3}, msg.Batch.SignDoc.PolicyHash)
	require.Equal(t, []string{"record-b", "record-a"}, []string{
		msg.Batch.SignDoc.Records[0].AuthorizationId,
		msg.Batch.SignDoc.Records[1].AuthorizationId,
	})
	require.Equal(t, []byte{9, 8, 7}, msg.Batch.Signatures[0].Signature)
	require.Equal(t, []byte{6, 5, 4}, msg.Batch.Signatures[1].Signature)
	require.Equal(t, original, batch)
}

func TestBuildBatchUpsertMessageRejectsInvalidInput(t *testing.T) {
	from := client.Context{}.WithFromAddress(sdk.AccAddress(bytes.Repeat([]byte{1}, 20)))
	write := func(t *testing.T, data []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "batch.pb")
		require.NoError(t, os.WriteFile(path, data, 0o600))
		return path
	}
	marshal := func(t *testing.T, batch *types.AuthorizationBatch) []byte {
		t.Helper()
		bz, err := batch.Marshal()
		require.NoError(t, err)
		return bz
	}

	tests := []struct {
		name string
		ctx  client.Context
		path func(*testing.T) string
		want string
	}{
		{"missing from", client.Context{}, func(t *testing.T) string { return writeBatchFile(t, cliBatch()) }, "--from identity is required"},
		{"unreadable", from, func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing.pb") }, "read authorization batch"},
		{"empty", from, func(t *testing.T) string { return write(t, nil) }, "file is empty"},
		{"malformed", from, func(t *testing.T) string { return write(t, []byte{0xff}) }, "decode authorization batch protobuf"},
		{"nil sign doc", from, func(t *testing.T) string {
			return write(t, marshal(t, &types.AuthorizationBatch{Signatures: []*types.BatchSignature{{IssuerId: "issuer", Signature: []byte{1}}}}))
		}, "sign_doc is required"},
		{"empty signatures", from, func(t *testing.T) string {
			return write(t, marshal(t, &types.AuthorizationBatch{SignDoc: &types.AuthorizationBatchSignDoc{Domain: "transport"}}))
		}, "signatures are required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg, err := buildBatchUpsertMessage(test.ctx, test.path(t))
			require.Nil(t, msg)
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestSubmitAuthzBatchCommandRegistrationAndArgs(t *testing.T) {
	root := (AppModule{}).GetTxCmd()
	cmd, _, err := root.Find([]string{"submit-authz-batch"})
	require.NoError(t, err)
	require.Equal(t, "submit-authz-batch", cmd.Name())
	require.Error(t, cmd.Args(cmd, nil))
	require.NoError(t, cmd.Args(cmd, []string{"batch.pb"}))
	require.Error(t, cmd.Args(cmd, []string{"one.pb", "two.pb"}))
}
