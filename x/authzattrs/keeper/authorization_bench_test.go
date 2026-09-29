package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
)

// These are keeper MICROBENCHMARKS, not end-to-end transaction latency.
// Setup, account signature verification, Ante gas, and network I/O are excluded.
var benchmarkV1Decision types.Decision
var benchmarkV2Weight uint64
var benchmarkV2Digest [32]byte

func BenchmarkV1DirectMsgSendAuthorizationLookup(b *testing.B) {
	f := initFixture(b)
	require.NoError(b, f.keeper.SetAuthorization(f.ctx, record()))
	message := msg(100)
	b.ReportAllocs()
	b.ResetTimer()
	var decision types.Decision
	for i := 0; i < b.N; i++ {
		var err error
		decision, _, err = f.keeper.AuthorizeMsgSend(f.ctx, 15, message)
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkV1Decision = decision
}

func BenchmarkV2CertificateVerification(b *testing.B) {
	f := initFixture(b)
	certificate, issuers := v2GoldenCertificate(b)
	require.NoError(b, f.keeper.SetIssuerSet(f.ctx, types.IssuerSet{
		IssuerSetId: 9, Active: true, PolicyId: certificate.SignDoc.PolicyId,
		MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 5,
	}))
	for _, issuer := range issuers {
		require.NoError(b, f.keeper.SetIssuer(f.ctx, issuer))
	}
	require.NoError(b, f.keeper.SetCurrentIssuerSet(f.ctx, certificate.SignDoc.PolicyId, types.MsgSendTypeURL, 9))
	b.ReportAllocs()
	b.ResetTimer()
	var weight uint64
	var digest [32]byte
	for i := 0; i < b.N; i++ {
		var err error
		weight, digest, err = f.keeper.VerifyCertificateV2(f.ctx, 105, "alpha-1", certificate)
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkV2Weight, benchmarkV2Digest = weight, digest
}
