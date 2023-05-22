package multisig_test

import (
	"testing"

	"github.com/herumi/bls-go-binary/bls"
	"github.com/kalyan3104/k-core/hashing/blake2b"
	crypto "github.com/kalyan3104/k-crypto-core-go"
	"github.com/kalyan3104/k-crypto-core-go/signing"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl/multisig"
	"github.com/stretchr/testify/require"
)

const blsHashSize = 16

func Benchmark_PreparePublicKeys63(b *testing.B) {
	benchmarkPreparePublicKeys(63, b)
}

func Benchmark_PreparePublicKeys400(b *testing.B) {
	benchmarkPreparePublicKeys(400, b)
}

func benchmarkPreparePublicKeys(nPubKeys int, b *testing.B) {
	hasher, err := blake2b.NewBlake2bWithSize(blsHashSize)
	require.Nil(b, err)

	pubKeys := createBLSPubKeys(nPubKeys)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prepPubKeys, err := multisig.PreparePublicKeys(pubKeys, hasher, pubKeys[0].Suite())
		require.Nil(b, err)
		require.NotNil(b, prepPubKeys)
	}
}

func Benchmark_ConcatPubKeys63(b *testing.B) {
	benchmarkConcatPubKeys(63, b)
}

func Benchmark_ConcatPubKeys400(b *testing.B) {
	benchmarkConcatPubKeys(400, b)
}

func benchmarkConcatPubKeys(nPubKeys int, b *testing.B) {
	pubKeys := createBLSPubKeys(nPubKeys)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := multisig.ConcatPubKeys(pubKeys)
		require.Nil(b, err)
	}
}

func Benchmark_AggregatedSig63(b *testing.B) {
	benchmarkAggregatedSig(63, b)
}

func Benchmark_AggregatedSig400(b *testing.B) {
	benchmarkAggregatedSig(400, b)
}

func benchmarkAggregatedSig(nPubKeys uint16, b *testing.B) {
	msg := []byte(testMessage)

	hasher, err := blake2b.NewBlake2bWithSize(blsHashSize)
	require.Nil(b, err)
	llSig := &multisig.BlsMultiSigner{Hasher: hasher}
	pubKeys, sigShares := createSigSharesBLS(nPubKeys, msg, llSig)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := llSig.AggregateSignatures(pubKeys[0].Suite(), sigShares, pubKeys)
		require.Nil(b, err)
	}
}

func Benchmark_VerifyAggregatedSig63(b *testing.B) {
	benchmarkVerifyAggregatedSig(63, b)
}

func Benchmark_VerifyAggregatedSig400(b *testing.B) {
	benchmarkVerifyAggregatedSig(400, b)
}

func benchmarkVerifyAggregatedSig(nPubKeys uint16, b *testing.B) {
	msg := []byte(testMessage)

	hasher, err := blake2b.NewBlake2bWithSize(blsHashSize)
	require.Nil(b, err)

	llSig := &multisig.BlsMultiSigner{Hasher: hasher}
	pubKeys, sigShares := createSigSharesBLS(nPubKeys, msg, llSig)
	aggSigBytes, err := llSig.AggregateSignatures(pubKeys[0].Suite(), sigShares, pubKeys)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = llSig.VerifyAggregatedSig(pubKeys[0].Suite(), pubKeys, aggSigBytes, msg)
		require.Nil(b, err)
	}
}

func Benchmark_VerifyAggregatedSigWithoutPrepare63(b *testing.B) {
	benchmarkVerifyAggregatedSigWithoutPrepare(63, b)
}

func Benchmark_VerifyAggregatedSigWithoutPrepare400(b *testing.B) {
	benchmarkVerifyAggregatedSigWithoutPrepare(400, b)
}

func benchmarkVerifyAggregatedSigWithoutPrepare(nPubKeys uint16, b *testing.B) {
	msg := []byte(testMessage)

	hasher, err := blake2b.NewBlake2bWithSize(blsHashSize)
	require.Nil(b, err)
	llSig := &multisig.BlsMultiSigner{Hasher: hasher}
	pubKeys, sigShares := createSigSharesBLS(nPubKeys, msg, llSig)
	aggSigBytes, err := llSig.AggregateSignatures(pubKeys[0].Suite(), sigShares, pubKeys)
	require.Nil(b, err)

	prepPubKeys, err := multisig.PreparePublicKeys(pubKeys, hasher, pubKeys[0].Suite())
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aggSig := &bls.Sign{}
		err = aggSig.Deserialize(aggSigBytes)
		require.Nil(b, err)

		res := aggSig.FastAggregateVerify(prepPubKeys, msg)
		require.True(b, res)
	}
}

func createBLSPubKeys(
	nPubKeys int,
) (pubKeys []crypto.PublicKey) {
	suite := mcl.NewSuiteBLS12()
	kg := signing.NewKeyGenerator(suite)

	pubKeys = make([]crypto.PublicKey, nPubKeys)

	for i := 0; i < nPubKeys; i++ {
		_, pk := kg.GeneratePair()
		pubKeys[i] = pk
	}

	return pubKeys
}

func Benchmark_SignShare(b *testing.B) {
	msg := []byte(testMessage)
	privKey, _, _, lls := genSigParamsBLS()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := lls.SignShare(privKey, msg)
		require.Nil(b, err)
	}
}

func Benchmark_VerifyShare(b *testing.B) {
	msg := []byte(testMessage)
	privKey, pubKey, _, lls := genSigParamsBLS()
	sig, err := lls.SignShare(privKey, msg)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := lls.VerifySigShare(pubKey, msg, sig)
		require.Nil(b, err)
	}
}

func Benchmark_HashPublicKeyPoints63(b *testing.B) {
	benchmarkHashPublicKeyPoints(63, b)
}

func Benchmark_HashPublicKeyPoints400(b *testing.B) {
	benchmarkHashPublicKeyPoints(400, b)
}

func benchmarkHashPublicKeyPoints(nPubKeys int, b *testing.B) {
	hasher, err := blake2b.NewBlake2bWithSize(blsHashSize)
	require.Nil(b, err)

	pubKeys := createBLSPubKeys(nPubKeys)
	concatPubKeys, err := multisig.ConcatPubKeys(pubKeys)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash, err := multisig.HashPublicKeyPoints(hasher, pubKeys[0].Point(), concatPubKeys)
		require.Nil(b, err)
		require.NotNil(b, hash)
	}
}
