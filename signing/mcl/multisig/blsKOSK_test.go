package multisig_test

import (
	"testing"

	"github.com/herumi/bls-go-binary/bls"
	crypto "github.com/kalyan3104/k-crypto-core-go"
	"github.com/kalyan3104/k-crypto-core-go/mock"
	"github.com/kalyan3104/k-crypto-core-go/signing"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl/multisig"
	"github.com/stretchr/testify/require"
)

func TestBlsMultiSignerKOSK_VerifySigBytes(t *testing.T) {
	t.Parallel()

	t.Run("nil or empty sig should err", func(t *testing.T) {
		llSig := &multisig.BlsMultiSignerKOSK{}
		err := llSig.VerifySigBytes(nil, nil)
		require.Equal(t, crypto.ErrNilSignature, err)

		err = llSig.VerifySigBytes(nil, []byte{})
		require.Equal(t, crypto.ErrNilSignature, err)
	})
	t.Run("invalid sig should err", func(t *testing.T) {
		invalidSig := &bls.Sign{}
		invalidSigBytes := invalidSig.Serialize()
		llSig := &multisig.BlsMultiSignerKOSK{}
		err := llSig.VerifySigBytes(nil, invalidSigBytes)

		require.NotNil(t, err)
	})
	t.Run("ok sig should return nil error", func(t *testing.T) {
		msg := []byte(testMessage)
		llSig := &multisig.BlsMultiSignerKOSK{}
		suite := mcl.NewSuiteBLS12()
		kg := signing.NewKeyGenerator(suite)

		sk, _ := kg.GeneratePair()
		sig, _ := llSig.SignShare(sk, msg)
		err := llSig.VerifySigBytes(nil, sig)

		require.Nil(t, err)
	})
}

func TestBlsMultiSignerKOSK_SignShare(t *testing.T) {
	t.Parallel()
	msg := []byte(testMessage)
	sk, _, _, lls := genSigParamsKOSK()

	t.Run("nil private key should err", func(t *testing.T) {

		sig, err := lls.SignShare(nil, msg)
		require.Equal(t, crypto.ErrNilPrivateKey, err)
		require.Nil(t, sig)
	})
	t.Run("invalid private key should err", func(t *testing.T) {
		sk := &mock.PrivateKeyStub{
			ScalarStub: func() crypto.Scalar {
				return &mock.ScalarMock{}
			},
		}

		sig, err := lls.SignShare(sk, msg)
		require.Equal(t, crypto.ErrInvalidPrivateKey, err)
		require.Nil(t, sig)
	})
	t.Run("nil msg should err", func(t *testing.T) {
		sig, err := lls.SignShare(sk, nil)
		require.Equal(t, crypto.ErrNilMessage, err)
		require.Nil(t, sig)
	})
	t.Run("sig share ok", func(t *testing.T) {
		sig, err := lls.SignShare(sk, msg)
		require.Nil(t, err)
		require.NotNil(t, sig)
	})
}

func TestBlsMultiSignerKOSK_VerifySigShare(t *testing.T) {
	t.Parallel()
	msg := []byte(testMessage)
	sk, pk, _, lls := genSigParamsKOSK()
	sig, _ := lls.SignShare(sk, msg)

	t.Run("nil pub key should err", func(t *testing.T) {
		err := lls.VerifySigShare(nil, msg, sig)
		require.Equal(t, crypto.ErrNilPublicKey, err)
	})
	t.Run("invalid pub key should err", func(t *testing.T) {
		pk := &mock.PublicKeyStub{
			ToByteArrayStub: func() (bytes []byte, err error) {
				return []byte("invalid key"), nil
			},
			PointStub: func() crypto.Point {
				return &mock.PointMock{}
			},
			SuiteStub: func() crypto.Suite {
				return mcl.NewSuiteBLS12()
			},
		}

		err := lls.VerifySigShare(pk, msg, sig)
		require.Equal(t, crypto.ErrInvalidPublicKey, err)
	})
	t.Run("nil msg should err", func(t *testing.T) {
		err := lls.VerifySigShare(pk, nil, sig)
		require.Equal(t, crypto.ErrNilMessage, err)
	})
	t.Run("nil sig should err", func(t *testing.T) {
		err := lls.VerifySigShare(pk, msg, nil)
		require.Equal(t, crypto.ErrNilSignature, err)
	})
	t.Run("invalid sig should err", func(t *testing.T) {
		sig := &bls.Sign{}
		sigBytes := sig.Serialize()
		err := lls.VerifySigShare(pk, msg, sigBytes)
		require.NotNil(t, err)
	})
	t.Run("verify sig share OK", func(t *testing.T) {
		err := lls.VerifySigShare(pk, msg, sig)
		require.Nil(t, err)
	})
}

func TestBlsMultiSignerKOSK_AggregateSignatures(t *testing.T) {
	t.Parallel()

	msg := []byte(testMessage)
	llSig := &multisig.BlsMultiSignerKOSK{}
	pubKeys, sigShares := createSigSharesBLS(20, msg, llSig)

	t.Run("nil suite should err", func(t *testing.T) {
		sigAgg, err := llSig.AggregateSignatures(nil, sigShares, pubKeys)
		require.Equal(t, crypto.ErrNilSuite, err)
		require.Nil(t, sigAgg)
	})
	t.Run("nil or empty sig shares should err", func(t *testing.T) {
		sigAgg, err := llSig.AggregateSignatures(pubKeys[0].Suite(), nil, pubKeys)
		require.Equal(t, crypto.ErrNilSignaturesList, err)
		require.Nil(t, sigAgg)

		sigAgg, err = llSig.AggregateSignatures(pubKeys[0].Suite(), [][]byte{}, pubKeys)
		require.Equal(t, crypto.ErrNilSignaturesList, err)
		require.Nil(t, sigAgg)
	})
	t.Run("nil or empty pubKeys should err", func(t *testing.T) {
		sigAgg, err := llSig.AggregateSignatures(pubKeys[0].Suite(), sigShares, nil)
		require.Equal(t, crypto.ErrNilPublicKeys, err)
		require.Nil(t, sigAgg)

		sigAgg, err = llSig.AggregateSignatures(pubKeys[0].Suite(), sigShares, []crypto.PublicKey{})
		require.Equal(t, crypto.ErrNilPublicKeys, err)
		require.Nil(t, sigAgg)
	})
	t.Run("invalid sig share should err", func(t *testing.T) {
		sigSharesCopy := make([][]byte, len(sigShares))
		for i := range sigShares {
			sigSharesCopy[i] = make([]byte, len(sigShares[i]))
			copy(sigSharesCopy[i], sigShares[i])
		}
		sigSharesCopy[0] = (&bls.Sign{}).Serialize()
		sigAgg, err := llSig.AggregateSignatures(pubKeys[0].Suite(), sigSharesCopy, pubKeys)
		require.Equal(t, crypto.ErrBLSInvalidSignature, err)
		require.Nil(t, sigAgg)
	})
	t.Run("valid sigs OK", func(t *testing.T) {
		sigAgg, err := llSig.AggregateSignatures(pubKeys[0].Suite(), sigShares, pubKeys)
		require.Nil(t, err)
		require.NotNil(t, sigAgg)
	})
}

func TestBlsMultiSignerKOSK_VerifyAggregatedSig(t *testing.T) {
	t.Parallel()
	msg := []byte(testMessage)
	llSig := &multisig.BlsMultiSignerKOSK{}
	pubKeys, sigShares := createSigSharesBLS(20, msg, llSig)
	aggSig, err := llSig.AggregateSignatures(pubKeys[0].Suite(), sigShares, pubKeys)
	require.Nil(t, err)

	t.Run("nil suite should err", func(t *testing.T) {
		err = llSig.VerifyAggregatedSig(nil, pubKeys, aggSig, msg)
		require.Equal(t, crypto.ErrNilSuite, err)
	})
	t.Run("nil or empty pub keys should err", func(t *testing.T) {
		err = llSig.VerifyAggregatedSig(pubKeys[0].Suite(), nil, aggSig, msg)
		require.Equal(t, crypto.ErrNilPublicKeys, err)

		err = llSig.VerifyAggregatedSig(pubKeys[0].Suite(), []crypto.PublicKey{}, aggSig, msg)
		require.Equal(t, crypto.ErrNilPublicKeys, err)
	})
	t.Run("nil or empty aggSig should err", func(t *testing.T) {
		err = llSig.VerifyAggregatedSig(pubKeys[0].Suite(), pubKeys, nil, msg)
		require.Equal(t, crypto.ErrNilSignature, err)

		err = llSig.VerifyAggregatedSig(pubKeys[0].Suite(), pubKeys, []byte{}, msg)
		require.Equal(t, crypto.ErrNilSignature, err)
	})
	t.Run("invalid aggregated sig should err", func(t *testing.T) {
		err = llSig.VerifyAggregatedSig(pubKeys[0].Suite(), pubKeys, sigShares[0], msg)
		require.Equal(t, crypto.ErrAggSigNotValid, err)
	})
	t.Run("nil msg should err", func(t *testing.T) {
		err = llSig.VerifyAggregatedSig(pubKeys[0].Suite(), pubKeys, aggSig, nil)
		require.Equal(t, crypto.ErrNilMessage, err)
	})
	t.Run("verify OK", func(t *testing.T) {
		err = llSig.VerifyAggregatedSig(pubKeys[0].Suite(), pubKeys, aggSig, msg)
		require.Nil(t, err)
	})
}

func genSigParamsKOSK() (
	privKey crypto.PrivateKey,
	pubKey crypto.PublicKey,
	kg crypto.KeyGenerator,
	llSigner crypto.LowLevelSignerBLS,
) {
	suite := mcl.NewSuiteBLS12()
	kg = signing.NewKeyGenerator(suite)
	llSigner = &multisig.BlsMultiSignerKOSK{}
	privKey, pubKey = kg.GeneratePair()

	return privKey, pubKey, kg, llSigner
}
