package multisig_test

import (
	"encoding/hex"
	"testing"

	"github.com/herumi/bls-go-binary/bls"
	crypto "github.com/kalyan3104/k-crypto-core-go"
	"github.com/kalyan3104/k-crypto-core-go/mock"
	"github.com/kalyan3104/k-crypto-core-go/signing"
	"github.com/kalyan3104/k-crypto-core-go/signing/ed25519"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl/multisig"
	"github.com/stretchr/testify/require"
)

func Test_ScalarMulSigNilScalarShouldErr(t *testing.T) {
	t.Parallel()
	msg := []byte(testMessage)
	privKey, pubKey, _, llSig := genSigParamsBLS()
	sig, _ := llSig.SignShare(privKey, msg)

	sigPointG1, err := sigBytesToPointG1(sig)
	require.Nil(t, err)

	res, err := multisig.ScalarMulSig(pubKey.Suite(), nil, sigPointG1)

	require.Equal(t, crypto.ErrNilParam, err)
	require.Nil(t, res)
}

func Test_ScalarMulSigNilSigShouldErr(t *testing.T) {
	t.Parallel()
	_, pubKey, _, _ := genSigParamsBLS()
	scalar, _ := pubKey.Suite().CreateScalar().Pick()

	scalarBytes, _ := scalar.MarshalBinary()
	res, err := multisig.ScalarMulSig(pubKey.Suite(), scalarBytes, nil)

	require.Equal(t, crypto.ErrNilSignature, err)
	require.Nil(t, res)
}

func Test_ScalarMulSigNilSuiteShouldErr(t *testing.T) {
	t.Parallel()
	privKey, pubKey, _, llSig := genSigParamsBLS()
	msg := []byte(testMessage)
	sig, _ := llSig.SignShare(privKey, msg)

	scalar, _ := pubKey.Suite().CreateScalar().Pick()
	mclScalar, _ := scalar.(*mcl.Scalar)
	scalarBytesHexStr := mclScalar.Scalar.GetString(16)

	// odd length hex string fails hex decoding, so make it even
	if len(scalarBytesHexStr)%2 != 0 {
		scalarBytesHexStr = "0" + scalarBytesHexStr
	}

	scalarBytes, err := hex.DecodeString(scalarBytesHexStr)
	require.Nil(t, err)
	sigPointG1, err := sigBytesToPointG1(sig)
	require.Nil(t, err)
	res, err := multisig.ScalarMulSig(nil, scalarBytes, sigPointG1)

	require.Equal(t, crypto.ErrNilSuite, err)
	require.Nil(t, res)
}

func Test_ScalarMulSigOK(t *testing.T) {
	t.Parallel()
	msg := []byte(testMessage)
	privKey, pubKey, _, llSig := genSigParamsBLS()
	sig, _ := llSig.SignShare(privKey, msg)
	scalar, _ := pubKey.Suite().CreateScalar().Pick()
	mclScalar, _ := scalar.(*mcl.Scalar)
	scalarBytesHexStr := mclScalar.Scalar.GetString(16)

	// odd length hex string fails hex decoding, so make it even
	if len(scalarBytesHexStr)%2 != 0 {
		scalarBytesHexStr = "0" + scalarBytesHexStr
	}

	scalarBytes, err := hex.DecodeString(scalarBytesHexStr)
	require.Nil(t, err)

	sigPointG1, err := sigBytesToPointG1(sig)
	require.Nil(t, err)

	res, err := multisig.ScalarMulSig(pubKey.Suite(), scalarBytes, sigPointG1)

	require.Nil(t, err)
	require.NotNil(t, res)
}

func Test_ScalarMulPkNilPkShouldErr(t *testing.T) {
	t.Parallel()

	suite := mcl.NewSuiteBLS12()
	scalar := suite.CreateScalar()
	scalarBytes, err := scalar.MarshalBinary()
	require.Nil(t, err)

	point, err := multisig.ScalarMulPk(suite, scalarBytes, nil)
	require.Equal(t, crypto.ErrNilParam, err)
	require.Nil(t, point)
}

func Test_ScalarMulPkNilSuiteShouldErr(t *testing.T) {
	t.Parallel()

	suite := mcl.NewSuiteBLS12()
	scalar := suite.CreateScalar()
	kg := signing.NewKeyGenerator(suite)
	_, pk := kg.GeneratePair()
	scalarBytes, err := scalar.MarshalBinary()
	require.Nil(t, err)

	point, err := multisig.ScalarMulPk(nil, scalarBytes, pk.Point())
	require.Equal(t, crypto.ErrNilSuite, err)
	require.Nil(t, point)
}

func Test_ScalarMulPkOK(t *testing.T) {
	t.Parallel()

	suite := mcl.NewSuiteBLS12()
	scalar := suite.CreateScalar()
	kg := signing.NewKeyGenerator(suite)

	_, pk := kg.GeneratePair()
	require.NotNil(t, pk)

	mclScalar, ok := scalar.GetUnderlyingObj().(*bls.Fr)
	require.True(t, ok)
	scalarHexStr := mclScalar.GetString(16)
	scalarBytes := make([]byte, 32)

	// odd length hex string fails hex decoding, so make it even
	if len(scalarHexStr)%2 != 0 {
		scalarHexStr = "0" + scalarHexStr
	}
	scalarHexStr = "1" + scalarHexStr[1:] //make the first byte non 0 (resulting value will be 32 bytes long in all cases)

	nb, err := hex.Decode(scalarBytes, []byte(scalarHexStr))
	require.Nil(t, err)
	require.Equal(t, 32, nb)

	point, err := multisig.ScalarMulPk(suite, scalarBytes, pk.Point())
	require.Nil(t, err)
	require.NotNil(t, point)
}

func Test_HashPublicKeyPointsNilHasherShouldErr(t *testing.T) {
	t.Parallel()

	hasher := &mock.HasherSpongeMock{}
	llSig := &multisig.BlsMultiSigner{Hasher: hasher}
	msg := testMessage
	pubKeys, _ := createSigSharesBLS(20, []byte(msg), llSig)
	concatPubKeys, err := multisig.ConcatPubKeys(pubKeys)
	require.Nil(t, err)

	hash, err := multisig.HashPublicKeyPoints(nil, pubKeys[0].Point(), concatPubKeys)
	require.Equal(t, crypto.ErrNilHasher, err)
	require.Nil(t, hash)
}

func Test_HashPublicKeyPointsNilPubKeyShouldErr(t *testing.T) {
	t.Parallel()

	hasher := &mock.HasherSpongeMock{}
	llSig := &multisig.BlsMultiSigner{Hasher: hasher}
	msg := testMessage
	pubKeys, _ := createSigSharesBLS(20, []byte(msg), llSig)
	concatPubKeys, err := multisig.ConcatPubKeys(pubKeys)
	require.Nil(t, err)

	hash, err := multisig.HashPublicKeyPoints(hasher, nil, concatPubKeys)
	require.Equal(t, crypto.ErrNilPublicKeyPoint, err)
	require.Nil(t, hash)
}

func Test_HashPublicKeyPointsWrongSizeHasherShouldErr(t *testing.T) {
	t.Parallel()

	hasher := &mock.HasherMock{}
	llSig := &multisig.BlsMultiSigner{Hasher: hasher}
	msg := testMessage
	pubKeys, _ := createSigSharesBLS(20, []byte(msg), llSig)
	concatPubKeys, err := multisig.ConcatPubKeys(pubKeys)
	require.Nil(t, err)

	hash, err := multisig.HashPublicKeyPoints(hasher, pubKeys[0].Point(), concatPubKeys)
	require.Equal(t, crypto.ErrWrongSizeHasher, err)
	require.Nil(t, hash)
}

func Test_HashPublicKeyPointsNilConcatPubKeysShouldErr(t *testing.T) {
	t.Parallel()

	hasher := &mock.HasherSpongeMock{}
	llSig := &multisig.BlsMultiSigner{Hasher: hasher}
	msg := testMessage
	pubKeys, _ := createSigSharesBLS(20, []byte(msg), llSig)
	hash, err := multisig.HashPublicKeyPoints(hasher, pubKeys[0].Point(), nil)
	require.Equal(t, crypto.ErrNilParam, err)
	require.Nil(t, hash)
}

func Test_HashPublicKeyPointsOK(t *testing.T) {
	t.Parallel()

	hasher := &mock.HasherSpongeMock{}
	llSig := &multisig.BlsMultiSigner{Hasher: hasher}
	msg := testMessage
	pubKeys, _ := createSigSharesBLS(20, []byte(msg), llSig)
	concatPubKeys, err := multisig.ConcatPubKeys(pubKeys)
	require.Nil(t, err)

	hash, err := multisig.HashPublicKeyPoints(hasher, pubKeys[0].Point(), concatPubKeys)
	require.Nil(t, err)
	require.NotNil(t, hash)
}

func Test_SigBytesToSig(t *testing.T) {
	t.Parallel()

	t.Run("nil or empty signature should err", func(t *testing.T) {
		sig, err := multisig.SigBytesToSig(nil)
		require.Nil(t, sig)
		require.Equal(t, crypto.ErrNilSignature, err)

		sig, err = multisig.SigBytesToSig([]byte{})
		require.Nil(t, sig)
		require.Equal(t, crypto.ErrNilSignature, err)
	})
	t.Run("wrong serialization sig should err", func(t *testing.T) {
		wrongSerialization := []byte{1, 2}
		sig, err := multisig.SigBytesToSig(wrongSerialization)
		require.Nil(t, sig)
		require.NotNil(t, err)
	})
	t.Run("invalid sig point should err", func(t *testing.T) {
		invalidSig := &bls.Sign{}
		invalidSigBytes := invalidSig.Serialize()
		sig, err := multisig.SigBytesToSig(invalidSigBytes)
		require.Nil(t, sig)
		require.Equal(t, crypto.ErrBLSInvalidSignature, err)
	})
	t.Run("sig ok", func(t *testing.T) {
		msg := []byte(testMessage)
		privKey, _, _, llSig := genSigParamsBLS()
		goodSig, _ := llSig.SignShare(privKey, msg)

		sig, err := multisig.SigBytesToSig(goodSig)
		require.Nil(t, err)
		require.NotNil(t, sig)
	})
}

func Test_SigBytesToPoint(t *testing.T) {
	t.Parallel()

	t.Run("invalid sig should err", func(t *testing.T) {
		invalidSig := &bls.Sign{}
		invalidSigBytes := invalidSig.Serialize()
		point, err := multisig.SigBytesToPoint(invalidSigBytes)
		require.Nil(t, point)
		require.Equal(t, crypto.ErrBLSInvalidSignature, err)
	})
	t.Run("valid sig OK", func(t *testing.T) {
		msg := []byte(testMessage)
		privKey, _, _, llSig := genSigParamsBLS()
		goodSig, _ := llSig.SignShare(privKey, msg)

		point, err := multisig.SigBytesToPoint(goodSig)
		require.Nil(t, err)
		require.NotNil(t, point)
	})
}

func Test_PubKeyCryptoToBLS(t *testing.T) {
	t.Parallel()

	t.Run("invalid pubKey should err", func(t *testing.T) {
		suite := ed25519.NewEd25519()
		kg := signing.NewKeyGenerator(suite)
		_, pk := kg.GeneratePair()

		pubKeyBLS, err := multisig.PubKeyCryptoToBLS(pk)
		require.Nil(t, pubKeyBLS)
		require.Equal(t, crypto.ErrInvalidPoint, err)
	})
	t.Run("valid pub key OK", func(t *testing.T) {
		suite := mcl.NewSuiteBLS12()
		kg := signing.NewKeyGenerator(suite)
		_, pk := kg.GeneratePair()

		pubKeyBLS, err := multisig.PubKeyCryptoToBLS(pk)
		require.Nil(t, err)
		require.NotNil(t, pubKeyBLS)
	})
}

func Test_PubKeysCryptoToBLS(t *testing.T) {
	t.Parallel()

	t.Run("invalid pubKey should err", func(t *testing.T) {
		suite := ed25519.NewEd25519()
		kg := signing.NewKeyGenerator(suite)
		_, invalidPk := kg.GeneratePair()

		suiteBLS := mcl.NewSuiteBLS12()
		kgBLS := signing.NewKeyGenerator(suiteBLS)
		_, pkBLS := kgBLS.GeneratePair()

		pubKeyBLS, err := multisig.PubKeysCryptoToBLS([]crypto.PublicKey{invalidPk, pkBLS})
		require.Nil(t, pubKeyBLS)
		require.Equal(t, crypto.ErrInvalidPoint, err)
	})
	t.Run("valid pubKeys OK", func(t *testing.T) {
		suiteBLS := mcl.NewSuiteBLS12()
		kgBLS := signing.NewKeyGenerator(suiteBLS)
		_, pkBLS1 := kgBLS.GeneratePair()
		_, pkBLS2 := kgBLS.GeneratePair()

		pubKeysBLS, err := multisig.PubKeysCryptoToBLS([]crypto.PublicKey{pkBLS1, pkBLS2})
		require.Nil(t, err)
		require.Len(t, pubKeysBLS, 2)
	})
}
