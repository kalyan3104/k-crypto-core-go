package multisig_test

import (
	"testing"

	"github.com/kalyan3104/k-core/core/check"
	crypto "github.com/kalyan3104/k-crypto-core-go"
	"github.com/kalyan3104/k-crypto-core-go/mock"
	"github.com/kalyan3104/k-crypto-core-go/signing"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl"
	llsig "github.com/kalyan3104/k-crypto-core-go/signing/mcl/multisig"
	"github.com/kalyan3104/k-crypto-core-go/signing/multisig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateMultiSigParamsBLSWithPrivateKeys(nbSigners int) (
	privKeys [][]byte,
	pubKeys [][]byte,
	kg crypto.KeyGenerator,
) {
	suite := mcl.NewSuiteBLS12()
	kg = signing.NewKeyGenerator(suite)
	pubKeys = make([][]byte, 0, nbSigners)
	privKeys = make([][]byte, 0, nbSigners)

	for i := 0; i < nbSigners; i++ {
		sk, pk := kg.GeneratePair()
		pubKeyBytes, _ := pk.ToByteArray()
		skBytes, _ := sk.ToByteArray()
		pubKeys = append(pubKeys, pubKeyBytes)
		privKeys = append(privKeys, skBytes)
	}

	return privKeys, pubKeys, kg
}

func generateMultiSigParamsBLS(nbSigners int) (
	pubKeys [][]byte,
	kg crypto.KeyGenerator,
) {
	_, pubKeys, kg = generateMultiSigParamsBLSWithPrivateKeys(nbSigners)
	return
}

func createSignerAndSigShareBLS(
	privKey []byte,
	kg crypto.KeyGenerator,
	message []byte,
	llSigner crypto.LowLevelSignerBLS,
) (sigShare []byte, multiSig crypto.MultiSigner) {
	multiSig, _ = multisig.NewBLSMultisig(llSigner, kg)
	sigShare, _ = multiSig.CreateSignatureShare(privKey, message)

	return sigShare, multiSig
}

func createSigSharesBLS(
	nbSigs uint16,
	message []byte,
	llSigner crypto.LowLevelSignerBLS,
) (multiSigner crypto.MultiSigner, pubKeys [][]byte, sigShares [][]byte) {
	suite := mcl.NewSuiteBLS12()
	kg := signing.NewKeyGenerator(suite)

	privKeyBytes := make([][]byte, nbSigs)
	pubKesBytes := make([][]byte, nbSigs)

	for i := uint16(0); i < nbSigs; i++ {
		sk, pk := kg.GeneratePair()
		privKeyBytes[i], _ = sk.ToByteArray()
		pubKesBytes[i], _ = pk.ToByteArray()
	}

	sigShares = make([][]byte, nbSigs)
	multiSigner, _ = multisig.NewBLSMultisig(llSigner, kg)

	for i := uint16(0); i < nbSigs; i++ {
		sigShares[i], _ = multiSigner.CreateSignatureShare(privKeyBytes[i], message)
	}

	return multiSigner, pubKesBytes, sigShares
}

func createAndAddSignatureSharesBLS(msg []byte, llSigner crypto.LowLevelSignerBLS) (multiSigner crypto.MultiSigner, pubKeys [][]byte, sigs [][]byte) {
	nbSigners := uint16(3)

	return createSigSharesBLS(nbSigners, msg, llSigner)
}

func createAggregatedSigBLS(msg []byte, llSigner crypto.LowLevelSignerBLS, t *testing.T) (multiSigner crypto.MultiSigner, pubKeys [][]byte, aggSig []byte) {
	multiSigner, pubKeys, signatures := createAndAddSignatureSharesBLS(msg, llSigner)
	aggSig, err := multiSigner.AggregateSigs(pubKeys, signatures)

	assert.Nil(t, err)

	return multiSigner, pubKeys, aggSig
}

func TestNewBLSMultisig_NilLowLevelSignerShouldErr(t *testing.T) {
	t.Parallel()

	_, kg := generateMultiSigParamsBLS(4)
	multiSig, err := multisig.NewBLSMultisig(nil, kg)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrNilLowLevelSigner, err)
}

func TestNewBLSMultisig_NilKeyGenShouldErr(t *testing.T) {
	t.Parallel()

	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}

	multiSig, err := multisig.NewBLSMultisig(llSigner, nil)

	assert.Nil(t, multiSig)
	assert.Equal(t, crypto.ErrNilKeyGenerator, err)
}

func TestNewBLSMultisig_OK(t *testing.T) {
	t.Parallel()

	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	_, kg := generateMultiSigParamsBLS(4)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, err := multisig.NewBLSMultisig(llSigner, kg)

		assert.Nil(t, err)
		assert.False(t, check.IfNil(multiSig))
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, err := multisig.NewBLSMultisig(llSignerKOSK, kg)

		assert.Nil(t, err)
		assert.False(t, check.IfNil(multiSig))
	})
}

func TestBLSMultiSigner_CreateSignatureShareNilMessageShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := 3
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKeys, _, kg := generateMultiSigParamsBLSWithPrivateKeys(4)

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, kg)
		sigShare, err := multiSig.CreateSignatureShare(privKeys[ownIndex], nil)

		assert.Nil(t, sigShare)
		assert.Equal(t, crypto.ErrNilMessage, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, kg)
		sigShare, err := multiSig.CreateSignatureShare(privKeys[ownIndex], nil)

		assert.Nil(t, sigShare)
		assert.Equal(t, crypto.ErrNilMessage, err)
	})
}

func TestBLSMultiSigner_CreateSignatureShareOK(t *testing.T) {
	t.Parallel()

	ownIndex := 3
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKeys, pubKeys, kg := generateMultiSigParamsBLSWithPrivateKeys(4)
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, kg)
		sigShare, err := multiSig.CreateSignatureShare(privKeys[ownIndex], msg)

		verifErr := multiSig.VerifySignatureShare(pubKeys[ownIndex], msg, sigShare)

		assert.Nil(t, err)
		assert.NotNil(t, sigShare)
		assert.Nil(t, verifErr)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, kg)
		sigShare, err := multiSig.CreateSignatureShare(privKeys[ownIndex], msg)

		verifErr := multiSig.VerifySignatureShare(pubKeys[ownIndex], msg, sigShare)

		assert.Nil(t, err)
		assert.NotNil(t, sigShare)
		assert.Nil(t, verifErr)
	})
}

func TestBLSMultiSigner_VerifySignatureShareNilSigShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := 3
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	_, pubKeys, kg := generateMultiSigParamsBLSWithPrivateKeys(4)
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSigner, kg)
		verifErr := multiSig.VerifySignatureShare(pubKeys[ownIndex], msg, nil)

		assert.Equal(t, crypto.ErrNilSignature, verifErr)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, _ := multisig.NewBLSMultisig(llSignerKOSK, kg)
		verifErr := multiSig.VerifySignatureShare(pubKeys[ownIndex], msg, nil)

		assert.Equal(t, crypto.ErrNilSignature, verifErr)
	})
}

func TestBLSMultiSigner_VerifySignatureShareInvalidSignatureShouldErr(t *testing.T) {
	t.Parallel()

	ownIndex := 3
	numSigners := uint16(4)
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSig, pubKeys, sigShares := createSigSharesBLS(numSigners, msg, llSigner)
		// valid signature but for a different public key
		verifErr := multiSig.VerifySignatureShare(pubKeys[ownIndex], msg, sigShares[ownIndex-1])

		assert.NotNil(t, verifErr)
		assert.Contains(t, verifErr.Error(), "signature is invalid")
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSig, pubKeys, sigShares := createSigSharesBLS(numSigners, msg, llSignerKOSK)
		// valid signature but for a different public key
		verifErr := multiSig.VerifySignatureShare(pubKeys[ownIndex], msg, sigShares[ownIndex-1])

		assert.NotNil(t, verifErr)
		assert.Contains(t, verifErr.Error(), "signature is invalid")
	})
}

func TestBLSMultiSigner_VerifySignatureShareOK(t *testing.T) {
	t.Parallel()

	ownIndex := 3
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}
	privKeys, pubKeys, kg := generateMultiSigParamsBLSWithPrivateKeys(4)
	msg := []byte("message")

	t.Run("with rogue key prevention", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(privKeys[ownIndex], kg, msg, llSigner)
		verifErr := multiSig.VerifySignatureShare(pubKeys[ownIndex], msg, sigShare)

		assert.Nil(t, verifErr)
	})
	t.Run("with KOSK", func(t *testing.T) {
		sigShare, multiSig := createSignerAndSigShareBLS(privKeys[ownIndex], kg, msg, llSignerKOSK)
		verifErr := multiSig.VerifySignatureShare(pubKeys[ownIndex], msg, sigShare)

		assert.Nil(t, verifErr)
	})
}

func TestBLSMultiSigner_AggregateSigsMismatchPubKeysAndSigShares(t *testing.T) {
	t.Parallel()

	nbSigners := uint16(3)
	message := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, pubKeys, sigShares := createSigSharesBLS(nbSigners, message, llSigner)

		aggSig, err := multiSigner.AggregateSigs(pubKeys[:nbSigners-2], sigShares)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrInvalidParam, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, pubKeys, sigShares := createSigSharesBLS(nbSigners, message, llSignerKOSK)

		aggSig, err := multiSigner.AggregateSigs(pubKeys[:nbSigners-2], sigShares)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrInvalidParam, err)
	})
}

func TestBLSMultiSigner_AggregateSigsInvalidPubKey(t *testing.T) {
	t.Parallel()

	nbSigners := uint16(3)
	message := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, pubKeys, sigShares := createSigSharesBLS(nbSigners, message, llSigner)
		pubKeys[0] = []byte{}
		aggSig, err := multiSigner.AggregateSigs(pubKeys, sigShares)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrEmptyPubKey, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, pubKeys, sigShares := createSigSharesBLS(nbSigners, message, llSignerKOSK)
		pubKeys[0] = []byte{}
		aggSig, err := multiSigner.AggregateSigs(pubKeys, sigShares)

		assert.Nil(t, aggSig)
		assert.Equal(t, crypto.ErrEmptyPubKey, err)
	})
}

func TestBLSMultiSigner_AggregateSigsOK(t *testing.T) {
	t.Parallel()

	nbSigners := uint16(3)
	message := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, pubKeys, sigShares := createSigSharesBLS(nbSigners, message, llSigner)
		aggSig, err := multiSigner.AggregateSigs(pubKeys, sigShares)

		assert.Nil(t, err)
		assert.NotNil(t, aggSig)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, pubKeys, sigShares := createSigSharesBLS(nbSigners, message, llSignerKOSK)
		aggSig, err := multiSigner.AggregateSigs(pubKeys, sigShares)

		assert.Nil(t, err)
		assert.NotNil(t, aggSig)
	})
}

func TestBLSMultiSigner_VerifyAggregatedSigNilPubKeyShouldErr(t *testing.T) {
	t.Parallel()

	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, pubKeys, aggSig := createAggregatedSigBLS(msg, llSigner, t)
		pubKeys[0] = []byte{}
		err := multiSigner.VerifyAggregatedSig(pubKeys, msg, aggSig)

		assert.Equal(t, crypto.ErrEmptyPubKey, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, pubKeys, aggSig := createAggregatedSigBLS(msg, llSignerKOSK, t)
		pubKeys[0] = []byte{}
		err := multiSigner.VerifyAggregatedSig(pubKeys, msg, aggSig)

		assert.Equal(t, crypto.ErrEmptyPubKey, err)
	})
}

func TestBLSMultiSigner_VerifyAggregatedSigSigValid(t *testing.T) {
	t.Parallel()

	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, pubKeys, aggSig := createAggregatedSigBLS(msg, llSigner, t)
		err := multiSigner.VerifyAggregatedSig(pubKeys, msg, aggSig)
		assert.Nil(t, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, pubKeys, aggSig := createAggregatedSigBLS(msg, llSignerKOSK, t)
		err := multiSigner.VerifyAggregatedSig(pubKeys, msg, aggSig)
		assert.Nil(t, err)
	})
}

func TestBLSMultiSigner_VerifyAggregatedSigSigInvalid(t *testing.T) {
	t.Parallel()

	msg := []byte("message")
	hasher := &mock.HasherSpongeMock{}
	llSigner := &llsig.BlsMultiSigner{Hasher: hasher}
	llSignerKOSK := &llsig.BlsMultiSignerKOSK{}

	t.Run("with rogue key prevention", func(t *testing.T) {
		multiSigner, pubKeys, aggSig := createAggregatedSigBLS(msg, llSigner, t)
		// make sig invalid
		aggSig[len(aggSig)-1] = aggSig[len(aggSig)-1] ^ 255
		err := multiSigner.VerifyAggregatedSig(pubKeys, msg, aggSig)

		assert.NotNil(t, err)
	})
	t.Run("with KOSK", func(t *testing.T) {
		multiSigner, pubKeys, aggSig := createAggregatedSigBLS(msg, llSignerKOSK, t)
		// make sig invalid
		aggSig[len(aggSig)-1] = aggSig[len(aggSig)-1] ^ 255
		err := multiSigner.VerifyAggregatedSig(pubKeys, msg, aggSig)

		assert.NotNil(t, err)
	})
}

func Test_ConvertBytesToPubKeys(t *testing.T) {
	t.Parallel()

	numSigners := 4
	pubKeysBytes, kg := generateMultiSigParamsBLS(numSigners)
	t.Run("empty keys should err", func(t *testing.T) {
		pubKeys, err := multisig.ConvertBytesToPubKeys([][]byte{}, kg)
		require.Nil(t, pubKeys)
		require.Equal(t, crypto.ErrNilPublicKeys, err)
	})
	t.Run("one nil pubKey should err", func(t *testing.T) {
		pubKeys, err := multisig.ConvertBytesToPubKeys([][]byte{nil}, kg)
		require.Nil(t, pubKeys)
		require.Equal(t, crypto.ErrEmptyPubKey, err)
	})
	t.Run("valid params", func(t *testing.T) {
		pubKeys, err := multisig.ConvertBytesToPubKeys(pubKeysBytes, kg)
		require.Nil(t, err)
		require.Len(t, pubKeys, numSigners)
	})
}

func Test_ConvertBytesToPubKey(t *testing.T) {
	t.Parallel()

	numSigners := 4
	pubKeysBytes, kg := generateMultiSigParamsBLS(numSigners)
	t.Run("empty pub key should err", func(t *testing.T) {
		pubKey, err := multisig.ConvertBytesToPubKey([]byte{}, kg)
		require.Nil(t, pubKey)
		require.Equal(t, crypto.ErrEmptyPubKey, err)
	})
	t.Run("nil key generator should err", func(t *testing.T) {
		pubKey, err := multisig.ConvertBytesToPubKey(pubKeysBytes[0], nil)
		require.Nil(t, pubKey)
		require.Equal(t, crypto.ErrNilKeyGenerator, err)
	})
	t.Run("valid params", func(t *testing.T) {
		pubKey, err := multisig.ConvertBytesToPubKey(pubKeysBytes[0], kg)
		require.Nil(t, err)
		require.NotNil(t, pubKey)
	})
}

func Test_ConvertBytesToPrivateKey(t *testing.T) {
	t.Parallel()

	numSigners := 1
	privKeys, _, kg := generateMultiSigParamsBLSWithPrivateKeys(numSigners)
	t.Run("nil private key should err", func(t *testing.T) {
		privKey, err := multisig.ConvertBytesToPrivateKey(nil, kg)
		require.Nil(t, privKey)
		require.Equal(t, crypto.ErrNilPrivateKey, err)
	})
	t.Run("nil key generator should err", func(t *testing.T) {
		privKey, err := multisig.ConvertBytesToPrivateKey(privKeys[0], nil)
		require.Nil(t, privKey)
		require.Equal(t, crypto.ErrNilKeyGenerator, err)
	})
	t.Run("valid params", func(t *testing.T) {
		privKey, err := multisig.ConvertBytesToPrivateKey(privKeys[0], kg)
		require.Nil(t, err)
		require.NotNil(t, privKey)
	})
}
