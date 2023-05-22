package multisig

import (
	"github.com/kalyan3104/k-core/core/check"
	crypto "github.com/kalyan3104/k-crypto-core-go"
)

var _ crypto.MultiSigner = (*blsMultiSigner)(nil)

type blsMultiSigner struct {
	keyGen   crypto.KeyGenerator
	llSigner crypto.LowLevelSignerBLS
}

// NewBLSMultisig creates a new BLS multi-signer
func NewBLSMultisig(
	llSigner crypto.LowLevelSignerBLS,
	keyGen crypto.KeyGenerator,
) (*blsMultiSigner, error) {
	if check.IfNil(llSigner) {
		return nil, crypto.ErrNilLowLevelSigner
	}
	if check.IfNil(keyGen) {
		return nil, crypto.ErrNilKeyGenerator
	}
	return &blsMultiSigner{
		keyGen:   keyGen,
		llSigner: llSigner,
	}, nil
}

// CreateSignatureShare returns a BLS single signature over the message with the given private key
func (bms *blsMultiSigner) CreateSignatureShare(privateKeyBytes []byte, message []byte) ([]byte, error) {
	privateKey, err := convertBytesToPrivateKey(privateKeyBytes, bms.keyGen)
	if err != nil {
		return nil, err
	}

	return bms.llSigner.SignShare(privateKey, message)
}

// VerifySignatureShare verifies the single signature share with the given message and public key
func (bms *blsMultiSigner) VerifySignatureShare(publicKey []byte, message []byte, sig []byte) error {
	if sig == nil {
		return crypto.ErrNilSignature
	}

	pubKey, err := convertBytesToPubKey(publicKey, bms.keyGen)
	if err != nil {
		return err
	}

	return bms.llSigner.VerifySigShare(pubKey, message, sig)
}

// AggregateSigs aggregates the received signatures, corresponding to the given public keys into one signature
func (bms *blsMultiSigner) AggregateSigs(pubKeysSigners [][]byte, signatures [][]byte) ([]byte, error) {
	if len(pubKeysSigners) != len(signatures) {
		return nil, crypto.ErrInvalidParam
	}

	pubKeys, err := convertBytesToPubKeys(pubKeysSigners, bms.keyGen)
	if err != nil {
		return nil, err
	}

	return bms.llSigner.AggregateSignatures(bms.keyGen.Suite(), signatures, pubKeys)
}

// VerifyAggregatedSig verifies the aggregated signature validity with respect to the aggregated public keys and given message
func (bms *blsMultiSigner) VerifyAggregatedSig(pubKeysSigners [][]byte, message []byte, aggSig []byte) error {
	pubKeys, err := convertBytesToPubKeys(pubKeysSigners, bms.keyGen)
	if err != nil {
		return err
	}

	return bms.llSigner.VerifyAggregatedSig(bms.keyGen.Suite(), pubKeys, aggSig, message)
}

// IsInterfaceNil returns true if there is no value under the interface
func (bms *blsMultiSigner) IsInterfaceNil() bool {
	return bms == nil
}
