package multisig

import (
	"github.com/herumi/bls-go-binary/bls"
	"github.com/kalyan3104/k-core/core/check"
	crypto "github.com/kalyan3104/k-crypto-core-go"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl/singlesig"
)

var _ crypto.LowLevelSignerBLS = (*BlsMultiSignerKOSK)(nil)

// BlsMultiSignerKOSK provides an implementation of the crypto.LowLevelSignerBLS interface
type BlsMultiSignerKOSK struct {
	singlesig.BlsSingleSigner
}

// SignShare produces a BLS signature share (single BLS signature) over a given message
func (bms *BlsMultiSignerKOSK) SignShare(privKey crypto.PrivateKey, message []byte) ([]byte, error) {
	return bms.Sign(privKey, message)
}

// VerifySigShare verifies a BLS signature share (single BLS signature) over a given message
func (bms *BlsMultiSignerKOSK) VerifySigShare(pubKey crypto.PublicKey, message []byte, sig []byte) error {
	return bms.Verify(pubKey, message, sig)
}

// VerifySigBytes provides an "cheap" integrity check of a signature given as a byte array
// It does not validate the signature over a message, only verifies that it is a signature
func (bms *BlsMultiSignerKOSK) VerifySigBytes(_ crypto.Suite, sig []byte) error {
	if len(sig) == 0 {
		return crypto.ErrNilSignature
	}

	_, err := sigBytesToPoint(sig)

	return err
}

// AggregateSignatures produces an aggregation of single BLS signatures over the same message
func (bms *BlsMultiSignerKOSK) AggregateSignatures(
	suite crypto.Suite,
	signatures [][]byte,
	pubKeysSigners []crypto.PublicKey,
) ([]byte, error) {
	if check.IfNil(suite) {
		return nil, crypto.ErrNilSuite
	}
	if len(signatures) == 0 {
		return nil, crypto.ErrNilSignaturesList
	}
	if len(pubKeysSigners) == 0 {
		return nil, crypto.ErrNilPublicKeys
	}
	_, ok := suite.GetUnderlyingSuite().(*mcl.SuiteBLS12)
	if !ok {
		return nil, crypto.ErrInvalidSuite
	}

	var err error
	var sigBLS *bls.Sign
	sigsBLS := make([]bls.Sign, 0, len(signatures))
	for _, sig := range signatures {
		sigBLS, err = sigBytesToSig(sig)
		if err != nil {
			return nil, err
		}

		sigsBLS = append(sigsBLS, *sigBLS)
	}

	aggSigBLS := &bls.Sign{}
	aggSigBLS.Aggregate(sigsBLS)

	return aggSigBLS.Serialize(), nil
}

// VerifyAggregatedSig verifies if a BLS aggregated signature is valid over a given message
func (bms *BlsMultiSignerKOSK) VerifyAggregatedSig(
	suite crypto.Suite,
	pubKeys []crypto.PublicKey,
	aggSigBytes []byte,
	msg []byte,
) error {
	if check.IfNil(suite) {
		return crypto.ErrNilSuite
	}
	if len(pubKeys) == 0 {
		return crypto.ErrNilPublicKeys
	}
	if len(aggSigBytes) == 0 {
		return crypto.ErrNilSignature
	}
	if len(msg) == 0 {
		return crypto.ErrNilMessage
	}

	_, ok := suite.GetUnderlyingSuite().(*mcl.SuiteBLS12)
	if !ok {
		return crypto.ErrInvalidSuite
	}

	pubKeysBLS, err := pubKeysCryptoToBLS(pubKeys)
	if err != nil {
		return err
	}

	aggSig := &bls.Sign{}
	err = aggSig.Deserialize(aggSigBytes)
	if err != nil {
		return err
	}

	res := aggSig.FastAggregateVerify(pubKeysBLS, msg)
	if !res {
		return crypto.ErrAggSigNotValid
	}

	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (bms *BlsMultiSignerKOSK) IsInterfaceNil() bool {
	return bms == nil
}
