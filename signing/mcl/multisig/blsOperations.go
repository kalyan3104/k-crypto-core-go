package multisig

import (
	"encoding/hex"

	"github.com/herumi/bls-go-binary/bls"
	"github.com/kalyan3104/k-core/core/check"
	crypto "github.com/kalyan3104/k-crypto-core-go"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl"
	"github.com/kalyan3104/k-crypto-core-go/signing/mcl/singlesig"
)

// scalarMulPk returns the result of multiplying a scalar given as a bytes array, with a BLS public key (point)
func scalarMulPk(suite crypto.Suite, scalarBytes []byte, pk crypto.Point) (crypto.Point, error) {
	if pk == nil {
		return nil, crypto.ErrNilParam
	}

	scalar, err := createScalar(suite, scalarBytes)
	if err != nil {
		return nil, err
	}

	return pk.Mul(scalar)
}

// scalarMulSig returns the result of multiplication of a scalar with a BLS signature
func scalarMulSig(suite crypto.Suite, scalarBytes []byte, sigPoint *mcl.PointG1) (*mcl.PointG1, error) {
	if len(scalarBytes) == 0 {
		return nil, crypto.ErrNilParam
	}
	if sigPoint == nil {
		return nil, crypto.ErrNilSignature
	}
	if check.IfNil(suite) {
		return nil, crypto.ErrNilSuite
	}

	scalar := suite.CreateScalar()
	sc, ok := scalar.(*mcl.Scalar)
	if !ok {
		return nil, crypto.ErrInvalidScalar
	}

	err := sc.Scalar.SetString(hex.EncodeToString(scalarBytes), 16)
	if err != nil {
		return nil, crypto.ErrInvalidScalar
	}

	resPoint, err := sigPoint.Mul(scalar)
	if err != nil {
		return nil, err
	}

	resPointG1, ok := resPoint.(*mcl.PointG1)
	if !ok {
		return nil, crypto.ErrInvalidPoint
	}

	return resPointG1, nil
}

// sigBytesToPoint returns the point corresponding to the BLS signature byte array
func sigBytesToPoint(sig []byte) (crypto.Point, error) {
	sigBLS, err := sigBytesToSig(sig)
	if err != nil {
		return nil, err
	}

	pG1 := mcl.NewPointG1()
	pG1.G1 = bls.CastFromSign(sigBLS)

	return pG1, nil
}

func sigBytesToSig(sig []byte) (*bls.Sign, error) {
	sigBLS := &bls.Sign{}
	if len(sig) == 0 {
		return nil, crypto.ErrNilSignature
	}
	err := sigBLS.Deserialize(sig)
	if err != nil {
		return nil, err
	}

	if !singlesig.IsSigValidPoint(sigBLS) {
		return nil, crypto.ErrBLSInvalidSignature
	}

	return sigBLS, nil
}

func pubKeysCryptoToBLS(pubKeys []crypto.PublicKey) ([]bls.PublicKey, error) {
	pubKeysBLS := make([]bls.PublicKey, 0, len(pubKeys))
	for _, pubKey := range pubKeys {
		pubKeyBLS, err := pubKeyCryptoToBLS(pubKey)
		if err != nil {
			return nil, err
		}

		pubKeysBLS = append(pubKeysBLS, *pubKeyBLS)
	}

	return pubKeysBLS, nil
}

func pubKeyCryptoToBLS(pubKey crypto.PublicKey) (*bls.PublicKey, error) {
	pubKeyPoint := pubKey.Point()
	pubKeyG2, ok := pubKeyPoint.GetUnderlyingObj().(*bls.G2)
	if !ok {
		return nil, crypto.ErrInvalidPoint
	}

	pubKeyBLS := *bls.CastToPublicKey(pubKeyG2)

	return &pubKeyBLS, nil
}

// createScalar creates crypto.Scalar from a 32 len byte array
func createScalar(suite crypto.Suite, scalarBytes []byte) (crypto.Scalar, error) {
	if check.IfNil(suite) {
		return nil, crypto.ErrNilSuite
	}

	scalar := suite.CreateScalar()
	sc, _ := scalar.(*mcl.Scalar)

	err := sc.Scalar.SetString(hex.EncodeToString(scalarBytes), 16)
	if err != nil {
		return nil, err
	}

	return scalar, nil
}
