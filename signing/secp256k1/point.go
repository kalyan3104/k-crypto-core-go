package secp256k1

import (
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/kalyan3104/k-core/core/check"
	crypto "github.com/kalyan3104/k-crypto-core-go"
)

var _ crypto.Point = (*secp256k1Point)(nil)

type secp256k1Point struct {
	secp.PublicKey
}

// GetUnderlyingObj returns the object the implementation wraps
func (bp *secp256k1Point) GetUnderlyingObj() interface{} {
	return bp.PublicKey
}

// MarshalBinary transforms the Point into a byte array
func (bp *secp256k1Point) MarshalBinary() ([]byte, error) {
	return bp.PublicKey.SerializeCompressed(), nil
}

// UnmarshalBinary recreates the Point from a byte array
func (bp *secp256k1Point) UnmarshalBinary(key []byte) error {
	pubKey, err := secp.ParsePubKey(key)
	if err != nil {
		return err
	}

	bp.PublicKey = *pubKey

	return nil
}

// Clone returns a clone of the receiver.
func (bp *secp256k1Point) Clone() crypto.Point {
	if bp == nil {
		return nil
	}

	p2 := &secp256k1Point{}

	pointBytes, _ := bp.MarshalBinary()
	err := p2.UnmarshalBinary(pointBytes)
	if err != nil {
		log.Error("Clone: failed to unmarshal binary", "error", err)
		return nil
	}

	return p2
}

// Equal tests if receiver is equal with the Point p given as parameter.
// Both Points need to be derived from the same Group
func (bp *secp256k1Point) Equal(p crypto.Point) (bool, error) {
	if check.IfNil(p) {
		return false, crypto.ErrNilParam
	}

	point, ok := p.(*secp256k1Point)
	if !ok {
		return false, crypto.ErrInvalidPublicKey
	}

	return point.IsEqual(&bp.PublicKey), nil
}

// Set sets the receiver equal to another Point p.
func (bp *secp256k1Point) Set(p crypto.Point) error {
	if check.IfNil(p) {
		return crypto.ErrNilParam
	}

	point, ok := p.(*secp256k1Point)
	if !ok {
		return crypto.ErrInvalidPublicKey
	}

	bp.PublicKey = point.PublicKey

	return nil
}

// Null returns nil
func (bp *secp256k1Point) Null() crypto.Point {
	log.Error("secp256k1Point", "Null not implemented")

	return nil
}

// Add returns nil
func (bp *secp256k1Point) Add(_ crypto.Point) (crypto.Point, error) {
	return nil, crypto.ErrNotImplemented
}

// Sub returns nil
func (bp *secp256k1Point) Sub(_ crypto.Point) (crypto.Point, error) {
	return nil, crypto.ErrNotImplemented
}

// Neg returns nil
func (bp *secp256k1Point) Neg() crypto.Point {
	log.Error("secp256k1Point", "Neg not implemented")

	return nil
}

// Mul returns nil
func (bp *secp256k1Point) Mul(_ crypto.Scalar) (crypto.Point, error) {
	return nil, crypto.ErrNotImplemented
}

// Pick returns nil
func (bp *secp256k1Point) Pick() (crypto.Point, error) {
	return nil, crypto.ErrNotImplemented
}

// IsInterfaceNil returns true if there is no value under the interface
func (bp *secp256k1Point) IsInterfaceNil() bool {
	return bp == nil
}
