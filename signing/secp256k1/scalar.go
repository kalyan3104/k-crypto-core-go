package secp256k1

import (
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/kalyan3104/k-core/core/check"
	crypto "github.com/kalyan3104/k-crypto-core-go"
)

var _ crypto.Scalar = (*secp256k1Scalar)(nil)

type secp256k1Scalar struct {
	secp.PrivateKey
}

// GetUnderlyingObj returns the object the implementation wraps
func (e *secp256k1Scalar) GetUnderlyingObj() interface{} {
	return e.PrivateKey
}

// MarshalBinary transforms the Scalar into a byte array
func (e *secp256k1Scalar) MarshalBinary() ([]byte, error) {
	return e.PrivateKey.Serialize(), nil
}

// UnmarshalBinary recreates the Scalar from a byte array
func (e *secp256k1Scalar) UnmarshalBinary(key []byte) error {
	privKey := secp.PrivKeyFromBytes(key)

	e.PrivateKey = *privKey

	return nil
}

// Equal tests if receiver is equal with the scalar s given as parameter.
// Both scalars need to be derived from the same Group
func (e *secp256k1Scalar) Equal(s crypto.Scalar) (bool, error) {
	if check.IfNil(s) {
		return false, crypto.ErrNilParam
	}

	scalar, ok := s.(*secp256k1Scalar)
	if !ok {
		return false, crypto.ErrInvalidPrivateKey
	}

	return e.PrivateKey.PubKey().IsEqual(scalar.PubKey()), nil
}

// Set sets the receiver to Scalar s given as parameter
func (e *secp256k1Scalar) Set(s crypto.Scalar) error {
	if check.IfNil(s) {
		return crypto.ErrNilParam
	}

	scalar, ok := s.(*secp256k1Scalar)
	if !ok {
		return crypto.ErrInvalidPrivateKey
	}

	e.PrivateKey = scalar.PrivateKey

	return nil
}

// Clone creates a new Scalar with same value as receiver
func (e *secp256k1Scalar) Clone() crypto.Scalar {
	if e == nil {
		return nil
	}

	e2 := &secp256k1Scalar{}

	scalarBytes, _ := e.MarshalBinary()
	_ = e2.UnmarshalBinary(scalarBytes)

	return e2
}

// SetInt64 does nothing
func (e *secp256k1Scalar) SetInt64(_ int64) {
	log.Error("secp256k1Scalar", "SetInt64 not implemented")
}

// Zero returns nil
func (e *secp256k1Scalar) Zero() crypto.Scalar {
	log.Error("secp256k1Scalar", "Zero not implemented")

	return nil
}

// Add returns nil
func (e *secp256k1Scalar) Add(_ crypto.Scalar) (crypto.Scalar, error) {
	return nil, crypto.ErrNotImplemented
}

// Sub returns nil
func (e *secp256k1Scalar) Sub(_ crypto.Scalar) (crypto.Scalar, error) {
	return nil, crypto.ErrNotImplemented
}

// Neg returns nil
func (e *secp256k1Scalar) Neg() crypto.Scalar {
	log.Error("secp256k1Scalar", "Neg not implemented")

	return nil
}

// One returns nil
func (e *secp256k1Scalar) One() crypto.Scalar {
	log.Error("secp256k1Scalar", "One not implemented")

	return nil
}

// Mul returns nil
func (e *secp256k1Scalar) Mul(_ crypto.Scalar) (crypto.Scalar, error) {
	return nil, crypto.ErrNotImplemented
}

// Div returns nil
func (e *secp256k1Scalar) Div(_ crypto.Scalar) (crypto.Scalar, error) {
	return nil, crypto.ErrNotImplemented
}

// Inv returns nil
func (e *secp256k1Scalar) Inv(_ crypto.Scalar) (crypto.Scalar, error) {
	return nil, crypto.ErrNotImplemented
}

// Pick returns nil
func (e *secp256k1Scalar) Pick() (crypto.Scalar, error) {
	return nil, crypto.ErrNotImplemented
}

// SetBytes returns nil
func (e *secp256k1Scalar) SetBytes(_ []byte) (crypto.Scalar, error) {
	return nil, crypto.ErrNotImplemented
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *secp256k1Scalar) IsInterfaceNil() bool {
	return e == nil
}
