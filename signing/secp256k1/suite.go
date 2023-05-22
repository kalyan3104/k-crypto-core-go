package secp256k1

import (
	"crypto/cipher"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	logger "github.com/kalyan3104/k-core-logger-go"
	crypto "github.com/kalyan3104/k-crypto-core-go"
)

var log = logger.GetOrCreate("crypto/signing/secp256k1")

var _ crypto.Group = (*secp256k1Suite)(nil)
var _ crypto.Random = (*secp256k1Suite)(nil)
var _ crypto.Suite = (*secp256k1Suite)(nil)

// Secp256k1Str suite string name
const Secp256k1Str = "secp256k1"

// These constants define the lengths of serialized public keys.
const (
	PrivKeyBytesLen          = 32
	PubKeyBytesLenCompressed = 33
)

type secp256k1Suite struct{}

// NewSecp256k1 returns a wrapper over secp256k1 suite
func NewSecp256k1() *secp256k1Suite {
	return &secp256k1Suite{}
}

// CreateKeyPair creates a scalar and a point pair that can be used in asymmetric cryptography
func (s *secp256k1Suite) CreateKeyPair() (crypto.Scalar, crypto.Point) {
	privKey, err := secp.GeneratePrivateKey()
	if err != nil {
		panic("could not create secp256k1 key pair: " + err.Error())
	}

	return &secp256k1Scalar{*privKey}, &secp256k1Point{*privKey.PubKey()}
}

// String returns the string for the group
func (s *secp256k1Suite) String() string {
	return Secp256k1Str
}

// ScalarLen returns the maximum length of scalars in bytes
func (s *secp256k1Suite) ScalarLen() int {
	return PrivKeyBytesLen
}

// CreateScalar creates a new Scalar
func (s *secp256k1Suite) CreateScalar() crypto.Scalar {
	privKey, err := secp.GeneratePrivateKey()
	if err != nil {
		panic("could not create secp256k1 key pair: " + err.Error())
	}

	return &secp256k1Scalar{*privKey}
}

// PointLen returns the max length of point in nb of bytes
func (s *secp256k1Suite) PointLen() int {
	return PubKeyBytesLenCompressed
}

// CreatePoint creates a new point
func (s *secp256k1Suite) CreatePoint() crypto.Point {
	_, publicKey := s.CreateKeyPair()
	return publicKey
}

// CreatePointForScalar creates a new point corresponding to the given scalar
func (s *secp256k1Suite) CreatePointForScalar(scalar crypto.Scalar) (crypto.Point, error) {
	privateKey, ok := scalar.GetUnderlyingObj().(secp.PrivateKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	return &secp256k1Point{*privateKey.PubKey()}, nil
}

// CheckPointValid returns nil
func (s *secp256k1Suite) CheckPointValid(pointBytes []byte) error {
	if len(pointBytes) != s.PointLen() {
		return crypto.ErrInvalidParam
	}

	point := s.CreatePoint()
	err := point.UnmarshalBinary(pointBytes)
	if err != nil {
		return err
	}

	return nil
}

// RandomStream returns nil
func (s *secp256k1Suite) RandomStream() cipher.Stream {
	log.Error("secp256k1Suite", "RandomStream not implemented")

	return nil
}

// GetUnderlyingSuite returns nil
func (s *secp256k1Suite) GetUnderlyingSuite() interface{} {
	log.Error("secp256k1Suite", "GetUnderlyingSuite not implemented")

	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *secp256k1Suite) IsInterfaceNil() bool {
	return s == nil
}
