package secp256k1_test

import (
	"testing"

	"github.com/kalyan3104/k-core/core/check"
	crypto "github.com/kalyan3104/k-crypto-core-go"
	"github.com/kalyan3104/k-crypto-core-go/mock"
	"github.com/kalyan3104/k-crypto-core-go/signing/secp256k1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecp256k1Suite(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	assert.False(t, check.IfNil(suite))
}

func TestCreateKeys(t *testing.T) {
	t.Parallel()

	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()

		privateKey, publicKey := suite.CreateKeyPair()
		assert.NotNil(t, privateKey)
		assert.NotNil(t, publicKey)
	})

	t.Run("generates different key pairs", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		privateKey, publicKey := suite.CreateKeyPair()
		privateKey2, publicKey2 := suite.CreateKeyPair()

		assert.NotEqual(t, privateKey, privateKey2)
		assert.NotEqual(t, publicKey, publicKey2)
	})

	t.Run("create scalar", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		privateKey := suite.CreateScalar()
		assert.NotNil(t, privateKey)
	})

	t.Run("create point", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		publicKey := suite.CreatePoint()
		assert.NotNil(t, publicKey)
	})
}

func TestCreatePointForScalar(t *testing.T) {
	t.Parallel()

	t.Run("not expected private key should fail", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		publicKey, err := suite.CreatePointForScalar(&mock.ScalarMock{})
		assert.Equal(t, crypto.ErrInvalidPrivateKey, err)
		assert.Nil(t, publicKey)
	})

	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		privateKey := suite.CreateScalar()
		publicKey, err := suite.CreatePointForScalar(privateKey)
		assert.Nil(t, err)
		assert.NotNil(t, publicKey)
	})
}

func TestCheckPointValid(t *testing.T) {
	t.Parallel()

	t.Run("invalid param", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		err := suite.CheckPointValid([]byte{})
		assert.Equal(t, crypto.ErrInvalidParam, err)
	})

	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		point := suite.CreatePoint()
		poinyBytes, err := point.MarshalBinary()
		require.Nil(t, err)

		err = suite.CheckPointValid(poinyBytes)
		assert.Nil(t, err)
	})
}

func TestString(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	assert.Equal(t, secp256k1.Secp256k1Str, suite.String())
}

func TestScalarLen(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	assert.Equal(t, secp256k1.PrivKeyBytesLen, suite.ScalarLen())
}

func TestPointLen(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	assert.Equal(t, secp256k1.PubKeyBytesLenCompressed, suite.PointLen())
}
