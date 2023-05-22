package secp256k1_test

import (
	"testing"

	crypto "github.com/kalyan3104/k-crypto-core-go"
	"github.com/kalyan3104/k-crypto-core-go/mock"
	"github.com/kalyan3104/k-crypto-core-go/signing/secp256k1"
	"github.com/stretchr/testify/assert"
)

func TestPoint_Equal(t *testing.T) {
	t.Parallel()

	t.Run("nil param should error", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		point := suite.CreatePoint()

		_, err := point.Equal(nil)
		assert.Equal(t, crypto.ErrNilParam, err)
	})

	t.Run("invalid pub key, should fail", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		point := suite.CreatePoint()

		ok, err := point.Equal(&mock.PointMock{})
		assert.False(t, ok)
		assert.Equal(t, crypto.ErrInvalidPublicKey, err)
	})

	t.Run("returns false for different keys", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		point := suite.CreatePoint()
		point2 := suite.CreatePoint()

		ok, err := point.Equal(point2)
		assert.Nil(t, err)
		assert.False(t, ok)
	})

	t.Run("returns true for same keys", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		point := suite.CreatePoint()

		ok, err := point.Equal(point)
		assert.Nil(t, err)
		assert.True(t, ok)
	})
}

func TestPoint_Set(t *testing.T) {
	t.Parallel()

	t.Run("nil param should error", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		point := suite.CreatePoint()

		err := point.Set(nil)
		assert.Equal(t, crypto.ErrNilParam, err)
	})

	t.Run("invalid pub key, should fail", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		point := suite.CreatePoint()

		err := point.Set(&mock.PointMock{})
		assert.Equal(t, crypto.ErrInvalidPublicKey, err)
	})

	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		point := suite.CreatePoint()
		point2 := suite.CreatePoint()

		_ = point.Set(point2)
		eq, _ := point.Equal(point2)
		assert.True(t, eq)
	})

	t.Run("it should set by value", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		point := suite.CreatePoint()
		point2 := suite.CreatePoint()
		point3 := suite.CreatePoint()

		_ = point.Set(point2)
		_ = point2.Set(point3)
		eq, _ := point.Equal(point3)
		assert.False(t, eq)
	})
}

func TestPoint_Clone(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	point := suite.CreatePoint()
	point2 := point.Clone()

	eq, _ := point.Equal(point2)
	assert.True(t, eq)
}

func TestPoint_MarshallUnmarshall(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	point := suite.CreatePoint()

	bytes, _ := point.MarshalBinary()
	point2 := suite.CreatePoint()
	_ = point2.UnmarshalBinary(bytes)

	eq, _ := point.Equal(point2)
	assert.True(t, eq)
}

func TestPoint_NotImplementedMethods(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	point := suite.CreatePoint()

	assert.Nil(t, point.Null())
	assert.Nil(t, point.Neg())

	p, err := point.Add(&mock.PointMock{})
	assert.Nil(t, p)
	assert.Equal(t, crypto.ErrNotImplemented, err)

	p, err = point.Sub(&mock.PointMock{})
	assert.Nil(t, p)
	assert.Equal(t, crypto.ErrNotImplemented, err)

	p, err = point.Mul(&mock.ScalarMock{})
	assert.Nil(t, p)
	assert.Equal(t, crypto.ErrNotImplemented, err)

	p, err = point.Pick()
	assert.Nil(t, p)
	assert.Equal(t, crypto.ErrNotImplemented, err)
}
