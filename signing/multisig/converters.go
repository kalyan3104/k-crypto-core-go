package multisig

import (
	"github.com/kalyan3104/k-core/core/check"
	crypto "github.com/kalyan3104/k-crypto-core-go"
)

func convertBytesToPubKeys(pubKeys [][]byte, kg crypto.KeyGenerator) ([]crypto.PublicKey, error) {
	if len(pubKeys) == 0 {
		return nil, crypto.ErrNilPublicKeys
	}
	pk := make([]crypto.PublicKey, 0, len(pubKeys))
	for _, pubKeyStr := range pubKeys {
		pubKey, err := convertBytesToPubKey(pubKeyStr, kg)
		if err != nil {
			return nil, err
		}

		pk = append(pk, pubKey)
	}
	return pk, nil
}

func convertBytesToPubKey(pubKeyBytes []byte, kg crypto.KeyGenerator) (crypto.PublicKey, error) {
	if len(pubKeyBytes) == 0 {
		return nil, crypto.ErrEmptyPubKey
	}
	if check.IfNil(kg) {
		return nil, crypto.ErrNilKeyGenerator
	}

	return kg.PublicKeyFromByteArray(pubKeyBytes)
}

func convertBytesToPrivateKey(privateKey []byte, kg crypto.KeyGenerator) (crypto.PrivateKey, error) {
	if len(privateKey) == 0 {
		return nil, crypto.ErrNilPrivateKey
	}
	if check.IfNil(kg) {
		return nil, crypto.ErrNilKeyGenerator
	}

	return kg.PrivateKeyFromByteArray(privateKey)
}
