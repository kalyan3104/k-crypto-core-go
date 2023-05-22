package multisig

import crypto "github.com/kalyan3104/k-crypto-core-go"

// ConvertBytesToPubKeys -
func ConvertBytesToPubKeys(pubKeys [][]byte, kg crypto.KeyGenerator) ([]crypto.PublicKey, error) {
	return convertBytesToPubKeys(pubKeys, kg)
}

// ConvertBytesToPubKey -
func ConvertBytesToPubKey(pubKeyBytes []byte, kg crypto.KeyGenerator) (crypto.PublicKey, error) {
	return convertBytesToPubKey(pubKeyBytes, kg)
}

// ConvertBytesToPrivateKey -
func ConvertBytesToPrivateKey(privateKey []byte, kg crypto.KeyGenerator) (crypto.PrivateKey, error) {
	return convertBytesToPrivateKey(privateKey, kg)
}
