package walletapi

import (
	"github.com/txchat/chatcipher/service/dh"
)

//GenerateDHSessionKey : generate the ECDH session key by local private key and endpoint public key
func GenerateDHSessionKey(privateKey, publicKey string) ([]byte, error) {
	return dh.GenerateDHSessionKey(privateKey, publicKey)
}

//EncryptWithDHKeyPair : encrypt the plaintext by ECDH session key that generated by the local private key and endpoint public key
func EncryptWithDHKeyPair(privateKey, publicKey string, plaintext []byte) ([]byte, error) {
	return dh.EncryptWithDHKeyPair(privateKey, publicKey, plaintext)
}

//DecryptWithDHKeyPair : decrypt the encrypted text by ECDH session key that generated by the local private key and endpoint public key
func DecryptWithDHKeyPair(privateKey, publicKey string, cyphertext []byte) ([]byte, error) {
	return dh.DecryptWithDHKeyPair(privateKey, publicKey, cyphertext)
}

func EncryptSymmetric(key string, plaintext []byte) ([]byte, error) {
	return dh.EncryptSymmetric(key, plaintext)
}

func DecryptSymmetric(key string, cyphertext []byte) ([]byte, error) {
	return dh.DecryptSymmetric(key, cyphertext)
}

// GenerateSymKey: generates a random symmetric key
func GenerateSymKey() (string, error) {
	return dh.GenerateSymKey()
}
