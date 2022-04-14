package dh

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand"

	"github.com/txchat/chatcipher/crypto"
	"github.com/txchat/chatcipher/crypto/ecies"
)

const (
	aesNonceLength = 12
	aesKeyLength   = 32 // in bytes
)

//GenerateDHSessionKey : 根据本端私钥和对端公钥生成ECDH会话密钥
func GenerateDHSessionKey(privateKey, publicKey string) ([]byte, error) {
	ecdsaPrivateKey, error := crypto.HexToECDSA(privateKey)
	if nil != error {
		return nil, error
	}
	eciesPrivateKey := ecies.ImportECDSA(ecdsaPrivateKey)

	ecdsaPublicKey, error := crypto.HexToECDSAPublic(publicKey)
	if nil != error {
		return nil, error
	}
	eciesPublicKey := ecies.ImportECDSAPublic(ecdsaPublicKey)

	return eciesPrivateKey.GenerateShared(eciesPublicKey, sskLen, sskLen)
}

//EncryptWithDHKeyPair : 根据用户的私钥和对端的公钥生成ecdh密钥并进行对称加密
func EncryptWithDHKeyPair(privateKey, publicKey string, plaintext []byte) ([]byte, error) {
	key, error := GenerateDHSessionKey(privateKey, publicKey)
	if nil != error {
		return nil, error
	}

	return encryptSymmetric(key, plaintext)
}

//DecryptWithDHKeyPair : 根据用户的私钥和对端的公钥生成ecdh密钥并进行对称解密
func DecryptWithDHKeyPair(privateKey, publicKey string, cyphertext []byte) ([]byte, error) {
	key, error := GenerateDHSessionKey(privateKey, publicKey)
	if nil != error {
		return nil, error
	}

	return decryptSymmetric(key, cyphertext)
}

func EncryptSymmetric(key string, plaintext []byte) ([]byte, error) {
	keySlice, err := crypto.Hex2byte(key)
	if nil != err {
		return nil, err
	}

	return encryptSymmetric(keySlice, plaintext)
}

//encryptSymmetric : 对称加密
func encryptSymmetric(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	salt, err := crypto.GenerateSecureRandomData(aesNonceLength)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	encrypted, err := aesgcm.Seal(nil, salt, plaintext, nil), nil
	if err != nil {
		return nil, err
	}

	return append(encrypted, salt...), nil
}

func DecryptSymmetric(key string, cyphertext []byte) ([]byte, error) {
	keySlice, err := crypto.Hex2byte(key)
	if nil != err {
		return nil, err
	}

	return decryptSymmetric(keySlice, cyphertext)
}

//decryptSymmetric : 对称解密
func decryptSymmetric(key []byte, cyphertext []byte) ([]byte, error) {
	// symmetric messages are expected to contain the 12-byte nonce at the end of the payload
	if len(cyphertext) < aesNonceLength {
		return nil, errors.New("missing salt or invalid payload in symmetric message")
	}
	salt := cyphertext[len(cyphertext)-aesNonceLength:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	decrypted, err := aesgcm.Open(nil, salt, cyphertext[:len(cyphertext)-aesNonceLength], nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// GenerateSymKey: generates a random symmetric key
func GenerateSymKey() (string, error) {
	key, err := generateSecureRandomData(aesKeyLength)
	if err != nil {
		return "", err
	} else if !validateDataIntegrity(key, aesKeyLength) {
		return "", fmt.Errorf("error in GenerateSymKey: crypto/rand failed to generate random data")
	}

	return crypto.Bytes2Hex(key), nil
}

// generateSecureRandomData generates random data where extra security is required.
// The purpose of this function is to prevent some bugs in software or in hardware
// from delivering not-very-random data. This is especially useful for AES nonce,
// where true randomness does not really matter, but it is very important to have
// a unique nonce for every message.
func generateSecureRandomData(length int) ([]byte, error) {
	x := make([]byte, length)
	y := make([]byte, length)
	res := make([]byte, length)

	_, err := crand.Read(x)
	if err != nil {
		return nil, err
	} else if !validateDataIntegrity(x, length) {
		return nil, errors.New("crypto/rand failed to generate secure random data")
	}
	_, err = mrand.Read(y)
	if err != nil {
		return nil, err
	} else if !validateDataIntegrity(y, length) {
		return nil, errors.New("math/rand failed to generate secure random data")
	}
	for i := 0; i < length; i++ {
		res[i] = x[i] ^ y[i]
	}
	if !validateDataIntegrity(res, length) {
		return nil, errors.New("failed to generate secure random data")
	}
	return res, nil
}

// validateDataIntegrity returns false if the data have the wrong or contains all zeros,
// which is the simplest and the most common bug.
func validateDataIntegrity(k []byte, expectedSize int) bool {
	if len(k) != expectedSize {
		return false
	}
	if expectedSize > 3 && containsOnlyZeros(k) {
		return false
	}
	return true
}

// containsOnlyZeros checks if the data contain only zeros.
func containsOnlyZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
