package dh

import (
	"crypto/aes"
	_ "crypto/aes"
	"crypto/cipher"
	_ "crypto/cipher"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/txchat/chatcipher/crypto"
)

//encryptSymmetric : 对称加密
func myEncryptSymmetric(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	salt, err := crypto.GenerateSecureRandomData(aesNonceLength)
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	encrypted, err := aesgcm.Seal(nil, salt, plaintext, nil), nil
	if err != nil {
		return nil, nil, err
	}

	return append(encrypted, salt...), salt, nil
}

func Test_EncryptSymmetric(t *testing.T) {
	key, err := hex.DecodeString("9eb770272e9297696f60ac3871330fe3ce61d8bcfa42aad3fa745b98bc5d8bf6")
	if err != nil {
		t.Error(err)
		return
	}

	ret, salt, err := myEncryptSymmetric(key, []byte("你好"))
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(fmt.Sprintf("salt is : %v", hex.EncodeToString(salt)))

	str := hex.EncodeToString(ret)
	t.Log(fmt.Sprintf("result is : %v", str))
	return
}

func Test_DecryptSymmetric(t *testing.T) {
	key, err := hex.DecodeString("9eb770272e9297696f60ac3871330fe3ce61d8bcfa42aad3fa745b98bc5d8bf6")
	if err != nil {
		t.Error(err)
		return
	}

	//val, err := hex.DecodeString("4cf4cce971f7e9e9def6e1142327b2a0d3502d4d827788ae4caf01fc2cce1db184a992")
	val, err := hex.DecodeString("487b999579c99a5066f751a4e06762c60caa97ee4b3f2fa5fa6ac3562310d05dc45d")
	if err != nil {
		t.Error(err)
		return
	}

	ret, err := decryptSymmetric(key, val)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(fmt.Sprintf("result is : %v", string(ret)))
	t.Log(fmt.Sprintf("result is : %v", ret))
	return
}
