package walletapi

import (
	"testing"

	"github.com/txchat/chatcipher/crypto"
	"github.com/txchat/chatcipher/service/dh"
)

func Test_EncryptWithSymmKey(t *testing.T) {
	symKey1, _ := dh.GenerateSymKey()
	t.Logf("The 1st symmetric key =%s\n", symKey1)

	plainText := "Symmetric encryption algorithm verification"

	t.Logf("The plain text before encryption is as below\n")
	t.Logf("%s\n\n", plainText)

	cipherText, err := dh.EncryptSymmetric(symKey1, []byte(plainText))
	if nil != err {
		t.Logf("EncryptSymmetric failed,due to %s\n\n", err.Error())
		return
	}

	t.Logf("The ciphered text after encryption is as below\n")
	t.Logf("%s\n\n", string(cipherText))

	plainTextSlice, err := dh.DecryptSymmetric(symKey1, cipherText)
	if nil != err {
		t.Logf("DecryptSymmetric failed,due to %s\n\n", err.Error())
		return
	}

	t.Logf("Succeed to decrypt the cipher text as below\n")
	t.Logf("%s\n", string(plainTextSlice))
}

func Test_EncryptWithDHSessionKey(t *testing.T) {
	ecdsaPriKey1, _ := crypto.GenerateKey()
	PriKey1 := crypto.Bytes2Hex(crypto.FromECDSA(ecdsaPriKey1))
	PubKey1 := crypto.Bytes2Hex(crypto.CompressPubkey(&ecdsaPriKey1.PublicKey))
	t.Logf("The 1st private key =%s\n", PriKey1)
	t.Logf("The 1st public key =%s\n", PubKey1)

	ecdsaPriKey2, _ := crypto.GenerateKey()
	PriKey2 := crypto.Bytes2Hex(crypto.FromECDSA(ecdsaPriKey2))
	PubKey2 := crypto.Bytes2Hex(crypto.CompressPubkey(&ecdsaPriKey2.PublicKey))
	t.Logf("The 2nd private key =%s\n", PriKey2)
	t.Logf("The 2nd public key =%s\n", PubKey2)

	plainText := "DH encryption algorithm verification"

	t.Logf("The plain text before encryption is as below\n")
	t.Logf("%s\n\n", plainText)

	ciphertext, error := dh.EncryptWithDHKeyPair(PriKey1, PubKey2, []byte(plainText))
	if error != nil {
		t.Logf("Filed to do EncryptWithDHKeyPair due to %s\n", error.Error())
		return
	}
	t.Logf("The ciphertext after encryption is as below\n")
	t.Logf("%s\n\n", string(ciphertext))

	plaintextSlice, error2 := dh.DecryptWithDHKeyPair(PriKey2, PubKey1, ciphertext)
	if nil != error2 {
		t.Logf("Filed to do DecryptWithDHKeyPair due to %s\n", error2.Error())
		return
	}

	t.Logf("Succeed to decrypt the cipher text as below\n")
	t.Logf("%s\n", string(plaintextSlice))
}

func Test_PrivatePublickKeyImportExport(t *testing.T) {
	t.Logf("test_privatePublickKeyImportExport...\n")
	publicKey := string("0x02504fa1c28caaf1d5a20fefb87c50a49724ff401043420cb3ba271997eb5a4387")
	privateKey := string("0xcc38546e9e659d15e6b4893f0ab32a06d103931a8230b0bde71459d2b27d6944")

	esdsaPrivateKey, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		t.Logf("Failed to do HexToECDSA with error:%s\n", err.Error())
		return
	}

	pubKeySlice := crypto.CompressPubkey(&esdsaPrivateKey.PublicKey)
	t.Logf("The converted and compressed public key is:%s\n", crypto.Bytes2Hex(pubKeySlice))

	esdsaPublicKey, err := crypto.HexToECDSAPublic(publicKey)
	if err != nil {
		t.Logf("Failed to do HexToECDSAPublic with error:%s\n", err.Error())
		return
	}

	privateKeyBack := crypto.Bytes2Hex(crypto.FromECDSA(esdsaPrivateKey))
	publicKeyBack := crypto.Bytes2Hex(crypto.CompressPubkey(esdsaPublicKey))

	t.Logf("The final private key=%s\n", privateKeyBack)
	t.Logf("The final public  key=%s\n", publicKeyBack)
	t.Log("\n")
}
