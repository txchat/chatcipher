package walletapi

import (
	"crypto/ecdsa"

	"github.com/txchat/chatcipher/crypto"
)

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func Bytes2Hex(d []byte) string {
	return crypto.Bytes2Hex(d)
}

func HexTobyte(param string) []byte {
	res, _ := crypto.Hex2byte(param)
	return res
}

func FromECDSA(priv *ecdsa.PrivateKey) []byte {
	return crypto.FromECDSA(priv)
}

func CompressPubkey(pubkey *ecdsa.PublicKey) []byte {
	return crypto.CompressPubkey(pubkey)
}

func HexToECDSA(hexkey string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(hexkey)
}
