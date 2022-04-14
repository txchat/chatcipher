package walletapi

import (
	"encoding/hex"
	"github.com/txchat/chatcipher/common/address"
	"testing"
)

func Test_PublickToAddress(t *testing.T) {
	pub, err := hex.DecodeString("0241d2ae704b5666d8b53dfb27b3df687d6f440ef1ed41bedfd994411baa1f4e25")
	if err != nil {
		t.Error(err)
		return
	}
	if address.PublicKeyToAddress(address.NormalVer, pub) != "1NQSfNVefAf7yxQZEGxSbqc8NFBQRbRLWj" {
		t.Error("failed")
		return
	}
	t.Log("success")
}

func Test_ChatSign(t *testing.T) {
	msg := []byte("count%3D40%26index%3D%26mainAddress%3D1JoFzozbxvst22c2K7MBYwQGjCaMZbC5Qm%26time%3D1581594811061")
	privateKey, err := hex.DecodeString("2be91095f403d219060d257d910b5eada78a17b5a525897c387be4de1993dfb7")
	if err != nil {
		t.Error(err)
		return
	}
	sig := ChatSign(msg, privateKey)
	t.Log(hex.EncodeToString(sig))
}
