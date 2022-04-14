package test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/FactomProject/go-bip32"
	"github.com/FactomProject/go-bip39"
	"github.com/piotrnar/gocoin/lib/btc"
	"github.com/txchat/chatcipher/bipwallet"
)

func TestBipwalletSeed(t *testing.T) {
	mnem, err := bipwallet.NewMnemonicString(1, 256) //这个函数各个版本通用
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("TestBipwalletSeed助记词:", mnem)
	//选择币种，填入种子创建wallet对象
	//seedBytes := bip39.NewSeed("爱 企 硅 浅 哈 丝 形 亭 事 辛 剥 辅 劣 史 谢 舒 庆 惜 推 峡 丧 战 驾 桃", "fuzamie33")
	//seedBytes := bip39.NewSeed("章 环 浇 劣 狠 屈 罩 偿 梅 束 归 拉 恩 消 些", "")
	seedBytes := bip39.NewSeed(mnem)
	masterKey, err := bip32.NewMasterKey(seedBytes)
	if err != nil {
		t.Error(err)
		return
	}
	privhex := hex.EncodeToString(masterKey.Key)
	t.Log("privkey:", privhex, len(privhex))
	t.Log("privkey-1:", masterKey.String(), len(masterKey.String()))
	t.Log("pubkey-1:", masterKey.PublicKey())

	//通过bip32 生成child key

	childpubkey, err := masterKey.PublicKey().NewChildKey(1)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("Child.2:", childpubkey.String())

	wallet, err := btc.StringWallet(masterKey.PublicKey().String())
	if err != nil {
		t.Error(err)
		return
	}
	StringChildPub := wallet.Child(2)
	t.Log("child.2:", StringChildPub)

	t.Log("chaild.2.2:", btc.StringChild(masterKey.PublicKey().String(), 2))
}
