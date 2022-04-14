package test

import (
	"encoding/hex"
	"fmt"

	//"runtime"
	//"time"

	"testing"

	"github.com/txchat/chatcipher/bipwallet"
)

func TestBipwallet(t *testing.T) {
	/*目前暂时支持这些币种创建地址

		    TypeEther:        "ETH",
			TypeEtherClassic: "ETC",
			TypeBitcoin:      "BTC",
			TypeLitecoin:     "LTC",
			TypeZayedcoin:    "ZEC",
			TypeBty:          "BTY",
			TypeYcc:          "YCC",
			TypeDecred:       "DCR",

			//安卓适配版
	    TypeBitcoinString      = "BTC"
		TypeETHString          = "ETH"
		TypeEtherClassicString = "ETC"
		TypeLitecoinString     = "LTC"
		TypeZayedcoinString    = "ZEC"
		TypeBtyString          = "BTY"
		TypeYccString          = "YCC"
		TypeDcrString          = "DCR"
	*/
	//bitsize=128 返回12个单词或者汉子，bitsize+32=160  返回15个单词或者汉子，bitszie=256 返回24个单词或者汉子
	mnem, err := bipwallet.NewMnemonicString(1, 160) //这个函数各个版本通用
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("助记词:", mnem)
	//选择币种，填入种子创建wallet对象DCR
	//章 环 浇 劣 狠 屈 罩 偿 梅 束 归 拉 恩 消 些
	//"giggle catalog lucky message hollow shock opera cover slush burden shallow witness orphan weird glory
	wallet, err := bipwallet.NewWalletFromMnemonic_v2(bipwallet.TypeETHString,
		mnem)
	if err != nil {
		fmt.Println("err:", err.Error())
		return
	}
	var index int = 0
	//通过索引生成Key pair
	//priv, pub, err := wallet.NewKeyPair_v2(index)
	pub, err := wallet.NewKeyPub(index)
	if err != nil {
		fmt.Println("err:", err.Error())
		return
	}
	priv, err := wallet.NewKeyPriv(index)
	if err != nil {
		fmt.Println("err:", err.Error())
		return
	}
	t.Log("privkey:", hex.EncodeToString(priv))
	/*
		//对密码进行加密
		//查看内存
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		t.Log("mem1:", m.Sys/(1024*1024))
		t1 := time.Now().UnixNano()
		pbkdf2key := bipwallet.EncPasswd("123")
		t2 := time.Now().UnixNano()

		t.Log("密码加密后:", hex.EncodeToString(pbkdf2key), "cost time:", (t2-t1)/1e6)
		t.Log("密码哈希:", bipwallet.PasswdHash(pbkdf2key))
		//校验密码
		if bipwallet.CheckPasswd("123", bipwallet.PasswdHash(pbkdf2key)) {
			t.Log("密码校验成功")
		}
		t.Log("mem2:", m.Sys/(1024*1024))
		//对私钥进行加密
		enckey, _ := bipwallet.EncKey(pbkdf2key, priv)

		t.Log("enc key", hex.EncodeToString(enckey))
		//对私钥进行解密
		deckey, _ := bipwallet.DecKey(pbkdf2key, enckey)

		t.Log("dec key", hex.EncodeToString(deckey))

		fmt.Println("pubkey:", hex.EncodeToString(pub))

		t.Log("SEED对助记词进行加密")
		seedeckey, _ := bipwallet.SeedEncKey(pbkdf2key, []byte("giggle catalog lucky message hollow shock opera cover slush burden shallow witness orphan weird glory"))
		t.Log("seedeckey", hex.EncodeToString(seedeckey))

		//对私钥进行解密
		seeddeckey, _ := bipwallet.SeedDecKey(pbkdf2key, seedeckey)

		t.Log("seeddeckey", string(seeddeckey))
	*/

	//通过索引生成对应的地址
	for i := 0; i < 1; i++ {
		address, err := wallet.NewAddress_v2(index)
		if err != nil {
			fmt.Println("err:", err.Error())
			return
		}
		fmt.Println("xxxxxxxaddress:", address)
		address, err = bipwallet.PubToAddress(bipwallet.TypeEther, pub)
		if err != nil {
			fmt.Println("err:", err.Error())
			return
		}

		fmt.Println("PubToAddress:", address)
	}

	pub, err = bipwallet.PrivkeyToPub(bipwallet.TypeEther, priv)
	if err != nil {
		fmt.Println("err:", err.Error())
		return
	}

	fmt.Println("PrivToPub:", hex.EncodeToString(pub))

}
