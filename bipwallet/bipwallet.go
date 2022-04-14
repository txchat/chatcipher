package bipwallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/txchat/chatcipher/bipwallet/bip32"
	"github.com/txchat/chatcipher/bipwallet/bip39"
	"github.com/txchat/chatcipher/bipwallet/bip44"
	"github.com/txchat/chatcipher/bipwallet/transformer"
	_ "github.com/txchat/chatcipher/bipwallet/transformer/btcbase"
	_ "github.com/txchat/chatcipher/bipwallet/transformer/decred"
	_ "github.com/txchat/chatcipher/bipwallet/transformer/ethbase"
	"golang.org/x/crypto/pbkdf2"
)

// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
const (
	TypeBitcoin               uint32 = 0x80000000
	TypeTestnet               uint32 = 0x80000001
	TypeLitecoin              uint32 = 0x80000002
	TypeDogecoin              uint32 = 0x80000003
	TypeReddcoin              uint32 = 0x80000004
	TypeDash                  uint32 = 0x80000005
	TypePeercoin              uint32 = 0x80000006
	TypeNamecoin              uint32 = 0x80000007
	TypeFeathercoin           uint32 = 0x80000008
	TypeCounterparty          uint32 = 0x80000009
	TypeBlackcoin             uint32 = 0x8000000a
	TypeNuShares              uint32 = 0x8000000b
	TypeNuBits                uint32 = 0x8000000c
	TypeMazacoin              uint32 = 0x8000000d
	TypeViacoin               uint32 = 0x8000000e
	TypeClearingHouse         uint32 = 0x8000000f
	TypeRubycoin              uint32 = 0x80000010
	TypeGroestlcoin           uint32 = 0x80000011
	TypeDigitalcoin           uint32 = 0x80000012
	TypeCannacoin             uint32 = 0x80000013
	TypeDigiByte              uint32 = 0x80000014
	TypeOpenAssets            uint32 = 0x80000015
	TypeMonacoin              uint32 = 0x80000016
	TypeClams                 uint32 = 0x80000017
	TypePrimecoin             uint32 = 0x80000018
	TypeNeoscoin              uint32 = 0x80000019
	TypeJumbucks              uint32 = 0x8000001a
	TypeziftrCOIN             uint32 = 0x8000001b
	TypeVertcoin              uint32 = 0x8000001c
	TypeNXT                   uint32 = 0x8000001d
	TypeBurst                 uint32 = 0x8000001e
	TypeMonetaryUnit          uint32 = 0x8000001f
	TypeZoom                  uint32 = 0x80000020
	TypeVpncoin               uint32 = 0x80000021
	TypeCanadaeCoin           uint32 = 0x80000022
	TypeShadowCash            uint32 = 0x80000023
	TypeParkByte              uint32 = 0x80000024
	TypePandacoin             uint32 = 0x80000025
	TypeStartCOIN             uint32 = 0x80000026
	TypeMOIN                  uint32 = 0x80000027
	TypeDecred                uint32 = 0x8000002a
	TypeArgentum              uint32 = 0x8000002D
	TypeGlobalCurrencyReserve uint32 = 0x80000031
	TypeNovacoin              uint32 = 0x80000032
	TypeAsiacoin              uint32 = 0x80000033
	TypeBitcoindark           uint32 = 0x80000034
	TypeDopecoin              uint32 = 0x80000035
	TypeTemplecoin            uint32 = 0x80000036
	TypeAIB                   uint32 = 0x80000037
	TypeEDRCoin               uint32 = 0x80000038
	TypeSyscoin               uint32 = 0x80000039
	TypeSolarcoin             uint32 = 0x8000003a
	TypeSmileycoin            uint32 = 0x8000003b
	TypeEther                 uint32 = 0x8000003c
	TypeEtherClassic          uint32 = 0x8000003d
	TypeOpenChain             uint32 = 0x80000040
	TypeOKCash                uint32 = 0x80000045
	TypeDogecoinDark          uint32 = 0x8000004d
	TypeElectronicGulden      uint32 = 0x8000004e
	TypeClubCoin              uint32 = 0x8000004f
	TypeRichCoin              uint32 = 0x80000050
	TypePotcoin               uint32 = 0x80000051
	TypeQuarkcoin             uint32 = 0x80000052
	TypeTerracoin             uint32 = 0x80000053
	TypeGridcoin              uint32 = 0x80000054
	TypeAuroracoin            uint32 = 0x80000055
	TypeIXCoin                uint32 = 0x80000056
	TypeGulden                uint32 = 0x80000057
	TypeBitBean               uint32 = 0x80000058
	TypeBata                  uint32 = 0x80000059
	TypeMyriadcoin            uint32 = 0x8000005a
	TypeBitSend               uint32 = 0x8000005b
	TypeUnobtanium            uint32 = 0x8000005c
	TypeMasterTrader          uint32 = 0x8000005d
	TypeGoldBlocks            uint32 = 0x8000005e
	TypeSaham                 uint32 = 0x8000005f
	TypeChronos               uint32 = 0x80000060
	TypeUbiquoin              uint32 = 0x80000061
	TypeEvotion               uint32 = 0x80000062
	TypeSaveTheOcean          uint32 = 0x80000063
	TypeBigUp                 uint32 = 0x80000064
	TypeGameCredits           uint32 = 0x80000065
	TypeDollarcoins           uint32 = 0x80000066
	TypeZayedcoin             uint32 = 0x80000067
	TypeDubaicoin             uint32 = 0x80000068
	TypeStratis               uint32 = 0x80000069
	TypeShilling              uint32 = 0x8000006a
	TypePiggyCoin             uint32 = 0x80000076
	TypeMonero                uint32 = 0x80000080
	TypeNavCoin               uint32 = 0x80000082
	TypeFactomFactoids        uint32 = 0x80000083
	TypeFactomEntryCredits    uint32 = 0x80000084
	TypeZcash                 uint32 = 0x80000085
	TypeLisk                  uint32 = 0x80000086
	TypeBty                   uint32 = 0x80003333
	TypeYcc                   uint32 = 0x80003334
)

var TypeTransfer = map[string]uint32{
	"BTC": 0x80000000,
	"ETH": 0x8000003c,
	"ETC": 0x8000003d,
	"LTC": 0x80000002,
	"ZEC": 0x80000067,
	"BTY": 0x80003333,
	"YCC": 0x80003334,
	"DCR": 0x8000002a,
}

const (
	TypeBitcoinString      = "BTC"
	TypeETHString          = "ETH"
	TypeEtherClassicString = "ETC"
	TypeLitecoinString     = "LTC"
	TypeZayedcoinString    = "ZEC"
	TypeBtyString          = "BTY"
	TypeYccString          = "YCC"
	TypeDcrString          = "DCR"
)

var CoinName = map[uint32]string{
	TypeEther:        "ETH",
	TypeEtherClassic: "ETC",
	TypeBitcoin:      "BTC",
	TypeLitecoin:     "LTC",
	TypeZayedcoin:    "ZEC",
	TypeBty:          "BTY",
	TypeYcc:          "YCC",
	TypeDecred:       "DCR",
}

// 支持BIP-44标准的HD钱包
type HDWallet struct {
	CoinType  uint32
	RootSeed  []byte
	MasterKey *bip32.Key
}

// 通过索引生成新的秘钥对

func (w *HDWallet) NewKeyPub(index int) ([]byte, error) {
	key, err := bip44.NewKeyFromMasterKey(w.MasterKey, w.CoinType, bip32.FirstHardenedChild, 0, uint32(index))
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Key, nil
}

func (w *HDWallet) NewKeyPriv(index int) ([]byte, error) {
	key, err := bip44.NewKeyFromMasterKey(w.MasterKey, w.CoinType, bip32.FirstHardenedChild, 0, uint32(index))
	if err != nil {
		return nil, err
	}
	return key.Key, nil
}

func (w *HDWallet) NewKeyPair(index uint32) (priv, pub []byte, err error) {
	key, err := bip44.NewKeyFromMasterKey(w.MasterKey, w.CoinType, bip32.FirstHardenedChild, 0, index)
	if err != nil {
		return nil, nil, err
	}
	return key.Key, key.PublicKey().Key, err
}

func (w *HDWallet) NewAddress_v2(index int) (string, error) {
	return w.NewAddress(uint32(index))
}

func (w *HDWallet) NewAddress(index uint32) (string, error) {
	if cointype, ok := CoinName[w.CoinType]; ok {
		_, pub, err := w.NewKeyPair(index)
		if err != nil {
			return "", err
		}

		trans, err := transformer.New(cointype)
		if err != nil {
			return "", err
		}
		addr, err := trans.PubKeyToAddress(pub)
		if err != nil {
			return "", err
		}
		return addr, nil
	}

	return "", errors.New("cointype no support to create address")

}

func PrivkeyToPub_v2(coinType string, priv []byte) ([]byte, error) {

	if cointype, ok := TypeTransfer[coinType]; ok {
		return PrivkeyToPub(cointype, priv)
	}
	return nil, errors.New("cointype no support")
}

func PrivkeyToPub(coinType uint32, priv []byte) ([]byte, error) {

	if cointype, ok := CoinName[coinType]; ok {
		trans, err := transformer.New(cointype)
		if err != nil {
			return nil, err
		}
		pub, err := trans.PrivKeyToPub(priv)
		if err != nil {
			return nil, err
		}

		return pub, nil

	}
	return nil, errors.New("cointype no support to create address")
}

func PubToAddress_v2(coinType string, pub []byte) (string, error) {

	if cointype, ok := TypeTransfer[coinType]; ok {
		return PubToAddress(cointype, pub)
	}
	return "", errors.New("cointype no support to create address")
}

func PubToAddress(coinType uint32, pub []byte) (string, error) {
	if cointype, ok := CoinName[coinType]; ok {
		trans, err := transformer.New(cointype)
		if err != nil {
			return "", err
		}
		pub, err := trans.PubKeyToAddress(pub)
		if err != nil {
			return "", err
		}

		return pub, nil

	}
	return "", errors.New("cointype no support to create address")
}

//创建助记词 lang=0 英文助记词，lang=1 中文助记词bitsize=[128,256]并且bitsize%32=0
func NewMnemonicString(lang, bitsize int) (string, error) {
	entropy, err := bip39.NewEntropy(bitsize)
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy, int32(lang))
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

//助记词中英互换
func TransferMnemonic(mnemonic string) (string, error) {
	words := strings.Split(mnemonic, " ")
	var newmneonic string
	if k, ok := bip39.ReverseWordMapCHN[words[0]]; ok {

		newmneonic += bip39.WordList[k]
		for _, word := range words[1:] {
			if index, ok := bip39.ReverseWordMapCHN[word]; ok {
				newmneonic += " " + bip39.WordList[index]
			} else {
				return "", errors.New("err mnemonic")
			}

		}

	} else if k, ok := bip39.ReverseWordMap[words[0]]; ok {
		newmneonic += bip39.WordListCHN[k]

		for _, word := range words[1:] {
			if index, ok := bip39.ReverseWordMap[word]; ok {
				newmneonic += " " + bip39.WordListCHN[index]
			} else {
				return "", errors.New("err mnemonic")
			}

		}

	}

	return newmneonic, nil
}

// 通过助记词生成钱包对象

func NewWalletFromMnemonic_v2(coinType string, mnemonic string) (wallet *HDWallet, err error) {
	if cointype, ok := TypeTransfer[coinType]; ok {
		return NewWalletFromMnemonic(cointype, mnemonic)
	}
	return nil, errors.New("cointype no support to create address")
}

func NewWalletFromMnemonic(coinType uint32, mnemonic string) (wallet *HDWallet, err error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return nil, err
	}

	return NewWalletFromSeed(coinType, seed)
}

// 通过种子生成钱包对象
func NewWalletFromSeed(coinType uint32, seed []byte) (wallet *HDWallet, err error) {
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	return &HDWallet{
		CoinType:  coinType,
		RootSeed:  seed,
		MasterKey: masterKey}, nil
}

//使用钱包的encpwd对私钥进行aes cbc加密,返回加密后的privkey
//注意：encpwd:为Encpwd的结果
func EncKey(encpwd []byte, privkey []byte) ([]byte, error) {
	if len(encpwd) != 32 {
		return nil, errors.New("encpwd lack of length")
	}
	key := make([]byte, 32)
	Encrypted := make([]byte, len(privkey))
	copy(key, encpwd)
	block, _ := aes.NewCipher(key)
	iv := key[:block.BlockSize()]

	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(Encrypted, privkey)
	return Encrypted, nil
}

//使用钱包的encpwd对私钥进行aes cbc解密,返回解密后的privkey
//encpwd:为Encpwd的结果
func DecKey(encpwd []byte, privkey []byte) ([]byte, error) {
	if len(encpwd) != 32 {
		return nil, errors.New("encpwd lack of length")
	}

	key := make([]byte, 32)
	copy(key, encpwd)

	block, _ := aes.NewCipher(key)
	iv := key[:block.BlockSize()]
	decryptered := make([]byte, len(privkey))
	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(decryptered, privkey)
	return decryptered, nil
}

//用于加密自己的钱包密码
//使用方式：创建密码后，通过调用这个接口对密码进行加密

func EncPasswd(orginpwd string) []byte {
	return pbkdf2.Key([]byte(orginpwd), []byte(orginpwd+"pqb20180625@developmentgroup"), 102400, 32, sha512.New)
}

//对加密后的密码数据进行哈希运算，这个结果需要保存在文件中，以后密码校验的时候，调用CheckPasswd函数校验
func PasswdHash(encpasswd []byte) string {
	h := sha512.New()
	h.Write(encpasswd)
	return hex.EncodeToString(h.Sum(nil))
}

//校验密码 true:密码正确，false 密码错误
func CheckPasswd(encpasswd, passwdhash string) bool {
	return PasswdHash(EncPasswd(encpasswd)) == passwdhash
}

//使用钱包的password对seed进行aesgcm加密,返回加密后的seed
func SeedEncKey(password []byte, seed []byte) ([]byte, error) {
	key := make([]byte, 32)
	if len(password) > 32 {
		key = password[0:32]
	} else {
		copy(key, password)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		//seedlog.Error("AesgcmEncrypter NewCipher err", "err", err)
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		//seedlog.Error("AesgcmEncrypter NewGCM err", "err", err)
		return nil, err
	}

	Encrypted := aesgcm.Seal(nil, key[:12], seed, nil)
	//seedlog.Info("AesgcmEncrypter Seal", "seed", seed, "key", key, "Encrypted", Encrypted)
	return Encrypted, nil
}

//使用钱包的password对seed进行aesgcm解密,返回解密后的seed
func SeedDecKey(password []byte, seed []byte) ([]byte, error) {
	key := make([]byte, 32)
	if len(password) > 32 {
		key = password[0:32]
	} else {
		copy(key, password)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		//seedlog.Error("AesgcmDecrypter", "NewCipher err", err)
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		//seedlog.Error("AesgcmDecrypter", "NewGCM err", err)
		return nil, err
	}
	decryptered, err := aesgcm.Open(nil, key[:12], seed, nil)
	if err != nil {
		//seedlog.Error("AesgcmDecrypter", "aesgcm Open err", err)
		return nil, err
	}
	//seedlog.Info("AesgcmDecrypter", "password", string(password), "seed", seed, "decryptered", string(decryptered))
	return decryptered, nil
}
