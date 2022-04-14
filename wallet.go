package walletapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"github.com/haltingstate/secp256k1-go"
	"github.com/txchat/chatcipher/bipwallet/bip32"
	"github.com/txchat/chatcipher/bipwallet/bip39"
	"github.com/txchat/chatcipher/bipwallet/bip44"
	"github.com/txchat/chatcipher/common/address"
	"golang.org/x/crypto/pbkdf2"
)

var TypeTransfer = map[string]uint32{
	"BTC": 0x80000000,
	"ETH": 0x8000003c,
	"ETC": 0x8000003d,
	"LTC": 0x80000002,
	"ZEC": 0x80000085,
	"BTY": 0x80003333,
	"YCC": 0x80003334,
	"DCR": 0x8000002a,
}

// standard HD wallet that support BIP-44
type HDWallet struct {
	CoinType  uint32
	RootSeed  []byte
	MasterKey *bip32.Key
}

func ChatSign(msg, privateKey []byte) []byte {
	return secp256k1.Sign(msg, privateKey)
}

func PublicKeyToAddress(pubKey []byte) string {
	return address.PublicKeyToAddress(address.NormalVer, pubKey)
}

// generate key pairs by index
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

//create mnemonic: lang=0 english, lang=1 chinese; bit size=[128,256] & bit size%32=0
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

// create wallet object by mnemonic
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

// create wallet object by seed
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

// return encrypted password as source data encrypt by hash algorithm
// it can checked by CheckPasswd function
func PasswdHash(encpasswd []byte) string {
	h := sha512.New()
	h.Write(encpasswd)
	return hex.EncodeToString(h.Sum(nil))
}

//check password
func CheckPasswd(encpasswd, passwdhash string) bool {
	return PasswdHash(EncPasswd(encpasswd)) == passwdhash
}

// use to encrypt password
func EncPasswd(orginpwd string) []byte {
	return pbkdf2.Key([]byte(orginpwd), []byte(orginpwd+"pqb20180625@developmentgroup"), 102400, 32, sha512.New)
}

//return the seed that encrypted by wallet password as aesgcm
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

// return the seed that decrypted by wallet password as aesgcm
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

func StringTobyte(param string) ([]byte, error) {
	return []byte(param), nil
}

func ByteTostring(param []byte) string {
	return string(param[:])
}
