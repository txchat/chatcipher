package decred

import (
	"encoding/hex"
	"testing"

	"github.com/txchat/chatcipher/bipwallet/transformer"
)

var testHybridPub = []byte{
	0x07, 0x34, 0x8d, 0x8a, 0xeb, 0x42, 0x53, 0xca, 0x52, 0x45,
	0x6f, 0xe5, 0xda, 0x94, 0xab, 0x12, 0x63, 0xbf, 0xee, 0x16,
	0xbb, 0x81, 0x92, 0x49, 0x7f, 0x66, 0x63, 0x89, 0xca, 0x96,
	0x4f, 0x84, 0x79, 0x83, 0x75, 0x12, 0x9d, 0x79, 0x58, 0x84,
	0x3b, 0x14, 0x25, 0x8b, 0x90, 0x5d, 0xc9, 0x4f, 0xae, 0xd3,
	0x24, 0xdd, 0x8a, 0x9d, 0x67, 0xff, 0xac, 0x8c, 0xc0, 0xa8,
	0x5b, 0xe8, 0x4b, 0xac, 0x5d}
var ansHybridAddr = "DskEQZMCs4nifL7wx7iHYGWxMQvR9ThCBKQ"

var testUnCompressedPub = []byte{
	0x04, 0x64, 0xc4, 0x46, 0x53, 0xd6, 0x56, 0x7e, 0xff, 0x57,
	0x53, 0xc5, 0xd2, 0x4a, 0x68, 0x2d, 0xdc, 0x2b, 0x2c, 0xad,
	0xfe, 0x1b, 0x0c, 0x64, 0x33, 0xb1, 0x63, 0x74, 0xda, 0xce,
	0x67, 0x78, 0xf0, 0xb8, 0x7c, 0xa4, 0x27, 0x9b, 0x56, 0x5d,
	0x21, 0x30, 0xce, 0x59, 0xf7, 0x5b, 0xfb, 0xb2, 0xb8, 0x8d,
	0xa7, 0x94, 0x14, 0x3d, 0x7c, 0xfd, 0x3e, 0x80, 0x80, 0x8a,
	0x1f, 0xa3, 0x20, 0x39, 0x04}
var ansUnCompressedAddr = "DsfFjaADsV8c5oHWx85ZqfxCZy74K8RFuhK"

var testCompressedPub_0 = []byte{
	0x03, 0xe9, 0x25, 0xaa, 0xfc, 0x1e, 0xdd, 0x44, 0xe7, 0xc7,
	0xf1, 0xea, 0x4f, 0xb7, 0xd2, 0x65, 0xdc, 0x67, 0x2f, 0x20,
	0x4c, 0x3d, 0x0c, 0x81, 0x93, 0x03, 0x89, 0xc1, 0x0b, 0x81,
	0xfb, 0x75, 0xde}
var ansCompressedAddr_0 = "DsfiE2y23CGwKNxSGjbfPGeEW4xw1tamZdc"

var testCompressedPub_1 = []byte{
	0x02, 0x8f, 0x53, 0x83, 0x8b, 0x76, 0x39, 0x56, 0x3f, 0x27,
	0xc9, 0x48, 0x45, 0x54, 0x9a, 0x41, 0xe5, 0x14, 0x6b, 0xcd,
	0x52, 0xe7, 0xfe, 0xf0, 0xea, 0x6d, 0xa1, 0x43, 0xa0, 0x2b,
	0x0f, 0xe2, 0xed}
var ansCompressedAddr_1 = "DsT4FDqBKYG1Xr8aGrT1rKP3kiv6TZ5K5th"

//"ba6af2a1f0150db3a8745c2adbdf98e928c6264dd0aa866e59b06fa689740f05"
var testPrivkey = []byte{
	0xba, 0x6a, 0xf2, 0xa1, 0xf0, 0x15, 0x0d, 0xb3, 0xa8, 0x74,
	0x5c, 0x2a, 0xdb, 0xdf, 0x98, 0xe9, 0x28, 0xc6, 0x26, 0x4d,
	0xd0, 0xaa, 0x86, 0x6e, 0x59, 0xb0, 0x6f, 0xa6, 0x89, 0x74,
	0x0f, 0x05}

var ansPubkey = "0367476225d991b4850b64f751bdb58a65904b70dd09f6cb30f31855f45302ac6a"

//????????????????????????
func TestPrivToPub(t *testing.T) {
	t.Logf("PrivToPub test data:\n priv: %x\n pub: %s\n", testPrivkey, ansPubkey)
	coinTrans, err := transformer.New("DCR")
	if err != nil {
		t.Errorf("new DCR transformer error: %s", err)
	}

	pubByte, err := coinTrans.PrivKeyToPub(testPrivkey)
	if err != nil {
		t.Errorf("DCR PrivKeyToPub error: %s", err)
	}
	if hex.EncodeToString(pubByte) == ansPubkey {
		t.Logf("DCR public key match")
	} else {
		t.Errorf("DCR public key mismatch: want: %s have: %x", ansPubkey, pubByte)
	}
}

//???????????????????????????????????????
func TestPubToAddr(t *testing.T) {
	//????????????????????????????????????(P2PKH)
	testPubToAddr(t, testCompressedPub_0, ansCompressedAddr_0)
	testPubToAddr(t, testCompressedPub_1, ansCompressedAddr_1)
	//???????????????????????????
	testPubToAddr(t, testUnCompressedPub, ansUnCompressedAddr)
	//????????????????????????
	testPubToAddr(t, testHybridPub, ansHybridAddr)
}

//????????????????????????
func testPubToAddr(t *testing.T, testPub []byte, ansAddr string) {
	t.Logf("PubToAddr test data:\n pub: %x \n addr: %s", testPub, ansAddr)
	coinTrans, err := transformer.New("DCR")
	if err != nil {
		t.Errorf("new DCR transformer error: %s", err)
	}

	genAddr, err := coinTrans.PubKeyToAddress(testPub)
	if err != nil {
		t.Errorf("DCR PubKeyToAddress error: %s", err)
	}
	if genAddr == ansAddr {
		t.Logf("DCR address match")
	} else {
		t.Errorf("DCR address mismatch: want: %s have %s", ansAddr, genAddr)
	}
}
