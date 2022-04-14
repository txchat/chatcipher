package main

import (
	"C"
	"encoding/hex"
	"fmt"
	walletapi "github.com/txchat/chatcipher"
)

func main() {

}

//export ChatSign
func ChatSign(msg, privateKey *C.char) *C.char {
	data := C.GoString(msg)
	key := C.GoString(privateKey)

	pk, err := hex.DecodeString(key)
	if err != nil {
		panic(err)
	}
	res := string(walletapi.ChatSign([]byte(data), pk))
	fmt.Println(hex.EncodeToString([]byte(res)))
	return C.CString(res)
}
