package main

import (
	"flag"
	"fmt"

	"github.com/txchat/chatcipher/bipwallet"
)

var bitsize = flag.Int("bit", 256, "128,160,256")
var lang = flag.Int("lang", 0, "0->english 1->chinese")

func main() {
	flag.Parse()
	mnem, err := bipwallet.NewMnemonicString(*lang, *bitsize) //这个函数各个版本通用
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(mnem)
}
