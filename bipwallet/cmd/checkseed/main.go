package main

import (
	"flag"
	"fmt"

	"github.com/txchat/chatcipher/bipwallet/bip39"
)

var m = flag.String("m", "", "mnemonic word list")

func main() {
	flag.Parse()
	seed, err := bip39.NewSeedWithErrorChecking(*m, "")
	if err != nil {
		fmt.Println(err)
		return
	}
	println("OK", len(seed))
}
