package address

import (
	"encoding/hex"
	"testing"
)

func Test_Encoding(t *testing.T) {
	in, err := hex.DecodeString("02c041205ba02149d3e03c05ff67a6c519aa5d2bef293d2e7fc3951931bc9ad712")
	if err != nil {
		t.Error(err)
		return
	}
	addr := PublicKeyToAddress(NormalVer, in)
	t.Log(addr)
	if err := CheckAddress(NormalVer, addr); err != nil {
		t.Error(err)
		return
	}
	t.Log("check success")
}

func Test_CheckAddress(t *testing.T) {
	addr := "1JoFzozbxvst22c2K7MBYwQGjCaMZbC5Qm"
	if err := CheckAddress(NormalVer, addr); err != nil {
		t.Error(err)
		return
	}
	t.Log("check success")
}
