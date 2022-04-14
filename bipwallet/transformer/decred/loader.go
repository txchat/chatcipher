//对decred进行注册
package decred

import (
	"github.com/txchat/chatcipher/bipwallet/transformer"
)

//TODO：支持不同的地址类型前缀
var (
	PubKeyHashAddrID = [2]byte{0x07, 0x3f} //主网，PubKeyHashAddr，以"Ds"打头
)

func init() {
	//注册
	transformer.Register("DCR", &DcrTransformer{PubKeyHashAddrID[:]})
}
