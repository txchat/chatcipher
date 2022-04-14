//对SC进行注册
package siacoin

import (
	"github.com/txchat/chatcipher/bipwallet/transformer"
)

func init() {
	//注册
	transformer.Register("SC", &ScTransformer{})
}
