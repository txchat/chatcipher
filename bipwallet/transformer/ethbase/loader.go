//对ETH和ETC进行注册
package ethbase

import (
	"github.com/txchat/chatcipher/bipwallet/transformer"
)

func init() {
	//注册
	transformer.Register("ETH", &EthBaseTransformer{})
	transformer.Register("ETC", &EthBaseTransformer{})
}
