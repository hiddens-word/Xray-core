package udp

import (
	"github.com/hiddens-word/xray-core/common"
	"github.com/hiddens-word/xray-core/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
