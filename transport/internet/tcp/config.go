package tcp

import (
	"github.com/hiddens-word/xray-core/common"
	"github.com/hiddens-word/xray-core/transport/internet"
)

const protocolName = "tcp"

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
