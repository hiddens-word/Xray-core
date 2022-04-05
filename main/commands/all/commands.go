package all

import (
	"github.com/hiddens-word/xray-core/main/commands/all/api"
	"github.com/hiddens-word/xray-core/main/commands/all/tls"
	"github.com/hiddens-word/xray-core/main/commands/base"
)

// go:generate go run github.com/hiddens-word/xray-core/common/errors/errorgen

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		api.CmdAPI,
		// cmdConvert,
		tls.CmdTLS,
		cmdUUID,
	)
}
