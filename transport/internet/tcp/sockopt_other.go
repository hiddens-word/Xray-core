//go:build !linux && !freebsd
// +build !linux,!freebsd

package tcp

import (
	"github.com/hiddens-word/xray-core/common/net"
	"github.com/hiddens-word/xray-core/transport/internet/stat"
)

func GetOriginalDestination(conn stat.Connection) (net.Destination, error) {
	return net.Destination{}, nil
}
