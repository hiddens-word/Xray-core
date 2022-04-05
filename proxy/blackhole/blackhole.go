// Package blackhole is an outbound handler that blocks all connections.
package blackhole

//go:generate go run github.com/hiddens-word/xray-core/common/errors/errorgen

import (
	"context"
	"time"

	"github.com/hiddens-word/xray-core/common"
	"github.com/hiddens-word/xray-core/transport"
	"github.com/hiddens-word/xray-core/transport/internet"
)

// Handler is an outbound connection that silently swallow the entire payload.
type Handler struct {
	response ResponseConfig
}

// New creates a new blackhole handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	response, err := config.GetInternalResponse()
	if err != nil {
		return nil, err
	}
	return &Handler{
		response: response,
	}, nil
}

// Process implements OutboundHandler.Dispatch().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	nBytes := h.response.WriteTo(link.Writer)
	if nBytes > 0 {
		// Sleep a little here to make sure the response is sent to client.
		time.Sleep(time.Second)
	}
	common.Interrupt(link.Writer)
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
