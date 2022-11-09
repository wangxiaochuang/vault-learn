package vault

import (
	"context"
	"time"
)

// p119
type forwardingClient struct {
	RequestForwardingClient
	core        *Core
	echoTicker  *time.Ticker
	echoContext context.Context
}
