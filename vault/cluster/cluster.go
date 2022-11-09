package cluster

import (
	"crypto/tls"
	"net"
	"time"
)

// 490
type NetworkListener interface {
	net.Listener

	SetDeadline(t time.Time) error
}

// p499
type NetworkLayer interface {
	Addrs() []net.Addr
	Listeners() []NetworkListener
	Dial(address string, timeout time.Duration, tlsConfig *tls.Config) (*tls.Conn, error)
	Close() error
}
