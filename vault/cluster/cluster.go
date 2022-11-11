package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"time"

	log "github.com/hashicorp/go-hclog"
	"golang.org/x/net/http2"
)

const (
	ListenerAcceptDeadline = 500 * time.Millisecond
)

// Client is used to lookup a client certificate.
type Client interface {
	ClientLookup(context.Context, *tls.CertificateRequestInfo) (*tls.Certificate, error)
	ServerName() string
	CACert(ctx context.Context) *x509.Certificate
}

// Handler exposes functions for looking up TLS configuration and handing
// off a connection for a cluster listener application.
type Handler interface {
	ServerLookup(context.Context, *tls.ClientHelloInfo) (*tls.Certificate, error)
	CALookup(context.Context) ([]*x509.Certificate, error)

	// Handoff is used to pass the connection lifetime off to
	// the handler
	Handoff(context.Context, *sync.WaitGroup, chan struct{}, *tls.Conn) error
	Stop() error
}

type ClusterHook interface {
	AddClient(alpn string, client Client)
	RemoveClient(alpn string)
	AddHandler(alpn string, handler Handler)
	StopHandler(alpn string)
	TLSConfig(ctx context.Context) (*tls.Config, error)
	Addr() net.Addr
	GetDialerFunc(ctx context.Context, alpnProto string) func(string, time.Duration) (net.Conn, error)
}

// p62
type Listener struct {
	handlers   map[string]Handler
	clients    map[string]Client
	shutdown   *uint32
	shutdownWg *sync.WaitGroup
	server     *http2.Server

	networkLayer              NetworkLayer
	cipherSuites              []uint16
	advertise                 net.Addr
	logger                    log.Logger
	l                         sync.RWMutex
	tlsConnectionLoggingLevel log.Level
}

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
