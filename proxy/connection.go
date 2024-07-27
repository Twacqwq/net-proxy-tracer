package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

type ProxyConnContext struct {
	dialContext  func(context.Context) error
	alreadyClose bool

	ClientConnCtx *ClientConnContext
	ServerConnCtx *ServerConnContext
}

func NewProxyClientConnContext(c net.Conn) *ProxyConnContext {
	return &ProxyConnContext{
		ClientConnCtx: NewClientConnContext(c),
	}
}

type ClientConnContext struct {
	ID    uuid.UUID
	Conn  net.Conn
	IsTLS bool
}

func NewClientConnContext(c net.Conn) *ClientConnContext {
	return &ClientConnContext{
		ID:   uuid.NewV4(),
		Conn: c,
	}
}

type ServerConnContext struct {
	client       *http.Client
	tlsConn      *tls.Conn
	tlsConnState *tls.ConnectionState

	ID   uuid.UUID
	Addr string
	Conn net.Conn
}

func NewServerConnContext(addr string, c net.Conn, opts ...ServerConnContextOption) *ServerConnContext {
	s := &ServerConnContext{
		ID:   uuid.NewV4(),
		Addr: addr,
		Conn: c,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

type ServerConnContextOption func(*ServerConnContext)

func WithServerConnContextClient(c *http.Client) ServerConnContextOption {
	return func(scc *ServerConnContext) {
		scc.client = c
	}
}

type proxyClientConn struct {
	net.Conn

	r       *bufio.Reader
	connCtx *ProxyConnContext
	mu      sync.Mutex
	closed  bool
	err     error
	chClose chan struct{}
}

func newProxyClientConn(c net.Conn) *proxyClientConn {
	pc := &proxyClientConn{
		Conn:    c,
		r:       bufio.NewReader(c),
		chClose: make(chan struct{}),
	}

	pc.connCtx = NewProxyClientConnContext(pc)

	return pc
}

func (pcc *proxyClientConn) Peek(n int) ([]byte, error) {
	return pcc.r.Peek(n)
}

func (pcc *proxyClientConn) Read(p []byte) (int, error) {
	return pcc.r.Read(p)
}

func (pcc *proxyClientConn) Close() error {
	pcc.mu.Lock()
	defer pcc.mu.Unlock()

	if pcc.closed {
		return pcc.err
	}
	logrus.Debugf("ProxyClientConnClose: %s", pcc.Conn.RemoteAddr())

	pcc.closed = true
	pcc.err = pcc.Conn.Close()
	close(pcc.chClose)

	if pcc.connCtx.ServerConnCtx != nil && pcc.connCtx.ServerConnCtx.Conn != nil {
		pcc.err = pcc.connCtx.ServerConnCtx.Conn.Close()
	}

	return pcc.err
}

type proxyServerConn struct {
	net.Conn

	connCtx *ProxyConnContext
	mu      sync.Mutex
	closed  bool
	err     error
}

func (psc *proxyServerConn) Close() error {
	psc.mu.Lock()

	if psc.closed {
		psc.mu.Unlock()
		return psc.err
	}
	logrus.Debugf("ProxyServerConnClose: [%s] -> [%s]", psc.Conn.LocalAddr(), psc.Conn.RemoteAddr())

	psc.closed = true
	psc.err = psc.Conn.Close()
	psc.mu.Unlock()

	if !psc.connCtx.ClientConnCtx.IsTLS {
		_ = psc.connCtx.ClientConnCtx.Conn.(*proxyClientConn).Conn.(*net.TCPConn).CloseRead()
	} else {
		if psc.connCtx.alreadyClose {
			_ = psc.connCtx.ClientConnCtx.Conn.Close()
		}
	}

	return psc.err
}
