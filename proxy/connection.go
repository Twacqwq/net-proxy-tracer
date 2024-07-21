package proxy

import (
	"bufio"
	"net"
	"sync"

	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

type ProxyConnContext struct {
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
	Conn net.Conn
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

func newProxyClientConn(c net.Conn) (*proxyClientConn, error) {
	return &proxyClientConn{
		Conn:    c,
		connCtx: NewProxyClientConnContext(c),
		r:       bufio.NewReader(c),
		chClose: make(chan struct{}),
	}, nil
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
	log.Infof("do proxyClientConnClose, addr: %s\n", pcc.Conn.RemoteAddr())

	pcc.closed = true
	pcc.err = pcc.Conn.Close()
	close(pcc.chClose)

	if pcc.connCtx.ServerConnCtx != nil && pcc.connCtx.ServerConnCtx.Conn != nil {
		pcc.err = pcc.connCtx.ServerConnCtx.Conn.Close()
	}

	return pcc.err
}
