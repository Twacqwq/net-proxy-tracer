package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net-proxy-tracer/internal/ctxdata"
	"net/http"
)

type tracer struct {
	server   *http.Server
	client   *http.Client
	listener *traceListener
	// cert     cert.Cert
}

func newTracer(p *ProxyServer) (*tracer, error) {
	t := &tracer{
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:              p.ProxyURL(),
				ForceAttemptHTTP2:  false,
				DisableCompression: true,
				TLSClientConfig:    &tls.Config{},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		listener: &traceListener{
			chConn: make(chan net.Conn),
		},
	}

	t.server = &http.Server{
		Handler: t,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return ctxdata.ProxyConn.WithValue(ctx, c.(*traceConn).connCtx)
		},
	}

	return t, nil
}

func (t *tracer) start() error {
	return t.server.Serve(t.listener)
}

func (t *tracer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Host) == 0 {
		r.URL.Host = r.Host
	}

	t.sendProxyTrace(w, r)
}

func (t *tracer) sendProxyTrace(w http.ResponseWriter, r *http.Request) {
	// TODO read proxy request
	// TODO read proxy response
	// TODO write body
}

type traceListener struct {
	net.Listener

	chConn chan net.Conn
}

func (t *traceListener) Accept() (net.Conn, error) {
	return <-t.chConn, nil
}

func (t *traceListener) accept(c net.Conn) {
	t.chConn <- c
}

type traceConn struct {
	net.Conn

	connCtx *ProxyConnContext
}
