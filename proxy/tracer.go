package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"

	"github.com/Twacqwq/net-proxy-tracer/internal/ctxdata"
	"github.com/Twacqwq/net-proxy-tracer/internal/response"

	"github.com/sirupsen/logrus"
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
				ForceAttemptHTTP2:  true,
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
	connCtx := r.Context().Value(ctxdata.ProxyConn).(*ProxyConnContext)
	if connCtx == nil {
		logrus.Error("proxy connection context is nil")
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	// build proxy request with request context
	proxyReqCtx := context.WithValue(r.Context(), ctxdata.ProxyReq, r)
	proxyReq, err := http.NewRequestWithContext(proxyReqCtx, r.Method, r.URL.String(), r.Body)
	if err != nil {
		logrus.Error(err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	// copy request header
	for k, v := range r.Header {
		proxyReq.Header[k] = v
	}

	// TODO rewrite host
	rewriteHost := false

	// send proxy request
	var proxyResp *http.Response
	if rewriteHost {
		proxyResp, err = t.client.Do(proxyReq)
	} else {
		if connCtx.ServerConnCtx == nil && connCtx.dialContext != nil {
			if err := connCtx.dialContext(r.Context()); err != nil {
				logrus.Error(err)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
		}
		proxyResp, err = connCtx.ServerConnCtx.client.Do(proxyReq)
	}
	if err != nil {
		logrus.Errorf("Trace %s[%s %s], Status: %s\n%v",
			connCtx.ServerConnCtx.Conn.RemoteAddr(),
			proxyResp.Proto, proxyReq.URL.String(),
			proxyResp.Status,
			err,
		)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer proxyResp.Body.Close()
	connCtx.alreadyClose = proxyResp.Close

	resp := &response.Response{
		StatusCode: proxyResp.StatusCode,
		Header:     proxyResp.Header,
		Close:      proxyResp.Close,
	}
	respBody, err := io.ReadAll(proxyResp.Body)
	if err != nil {
		logrus.Error(err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	resp.Body = respBody

	if err := resp.WriteBody(w, proxyResp.Body); err != nil {
		logrus.Errorf("Trace %s[%s %s], Status: %s\n%v",
			connCtx.ServerConnCtx.Conn.RemoteAddr(),
			proxyResp.Proto, proxyReq.URL.String(),
			proxyResp.Status,
			err,
		)
		return
	}

	logrus.Infof("Trace %s[%s %s], Status: %s",
		connCtx.ServerConnCtx.Conn.RemoteAddr(),
		proxyResp.Proto, proxyReq.URL.String(),
		proxyResp.Status,
	)
	logrus.Debugf("Trace Response: %v", proxyResp)
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
