package proxy

import (
	"context"
	"io"
	"net"
	"net-proxy-tracer/internal/ctxdata"
	"net-proxy-tracer/internal/response"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
)

type ProxyConfig struct {
	Addr             string
	ExternalProxyURL string
}

type ProxyServer struct {
	server        *http.Server
	tracer        *tracer
	externalProxy func(req *http.Request) (*url.URL, error)

	Config *ProxyConfig
}

func NewProxyServer(config *ProxyConfig) (*ProxyServer, error) {
	ps := &ProxyServer{
		Config: config,
		server: &http.Server{
			Addr: config.Addr,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return ctxdata.ProxyConn.WithValue(ctx, c.(*proxyClientConn).connCtx)
			},
		},
	}
	ps.server.Handler = ps

	t, err := newTracer(ps)
	if err != nil {
		return nil, err
	}
	ps.tracer = t

	return ps, nil
}

func (ps *ProxyServer) Start() error {
	go func() {
		if err := ps.tracer.start(); err != nil {
			return
		}
	}()

	ln, err := net.Listen("tcp", ps.server.Addr)
	if err != nil {
		return err
	}

	log.Println("Start proxy server")

	return ps.server.Serve(&serverListener{ln})
}

func (ps *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() || len(r.URL.Host) == 0 {
		w = response.NewProxyResponseWriter(w)
		if res, ok := w.(*response.ProxyResponseWriter); ok {
			if !res.Wrote {
				res.WriteHeader(http.StatusBadRequest)
				io.WriteString(res, "Proxy Servers Cannot Initiate Requests Directly")
			}
		}
	}

	if r.Method == http.MethodConnect {
		ps.DoHTTPSProxyTrace(w, r)
		return
	}

	ps.DoHTTPProxyTrace(w, r)
}

func (ps *ProxyServer) DoHTTPProxyTrace(w http.ResponseWriter, r *http.Request) {
	connCtx := r.Context().Value(ctxdata.ProxyConn).(*ProxyConnContext)
	connCtx.httpDialContext(r)
	ps.tracer.sendProxyTrace(w, r)
}

func (ps *ProxyServer) DoHTTPSProxyTrace(w http.ResponseWriter, r *http.Request) {}

func (ps *ProxyServer) Close() error {
	return ps.server.Close()
}

func (ps *ProxyServer) Shutdown(ctx context.Context) error {
	return ps.server.Shutdown(ctx)
}

func (ps *ProxyServer) ProxyURL() func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		return ps.getExtenalURL(r.Context().Value(ctxdata.ProxyReqConn).(*http.Request))
	}
}

func (ps *ProxyServer) getExtenalURL(req *http.Request) (*url.URL, error) {
	if ps.externalProxy != nil {
		return ps.externalProxy(req)
	}

	return http.ProxyFromEnvironment(&http.Request{
		URL: &url.URL{
			Scheme: req.URL.Scheme,
			Host:   req.Host,
		},
	})
}

type serverListener struct {
	net.Listener
}

func (s *serverListener) Accept() (net.Conn, error) {
	c, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// create proxy client connection
	return newProxyClientConn(c)
}
