package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Twacqwq/net-proxy-tracer/internal/ctxdata"
	"github.com/Twacqwq/net-proxy-tracer/internal/response"
	"github.com/Twacqwq/net-proxy-tracer/internal/utils"

	"github.com/sirupsen/logrus"
)

type ProxyConfig struct {
	Addr             string
	ExternalProxyURL string
	Debug            bool
	SslInsecure      bool
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

	if config.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.Printf("LogLevel: %s", logrus.GetLevel())

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

	logrus.Infof("ProxyServer Starting in %s", ps.server.Addr)

	return ps.server.Serve(&serverListener{ln})
}

func (ps *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		ps.DoHTTPSProxyTrace(w, r)
		return
	}

	if !r.URL.IsAbs() || len(r.URL.Host) == 0 {
		w = response.NewProxyResponseWriterCheck(w)
		if res, ok := w.(*response.ProxyResponseWriterCheck); ok {
			if !res.Wrote {
				res.WriteHeader(http.StatusBadRequest)
				io.WriteString(res, "Proxy Servers Cannot Initiate Requests Directly")
			}
		}
	}

	ps.DoHTTPProxyTrace(w, r)
}

func (ps *ProxyServer) DoHTTPProxyTrace(w http.ResponseWriter, r *http.Request) {
	connCtx := r.Context().Value(ctxdata.ProxyConn).(*ProxyConnContext)
	connCtx.dialContext = func(ctx context.Context) error {
		addr := utils.HostJoinPort(r.URL)
		proxyConn, err := ps.ProxyConn(ctx, r)
		if err != nil {
			return err
		}

		c := &proxyServerConn{
			connCtx: connCtx,
			Conn:    proxyConn,
		}

		cli := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return proxyConn, nil
				},
				DisableCompression: true,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		connCtx.ServerConnCtx = NewServerConnContext(addr, c, WithServerConnContextClient(cli))

		logrus.Debugf(
			"Server Connect Success. [%s]: [%s] -> [%s]",
			connCtx.ClientConnCtx.Conn.RemoteAddr(),
			connCtx.ServerConnCtx.Conn.LocalAddr(),
			connCtx.ServerConnCtx.Conn.RemoteAddr(),
		)

		return nil
	}

	ps.tracer.sendProxyTrace(w, r)
}

func (ps *ProxyServer) DoHTTPSProxyTrace(w http.ResponseWriter, r *http.Request) {
	// get https server conn
	conn, err := ps.httpsServerConn(r.Context(), r)
	if err != nil {
		logrus.Error(err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	// hijack response after proxy conn
	pconn, err := ps.hiJack(w)
	if err != nil {
		logrus.Error(err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	b, err := pconn.(*proxyClientConn).Peek(3)
	if err != nil {
		_ = conn.Close()
		_ = pconn.Close()
		logrus.Error(err)
		return
	}

	// check tls
	if !utils.IsTLSConnection(pconn) && !utils.CheckTLSWithHeaderHex(b) {
		proxyTraffic(conn, pconn)
		_ = conn.Close()
		_ = pconn.Close()
		return
	}

	r.Context().Value(ctxdata.ProxyConn).(*ProxyConnContext).ClientConnCtx.IsTLS = true
	ps.tracer.tlsHandshake(r.Context(), conn, pconn)
}

func (ps *ProxyServer) Close() error {
	return ps.server.Close()
}

func (ps *ProxyServer) Shutdown(ctx context.Context) error {
	return ps.server.Shutdown(ctx)
}

func (ps *ProxyServer) ProxyURL() func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		return ps.getExtenalURL(r.Context().Value(ctxdata.ProxyReq).(*http.Request))
	}
}

func (ps *ProxyServer) ProxyConn(ctx context.Context, r *http.Request) (net.Conn, error) {
	proxyURL, err := ps.getExtenalURL(r)
	if err != nil {
		return nil, err
	}

	var (
		c    net.Conn
		addr = utils.HostJoinPort(r.URL)
	)
	if proxyURL != nil {
		c, err = ps.getProxyConnWithProxyURL(ctx, proxyURL, addr, ps.Config.SslInsecure)
	} else {
		c, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (ps *ProxyServer) getExtenalURL(req *http.Request) (*url.URL, error) {
	if ps.externalProxy != nil {
		return ps.externalProxy(req)
	}

	if len(req.URL.Scheme) == 0 {
		req.URL.Scheme = "https"
	}

	return http.ProxyFromEnvironment(&http.Request{
		URL: &url.URL{
			Scheme: req.URL.Scheme,
			Host:   req.Host,
		},
	})
}

func (ps *ProxyServer) getProxyConnWithProxyURL(ctx context.Context, proxyURL *url.URL, addr string, sslInsecure bool) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}

	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         proxyURL.Hostname(),
			InsecureSkipVerify: sslInsecure,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	proxyReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if proxyURL.User != nil {
		proxyReq.Header.Set("Proxy-Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(proxyURL.User.String()))))
	}

	proxyReqCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	var (
		resp     *http.Response
		chNotify = make(chan struct{})
	)
	go func() {
		defer close(chNotify)
		err = proxyReq.Write(conn)
		if err != nil {
			return
		}
		resp, err = http.ReadResponse(bufio.NewReader(conn), proxyReq)
	}()
	select {
	case <-proxyReqCtx.Done():
		_ = conn.Close()
		<-chNotify
		return nil, proxyReqCtx.Err()
	case <-chNotify:
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, errors.New(resp.Status)
	}

	return conn, nil
}

func (ps *ProxyServer) httpsServerConn(ctx context.Context, r *http.Request) (net.Conn, error) {
	connCtx := r.Context().Value(ctxdata.ProxyConn).(*ProxyConnContext)
	if connCtx == nil {
		return nil, errors.New("proxy connection context is nil")
	}

	pconn, err := ps.ProxyConn(ctx, r)
	if err != nil {
		return nil, err
	}

	connCtx.ServerConnCtx = NewServerConnContext(r.Host, pconn)

	return connCtx.ServerConnCtx.Conn, nil
}

func (ps *ProxyServer) hiJack(w http.ResponseWriter) (net.Conn, error) {
	pconn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return nil, err
	}

	_, err = pconn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return nil, err
	}

	return pconn, nil
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
	pcc := newProxyClientConn(c)

	logrus.Debugf("Client Connect Success. %s", pcc.Conn.RemoteAddr())

	return pcc, nil
}

// proxyTraffic full-duplex communication
func proxyTraffic(client, server io.ReadWriteCloser) {
	chErr := make(chan error, 2)

	// client -> server
	go func() {
		_, err := io.Copy(server, client)
		logrus.Debug("[Proxy Traffic]: Client -> Server")
		_ = client.Close()
		chErr <- err
	}()

	// server -> client
	go func() {
		_, err := io.Copy(client, server)
		logrus.Debug("[Proxy Traffic]: Server -> Client")
		_ = server.Close()

		if clientConn, ok := client.(*proxyClientConn); ok {
			err = clientConn.Conn.(*net.TCPConn).CloseRead()
		}

		chErr <- err
	}()

	// check error
	for i := 0; i < 2; i++ {
		if err := <-chErr; err != nil && err != io.EOF {
			logrus.Error(err)
			return
		}
	}
}
