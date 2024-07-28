package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"

	"github.com/Twacqwq/net-proxy-tracer/internal/cert"
	"github.com/Twacqwq/net-proxy-tracer/internal/ctxdata"
	"github.com/Twacqwq/net-proxy-tracer/internal/response"

	"github.com/sirupsen/logrus"
)

type tracer struct {
	config   *ProxyConfig
	server   *http.Server
	client   *http.Client
	listener *traceListener
	// cert     cert.Cert
}

func newTracer(p *ProxyServer) (*tracer, error) {
	t := &tracer{
		config: p.Config,
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
	if len(r.URL.Scheme) == 0 {
		r.URL.Scheme = "https"
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
		logrus.Errorf("Trace %s[%s] Error: %v",
			connCtx.ServerConnCtx.Conn.RemoteAddr(),
			proxyReq.URL.String(),
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

func (t *tracer) tlsHandshake(ctx context.Context, conn, pconn net.Conn) {
	connCtx := pconn.(*proxyClientConn).connCtx

	// tls channel
	chTlsClientHelloInfo := make(chan *tls.ClientHelloInfo)
	chTlsConnectionState := make(chan *tls.ConnectionState)
	chTlsHandshakeDone := make(chan struct{})

	// tls handshake error channel
	chClientHandshakeErr := make(chan error, 1)
	chServerHandshakeErr := make(chan error, 1)

	var tlsClientHelloInfo *tls.ClientHelloInfo
	clientTlsConn := tls.Server(pconn, &tls.Config{
		SessionTicketsDisabled: true,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			chTlsClientHelloInfo <- chi
			var nextProtocols []string

			// wait server handshake done
			select {
			case err := <-chServerHandshakeErr:
				return nil, err
			case tlsConnState := <-chTlsConnectionState:
				if len(tlsConnState.NegotiatedProtocol) > 0 {
					nextProtocols = append([]string{tlsConnState.NegotiatedProtocol}, nextProtocols...)
				}
			}

			// get cert with tls server name
			logrus.Debugf("ServerName: %s", chi.ServerName)
			s, err := cert.GetCert(chi.ServerName)
			if err != nil {
				logrus.Errorf("GetCert Error: %v", err)
				return nil, err
			}

			return &tls.Config{
				SessionTicketsDisabled: true,
				Certificates:           []tls.Certificate{*s},
				NextProtos:             nextProtocols,
			}, nil
		},
	})

	// client tls handshake
	go func() {
		if err := clientTlsConn.HandshakeContext(ctx); err != nil {
			logrus.Errorf("ClientTlsConn Handshake Error: %+v", err)
			chClientHandshakeErr <- err
			return
		}
		close(chTlsHandshakeDone)
	}()

	// get tlsClientHelloInfo in clientTlsConn
	select {
	case err := <-chClientHandshakeErr:
		_ = conn.Close()
		_ = pconn.Close()
		logrus.Error(err)
		return
	case tlsClientHelloInfo = <-chTlsClientHelloInfo:
		connCtx.ClientConnCtx.clientHelloInfo = tlsClientHelloInfo
	}

	// server tls handshake
	if err := t.tlsServerHandshakeContext(ctx, connCtx); err != nil {
		_ = conn.Close()
		_ = pconn.Close()
		logrus.Error(err)
		return
	}
	logrus.Debug("Tls Server handshake done")
	chTlsConnectionState <- connCtx.ServerConnCtx.tlsConnState

	// wait client handshake done
	select {
	case err := <-chClientHandshakeErr:
		_ = conn.Close()
		_ = pconn.Close()
		logrus.Error(err)
		return
	case <-chTlsHandshakeDone:
		logrus.Debug("Tls Client handshake done")
	}

	// serve proxy conn
	t.serveProxyConn(clientTlsConn, connCtx)
}

func (t *tracer) tlsServerHandshakeContext(ctx context.Context, connCtx *ProxyConnContext) error {
	clientHelloInfo := connCtx.ClientConnCtx.clientHelloInfo
	serverConnCtx := connCtx.ServerConnCtx
	tlsConfig := &tls.Config{
		InsecureSkipVerify: t.config.SslInsecure,
		ServerName:         clientHelloInfo.ServerName,
		NextProtos:         clientHelloInfo.SupportedProtos,
		CipherSuites:       clientHelloInfo.CipherSuites,
	}

	// get minVer maxVer if supportedVer > 0
	if len(clientHelloInfo.SupportedVersions) > 0 {
		minVer, maxVer := clientHelloInfo.SupportedVersions[0], clientHelloInfo.SupportedVersions[0]
		for _, ver := range clientHelloInfo.SupportedVersions {
			if ver < minVer {
				minVer = ver
			}
			if ver > maxVer {
				maxVer = ver
			}
		}
		tlsConfig.MinVersion = minVer
		tlsConfig.MaxVersion = maxVer
	}

	// trace server tls handshake
	serverConnCtx.tlsConn = tls.Client(serverConnCtx.Conn, tlsConfig)
	if err := serverConnCtx.tlsConn.HandshakeContext(ctx); err != nil {
		logrus.Error(err)
		return err
	}

	// get tls state
	tlsState := serverConnCtx.tlsConn.ConnectionState()
	serverConnCtx.tlsConnState = &tlsState

	serverConnCtx.client = &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return serverConnCtx.tlsConn, nil
			},
			ForceAttemptHTTP2:  true,
			DisableCompression: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return nil
}

func (t *tracer) serveProxyConn(tlsConn *tls.Conn, connCtx *ProxyConnContext) {
	connCtx.ClientConnCtx.NegotiatedProtocol = tlsConn.ConnectionState().NegotiatedProtocol
	t.listener.accept(&traceConn{
		Conn:    tlsConn,
		connCtx: connCtx,
	})
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
