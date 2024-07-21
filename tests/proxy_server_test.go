package tests

import (
	"log"
	"net-proxy-tracer/proxy"
	"testing"
)

func TestProxyServer(t *testing.T) {
	p, err := proxy.NewProxyServer(&proxy.ProxyConfig{
		Addr: ":8080",
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := p.Start(); err != nil {
		log.Fatal(err)
	}
}
