package tests

import (
	"log"
	"testing"

	"github.com/Twacqwq/net-proxy-tracer/proxy"
)

func TestProxyServer(t *testing.T) {
	p, err := proxy.NewProxyServer(&proxy.ProxyConfig{
		Addr:  ":8080",
		Debug: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := p.Start(); err != nil {
		log.Fatal(err)
	}
}
