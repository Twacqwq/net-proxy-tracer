package utils

import (
	"crypto/tls"
	"net"
	"net/url"
)

var schemeDefaultPortMap = map[string]string{
	"http":   "80",
	"https:": "443",
}

func HostJoinPort(u *url.URL) string {
	port := u.Port()
	if len(port) == 0 {
		port = schemeDefaultPortMap[u.Scheme]
	}

	return net.JoinHostPort(u.Hostname(), port)
}

// IsTLS .
func IsTLSConnection(conn net.Conn) bool {
	if _, ok := conn.(*tls.Conn); ok {
		return true
	}

	return false
}

func CheckTLSWithHeaderHex(b []byte) bool {
	return b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x03
}
