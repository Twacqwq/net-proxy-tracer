package utils

import (
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
