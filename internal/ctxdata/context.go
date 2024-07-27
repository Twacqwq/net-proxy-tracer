package ctxdata

import "context"

var (
	ProxyConn = new(ContextKey)
	ProxyReq  = new(ContextKey)
)

type ContextKey struct{}

func (c *ContextKey) WithValue(parent context.Context, val any) context.Context {
	return context.WithValue(parent, c, val)
}
