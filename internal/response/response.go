package response

import "net/http"

type ProxyResponseWriter struct {
	http.ResponseWriter

	Wrote bool
}

func NewProxyResponseWriter(w http.ResponseWriter) *ProxyResponseWriter {
	return &ProxyResponseWriter{
		ResponseWriter: w,
	}
}

func (w *ProxyResponseWriter) WriteHeader(statusCode int) {
	w.Wrote = true
	w.ResponseWriter.WriteHeader(statusCode)
}
