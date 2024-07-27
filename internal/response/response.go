package response

import (
	"io"
	"net/http"
)

type ProxyResponseWriterCheck struct {
	http.ResponseWriter

	Wrote bool
}

func NewProxyResponseWriterCheck(w http.ResponseWriter) *ProxyResponseWriterCheck {
	return &ProxyResponseWriterCheck{
		ResponseWriter: w,
	}
}

func (w *ProxyResponseWriterCheck) WriteHeader(statusCode int) {
	w.Wrote = true
	w.ResponseWriter.WriteHeader(statusCode)
}

type Response struct {
	StatusCode int         `json:"status_code"`
	Header     http.Header `json:"header"`
	Body       []byte      `json:"-"`
	BodyReader io.Reader
	Close      bool
}

func (resp *Response) WriteBody(w http.ResponseWriter, body io.Reader) error {
	if resp.Header != nil {
		for k, v := range resp.Header {
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}
	}
	if resp.Close {
		w.Header().Add("Connection", "close")
	}
	w.WriteHeader(resp.StatusCode)

	if body != nil {
		_, err := io.Copy(w, body)
		if err != nil {
			return err
		}
	}

	if resp.BodyReader != nil {
		_, err := io.Copy(w, resp.BodyReader)
		if err != nil {
			return err
		}
	}

	if len(resp.Body) > 0 {
		_, err := w.Write(resp.Body)
		if err != nil {
			return err
		}
	}

	return nil
}
