package api

import (
	"io"
	"net/http"
	"net/url"
)

type Request struct {
	Method        string
	URL           *url.URL
	Host          string
	Params        url.Values
	Headers       http.Header
	ClientToken   string
	MFAHeaderVals []string
	WrapTTL       string
	Obj           interface{}

	BodyBytes []byte

	Body     io.Reader
	BodySize int64

	PolicyOverride bool
}
