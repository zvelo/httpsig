package httpsig

import (
	"net/http"
	"strings"

	"zvelo.io/httpsig/digest"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/opentracing/opentracing-go/log"
)

// These are the default values for TransportOptions
const (
	DefaultDigestAlgo = digest.SHA256
	DefaultHeaderType = SignatureHeader
)

type transport struct {
	keyID      string
	key        interface{}
	algo       Algorithm
	digestAlgo digest.Algorithm
	headerType HeaderType
}

func defaultTransport() *transport {
	return &transport{
		digestAlgo: DefaultDigestAlgo,
		headerType: DefaultHeaderType,
	}
}

// A TransportOption is an option that can be used with Algorithm.Transport
type TransportOption func(*transport)

// WithAuthorizationHeader causes the Transport to use the Authorization header
// for HTTP signatures instead of the Signature header
func WithAuthorizationHeader() TransportOption {
	return func(t *transport) {
		t.headerType = AuthorizationHeader
	}
}

// WithDigestAlgorithm causes the Transport to use the digest algorithm val when
// generating HTTP Digest headers
func WithDigestAlgorithm(val digest.Algorithm) TransportOption {
	if val == digest.Unknown {
		val = DefaultDigestAlgo
	}

	return func(t *transport) {
		t.digestAlgo = val
	}
}

func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return &r2
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = cloneRequest(req) // per RoundTripper contract

	span, _ := opentracing.StartSpanFromContext(req.Context(), strings.ToUpper(req.URL.Scheme)+" "+req.Method)
	defer span.Finish()

	ext.SpanKindRPCClient.Set(span)
	ext.HTTPMethod.Set(span, req.Method)
	ext.HTTPUrl.Set(span, req.URL.String())
	ext.Component.Set(span, "httpsig")

	if err := t.headerType.Set(t.algo, t.keyID, t.key, req, t.digestAlgo); err != nil {
		span.LogFields(
			log.String("event", "error"),
			log.Error(err),
		)
		return nil, err
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		span.LogFields(
			log.String("event", "error"),
			log.Error(err),
		)
		return nil, err
	}

	ext.HTTPStatusCode.Set(span, uint16(resp.StatusCode))

	return resp, nil
}

// Transport returns an http.RoundTripper that sets HTTP signatures on outgoing
// requests
func (a Algorithm) Transport(keyID string, key interface{}, opts ...TransportOption) http.RoundTripper {
	t := defaultTransport()
	for _, opt := range opts {
		opt(t)
	}
	t.keyID = keyID
	t.key = key
	t.algo = a
	return t
}
