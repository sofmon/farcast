package farcast

import (
	"context"
	"net/http"
)

// NetAPI provides outbound networking through FatLine. The HTTP client it
// returns routes every request through the instance's network boundary,
// which permits only the external hosts the application declared in its
// ./farcast manifest; everything else is denied by default.
type NetAPI interface {
	// HTTPClient returns an *http.Client whose transport is forced through
	// FatLine. Requests to undeclared hosts are denied.
	HTTPClient() *http.Client
	// Status reports the health of the instance's network boundary.
	Status(ctx context.Context) (ConnStatus, error)
}

// ConnStatus reports the health of the instance's network boundary. Further
// fields are added in the implementation phase.
type ConnStatus struct {
	Connected bool
}

// Net returns the networking capability.
//
// Implementation lands with FatLine in a later phase; until then this
// returns a stub. Its HTTP client deliberately refuses every request with
// ErrNotImplemented rather than reaching the network directly, so that no
// traffic can bypass the (not-yet-present) FatLine boundary.
func Net() NetAPI {
	return netStub{}
}

var (
	_ NetAPI            = netStub{}
	_ http.RoundTripper = deniedTransport{}
)

type netStub struct{}

func (netStub) HTTPClient() *http.Client {
	return &http.Client{Transport: deniedTransport{}}
}

func (netStub) Status(context.Context) (ConnStatus, error) {
	return ConnStatus{}, ErrNotImplemented
}

// deniedTransport fails every request, ensuring the stub never makes an
// un-proxied outbound connection.
type deniedTransport struct{}

func (deniedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, ErrNotImplemented
}
