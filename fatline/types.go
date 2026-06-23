package fatline

import (
	"errors"
	"net/http"
	"time"
)

// StatusPath is the ingress endpoint the tunnel client queries for ConnStatus.
const StatusPath = "/_fatline/status"

// ConnStatus reports the health of the instance's network boundary. The SDK
// (sdk/go/net.go) keeps its own ConnStatus and maps onto Connected over the
// wire; `farcast connect` (2.3) renders the rest.
type ConnStatus struct {
	Connected bool      `json:"connected"`
	Endpoint  string    `json:"endpoint,omitempty"`
	Since     time.Time `json:"since,omitzero"`
	Active    int       `json:"active"`
	Allowlist []string  `json:"allowlist,omitempty"`
}

// Egress is the deny-by-default outbound proxy seam: an http.Handler that
// speaks CONNECT for HTTPS and absolute-URI for plain HTTP. The hot path sits
// behind this interface so a benchmark-gated Rust data plane (ADR 0002) can
// replace it without caller churn.
type Egress interface {
	http.Handler
}

// ErrDenied is the sentinel a client-side transport maps a denied CONNECT (HTTP
// 403 from FatLine) onto, so application code can errors.Is it. FatLine answers
// a denied request with 403; the SDK adopts this mapping when it is wired to
// FatLine (replacing its current ErrNotImplemented stub).
var ErrDenied = errors.New("fatline: destination not in allowlist")
