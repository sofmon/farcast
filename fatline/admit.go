package fatline

import (
	"crypto/tls"
	"net/http"
	"slices"
	"strings"

	"github.com/sofmon/farcast/fatline/identity"
)

// tunnelAdmits is the fixed rule for who may open the public tunnel at all:
// this instance's operator and its named keeper devices.
//
// Everything else the instance's CA issues is refused at the handshake. An
// application's leaf rests in a Kubernetes Secret, readable by whoever reads
// that namespace and by the cloud (ADR 0018 decision 6 prices it as worth one
// application's storage); admitted here, it would have opened the public
// carrier from anywhere and read every application's egress picture. Device
// leaves join only with the data route ADR 0018 decision 7 specifies.
//
// A rule rather than configuration: who may use the tunnel is a property of the
// identity scheme, and the only per-deployment input is which instance this is.
func tunnelAdmits(instance string) func(uri string) bool {
	operator := identity.OperatorURI(instance)
	keepers := identity.KeeperURI(instance, "")
	return func(uri string) bool {
		if instance == "" {
			return false
		}
		if uri == operator {
			return true
		}
		device, ok := strings.CutPrefix(uri, keepers)
		return ok && device != "" && !strings.ContainsAny(device, "/?#")
	}
}

// isKeeper reports whether an admitted caller is a keeper device rather than
// the operator.
func (s *Server) isKeeper(cs *tls.ConnectionState) bool {
	keepers := identity.KeeperURI(s.cfg.Instance, "")
	for _, u := range peerURIs(cs) {
		if strings.HasPrefix(u, keepers) && s.admits(u) {
			return true
		}
	}
	return false
}

// admitted reports whether the peer's leaf carries an identity the tunnel
// admits.
func (s *Server) admitted(cs *tls.ConnectionState) bool {
	return slices.ContainsFunc(peerURIs(cs), s.admits)
}

func peerURIs(cs *tls.ConnectionState) []string {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil
	}
	out := make([]string, 0, len(cs.PeerCertificates[0].URIs))
	for _, u := range cs.PeerCertificates[0].URIs {
		out = append(out, u.String())
	}
	return out
}

// admit re-checks the rule on every request. The handshake is the boundary;
// this keeps the handler from depending on it. Mutation testing confirms it is
// not load-bearing while the listener verifies the rule, and that is the point:
// it is what still holds if a later change serves the handler without it.
func (s *Server) admit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.admitted(r.TLS) {
			// Never echo the presented identity.
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
