package fatline

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/internal/netcopy"
)

// StreamPathPrefix is the ingress route that relays an opaque byte stream to a
// named in-instance service.
const StreamPathPrefix = "/_fatline/dial/"

// streamDialTimeout bounds reaching the in-instance service.
const streamDialTimeout = 10 * time.Second

// StreamRoute names one in-instance service the operator may reach through the
// tunnel.
//
// Routes are a CLOSED list fixed at deploy time, and a caller names a route
// rather than an address. That distinction is the whole security property: an
// operator leaf is a credential for reaching the services FarCast deployed, not
// a general-purpose port-forward into the cluster's network. Nothing a caller
// sends is ever used as a hostname.
type StreamRoute struct {
	// Name is what a caller asks for.
	Name string
	// Addr is the "host:port" to dial. When Ordinals is set it must contain
	// the substring "{ordinal}", which is replaced by the requested index.
	Addr string
	// Ordinals, when positive, admits indices in [0, Ordinals) so a caller
	// can address one replica of a StatefulSet deterministically. Zero means
	// the route has no ordinals and any index is refused.
	Ordinals int
}

// resolve turns a request's route name and ordinal into an address.
func (r StreamRoute) resolve(ordinal string) (string, error) {
	if r.Ordinals <= 0 {
		if ordinal != "" {
			return "", errors.New("route takes no ordinal")
		}
		return r.Addr, nil
	}
	if ordinal == "" {
		return "", errors.New("route requires an ordinal")
	}
	i, err := strconv.Atoi(ordinal)
	if err != nil || i < 0 || i >= r.Ordinals {
		return "", errors.New("ordinal out of range")
	}
	// Only the canonical spelling is accepted. Atoi takes "+1" as 1, and a
	// relay whose address depends on caller-supplied text should have exactly
	// one input that reaches any given service — not a family of them.
	if strconv.Itoa(i) != ordinal {
		return "", errors.New("ordinal must be canonical decimal")
	}
	return strings.ReplaceAll(r.Addr, "{ordinal}", strconv.Itoa(i)), nil
}

// validateStreamRoutes rejects a configuration that could not behave as
// documented, at construction rather than on first use.
func validateStreamRoutes(routes []StreamRoute) error {
	seen := make(map[string]struct{}, len(routes))
	for _, r := range routes {
		if r.Name == "" || strings.ContainsAny(r.Name, "/?#") {
			return fmt.Errorf("fatline: invalid stream route name %q", r.Name)
		}
		if _, dup := seen[r.Name]; dup {
			return fmt.Errorf("fatline: duplicate stream route %q", r.Name)
		}
		seen[r.Name] = struct{}{}
		if r.Addr == "" {
			return fmt.Errorf("fatline: stream route %q has no address", r.Name)
		}
		if r.Ordinals > 0 && !strings.Contains(r.Addr, "{ordinal}") {
			return fmt.Errorf("fatline: stream route %q has ordinals but no {ordinal} in its address", r.Name)
		}
		if r.Ordinals == 0 && strings.Contains(r.Addr, "{ordinal}") {
			return fmt.Errorf("fatline: stream route %q has {ordinal} in its address but no ordinals", r.Name)
		}
	}
	return nil
}

// streamHandler relays a full-duplex byte stream to a named in-instance
// service. It is how the operator reaches a service that must not be reachable
// from outside the instance — today the DataSphere keyholder.
//
// FatLine copies; it does not terminate what rides inside. The caller runs its
// own TLS session end-to-end with the service, so the bytes crossing this
// process are ciphertext under keys FatLine does not hold. That is deliberate
// and it is the reason this handler is so small: FatLine is the process on
// attacker-controlled bytes, and the material an operator pushes through here
// is the one secret whose exposure cannot be undone by rotation.
//
// The relay is HTTP/2 rather than CONNECT with a hijack. Go's HTTP/2 server
// does not implement http.Hijacker, and this listener negotiates h2, so a
// hijacking design would fail at run time with a hang rather than an error.
func (s *Server) streamHandler(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 {
		http.Error(w, "stream relay requires HTTP/2", http.StatusHTTPVersionNotSupported)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream relay requires a flushable response", http.StatusInternalServerError)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, StreamPathPrefix)
	route, found := s.route(name)
	if !found {
		// The refusal names nothing it was not given: an unknown route is
		// reported as unknown, never with the list of known ones.
		s.emitStream(name, "unknown_route", 0, 0)
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	addr, err := route.resolve(r.URL.Query().Get("ordinal"))
	if err != nil {
		s.emitStream(name, "bad_ordinal", 0, 0)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Dial on a background context with its own timeout: the request context
	// governs the relay, not the dial, and cancelling one must not silently
	// abandon a half-open upstream.
	dialCtx, cancel := context.WithTimeout(context.Background(), streamDialTimeout)
	defer cancel()
	var d net.Dialer
	upstream, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		s.emitStream(name, "dial_failed", 0, 0)
		http.Error(w, "cannot reach the service", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()

	// Headers must go out before any payload arrives, or the caller's own
	// request would block waiting for a response that is waiting for it.
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	up, down := netcopy.Duplex(upstream, flushWriter{w: w, f: flusher}, r.Body)

	// Shrike still witnesses that a relay happened, and how much moved — the
	// route name and byte counts only. No payload byte is ever recorded.
	s.emitStream(name, "relayed", up, down)
}

// route looks up a configured route by name.
func (s *Server) route(name string) (StreamRoute, bool) {
	for _, r := range s.cfg.StreamRoutes {
		if r.Name == name {
			return r, true
		}
	}
	return StreamRoute{}, false
}

func (s *Server) emitStream(route, reason string, up, down int64) {
	kind := event.Allow
	if reason != "relayed" {
		kind = event.Deny
	}
	s.events.Emit(event.Event{
		Kind:      kind,
		Proto:     "stream",
		Host:      route,
		Reason:    reason,
		BytesUp:   up,
		BytesDown: down,
	})
}

// flushWriter pushes each chunk to the caller as it arrives. Without the flush
// the relay would buffer, which turns an interactive duplex session into one
// that appears to hang.
type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	fw.f.Flush()
	return n, err
}
