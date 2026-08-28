package keyholder

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/sofmon/farcast/datasphere"
)

// Header names carried by the data path.
//
// The logical key rides a header, base64-encoded, rather than a URL path or
// query. Both halves of that matter. A logical key is raw bytes that
// participate in authentication — this module performs no Unicode folding, no
// slash collapsing, no trimming — and net/http cleans request paths, so a key
// routed through a path would arrive silently different from the one written,
// making the object permanently unreadable. Base64 keeps arbitrary UTF-8,
// embedded newlines and non-normalized forms byte-exact through a header that
// must stay ASCII. It also keeps logical keys out of request logs, which are
// the one place a name would otherwise leak in the clear.
const (
	HeaderKey    = "X-Farcast-Key"
	HeaderPrefix = "X-Farcast-Prefix"
	HeaderScope  = "X-Farcast-Scope"
	HeaderCode   = "X-Farcast-Code"
)

// Content types the unseal endpoint accepts. The endpoint contract is "opaque
// bytes, encoding named by Content-Type", so the sealed form can arrive
// alongside the plain one without the route changing.
const (
	ContentTypeBundle = "application/vnd.farcast.bundle"
)

// DefaultMaxObjectBytes caps a single object. It matches the blob format's own
// object cap; streaming for larger objects is an interface decision the frozen
// StorageAPI does not yet carry.
const DefaultMaxObjectBytes = 64 << 20

// StoreFor builds a Store over a scope's key material.
//
// It is a seam rather than a Provider field so the HTTP layer holds no
// knowledge of buckets or cloud adapters — the layering rule, in the type
// system. A Store is built per request rather than cached: an unseal can
// replace key material at any moment, and a cached Store would keep serving
// the retired keys.
type StoreFor func(datasphere.Scope) (*datasphere.Store, error)

// Config parameterizes a keyholder's HTTP surface.
type Config struct {
	// Instance is the instance this keyholder serves.
	Instance string
	// Vault holds the key material and the seal state.
	Vault *Vault
	// Stores builds a Store for a scope.
	Stores StoreFor
	// MaxObjectBytes caps a single object; zero means DefaultMaxObjectBytes.
	MaxObjectBytes int64
	// Log receives structured events. Key material never reaches it, and
	// neither do logical keys.
	Log *slog.Logger
}

// Server is the keyholder's HTTP surface. It exposes three muxes rather than
// one, because the three audiences are different and must not share a port:
// the kubelet (unauthenticated, must work while sealed), the operator and
// keepers (mTLS, may change the seal state), and applications (may read and
// write plaintext).
type Server struct {
	cfg Config
	max int64
	log *slog.Logger
}

// NewServer validates the configuration and returns the surface.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Instance == "" {
		return nil, errors.New("keyholder: instance is required")
	}
	if cfg.Vault == nil {
		return nil, errors.New("keyholder: vault is required")
	}
	if cfg.Stores == nil {
		return nil, errors.New("keyholder: a StoreFor seam is required")
	}
	max := cfg.MaxObjectBytes
	if max <= 0 {
		max = DefaultMaxObjectBytes
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, max: max, log: log}, nil
}

// StatusHandler serves the probes and the seal state.
//
// It carries no key material and no plaintext, which is what lets it run
// unauthenticated on a port the kubelet can reach — and, more importantly,
// what lets it be published for NOT-ready pods. When every replica is sealed
// the data Service has no endpoints at all, so without a status endpoint that
// answers while sealed, an application would receive an opaque dial error
// instead of ErrStorageSealed: the ADR's flagship contract failing in exactly
// the scenario it was written for.
func (s *Server) StatusHandler() http.Handler {
	mux := http.NewServeMux()

	// Liveness must NEVER fail because the keyholder is sealed. A sealed
	// keyholder is healthy and waiting; failing liveness here would restart
	// it in a loop, and every restart is another seal. This is the single
	// most dangerous misconfiguration in the deployment.
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.cfg.Vault.Ready() {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ready")
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, string(s.cfg.Vault.State().Phase))
	})

	mux.HandleFunc("GET /v1/state", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, stateBody(s.cfg.Instance, s.cfg.Vault.State()))
	})

	return mux
}

// ControlHandler serves the operator and, from 5.4, keeper devices. Every
// route here changes or reports the seal state; none of them touch stored
// data. The caller wraps it in mTLS that admits only operator and keeper
// leaves — this handler assumes its peer is already authenticated.
func (s *Server) ControlHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/state", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, stateBody(s.cfg.Instance, s.cfg.Vault.State()))
	})

	mux.HandleFunc("POST /v1/unseal", func(w http.ResponseWriter, r *http.Request) {
		intent := Intent(r.URL.Query().Get("intent"))
		switch intent {
		case IntentOperator, IntentReseed:
		case "":
			// Absent intent is the conservative one: a caller that does
			// not claim to be a person is not treated as one.
			intent = IntentReseed
		default:
			s.fail(w, r, fmt.Errorf("%w: unknown intent %q", datasphere.ErrBundleInvalid, intent))
			return
		}

		payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.max))
		if err != nil {
			s.fail(w, r, fmt.Errorf("%w: unreadable body", datasphere.ErrBundleInvalid))
			return
		}
		bundle, err := datasphere.ParseBundle(payload)
		clear(payload)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		defer bundle.Zero()

		if err := s.cfg.Vault.Unseal(bundle, intent); err != nil {
			// Logged without the bundle: a refusal names phases and
			// generations, never material.
			s.log.Warn("unseal refused", "intent", intent, "generation", bundle.Generation(), "error", err)
			s.fail(w, r, err)
			return
		}
		st := s.cfg.Vault.State()
		s.log.Info("unsealed", "intent", intent, "generation", st.Generation, "scopes", len(st.Scopes))
		writeJSON(w, http.StatusOK, stateBody(s.cfg.Instance, st))
	})

	mux.HandleFunc("POST /v1/seal", func(w http.ResponseWriter, r *http.Request) {
		hold := r.URL.Query().Get("hold") == "true"
		reason := r.URL.Query().Get("reason")
		st := s.cfg.Vault.Seal(hold, reason)
		s.log.Info("sealed", "hold", hold, "phase", st.Phase)
		writeJSON(w, http.StatusOK, stateBody(s.cfg.Instance, st))
	})

	mux.HandleFunc("POST /v1/release-hold", func(w http.ResponseWriter, r *http.Request) {
		st := s.cfg.Vault.ReleaseHold()
		s.log.Info("hold released", "phase", st.Phase)
		writeJSON(w, http.StatusOK, stateBody(s.cfg.Instance, st))
	})

	return mux
}

// DataHandler serves applications the four frozen StorageAPI operations.
func (s *Server) DataHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/object", s.read)
	mux.HandleFunc("PUT /v1/object", s.write)
	mux.HandleFunc("DELETE /v1/object", s.delete)
	mux.HandleFunc("GET /v1/list", s.list)
	return mux
}

func (s *Server) read(w http.ResponseWriter, r *http.Request) {
	key, store, err := s.resolve(r, HeaderKey)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	data, err := store.Read(r.Context(), key)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) write(w http.ResponseWriter, r *http.Request) {
	key, store, err := s.resolve(r, HeaderKey)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.max))
	if err != nil {
		s.fail(w, r, fmt.Errorf("%w: body exceeds %d bytes", datasphere.ErrTooLarge, s.max))
		return
	}
	if err := store.Write(r.Context(), key, body); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	key, store, err := s.resolve(r, HeaderKey)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := store.Delete(r.Context(), key); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	prefix, store, err := s.resolve(r, HeaderPrefix)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	keys, err := store.List(r.Context(), prefix)
	if err != nil {
		// A sealed or failing List must never answer with an empty set and
		// success: an application that read "no objects" from a seal could
		// conclude its data is gone.
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// resolve decodes the requested logical key and returns a Store over the scope
// that owns it.
func (s *Server) resolve(r *http.Request, header string) (string, *datasphere.Store, error) {
	raw := r.Header.Get(header)
	if raw == "" && header == HeaderKey {
		return "", nil, fmt.Errorf("%w: missing %s header", datasphere.ErrInvalidKey, header)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %s is not base64", datasphere.ErrInvalidKey, header)
	}
	key := string(decoded)

	// The scope is required rather than inferred. When 4.x derives it from
	// the caller's own certificate, a request that omits it must already be
	// a refusal — otherwise that change would be a fail-open one.
	declared := r.Header.Get(HeaderScope)
	if declared == "" {
		return "", nil, fmt.Errorf("%w: missing %s header", ErrOutOfScope, HeaderScope)
	}

	scope, err := s.cfg.Vault.Scope(key)
	if err != nil {
		return "", nil, err
	}
	if scope.Name != declared {
		return "", nil, fmt.Errorf("%w: key belongs to scope %q, request declared %q", ErrOutOfScope, scope.Name, declared)
	}
	store, err := s.cfg.Stores(scope)
	if err != nil {
		return "", nil, err
	}
	return key, store, nil
}

// fail writes the wire error. The message never quotes the logical key: it is
// a name the cloud must not learn, and an error body is the easiest place for
// one to escape into a log.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code := classify(err)
	if status == http.StatusInternalServerError {
		// An unrecognized error is a bug in the mapping, not a condition
		// to describe to a caller. Log it here and say nothing outward.
		s.log.Error("unclassified keyholder error", "path", r.URL.Path, "error", err)
		writeJSONWithCode(w, status, code, errorResponse{Code: code, Message: "internal error"})
		return
	}
	writeJSONWithCode(w, status, code, errorResponse{Code: code, Message: safeMessage(err)})
}

// safeMessage renders an error for a caller. Sentinel text is written in this
// package and in datasphere and never contains caller data; anything else is
// reduced to its sentinel so a wrapped message cannot carry a logical key out.
func safeMessage(err error) string {
	for _, known := range []error{
		ErrSealed, ErrOperatorHold, ErrGenerationTooOld, ErrInstanceMismatch, ErrOutOfScope,
		datasphere.ErrObjectNotFound, datasphere.ErrIntegrity, datasphere.ErrUnknownKey,
		datasphere.ErrInvalidKey, datasphere.ErrTooLarge, datasphere.ErrBundleInvalid,
		datasphere.ErrKeyringInvalid,
	} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "request refused"
}

type stateResponse struct {
	Instance   string    `json:"instance"`
	Phase      string    `json:"phase"`
	Since      time.Time `json:"since"`
	Generation uint64    `json:"generation"`
	HoldReason string    `json:"hold_reason,omitempty"`
	Scopes     []string  `json:"scopes,omitempty"`
}

func stateBody(instance string, st State) stateResponse {
	return stateResponse{
		Instance:   instance,
		Phase:      string(st.Phase),
		Since:      st.Since,
		Generation: st.Generation,
		HoldReason: st.HoldReason,
		Scopes:     st.Scopes,
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	writeJSONWithCode(w, status, "", body)
}

func writeJSONWithCode(w http.ResponseWriter, status int, code string, body any) {
	w.Header().Set("Content-Type", "application/json")
	if code != "" {
		// The code also rides a header so a caller can classify without
		// parsing a body it may have failed to read.
		w.Header().Set(HeaderCode, code)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
