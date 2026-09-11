// Command demo is the fixture the Phase 5.3 validation walk deploys.
//
// It exists because the claims 5.3 makes cannot be checked from outside a
// running application: that Config refuses the platform's namespace while that
// namespace is genuinely populated, that a Secret reaches no log in the clear,
// that a seal reports as a seal rather than as absence — and what a
// neighbouring application's secret does when reached for. That last one used
// to succeed, which was the uncomfortable half of ADR 0017; since ADR 0018
// gave every application its own scope it is refused, and the fixture reaches
// for it either way so a walk sees which.
//
// It reports STATE, never values: whether a secret is present and how long it
// is, never what it says. The one exception proves the rule — it deliberately
// logs a Secret, formats one, and marshals one, so the walk can read the
// redaction in `farcast logs` rather than trusting a unit test.
//
// See docs/runbooks/phase-5-3-validation.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	farcast "github.com/sofmon/farcast/sdk/go"
)

// The fixture's own configuration keys. DEMO_TIMEOUT is deliberately
// unparseable in the image, so the walk can see the SDK warn once and fall
// back rather than fail silently.
const (
	keyGreeting = "DEMO_GREETING"
	keyWorkers  = "DEMO_WORKERS"
	keyDebug    = "DEMO_DEBUG"
	keyTimeout  = "DEMO_TIMEOUT"

	// keySecret names the secret this application expects an operator to have
	// set with `farcast secret set`.
	keySecret = "DEMO_SECRET_NAME"

	// keyPeer and keyPeerSecret ask this application to read a NEIGHBOUR's
	// secret. Set them and it derives the neighbour's subtree from its own —
	// which is exactly what a compromised application would do, and exactly
	// what ADR 0017 decision 2 says succeeds today.
	keyPeer       = "DEMO_PEER"
	keyPeerSecret = "DEMO_PEER_SECRET"
)

func main() {
	ctx := context.Background()
	log := farcast.Log()

	// "app" and "instance" are NOT passed: the SDK stamps them on every record
	// and documents them as reserved keys. Passing them emits the pair twice —
	// the fixture did exactly that on its first run, which is a fair warning
	// that the logger takes an application's word for it.
	log.Info(ctx, "demo starting", "sdk_secrets_wired", os.Getenv("FARCAST_SECRETS_PREFIX") != "")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(collect(r.Context()))
	})

	// Reported on a tick as well as on demand, so a rotation, a seal and an
	// unseal are all visible in `farcast logs` without a restart — the SDK
	// holds no cache, and this is where that shows.
	go func() {
		for {
			report(ctx)
			time.Sleep(30 * time.Second)
		}
	}()

	srv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Error(ctx, "http server stopped", "err", err)
		os.Exit(1)
	}
}

// state is what this fixture is willing to say about a secret.
type state struct {
	Name  string `json:"name"`
	State string `json:"state"`
	Bytes int    `json:"bytes,omitempty"`
	Err   string `json:"err,omitempty"`
}

type snapshot struct {
	App      string            `json:"app"`
	Instance string            `json:"instance"`
	Config   map[string]string `json:"config"`
	Reserved map[string]any    `json:"reserved"`
	Secret   state             `json:"secret"`
	Peer     *state            `json:"peer,omitempty"`
}

func collect(ctx context.Context) snapshot {
	cfg := farcast.Config()
	s := snapshot{
		App:      farcast.AppName(),
		Instance: farcast.InstanceID(),
		Config: map[string]string{
			keyGreeting: cfg.GetString(keyGreeting, "(default)"),
			keyWorkers:  fmt.Sprint(cfg.GetInt(keyWorkers, -1)),
			keyDebug:    fmt.Sprint(cfg.GetBool(keyDebug, false)),
			// Present in the image and unparseable: the SDK warns once and
			// hands back this default.
			keyTimeout: fmt.Sprint(cfg.GetInt(keyTimeout, 30)),
		},
		Reserved: reserved(cfg),
		Secret:   readSecret(ctx, cfg.GetString(keySecret, "DB_PASSWORD")),
	}
	if peer := cfg.GetString(keyPeer, ""); peer != "" {
		p := readPeerSecret(ctx, peer, cfg.GetString(keyPeerSecret, "DB_PASSWORD"))
		s.Peer = &p
	}
	return s
}

// reserved is the contrast the walk is for: the credential IS in the
// environment, and Config will not hand it over.
//
// Its length is reported and its value never is. os.Getenv is used
// deliberately — Config is a guard rail on this SDK's surface, not a sandbox,
// and a fixture that hid that would be making a claim the SDK does not.
func reserved(cfg farcast.ConfigAPI) map[string]any {
	const key = "FARCAST_FATLINE_PROXY"
	raw := os.Getenv(key)
	_, viaConfig := cfg.Get(key)
	_, err := cfg.Require(key)

	class := "nil"
	switch {
	case errors.Is(err, farcast.ErrConfigReserved):
		class = "ErrConfigReserved"
	case errors.Is(err, farcast.ErrConfigMissing):
		class = "ErrConfigMissing"
	case err != nil:
		class = "other"
	}
	return map[string]any{
		"key":            key,
		"in_environment": raw != "",
		"env_bytes":      len(raw),
		"via_config":     viaConfig,
		"require_err":    class,
	}
}

func readSecret(ctx context.Context, name string) state {
	secret, err := farcast.Secrets().Get(ctx, name)
	st := state{Name: name, State: classify(err)}
	if err != nil {
		st.Err = err.Error()
		return st
	}
	st.Bytes = len(secret.Reveal())
	proveRedaction(ctx, secret)
	return st
}

// readPeerSecret derives a NEIGHBOUR's subtree from this application's own and
// reads from it through plain storage.
//
// It is not a back door: it is a probe, and what it demonstrates changed. Under
// ADR 0017 it succeeded, because every application shared one scope and the
// keyholder could not tell them apart. Under ADR 0018 each application has its
// own scope and its own leaf, so this is refused — and a walk that never
// reached for it could not tell the two worlds apart.
func readPeerSecret(ctx context.Context, peer, name string) state {
	// This application's own secrets prefix is app/<namespace>/<app>/secrets/.
	// A neighbour's is the same with the application segment replaced, which
	// is exactly the guess a compromised application would make.
	mine := os.Getenv("FARCAST_SECRETS_PREFIX")
	st := state{Name: peer + "/" + name}
	parts := strings.Split(strings.TrimSuffix(mine, "/"), "/")
	if mine == "" || len(parts) != 4 {
		st.State = "unconfigured"
		return st
	}
	parts[2] = peer
	data, err := farcast.Storage().Read(ctx, strings.Join(parts, "/")+"/"+name)
	st.State = classify(err)
	if err != nil {
		st.Err = err.Error()
		return st
	}
	st.Bytes = len(data)
	return st
}

// classify names the condition rather than the message, because the whole
// point of the sentinels is that an application branches on them.
func classify(err error) string {
	switch {
	case err == nil:
		return "present"
	case errors.Is(err, farcast.ErrSecretNotFound), errors.Is(err, farcast.ErrObjectNotFound):
		return "not-found"
	case errors.Is(err, farcast.ErrStorageSealed):
		return "sealed"
	case errors.Is(err, farcast.ErrNotImplemented):
		return "not-wired"
	case errors.Is(err, farcast.ErrPermission):
		return "refused"
	default:
		return "unavailable"
	}
}

// proveRedaction sends a real secret down every route that normally leaks one.
//
// The walk reads the result in `farcast logs`: if the value appears anywhere in
// this output, the redaction does not work on the wire, whatever the unit tests
// say.
func proveRedaction(ctx context.Context, secret farcast.Secret) {
	blob, err := json.Marshal(struct {
		Token farcast.Secret `json:"token"`
	}{Token: secret})

	farcast.Log().Info(ctx, "redaction check",
		"logged_directly", secret,
		"fmt_v", fmt.Sprintf("%v", secret),
		"fmt_s", fmt.Sprintf("%s", secret),
		"fmt_q", fmt.Sprintf("%q", secret),
		"fmt_hash_v", fmt.Sprintf("%#v", secret),
		"marshalled", string(blob),
		"marshal_err", fmt.Sprint(err),
	)
}

func report(ctx context.Context) {
	s := collect(ctx)
	log := farcast.Log()
	log.Info(ctx, "config", "values", s.Config)
	log.Info(ctx, "reserved namespace", "check", s.Reserved)
	log.Info(ctx, "secret", "name", s.Secret.Name, "state", s.Secret.State, "bytes", s.Secret.Bytes, "err", s.Secret.Err)
	if s.Peer != nil {
		log.Info(ctx, "neighbour's secret", "name", s.Peer.Name, "state", s.Peer.State, "bytes", s.Peer.Bytes, "err", s.Peer.Err)
	}
}
