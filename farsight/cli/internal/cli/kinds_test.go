package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The README's table of error kinds is the contract; this list is the code's.
// They are held to each other, so a kind cannot ship undocumented, and a
// documented one cannot be dropped.
func TestTheREADMEDocumentsEveryErrorKind(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	start := strings.Index(readme, "### Error kinds")
	if start < 0 {
		t.Fatal("the README has no Error kinds section")
	}
	section := readme[start:]
	if end := strings.Index(section[len("### Error kinds"):], "\n### "); end > 0 {
		section = section[:end+len("### Error kinds")]
	}
	var documented []string
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "| `") {
			documented = append(documented, strings.Trim(strings.SplitN(line, "|", 3)[1], " `"))
		}
	}
	if fmt.Sprint(documented) != fmt.Sprint(errorKinds) {
		t.Errorf("the README documents %v\nthe code has         %v", documented, errorKinds)
	}
	if strings.Contains(section, "| `usage`") {
		t.Error("usage is not a kind: exit 2 has no envelope")
	}
}

// Every command that loads an instance record that is not there reports
// not_found — inferred by the router, since none of them named it.
func TestAMissingRecordIsNotFoundForEveryCommand(t *testing.T) {
	dir := vectorConfigDir(t)
	for _, args := range [][]string{{"ps", "nowhere"}, {"costs", "nowhere"}, {"usage", "nowhere"}, {"world", "nowhere"}} {
		out, code := runRouter(t, append([]string{"--config", dir.Path(), "-o", "json"}, args...)...)
		var env struct {
			Error struct {
				Kind string `json:"kind"`
				Code int    `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(out, &env); err != nil {
			t.Fatalf("%v: not an envelope: %v\n%s", args, err, out)
		}
		if env.Error.Kind != kindNotFound || env.Error.Code != code || code != 1 {
			t.Errorf("%v: kind %q code %d exit %d", args, env.Error.Kind, env.Error.Code, code)
		}
	}
}

// Exit 2 has no envelope, in JSON mode as in human mode.
func TestUsageErrorsHaveNoEnvelope(t *testing.T) {
	dir := vectorConfigDir(t)
	for _, args := range [][]string{{"world"}, {"world", "--no-such-flag", "x"}, {"frobnicate"}, {"instances", "extra"}} {
		out, code := runRouter(t, append([]string{"--config", dir.Path(), "-o", "json"}, args...)...)
		if code != 2 || len(out) != 0 {
			t.Errorf("%v: exit %d, stdout %q; want exit 2 and nothing on stdout", args, code, out)
		}
	}
}

func TestKindsAreFoundThroughWrapping(t *testing.T) {
	err := fmt.Errorf("outer: %w", withKind(kindTimeout, errors.New("inner")))
	if kindOf(err) != kindTimeout || err.Error() != "outer: inner" {
		t.Errorf("kind %q, text %q", kindOf(err), err)
	}
	if kindOf(errors.New("plain")) != kindInternal || withKind(kindTimeout, nil) != nil {
		t.Error("a plain error is internal, and a nil one stays nil")
	}
	// A named kind is never overridden by the router's inference.
	named := withKind(kindRecordUnreadable, fmt.Errorf("x: %w", config.ErrNoInstanceRecord))
	if kindOf(classified(named)) != kindRecordUnreadable {
		t.Error("the router overrode a kind a command named")
	}
}

// The costs report reads the same checkpoint the same way, and its version
// refusal now carries the kind world reports.
func TestCostsAndWorldShareTheCheckpointReader(t *testing.T) {
	_, _, err := decodeCheckpoint(`{"version":99}`)
	if kindOf(err) != kindVersionSkew || !strings.Contains(err.Error(), "ledger version 99 and this build reads versions 1 to 2") {
		t.Errorf("version: %v (%s)", err, kindOf(err))
	}
	if _, _, err := decodeCheckpoint(`not json`); kindOf(err) != kindDocumentUnreadable || !strings.HasPrefix(err.Error(), "decode the kernel's ledger") {
		t.Errorf("garbage: %v (%s)", err, kindOf(err))
	}
	if got := notMeteredFacts(); len(got) != 5 || !strings.Contains(got[3], "$37/month") {
		t.Errorf("not metered: %q", got)
	}
}

// Design §8.1, mutation 61: a kind once shipped keeps its meaning, so the
// five ADR 0023 M2 retired are never emitted again and never reused. No
// kind in errorKinds is one of them, and no kind* constant in kinds.go holds
// one, read from the source so a constant added outside errorKinds is caught
// too.
func TestRetiredKindsAreNeverReused(t *testing.T) {
	if want := []string{"kubectl_missing", "kubectl_failed", "gcloud_mismatch", "gcloud_signed_out", "auth_tool_missing"}; !slices.Equal(retiredKinds, want) {
		t.Errorf("retiredKinds = %q, want %q", retiredKinds, want)
	}
	for _, k := range errorKinds {
		if slices.Contains(retiredKinds, k) {
			t.Errorf("errorKinds holds the retired kind %q", k)
		}
	}
	if len(errorKinds) != 21 {
		t.Errorf("errorKinds holds %d kinds, want the 21 of ADR 0023 M2.4", len(errorKinds))
	}
	f, err := parser.ParseFile(token.NewFileSet(), "kinds.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	consts := 0
	ast.Inspect(f, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.CONST {
			return true
		}
		for _, spec := range decl.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "kind") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue // kindInternal = output.KindInternal
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				consts++
				if slices.Contains(retiredKinds, v) {
					t.Errorf("the constant %s holds the retired kind %q", name.Name, v)
				}
			}
		}
		return false
	})
	if consts < 20 {
		t.Fatalf("read %d kind constants from kinds.go; the walk proves nothing", consts)
	}
}

// Design §8.1 and A18-9: every row of clusterKind's mapping, from wrapped
// errors, from the refusal type openCluster returns, and from what kube's
// own client returns against kubetest; in its order, and through classified,
// which gives an envelope its kind.
func TestClusterKindIsFoundByErrorsIs(t *testing.T) {
	apiError := func(code int, status bool) error {
		return fmt.Errorf("read: %w", &kube.APIError{Method: "GET", Path: "/api/v1/namespaces/farcast-system/configmaps/x",
			Status: kube.Status{Status: tkube.Status{Code: code}}, KubernetesStatus: status})
	}
	for _, row := range []struct {
		name string
		err  error
		want string
	}{
		{"a context that ended", fmt.Errorf("kube: GET x: %w", context.DeadlineExceeded), kindTimeout},
		{"a wait that ran out", fmt.Errorf("deployment a/b: %w", kube.ErrTimedOut), kindTimeout},
		{"an attempt past its deadline, which is unreachable too", errors.Join(kube.ErrUnreachable, context.DeadlineExceeded), kindTimeout},
		{"a refusal of the reader", refuse(errCredentialMissing, "instance %q has no reader identity", "atlas"), kindCredentialMissing},
		{"a key that is not one", fmt.Errorf("x: %w", kube.ErrCredentialInvalid), kindCredentialMissing},
		{"an environment that would print a secret", fmt.Errorf("x: %w", kube.ErrUnsafeEnvironment), kindUnsafeEnvironment},
		{"that environment, before the endpoint", errors.Join(kube.ErrEndpointRefused, kube.ErrUnsafeEnvironment), kindUnsafeEnvironment},
		{"no endpoint", refuse(kube.ErrEndpointRefused, "instance %q records no cluster endpoint", "atlas"), kindEndpointRefused},
		{"a mint refused", fmt.Errorf("x: %w", kube.ErrTokenRefused), kindCredentialRefused},
		{"nothing answered", fmt.Errorf("x: %w", kube.ErrUnreachable), kindClusterUnreachable},
		{"a token refused", apiError(http.StatusUnauthorized, true), kindUnauthorized},
		{"tkube's unauthorized", fmt.Errorf("x: %w", tkube.ErrUnauthorized), kindUnauthorized},
		{"RBAC's refusal", apiError(http.StatusForbidden, true), kindForbidden},
		{"the endpoint's refusal", apiError(http.StatusForbidden, false), kindForbidden},
		// Mutation O11: a chain holding a 401 and a 403, as logs' joined
		// namespace failures can when two namespaces answer differently in
		// one run, is unauthorized, whatever came first (§8.1's order).
		{"a 401 joined before a 403", errors.Join(apiError(http.StatusUnauthorized, true), apiError(http.StatusForbidden, true)), kindUnauthorized},
		{"a 403 joined before a 401", errors.Join(apiError(http.StatusForbidden, true), apiError(http.StatusUnauthorized, true)), kindUnauthorized},
		{"namespaces that answered 403 and 401", namespaceErrors{fmt.Errorf("a: %w", apiError(http.StatusForbidden, true)), fmt.Errorf("b: %w", apiError(http.StatusUnauthorized, true))}, kindUnauthorized},
		{"a document that does not read", fmt.Errorf("x: %w", kube.ErrUnreadable), kindDocumentUnreadable},
		{"a stalled rollout", fmt.Errorf("x: %w", kube.ErrRolloutStalled), kindRolloutStalled},
		{"an object that came back unmigrated", fmt.Errorf("x: %w", kube.ErrNotMigrated), kindClusterRejected},
		{"a document farcast refused", fmt.Errorf("x: %w", kube.ErrRefusedDocument), kindInternal},
		{"a 500", apiError(http.StatusInternalServerError, true), kindClusterRejected},
		{"a 404", apiError(http.StatusNotFound, true), kindClusterRejected},
		{"a 409", apiError(http.StatusConflict, true), kindClusterRejected},
		{"a 429", apiError(http.StatusTooManyRequests, true), kindClusterRejected},
		{"a kind a command named", withKind(kindVersionSkew, errors.New("x")), kindVersionSkew},
		{"a sentinel under a named kind", withKind(kindNotConnected, refuse(kube.ErrEndpointRefused, "x")), kindEndpointRefused},
		{"anything else", errors.New("plain"), ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := clusterKind(row.err); got != row.want {
				t.Errorf("clusterKind = %q, want %q", got, row.want)
			}
			var k interface{ ErrorKind() string }
			if errors.As(row.err, &k) {
				return // classified honours a kind a command named
			}
			want := row.want
			if want == "" {
				want = kindInternal
			}
			if got := kindOf(classified(row.err)); got != want {
				t.Errorf("classified's kind = %q, want %q", got, want)
			}
			if classified(row.err).Error() != row.err.Error() {
				t.Error("classifying changed the error's text")
			}
		})
	}

	// And what kube itself returns, read through openCluster as the reader.
	read := func(t *testing.T, opts ...kubetest.Option) (*kubetest.Server, func() error) {
		t.Helper()
		s := kubetest.New(t, opts...)
		dir, meta := readerInstance(t, s, "atlas", true)
		cl, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Reader})
		if err != nil {
			t.Fatal(err)
		}
		return s, func() error {
			_, _, err := cl.ConfigMapValue(t.Context(), "farcast-system", "technocore-checkpoint", "checkpoint.json")
			return err
		}
	}
	const path = "/api/v1/namespaces/farcast-system/configmaps/technocore-checkpoint"
	for _, row := range []struct {
		name string
		fail func(s *kubetest.Server)
		opts []kubetest.Option
		want string
	}{
		{"403", func(s *kubetest.Server) { s.Fail(http.MethodGet, path, http.StatusForbidden, kube.Status{}) }, nil, kindForbidden},
		{"401 after a fresh token", func(s *kubetest.Server) {
			s.Fail(http.MethodGet, path, http.StatusUnauthorized, kube.Status{})
			s.Fail(http.MethodGet, path, http.StatusUnauthorized, kube.Status{})
		}, nil, kindUnauthorized},
		{"500", func(s *kubetest.Server) { s.Fail(http.MethodGet, path, http.StatusInternalServerError, kube.Status{}) }, nil, kindClusterRejected},
		{"a mint refused", nil, []kubetest.Option{kubetest.WithTokenAnswer(func(string) (int, []byte, bool) {
			return http.StatusBadRequest, []byte(`{"error":"invalid_grant"}`), true
		})}, kindCredentialRefused},
		{"a server that is gone", func(s *kubetest.Server) { s.Close() }, nil, kindClusterUnreachable},
	} {
		t.Run("kube/"+row.name, func(t *testing.T) {
			s, call := read(t, row.opts...)
			if row.fail != nil {
				row.fail(s)
			}
			err := call()
			if got := clusterKind(err); got != row.want {
				t.Errorf("clusterKind(%v) = %q, want %q", err, got, row.want)
			}
			if got := kindOf(classified(err)); got != row.want {
				t.Errorf("classified's kind = %q, want %q", got, row.want)
			}
		})
	}
}

// Design §3.5 and §8.1, mutation 63: no endpoint recorded is endpoint_refused,
// never not_connected, which means no FatLine is recorded: in world's
// cluster sections, while its tunnel sections read, and in the envelopes of
// ps and costs. Nothing is sent.
func TestAMissingEndpointIsEndpointRefused(t *testing.T) {
	f := newWorldFixture(t) // a connected instance that records no cluster endpoint
	if m, err := f.dir.LoadInstanceMetadata("atlas"); err != nil || m.Endpoint != "" {
		t.Fatalf("guard: the fixture records the endpoint %q (%v)", m.Endpoint, err)
	}
	f.cmd.newCluster = nil // openCluster, as farcast runs it
	doc, raw := f.run(t)
	wantSections(t, doc.Sections, map[string]string{
		"spend": kindEndpointRefused, "apps": kindEndpointRefused, "policy": kindEndpointRefused,
		"network": "read", "seal": "read",
	})
	if msg := sectionMessage(t, raw, "apps"); msg != `instance "atlas" records no cluster endpoint; 'farcast install' records one; nothing was sent` {
		t.Errorf("apps: %q", msg)
	}
	for _, cmd := range []string{"ps", "costs"} {
		out, code := runRouter(t, "--config", f.dir.Path(), "-o", "json", cmd, "atlas")
		var env struct {
			Error struct {
				Kind string `json:"kind"`
			} `json:"error"`
		}
		if err := json.Unmarshal(out, &env); err != nil || code != 1 {
			t.Fatalf("%s: exit %d, not an envelope (%v):\n%s", cmd, code, err, out)
		}
		if env.Error.Kind != kindEndpointRefused {
			t.Errorf("%s: kind %q, want %q", cmd, env.Error.Kind, kindEndpointRefused)
		}
	}
}
