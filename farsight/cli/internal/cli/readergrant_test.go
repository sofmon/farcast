package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// grantStart is the fake clock's start in these tests.
var grantStart = time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

// grantClock is a fake clock: Sleep advances it at once and keeps each wait.
type grantClock struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
}

func (c *grantClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *grantClock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	c.slept = append(c.slept, d)
	return nil
}

// grantMetered is what the fixtures' kernel meters.
var grantMetered = []string{"farcast-system", "web"}

// grantFixture is a loopback instance against kubetest, its reader recorded
// and uploaded, its kernel metering farcast-system and web, and a 'reader
// grant' whose kubectl apply is a fake, whose terminal answers "y", and whose
// clock is fake. Its reader opens through the default newReader, openCluster.
type grantFixture struct {
	s       *kubetest.Server
	dir     config.Dir
	email   string
	applier *fakeCluster
	// applierRefs is every clusterRef newApplier was handed.
	applierRefs []clusterRef
	clock       *grantClock
	cmd         *readerGrantCommand
	env         *Env
	out, errb   *bytes.Buffer
}

const grantName = "atlas"

// grantEmail is the fixtures' reader: the derived loopback one.
var grantEmail = readerName(grantName) + "@kubetest.invalid"

// grantRBAC authorizes the fixture's reader with the RBAC 'reader grant'
// renders for it, as if the apply had landed.
func grantRBAC(t *testing.T) kubetest.Option {
	t.Helper()
	stream, err := renderReaderRBAC(grantEmail, grantMetered)
	if err != nil {
		t.Fatal(err)
	}
	return kubetest.WithRBAC(grantEmail, stream)
}

// grantNothing authorizes the fixture's reader with RBAC that binds another
// account, so every read it makes is forbidden: a grant that never landed.
func grantNothing(t *testing.T) kubetest.Option {
	t.Helper()
	stream, err := renderReaderRBAC(readerName("other")+"@kubetest.invalid", grantMetered)
	if err != nil {
		t.Fatal(err)
	}
	return kubetest.WithRBAC(grantEmail, stream)
}

func newGrantFixture(t *testing.T, granted bool, opts ...kubetest.Option) *grantFixture {
	t.Helper()
	f := &grantFixture{s: kubetest.New(t, opts...), email: grantEmail, applier: &fakeCluster{}, clock: &grantClock{now: grantStart}}
	managed := map[string]any{"app.kubernetes.io/managed-by": "farcast"}
	for _, ns := range grantMetered {
		f.s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns, "labels": managed}})
	}
	dir, meta := readerInstance(t, f.s, grantName, granted)
	if meta.Reader.Email != grantEmail {
		t.Fatalf("the fixture's reader is %q, not %q", meta.Reader.Email, grantEmail)
	}
	meta.Kernel = &config.Kernel{Deployed: true, Applied: true, Namespaces: grantMetered}
	if err := dir.SaveInstanceMetadata(grantName, meta); err != nil {
		t.Fatal(err)
	}
	f.dir = dir
	f.cmd = &readerGrantCommand{
		newApplier: func(r clusterRef) (clusterApplier, error) {
			f.applierRefs = append(f.applierRefs, r)
			return f.applier, nil
		},
		interactive: func(*Env) bool { return true },
		now:         f.clock.Now,
		sleep:       f.clock.Sleep,
	}
	f.env, f.out, f.errb = testEnvBoth(dir, output.ModeHuman)
	f.env.In = strings.NewReader("y\n")
	return f
}

func (f *grantFixture) run(t *testing.T) error {
	t.Helper()
	return f.cmd.Run(context.Background(), f.env, []string{grantName})
}

func (f *grantFixture) reader(t *testing.T) *config.Reader {
	t.Helper()
	meta, err := f.dir.LoadInstanceMetadata(grantName)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Reader == nil {
		t.Fatal("the reader record is gone")
	}
	return meta.Reader
}

// apiRequests is every request but the token mints, and the method and path
// of each.
func apiRequests(s *kubetest.Server) (reqs []kubetest.Request, lines []string) {
	for _, r := range s.Requests() {
		if r.Path == "/token" {
			continue
		}
		reqs = append(reqs, r)
		lines = append(lines, r.Method+" "+r.Path)
	}
	return reqs, lines
}

func countMethod(reqs []kubetest.Request, method string) int {
	n := 0
	for _, r := range reqs {
		if r.Method == method {
			n++
		}
	}
	return n
}

const selfReviewPath = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"

// ADR 0023 M2.3, mutation 51: 'reader grant' records the reader as granted
// only after one read as the reader succeeded. The read is retried on a 401
// or a 403 while IAM propagates, after 5, 10, 20 and 40 seconds and then every
// 60, for 8 minutes on the fake clock; a 403 that outlasts it records nothing.
// No other failure is retried.
func TestReaderGrantVerifiesAsTheReader(t *testing.T) {
	t.Run("granted at the first read", func(t *testing.T) {
		f := newGrantFixture(t, false, grantRBAC(t))
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		reqs, lines := apiRequests(f.s)
		if got := countMethod(reqs, http.MethodGet); got != 1 {
			t.Errorf("%d GETs; want the one verifying read: %q", got, lines)
		}
		if reqs[0].Method != http.MethodGet || reqs[0].Path != "/api/v1/namespaces" ||
			!strings.Contains("&"+reqs[0].RawQuery+"&", "&labelSelector=app.kubernetes.io%2Fmanaged-by%3Dfarcast&") {
			t.Errorf("the first request is %s %s?%s; want the verifying read", reqs[0].Method, reqs[0].Path, reqs[0].RawQuery)
		}
		if got := countMethod(reqs, http.MethodPost); got != len(readerReviews) {
			t.Errorf("%d POSTs; want the %d reviews: %q", got, len(readerReviews), lines)
		}
		for _, r := range f.s.Requests() {
			if r.As != "reader" {
				t.Errorf("%s %s as %q; want only the reader", r.Method, r.Path, r.As)
			}
			if r.Method == http.MethodPost && r.Path != selfReviewPath && r.Path != "/token" {
				t.Errorf("POST %s: the verification writes nothing", r.Path)
			}
		}
		got := f.reader(t)
		if !got.GrantedAt.Equal(grantStart) || got.Scope != readerScopeMetered || got.Email != grantEmail {
			t.Errorf("recorded %+v; want GrantedAt %s and Scope %q", got, grantStart, readerScopeMetered)
		}
		if len(f.clock.slept) != 0 || strings.Contains(f.errb.String(), "IAM changes") {
			t.Errorf("a read that succeeded at once waited %v:\n%s", f.clock.slept, f.errb)
		}
		for _, ns := range grantMetered {
			if line := "the reader " + grantEmail + " may now read " + ns + "\n"; !strings.Contains(f.out.String(), line) {
				t.Errorf("the result does not say %q:\n%s", line, f.out)
			}
		}
	})

	t.Run("a 403 that outlasts the backoff", func(t *testing.T) {
		f := newGrantFixture(t, false, grantNothing(t))
		err := f.run(t)
		if err == nil || !errors.Is(err, tkube.ErrForbidden) || !strings.Contains(err.Error(), "still cannot read instance \"atlas\"'s cluster after 8m0s") ||
			!strings.Contains(err.Error(), "nothing was recorded") {
			t.Fatalf("grant = %v; want the 403 that outlasted 8 minutes", err)
		}
		// The 403 is the reader's: reader grant's writer makes no in-process
		// call, so its error never names the installer service account
		// (A20-9 is for the writer's own 403s; M-F8).
		if strings.Contains(err.Error(), "installer service account") {
			t.Errorf("reader grant's 403 names the installer: %q", err)
		}
		want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second,
			time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, 45 * time.Second}
		if !slices.Equal(f.clock.slept, want) {
			t.Errorf("waited %v; want %v", f.clock.slept, want)
		}
		if got := f.clock.Now().Sub(grantStart); got != readerPropagation {
			t.Errorf("gave up after %s; want %s", got, readerPropagation)
		}
		reqs, lines := apiRequests(f.s)
		if got := countMethod(reqs, http.MethodGet); got != len(want)+1 {
			t.Errorf("%d reads; want one per attempt, %d: %q", got, len(want)+1, lines)
		}
		if got := countMethod(reqs, http.MethodPost); got != 0 {
			t.Errorf("%d reviews after a read that never succeeded: %q", got, lines)
		}
		line := "IAM changes typically take 2 minutes, and can take 7 minutes or longer; checking again until 10:08:00\n"
		if got := strings.Count(f.errb.String(), line); got != 1 {
			t.Errorf("stderr says %q %d times; want once:\n%s", line, got, f.errb)
		}
		if got := f.reader(t); !got.GrantedAt.IsZero() || got.Scope != "" {
			t.Errorf("a reader that never read was recorded: %+v", got)
		}
	})

	t.Run("a 403 that clears", func(t *testing.T) {
		f := newGrantFixture(t, false, grantRBAC(t))
		f.s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusForbidden, kube.Status{})
		f.s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusForbidden, kube.Status{})
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		if want := []time.Duration{5 * time.Second, 10 * time.Second}; !slices.Equal(f.clock.slept, want) {
			t.Errorf("waited %v; want %v", f.clock.slept, want)
		}
		if got := f.reader(t); !got.GrantedAt.Equal(grantStart.Add(15*time.Second)) || got.Scope != readerScopeMetered {
			t.Errorf("recorded %+v; want GrantedAt at the read that succeeded", got)
		}
		if got := strings.Count(f.errb.String(), "IAM changes typically take 2 minutes"); got != 1 {
			t.Errorf("the propagation line appears %d times; want once:\n%s", got, f.errb)
		}
	})

	t.Run("a 401 is retried too", func(t *testing.T) {
		f := newGrantFixture(t, false, grantRBAC(t))
		// Two per attempt: kube mints once more after the first.
		f.s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusUnauthorized, kube.Status{})
		f.s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusUnauthorized, kube.Status{})
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		if want := []time.Duration{5 * time.Second}; !slices.Equal(f.clock.slept, want) {
			t.Errorf("waited %v; want %v", f.clock.slept, want)
		}
		// The first retry says why it waits.
		if line := "checking again until 10:08:00\n"; strings.Count(f.errb.String(), line) != 1 {
			t.Errorf("stderr does not say %q once:\n%s", line, f.errb)
		}
		if got := f.reader(t); got.GrantedAt.IsZero() {
			t.Errorf("not recorded: %+v", got)
		}
	})

	t.Run("another failure is not retried", func(t *testing.T) {
		f := newGrantFixture(t, false, grantRBAC(t))
		f.s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusInternalServerError, kube.Status{})
		err := f.run(t)
		if err == nil || !strings.Contains(err.Error(), "nothing was recorded") {
			t.Fatalf("grant = %v; want the 500, unretried", err)
		}
		if len(f.clock.slept) != 0 {
			t.Errorf("waited %v after a 500", f.clock.slept)
		}
		if got := f.reader(t); !got.GrantedAt.IsZero() || got.Scope != "" {
			t.Errorf("recorded %+v after a failed read", got)
		}
	})
}

// ADR 0023 M2.3, mutation 52: each of the five reviews, asked as the reader
// with its own attributes, must answer no. A reader that may do any of the
// first four is not read-only; one that may list pods in kube-system, where
// no farcast RBAC binds it, reads beyond that RBAC. A first grant records
// nothing.
func TestReaderGrantRefusesAReaderThatCanWrite(t *testing.T) {
	for _, row := range []struct {
		attrs kube.ResourceAttributes
		want  string
	}{
		{kube.ResourceAttributes{Namespace: "farcast-system", Verb: "get", Resource: "secrets"},
			"the reader " + grantEmail + " may get secrets in farcast-system; it is not read-only, so nothing was recorded; check the role the Cloud Shell script granted (roles/container.clusterViewer only)"},
		{kube.ResourceAttributes{Namespace: "farcast-system", Verb: "create", Group: "apps", Resource: "deployments"},
			"the reader " + grantEmail + " may create deployments in farcast-system; it is not read-only, so nothing was recorded; check the role the Cloud Shell script granted (roles/container.clusterViewer only)"},
		{kube.ResourceAttributes{Namespace: "farcast-system", Verb: "patch", Group: "apps", Resource: "deployments", Subresource: "scale"},
			"the reader " + grantEmail + " may patch deployments/scale in farcast-system; it is not read-only, so nothing was recorded; check the role the Cloud Shell script granted (roles/container.clusterViewer only)"},
		{kube.ResourceAttributes{Verb: "list", Resource: "secrets"},
			"the reader " + grantEmail + " may list secrets in every namespace; it is not read-only, so nothing was recorded; check the role the Cloud Shell script granted (roles/container.clusterViewer only)"},
		{kube.ResourceAttributes{Namespace: "kube-system", Verb: "list", Resource: "pods"},
			"the reader " + grantEmail + " may list pods in kube-system; it reads beyond the RBAC farcast applied, so nothing was recorded; check the role the Cloud Shell script granted (roles/container.clusterViewer only)"},
	} {
		t.Run(row.attrs.Verb+" "+row.attrs.Resource+"/"+row.attrs.Subresource, func(t *testing.T) {
			f := newGrantFixture(t, false, grantRBAC(t), kubetest.WithAccess(func(id string, a kube.ResourceAttributes) bool {
				return id == "reader" && a == row.attrs
			}))
			err := f.run(t)
			if err == nil || err.Error() != row.want {
				t.Fatalf("grant = %v;\nwant %q", err, row.want)
			}
			if got := f.reader(t); !got.GrantedAt.IsZero() || got.Scope != "" {
				t.Errorf("a reader that can write was recorded: %+v", got)
			}
			for _, r := range f.s.Requests() {
				if r.As != "reader" {
					t.Errorf("%s %s as %q; the reviews are the reader's", r.Method, r.Path, r.As)
				}
			}
		})
	}
}

// ADR 0023 M2.3, mutation 52a: 'reader grant' run again on a granted reader
// that now fails a review withdraws the earlier verification, GrantedAt and
// Scope both, so a read through openCluster as the reader refuses and sends
// nothing, and no later command binds it.
func TestReaderGrantWithdrawsAVerificationThatNoLongerHolds(t *testing.T) {
	f := newGrantFixture(t, true, grantRBAC(t), kubetest.WithAccess(func(id string, a kube.ResourceAttributes) bool {
		return id == "reader" && a.Verb == "get" && a.Resource == "secrets"
	}))
	before := f.reader(t)
	if before.GrantedAt.IsZero() || before.Scope != readerScopeMetered {
		t.Fatalf("the fixture's reader is not granted: %+v", before)
	}
	err := f.run(t)
	want := "the reader " + grantEmail + " may get secrets in farcast-system; it is not read-only, so its earlier verification was withdrawn and reads refuse until a clean grant; check the role the Cloud Shell script granted (roles/container.clusterViewer only)"
	if err == nil || err.Error() != want {
		t.Fatalf("grant = %v;\nwant %q", err, want)
	}
	after := f.reader(t)
	if !after.GrantedAt.IsZero() || after.Scope != "" {
		t.Errorf("the verification was kept: %+v", after)
	}
	if after.Email != before.Email || after.KeyID != before.KeyID {
		t.Errorf("the withdrawal changed the reader itself: %+v, was %+v", after, before)
	}

	sent := len(f.s.Requests())
	meta, err := f.dir.LoadInstanceMetadata(grantName)
	if err != nil {
		t.Fatal(err)
	}
	c, err := openCluster(clusterRef{Dir: f.dir, Meta: meta, Identity: kube.Reader, Warn: &bytes.Buffer{}})
	if c != nil || !errors.Is(err, errCredentialMissing) || !strings.Contains(err.Error(), "has not been verified read-only") {
		t.Errorf("a read after the withdrawal: openCluster = %v, %v; want the unverified refusal", c, err)
	}
	if got := len(f.s.Requests()); got != sent {
		t.Errorf("a read after the withdrawal sent %d requests", got-sent)
	}
	if got, warning := meteredReaderNote(f.env, grantName, meta); got != "" || warning != "" {
		t.Errorf("a withdrawn reader is still bound by later commands, as %q (warning %q)", got, warning)
	}
}

// unevaluatedReview makes the API server answer the review of one verb and
// resource allowed: false with an evaluationError, as an authorizer that
// could not finish answers. kube reads that as ErrUnreadable, never a no
// (A15-8).
func unevaluatedReview(verb, resource string) kubetest.Option {
	return kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.Method != http.MethodPost || r.Path != selfReviewPath {
			return 0, nil, false
		}
		var review struct {
			Spec struct {
				ResourceAttributes kube.ResourceAttributes `json:"resourceAttributes"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(r.Body, &review); err != nil {
			return 0, nil, false
		}
		if a := review.Spec.ResourceAttributes; a.Verb != verb || a.Resource != resource {
			return 0, nil, false
		}
		return http.StatusCreated, []byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview",` +
			`"status":{"allowed":false,"evaluationError":"the authorizer did not answer in time"}}`), true
	})
}

// ADR 0023 M2.3 (design §7.2 step 6, "any other failure records nothing"): a
// review that fails, rather than answering, proves nothing about the reader.
// A 500, or an answer the API server could not fully evaluate, refuses the
// grant. A first grant records nothing, and a re-run leaves the earlier
// verification exactly as it was: never refreshed as if every review had
// said no, and never withdrawn as if one had said yes.
func TestReaderGrantRecordsNothingWhenAReviewFails(t *testing.T) {
	for _, row := range []struct {
		name     string
		opts     []kubetest.Option
		fail     bool // a 500 on the first review
		want     []string
		sentinel error
	}{
		{name: "a 500", fail: true,
			want: []string{"ask, as the reader " + grantEmail + ", whether it may create deployments in farcast-system: ", "; nothing was recorded"}},
		{name: "an evaluationError", opts: []kubetest.Option{unevaluatedReview("list", "secrets")},
			want:     []string{"ask, as the reader " + grantEmail + ", whether it may list secrets in every namespace: ", "its answer proves nothing; nothing was recorded"},
			sentinel: kube.ErrUnreadable},
	} {
		for _, granted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, granted %v", row.name, granted), func(t *testing.T) {
				f := newGrantFixture(t, granted, append([]kubetest.Option{grantRBAC(t)}, row.opts...)...)
				if row.fail {
					f.s.Fail(http.MethodPost, selfReviewPath, http.StatusInternalServerError, kube.Status{})
				}
				before := *f.reader(t)
				err := f.run(t)
				if err == nil {
					t.Fatal("grant = nil; want the failed review, nothing recorded")
				}
				for _, w := range row.want {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("grant = %v;\nwant it to say %q", err, w)
					}
				}
				if row.sentinel != nil && !errors.Is(err, row.sentinel) {
					t.Errorf("%v does not match %v", err, row.sentinel)
				}
				after := f.reader(t)
				if !after.GrantedAt.Equal(before.GrantedAt) || after.Scope != before.Scope {
					t.Errorf("a grant whose review failed changed the record: %+v, was %+v", *after, before)
				}
				if f.out.Len() != 0 {
					t.Errorf("a failed grant printed a result:\n%s", f.out)
				}
			})
		}
	}
}

// ADR 0023 M2.3, mutation 53: --yes never grants. It is a usage error that
// says to confirm in a terminal, or to review the plan and confirm its
// digest (A23-41), before anything is read, asked, applied or sent, even
// with a terminal that would answer yes. A name that is not an instance's
// is not repeated: the text names <instance>.
func TestReaderGrantRefusesYes(t *testing.T) {
	const want = "reader grant cannot be run with --yes: it gives a Google identity read access to the cluster; confirm it in a terminal, " +
		"or review 'farcast reader grant atlas --plan' and pass --confirm <digest>"
	dir := readerRecordFor(t, grantName, "proj-test1")
	before := instanceFiles(t, dir, grantName)
	for _, flag := range []string{"--yes", "-y"} {
		_, stderr, code := farcastIn(t, dir, "reader", "grant", grantName, flag)
		if code != 2 || !strings.Contains(stderr, want) {
			t.Errorf("reader grant %s: exit %d, %q; want exit 2 and %q", flag, code, stderr, want)
		}
		const named = "confirm it in a terminal, or review 'farcast reader grant <instance> --plan' and pass --confirm <digest>"
		if _, stderr, code := farcastIn(t, dir, "reader", "grant", "Not;an instance", flag); code != 2 || !strings.Contains(stderr, named) {
			t.Errorf("reader grant 'Not;an instance' %s: exit %d, %q; want exit 2 and %q", flag, code, stderr, named)
		}
	}
	sameFiles(t, "reader grant --yes", before, instanceFiles(t, dir, grantName))

	f := newGrantFixture(t, false, grantRBAC(t))
	f.cmd.yes = true
	err := f.run(t)
	var ue *usageError
	if !errors.As(err, &ue) || err.Error() != want {
		t.Fatalf("grant with yes = %v; want the usage error %q", err, want)
	}
	if len(f.applier.applied) != 0 || len(f.s.Requests()) != 0 {
		t.Errorf("grant with yes applied %d streams and sent %d requests", len(f.applier.applied), len(f.s.Requests()))
	}
	if got := f.reader(t); !got.GrantedAt.IsZero() || got.Scope != "" {
		t.Errorf("grant with yes recorded %+v", got)
	}
}

// Without a terminal, and with no flag, 'reader grant' is a usage error that
// names the route without one, --plan and then --confirm (A23-41): nothing
// is applied or sent.
func TestReaderGrantNeedsATerminal(t *testing.T) {
	const want = "reader grant needs a terminal to confirm, or --plan and then --confirm <digest>"
	dir := readerRecordFor(t, grantName, "proj-test1")
	if _, err := dir.UpdateInstanceMetadata(grantName, func(m *config.InstanceMetadata) error {
		m.Reader = &config.Reader{Email: readerEmail(grantName, "proj-test1"), KeyID: readerTestKeyID}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := instanceFiles(t, dir, grantName)
	if _, stderr, code := farcastIn(t, dir, "reader", "grant", grantName); code != 2 || !strings.Contains(stderr, want) {
		t.Errorf("reader grant without a terminal: exit %d, %q; want exit 2 and %q", code, stderr, want)
	}
	sameFiles(t, "reader grant without a terminal", before, instanceFiles(t, dir, grantName))

	f := newGrantFixture(t, false, grantRBAC(t))
	f.cmd.interactive = func(*Env) bool { return false }
	err := f.run(t)
	var ue *usageError
	if !errors.As(err, &ue) || err.Error() != want {
		t.Fatalf("grant = %v; want the usage error %q", err, want)
	}
	if len(f.applier.applied) != 0 || len(f.s.Requests()) != 0 || f.errb.Len() != 0 {
		t.Errorf("a refused grant applied %d streams, sent %d requests and printed %q", len(f.applier.applied), len(f.s.Requests()), f.errb)
	}
}

// The consent prompt is design §7.2 step 4's, word for word, naming the
// account, the instance, today's metered namespaces and every ConfigMap; a
// "no" applies, sends and records nothing.
func TestReaderGrantAsksBeforeItApplies(t *testing.T) {
	f := newGrantFixture(t, false, grantRBAC(t))
	f.env.In = strings.NewReader("n\n")
	if err := f.run(t); err != nil {
		t.Fatal(err)
	}
	want := "Grant " + grantEmail + ", which the Cloud Shell script gave roles/container.clusterViewer, read access in \"atlas\"'s cluster: " +
		"namespaces (list); in farcast-system and every namespace the kernel meters, now and later (today farcast-system, web): " +
		"deployments, statefulsets, jobs, pods and their logs, and the ConfigMaps technocore-namespaces, technocore-ledger, " +
		"technocore-profiles, fatline-egress-policy, datasphered-pin? [y/N]: Aborted.\n"
	if got := f.errb.String(); got != want {
		t.Errorf("stderr:\n got %q\nwant %q", got, want)
	}
	if len(f.applier.applied) != 0 || len(f.s.Requests()) != 0 || f.out.Len() != 0 {
		t.Errorf("a refused prompt applied %d streams, sent %d requests and printed %q", len(f.applier.applied), len(f.s.Requests()), f.out)
	}
	if got := f.reader(t); !got.GrantedAt.IsZero() {
		t.Errorf("a refused prompt recorded %+v", got)
	}
}

// 'reader grant' needs no kernel: with none recorded it binds the reader in
// farcast-system alone, and its prompt, its result and its JSON name the
// namespaces it binds, never meta.Kernel.Namespaces' (here, none).
func TestReaderGrantWithNoKernelNamesFarcastSystem(t *testing.T) {
	for _, mode := range []output.Mode{output.ModeHuman, output.ModeJSON} {
		t.Run(fmt.Sprintf("mode %d", mode), func(t *testing.T) {
			f := newGrantFixture(t, false, grantRBAC(t))
			if _, err := f.dir.UpdateInstanceMetadata(grantName, func(m *config.InstanceMetadata) error {
				m.Kernel = nil
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			f.env, f.out, f.errb = testEnvBoth(f.dir, mode)
			f.env.In = strings.NewReader("y\n")
			if err := f.run(t); err != nil {
				t.Fatal(err)
			}
			if want := "now and later (today farcast-system): "; !strings.Contains(f.errb.String(), want) {
				t.Errorf("the prompt does not name farcast-system as bound today (%q):\n%s", want, f.errb)
			}
			want, err := renderReaderRBAC(grantEmail, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.applier.applied) != 1 || !bytes.Equal(f.applier.applied[0], want) {
				t.Fatalf("applied %d streams; want the RBAC for farcast-system alone", len(f.applier.applied))
			}
			if got := readerBindingsIn(t, []string{string(f.applier.applied[0])}); !slices.Equal(got, []string{"farcast-system"}) {
				t.Errorf("the stream binds the reader in %q; want farcast-system", got)
			}
			if mode == output.ModeHuman {
				if line := "the reader " + grantEmail + " may now read farcast-system\n"; !strings.Contains(f.out.String(), line) {
					t.Errorf("the result does not say %q:\n%s", line, f.out)
				}
				return
			}
			var doc struct {
				Namespaces []string `json:"namespaces"`
			}
			if err := json.Unmarshal(f.out.Bytes(), &doc); err != nil {
				t.Fatalf("%v:\n%s", err, f.out)
			}
			if !slices.Equal(doc.Namespaces, []string{"farcast-system"}) {
				t.Errorf("the JSON names %q; want [farcast-system]:\n%s", doc.Namespaces, f.out)
			}
		})
	}
}

// 'reader grant' opens the reader it verifies as before it asks or applies
// anything: openCluster refuses only on local state and sends nothing, so a
// reader that could never verify the grant (reader.key gone, or an endpoint
// the rule refuses) is refused with openCluster's own words before a Google
// identity is given RBAC. Nothing is asked, applied, sent or changed.
func TestReaderGrantOpensTheReaderBeforeItAsks(t *testing.T) {
	for _, row := range []struct {
		name     string
		edit     func(t *testing.T, dir config.Dir, m *config.InstanceMetadata)
		sentinel error
	}{
		{"reader.key is missing", func(t *testing.T, dir config.Dir, _ *config.InstanceMetadata) {
			if err := os.Remove(filepath.Join(dir.InstancePath(grantName), "reader.key")); err != nil {
				t.Fatal(err)
			}
		}, errCredentialMissing},
		// The derived Google email, so that the email check, which holds
		// an endpoint it cannot classify to the Google rule, passes.
		{"an endpoint the rule refuses", func(_ *testing.T, _ config.Dir, m *config.InstanceMetadata) {
			m.Endpoint = "https://evil.example.com"
			m.Reader.Email = readerEmail(grantName, "proj-test1")
		}, kube.ErrEndpointRefused},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newGrantFixture(t, false, grantRBAC(t))
			if _, err := f.dir.UpdateInstanceMetadata(grantName, func(m *config.InstanceMetadata) error {
				row.edit(t, f.dir, m)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			meta, err := f.dir.LoadInstanceMetadata(grantName)
			if err != nil {
				t.Fatal(err)
			}
			_, want := openCluster(clusterRef{Dir: f.dir, Meta: meta, Identity: kube.Reader, Warn: &bytes.Buffer{}, Verifying: true})
			if want == nil || !errors.Is(want, row.sentinel) {
				t.Fatalf("the fixture's reader opens (%v); want a refusal matching %v", want, row.sentinel)
			}
			before := instanceFiles(t, f.dir, grantName)
			err = f.run(t)
			if err == nil || err.Error() != want.Error() || !errors.Is(err, row.sentinel) {
				t.Fatalf("grant = %v;\nwant openCluster's %q", err, want)
			}
			if len(f.applier.applied) != 0 || len(f.s.Requests()) != 0 || f.errb.Len() != 0 {
				t.Errorf("a grant whose reader cannot open applied %d streams, sent %d requests and asked %q",
					len(f.applier.applied), len(f.s.Requests()), f.errb)
			}
			sameFiles(t, "a grant whose reader cannot open", before, instanceFiles(t, f.dir, grantName))
		})
	}
}

// The apply runs through newApplier, opened as the instance's writer, with
// exactly the stream renderReaderRBAC renders for the reader, farcast-system
// and every metered namespace, before the reader reads anything. A failed
// apply records nothing and sends nothing as the reader.
func TestReaderGrantAppliesTheRenderedRBAC(t *testing.T) {
	f := newGrantFixture(t, false, grantRBAC(t))
	if err := f.run(t); err != nil {
		t.Fatal(err)
	}
	want, err := renderReaderRBAC(grantEmail, grantMetered)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.applier.applied) != 1 || !bytes.Equal(f.applier.applied[0], want) {
		t.Errorf("applied %d streams; want exactly the rendered RBAC:\n%s", len(f.applier.applied), bytes.Join(f.applier.applied, []byte("\n=====\n")))
	}
	if len(f.applierRefs) != 1 || f.applierRefs[0].Identity != kube.Writer || f.applierRefs[0].Meta == nil ||
		f.applierRefs[0].Meta.Name != grantName || f.applierRefs[0].Dir != f.dir {
		t.Errorf("newApplier was given %+v; want one writer of instance %q in %s", f.applierRefs, grantName, f.dir)
	}

	failed := newGrantFixture(t, false, grantRBAC(t))
	failed.applier.applyErr = errors.New("kubectl said no")
	err = failed.run(t)
	if err == nil || !strings.Contains(err.Error(), "kubectl said no") || !strings.Contains(err.Error(), "nothing was recorded") {
		t.Fatalf("grant after a failed apply = %v", err)
	}
	if got := len(failed.s.Requests()); got != 0 {
		t.Errorf("a failed apply was followed by %d requests as the reader", got)
	}
	if got := failed.reader(t); !got.GrantedAt.IsZero() || got.Scope != "" {
		t.Errorf("a failed apply recorded %+v", got)
	}
}

// 'reader grant' refuses, before anything is rendered, asked, applied or
// sent, a record with no reader, one whose key is not uploaded, one whose
// email is not the derived one, and one farcast cannot render from.
func TestReaderGrantRefusesWithoutAGrantableReader(t *testing.T) {
	for _, row := range []struct {
		name     string
		edit     func(m *config.InstanceMetadata)
		sentinel error
		want     string
	}{
		{"no reader", func(m *config.InstanceMetadata) { m.Reader = nil }, errCredentialMissing,
			`instance "atlas" has no reader identity; run 'farcast reader init atlas'`},
		{"no key id", func(m *config.InstanceMetadata) { m.Reader.KeyID = "" }, errCredentialMissing,
			`instance "atlas"'s reader key is not yet uploaded; run the printed Cloud Shell script, then 'farcast reader record atlas --key-id <id>'`},
		{"not the derived reader", func(m *config.InstanceMetadata) { m.Reader.Email = "writer@kubetest.invalid" }, errCredentialMissing,
			`instance "atlas" records the reader "writer@kubetest.invalid", which is not the reader farcast derives for it (` + readerName(grantName) + `@<a name under .invalid>); no RBAC was rendered for it`},
		{"an unsafe project", func(m *config.InstanceMetadata) { m.Project = "proj'$(id)" }, nil,
			fmt.Sprintf(msgUnsafeRecord, grantName, "project ID", "proj'$(id)")},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newGrantFixture(t, false, grantRBAC(t))
			if _, err := f.dir.UpdateInstanceMetadata(grantName, func(m *config.InstanceMetadata) error {
				row.edit(m)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before := instanceFiles(t, f.dir, grantName)
			err := f.run(t)
			if err == nil || err.Error() != row.want {
				t.Fatalf("grant = %v;\nwant %q", err, row.want)
			}
			if row.sentinel != nil && !errors.Is(err, row.sentinel) {
				t.Errorf("%v does not match %v", err, row.sentinel)
			}
			if len(f.applier.applied) != 0 || len(f.s.Requests()) != 0 || f.errb.Len() != 0 {
				t.Errorf("a refused grant applied %d streams, sent %d requests and asked %q", len(f.applier.applied), len(f.s.Requests()), f.errb)
			}
			sameFiles(t, "a refused grant", before, instanceFiles(t, f.dir, grantName))
		})
	}
}

// grantOpens wraps f's reader and applier seams to count their opens.
func (f *grantFixture) grantOpens() (readers, appliers func() int) {
	opened := 0
	reader := f.cmd.newReader
	if reader == nil {
		reader = openReaderVerifier
	}
	f.cmd.newReader = func(r clusterRef) (readerVerifier, error) {
		opened++
		return reader(r)
	}
	return func() int { return opened }, func() int { return len(f.applierRefs) }
}

// ADR 0023 M2.6 (A23-41): reader grant's plan reads the record alone. It
// never asks whether stdin is a terminal, opens neither the reader nor the
// writer, sends nothing and writes nothing; it binds the reader, its role and
// its grant, then a write for each document of the RBAC it would apply, in
// order, each with the hash of exactly the bytes apply would send.
func TestReaderGrantPlanReadsNoClusterAndNeedsNoTerminal(t *testing.T) {
	for _, mode := range []output.Mode{output.ModeJSON, output.ModeHuman} {
		t.Run(fmt.Sprintf("mode %d", mode), func(t *testing.T) {
			f := newGrantFixture(t, false, grantRBAC(t))
			asked := 0
			f.cmd.interactive = func(*Env) bool { asked++; return false }
			readers, appliers := f.grantOpens()
			withFlags(t, f.cmd, "--plan")
			f.env, f.out, f.errb = testEnvBoth(f.dir, mode)
			before := treeFiles(t, string(f.dir))
			if err := f.run(t); err != nil {
				t.Fatalf("reader grant --plan: %v", err)
			}
			if asked != 0 || readers() != 0 || appliers() != 0 || len(f.s.Requests()) != 0 || f.errb.Len() != 0 {
				t.Errorf("the plan asked the terminal %d times, opened %d readers and %d writers, sent %d requests, and printed %q",
					asked, readers(), appliers(), len(f.s.Requests()), f.errb)
			}
			sameFiles(t, "reader grant --plan", before, treeFiles(t, string(f.dir)))

			meta, err := f.dir.LoadInstanceMetadata(grantName)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := renderReaderRBAC(grantEmail, grantMetered)
			if err != nil {
				t.Fatal(err)
			}
			want := newBound("reader grant", meta, "none", "")
			want.Facts = append([]plan.Fact{plan.ReaderFact{
				Type: plan.TypeReader, Email: grantEmail, IAMRole: "roles/container.clusterViewer", Scope: "metered",
				Namespaces: grantMetered, Resources: []string{"deployments", "statefulsets", "pods", "pods/log", "jobs"},
				ConfigMaps: []string{"technocore-namespaces", "technocore-ledger", "technocore-profiles", "fatline-egress-policy", "datasphered-pin"},
			}}, wantWrites(t, stream)...)
			if mode == output.ModeHuman {
				for _, line := range []string{
					"farcast reader grant atlas, stage -, reading the cluster as none\n",
					"reader: " + grantEmail + " (roles/container.clusterViewer), scope metered: deployments, statefulsets, pods, pods/log, jobs in farcast-system, web;",
					"write: apply RoleBinding web/farcast-reader (rbac.authorization.k8s.io/v1), force: no, sha256 ",
					"\ndigest: " + plan.DigestOf([]byte(mustCanonical(t, want))) + "\n",
				} {
					if !strings.Contains(f.out.String(), line) {
						t.Errorf("the rendering does not say %q:\n%s", line, f.out)
					}
				}
				return
			}
			doc := printedDocument(t, f.out.Bytes())
			if got := string(doc.Bound); got != mustCanonical(t, want) {
				t.Errorf("the plan binds\n%s\nwant\n%s", got, mustCanonical(t, want))
			}
			if got := writeTargets(decodedBound(t, doc)); !slices.Equal(got, []string{
				"ClusterRole /farcast-reader-namespaces", "ClusterRoleBinding /farcast-reader-namespaces", "ClusterRole /farcast-reader",
				"RoleBinding farcast-system/farcast-reader", "RoleBinding web/farcast-reader",
			}) {
				t.Errorf("the plan writes %q", got)
			}
		})
	}
}

// ADR 0023 M2.6 (A23-41; M-M26A-MUT-05): the reader fact names the
// namespaces the RBAC binds the reader in, farcast-system first, exactly as
// its RoleBinding writes do, whatever the record meters and in whatever
// order: never the record's list as it stands.
func TestReaderGrantPlanNamesTheNamespacesItBinds(t *testing.T) {
	for _, row := range []struct {
		name          string
		metered, want []string
	}{
		{"farcast-system not recorded", []string{"web"}, []string{"farcast-system", "web"}},
		{"farcast-system recorded last", []string{"demo", "farcast-system"}, []string{"farcast-system", "demo"}},
		{"nothing metered", nil, []string{"farcast-system"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newGrantFixture(t, false, grantRBAC(t))
			if _, err := f.dir.UpdateInstanceMetadata(grantName, func(m *config.InstanceMetadata) error {
				m.Kernel.Namespaces = row.metered
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			withFlags(t, f.cmd, "--plan")
			f.env, f.out, f.errb = testEnvBoth(f.dir, output.ModeJSON)
			if err := f.run(t); err != nil {
				t.Fatal(err)
			}
			b := decodedBound(t, printedDocument(t, f.out.Bytes()))
			if r, ok := b.Facts[0].(plan.ReaderFact); !ok || !slices.Equal(r.Namespaces, row.want) {
				t.Errorf("the reader fact is %+v; want the namespaces %q", b.Facts[0], row.want)
			}
			var bound []string
			for _, fact := range b.Facts {
				if w, ok := fact.(plan.WriteFact); ok && w.Kind == "RoleBinding" && w.Name == readerRole {
					bound = append(bound, w.Namespace)
				}
			}
			if !slices.Equal(bound, row.want) {
				t.Errorf("the plan binds the reader in %q; want %q", bound, row.want)
			}
		})
	}
}

// ADR 0023 M2.6 (A23-18, A23-41): a reader that is not recorded, not
// uploaded, or not the one farcast derives blocks the plan: --plan prints it,
// exit 0, with no fact and nothing read, sent or written; --confirm of it
// refuses with the block's kind and words, before anything opens. A record
// farcast cannot render from is refused before any plan, as it is today.
func TestReaderGrantPlanBlocks(t *testing.T) {
	for _, row := range []struct {
		name string
		edit func(m *config.InstanceMetadata)
		want string
	}{
		{"no reader", func(m *config.InstanceMetadata) { m.Reader = nil },
			`instance "atlas" has no reader identity; run 'farcast reader init atlas'`},
		{"no key id", func(m *config.InstanceMetadata) { m.Reader.KeyID = "" },
			`instance "atlas"'s reader key is not yet uploaded; run the printed Cloud Shell script, then 'farcast reader record atlas --key-id <id>'`},
		{"not the derived reader", func(m *config.InstanceMetadata) { m.Reader.Email = "writer@kubetest.invalid" },
			`instance "atlas" records the reader "writer@kubetest.invalid", which is not the reader farcast derives for it (` + readerName(grantName) + `@<a name under .invalid>); no RBAC was rendered for it`},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newGrantFixture(t, false, grantRBAC(t))
			if _, err := f.dir.UpdateInstanceMetadata(grantName, func(m *config.InstanceMetadata) error {
				row.edit(m)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			readers, appliers := f.grantOpens()
			before := treeFiles(t, string(f.dir))

			withFlags(t, f.cmd, "--plan")
			f.env, f.out, f.errb = testEnvBoth(f.dir, output.ModeJSON)
			if err := f.run(t); err != nil {
				t.Fatalf("--plan of a blocked plan = %v; want it printed, exit 0", err)
			}
			doc := printedDocument(t, f.out.Bytes())
			b := decodedBound(t, doc)
			if len(b.Facts) != 0 || !slices.Equal(b.Blocked, []plan.Block{{Kind: kindCredentialMissing, Message: row.want}}) {
				t.Errorf("the plan has facts %v and blocks %+v; want no fact and the one block", b.Facts, b.Blocked)
			}
			if b.Command != "reader grant" || b.Instance != grantName || b.ClusterIdentity != "none" || len(b.Options) != 0 {
				t.Errorf("the blocked plan binds %+v", b)
			}

			withFlags(t, f.cmd, "--confirm", doc.Digest)
			err := f.run(t)
			if kindOf(classified(err)) != kindCredentialMissing || err.Error() != row.want || exitCodeOf(err) != 1 {
				t.Errorf("--confirm of the blocked plan = %v (kind %s, exit %d); want its block", err, kindOf(classified(err)), exitCodeOf(err))
			}
			if readers() != 0 || appliers() != 0 || len(f.s.Requests()) != 0 {
				t.Errorf("a blocked plan opened %d readers and %d writers and sent %d requests", readers(), appliers(), len(f.s.Requests()))
			}
			sameFiles(t, "a blocked reader grant", before, treeFiles(t, string(f.dir)))
		})
	}

	t.Run("an unsafe project", func(t *testing.T) {
		f := newGrantFixture(t, false, grantRBAC(t))
		if _, err := f.dir.UpdateInstanceMetadata(grantName, func(m *config.InstanceMetadata) error {
			m.Project = "proj'$(id)"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		withFlags(t, f.cmd, "--plan")
		err := f.run(t)
		if want := fmt.Sprintf(msgUnsafeRecord, grantName, "project ID", "proj'$(id)"); err == nil || err.Error() != want || f.out.Len() != 0 {
			t.Errorf("--plan of an unsafe record = %v, printing %q; want %q and no plan", err, f.out, want)
		}
	})
}

// ADR 0023 M2.6 (A23-41): under --confirm, reader grant recomputes its plan
// and compares it before it opens anything. A plan that changed opens
// neither the reader nor the writer, applies nothing and sends nothing. The
// plan confirmed opens the reader and the writer, asks nothing, applies the
// planned RBAC, then reads and reviews as the reader, and records the grant;
// a review that answers yes records nothing.
func TestReaderGrantConfirmVerifiesAsTheReaderAfterTheCompare(t *testing.T) {
	planned := func(t *testing.T, f *grantFixture) string {
		t.Helper()
		withFlags(t, f.cmd, "--plan")
		f.env, f.out, f.errb = testEnvBoth(f.dir, output.ModeJSON)
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		return printedDocument(t, f.out.Bytes()).Digest
	}

	t.Run("a changed plan", func(t *testing.T) {
		f := newGrantFixture(t, false, grantRBAC(t))
		digest := planned(t, f)
		if _, err := f.dir.UpdateInstanceMetadata(grantName, func(m *config.InstanceMetadata) error {
			m.Kernel.Namespaces = append(m.Kernel.Namespaces, "api")
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		readers, appliers := f.grantOpens()
		withFlags(t, f.cmd, "--confirm", digest)
		f.env, f.out, f.errb = testEnvBoth(f.dir, output.ModeHuman)
		err := f.run(t)
		if kindOf(classified(err)) != kindPlanChanged || !strings.Contains(err.Error(), "not the "+digest+" given to --confirm") {
			t.Fatalf("--confirm of a changed plan = %v; want plan_changed", err)
		}
		if readers() != 0 || appliers() != 0 || len(f.applier.applied) != 0 || len(f.s.Requests()) != 0 || f.errb.Len() != 0 {
			t.Errorf("a changed plan opened %d readers and %d writers, applied %d streams, sent %d requests and printed %q",
				readers(), appliers(), len(f.applier.applied), len(f.s.Requests()), f.errb)
		}
		if got := f.reader(t); !got.GrantedAt.IsZero() {
			t.Errorf("a changed plan recorded %+v", got)
		}
	})

	t.Run("the plan confirmed", func(t *testing.T) {
		f := newGrantFixture(t, false, grantRBAC(t))
		digest := planned(t, f)
		readers, appliers := f.grantOpens()
		// No terminal, and stdin that would answer no: --confirm asks nothing.
		f.cmd.interactive = func(*Env) bool { return false }
		withFlags(t, f.cmd, "--confirm", digest)
		f.env, f.out, f.errb = testEnvBoth(f.dir, output.ModeHuman)
		f.env.In = strings.NewReader("n\n")
		if err := f.run(t); err != nil {
			t.Fatalf("--confirm of the plan: %v", err)
		}
		if strings.Contains(f.errb.String(), "[y/N]") {
			t.Errorf("--confirm asked:\n%s", f.errb)
		}
		want, err := renderReaderRBAC(grantEmail, grantMetered)
		if err != nil {
			t.Fatal(err)
		}
		if readers() != 1 || appliers() != 1 || len(f.applier.applied) != 1 || !bytes.Equal(f.applier.applied[0], want) {
			t.Fatalf("opened %d readers and %d writers and applied %d streams; want one each, the planned RBAC", readers(), appliers(), len(f.applier.applied))
		}
		reqs, lines := apiRequests(f.s)
		if countMethod(reqs, http.MethodGet) != 1 || countMethod(reqs, http.MethodPost) != len(readerReviews) {
			t.Errorf("the verification sent %q; want one read and the %d reviews", lines, len(readerReviews))
		}
		for _, r := range f.s.Requests() {
			if r.As != "reader" {
				t.Errorf("%s %s as %q; the verification is the reader's", r.Method, r.Path, r.As)
			}
		}
		if got := f.reader(t); !got.GrantedAt.Equal(grantStart) || got.Scope != readerScopeMetered {
			t.Errorf("recorded %+v; want the grant", got)
		}
	})

	t.Run("a review that answers yes", func(t *testing.T) {
		f := newGrantFixture(t, false, grantRBAC(t), kubetest.WithAccess(func(id string, a kube.ResourceAttributes) bool {
			return id == "reader" && a.Verb == "get" && a.Resource == "secrets"
		}))
		digest := planned(t, f)
		withFlags(t, f.cmd, "--confirm", digest)
		err := f.run(t)
		if err == nil || !strings.Contains(err.Error(), "may get secrets in farcast-system; it is not read-only, so nothing was recorded") {
			t.Fatalf("--confirm with a reader that can read Secrets = %v", err)
		}
		if got := f.reader(t); !got.GrantedAt.IsZero() || got.Scope != "" {
			t.Errorf("a reader that can read Secrets was recorded: %+v", got)
		}
	})
}
