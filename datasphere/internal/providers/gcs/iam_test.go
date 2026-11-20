package gcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/sofmon/farcast/datasphere"
)

// A bucket's IAM on the wire (ADR 0023 M2.8, design §33, A33-13). The adapter
// writes back the whole policy, so what it does not mean to change must go
// back exactly as it came: a binding lost, a condition dropped or a member
// added to a conditional grant is somebody else's access changed with no
// error and no symptom.

const (
	objectAdmin  = "roles/storage.objectAdmin"
	bucketReader = "roles/storage.legacyBucketReader"

	// uidPrincipal and sharedPrincipal are design §33's fixture principals
	// for the keyholder: by its ServiceAccount's uid, and the one every
	// instance in the project shares.
	uidPrincipal    = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/kubernetes.serviceaccount.uid/00000000-0000-4000-8000-0000000000d5"
	sharedPrincipal = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/subject/ns/farcast-system/sa/datasphered"

	// ownerBinding is the binding GCS gives every bucket.
	ownerBinding = `{"role":"roles/storage.legacyBucketOwner","members":["projectEditor:farcast-test-proj","projectOwner:farcast-test-proj"]}`
	// oddBinding is spaced, ordered and extended as no encoder of this
	// package would write it, with text encoding/json would escape.
	oddBinding = `{ "members" : ["user:b@example.com",  "user:a@example.com"], "role":"roles/storage.objectViewer", "x-future": {"note": "<a & b>"} }`
)

var grantRoles = []string{objectAdmin, bucketReader}

// conditioned is a binding of role, for members, under a condition.
func conditioned(role string, members ...string) string {
	m, _ := json.Marshal(members)
	return `{"role":"` + role + `","members":` + string(m) +
		`,"condition":{"title":"until 2030","expression":"request.time < timestamp(\"2030-01-01T00:00:00Z\")"}}`
}

// plain is a binding of role, for members, with no condition.
func plain(role string, members ...string) string {
	m, _ := json.Marshal(members)
	return `{"role":"` + role + `","members":` + string(m) + `}`
}

// policyReply is getIamPolicy's answer: the policy with its etag, the
// bindings as given.
func policyReply(etag string, bindings ...string) *http.Response {
	return jsonReply(http.StatusOK, `{"kind":"storage#policy","resourceId":"projects/_/buckets/`+testBucket+`","version":1,"etag":"`+etag+
		`","bindings":[`+strings.Join(bindings, ",")+`]}`)
}

// setReply is setIamPolicy's answer.
func setReply() *http.Response {
	return jsonReply(http.StatusOK, `{"kind":"storage#policy","etag":"after"}`)
}

// putPolicyBody is a PUT's body as the wire carries it, its bindings raw.
type putPolicyBody struct {
	Bindings []json.RawMessage `json:"bindings"`
	Etag     string            `json:"etag"`
	Version  int               `json:"version"`
}

func decodePut(t *testing.T, r capturedRequest) putPolicyBody {
	t.Helper()
	if r.method != http.MethodPut || !strings.HasSuffix(strings.Split(r.url, "?")[0], "/storage/v1/b/"+testBucket+"/iam") {
		t.Fatalf("request %s %s is not setIamPolicy on the bucket", r.method, r.url)
	}
	var b putPolicyBody
	if err := json.Unmarshal(r.body, &b); err != nil {
		t.Fatalf("the PUT body does not decode: %v\n%s", err, r.body)
	}
	return b
}

// bindingRoles decodes the PUT's bindings' roles, members and condition
// presence, for assertions on what changed.
type decodedBinding struct {
	Role      string          `json:"role"`
	Members   []string        `json:"members"`
	Condition json.RawMessage `json:"condition"`
}

func decodeBindings(t *testing.T, raw []json.RawMessage) []decodedBinding {
	t.Helper()
	out := make([]decodedBinding, len(raw))
	for i, r := range raw {
		if err := json.Unmarshal(r, &out[i]); err != nil {
			t.Fatalf("binding %d does not decode: %v\n%s", i, err, r)
		}
	}
	return out
}

func ensureGrant(p *provider) (bool, error) {
	return p.EnsureGrant(context.Background(), testBucket, grantRoles, uidPrincipal, sharedPrincipal)
}

// methods is the requests' methods, in order.
func methods(f *fakeCloud) []string {
	var out []string
	for _, tr := range f.trace() {
		m, _, _ := strings.Cut(tr, " ")
		out = append(out, m)
	}
	return out
}

// TestBucketGrantUsesTheEtag: the write is conditional on the read it was
// built from, so a change made in between is refused rather than overwritten
// (mutation row 107).
func TestBucketGrantUsesTheEtag(t *testing.T) {
	p, fake := newTestProvider(t, policyReply("BwXyZ+/a=", ownerBinding), setReply())
	changed, err := ensureGrant(p)
	if err != nil || !changed {
		t.Fatalf("EnsureGrant = %v, %v; want a write that changed the policy", changed, err)
	}
	put := fake.request(t, 1)
	if got := jsonField(t, put.body, "etag"); got != "BwXyZ+/a=" {
		t.Errorf("the PUT's etag is %v, want the read's", got)
	}
	if got := put.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("the PUT's Content-Type is %q", got)
	}
	if !bytes.HasPrefix(put.body, []byte(`{"bindings":[`)) || !bytes.HasSuffix(put.body, []byte(`],"etag":"BwXyZ+/a=","version":3}`)) {
		t.Errorf("the PUT body is not {bindings, etag, version}:\n%s", put.body)
	}

	t.Run("a read without an etag is never written", func(t *testing.T) {
		p, fake := newTestProvider(t, jsonReply(http.StatusOK, `{"version":1,"bindings":[`+ownerBinding+`]}`))
		changed, err := ensureGrant(p)
		if err == nil || changed || !strings.Contains(err.Error(), "without an etag") {
			t.Errorf("EnsureGrant = %v, %v; want a refusal naming the missing etag", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET"}) {
			t.Errorf("requests = %v, want the read alone", got)
		}
	})
}

// TestBucketGrantAsksForPolicyVersion3: every read asks for version 3 and
// every write sends it, since a lower version leaves conditional bindings out
// of the read, and a write of that read deletes them (mutation row 108).
func TestBucketGrantAsksForPolicyVersion3(t *testing.T) {
	check := func(t *testing.T, r capturedRequest) {
		t.Helper()
		if r.method != http.MethodGet {
			t.Fatalf("request %s %s, want the policy's GET", r.method, r.url)
		}
		if got := r.query(t); got.Get("optionsRequestedPolicyVersion") != "3" || len(got) != 1 {
			t.Errorf("the read's query is %v, want optionsRequestedPolicyVersion=3 alone", got)
		}
		if want := "GET /storage/v1/b/" + testBucket + "/iam"; traceOf([]capturedRequest{r})[0] != want {
			t.Errorf("the read is %s, want %s", traceOf([]capturedRequest{r})[0], want)
		}
	}

	t.Run("the state's read", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding))
		if _, _, _, err := p.GrantState(context.Background(), testBucket, grantRoles, uidPrincipal, sharedPrincipal); err != nil {
			t.Fatal(err)
		}
		check(t, fake.request(t, 0))
	})
	t.Run("the grant's read and write", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding), setReply())
		if _, err := ensureGrant(p); err != nil {
			t.Fatal(err)
		}
		check(t, fake.request(t, 0))
		if got := decodePut(t, fake.request(t, 1)).Version; got != 3 {
			t.Errorf("the PUT's version is %d, want 3", got)
		}
	})
}

// TestBucketGrantKeepsConditionalBindings: a binding with a condition is
// never where the member is added, and goes back byte for byte; the member
// goes into a new binding with no condition (mutation row 109).
func TestBucketGrantKeepsConditionalBindings(t *testing.T) {
	cond := conditioned(objectAdmin, "user:temp@example.com")
	p, fake := newTestProvider(t, policyReply("e1", ownerBinding, cond, plain(bucketReader, "user:ops@example.com")), setReply())
	if changed, err := ensureGrant(p); err != nil || !changed {
		t.Fatalf("EnsureGrant = %v, %v", changed, err)
	}
	put := decodePut(t, fake.request(t, 1))
	if len(put.Bindings) != 4 {
		t.Fatalf("the PUT has %d bindings, want the three read and one added:\n%s", len(put.Bindings), fake.request(t, 1).body)
	}
	if !bytes.Equal(put.Bindings[1], []byte(cond)) {
		t.Errorf("the conditioned binding changed:\n got %s\nwant %s", put.Bindings[1], cond)
	}
	got := decodeBindings(t, put.Bindings)
	if got[2].Role != bucketReader || !slices.Equal(got[2].Members, []string{"user:ops@example.com", uidPrincipal}) || got[2].Condition != nil {
		t.Errorf("the reader binding is %+v, want the member added to it", got[2])
	}
	if got[3].Role != objectAdmin || !slices.Equal(got[3].Members, []string{uidPrincipal}) || got[3].Condition != nil {
		t.Errorf("the added binding is %+v, want objectAdmin for the member alone, with no condition", got[3])
	}
}

// TestBucketGrantKeepsEveryOtherBindingByteForByte: a binding the grant does
// not change is written back exactly as it was read: its spacing, its key
// order, a field this adapter does not know and text an encoder would escape
// (mutation row 109b). The shared principal in a role the grant does not
// name is somebody else's grant, and goes back with it (design §33, A33-4
// (d), A33-13 step 4). A binding the grant does change keeps every field
// but its members.
func TestBucketGrantKeepsEveryOtherBindingByteForByte(t *testing.T) {
	held := plain(bucketReader, "user:ops@example.com", uidPrincipal)
	otherRole := plain("roles/storage.objectViewer", sharedPrincipal, "user:ops@example.com")
	p, fake := newTestProvider(t, policyReply("e1", oddBinding, ownerBinding, otherRole, held, conditioned(objectAdmin, sharedPrincipal)), setReply())
	if changed, err := ensureGrant(p); err != nil || !changed {
		t.Fatalf("EnsureGrant = %v, %v", changed, err)
	}
	put := decodePut(t, fake.request(t, 1))
	want := []string{oddBinding, ownerBinding, otherRole, held, conditioned(objectAdmin, sharedPrincipal)}
	if len(put.Bindings) != len(want)+1 {
		t.Fatalf("the PUT has %d bindings, want %d:\n%s", len(put.Bindings), len(want)+1, fake.request(t, 1).body)
	}
	for i, w := range want {
		if !bytes.Equal(put.Bindings[i], []byte(w)) {
			t.Errorf("binding %d changed:\n got %s\nwant %s", i, put.Bindings[i], w)
		}
	}
	if !bytes.Contains(fake.request(t, 1).body, []byte(oddBinding)) {
		t.Errorf("the PUT body does not carry the unknown binding as it was read:\n%s", fake.request(t, 1).body)
	}

	t.Run("a binding it changes", func(t *testing.T) {
		changing := `{"role":"` + objectAdmin + `","members":["user:ops@example.com"],"x-future":{"note":"<a & b>"}}`
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding, changing, plain(bucketReader, uidPrincipal)), setReply())
		if changed, err := ensureGrant(p); err != nil || !changed {
			t.Fatalf("EnsureGrant = %v, %v", changed, err)
		}
		put := decodePut(t, fake.request(t, 1))
		if len(put.Bindings) != 3 || !bytes.Contains(put.Bindings[1], []byte(`"x-future":{"note":"<a & b>"}`)) {
			t.Fatalf("the changed binding lost a field the grant does not change:\n%s", fake.request(t, 1).body)
		}
		if got := decodeBindings(t, put.Bindings)[1]; got.Role != objectAdmin || !slices.Equal(got.Members, []string{"user:ops@example.com", uidPrincipal}) {
			t.Errorf("the changed binding is %+v; want the member added to it", got)
		}
	})
}

// TestGrantStateObservations: design §33's two observations (A33-11) of one
// read. The member is present when every role's binding with no condition
// holds it exactly; the shared principal is present when any role's does,
// and its roles are named in the roles' order. A conditioned binding never
// counts. A 403 is unknown for both, with no error; anything else that is
// not a policy is an error (mutation row 109a).
func TestGrantStateObservations(t *testing.T) {
	for _, tc := range []struct {
		name          string
		bindings      []string
		state, shared datasphere.GrantState
		sharedRoles   []string
	}{
		{"an empty policy", nil, datasphere.GrantMissing, datasphere.GrantMissing, nil},
		{"the owner's binding alone", []string{ownerBinding}, datasphere.GrantMissing, datasphere.GrantMissing, nil},
		{"both roles hold the member",
			[]string{plain(objectAdmin, "user:x@example.com", uidPrincipal), plain(bucketReader, uidPrincipal)},
			datasphere.GrantPresent, datasphere.GrantMissing, nil},
		{"one role holds the member",
			[]string{plain(objectAdmin, uidPrincipal)}, datasphere.GrantMissing, datasphere.GrantMissing, nil},
		{"one role holds the member only under a condition",
			[]string{conditioned(objectAdmin, uidPrincipal), plain(bucketReader, uidPrincipal)},
			datasphere.GrantMissing, datasphere.GrantMissing, nil},
		{"both roles hold the member, one also under a condition",
			[]string{conditioned(objectAdmin, uidPrincipal), plain(objectAdmin, uidPrincipal), plain(bucketReader, uidPrincipal)},
			datasphere.GrantPresent, datasphere.GrantMissing, nil},
		{"another role holds the member",
			[]string{plain("roles/storage.objectViewer", uidPrincipal), plain(bucketReader, uidPrincipal)},
			datasphere.GrantMissing, datasphere.GrantMissing, nil},
		{"a member that only resembles it",
			[]string{plain(objectAdmin, uidPrincipal+"6"), plain(bucketReader, strings.ToUpper(uidPrincipal))},
			datasphere.GrantMissing, datasphere.GrantMissing, nil},
		{"the shared principal in the reader role",
			[]string{plain(bucketReader, sharedPrincipal)},
			datasphere.GrantMissing, datasphere.GrantPresent, []string{bucketReader}},
		{"the shared principal in both roles, in the roles' order",
			[]string{plain(bucketReader, sharedPrincipal), plain(objectAdmin, sharedPrincipal)},
			datasphere.GrantMissing, datasphere.GrantPresent, []string{objectAdmin, bucketReader}},
		{"the shared principal only under a condition",
			[]string{conditioned(objectAdmin, sharedPrincipal), conditioned(bucketReader, sharedPrincipal)},
			datasphere.GrantMissing, datasphere.GrantMissing, nil},
		{"both principals in both roles",
			[]string{plain(objectAdmin, sharedPrincipal, uidPrincipal), plain(bucketReader, uidPrincipal, sharedPrincipal)},
			datasphere.GrantPresent, datasphere.GrantPresent, []string{objectAdmin, bucketReader}},
		{"a condition key that is null still counts as one",
			[]string{`{"role":"` + objectAdmin + `","members":["` + uidPrincipal + `"],"condition":null}`, plain(bucketReader, uidPrincipal)},
			datasphere.GrantMissing, datasphere.GrantMissing, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, fake := newTestProvider(t, policyReply("e1", tc.bindings...))
			state, shared, roles, err := p.GrantState(context.Background(), testBucket, grantRoles, uidPrincipal, sharedPrincipal)
			if err != nil {
				t.Fatalf("GrantState: %v", err)
			}
			if state != tc.state || shared != tc.shared || !slices.Equal(roles, tc.sharedRoles) {
				t.Errorf("GrantState = %s, %s, %q; want %s, %s, %q", state, shared, roles, tc.state, tc.shared, tc.sharedRoles)
			}
			if got := methods(fake); !slices.Equal(got, []string{"GET"}) {
				t.Errorf("requests = %v, want one read", got)
			}
		})
	}

	t.Run("a policy the credential may not read", func(t *testing.T) {
		p, fake := newTestProvider(t, errorReply(http.StatusForbidden, "PERMISSION_DENIED", "no storage.buckets.getIamPolicy"))
		state, shared, roles, err := p.GrantState(context.Background(), testBucket, grantRoles, uidPrincipal, sharedPrincipal)
		if err != nil || state != datasphere.GrantUnknown || shared != datasphere.GrantUnknown || roles != nil {
			t.Errorf("a 403 gives %s, %s, %q, %v; want unknown, unknown, none and no error", state, shared, roles, err)
		}
		if n := fake.count(); n != 1 {
			t.Errorf("a 403 was asked %d times; it is the credential's answer, not the server's", n)
		}
	})
	t.Run("a bucket that is not there", func(t *testing.T) {
		p, _ := newTestProvider(t, errorReply(http.StatusNotFound, "NOT_FOUND", "no such bucket"))
		_, _, _, err := p.GrantState(context.Background(), testBucket, grantRoles, uidPrincipal, sharedPrincipal)
		if !errors.Is(err, datasphere.ErrBucketNotFound) || errors.Is(err, datasphere.ErrPermissionDenied) || !strings.Contains(err.Error(), testBucket) {
			t.Errorf("a 404 gives %v; want an error naming the bucket that wraps ErrBucketNotFound", err)
		}
	})
	t.Run("a server that keeps failing", func(t *testing.T) {
		p, fake := newTestProvider(t, repeatReply(maxAttempts, func() *http.Response {
			return errorReply(http.StatusInternalServerError, "INTERNAL", "backend error")
		})...)
		state, _, _, err := p.GrantState(context.Background(), testBucket, grantRoles, uidPrincipal, sharedPrincipal)
		if err == nil || state != "" || errors.Is(err, datasphere.ErrPermissionDenied) {
			t.Errorf("a 500 gives %s, %v; want an error and no state", state, err)
		}
		if n := fake.count(); n != maxAttempts {
			t.Errorf("made %d attempts, want send's %d", n, maxAttempts)
		}
	})
	t.Run("a binding that does not decode", func(t *testing.T) {
		p, _ := newTestProvider(t, policyReply("e1", `{"role":"`+objectAdmin+`","members":"`+uidPrincipal+`"}`))
		if _, _, _, err := p.GrantState(context.Background(), testBucket, grantRoles, uidPrincipal, sharedPrincipal); err == nil {
			t.Error("a binding whose members are not a list read as a policy")
		}
	})
	for name, args := range map[string]struct {
		bucket         string
		roles          []string
		member, shared string
	}{
		"no bucket":              {"", grantRoles, uidPrincipal, sharedPrincipal},
		"no role":                {testBucket, nil, uidPrincipal, sharedPrincipal},
		"an empty role":          {testBucket, []string{objectAdmin, ""}, uidPrincipal, sharedPrincipal},
		"a role twice":           {testBucket, []string{objectAdmin, objectAdmin}, uidPrincipal, sharedPrincipal},
		"no member":              {testBucket, grantRoles, "", sharedPrincipal},
		"no shared":              {testBucket, grantRoles, uidPrincipal, ""},
		"one principal for both": {testBucket, grantRoles, uidPrincipal, uidPrincipal},
	} {
		t.Run(name, func(t *testing.T) {
			p, fake := newTestProvider(t)
			if _, _, _, err := p.GrantState(context.Background(), args.bucket, args.roles, args.member, args.shared); err == nil {
				t.Error("GrantState read with a value missing")
			}
			if _, err := p.EnsureGrant(context.Background(), args.bucket, args.roles, args.member, args.shared); err == nil {
				t.Error("EnsureGrant ran with a value missing")
			}
			if n := fake.count(); n != 0 {
				t.Errorf("made %d requests with a value missing", n)
			}
		})
	}
}

// TestBucketGrantRetriesAStaleEtagOnce: a write refused because the policy
// changed since its read is read and built again once: at most two policy
// writes. A second refusal is read once more, with no third write, and is
// ErrPolicyChanged unless that read finds the grant done; that read needs
// no etag. send's own retries of a 5xx replay one write unchanged and are
// not a second write (mutation row 109d). A refusal other than a 409 or a
// 412 that follows an attempt of the same write that failed in transport,
// failed reading its body, or got a 5xx is ErrPolicyUnconfirmed; after a
// 429 it settles the write (mutation rows 169 to 172).
func TestBucketGrantRetriesAStaleEtagOnce(t *testing.T) {
	stale := func(code int) *http.Response {
		if code == http.StatusConflict {
			return errorReply(code, "CONFLICT", "the policy changed")
		}
		return errorReply(code, "FAILED_PRECONDITION", "etag mismatch")
	}
	for _, code := range []int{http.StatusConflict, http.StatusPreconditionFailed} {
		// A write refused as stale whose re-read finds the grant done is
		// reported as a change: the write may be its own, committed with
		// its answer lost and its replay refused as stale, which the wire
		// cannot tell from another writer's.
		t.Run(http.StatusText(code)+", then found granted", func(t *testing.T) {
			p, fake := newTestProvider(t, policyReply("e1", ownerBinding), stale(code),
				policyReply("e2", ownerBinding, plain(objectAdmin, uidPrincipal), plain(bucketReader, uidPrincipal)))
			changed, err := ensureGrant(p)
			if err != nil || !changed {
				t.Errorf("EnsureGrant = %v, %v; want done, reported as a change a write it sent may have made", changed, err)
			}
			if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "GET"}) {
				t.Errorf("requests = %v, want a read, the refused write and one read again", got)
			}
		})
		t.Run(http.StatusText(code)+", then still missing", func(t *testing.T) {
			p, fake := newTestProvider(t, policyReply("e1", ownerBinding), stale(code),
				policyReply("e2", ownerBinding, plain("roles/storage.objectViewer", "user:new@example.com")), setReply())
			changed, err := ensureGrant(p)
			if err != nil || !changed {
				t.Fatalf("EnsureGrant = %v, %v; want the second write to land", changed, err)
			}
			if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "GET", "PUT"}) {
				t.Fatalf("requests = %v, want read, write, read, write", got)
			}
			second := decodePut(t, fake.request(t, 3))
			if second.Etag != "e2" {
				t.Errorf("the second write carries the etag %q, want the fresh read's", second.Etag)
			}
			if len(second.Bindings) != 4 || !bytes.Equal(second.Bindings[1], []byte(plain("roles/storage.objectViewer", "user:new@example.com"))) {
				t.Errorf("the second write is not built from the fresh read:\n%s", fake.request(t, 3).body)
			}
		})
	}
	t.Run("stale twice", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding), stale(http.StatusConflict),
			policyReply("e2", ownerBinding), stale(http.StatusPreconditionFailed), policyReply("e3", ownerBinding))
		changed, err := ensureGrant(p)
		if !errors.Is(err, datasphere.ErrPolicyChanged) || changed || errors.Is(err, datasphere.ErrPolicyUnconfirmed) {
			t.Errorf("EnsureGrant = %v, %v; want ErrPolicyChanged alone", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "GET", "PUT", "GET"}) {
			t.Errorf("requests = %v, want exactly two writes and a read after each", got)
		}
	})
	// scripted is a provider that answers each request with the next of
	// replies, a nil response being a transport failure.
	scripted := func(t *testing.T, replies ...*http.Response) (*provider, *fakeCloud) {
		i := 0
		return newTestProviderFunc(t, func(r *http.Request) (*http.Response, error) {
			if i >= len(replies) {
				t.Errorf("unscripted request %d: %s %s", i+1, r.Method, r.URL)
				return jsonReply(http.StatusInternalServerError, `{}`), nil
			}
			i++
			if replies[i-1] == nil {
				return nil, errors.New("read tcp: connection reset by peer")
			}
			return replies[i-1], nil
		})
	}
	// sharedHeld is a first read whose policy grants the shared principal
	// both roles.
	sharedHeld := func() *http.Response {
		return policyReply("e1", ownerBinding, plain(objectAdmin, sharedPrincipal), plain(bucketReader, sharedPrincipal))
	}
	// The write lands, its answer is lost, and send's replay of the same
	// bytes, etag included, is refused as stale; the re-read finds the
	// grant done. The change is this write's, and is reported, so a refusal
	// after it never hides the shared principal's removal (design §33,
	// A33-26). Which code GCS answers a stale etag with is [unverified]
	// (design §33, A33-13).
	t.Run("a write whose answer was lost, its replay refused as stale", func(t *testing.T) {
		p, fake := scripted(t, sharedHeld(), nil, stale(http.StatusPreconditionFailed),
			policyReply("e2", ownerBinding, plain(objectAdmin, uidPrincipal), plain(bucketReader, uidPrincipal)))
		changed, err := ensureGrant(p)
		if err != nil || !changed {
			t.Errorf("EnsureGrant = %v, %v; want the change its own write made reported", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "PUT", "GET"}) {
			t.Errorf("requests = %v, want a read, one write sent twice and one read again", got)
		}
	})
	// The same on the second write: the first is refused as stale, the
	// second lands with its answer lost and its replay refused as stale,
	// and the read after it finds the grant done. That is a change too,
	// never ErrPolicyChanged, whose refusal would say nothing else was
	// written although the shared principal is gone.
	t.Run("the second write's answer lost, its replay refused as stale", func(t *testing.T) {
		p, fake := scripted(t, sharedHeld(), stale(http.StatusPreconditionFailed),
			policyReply("e2", ownerBinding, plain(objectAdmin, sharedPrincipal), plain(bucketReader, sharedPrincipal), plain("roles/storage.objectViewer", "user:new@example.com")),
			nil, stale(http.StatusPreconditionFailed),
			policyReply("e3", ownerBinding, plain(objectAdmin, uidPrincipal), plain(bucketReader, uidPrincipal), plain("roles/storage.objectViewer", "user:new@example.com")))
		changed, err := ensureGrant(p)
		if err != nil || !changed {
			t.Errorf("EnsureGrant = %v, %v; want the change its own second write made reported", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "GET", "PUT", "PUT", "GET"}) {
			t.Errorf("requests = %v, want two writes, the second sent twice, and a read after each", got)
		}
	})
	t.Run("a 503 is send's retry, not a second write", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding),
			errorReply(http.StatusServiceUnavailable, "UNAVAILABLE", "try again"), setReply())
		changed, err := ensureGrant(p)
		if err != nil || !changed {
			t.Fatalf("EnsureGrant = %v, %v", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "PUT"}) {
			t.Fatalf("requests = %v, want the read and one write sent twice", got)
		}
		if !bytes.Equal(fake.request(t, 1).body, fake.request(t, 2).body) {
			t.Errorf("the retried write differs from the first:\n%s\n%s", fake.request(t, 1).body, fake.request(t, 2).body)
		}
	})
	// A write one of whose attempts failed in transport, failed reading its
	// body, or got a 5xx may have landed, and send's replay of it may be
	// refused for another reason than a stale etag. A 403 or a 400 then
	// answers only the replay: the write is unconfirmed, never refused with
	// its policy unchanged, and the refusal's own reason stays in the error.
	// Any such attempt counts, wherever it falls among the write's attempts
	// and whatever 5xx it got, and a 429 after it does not settle the write
	// again. Which code GCS answers a stale etag with is [unverified]
	// (design §33, A33-13); a 409 or a 412 after such an attempt is stale,
	// as above (design §35, A35-3; mutation rows 169 and 172).
	bodyFails := func() *http.Response {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(iotest.ErrReader(errors.New("unexpected EOF")))}
	}
	for _, tc := range []struct {
		name    string
		replies func() []*http.Response
		want    []string
	}{
		{"a write lost in transport, its replay refused 403", func() []*http.Response {
			return []*http.Response{sharedHeld(), nil, errorReply(http.StatusForbidden, "PERMISSION_DENIED", "replay refused")}
		}, []string{"GET", "PUT", "PUT"}},
		{"a write lost in transport, its replay refused 400", func() []*http.Response {
			return []*http.Response{sharedHeld(), nil, errorReply(http.StatusBadRequest, "FAILED_PRECONDITION", "replay refused")}
		}, []string{"GET", "PUT", "PUT"}},
		{"a write answered 500, its replay refused 400", func() []*http.Response {
			return []*http.Response{sharedHeld(), errorReply(http.StatusInternalServerError, "INTERNAL", "backend error"),
				errorReply(http.StatusBadRequest, "INVALID_ARGUMENT", "replay refused")}
		}, []string{"GET", "PUT", "PUT"}},
		{"a write whose answer failed to read, its replay refused 403", func() []*http.Response {
			return []*http.Response{sharedHeld(), bodyFails(), errorReply(http.StatusForbidden, "PERMISSION_DENIED", "replay refused")}
		}, []string{"GET", "PUT", "PUT"}},
		{"a write lost in transport, then answered 429, its replay refused 403", func() []*http.Response {
			return []*http.Response{sharedHeld(), nil, errorReply(http.StatusTooManyRequests, "RESOURCE_EXHAUSTED", "slow down"),
				errorReply(http.StatusForbidden, "PERMISSION_DENIED", "replay refused")}
		}, []string{"GET", "PUT", "PUT", "PUT"}},
		{"a write answered 429, then lost in transport, its replay refused 403", func() []*http.Response {
			return []*http.Response{sharedHeld(), errorReply(http.StatusTooManyRequests, "RESOURCE_EXHAUSTED", "slow down"), nil,
				errorReply(http.StatusForbidden, "PERMISSION_DENIED", "replay refused")}
		}, []string{"GET", "PUT", "PUT", "PUT"}},
		{"a write answered 503, its replay refused 403", func() []*http.Response {
			return []*http.Response{sharedHeld(), errorReply(http.StatusServiceUnavailable, "UNAVAILABLE", "try again"),
				errorReply(http.StatusForbidden, "PERMISSION_DENIED", "replay refused")}
		}, []string{"GET", "PUT", "PUT"}},
		{"a stale write, then the second lost in transport and its replay refused 403", func() []*http.Response {
			return []*http.Response{sharedHeld(), stale(http.StatusPreconditionFailed),
				policyReply("e2", ownerBinding, plain(objectAdmin, sharedPrincipal), plain(bucketReader, sharedPrincipal)),
				nil, errorReply(http.StatusForbidden, "PERMISSION_DENIED", "replay refused")}
		}, []string{"GET", "PUT", "GET", "PUT", "PUT"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, fake := scripted(t, tc.replies()...)
			changed, err := ensureGrant(p)
			if !errors.Is(err, datasphere.ErrPolicyUnconfirmed) || changed || errors.Is(err, datasphere.ErrPolicyRejected) ||
				errors.Is(err, datasphere.ErrPermissionDenied) || errors.Is(err, datasphere.ErrPolicyChanged) {
				t.Errorf("EnsureGrant = %v, %v; want ErrPolicyUnconfirmed alone: the write may have landed", changed, err)
			}
			if err != nil && !strings.Contains(err.Error(), "replay refused") {
				t.Errorf("the error %v drops the replay's refusal", err)
			}
			if got := methods(fake); !slices.Equal(got, tc.want) {
				t.Errorf("requests = %v, want %v", got, tc.want)
			}
		})
	}
	// A 429 is an attempt the server did not process, so a refusal after it
	// settles the write (mutation row 170).
	t.Run("a write answered 429, its retry refused 403", func(t *testing.T) {
		p, fake := scripted(t, sharedHeld(), errorReply(http.StatusTooManyRequests, "RESOURCE_EXHAUSTED", "slow down"),
			errorReply(http.StatusForbidden, "PERMISSION_DENIED", "no setIamPolicy"))
		changed, err := ensureGrant(p)
		if !errors.Is(err, datasphere.ErrPermissionDenied) || changed || errors.Is(err, datasphere.ErrPolicyUnconfirmed) {
			t.Errorf("EnsureGrant = %v, %v; want ErrPermissionDenied, not ErrPolicyUnconfirmed", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "PUT"}) {
			t.Errorf("requests = %v, want the read and one write sent twice", got)
		}
	})
	// The read after the second stale write writes nothing, so its etag is
	// not needed: done there is a change, not done is ErrPolicyChanged, and
	// neither is unconfirmed. A read after a stale first write that finds
	// the grant done needs no etag either: it writes nothing (design §35,
	// A35-3; mutation row 171).
	t.Run("stale twice, then a read with no etag", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding), stale(http.StatusConflict),
			policyReply("e2", ownerBinding), stale(http.StatusPreconditionFailed),
			jsonReply(http.StatusOK, `{"version":1,"bindings":[`+ownerBinding+`]}`))
		changed, err := ensureGrant(p)
		if !errors.Is(err, datasphere.ErrPolicyChanged) || changed || errors.Is(err, datasphere.ErrPolicyUnconfirmed) {
			t.Errorf("EnsureGrant = %v, %v; want ErrPolicyChanged alone", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "GET", "PUT", "GET"}) {
			t.Errorf("requests = %v, want two writes and a read after each", got)
		}
	})
	t.Run("a stale write, then a read with no etag that finds the grant done", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding), stale(http.StatusPreconditionFailed),
			jsonReply(http.StatusOK, `{"version":1,"bindings":[`+ownerBinding+`,`+plain(objectAdmin, uidPrincipal)+`,`+plain(bucketReader, uidPrincipal)+`]}`))
		changed, err := ensureGrant(p)
		if err != nil || !changed {
			t.Errorf("EnsureGrant = %v, %v; want done, reported as a change a write it sent may have made", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "GET"}) {
			t.Errorf("requests = %v, want a read, the refused write and one read again", got)
		}
	})
}

// TestBucketGrantReplayRefusedAfterItsWriteLandedIsUnconfirmed: the server
// commits the first write and closes the connection without answering, and
// send replays the same bytes, whose etag is now stale. A 412 is stale, and
// the read after it finds the grant done: a change. A 403 or a 400 answers
// only the replay, so the write is unconfirmed: the policy holds the grant
// and no longer names the shared principal, and "refused, unchanged" would
// be false (design §35, A35-3; mutation row 169). It runs over a real
// http.Transport and a loopback listener, the one in this package's tests,
// because its point is how net/http reports a connection the server closed
// after it committed the write.
func TestBucketGrantReplayRefusedAfterItsWriteLandedIsUnconfirmed(t *testing.T) {
	for _, code := range []int{http.StatusPreconditionFailed, http.StatusForbidden, http.StatusBadRequest} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var (
				mu       sync.Mutex
				etag     = 1
				bindings = []json.RawMessage{json.RawMessage(ownerBinding),
					json.RawMessage(plain(objectAdmin, sharedPrincipal)), json.RawMessage(plain(bucketReader, sharedPrincipal))}
				puts, landed int
			)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet {
					out, _ := json.Marshal(map[string]any{"version": 3, "etag": fmt.Sprintf("e%d", etag), "bindings": bindings})
					_, _ = w.Write(out)
					return
				}
				puts++
				var in putPolicyBody
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if in.Etag != fmt.Sprintf("e%d", etag) {
					w.WriteHeader(code)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":"replay refused"}}`, code)
					return
				}
				bindings, etag, landed = in.Bindings, etag+1, landed+1
				if puts == 1 {
					// Committed, and the answer lost.
					c, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Errorf("hijack: %v", err)
						return
					}
					_ = c.Close()
					return
				}
				_, _ = fmt.Fprintf(w, `{"etag":"e%d"}`, etag)
			}))
			defer srv.Close()
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			oldClient, oldBackoff := newHTTPClient, retryBackoff
			t.Cleanup(func() { newHTTPClient, retryBackoff = oldClient, oldBackoff })
			newHTTPClient = func(datasphere.Config) (*http.Client, error) { return &http.Client{Transport: transport}, nil }
			retryBackoff = time.Microsecond
			pv, err := New(datasphere.Config{Project: testProject, Location: testLocation})
			if err != nil {
				t.Fatal(err)
			}
			p := pv.(*provider)
			p.base = srv.URL + "/storage/v1/"

			changed, err := ensureGrant(p)
			mu.Lock()
			final, gotPuts, gotLanded := fmt.Sprintf("%s", bindings), puts, landed
			mu.Unlock()
			if gotPuts != 2 || gotLanded != 1 || !strings.Contains(final, uidPrincipal) || strings.Contains(final, sharedPrincipal) {
				t.Fatalf("the server took %d writes, %d landed, and holds %s; want one write sent twice, the first landed", gotPuts, gotLanded, final)
			}
			if code == http.StatusPreconditionFailed {
				if err != nil || !changed {
					t.Errorf("EnsureGrant = %v, %v; want the change its own write made reported", changed, err)
				}
				return
			}
			if !errors.Is(err, datasphere.ErrPolicyUnconfirmed) || changed || errors.Is(err, datasphere.ErrPolicyRejected) ||
				errors.Is(err, datasphere.ErrPermissionDenied) {
				t.Errorf("EnsureGrant = %v, %v; want ErrPolicyUnconfirmed alone: the write landed", changed, err)
			}
		})
	}
}

// TestBucketGrantRemovesTheSharedBinding: the grant removes the principal
// every instance in the project shares from both roles' bindings with no
// condition, in the write that adds the member, and drops a binding left
// with no member (mutation row 132).
func TestBucketGrantRemovesTheSharedBinding(t *testing.T) {
	t.Run("from bindings it also adds to", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding,
			plain(objectAdmin, sharedPrincipal, "user:ops@example.com"), plain(bucketReader, sharedPrincipal)), setReply())
		if changed, err := ensureGrant(p); err != nil || !changed {
			t.Fatalf("EnsureGrant = %v, %v", changed, err)
		}
		got := decodeBindings(t, decodePut(t, fake.request(t, 1)).Bindings)
		if len(got) != 3 ||
			got[1].Role != objectAdmin || !slices.Equal(got[1].Members, []string{"user:ops@example.com", uidPrincipal}) ||
			got[2].Role != bucketReader || !slices.Equal(got[2].Members, []string{uidPrincipal}) {
			t.Errorf("the PUT's bindings are %+v; want the shared principal replaced by the member in both", got)
		}
	})
	t.Run("when the member is already granted", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding,
			plain(objectAdmin, uidPrincipal), plain(bucketReader, uidPrincipal),
			plain(objectAdmin, sharedPrincipal), plain(bucketReader, "user:ops@example.com", sharedPrincipal)), setReply())
		if changed, err := ensureGrant(p); err != nil || !changed {
			t.Fatalf("EnsureGrant = %v, %v; want a write that only removes", changed, err)
		}
		put := decodePut(t, fake.request(t, 1))
		got := decodeBindings(t, put.Bindings)
		if len(got) != 4 || !slices.Equal(got[3].Members, []string{"user:ops@example.com"}) {
			t.Errorf("the PUT's bindings are %+v; want the shared one's binding dropped and the other emptied of it", got)
		}
		for i, want := range []string{ownerBinding, plain(objectAdmin, uidPrincipal), plain(bucketReader, uidPrincipal)} {
			if !bytes.Equal(put.Bindings[i], []byte(want)) {
				t.Errorf("binding %d changed:\n got %s\nwant %s", i, put.Bindings[i], want)
			}
		}
		if bytes.Contains(fake.request(t, 1).body, []byte(sharedPrincipal)) {
			t.Errorf("the PUT still names the shared principal:\n%s", fake.request(t, 1).body)
		}
	})
	t.Run("nothing to do", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding, plain(objectAdmin, uidPrincipal), plain(bucketReader, uidPrincipal)))
		if changed, err := ensureGrant(p); err != nil || changed {
			t.Errorf("EnsureGrant = %v, %v; want no write", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET"}) {
			t.Errorf("requests = %v, want the read alone", got)
		}
	})
}

// TestBucketGrantLeavesConditionedSharedBindings: the shared principal under
// a condition is somebody's deliberate, bounded grant; the write leaves it,
// byte for byte, and the state does not count it (mutation row 131).
func TestBucketGrantLeavesConditionedSharedBindings(t *testing.T) {
	cond := conditioned(objectAdmin, sharedPrincipal, "user:temp@example.com")
	p, fake := newTestProvider(t, policyReply("e1", ownerBinding, cond, plain(bucketReader, sharedPrincipal)), setReply())
	if changed, err := ensureGrant(p); err != nil || !changed {
		t.Fatalf("EnsureGrant = %v, %v", changed, err)
	}
	put := decodePut(t, fake.request(t, 1))
	if len(put.Bindings) != 4 || !bytes.Equal(put.Bindings[1], []byte(cond)) {
		t.Fatalf("the conditioned binding did not go back as it came:\n%s", fake.request(t, 1).body)
	}
	got := decodeBindings(t, put.Bindings)
	if got[2].Role != bucketReader || !slices.Equal(got[2].Members, []string{uidPrincipal}) {
		t.Errorf("the reader binding is %+v, want the shared principal replaced", got[2])
	}

	p, _ = newTestProvider(t, policyReply("e1", cond, plain(objectAdmin, uidPrincipal), plain(bucketReader, uidPrincipal)))
	state, shared, roles, err := p.GrantState(context.Background(), testBucket, grantRoles, uidPrincipal, sharedPrincipal)
	if err != nil || state != datasphere.GrantPresent || shared != datasphere.GrantMissing || roles != nil {
		t.Errorf("GrantState = %s, %s, %q, %v; want present, missing: a conditioned shared binding is not the shared grant", state, shared, roles, err)
	}
}

// TestBucketGrantRefusalsNameTheirCause: the credential's refusal, on the
// read or on the write, wraps ErrPermissionDenied, and a refusal of a
// write at its first attempt never ErrPolicyUnconfirmed, which storage
// deploy checks first; a write the server answers at its first attempt
// with any other refusal, a redirect included, wraps ErrPolicyRejected,
// the policy unchanged, and the same refusal after a 5xx, behind which
// the write may have landed, wraps ErrPolicyUnconfirmed; a write sent and
// never answered, cancelled in flight or out of send's retries, and a
// read after a sent write that fails, or that it would write from and
// that comes without an etag, wrap ErrPolicyUnconfirmed, since a write
// may have landed; and a failure before any write is sent, a read
// answered with a redirect included, wraps none of the three.
func TestBucketGrantRefusalsNameTheirCause(t *testing.T) {
	t.Run("the read", func(t *testing.T) {
		p, fake := newTestProvider(t, errorReply(http.StatusForbidden, "PERMISSION_DENIED", "no"))
		changed, err := ensureGrant(p)
		if !errors.Is(err, datasphere.ErrPermissionDenied) || changed || !strings.Contains(err.Error(), testBucket) {
			t.Errorf("EnsureGrant = %v, %v; want ErrPermissionDenied naming the bucket", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET"}) {
			t.Errorf("requests = %v, want the read alone", got)
		}
	})
	t.Run("the write", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding), errorReply(http.StatusForbidden, "PERMISSION_DENIED", "no setIamPolicy"))
		changed, err := ensureGrant(p)
		if !errors.Is(err, datasphere.ErrPermissionDenied) || changed || errors.Is(err, datasphere.ErrPolicyUnconfirmed) {
			t.Errorf("EnsureGrant = %v, %v; want ErrPermissionDenied, not ErrPolicyUnconfirmed", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT"}) {
			t.Errorf("requests = %v, want one write, not retried", got)
		}
	})
	t.Run("an invalid member", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding), errorReply(http.StatusBadRequest, "INVALID_ARGUMENT", "invalid member"))
		changed, err := ensureGrant(p)
		if !errors.Is(err, datasphere.ErrPolicyRejected) || changed || errors.Is(err, datasphere.ErrPolicyUnconfirmed) ||
			errors.Is(err, datasphere.ErrPermissionDenied) || errors.Is(err, datasphere.ErrPolicyChanged) {
			t.Errorf("EnsureGrant = %v, %v; want ErrPolicyRejected alone", changed, err)
		}
		if !strings.Contains(err.Error(), "invalid member") {
			t.Errorf("the error %v drops Google's reason", err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT"}) {
			t.Errorf("requests = %v, want one write, not retried", got)
		}
	})
	// Neither request of the policy follows a redirect: net/http would
	// follow a 303 to the PUT as a GET, and a 2xx to that GET would be
	// reported as a change no write made. The 3xx is a refusal like any
	// other: answered at the write's first attempt, and unconfirmed after
	// an attempt that got a 5xx, since the write may have landed (design
	// §35, A35-3 and A35-17; mutation rows 169 and 173).
	redirect := func(code int) *http.Response {
		return &http.Response{StatusCode: code, Header: http.Header{"Location": []string{"/elsewhere"}}, Body: io.NopCloser(strings.NewReader(""))}
	}
	t.Run("a write answered with a redirect", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding), redirect(http.StatusSeeOther), setReply())
		changed, err := ensureGrant(p)
		if !errors.Is(err, datasphere.ErrPolicyRejected) || changed || errors.Is(err, datasphere.ErrPolicyUnconfirmed) {
			t.Errorf("EnsureGrant = %v, %v; want ErrPolicyRejected, not a change", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT"}) {
			t.Errorf("requests = %v, want the read and the write, the redirect not followed", got)
		}
	})
	t.Run("a write answered 503, then with a redirect", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding),
			errorReply(http.StatusServiceUnavailable, "UNAVAILABLE", "try again"), redirect(http.StatusSeeOther), setReply())
		changed, err := ensureGrant(p)
		if !errors.Is(err, datasphere.ErrPolicyUnconfirmed) || changed || errors.Is(err, datasphere.ErrPolicyRejected) {
			t.Errorf("EnsureGrant = %v, %v; want ErrPolicyUnconfirmed, not ErrPolicyRejected: the write may have landed", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "PUT"}) {
			t.Errorf("requests = %v, want the read and one write sent twice, the redirect not followed", got)
		}
	})
	t.Run("a read answered with a redirect", func(t *testing.T) {
		p, fake := newTestProvider(t, redirect(http.StatusFound), policyReply("e1", ownerBinding), setReply())
		changed, err := ensureGrant(p)
		if err == nil || changed || errors.Is(err, datasphere.ErrPolicyRejected) || errors.Is(err, datasphere.ErrPolicyUnconfirmed) {
			t.Errorf("EnsureGrant = %v, %v; want a failed read, no write sent", changed, err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET"}) {
			t.Errorf("requests = %v, want the read alone, the redirect not followed", got)
		}
	})

	// unconfirmed is a write that may have landed: ErrPolicyUnconfirmed,
	// and never ErrPolicyRejected, whose policy is unchanged.
	unconfirmed := func(t *testing.T, changed bool, err error) {
		t.Helper()
		if !errors.Is(err, datasphere.ErrPolicyUnconfirmed) || changed || errors.Is(err, datasphere.ErrPolicyRejected) {
			t.Errorf("EnsureGrant = %v, %v; want ErrPolicyUnconfirmed, not ErrPolicyRejected", changed, err)
		}
	}
	t.Run("a write cancelled in flight", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		p, _ := newTestProviderFunc(t, func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodGet {
				return policyReply("e1", ownerBinding), nil
			}
			cancel()
			return nil, context.Canceled
		})
		changed, err := p.EnsureGrant(ctx, testBucket, grantRoles, uidPrincipal, sharedPrincipal)
		unconfirmed(t, changed, err)
	})
	t.Run("a write never answered", func(t *testing.T) {
		p, fake := newTestProviderFunc(t, func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodGet {
				return policyReply("e1", ownerBinding), nil
			}
			return nil, errors.New("read tcp: connection reset by peer")
		})
		changed, err := ensureGrant(p)
		unconfirmed(t, changed, err)
		if got := fake.count(); got != 1+maxAttempts {
			t.Errorf("made %d requests; want the read and send's %d attempts", got, maxAttempts)
		}
	})
	t.Run("a write answered with server errors to the last attempt", func(t *testing.T) {
		p, _ := newTestProvider(t, append([]*http.Response{policyReply("e1", ownerBinding)}, repeatReply(maxAttempts, func() *http.Response {
			return errorReply(http.StatusInternalServerError, "INTERNAL", "backend error")
		})...)...)
		changed, err := ensureGrant(p)
		unconfirmed(t, changed, err)
	})
	t.Run("a read that fails after a stale write", func(t *testing.T) {
		p, _ := newTestProvider(t, policyReply("e1", ownerBinding), errorReply(http.StatusPreconditionFailed, "FAILED_PRECONDITION", "etag mismatch"),
			errorReply(http.StatusNotFound, "NOT_FOUND", "no such bucket"))
		changed, err := ensureGrant(p)
		unconfirmed(t, changed, err)
	})
	t.Run("a re-read with no etag after a stale write", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding), errorReply(http.StatusPreconditionFailed, "FAILED_PRECONDITION", "etag mismatch"),
			jsonReply(http.StatusOK, `{"version":1,"bindings":[`+ownerBinding+`]}`))
		changed, err := ensureGrant(p)
		unconfirmed(t, changed, err)
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "GET"}) {
			t.Errorf("requests = %v, want a read, the refused write and one read again", got)
		}
	})
	// The read after the second write refused as stale: it writes nothing,
	// and its failure may follow a write that landed.
	t.Run("a read that fails after two stale writes", func(t *testing.T) {
		p, fake := newTestProvider(t, policyReply("e1", ownerBinding), errorReply(http.StatusConflict, "CONFLICT", "the policy changed"),
			policyReply("e2", ownerBinding), errorReply(http.StatusPreconditionFailed, "FAILED_PRECONDITION", "etag mismatch"),
			errorReply(http.StatusForbidden, "PERMISSION_DENIED", "no getIamPolicy"))
		changed, err := ensureGrant(p)
		unconfirmed(t, changed, err)
		if errors.Is(err, datasphere.ErrPolicyChanged) {
			t.Errorf("EnsureGrant = %v; want the read's failure, not ErrPolicyChanged", err)
		}
		if got := methods(fake); !slices.Equal(got, []string{"GET", "PUT", "GET", "PUT", "GET"}) {
			t.Errorf("requests = %v, want two writes and a read after each", got)
		}
	})
	for name, replies := range map[string][]*http.Response{
		"a read that fails":      {errorReply(http.StatusNotFound, "NOT_FOUND", "no such bucket")},
		"a policy with no etag":  {jsonReply(http.StatusOK, `{"version":1,"bindings":[`+ownerBinding+`]}`)},
		"a binding that is bent": {policyReply("e1", `{"role":"`+objectAdmin+`","members":"`+uidPrincipal+`"}`)},
	} {
		t.Run(name+", before any write", func(t *testing.T) {
			p, fake := newTestProvider(t, replies...)
			changed, err := ensureGrant(p)
			if err == nil || changed || errors.Is(err, datasphere.ErrPolicyRejected) || errors.Is(err, datasphere.ErrPolicyUnconfirmed) {
				t.Errorf("EnsureGrant = %v, %v; want an error that says no write was refused or sent", changed, err)
			}
			if got := methods(fake); !slices.Equal(got, []string{"GET"}) {
				t.Errorf("requests = %v, want the read alone", got)
			}
		})
	}
}
