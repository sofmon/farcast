package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
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
)

// readerGrantedAt is when the fixtures' readers were verified read-only.
var readerGrantedAt = time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)

// readerKey makes a reader key as 'reader init' does (kube.NewReaderKey) and,
// when s is non-nil, registers its public key with s under id and email. The
// key id is 40 hex characters, the shape of Google's.
func readerKey(t *testing.T, s *kubetest.Server, id, email string) (keyPEM, certPEM []byte, keyID string) {
	t.Helper()
	keyPEM, certPEM, err := kube.NewReaderKey(rand.Reader, time.Now().Add(-time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("NewReaderKey made no PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub := &parsed.(*rsa.PrivateKey).PublicKey
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	if s != nil {
		s.AddKey(id, email, pub)
	}
	return keyPEM, certPEM, hex.EncodeToString(sum[:20])
}

// readerInstance records a loopback instance against s, as the rehearsal
// will: its endpoint is s's, cluster-ca.crt is s's CA, and its reader is
// recorded under the derived loopback email with an uploaded key, reader.key,
// registered with s under id "reader". granted sets GrantedAt and Scope, as a
// verified 'reader grant' does. A writer credentials.yaml registered under id
// "writer" sits beside it, so a test can show the reader path never opens it.
func readerInstance(t *testing.T, s *kubetest.Server, name string, granted bool) (config.Dir, *config.InstanceMetadata) {
	t.Helper()
	dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
	if err := dir.CreateInstance(name); err != nil {
		t.Fatal(err)
	}
	email := readerName(name) + "@kubetest.invalid"
	keyPEM, certPEM, keyID := readerKey(t, s, "reader", email)
	meta := &config.InstanceMetadata{
		Name: name, Provider: "gke", Project: "proj-test1", Region: "us-central1",
		Cluster: "farcast-" + name, Endpoint: s.Endpoint(), Status: config.InstanceRunning,
		Reader: &config.Reader{Email: email, KeyID: keyID},
	}
	if granted {
		meta.Reader.GrantedAt, meta.Reader.Scope = readerGrantedAt, "metered"
	}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveReaderKey(name, keyPEM, certPEM); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir.InstancePath(name), "cluster-ca.crt"), s.CAPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := s.Credential("writer")
	key, err := json.Marshal(map[string]string{
		"type": "service_account", "client_email": writer.Email,
		"private_key_id": writer.PrivateKeyID, "private_key": string(writer.PrivateKeyPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceCredentials(name, &config.InstanceCredentials{Provider: "gke", ServiceAccountKey: string(key)}); err != nil {
		t.Fatal(err)
	}
	loaded, err := dir.LoadInstanceMetadata(name)
	if err != nil {
		t.Fatal(err)
	}
	return dir, loaded
}

// observeConfigReads collects every file the config package reads until the
// test ends.
func observeConfigReads(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var read []string
	stop := config.ObserveReads(func(p string) {
		mu.Lock()
		defer mu.Unlock()
		read = append(read, p)
	})
	t.Cleanup(stop)
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(read)
	}
}

// Each of openCluster's refusals (design §3.5) fires in its step's order,
// with its own words and its sentinel, and sends nothing. Every row's record
// also fails every later step, so a row passes only if its own step comes
// first.
func TestOpenClusterRefusesInOrder(t *testing.T) {
	s := kubetest.New(t)
	const name = "atlas"
	derived := readerName(name) + "@kubetest.invalid"
	for _, row := range []struct {
		step     string
		endpoint string
		ca       bool
		reader   *config.Reader
		key      bool
		sentinel error
		want     string
	}{
		{"1, no endpoint", "", true, nil, false, kube.ErrEndpointRefused,
			`instance "atlas" records no cluster endpoint; 'farcast install' records one; nothing was sent`},
		{"2 and 3, a loopback endpoint with no cluster-ca.crt", s.Endpoint(), false, nil, false, kube.ErrEndpointRefused,
			fmt.Sprintf("the instance records the loopback endpoint %q with no cluster-ca.crt; a loopback endpoint is trusted only on its own CA; nothing was sent", s.Endpoint())},
		{"2 and 3, a Google endpoint with a cluster-ca.crt", "uid.us-central1.gke.goog", true, nil, false, kube.ErrEndpointRefused,
			`the instance records the Google endpoint "uid.us-central1.gke.goog", and cluster-ca.crt exists: a Google endpoint is trusted on the system roots alone, so a cluster CA beside it is refused; nothing was sent`},
		{"3, an endpoint the rule refuses", "10.0.0.5:443", true, nil, false, kube.ErrEndpointRefused,
			`the instance records the endpoint "10.0.0.5:443", an IP literal outside 127.0.0.0/8 and ::1; nothing was sent`},
		{"4, no reader", s.Endpoint(), true, nil, false, errCredentialMissing,
			`instance "atlas" has no reader identity; run 'farcast reader init atlas'`},
		{"4, not the derived reader", s.Endpoint(), true, &config.Reader{Email: "writer@kubetest.invalid"}, false, errCredentialMissing,
			`instance "atlas" records the reader "writer@kubetest.invalid", which is not the reader farcast derives for it (` + readerName(name) + `@<a name under .invalid>); nothing was sent`},
		{"4, a key not uploaded", s.Endpoint(), true, &config.Reader{Email: derived}, false, errCredentialMissing,
			`instance "atlas"'s reader key is not yet uploaded; run the printed Cloud Shell script, then 'farcast reader record atlas --key-id <id>'`},
		{"4, a reader not verified", s.Endpoint(), true, &config.Reader{Email: derived, KeyID: strings.Repeat("ab", 20)}, false, errCredentialMissing,
			`instance "atlas"'s reader has not been verified read-only; run 'farcast reader grant atlas'`},
		{"4, no reader.key", s.Endpoint(), true, &config.Reader{Email: derived, KeyID: strings.Repeat("ab", 20), GrantedAt: readerGrantedAt}, false, errCredentialMissing,
			`instances/atlas/reader.key is missing; run 'farcast reader init atlas --rotate'`},
	} {
		dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
		meta := &config.InstanceMetadata{Name: name, Provider: "gke", Project: "proj-test1", Region: "us-central1", Endpoint: row.endpoint, Reader: row.reader}
		writeRecord(t, dir, meta)
		if row.ca {
			if err := os.WriteFile(filepath.Join(dir.InstancePath(name), "cluster-ca.crt"), s.CAPEM(), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Reader, Warn: &bytes.Buffer{}})
		if c != nil || err == nil {
			t.Errorf("step %s: openCluster = %v, %v; want a refusal", row.step, c, err)
			continue
		}
		if err.Error() != row.want {
			t.Errorf("step %s:\n got %q\nwant %q", row.step, err, row.want)
		}
		if !errors.Is(err, row.sentinel) {
			t.Errorf("step %s: %v does not match its sentinel %v", row.step, err, row.sentinel)
		}
		if row.sentinel == errCredentialMissing && errors.Is(err, kube.ErrEndpointRefused) ||
			row.sentinel == kube.ErrEndpointRefused && errors.Is(err, errCredentialMissing) {
			t.Errorf("step %s: %v matches the other sentinel too", row.step, err)
		}
	}

	// 1b, after step 1 and before step 2 (A18-8): a record checkedReader
	// refuses, refused with its value quoted, and nothing read. None has a
	// usable reader, so step 4 would refuse each as a missing reader, and
	// step 3 each without a cluster-ca.crt as the endpoint; the last has a
	// cluster-ca.crt that cannot be read, which step 2 would refuse as the
	// endpoint after reading it (mutation O6c). A row passes only if
	// checkedReader comes first, before a path is built from the recorded
	// name or anything is read from one.
	key := strings.Repeat("ab", 20)
	reads := observeConfigReads(t)
	for _, row := range []struct {
		field, value string
		meta         config.InstanceMetadata
		caDir        bool // cluster-ca.crt is a directory, which no read can open
	}{
		{"name", "atlas\x1b[2J", config.InstanceMetadata{Name: "atlas\x1b[2J", Project: "proj-test1", Reader: &config.Reader{Email: derived, KeyID: key}}, false},
		{"name", "../atlas", config.InstanceMetadata{Name: "../atlas", Project: "proj-test1"}, false},
		{"project ID", "proj'$(id)", config.InstanceMetadata{Name: name, Project: "proj'$(id)", Reader: &config.Reader{Email: derived, KeyID: key}}, false},
		{"key id", strings.ToUpper(key), config.InstanceMetadata{Name: name, Project: "proj-test1", Reader: &config.Reader{Email: derived, KeyID: strings.ToUpper(key)}}, false},
		{"project ID", "proj'$(id)", config.InstanceMetadata{Name: name, Project: "proj'$(id)", Reader: &config.Reader{Email: derived, KeyID: key, GrantedAt: readerGrantedAt}}, true},
	} {
		meta := row.meta
		meta.Provider, meta.Region, meta.Endpoint = "gke", "us-central1", s.Endpoint()
		dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
		if row.caDir {
			if err := os.MkdirAll(filepath.Join(dir.InstancePath(meta.Name), "cluster-ca.crt"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		c, err := openCluster(clusterRef{Dir: dir, Meta: &meta, Identity: kube.Reader, Warn: &bytes.Buffer{}})
		want := fmt.Sprintf(msgUnsafeRecord, meta.Name, row.field, row.value)
		if c != nil || err == nil || err.Error() != want || !errors.Is(err, errCredentialMissing) || errors.Is(err, kube.ErrEndpointRefused) {
			t.Errorf("step 1b, the %s %q (an unreadable cluster-ca.crt: %v): openCluster = %v, %v; want %q, matching errCredentialMissing alone", row.field, row.value, row.caDir, c, err, want)
		}
	}
	if got := reads(); len(got) != 0 {
		t.Errorf("step 1b read %v from records it refuses", got)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("the refusals sent %d requests", len(got))
	}
}

// A cluster-ca.crt that exists and cannot be read is refused as the
// endpoint (A18-8), never read as absent: a loopback endpoint is trusted on
// its own CA alone, and a Google endpoint with a CA beside it is refused. The
// record is otherwise one that reads.
func TestAnUnreadableClusterCAIsRefusedAsTheEndpoint(t *testing.T) {
	s := kubetest.New(t)
	dir, meta := readerInstance(t, s, "atlas", true)
	ca := filepath.Join(dir.InstancePath("atlas"), "cluster-ca.crt")
	if err := os.Remove(ca); err != nil {
		t.Fatal(err)
	}
	// A directory in its place: reading it fails whoever runs the test.
	if err := os.Mkdir(ca, 0o700); err != nil {
		t.Fatal(err)
	}
	_, readErr := os.ReadFile(ca)
	if readErr == nil {
		t.Fatal("a directory read as a file")
	}
	c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Reader, Warn: &bytes.Buffer{}})
	want := fmt.Sprintf("instance %q's cluster-ca.crt exists and cannot be read (%v); nothing was sent", "atlas", readErr)
	if c != nil || err == nil || err.Error() != want {
		t.Fatalf("openCluster = %v, %v; want %q", c, err, want)
	}
	if !errors.Is(err, kube.ErrEndpointRefused) || errors.Is(err, errCredentialMissing) {
		t.Errorf("%v does not match kube.ErrEndpointRefused alone", err)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("the refusal sent %d requests", len(got))
	}
}

// ADR 0023 M2.3, mutation 50: the reader openCluster opens is the one farcast
// derives for the instance, in both modes. The installer's email, or a
// hand-edited one, is refused before anything is sent, so a certificate
// uploaded to the installer's account never makes a "reader" read an admin
// read. Each refused email's key is registered with kubetest, so skipping the
// check would read.
func TestReaderEmailMustBeTheDerivedOne(t *testing.T) {
	const name = "atlas"

	t.Run("loopback", func(t *testing.T) {
		s := kubetest.New(t)
		s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "farcast-system"}})
		dir, meta := readerInstance(t, s, name, true)
		for _, email := range []string{
			"writer@kubetest.invalid",                               // the installer's
			readerName("other") + "@kubetest.invalid",               // another instance's reader
			strings.ToUpper(readerName(name)) + "@kubetest.invalid", // the derived name, edited
			readerName(name) + "x@kubetest.invalid",
			readerName(name) + "@invalid",               // no name under .invalid
			readerName(name) + "@.invalid",              // the bare suffix
			readerName(name) + "@kubetest.invalid.test", // not under .invalid
			readerName(name) + "@proj-test1.iam.gserviceaccount.com",
			readerEmail(name, "proj-test1") + "@kubetest.invalid",
			// Under .invalid, but not DNS labels: nothing is printed from
			// a domain a shell or a YAML scalar would read otherwise.
			readerName(name) + "@$(id).invalid",
			readerName(name) + "@a'$(id)'.invalid",
			readerName(name) + "@a b.invalid",
			readerName(name) + "@Kubetest.invalid",
			readerName(name) + "@-kubetest.invalid",
			readerName(name) + "@kubetest..invalid",
		} {
			keyPEM, certPEM, keyID := readerKey(t, s, "edited", email)
			if err := dir.SaveReaderKey(name, keyPEM, certPEM); err != nil {
				t.Fatal(err)
			}
			edited := *meta
			edited.Reader = &config.Reader{Email: email, KeyID: keyID, GrantedAt: readerGrantedAt, Scope: "metered"}
			c, err := openCluster(clusterRef{Dir: dir, Meta: &edited, Identity: kube.Reader, Warn: &bytes.Buffer{}})
			want := fmt.Sprintf("instance %q records the reader %q, which is not the reader farcast derives for it (%s@<a name under .invalid>); nothing was sent", name, email, readerName(name))
			if c != nil || !errors.Is(err, errCredentialMissing) || err.Error() != want {
				t.Errorf("%s: openCluster = %v, %v; want %q", email, c, err, want)
			}
		}
		if got := s.Requests(); len(got) != 0 {
			t.Errorf("the refused readers sent %d requests", len(got))
		}

		// The derived reader, at any name under .invalid, reads.
		for _, domain := range []string{"kubetest.invalid", "rehearsal.invalid"} {
			email := readerName(name) + "@" + domain
			keyPEM, certPEM, keyID := readerKey(t, s, "derived", email)
			if err := dir.SaveReaderKey(name, keyPEM, certPEM); err != nil {
				t.Fatal(err)
			}
			derived := *meta
			derived.Reader = &config.Reader{Email: email, KeyID: keyID, GrantedAt: readerGrantedAt, Scope: "metered"}
			c, err := openCluster(clusterRef{Dir: dir, Meta: &derived, Identity: kube.Reader, Warn: &bytes.Buffer{}})
			if err != nil {
				t.Fatalf("%s: %v", email, err)
			}
			if names, err := c.NamespacesLabelled(t.Context(), ""); err != nil || !slices.Equal(names, []string{"farcast-system"}) {
				t.Errorf("%s: NamespacesLabelled = %q, %v", email, names, err)
			}
		}
		for _, r := range s.Requests() {
			if r.As != "derived" {
				t.Errorf("%s %s as %q; want only the derived reader", r.Method, r.Path, r.As)
			}
		}
	})

	t.Run("google", func(t *testing.T) {
		dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
		meta := &config.InstanceMetadata{
			Name: name, Provider: "gke", Project: "proj-test1", Region: "us-central1",
			Endpoint: "uid.us-central1.gke.goog", Status: config.InstanceRunning,
		}
		writeRecord(t, dir, meta)
		keyPEM, certPEM, keyID := readerKey(t, nil, "", "")
		if err := dir.SaveReaderKey(name, keyPEM, certPEM); err != nil {
			t.Fatal(err)
		}
		derived := readerEmail(name, "proj-test1")
		for _, email := range []string{
			"farcast-installer@proj-test1.iam.gserviceaccount.com", // the installer's
			readerEmail(name, "other-proj"),                        // another project's
			readerEmail("other", "proj-test1"),                     // another instance's
			strings.ToUpper(derived),
			derived + " ",
			" " + derived,
			readerName(name) + "@kubetest.invalid", // the loopback form
		} {
			meta.Reader = &config.Reader{Email: email, KeyID: keyID, GrantedAt: readerGrantedAt, Scope: "metered"}
			c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Reader, Warn: &bytes.Buffer{}})
			want := fmt.Sprintf("instance %q records the reader %q, which is not the reader farcast derives for it (%s); nothing was sent", name, email, derived)
			if c != nil || !errors.Is(err, errCredentialMissing) || err.Error() != want {
				t.Errorf("%q: openCluster = %v, %v; want %q", email, c, err, want)
			}
		}
		// The derived one opens. Nothing is dialled before a method is called.
		meta.Reader = &config.Reader{Email: derived, KeyID: keyID, GrantedAt: readerGrantedAt, Scope: "metered"}
		if c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Reader, Warn: &bytes.Buffer{}}); c == nil || err != nil {
			t.Errorf("the derived reader: openCluster = %v, %v", c, err)
		}
	})
}

// A granted reader with a registered key reads in-process, as the reader:
// the token is minted with the recorded key id, every request carries the
// reader's token, the API's warnings reach the command's stderr, and the
// installer's credentials.yaml is never opened.
func TestAGrantedReaderReadsTheCluster(t *testing.T) {
	s := kubetest.New(t, kubetest.WithWarnings(func(r kubetest.Request) []string {
		return []string{"a deprecated thing"}
	}))
	managed := map[string]any{"app.kubernetes.io/managed-by": "farcast"}
	for _, ns := range []string{"web", "farcast-system"} {
		s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns, "labels": managed}})
	}
	s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "kube-system"}})
	dir, meta := readerInstance(t, s, "atlas", true)
	reads := observeConfigReads(t)

	var warn bytes.Buffer
	c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Reader, Warn: &warn})
	if err != nil {
		t.Fatal(err)
	}
	names, err := c.NamespacesLabelled(t.Context(), "app.kubernetes.io/managed-by=farcast")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"farcast-system", "web"}; !slices.Equal(names, want) {
		t.Errorf("NamespacesLabelled = %q, want %q", names, want)
	}
	reqs := s.Requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %+v; want one mint and one list", reqs)
	}
	if reqs[0].Path != "/token" || reqs[0].As != "reader" || reqs[0].KeyID != meta.Reader.KeyID {
		t.Errorf("mint = %s as %q with kid %q; want the reader's recorded key id %q", reqs[0].Path, reqs[0].As, reqs[0].KeyID, meta.Reader.KeyID)
	}
	if reqs[1].Method != http.MethodGet || reqs[1].Path != "/api/v1/namespaces" || reqs[1].As != "reader" {
		t.Errorf("read = %s %s as %q", reqs[1].Method, reqs[1].Path, reqs[1].As)
	}
	if got := warn.String(); got != "Warning (cluster): a deprecated thing\n" {
		t.Errorf("warnings = %q", got)
	}
	got := reads()
	if !slices.Contains(got, filepath.Join(dir.InstancePath("atlas"), "reader.key")) {
		t.Errorf("reads %v do not include reader.key", got)
	}
	if slices.Contains(got, filepath.Join(dir.InstancePath("atlas"), "credentials.yaml")) {
		t.Errorf("the reader path opened the installer's credentials.yaml: %v", got)
	}
}

// Verifying is reader grant's own exception: it opens a reader whose
// GrantedAt is zero, for the verifying read and reviews. Without it, the same
// record is refused and the server sees nothing.
func TestOnlyVerifyingOpensAnUnverifiedReader(t *testing.T) {
	s := kubetest.New(t, kubetest.WithAccess(func(id string, a kube.ResourceAttributes) bool { return false }))
	s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "farcast-system"}})
	dir, meta := readerInstance(t, s, "atlas", false)

	c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Reader, Warn: &bytes.Buffer{}})
	if c != nil || !errors.Is(err, errCredentialMissing) || !strings.Contains(err.Error(), "has not been verified read-only") {
		t.Fatalf("an unverified reader: openCluster = %v, %v", c, err)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Fatalf("an unverified reader sent %d requests", len(got))
	}

	c, err = openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Reader, Warn: &bytes.Buffer{}, Verifying: true})
	if err != nil {
		t.Fatal(err)
	}
	if names, err := c.NamespacesLabelled(t.Context(), ""); err != nil || !slices.Equal(names, []string{"farcast-system"}) {
		t.Errorf("the verifying read = %q, %v", names, err)
	}
	if ok, err := c.CanI(t.Context(), kube.ResourceAttributes{Namespace: "farcast-system", Verb: "get", Resource: "secrets"}); ok || err != nil {
		t.Errorf("the verifying review = %v, %v", ok, err)
	}
	for _, r := range s.Requests() {
		if r.As != "reader" {
			t.Errorf("%s %s as %q; want the reader", r.Method, r.Path, r.As)
		}
	}
}

// An identity an instance does not have never opens, and neither does a
// call with no record. Neither sends anything or opens the installer's key.
func TestOpenClusterRefusesAnIdentityAnInstanceDoesNotHave(t *testing.T) {
	s := kubetest.New(t)
	dir, meta := readerInstance(t, s, "atlas", true)
	reads := observeConfigReads(t)
	for _, row := range []struct {
		identity kube.Identity
		want     string
	}{
		{"", `cli: "" is not one of an instance's identities`},
		{"admin", `cli: "admin" is not one of an instance's identities`},
	} {
		c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: row.identity, Warn: &bytes.Buffer{}})
		if c != nil || err == nil || err.Error() != row.want {
			t.Errorf("identity %q: openCluster = %v, %v; want %q", row.identity, c, err, row.want)
		}
	}
	if slices.Contains(reads(), filepath.Join(dir.InstancePath("atlas"), "credentials.yaml")) {
		t.Error("a refused identity opened credentials.yaml")
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("the refusals sent %d requests", len(got))
	}
	if c, err := openCluster(clusterRef{Dir: dir, Identity: kube.Writer}); c != nil || err == nil {
		t.Errorf("no record: openCluster = %v, %v", c, err)
	}
}

// writerKeyJSON is a service-account key file's JSON for cred, as Google's
// key files are, with fields replaced or added from extra.
func writerKeyJSON(t *testing.T, cred kube.Credential, extra map[string]string) string {
	t.Helper()
	fields := map[string]string{
		"type": "service_account", "client_email": cred.Email,
		"private_key_id": cred.PrivateKeyID, "private_key": string(cred.PrivateKeyPEM),
	}
	for k, v := range extra {
		fields[k] = v
	}
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// keyBytesIn reports whether msg holds any piece of a PEM key's body: every
// base64 line is looked for by its first 16 characters, which no message
// farcast writes could hold by chance.
func keyBytesIn(msg string, keyPEM []byte) bool {
	for _, line := range strings.Split(string(keyPEM), "\n") {
		if strings.HasPrefix(line, "-----") || len(line) < 16 {
			continue
		}
		if strings.Contains(msg, line[:16]) {
			return true
		}
	}
	return false
}

// ADR 0023 M2.5 (A20-8), mutations 71c and 71d: each of openCluster's
// refusals of the writer fires in its step's order, with its own words, and
// matches its sentinel: errCredentialMissing for the record's name and for
// credentials.yaml, kube.ErrEndpointRefused for the endpoint and for a key
// that does not pair with it. None sends anything, and no message holds a
// byte of the private key credentials.yaml holds: a file that does not parse
// is named by its fault and position, never by the YAML library's text,
// which quotes the source lines; and a key that is not a service-account key
// keeps kube's text, which names the field. A name install would refuse is
// refused before any path is built from it, so nothing is read at all.
func TestOpenClusterRefusesTheWriterInOrder(t *testing.T) {
	s := kubetest.New(t)
	const name = "atlas"
	writer := s.Credential("writer")
	google := kube.Credential{Email: "installer@proj-test1.iam.gserviceaccount.com", PrivateKeyID: writer.PrivateKeyID, PrivateKeyPEM: writer.PrivateKeyPEM}
	valid := writerKeyJSON(t, writer, nil)
	savedCreds := func(key string) func(t *testing.T, dir config.Dir) {
		return func(t *testing.T, dir config.Dir) {
			if err := dir.SaveInstanceCredentials(name, &config.InstanceCredentials{Provider: "gke", ServiceAccountKey: key}); err != nil {
				t.Fatal(err)
			}
		}
	}
	credsFile := func(dir config.Dir) string { return filepath.Join(dir.InstancePath(name), "credentials.yaml") }
	// corrupt is a credentials.yaml holding the whole key, with a YAML
	// syntax error on the line after it, so the YAML library's own message
	// quotes the key's lines.
	corrupt := func(t *testing.T, dir config.Dir) {
		savedCreds(valid)(t, dir)
		b, err := os.ReadFile(credsFile(dir))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(credsFile(dir), append(b, []byte("  - [unclosed\n")...), 0o600); err != nil {
			t.Fatal(err)
		}
		// The fixture is only worth its name if the library's text would
		// have leaked the key.
		if _, err := dir.LoadInstanceCredentials(name); err == nil || !keyBytesIn(err.Error(), writer.PrivateKeyPEM) {
			t.Fatalf("the corrupt credentials.yaml's own parse error = %v; want one that quotes the key", err)
		}
	}
	for _, row := range []struct {
		step     string
		endpoint string
		creds    func(t *testing.T, dir config.Dir)
		sentinel error
		want     func(dir config.Dir) string
	}{
		{"1, no endpoint", "", savedCreds(""), kube.ErrEndpointRefused,
			func(config.Dir) string {
				return `instance "atlas" records no cluster endpoint; 'farcast install' records one; nothing was sent`
			}},
		{"4, no credentials.yaml", s.Endpoint(), nil, errCredentialMissing,
			func(config.Dir) string {
				return `instances/atlas/credentials.yaml is missing; this machine holds no installer key for instance "atlas"; nothing was sent`
			}},
		{"4, a credentials.yaml that cannot be read", s.Endpoint(), func(t *testing.T, dir config.Dir) {
			if err := os.Mkdir(credsFile(dir), 0o700); err != nil {
				t.Fatal(err)
			}
		}, errCredentialMissing,
			func(dir config.Dir) string {
				_, err := os.ReadFile(credsFile(dir))
				var pe *fs.PathError
				if !errors.As(err, &pe) {
					t.Fatalf("reading a directory = %v", err)
				}
				return fmt.Sprintf(`instance "atlas"'s credentials.yaml cannot be read (%v); nothing was sent`, pe.Err)
			}},
		{"4, a credentials.yaml that does not parse", s.Endpoint(), corrupt, errCredentialMissing,
			func(dir config.Dir) string {
				_, err := dir.LoadInstanceCredentials(name)
				fault, ok := config.ParseFault(err)
				if !ok {
					t.Fatalf("ParseFault(%v) found no fault", err)
				}
				return fmt.Sprintf(`instance "atlas"'s credentials.yaml does not parse (%s); nothing was sent`, fault)
			}},
		{"4, a blank key (Application Default Credentials)", s.Endpoint(), savedCreds(""), errCredentialMissing,
			func(config.Dir) string {
				return `instance "atlas" was installed without a service-account key (Application Default Credentials), which farcast no longer uses for its cluster (ADR 0023 M2); ` +
					`release it ('farcast release atlas') and install a new instance with --credentials`
			}},
		{"4, a key that is not a service account's", s.Endpoint(), savedCreds(writerKeyJSON(t, writer, map[string]string{"type": "authorized_user"})), errCredentialMissing,
			func(config.Dir) string {
				return "the stored service-account key is not a service-account key farcast uses (type)"
			}},
		{"4, a key whose private key is not RSA", s.Endpoint(), savedCreds(writerKeyJSON(t, writer, map[string]string{"private_key": "-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("QUJD", 20) + "\n-----END PRIVATE KEY-----\n"})), errCredentialMissing,
			func(config.Dir) string {
				return "the stored service-account key is not a service-account key farcast uses (private_key)"
			}},
		{"5, a Google key to a loopback endpoint", s.Endpoint(), savedCreds(writerKeyJSON(t, google, nil)), kube.ErrEndpointRefused,
			func(config.Dir) string {
				return "a Google credential (proj-test1.iam.gserviceaccount.com) does not go to a loopback endpoint; nothing was sent"
			}},
	} {
		dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
		meta := &config.InstanceMetadata{Name: name, Provider: "gke", Project: "proj-test1", Region: "us-central1", Endpoint: row.endpoint}
		writeRecord(t, dir, meta)
		if err := os.WriteFile(filepath.Join(dir.InstancePath(name), "cluster-ca.crt"), s.CAPEM(), 0o600); err != nil {
			t.Fatal(err)
		}
		if row.creds != nil {
			row.creds(t, dir)
		}
		c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Writer, Warn: &bytes.Buffer{}})
		if c != nil || err == nil {
			t.Errorf("step %s: openCluster = %v, %v; want a refusal", row.step, c, err)
			continue
		}
		if want := row.want(dir); err.Error() != want {
			t.Errorf("step %s:\n got %q\nwant %q", row.step, err, want)
		}
		if !errors.Is(err, row.sentinel) {
			t.Errorf("step %s: %v does not match its sentinel %v", row.step, err, row.sentinel)
		}
		if keyBytesIn(err.Error(), writer.PrivateKeyPEM) || strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("step %s: the refusal holds the key: %q", row.step, err)
		}
		if kind := kindOf(classified(err)); kind != map[error]string{errCredentialMissing: kindCredentialMissing, kube.ErrEndpointRefused: kindEndpointRefused}[row.sentinel] {
			t.Errorf("step %s: kind %q", row.step, kind)
		}
	}

	// 1b (A20-8): a recorded name install would refuse is refused, quoted,
	// before any path is built from it: nothing is read, not even
	// cluster-ca.crt. Each row's directory holds a usable writer under that
	// name, so skipping the check would open it.
	reads := observeConfigReads(t)
	for _, bad := range []string{"atlas\x1b[2J", "../atlas", "Atlas", "atlas/x"} {
		dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
		inst := filepath.Join(string(dir), "instances", bad)
		if err := os.MkdirAll(inst, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(inst, "cluster-ca.crt"), s.CAPEM(), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(inst, "credentials.yaml"), []byte("provider: gke\nservice_account_key: "+strconvQuote(valid)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		meta := &config.InstanceMetadata{Name: bad, Provider: "gke", Project: "proj-test1", Region: "us-central1", Endpoint: s.Endpoint()}
		c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Writer, Warn: &bytes.Buffer{}})
		want := fmt.Sprintf(msgUnsafeRecord, bad, "name", bad)
		if c != nil || err == nil || err.Error() != want || !errors.Is(err, errCredentialMissing) {
			t.Errorf("the name %q: openCluster = %v, %v; want %q", bad, c, err, want)
		}
	}
	if got := reads(); len(got) != 0 {
		t.Errorf("the writer read %v from records whose name it refuses", got)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("the refusals sent %d requests", len(got))
	}
}

// ADR 0023 M2.6 (A23-24 step 2): loadInstallerKey is the one reader of the
// installer's key, for the writer and for what a plan reads from Google with
// it, so each of its refusals is the writer's, word for word, with the same
// sentinel, and holds no byte of the key. A usable key is returned as it is
// stored.
func TestLoadInstallerKeyRefusesAsTheWriterDoes(t *testing.T) {
	s := kubetest.New(t)
	const name = "atlas"
	writer := s.Credential("writer")
	valid := writerKeyJSON(t, writer, nil)
	credsFile := func(dir config.Dir) string { return filepath.Join(dir.InstancePath(name), "credentials.yaml") }
	saved := func(key string) func(t *testing.T, dir config.Dir) {
		return func(t *testing.T, dir config.Dir) {
			if err := dir.SaveInstanceCredentials(name, &config.InstanceCredentials{Provider: "gke", ServiceAccountKey: key}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, row := range []struct {
		name  string
		creds func(t *testing.T, dir config.Dir)
	}{
		{"no credentials.yaml", func(*testing.T, config.Dir) {}},
		{"a credentials.yaml that cannot be read", func(t *testing.T, dir config.Dir) {
			if err := os.Mkdir(credsFile(dir), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"a credentials.yaml that does not parse", func(t *testing.T, dir config.Dir) {
			saved(valid)(t, dir)
			b, err := os.ReadFile(credsFile(dir))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(credsFile(dir), append(b, []byte("  - [unclosed\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a blank key (Application Default Credentials)", saved("")},
		{"a key of white space", saved(" \n\t")},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
			meta := &config.InstanceMetadata{Name: name, Provider: "gke", Project: "proj-test1", Region: "us-central1", Endpoint: s.Endpoint()}
			writeRecord(t, dir, meta)
			if err := os.WriteFile(filepath.Join(dir.InstancePath(name), "cluster-ca.crt"), s.CAPEM(), 0o600); err != nil {
				t.Fatal(err)
			}
			row.creds(t, dir)
			creds, err := loadInstallerKey(dir, name)
			if creds != nil || err == nil {
				t.Fatalf("loadInstallerKey returned credentials (%v), or no refusal", creds != nil)
			}
			_, werr := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Writer, Warn: &bytes.Buffer{}})
			if werr == nil || err.Error() != werr.Error() {
				t.Errorf("loadInstallerKey refused with\n %q\nthe writer with\n %q", err, werr)
			}
			if !errors.Is(err, errCredentialMissing) || kindOf(classified(err)) != kindCredentialMissing {
				t.Errorf("%v is not credential_missing", err)
			}
			if keyBytesIn(err.Error(), writer.PrivateKeyPEM) || strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Error("the refusal holds the key")
			}
		})
	}
	t.Run("a usable key", func(t *testing.T) {
		dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
		writeRecord(t, dir, &config.InstanceMetadata{Name: name, Provider: "gke"})
		saved(valid)(t, dir)
		creds, err := loadInstallerKey(dir, name)
		if err != nil || creds == nil || creds.ServiceAccountKey != valid || creds.Provider != "gke" {
			t.Fatalf("loadInstallerKey = %v (credentials returned: %v), want the stored key", err, creds != nil)
		}
	})
}

// strconvQuote is a YAML double-quoted scalar for s: JSON's quoting, which
// YAML reads.
func strconvQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// ADR 0023 M2.5 (A20-8): the writer opens as the installer's key from
// credentials.yaml, in loopback mode against kubetest. Its reads go
// in-process as the writer, minted with the stored key id, and reader.key is
// never read. Since ADR 0023 M2.7 (A30-31) its Apply is in-process too: one
// apply-patch, as the writer, on the token it already minted, and nothing
// runs kubectl.
func TestAWriterOpensAsTheInstallerKey(t *testing.T) {
	s := kubetest.New(t, kubetest.WithSettledWorkloads())
	s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "farcast-system", "uid": "uid-1"}})
	dir, meta := readerInstance(t, s, "atlas", true)
	reads := observeConfigReads(t)

	c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Writer, Warn: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if uid, err := c.NamespaceUID(t.Context(), "farcast-system"); err != nil || uid == "" {
		t.Fatalf("NamespaceUID = %q, %v", uid, err)
	}
	reqs := s.Requests()
	if len(reqs) != 2 || reqs[0].Path != "/token" || reqs[0].As != "writer" || reqs[1].As != "writer" {
		t.Fatalf("requests = %+v; want one mint and one read, as the writer", reqs)
	}
	got := reads()
	if !slices.Contains(got, filepath.Join(dir.InstancePath("atlas"), "credentials.yaml")) {
		t.Errorf("the writer never read credentials.yaml: %v", got)
	}
	if slices.Contains(got, filepath.Join(dir.InstancePath("atlas"), "reader.key")) {
		t.Errorf("the writer read reader.key: %v", got)
	}

	namespace := []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n")
	if err := c.Apply(t.Context(), namespace); err != nil {
		t.Fatal(err)
	}
	reqs = s.Requests()[2:]
	if len(reqs) != 1 || reqs[0].Method != http.MethodPatch || reqs[0].Path != "/api/v1/namespaces/x" ||
		reqs[0].ContentType != "application/apply-patch+yaml" || reqs[0].RawQuery != applyQuery ||
		reqs[0].As != "writer" || !bytes.Equal(reqs[0].Body, namespace) {
		t.Errorf("Apply sent %+v; want one apply-patch of the document, as the writer, with no second mint", reqs)
	}
}
