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
			`instance "atlas" records the reader writer@kubetest.invalid, which is not the reader farcast derives for it (` + readerName(name) + `@<a name under .invalid>); nothing was sent`},
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
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("the refusals sent %d requests", len(got))
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
			want := fmt.Sprintf("instance %q records the reader %s, which is not the reader farcast derives for it (%s@<a name under .invalid>); nothing was sent", name, email, readerName(name))
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
			want := fmt.Sprintf("instance %q records the reader %s, which is not the reader farcast derives for it (%s); nothing was sent", name, email, derived)
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

// Until ADR 0023 M2.5 the writer does not open in-process, and an identity
// an instance does not have never opens. Neither sends anything or opens the
// installer's key.
func TestOpenClusterLeavesTheWriterToM25(t *testing.T) {
	s := kubetest.New(t)
	dir, meta := readerInstance(t, s, "atlas", true)
	reads := observeConfigReads(t)
	for _, row := range []struct {
		identity kube.Identity
		want     string
	}{
		{kube.Writer, "cli: the writer opens in-process from ADR 0023 M2.5"},
		{"", `cli: "" is not one of an instance's identities`},
		{"admin", `cli: "admin" is not one of an instance's identities`},
	} {
		c, err := openCluster(clusterRef{Dir: dir, Meta: meta, Identity: row.identity, Warn: &bytes.Buffer{}})
		if c != nil || err == nil || err.Error() != row.want {
			t.Errorf("identity %q: openCluster = %v, %v; want %q", row.identity, c, err, row.want)
		}
	}
	if slices.Contains(reads(), filepath.Join(dir.InstancePath("atlas"), "credentials.yaml")) {
		t.Error("the refused writer opened credentials.yaml")
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("the refusals sent %d requests", len(got))
	}
	if c, err := openCluster(clusterRef{Dir: dir, Identity: kube.Reader}); c != nil || err == nil {
		t.Errorf("no record: openCluster = %v, %v", c, err)
	}
}
