package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sofmon/farcast/datasphere"
)

// The verbs an operator actually runs, driven end to end through a registered
// in-memory provider.
//
// The other harness tests cover the flows that touch no cloud (keygen,
// mint-name, argument handling). These cover the rest, and they matter for a
// reason the unit tests below the harness cannot reach: this is the composition
// root. It is where the ownership check is enforced before a Store exists, where
// a refusal has to be turned into advice an operator can act on, and where the
// only human-readable output in the module is produced.

const testProviderName = "harness-test-fake"

// harnessFake is a whole in-memory object store, registered under its own
// provider name so these tests never reach the real GCS adapter.
type harnessFake struct {
	mu      sync.Mutex
	objects map[string]datasphere.Object

	// instance is the one this fake's bucket belongs to. Validate refuses any
	// other, exactly as the GCS adapter does, so the harness's enforcement
	// point is exercised rather than simulated.
	instance string
	// retention makes EnsureBucket and DeleteBucket return the
	// ErrRetentionForced notice alongside their successful result.
	retention bool
}

var (
	fakeMu      sync.Mutex
	currentFake *harnessFake
)

func init() {
	datasphere.Register(testProviderName, func(datasphere.Config) (datasphere.Provider, error) {
		fakeMu.Lock()
		defer fakeMu.Unlock()
		if currentFake == nil {
			return nil, errors.New("no fake installed")
		}
		return currentFake, nil
	})
}

// installFake makes f the provider the next Open returns, for the duration of
// one test.
func installFake(t *testing.T, f *harnessFake) *harnessFake {
	t.Helper()
	fakeMu.Lock()
	currentFake = f
	fakeMu.Unlock()
	t.Cleanup(func() {
		fakeMu.Lock()
		currentFake = nil
		fakeMu.Unlock()
	})
	return f
}

func newHarnessFake(instance string) *harnessFake {
	return &harnessFake{objects: map[string]datasphere.Object{}, instance: instance}
}

func (f *harnessFake) Name() string { return testProviderName }

func (f *harnessFake) Validate(_ context.Context, ref datasphere.BucketRef) error {
	if ref.Name == "" {
		return nil
	}
	if ref.Instance != f.instance {
		return fmt.Errorf("%w: bucket %q belongs to %q", datasphere.ErrNotOwned, ref.Name, f.instance)
	}
	return nil
}

func (f *harnessFake) EnsureBucket(_ context.Context, spec datasphere.BucketSpec) (*datasphere.Bucket, error) {
	bucket := &datasphere.Bucket{Ref: datasphere.BucketRef{Name: spec.Name, Location: spec.Location, Instance: spec.Instance}}
	if spec.Instance != f.instance {
		return nil, fmt.Errorf("%w: bucket %q belongs to %q", datasphere.ErrNotOwned, spec.Name, f.instance)
	}
	if f.retention {
		return bucket, fmt.Errorf("%w: bucket %q retains deleted objects for 168h0m0s", datasphere.ErrRetentionForced, spec.Name)
	}
	return bucket, nil
}

func (f *harnessFake) DeleteBucket(_ context.Context, ref datasphere.BucketRef) error {
	if ref.Instance != f.instance {
		return fmt.Errorf("%w: bucket %q belongs to %q", datasphere.ErrNotOwned, ref.Name, f.instance)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects = map[string]datasphere.Object{}
	if f.retention {
		return fmt.Errorf("%w: bucket %q retains deleted objects for 168h0m0s", datasphere.ErrRetentionForced, ref.Name)
	}
	return nil
}

func (f *harnessFake) Put(_ context.Context, _ string, obj datasphere.Object) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[obj.Name] = obj
	return nil
}

func (f *harnessFake) Get(_ context.Context, _, name string) (*datasphere.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", datasphere.ErrObjectNotFound, name)
	}
	return &obj, nil
}

func (f *harnessFake) List(_ context.Context, _, prefix string) ([]datasphere.ObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []datasphere.ObjectInfo
	for name, obj := range f.objects {
		if strings.HasPrefix(name, prefix) {
			out = append(out, datasphere.ObjectInfo{Name: name, Size: int64(len(obj.Data)), Meta: obj.Meta})
		}
	}
	return out, nil
}

func (f *harnessFake) Delete(_ context.Context, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, name)
	return nil
}

// harnessEnv is one test's working directory, keyring, and captured output.
type harnessEnv struct {
	t    *testing.T
	dir  string
	keys string
}

func newHarnessEnv(t *testing.T) *harnessEnv {
	t.Helper()
	env := &harnessEnv{t: t, dir: t.TempDir()}
	env.keys = filepath.Join(env.dir, "keys.yaml")
	if code, out, errOut := env.run("keygen", "--keys", env.keys); code != 0 {
		t.Fatalf("keygen = %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	return env
}

func (e *harnessEnv) run(args ...string) (int, string, string) {
	e.t.Helper()
	var out, errOut bytes.Buffer
	code := run(append([]string{"datasphere"}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

// common is the flag set every data-touching verb needs.
func (e *harnessEnv) common(instance string) []string {
	return []string{
		"--provider", testProviderName,
		"--project", "test-project",
		"--location", "test-region",
		"--instance", instance,
		"--bucket", "farcast-" + instance + "-0badc0de",
		"--keys", e.keys,
	}
}

// TestHarnessObjectLifecycle walks put, ls, get and rm through the full Store,
// and — the part worth having — checks that what the provider ended up holding
// is opaque.
func TestHarnessObjectLifecycle(t *testing.T) {
	fake := installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)
	common := env.common("demo")

	payload := filepath.Join(env.dir, "plain.txt")
	if err := os.WriteFile(payload, []byte("the quick brown fox"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"app/blue/web/config.json", "app/blue/api/config.json", "system/instance.yaml"} {
		if code, _, errOut := env.run(append(append([]string{"put"}, common...), key, payload)...); code != 0 {
			t.Fatalf("put %s = %d: %s", key, code, errOut)
		}
	}

	code, out, errOut := env.run(append([]string{"ls"}, common...)...)
	if code != 0 {
		t.Fatalf("ls = %d: %s", code, errOut)
	}
	want := "app/blue/api/config.json\napp/blue/web/config.json\nsystem/instance.yaml\n"
	if out != want {
		t.Errorf("ls =\n%q\nwant sorted logical names\n%q", out, want)
	}

	code, out, errOut = env.run(append(append([]string{"ls"}, common...), "app/blue/")...)
	if code != 0 {
		t.Fatalf("ls prefix = %d: %s", code, errOut)
	}
	if out != "app/blue/api/config.json\napp/blue/web/config.json\n" {
		t.Errorf("ls app/blue/ =\n%q", out)
	}

	code, out, errOut = env.run(append(append([]string{"get"}, common...), "app/blue/web/config.json", "-")...)
	if code != 0 {
		t.Fatalf("get = %d: %s", code, errOut)
	}
	if out != "the quick brown fox" {
		t.Errorf("get = %q, want the exact plaintext back", out)
	}

	// The claim, checked at the harness boundary rather than assumed from the
	// layer below: nothing the provider is holding resembles what was stored.
	fake.mu.Lock()
	for name, obj := range fake.objects {
		if strings.Contains(name, "config.json") || strings.Contains(name, "app/") {
			t.Errorf("provider holds a recognisable object name %q", name)
		}
		if bytes.Contains(obj.Data, []byte("quick brown fox")) {
			t.Errorf("provider holds the plaintext for %q", name)
		}
	}
	stored := len(fake.objects)
	fake.mu.Unlock()
	if stored != 3 {
		t.Fatalf("provider holds %d objects, want 3", stored)
	}

	if code, _, errOut := env.run(append(append([]string{"rm"}, common...), "app/blue/api/config.json")...); code != 0 {
		t.Fatalf("rm = %d: %s", code, errOut)
	}
	code, out, _ = env.run(append([]string{"ls"}, common...)...)
	if code != 0 || strings.Contains(out, "api/config.json") {
		t.Errorf("after rm, ls =\n%q", out)
	}
}

// TestHarnessLsTokens covers the flag that exists to be believed rather than
// trusted: it prints the stored name beside the logical one.
func TestHarnessLsTokens(t *testing.T) {
	installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)
	common := env.common("demo")

	payload := filepath.Join(env.dir, "plain.txt")
	if err := os.WriteFile(payload, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := env.run(append(append([]string{"put"}, common...), "app/blue/web/config.json", payload)...); code != 0 {
		t.Fatalf("put = %d: %s", code, errOut)
	}

	code, out, errOut := env.run(append(append([]string{"ls"}, common...), "--tokens")...)
	if code != 0 {
		t.Fatalf("ls --tokens = %d: %s", code, errOut)
	}
	line := strings.TrimSuffix(out, "\n")
	storedName, logical, found := strings.Cut(line, "\t")
	if !found {
		t.Fatalf("ls --tokens = %q, want <stored>\\t<logical>", out)
	}
	if logical != "app/blue/web/config.json" {
		t.Errorf("logical column = %q", logical)
	}
	tokens := strings.Split(storedName, "/")
	if len(tokens) != 4 {
		t.Fatalf("stored name %q has %d segments, want one per logical segment", storedName, len(tokens))
	}
	for _, token := range tokens {
		if len(token) != 32 || strings.ContainsAny(token, "ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Errorf("segment %q is not 32 lowercase hex characters", token)
		}
	}
	if strings.Contains(storedName, "config") || strings.Contains(storedName, "app") || strings.Contains(storedName, "blue") {
		t.Errorf("stored name %q leaks part of the logical name", storedName)
	}
}

// TestHarnessRefusesAForeignBucket is the enforcement point in action: the
// composition root validates the recorded ref before a Store exists, so
// tampered local metadata cannot point writes at a stranger's bucket.
func TestHarnessRefusesAForeignBucket(t *testing.T) {
	fake := installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)

	payload := filepath.Join(env.dir, "plain.txt")
	if err := os.WriteFile(payload, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := env.run(append(append([]string{"put"}, env.common("someone-else")...), "k", payload)...)
	if code == 0 {
		t.Fatal("put into a bucket this instance does not own succeeded")
	}
	if !strings.Contains(errOut, "not this instance's") {
		t.Errorf("stderr = %q, want the ownership refusal", errOut)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.objects) != 0 {
		t.Errorf("provider received %d objects despite the refusal", len(fake.objects))
	}
}

// TestHarnessEnsureAndDeleteBucket covers the bucket verbs, including the cost
// line the spec requires the first ensure to print.
func TestHarnessEnsureAndDeleteBucket(t *testing.T) {
	installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)

	code, out, errOut := env.run("ensure-bucket", "--provider", testProviderName, "--project", "p",
		"--location", "test-region", "--instance", "demo", "--bucket", "farcast-demo-0badc0de")
	if code != 0 {
		t.Fatalf("ensure-bucket = %d: %s", code, errOut)
	}
	if !strings.Contains(out, "farcast-demo-0badc0de") || !strings.Contains(out, "cost:") {
		t.Errorf("ensure-bucket output = %q, want the bucket and the price model as a line item", out)
	}

	code, out, errOut = env.run("delete-bucket", "--provider", testProviderName, "--project", "p",
		"--location", "test-region", "--instance", "demo", "--bucket", "farcast-demo-0badc0de")
	if code != 0 {
		t.Fatalf("delete-bucket = %d: %s", code, errOut)
	}
	if !strings.Contains(out, "permanently unreadable") {
		t.Errorf("delete-bucket output = %q, want it to say the data is gone for good", out)
	}
}

// TestHarnessEnsureRefusesAForeignName checks that ErrNotOwned is turned into
// advice. The adapter mints nothing, so the operator is the one who has to pick
// a new name — and they need to be told that, not handed a bare error.
func TestHarnessEnsureRefusesAForeignName(t *testing.T) {
	installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)

	code, _, errOut := env.run("ensure-bucket", "--provider", testProviderName, "--project", "p",
		"--location", "test-region", "--instance", "squatted", "--bucket", "farcast-squatted-0badc0de")
	if code == 0 {
		t.Fatal("ensure-bucket adopted a bucket it does not own")
	}
	if !strings.Contains(errOut, "mint-name") {
		t.Errorf("stderr = %q, want it to tell the operator to mint and record a new name", errOut)
	}
}

// TestHarnessSurfacesForcedRetention pins the cost-pillar behaviour: when the
// cloud is still holding ciphertext the operator ordered destroyed, the command
// succeeds AND says so. Reporting "nothing left billing" while retained copies
// bill for days is the failure this exists to prevent.
func TestHarnessSurfacesForcedRetention(t *testing.T) {
	fake := installFake(t, newHarnessFake("demo"))
	fake.retention = true
	env := newHarnessEnv(t)

	code, out, errOut := env.run("delete-bucket", "--provider", testProviderName, "--project", "p",
		"--location", "test-region", "--instance", "demo", "--bucket", "farcast-demo-0badc0de")
	if code != 0 {
		t.Fatalf("delete-bucket = %d: %s — a retention warning must not fail the teardown", code, errOut)
	}
	if !strings.Contains(errOut, "168h0m0s") || !strings.Contains(errOut, "Warning") {
		t.Errorf("stderr = %q, want a warning naming the retention window", errOut)
	}
	if !strings.Contains(out, "deleted") {
		t.Errorf("stdout = %q, want the teardown still reported as done", out)
	}
}

// TestHarnessValidate covers both probes: credentials only, and credentials
// plus the recorded bucket's ownership.
func TestHarnessValidate(t *testing.T) {
	installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)

	code, out, errOut := env.run("validate", "--provider", testProviderName, "--project", "p", "--location", "test-region")
	if code != 0 || !strings.Contains(out, "credentials OK") {
		t.Fatalf("validate = %d, out %q, err %q", code, out, errOut)
	}

	code, out, errOut = env.run("validate", "--provider", testProviderName, "--project", "p",
		"--location", "test-region", "--instance", "demo", "--bucket", "farcast-demo-0badc0de")
	if code != 0 || !strings.Contains(out, "belongs to") {
		t.Fatalf("validate with a ref = %d, out %q, err %q", code, out, errOut)
	}

	code, _, errOut = env.run("validate", "--provider", testProviderName, "--project", "p",
		"--location", "test-region", "--instance", "someone-else", "--bucket", "farcast-demo-0badc0de")
	if code == 0 {
		t.Fatal("validate accepted a bucket belonging to another instance")
	}
	if !strings.Contains(errOut, "not this instance's") {
		t.Errorf("stderr = %q", errOut)
	}
}

// TestHarnessWarnsAboutALooseKeyring covers the mode check. The package never
// touches the keys file, so its permissions are the caller's responsibility —
// which makes the caller the only place a loose one can be caught.
func TestHarnessWarnsAboutALooseKeyring(t *testing.T) {
	installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)
	if err := os.Chmod(env.keys, 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := env.run(append([]string{"ls"}, env.common("demo")...)...)
	if code != 0 {
		t.Fatalf("ls = %d: %s", code, errOut)
	}
	if !strings.Contains(errOut, "0644") || !strings.Contains(errOut, "Warning") {
		t.Errorf("stderr = %q, want a warning that the keyring is world-readable", errOut)
	}
}

// TestHarnessMissingKeyringCarriesTheWarning: the one error where an operator
// most needs to be told what losing this file means.
func TestHarnessMissingKeyringCarriesTheWarning(t *testing.T) {
	installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)
	if err := os.Remove(env.keys); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := env.run(append([]string{"ls"}, env.common("demo")...)...)
	if code == 0 {
		t.Fatal("ls succeeded with no keyring")
	}
	if !strings.Contains(errOut, datasphere.KeyLossWarning) {
		t.Errorf("stderr = %q, want it to carry the mandated key-loss sentence verbatim", errOut)
	}
}

// TestHarnessRejectsMalformedKeys checks the refusal reaches the operator
// without echoing the key back — an error message is a place a logical name can
// escape to.
func TestHarnessRejectsMalformedKeys(t *testing.T) {
	installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)
	common := env.common("demo")

	code, _, errOut := env.run(append(append([]string{"get"}, common...), "trailing/slash/")...)
	if code == 0 {
		t.Fatal("get accepted a key ending in a slash")
	}
	if !strings.Contains(errOut, "invalid object key") {
		t.Errorf("stderr = %q, want the ErrInvalidKey text", errOut)
	}
	if strings.Contains(errOut, "trailing/slash") {
		t.Errorf("stderr = %q quotes the rejected key back; a logical key is exactly what must not reach a log", errOut)
	}
}

// TestHarnessGetWritesToAFile covers the file operand, including the mode it
// lands under: decrypted plaintext is not something to leave world-readable.
func TestHarnessGetWritesToAFile(t *testing.T) {
	installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)
	common := env.common("demo")

	src := filepath.Join(env.dir, "in.txt")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := env.run(append(append([]string{"put"}, common...), "k", src)...); code != 0 {
		t.Fatalf("put = %d: %s", code, errOut)
	}

	dst := filepath.Join(env.dir, "out.txt")
	if code, _, errOut := env.run(append(append([]string{"get"}, common...), "k", dst)...); code != 0 {
		t.Fatalf("get = %d: %s", code, errOut)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Errorf("file = %q, want the exact plaintext", got)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("decrypted output is mode %04o; it must not be readable by other accounts on this machine", perm)
	}
}

// TestHarnessCorruptKeyringDoesNotPrintKeys closes the loop on the parse-path
// leak at the only place it would actually reach a human.
//
// datasphere.ParseKeyring is where the YAML library's source-echoing error is
// neutralised, but this is the process that would have printed it: loadKeyring
// wraps the parse failure and fail() writes it to stderr, which is terminal
// scrollback, or a shell redirect at umask 0644, or a pasted bug report. The
// provider here validates successfully, so the run reaches the keyring rather
// than dying on credentials first.
func TestHarnessCorruptKeyringDoesNotPrintKeys(t *testing.T) {
	installFake(t, newHarnessFake("demo"))
	env := newHarnessEnv(t)

	sound, err := os.ReadFile(env.keys)
	if err != nil {
		t.Fatal(err)
	}
	// Collect the actual key material before corrupting the file, so the
	// assertion below is against this run's real secrets.
	var secrets []string
	for _, line := range strings.Split(string(sound), "\n") {
		if _, value, found := strings.Cut(strings.TrimSpace(line), "key: "); found {
			secrets = append(secrets, value)
		}
	}
	if len(secrets) != 2 {
		t.Fatalf("found %d key values in the keyring, want 2", len(secrets))
	}

	// A mis-indented hand edit: the smallest realistic corruption.
	corrupt := strings.Replace(string(sound), "\n  key:", "\n   key:", 1)
	if corrupt == string(sound) {
		t.Fatal("failed to corrupt the keyring")
	}
	if err := os.WriteFile(env.keys, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := env.run(append([]string{"ls"}, env.common("demo")...)...)
	if code == 0 {
		t.Fatal("ls succeeded against a corrupt keyring")
	}
	for _, secret := range secrets {
		if strings.Contains(errOut, secret) || strings.Contains(out, secret) {
			t.Errorf("key material reached the harness's output\nstderr: %s", errOut)
		}
	}
	if !strings.Contains(errOut, "invalid keyring") {
		t.Errorf("stderr = %q, want the operator told their keyring is invalid", errOut)
	}
}
