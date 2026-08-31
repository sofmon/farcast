package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/storage"
)

// reproProvider is an in-memory object store shared by the operator's Store and
// the keyholder's, exactly as one bucket is shared in a real instance.
type reproProvider struct {
	mu      sync.Mutex
	objects map[string]datasphere.Object
}

func newReproProvider() *reproProvider {
	return &reproProvider{objects: map[string]datasphere.Object{}}
}

func (p *reproProvider) Name() string                                             { return "repro" }
func (p *reproProvider) Validate(context.Context, datasphere.BucketRef) error     { return nil }
func (p *reproProvider) DeleteBucket(context.Context, datasphere.BucketRef) error { return nil }

func (p *reproProvider) EnsureBucket(_ context.Context, spec datasphere.BucketSpec) (*datasphere.Bucket, error) {
	return &datasphere.Bucket{Ref: datasphere.BucketRef{Name: spec.Name}}, nil
}

func (p *reproProvider) Put(_ context.Context, _ string, obj datasphere.Object) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.objects[obj.Name] = datasphere.Object{Name: obj.Name, Data: append([]byte(nil), obj.Data...), Meta: obj.Meta}
	return nil
}

func (p *reproProvider) Get(_ context.Context, _, name string) (*datasphere.Object, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	obj, ok := p.objects[name]
	if !ok {
		return nil, datasphere.ErrObjectNotFound
	}
	out := datasphere.Object{Name: obj.Name, Data: append([]byte(nil), obj.Data...), Meta: obj.Meta}
	return &out, nil
}

func (p *reproProvider) List(_ context.Context, _, prefix string) ([]datasphere.ObjectInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []datasphere.ObjectInfo
	for name, obj := range p.objects {
		if strings.HasPrefix(name, prefix) {
			out = append(out, datasphere.ObjectInfo{
				Name: name, Size: int64(len(obj.Data)), Created: time.Unix(0, 0).UTC(), Meta: obj.Meta,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (p *reproProvider) Delete(_ context.Context, _, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.objects, name)
	return nil
}

func (p *reproProvider) PutStream(ctx context.Context, bucket string, obj datasphere.StreamObject) error {
	data, err := io.ReadAll(obj.Data)
	if err != nil {
		return err
	}
	return p.Put(ctx, bucket, datasphere.Object{Name: obj.Name, Data: data, Meta: obj.Meta})
}

func (p *reproProvider) GetStream(ctx context.Context, bucket, name string, offset, length int64) (io.ReadCloser, error) {
	obj, err := p.Get(ctx, bucket, name)
	if err != nil {
		return nil, err
	}
	data := obj.Data[offset:]
	if length >= 0 && length < int64(len(data)) {
		data = data[:length]
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// The exact sequence the 2026-08-31 live run performed, end to end, with the
// keyring REWRITTEN mid-sequence and the bundle round-tripped through its wire
// form — the two things none of the other tests do together.
//
// This is the reproduction for the open criterion 5: after an application
// writes through the keyholder, the operator's own CLI must be able to list and
// read that object from a keys.yaml it loads fresh from disk.
// reproSession builds the exact state the 2026-08-31 live run reached: an
// instance whose keyring was rewritten mid-sequence to carry a scope, an
// object written outside every scope by the operator, and one written inside
// the scope by the keyholder from a bundle that crossed its wire form.
func reproSession(t *testing.T) (*storage.Session, *reproProvider, config.Dir) {
	t.Helper()
	ctx := context.Background()

	dir := config.Dir(t.TempDir())
	if err := os.Chmod(string(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	const name = "p32"
	if err := dir.CreateInstance(name); err != nil {
		t.Fatal(err)
	}

	provider := newReproProvider()
	providerName := "ds-repro-" + strings.ReplaceAll(t.Name(), "/", "-")
	datasphere.Register(providerName, func(datasphere.Config) (datasphere.Provider, error) { return provider, nil })

	meta := &config.InstanceMetadata{
		Name: name, Provider: "gke", Region: "us-central1", Status: "running",
		FatLineDeployed: true,
		Storage: &config.Storage{
			Bucket: "farcast-p32-0a1b2c3d", Provider: providerName, Location: "us-central1",
			RecordedAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
		},
		Keyholder: &config.Keyholder{Deployed: true, Replicas: 2},
	}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceCredentials(name, &config.InstanceCredentials{Provider: "gke"}); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(dir, output.ModeHuman)

	// 1. The operator's first storage use mints a master-only keyring (v1) and
	//    writes an object outside every scope.
	master, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := master.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstanceKeyring(name, encoded); err != nil {
		t.Fatal(err)
	}
	masterStore, err := datasphere.NewStore(provider, meta.Storage.Bucket, master)
	if err != nil {
		t.Fatal(err)
	}
	if err := masterStore.Write(ctx, "system/operator.txt", []byte("operator data")); err != nil {
		t.Fatal(err)
	}

	// 2. `storage unseal` mints the scope and REWRITES keys.yaml to v2.
	loaded, err := dir.LoadInstanceKeyring(name)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := datasphere.ParseKeyring(loaded)
	if err != nil {
		t.Fatal(err)
	}
	scope, generation, err := ensureScope(env, name, meta, keys)
	if err != nil {
		t.Fatalf("ensureScope: %v", err)
	}

	// 3. The bundle crosses the wire and is installed in a real vault.
	bundle, err := datasphere.NewBundle(name, generation, []datasphere.Scope{scope})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := bundle.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := datasphere.ParseBundle(wire)
	if err != nil {
		t.Fatal(err)
	}
	vault := dskeyholder.New(name)
	if err := vault.Unseal(delivered, dskeyholder.IntentOperator); err != nil {
		t.Fatalf("vault.Unseal: %v", err)
	}

	// 4. An application writes through the keyholder's scoped Store.
	held, err := vault.Scope("app/sdk-written")
	if err != nil {
		t.Fatalf("vault.Scope: %v", err)
	}
	keyholderStore, err := datasphere.NewStore(provider, meta.Storage.Bucket, held.Keyring())
	if err != nil {
		t.Fatal(err)
	}
	if err := keyholderStore.Write(ctx, "app/sdk-written", []byte("written by the application")); err != nil {
		t.Fatal(err)
	}

	// 5. The operator's CLI, loading keys.yaml FRESH FROM DISK, must see it.
	session, err := openSession(ctx, env, name, false)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	return session, provider, dir

}

func TestScopedObjectIsVisibleToTheOperatorCLI(t *testing.T) {
	session, _, _ := reproSession(t)
	ctx := context.Background()

	t.Run("ls of the scope prefix finds it", func(t *testing.T) {
		entries, _, err := listAcrossScopes(ctx, session, "app/")
		if err != nil {
			t.Errorf("listing reported: %v", err)
		}
		if len(entries) != 1 || entries[0].Key != "app/sdk-written" {
			t.Fatalf("ls app/ = %v, want [app/sdk-written]", keysOf(entries))
		}
	})

	t.Run("ls of the root spans both key spaces", func(t *testing.T) {
		entries, _, _ := listAcrossScopes(ctx, session, "")
		got := keysOf(entries)
		for _, want := range []string{"app/sdk-written", "system/operator.txt"} {
			if !contains(got, want) {
				t.Errorf("root listing is missing %q: %v", want, got)
			}
		}
	})

	t.Run("the object reads back byte-exact", func(t *testing.T) {
		store, err := session.StoreFor("app/sdk-written")
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.Read(ctx, "app/sdk-written")
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != "written by the application" {
			t.Errorf("read %q", got)
		}
	})

	t.Run("the operator's own object still reads", func(t *testing.T) {
		store, err := session.StoreFor("system/operator.txt")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := store.Read(ctx, "system/operator.txt"); err != nil || string(got) != "operator data" {
			t.Errorf("read %q, %v", got, err)
		}
	})
}

func keysOf(entries []datasphere.Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Key
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// --explain is the diagnostic the first live run lacked. An empty listing is
// unreadable without it: nothing distinguished "the prefix holds nothing" from
// "this keyring tokenizes it somewhere nothing was written", which is exactly
// what a scope mismatch looks like from outside.
func TestExplainReportsWhatEachKeySpaceQueried(t *testing.T) {
	ctx := context.Background()
	session, _, _ := reproSession(t)

	_, reports, err := listAcrossScopes(ctx, session, "app/")
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("listing %q consulted %d key spaces, want only the scope's", "app/", len(reports))
	}
	r := reports[0]
	if r.Space != "app" {
		t.Errorf("space = %q, want the scope", r.Space)
	}
	if r.Queried == "" {
		t.Error("the queried prefix is empty; the diagnostic reports nothing actionable")
	}
	if r.Objects != 1 || r.Recovered != 1 {
		t.Errorf("objects=%d recovered=%d, want 1/1", r.Objects, r.Recovered)
	}

	// The root spans both, and each reports a DIFFERENT queried prefix —
	// which is the fact that identifies a mismatched keyring.
	_, rootReports, _ := listAcrossScopes(ctx, session, "")
	if len(rootReports) != 2 {
		t.Fatalf("root listing consulted %d key spaces, want 2", len(rootReports))
	}
	seen := map[string]bool{}
	for _, rr := range rootReports {
		seen[rr.Space] = true
	}
	if !seen["master"] || !seen["app"] {
		t.Errorf("root listing did not name both key spaces: %v", seen)
	}
}
