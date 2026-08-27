package datasphere

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// fakeProvider is an in-memory Provider that also keeps every byte it was ever
// handed.
//
// The recording is not debugging scaffolding. This module's central claim is
// that no plaintext byte and no logical name can reach a Provider, and the only
// honest way to test a claim of that shape is to retain the whole input surface
// — every bucket, name, prefix, body, and metadata key and value of every call
// — and search it. See TestProviderNeverSeesPlaintextOrNames.
type fakeProvider struct {
	mu      sync.Mutex
	objects map[string]Object
	order   []string // write order, so List can hand back deliberately unsorted pages

	seen  []string       // every string and []byte argument of every call, verbatim
	calls map[string]int // per-method call counts, for the List fallback assertions
	gets  []string       // names passed to Get, in order

	getErr  map[string]error // per stored name, injected Get failures
	listErr error
	putErr  error
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{
		objects: map[string]Object{},
		calls:   map[string]int{},
		getErr:  map[string]error{},
	}
}

// note records one call's arguments. Callers hold f.mu.
func (f *fakeProvider) note(method string, args ...string) {
	f.calls[method]++
	f.seen = append(f.seen, args...)
}

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) Validate(_ context.Context, ref BucketRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("Validate", ref.Name, ref.Location, ref.Instance)
	return nil
}

func (f *fakeProvider) EnsureBucket(_ context.Context, spec BucketSpec) (*Bucket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	args := []string{spec.Name, spec.Instance, spec.Location}
	for k, v := range spec.Labels {
		args = append(args, k, v)
	}
	f.note("EnsureBucket", args...)
	return &Bucket{Ref: BucketRef{Name: spec.Name, Location: spec.Location, Instance: spec.Instance}}, nil
}

func (f *fakeProvider) DeleteBucket(_ context.Context, ref BucketRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("DeleteBucket", ref.Name, ref.Location, ref.Instance)
	return nil
}

func (f *fakeProvider) Put(_ context.Context, bucket string, obj Object) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	args := []string{bucket, obj.Name, string(obj.Data)}
	for k, v := range obj.Meta {
		args = append(args, k, v)
	}
	f.note("Put", args...)
	if f.putErr != nil {
		return f.putErr
	}
	if _, existing := f.objects[obj.Name]; !existing {
		f.order = append(f.order, obj.Name)
	}
	f.objects[obj.Name] = copyObject(obj)
	return nil
}

func (f *fakeProvider) Get(_ context.Context, bucket, name string) (*Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("Get", bucket, name)
	f.gets = append(f.gets, name)
	if err := f.getErr[name]; err != nil {
		return nil, err
	}
	obj, ok := f.objects[name]
	if !ok {
		// Wrapped rather than returned bare, so the Store's callers are shown
		// to classify with errors.Is rather than equality.
		return nil, fmt.Errorf("fake: no object %q: %w", name, ErrObjectNotFound)
	}
	out := copyObject(obj)
	return &out, nil
}

func (f *fakeProvider) List(_ context.Context, bucket, prefix string) ([]ObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("List", bucket, prefix)
	if f.listErr != nil {
		return nil, f.listErr
	}
	// Reverse write order: a real cloud sorts by the *stored* name, which has
	// no relationship to logical order, so handing back anything that could be
	// mistaken for sorted output would let a missing sort in Store pass.
	var out []ObjectInfo
	for i := len(f.order) - 1; i >= 0; i-- {
		name := f.order[i]
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		obj := f.objects[name]
		out = append(out, ObjectInfo{Name: name, Size: int64(len(obj.Data)), Meta: cloneMeta(obj.Meta)})
	}
	return out, nil
}

func (f *fakeProvider) Delete(_ context.Context, bucket, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("Delete", bucket, name)
	if _, ok := f.objects[name]; ok {
		delete(f.objects, name)
		f.order = slices.DeleteFunc(f.order, func(n string) bool { return n == name })
	}
	return nil
}

func (f *fakeProvider) object(name string) (Object, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[name]
	if !ok {
		return Object{}, false
	}
	return copyObject(obj), true
}

func (f *fakeProvider) setObject(name string, obj Object) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[name]; !ok {
		panic("fake: setObject on an absent object " + name)
	}
	f.objects[name] = copyObject(obj)
}

func (f *fakeProvider) objectCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects)
}

func (f *fakeProvider) callCount(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

func (f *fakeProvider) getNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.gets)
}

func (f *fakeProvider) resetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = map[string]int{}
	f.gets = nil
}

// everything is every argument the provider has ever been handed.
func (f *fakeProvider) everything() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.seen)
}

func copyObject(obj Object) Object {
	return Object{Name: obj.Name, Data: bytes.Clone(obj.Data), Meta: cloneMeta(obj.Meta)}
}

func cloneMeta(meta map[string]string) map[string]string {
	if meta == nil {
		return nil
	}
	out := make(map[string]string, len(meta))
	for k, v := range meta {
		out[k] = v
	}
	return out
}

func newTestStore(t *testing.T) (*Store, *fakeProvider) {
	t.Helper()
	fake := newFakeProvider()
	s, err := NewStore(fake, "farcast-test-bucket", testKeyring(t))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s, fake
}

func mustStoredName(t *testing.T, s *Store, key string) string {
	t.Helper()
	stored, err := s.StoredName(key)
	if err != nil {
		t.Fatalf("StoredName(%q): %v", key, err)
	}
	return stored
}

// ---------------------------------------------------------------------------
// The test this module exists for.
// ---------------------------------------------------------------------------

// TestProviderNeverSeesPlaintextOrNames is the one assertion the whole layering
// is built to make true: Store is the only code in FarCast that holds storage
// plaintext or logical names together with the ability to reach a cloud, so a
// Provider must never be handed either.
//
// It works by writing objects whose plaintext, whose logical key, and whose
// keyring material all carry distinctive markers, driving every Store method,
// and then searching every byte the provider was ever given — object names,
// bodies, metadata keys and values, bucket names, list prefixes — for those
// markers. Each recorded argument is searched both as-is and after being run
// back through the encodings this module puts on the wire, so a marker wrapped
// in base64 (which is exactly how the sealed name travels) cannot slip past on
// an alignment technicality.
func TestProviderNeverSeesPlaintextOrNames(t *testing.T) {
	// Short markers, placed at both ends of every value and at the head of
	// every segment: a leak that truncates — a debug preview, a log line
	// capped at some width — must still trip the scan.
	const (
		plainMarker = "PMK-8f2c41d9"
		nameMarker  = "NMK-6b0e37a5"
	)
	ctx := context.Background()
	s, fake := newTestStore(t)

	key := nameMarker + "/lawsuit-2026/" + nameMarker + ".txt"
	value := []byte(plainMarker + " leading and trailing plaintext " + plainMarker)
	sibling := nameMarker + "/lawsuit-2026/second-" + nameMarker
	siblingValue := []byte(plainMarker)

	if err := s.Write(ctx, key, value); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Write(ctx, sibling, siblingValue); err != nil {
		t.Fatalf("Write sibling: %v", err)
	}
	got, err := s.Read(ctx, key)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("Read = %q, want %q", got, value)
	}
	if _, err := s.List(ctx, nameMarker+"/lawsuit-2026/"); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.List(ctx, nameMarker+"/lawsuit-2026/second-"+nameMarker[:6]); err != nil {
		t.Fatalf("List with a partial-segment prefix: %v", err)
	}
	if err := s.Delete(ctx, sibling); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Guard against a vacuous pass: if the Store had somehow reached no
	// provider method, every search below would trivially succeed.
	for _, method := range []string{"Put", "Get", "List", "Delete"} {
		if fake.callCount(method) == 0 {
			t.Fatalf("the provider was never asked to %s; the scan below would prove nothing", method)
		}
	}
	seen := fake.everything()
	if len(seen) == 0 {
		t.Fatal("the provider recorded no arguments")
	}

	// Everything that must never reach a cloud: the plaintext, the logical
	// names, and — since the fake sees the blob bodies — the key material that
	// sealed them.
	var forbidden []string
	for _, secret := range []string{
		plainMarker, nameMarker, string(value), string(siblingValue), key, sibling,
		testNameKeyMaterial, testKEKMaterial,
	} {
		forbidden = append(forbidden, secretForms([]byte(secret))...)
	}
	scanForLeaks(t, seen, forbidden)

	// And the positive half: what the provider *does* hold is a path of
	// tokens. Stating the shape catches a regression that stopped leaking
	// markers by accident rather than by tokenizing.
	stored := mustStoredName(t, s, key)
	tokens := strings.Split(stored, "/")
	if want := len(strings.Split(key, "/")); len(tokens) != want {
		t.Errorf("stored name %q has %d segments, want %d", stored, len(tokens), want)
	}
	for _, tok := range tokens {
		if len(tok) != 2*crypto.TokenBytes {
			t.Errorf("stored token %q is %d characters, want %d", tok, len(tok), 2*crypto.TokenBytes)
		}
		if _, err := hex.DecodeString(tok); err != nil {
			t.Errorf("stored token %q is not lowercase hex: %v", tok, err)
		}
		if strings.ToLower(tok) != tok {
			t.Errorf("stored token %q is not lowercase", tok)
		}
	}
}

// scanForLeaks fails the test if any forbidden value appears in anything the
// provider was handed — as-is, or under any encoding this module uses.
func scanForLeaks(t *testing.T, seen, forbidden []string) {
	t.Helper()
	for i, arg := range seen {
		candidates := append([]string{arg}, decodings(arg)...)
		for _, candidate := range candidates {
			for _, secret := range forbidden {
				if secret == "" || !strings.Contains(candidate, secret) {
					continue
				}
				t.Errorf("provider argument %d leaked %q (argument begins %q)", i, secret, truncate(arg, 64))
			}
		}
	}
}

// decodings runs arg back through the encodings a leak could hide behind. The
// sealed name genuinely travels as base64 in the metadata map, so decoding
// before searching is what makes the scan a claim about the plaintext rather
// than about one particular framing of it.
func decodings(arg string) []string {
	var out []string
	for _, decode := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if raw, err := decode(arg); err == nil && len(raw) > 0 {
			out = append(out, string(raw))
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// Round trips.
// ---------------------------------------------------------------------------

func TestStoreWriteReadRoundTrip(t *testing.T) {
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}

	tests := []struct {
		name  string
		key   string
		value []byte
	}{
		{"single segment", "readme", []byte("hello")},
		{"nested key", "system/config/app.yaml", []byte("nested")},
		{"deepest legal key", strings.TrimSuffix(strings.Repeat("s/", crypto.MaxKeySegments), "/"), []byte("deep")},
		{"longest legal key", strings.Repeat("k", crypto.MaxKeyBytes), []byte("long")},
		// A key the Store must not normalize: "café" written decomposed stays
		// decomposed, because the key's exact bytes are the data seal's AAD.
		{"decomposed unicode key", "users/café/☕/naïve", []byte("no normalization, ever")},
		{"empty value", "system/empty", []byte{}},
		{"nil value", "system/nil", nil},
		{"every byte value", "system/binary", allBytes},
		{"64 KiB", "system/large", bytes.Repeat([]byte("farcast"), 9363)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, fake := newTestStore(t)

			if err := s.Write(ctx, tc.key, tc.value); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if got := fake.objectCount(); got != 1 {
				t.Fatalf("provider holds %d objects after one Write, want 1", got)
			}
			got, err := s.Read(ctx, tc.key)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if !bytes.Equal(got, tc.value) {
				t.Errorf("Read = %q (%d bytes), want %q (%d bytes)", got, len(got), tc.value, len(tc.value))
			}

			// A zero-byte object is a real object: it lists, and it is a full
			// blob on the wire rather than nothing at all.
			names, err := s.List(ctx, "")
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if !slices.Equal(names, []string{tc.key}) {
				t.Errorf("List = %q, want [%q]", names, tc.key)
			}
			obj, ok := fake.object(mustStoredName(t, s, tc.key))
			if !ok {
				t.Fatal("the provider holds no object under the stored name")
			}
			if len(obj.Data) <= crypto.HeaderLen {
				t.Errorf("stored blob is %d bytes, want more than the %d-byte header", len(obj.Data), crypto.HeaderLen)
			}
			if obj.Meta[MetaName] == "" {
				t.Errorf("stored object carries no %q metadata mirror", MetaName)
			}
		})
	}
}

// TestStoreWriteIsAnUpsert pins Write's documented semantics: writing an
// existing key replaces it rather than erroring or accumulating versions.
func TestStoreWriteIsAnUpsert(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)
	const key = "system/config"

	if err := s.Write(ctx, key, []byte("first")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	stored := mustStoredName(t, s, key)
	first, _ := fake.object(stored)

	if err := s.Write(ctx, key, []byte("second")); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if got := fake.objectCount(); got != 1 {
		t.Errorf("provider holds %d objects after an overwrite, want 1", got)
	}
	got, err := s.Read(ctx, key)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("Read = %q, want the second write", got)
	}

	// Rewriting the same key under the same value must still produce different
	// bytes: every write mints a fresh single-use DEK and fresh nonces, which
	// is what makes the data seal's nonce budget a non-question.
	if err := s.Write(ctx, key, []byte("first")); err != nil {
		t.Fatalf("third Write: %v", err)
	}
	third, _ := fake.object(stored)
	if bytes.Equal(first.Data, third.Data) {
		t.Error("re-writing the same value produced identical ciphertext; the DEK or the nonces were reused")
	}
}

func TestStoreReadAbsentKey(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)

	if _, err := s.Read(ctx, "system/never-written"); !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("Read of an absent key error = %v, want ErrObjectNotFound", err)
	}
}

func TestStoreDeleteAbsentKeyIsNotAnError(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)

	if err := s.Delete(ctx, "system/never-written"); err != nil {
		t.Errorf("Delete of an absent key = %v, want nil", err)
	}
	// Twice, because idempotence is the property callers rely on, not luck.
	if err := s.Delete(ctx, "system/never-written"); err != nil {
		t.Errorf("second Delete of an absent key = %v, want nil", err)
	}
	if got := fake.callCount("Delete"); got != 2 {
		t.Errorf("provider saw %d Delete calls, want 2", got)
	}
}

func TestStoreDeleteRemovesTheObject(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)
	const key = "system/doomed"

	if err := s.Write(ctx, key, []byte("data")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := fake.objectCount(); got != 0 {
		t.Errorf("provider holds %d objects after Delete, want 0", got)
	}
	if _, err := s.Read(ctx, key); !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("Read after Delete error = %v, want ErrObjectNotFound", err)
	}
}

// TestStoredNameSharesPrefixesAndNothingElse pins the property Store.List is
// built on — equal logical path prefixes yield equal stored prefixes — and its
// limit: chaining means an equal segment under a different parent does not
// correlate.
func TestStoredNameSharesPrefixesAndNothingElse(t *testing.T) {
	s, _ := newTestStore(t)
	alice := strings.Split(mustStoredName(t, s, "users/alice"), "/")
	bob := strings.Split(mustStoredName(t, s, "users/bob"), "/")
	otherAlice := strings.Split(mustStoredName(t, s, "admins/alice"), "/")

	if alice[0] != bob[0] {
		t.Error("keys under the same parent do not share a stored prefix; cloud-side prefix listing cannot work")
	}
	if alice[1] == bob[1] {
		t.Error("different leaf names tokenized identically")
	}
	if alice[1] == otherAlice[1] {
		t.Error("the same leaf name under different parents tokenized identically; tokens are not chained")
	}
	if alice[0] == otherAlice[0] {
		t.Error("different parents tokenized identically")
	}
}

// ---------------------------------------------------------------------------
// List.
// ---------------------------------------------------------------------------

var listCorpus = []string{
	"orders/2026/january",
	"readme",
	"users/alan",
	"users/alice",
	"users/bob",
}

func writeListCorpus(t *testing.T, s *Store, fake *fakeProvider) {
	t.Helper()
	ctx := context.Background()
	for _, key := range listCorpus {
		if err := s.Write(ctx, key, []byte("value of "+key)); err != nil {
			t.Fatalf("Write(%q): %v", key, err)
		}
	}
	if got := fake.objectCount(); got != len(listCorpus) {
		t.Fatalf("provider holds %d objects, want %d", got, len(listCorpus))
	}
}

func TestStoreList(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   []string
	}{
		{"everything", "", listCorpus},
		{"aligned prefix", "users/", []string{"users/alan", "users/alice", "users/bob"}},
		// The case the spec calls out by name: a prefix that stops mid-segment
		// is honoured exactly, by over-listing one segment cloud-side and
		// filtering on the recovered logical names here.
		{"partial segment", "users/al", []string{"users/alan", "users/alice"}},
		{"partial first segment", "user", []string{"users/alan", "users/alice", "users/bob"}},
		{"exact key", "users/alice", []string{"users/alice"}},
		{"deeper aligned prefix", "orders/2026/", []string{"orders/2026/january"}},
		{"matches nothing within an existing parent", "users/z", nil},
		{"matches no parent at all", "nowhere/", nil},
		{"matches nothing at the root", "zzz", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, fake := newTestStore(t)
			writeListCorpus(t, s, fake)

			got, err := s.List(ctx, tc.prefix)
			if err != nil {
				t.Fatalf("List(%q): %v", tc.prefix, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("List(%q) = %q, want %q", tc.prefix, got, tc.want)
			}
			if !slices.IsSorted(got) {
				t.Errorf("List(%q) = %q, want sorted output", tc.prefix, got)
			}
		})
	}
}

// TestStoreListNarrowsCloudSideByToken checks the other half of List: the
// prefix handed to the provider is the tokenized aligned portion, never the
// logical prefix, and it really does narrow the page.
func TestStoreListNarrowsCloudSideByToken(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)
	writeListCorpus(t, s, fake)

	fake.resetCalls()
	if _, err := s.List(ctx, "users/al"); err != nil {
		t.Fatalf("List: %v", err)
	}
	seen := fake.everything()
	prefix := seen[len(seen)-1] // List records (bucket, prefix) last
	want := mustStoredName(t, s, "users") + "/"
	if prefix != want {
		t.Errorf("provider was asked to list under %q, want the tokenized parent %q", prefix, want)
	}

	// An empty logical prefix cannot be narrowed at all, so the whole bucket
	// is listed and the filtering happens here.
	fake.resetCalls()
	if _, err := s.List(ctx, ""); err != nil {
		t.Fatalf("List(\"\"): %v", err)
	}
	seen = fake.everything()
	if got := seen[len(seen)-1]; got != "" {
		t.Errorf("provider was asked to list under %q for the empty prefix, want the whole bucket", got)
	}
}

func TestStoreListPropagatesProviderErrors(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)
	sentinel := errors.New("the cloud said no")
	fake.listErr = sentinel

	names, err := s.List(ctx, "")
	if !errors.Is(err, sentinel) {
		t.Errorf("List error = %v, want the provider's error", err)
	}
	if names != nil {
		t.Errorf("List = %q alongside its error, want nothing", names)
	}
}

// ---------------------------------------------------------------------------
// List's degraded paths.
// ---------------------------------------------------------------------------

// TestStoreListFallsBackToTheHeader covers the mirror going bad in every way it
// can. The metadata copy is a cache; the blob header is the authority. A cloud
// that loses, mangles, or shuffles metadata makes List slower and must never
// make it wrong, so each case asserts both the right answer AND that the
// fallback fetch actually happened — an assertion on the answer alone would
// pass if the mirror had silently kept working.
func TestStoreListFallsBackToTheHeader(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(t *testing.T, s *Store, fake *fakeProvider, victim string)
	}{
		{"mirror missing", func(_ *testing.T, _ *Store, fake *fakeProvider, victim string) {
			obj, _ := fake.object(victim)
			obj.Meta = nil
			fake.setObject(victim, obj)
		}},
		{"mirror empty", func(_ *testing.T, _ *Store, fake *fakeProvider, victim string) {
			obj, _ := fake.object(victim)
			obj.Meta[MetaName] = ""
			fake.setObject(victim, obj)
		}},
		{"mirror is not base64", func(_ *testing.T, _ *Store, fake *fakeProvider, victim string) {
			obj, _ := fake.object(victim)
			obj.Meta[MetaName] = "not base64 at all !!"
			fake.setObject(victim, obj)
		}},
		{"mirror does not authenticate", func(_ *testing.T, _ *Store, fake *fakeProvider, victim string) {
			obj, _ := fake.object(victim)
			sealed, err := base64.StdEncoding.DecodeString(obj.Meta[MetaName])
			if err != nil {
				panic(err)
			}
			sealed[len(sealed)-1] ^= 0x01 // one bit of the tag
			obj.Meta[MetaName] = base64.StdEncoding.EncodeToString(sealed)
			fake.setObject(victim, obj)
		}},
		{"mirror transplanted from another object", func(t *testing.T, s *Store, fake *fakeProvider, victim string) {
			donor, _ := fake.object(mustStoredName(t, s, "users/bob"))
			obj, _ := fake.object(victim)
			obj.Meta[MetaName] = donor.Meta[MetaName]
			fake.setObject(victim, obj)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, fake := newTestStore(t)
			writeListCorpus(t, s, fake)

			victim := mustStoredName(t, s, "users/alan")
			tc.corrupt(t, s, fake, victim)

			fake.resetCalls()
			got, err := s.List(ctx, "users/")
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			want := []string{"users/alan", "users/alice", "users/bob"}
			if !slices.Equal(got, want) {
				t.Errorf("List = %q, want %q", got, want)
			}
			// Exactly one fetch, for exactly the broken object: proof the
			// answer came from the header and not from a mirror that quietly
			// still worked, and that the fallback is per-object rather than a
			// wholesale re-fetch of the page.
			if gets := fake.getNames(); !slices.Equal(gets, []string{victim}) {
				t.Errorf("provider Gets = %q, want exactly one fallback fetch of %q", gets, victim)
			}
		})
	}
}

// TestStoreListReportsWhatItCannotRecover is the loud-and-available half: an
// object whose mirror AND header both fail is named in a joined error while
// every name that did resolve is still returned. Suppressing the failure would
// hide the cloud's misbehaviour; failing the whole call would let one bad
// object deny the operator their listing.
func TestStoreListReportsWhatItCannotRecover(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)
	writeListCorpus(t, s, fake)

	victim := mustStoredName(t, s, "users/alan")
	obj, _ := fake.object(victim)
	obj.Meta[MetaName] = base64.StdEncoding.EncodeToString(make([]byte, 64))
	obj.Data[0] ^= 0xff // the magic: the header no longer parses either
	fake.setObject(victim, obj)

	got, err := s.List(ctx, "users/")

	// Both halves, asserted together, because either one alone is a different
	// (and wrong) contract.
	want := []string{"users/alice", "users/bob"}
	if !slices.Equal(got, want) {
		t.Errorf("List = %q, want the names that did resolve %q", got, want)
	}
	if err == nil {
		t.Fatal("List returned no error for an object whose name could not be recovered")
	}
	if !strings.Contains(err.Error(), victim) {
		t.Errorf("error = %v, want it to name the stored object %q", err, victim)
	}
	if !errors.Is(err, ErrIntegrity) {
		t.Errorf("error = %v, want it to classify as ErrIntegrity", err)
	}
	// The error names the stored token, never the logical name — the module
	// does not undo its own privacy in a diagnostic.
	for _, secret := range append(secretForms([]byte("users/alan")), secretForms([]byte("alan"))...) {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %v leaked the logical name as %q", err, secret)
		}
	}
}

func TestStoreListReportsAnUnfetchableObject(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)
	writeListCorpus(t, s, fake)

	victim := mustStoredName(t, s, "users/alan")
	obj, _ := fake.object(victim)
	obj.Meta = nil
	fake.setObject(victim, obj)
	fake.getErr[victim] = errors.New("503 after retries")

	got, err := s.List(ctx, "users/")
	want := []string{"users/alice", "users/bob"}
	if !slices.Equal(got, want) {
		t.Errorf("List = %q, want %q", got, want)
	}
	if err == nil || !strings.Contains(err.Error(), "503 after retries") {
		t.Errorf("error = %v, want it to carry the provider's failure", err)
	}
}

// ---------------------------------------------------------------------------
// Key validation and construction.
// ---------------------------------------------------------------------------

func TestStoreRejectsMalformedKeys(t *testing.T) {
	overSegments := strings.TrimSuffix(strings.Repeat("s/", crypto.MaxKeySegments+1), "/")

	keys := []struct{ name, key string }{
		{"empty", ""},
		{"trailing slash", "users/alice/"},
		{"only a slash", "/"},
		{"empty middle segment", "users//alice"},
		{"empty leading segment", "/users/alice"},
		{"over the byte cap", strings.Repeat("k", crypto.MaxKeyBytes+1)},
		{"over the segment cap", overSegments},
		{"invalid utf-8", "users/\xff\xfe"},
	}
	methods := []struct {
		name string
		call func(s *Store, key string) error
	}{
		{"Read", func(s *Store, key string) error { _, err := s.Read(context.Background(), key); return err }},
		{"Write", func(s *Store, key string) error { return s.Write(context.Background(), key, []byte("x")) }},
		{"Delete", func(s *Store, key string) error { return s.Delete(context.Background(), key) }},
		{"StoredName", func(s *Store, key string) error { _, err := s.StoredName(key); return err }},
	}

	for _, k := range keys {
		for _, m := range methods {
			t.Run(m.name+"/"+k.name, func(t *testing.T) {
				s, fake := newTestStore(t)
				if err := m.call(s, k.key); !errors.Is(err, ErrInvalidKey) {
					t.Errorf("%s error = %v, want ErrInvalidKey", m.name, err)
				}
				// A key that never validated must never have reached a cloud:
				// the refusal happens above the provider, not at it.
				if seen := fake.everything(); len(seen) != 0 {
					t.Errorf("%s reached the provider with %q despite a malformed key", m.name, seen)
				}
			})
		}
	}
}

// TestStoreRejectionsDoNotQuoteTheKey pins the reason ValidateLogicalKey names
// the rule and never the key: the key is the metadata this module exists to
// keep out of logs, and an error is a log line waiting to happen.
func TestStoreRejectionsDoNotQuoteTheKey(t *testing.T) {
	const marker = "SENSITIVE-KEY-MARKER-4a71"
	s, _ := newTestStore(t)

	for _, key := range []string{"users/" + marker + "/", "users//" + marker} {
		_, err := s.StoredName(key)
		if err == nil {
			t.Fatalf("StoredName(%q) unexpectedly succeeded", key)
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("error %v quoted the rejected key", err)
		}
	}
}

func TestNewStoreRejectsBadArguments(t *testing.T) {
	valid := testKeyring(t)

	tests := []struct {
		name     string
		provider Provider
		bucket   string
		keys     Keyring
		wantIs   error
	}{
		{"nil provider", nil, "farcast-test-bucket", valid, nil},
		{"empty bucket", newFakeProvider(), "", valid, nil},
		{"zero keyring", newFakeProvider(), "farcast-test-bucket", Keyring{}, ErrKeyringInvalid},
		{"no name keys", newFakeProvider(), "farcast-test-bucket",
			Keyring{keys: []KeyEntry{testEntry(t, "1112131415161718", testKEKMaterial)}}, ErrKeyringInvalid},
		{"no keys", newFakeProvider(), "farcast-test-bucket",
			Keyring{nameKeys: []KeyEntry{testEntry(t, "0102030405060708", testNameKeyMaterial)}}, ErrKeyringInvalid},
		{"short key material", newFakeProvider(), "farcast-test-bucket",
			Keyring{
				nameKeys: []KeyEntry{{ID: valid.NameKeys()[0].ID, key: []byte("too short")}},
				keys:     []KeyEntry{valid.KEKs()[0]},
			}, ErrKeyringInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewStore(tc.provider, tc.bucket, tc.keys)
			if err == nil {
				t.Fatal("NewStore accepted an unusable configuration")
			}
			if s != nil {
				t.Error("NewStore returned a Store alongside its error")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("error = %v, want %v", err, tc.wantIs)
			}
		})
	}
}

func TestNewStoreKeepsItsBucket(t *testing.T) {
	s, _ := newTestStore(t)
	if got := s.Bucket(); got != "farcast-test-bucket" {
		t.Errorf("Bucket() = %q, want the bucket it was constructed with", got)
	}
}

// TestStoreRejectsOversizedPlaintext pins the 64 MiB cap as a Store-level
// refusal: the API holds whole objects in memory, and streaming is a v2 format
// behind the version byte rather than a quiet relaxation of this.
func TestStoreRejectsOversizedPlaintext(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)

	if err := s.Write(ctx, "system/huge", make([]byte, crypto.MaxPlaintext+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Write error = %v, want ErrTooLarge", err)
	}
	if got := fake.callCount("Put"); got != 0 {
		t.Errorf("provider saw %d Put calls for an oversized object, want 0", got)
	}
}
