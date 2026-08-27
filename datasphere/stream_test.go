package datasphere

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// frameSize is the plaintext one v2 frame carries at the framing WriteStream
// picks. Every size in this file is expressed against it, because the
// interesting boundaries of a chunked format are all frame boundaries.
const frameSize = 1 << crypto.DefaultChunkExp

// ---------------------------------------------------------------------------
// Test scaffolding.
//
// The recording fakeProvider in store_test.go already implements the streaming
// pair, and everything below reuses it. Two properties under test here are
// invisible to a fake that records call arguments as strings, though: the byte
// RANGE a GetStream asked for, and the creation timestamp a real cloud stamps
// on every object. observedProvider decorates the fake with those two rather
// than changing a fake the rest of the package depends on.
// ---------------------------------------------------------------------------

type observedProvider struct {
	*fakeProvider

	// guard is deliberately not named mu: shadowing the embedded fake's mutex
	// would make every lock in this file ambiguous to a reader.
	guard   sync.Mutex
	reads   []rangeRead
	created map[string]time.Time
}

// rangeRead is one GetStream: what was asked for, and what the caller went on
// to consume. The requested range proves intent; the delivered count proves the
// intent survived contact with the reader.
type rangeRead struct {
	name      string
	offset    int64
	length    int64
	delivered int64
}

func newObservedProvider() *observedProvider {
	return &observedProvider{fakeProvider: newFakeProvider(), created: map[string]time.Time{}}
}

func newObservedStore(t *testing.T) (*Store, *observedProvider) {
	t.Helper()
	p := newObservedProvider()
	s, err := NewStore(p, "farcast-test-bucket", testKeyring(t))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s, p
}

func (o *observedProvider) GetStream(ctx context.Context, bucket, name string, offset, length int64) (io.ReadCloser, error) {
	body, err := o.fakeProvider.GetStream(ctx, bucket, name, offset, length)
	if err != nil {
		return nil, err
	}
	o.guard.Lock()
	o.reads = append(o.reads, rangeRead{name: name, offset: offset, length: length})
	index := len(o.reads) - 1
	o.guard.Unlock()
	return &countingBody{ReadCloser: body, owner: o, index: index}, nil
}

// List stamps each entry with the creation time a cloud would report. A
// provider that reports none leaves it zero, which is the case the fake alone
// already covers.
func (o *observedProvider) List(ctx context.Context, bucket, prefix string) ([]ObjectInfo, error) {
	infos, err := o.fakeProvider.List(ctx, bucket, prefix)
	o.guard.Lock()
	defer o.guard.Unlock()
	for i := range infos {
		infos[i].Created = o.created[infos[i].Name]
	}
	return infos, err
}

func (o *observedProvider) stamp(name string, created time.Time) {
	o.guard.Lock()
	defer o.guard.Unlock()
	o.created[name] = created
}

func (o *observedProvider) rangedReads() []rangeRead {
	o.guard.Lock()
	defer o.guard.Unlock()
	return slices.Clone(o.reads)
}

type countingBody struct {
	io.ReadCloser
	owner *observedProvider
	index int
}

func (c *countingBody) Read(b []byte) (int, error) {
	n, err := c.ReadCloser.Read(b)
	c.owner.guard.Lock()
	c.owner.reads[c.index].delivered += int64(n)
	c.owner.guard.Unlock()
	return n, err
}

// patternByte is a deterministic filler whose period is 16 MiB — longer than
// any object this file round-trips — so a frame that is dropped, duplicated, or
// delivered out of order changes the output instead of blending into it.
func patternByte(i int64) byte { return byte(i) ^ byte(i>>8) ^ byte(i>>16) }

func patternBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = patternByte(int64(i))
	}
	return out
}

// patternReader yields the same bytes without materializing them, so a test can
// cross the 64 MiB buffered cap without a 64 MiB source buffer sitting beside
// the 64 MiB blob it produces.
type patternReader struct {
	at        int64
	remaining int64
}

func (p *patternReader) Read(b []byte) (int, error) {
	if p.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(b)) > p.remaining {
		b = b[:p.remaining]
	}
	for i := range b {
		b[i] = patternByte(p.at + int64(i))
	}
	p.at += int64(len(b))
	p.remaining -= int64(len(b))
	return len(b), nil
}

// refusingReader fails the test if anything reads from it.
type refusingReader struct{ t *testing.T }

func (r refusingReader) Read([]byte) (int, error) {
	r.t.Helper()
	r.t.Error("the caller's plaintext was read despite the key being refused")
	return 0, io.EOF
}

// assertStreamBlob checks that what the provider holds is a v2 blob of exactly
// the length its framing implies.
//
// The length is derived from the object's size and never stored, so checking it
// here pins the frame count the format's self-termination depends on: every
// frame but the last carries a full P bytes and the last carries strictly
// fewer, which is why a plaintext that is an exact multiple of P ends in a
// zero-plaintext frame.
func assertStreamBlob(t *testing.T, blob []byte, plaintextLen int) {
	t.Helper()
	if len(blob) < crypto.HeaderLen {
		t.Fatalf("stored blob is %d bytes, shorter than the %d-byte header", len(blob), crypto.HeaderLen)
	}
	if got := string(blob[:4]); got != "FCDS" {
		t.Errorf("stored blob magic = %q, want %q", got, "FCDS")
	}
	if blob[4] != crypto.Version2 {
		t.Fatalf("stored blob version = %#x, want the chunked format %#x", blob[4], crypto.Version2)
	}
	nameLen := int(binary.BigEndian.Uint16(blob[crypto.HeaderLen-2 : crypto.HeaderLen]))
	frames := plaintextLen/frameSize + 1
	want := crypto.HeaderLen + nameLen + crypto.SaltLen + 1 + plaintextLen + frames*crypto.TagLen
	if len(blob) != want {
		t.Errorf("stored blob is %d bytes, want %d (%d frames of a %d-byte plaintext)",
			len(blob), want, frames, plaintextLen)
	}
}

// ---------------------------------------------------------------------------
// Round trips.
// ---------------------------------------------------------------------------

func TestStoreStreamRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"zero bytes", 0},
		{"one byte", 1},
		{"just under a frame", frameSize - 1},
		// The boundary the format's self-termination turns on: a plaintext that
		// is an exact multiple of the frame size must still end in a final
		// frame, empty, or a reader has nothing to stop on.
		{"exactly one frame", frameSize},
		{"just over a frame", frameSize + 1},
		{"several frames", 3*frameSize + 7},
		{"several frames plus an exact boundary", 2 * frameSize},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, fake := newTestStore(t)
			const key = "app/deployment/payload.bin"
			want := patternBytes(tc.size)

			if err := s.WriteStream(ctx, key, bytes.NewReader(want)); err != nil {
				t.Fatalf("WriteStream: %v", err)
			}
			if got := fake.objectCount(); got != 1 {
				t.Fatalf("provider holds %d objects after one WriteStream, want 1", got)
			}
			var got bytes.Buffer
			if err := s.ReadStream(ctx, key, &got); err != nil {
				t.Fatalf("ReadStream: %v", err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Errorf("ReadStream produced %d bytes, want %d (byte-exact)", got.Len(), len(want))
			}

			// A WriteStream that quietly emitted the buffered format would
			// round-trip perfectly and prove nothing about the format under
			// test, so the stored bytes are checked directly.
			obj, ok := fake.object(mustStoredName(t, s, key))
			if !ok {
				t.Fatal("the provider holds no object under the stored name")
			}
			assertStreamBlob(t, obj.Data, tc.size)
			if obj.Meta[MetaName] == "" {
				t.Errorf("streamed object carries no %q metadata mirror", MetaName)
			}
		})
	}
}

// TestStoreStreamListsLikeAnyOtherObject pins that a streamed object is an
// object: it appears in a listing under its logical name, and it deletes.
func TestStoreStreamListsLikeAnyOtherObject(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)
	const key = "app/deployment/payload.bin"

	if err := s.WriteStream(ctx, key, bytes.NewReader(patternBytes(frameSize+9))); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	names, err := s.List(ctx, "app/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !slices.Equal(names, []string{key}) {
		t.Errorf("List = %q, want [%q]", names, key)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := fake.objectCount(); got != 0 {
		t.Errorf("provider holds %d objects after deleting the streamed one, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// The test this module exists for, extended to the streaming path.
// ---------------------------------------------------------------------------

// TestProviderNeverSeesPlaintextOrNamesWhenStreaming is
// TestProviderNeverSeesPlaintextOrNames' claim carried onto the streaming API,
// and it is not a formality: the streaming path mints its sealed name in a
// different place, hands the provider a reader rather than a []byte, and passes
// metadata through a second code path. Every one of those is a fresh
// opportunity to leak the thing this module exists to hide.
//
// It writes an object whose plaintext carries distinctive markers at the head
// of every frame and at both ends, under a logical key whose every segment
// carries one, drives the streaming methods, and then searches every byte the
// provider was handed — including the whole blob PutStream streamed, which the
// fake records verbatim.
func TestProviderNeverSeesPlaintextOrNamesWhenStreaming(t *testing.T) {
	const (
		plainMarker = "PMK-3d71a08c"
		nameMarker  = "NMK-52e9b14f"
	)
	ctx := context.Background()
	s, fake := newTestStore(t)

	key := nameMarker + "/lawsuit-2026/" + nameMarker + ".bin"

	// Markers at the head of every frame as well as at both ends: a leak that
	// escapes one frame's worth of buffer must still trip the scan.
	value := patternBytes(2*frameSize + 4096)
	for offset := 0; offset < len(value); offset += frameSize {
		copy(value[offset:], plainMarker)
	}
	copy(value[len(value)-len(plainMarker):], plainMarker)

	if err := s.WriteStream(ctx, key, bytes.NewReader(value)); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	var got bytes.Buffer
	if err := s.ReadStream(ctx, key, &got); err != nil {
		t.Fatalf("ReadStream: %v", err)
	}
	if !bytes.Equal(got.Bytes(), value) {
		t.Fatalf("ReadStream did not round-trip the marked plaintext")
	}
	if _, err := s.List(ctx, nameMarker+"/lawsuit-2026/"); err != nil {
		t.Fatalf("List: %v", err)
	}

	// Guard against a vacuous pass. The fake's streaming methods funnel into
	// Put and Get, so those counters are what shows the calls happened at all;
	// the version byte of the stored object is what shows they happened through
	// the streaming format rather than the buffered one.
	for _, method := range []string{"Put", "Get", "List"} {
		if fake.callCount(method) == 0 {
			t.Fatalf("the provider was never asked to %s; the scan below would prove nothing", method)
		}
	}
	stored := mustStoredName(t, s, key)
	obj, ok := fake.object(stored)
	if !ok {
		t.Fatal("the provider holds no object under the stored name")
	}
	assertStreamBlob(t, obj.Data, len(value))

	seen := fake.everything()
	if len(seen) == 0 {
		t.Fatal("the provider recorded no arguments")
	}
	var forbidden []string
	for _, secret := range []string{
		plainMarker, nameMarker, key,
		// Bounded windows of the plaintext rather than all 2 MiB of it: the
		// markers already tile every frame, and these pin the two ends a
		// truncating leak would keep.
		string(value[:64]), string(value[len(value)-64:]),
		testNameKeyMaterial, testKEKMaterial,
	} {
		forbidden = append(forbidden, secretForms([]byte(secret))...)
	}
	scanForLeaks(t, seen, forbidden)
}

// ---------------------------------------------------------------------------
// Cross-API: which method wrote an object is not something a caller remembers.
// ---------------------------------------------------------------------------

// TestStoreBufferedAndStreamingAPIsInterchange pins that the two write paths
// produce objects the two read paths both accept. A caller that stored
// something with `storage cp` and reads it back through the SDK's []byte API —
// or the reverse — is the normal case, not an edge one, and nothing in the
// stored object tells the caller which API to use.
func TestStoreBufferedAndStreamingAPIsInterchange(t *testing.T) {
	t.Run("buffered write, streamed read", func(t *testing.T) {
		ctx := context.Background()
		s, fake := newTestStore(t)
		const key = "system/config.yaml"
		want := patternBytes(4096)

		if err := s.Write(ctx, key, want); err != nil {
			t.Fatalf("Write: %v", err)
		}
		obj, _ := fake.object(mustStoredName(t, s, key))
		if obj.Data[4] != crypto.Version {
			t.Fatalf("Write emitted version %#x, want the buffered format %#x", obj.Data[4], crypto.Version)
		}
		var got bytes.Buffer
		if err := s.ReadStream(ctx, key, &got); err != nil {
			t.Fatalf("ReadStream of a buffered object: %v", err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Errorf("ReadStream of a v1 object did not reproduce its plaintext")
		}
	})

	t.Run("streamed write, buffered read", func(t *testing.T) {
		ctx := context.Background()
		s, _ := newTestStore(t)
		const key = "system/streamed"
		want := patternBytes(2*frameSize + 11)

		if err := s.WriteStream(ctx, key, bytes.NewReader(want)); err != nil {
			t.Fatalf("WriteStream: %v", err)
		}
		got, err := s.Read(ctx, key)
		if err != nil {
			t.Fatalf("Read of a streamed object: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Read of a v2 object did not reproduce its plaintext")
		}
	})

	// The one place the interchange stops, and it stops honestly: the buffered
	// API holds whole objects in memory, so a streamed object over the cap is
	// refused with ErrTooLarge — which names ReadStream — rather than being
	// silently truncated or quietly allowed to blow the cap open.
	t.Run("streamed write over the buffered cap", func(t *testing.T) {
		ctx := context.Background()
		s, fake := newTestStore(t)
		const key = "system/oversized"

		if err := s.WriteStream(ctx, key, &patternReader{remaining: crypto.MaxPlaintext + 1}); err != nil {
			t.Fatalf("WriteStream of an object over the buffered cap: %v", err)
		}
		got, err := s.Read(ctx, key)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Read error = %v, want ErrTooLarge", err)
		}
		if got != nil {
			t.Errorf("Read returned %d bytes alongside its error, want nothing", len(got))
		}
		if !strings.Contains(err.Error(), "ReadStream") {
			t.Errorf("error = %v, want it to name the API that can read the object", err)
		}
		// And the object itself is fine — the refusal is about the API, not
		// about the data, so the streaming reader still returns every byte.
		var sink lengthWriter
		if err := s.ReadStream(ctx, key, &sink); err != nil {
			t.Fatalf("ReadStream of the same object: %v", err)
		}
		if sink.n != crypto.MaxPlaintext+1 {
			t.Errorf("ReadStream produced %d bytes, want %d", sink.n, crypto.MaxPlaintext+1)
		}
		if got := fake.objectCount(); got != 1 {
			t.Errorf("provider holds %d objects, want 1", got)
		}
	})
}

// lengthWriter counts bytes without keeping them, so an object at the buffered
// cap can be streamed without a second copy of it in memory.
type lengthWriter struct{ n int }

func (l *lengthWriter) Write(p []byte) (int, error) {
	l.n += len(p)
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Upsert.
// ---------------------------------------------------------------------------

// TestStoreWriteStreamIsAnUpsert pins WriteStream's documented semantics —
// writing an existing key replaces it rather than erroring or accumulating
// versions — and the property underneath it: two writes of identical bytes
// produce different stored ciphertext, because every write mints a fresh
// single-use DEK, a fresh wrap nonce, and a fresh frame salt. That is what
// makes the frame nonces' budget a non-question rather than an estimate.
func TestStoreWriteStreamIsAnUpsert(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)
	const key = "app/deployment/state"
	first := patternBytes(frameSize + 128)

	if err := s.WriteStream(ctx, key, bytes.NewReader(first)); err != nil {
		t.Fatalf("first WriteStream: %v", err)
	}
	stored := mustStoredName(t, s, key)
	before, _ := fake.object(stored)

	if err := s.WriteStream(ctx, key, bytes.NewReader([]byte("second"))); err != nil {
		t.Fatalf("second WriteStream: %v", err)
	}
	if got := fake.objectCount(); got != 1 {
		t.Errorf("provider holds %d objects after an overwrite, want 1", got)
	}
	var got bytes.Buffer
	if err := s.ReadStream(ctx, key, &got); err != nil {
		t.Fatalf("ReadStream: %v", err)
	}
	if got.String() != "second" {
		t.Errorf("ReadStream = %q, want the second write", got.String())
	}

	if err := s.WriteStream(ctx, key, bytes.NewReader(first)); err != nil {
		t.Fatalf("third WriteStream: %v", err)
	}
	third, _ := fake.object(stored)
	if bytes.Equal(before.Data, third.Data) {
		t.Error("re-streaming the same bytes produced identical ciphertext; the DEK, the salt, or the nonces were reused")
	}
	if before.Meta[MetaName] == third.Meta[MetaName] {
		t.Error("the sealed-name mirror was reused across writes; the name nonce is not fresh")
	}
}

// ---------------------------------------------------------------------------
// Key validation and absent objects.
// ---------------------------------------------------------------------------

func TestStoreStreamingRejectsMalformedKeys(t *testing.T) {
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
		call func(t *testing.T, s *Store, key string) error
	}{
		{"WriteStream", func(t *testing.T, s *Store, key string) error {
			// A refusing reader, because the refusal must land before a single
			// plaintext byte is pulled out of the caller's hands.
			return s.WriteStream(context.Background(), key, refusingReader{t: t})
		}},
		{"ReadStream", func(_ *testing.T, s *Store, key string) error {
			return s.ReadStream(context.Background(), key, io.Discard)
		}},
	}

	for _, k := range keys {
		for _, m := range methods {
			t.Run(m.name+"/"+k.name, func(t *testing.T) {
				s, fake := newTestStore(t)
				if err := m.call(t, s, k.key); !errors.Is(err, ErrInvalidKey) {
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

func TestStoreReadStreamAbsentKey(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)

	var got bytes.Buffer
	if err := s.ReadStream(ctx, "system/never-written", &got); !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("ReadStream of an absent key error = %v, want ErrObjectNotFound", err)
	}
	if got.Len() != 0 {
		t.Errorf("ReadStream wrote %d bytes for an absent key, want none", got.Len())
	}
}

// ---------------------------------------------------------------------------
// The partial-output contract.
// ---------------------------------------------------------------------------

// TestReadStreamPartialOutputOnADamagedFinalFrame is the one guarantee
// streaming gives up, asserted rather than assumed.
//
// v2 authenticates per frame, so damage in the last frame is detected only when
// the reader reaches it — after every earlier frame has already been written to
// w. That is arithmetic, not a choice: authenticating the whole object first
// would mean buffering the whole object, which is the property streaming exists
// to avoid. So this test asserts BOTH halves of the documented caveat: the
// error is real and still classifies as ErrIntegrity, and earlier plaintext
// really did reach the writer. A caller must therefore treat a non-nil error as
// "the output is incomplete and must not be used" — which is why `farcast
// storage cp` writes to a temporary file and renames only on success.
//
// The buffered API on the very same damaged object keeps v1's all-or-nothing
// guarantee, and the contrast is asserted here so the caveat reads as the
// bounded, documented trade it is rather than as a defect.
func TestReadStreamPartialOutputOnADamagedFinalFrame(t *testing.T) {
	ctx := context.Background()
	s, fake := newTestStore(t)
	const key = "app/deployment/archive"
	want := patternBytes(2*frameSize + 1024)

	if err := s.WriteStream(ctx, key, bytes.NewReader(want)); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	stored := mustStoredName(t, s, key)
	obj, ok := fake.object(stored)
	if !ok {
		t.Fatal("the provider holds no object under the stored name")
	}
	// One bit of the final frame's authentication tag: the cheapest damage a
	// cloud can do to the tail of an object.
	obj.Data[len(obj.Data)-1] ^= 0x01
	fake.setObject(stored, obj)

	var got bytes.Buffer
	err := s.ReadStream(ctx, key, &got)
	if err == nil {
		t.Fatal("ReadStream accepted an object whose final frame was tampered with")
	}
	if !errors.Is(err, ErrIntegrity) {
		t.Errorf("ReadStream error = %v, want it to classify as ErrIntegrity", err)
	}
	// The caveat itself: the frames that did authenticate are already out.
	if got.Len() != 2*frameSize {
		t.Fatalf("ReadStream wrote %d bytes before failing, want the %d bytes of the two intact frames",
			got.Len(), 2*frameSize)
	}
	if !bytes.Equal(got.Bytes(), want[:2*frameSize]) {
		t.Error("the bytes written before the failure are not the object's leading plaintext")
	}

	// And the guarantee that survives, because it can: the buffered API holds
	// the whole object, so it authenticates every frame before returning
	// anything, and returns nothing.
	buffered, err := s.Read(ctx, key)
	if !errors.Is(err, ErrIntegrity) {
		t.Errorf("Read error = %v, want ErrIntegrity", err)
	}
	if buffered != nil {
		t.Errorf("Read returned %d bytes of a damaged object, want none", len(buffered))
	}
}

// ---------------------------------------------------------------------------
// The ranged header fetch.
// ---------------------------------------------------------------------------

// TestStoreListFetchesOnlyTheHeaderOfALargeObject is a correctness requirement,
// not an optimization.
//
// Store.List's name-recovery fallback fetches an object whose metadata mirror
// is unreadable, because the blob header carries the authoritative copy of the
// logical name. For a streamed object that fallback must fetch a bounded
// PREFIX: recovering a 1,168-byte header out of a multi-gigabyte object by
// downloading the object would make the module's promise — that the bucket plus
// the keys file reconstruct every logical name — cost more than an operator can
// pay, exactly when something has already gone wrong. The object here is far
// larger than the header on purpose, so a whole-object read would be
// unmistakable in the recorded range.
func TestStoreListFetchesOnlyTheHeaderOfALargeObject(t *testing.T) {
	ctx := context.Background()
	s, fake := newObservedStore(t)
	const big = "archive/2026/backup.tar"

	if err := s.WriteStream(ctx, big, bytes.NewReader(patternBytes(4*frameSize))); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if err := s.Write(ctx, "archive/2026/notes", []byte("small and intact")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	victim := mustStoredName(t, s, big)
	obj, ok := fake.object(victim)
	if !ok {
		t.Fatal("the provider holds no object under the stored name")
	}
	if len(obj.Data) < 100*crypto.MaxHeaderLen {
		t.Fatalf("the stored object is %d bytes, too small for a whole-object read to be obvious", len(obj.Data))
	}
	obj.Meta = nil // the mirror is gone; only the header can name this object
	fake.setObject(victim, obj)

	names, err := s.List(ctx, "archive/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if want := []string{big, "archive/2026/notes"}; !slices.Equal(names, want) {
		t.Fatalf("List = %q, want %q", names, want)
	}

	reads := fake.rangedReads()
	if len(reads) != 1 {
		t.Fatalf("provider saw %d ranged reads, want exactly one fallback fetch", len(reads))
	}
	read := reads[0]
	if read.name != victim {
		t.Errorf("the fallback fetched %q, want the object whose mirror was broken %q", read.name, victim)
	}
	if read.offset != 0 || read.length != crypto.MaxHeaderLen {
		t.Errorf("the fallback asked for bytes %d..%d, want the %d-byte header prefix at 0 (a whole-object read asks for length -1)",
			read.offset, read.length, crypto.MaxHeaderLen)
	}
	// Requested and delivered, because a range that is asked for and then
	// over-read is the same download in the end.
	if read.delivered > crypto.MaxHeaderLen {
		t.Errorf("the fallback consumed %d bytes, want at most the %d-byte header", read.delivered, crypto.MaxHeaderLen)
	}
}

// ---------------------------------------------------------------------------
// ListEntries.
// ---------------------------------------------------------------------------

// TestStoreListEntriesCarriesSizesAndTimes pins what `storage ls --long` and
// usage reporting read: entries sorted by logical key, each carrying the stored
// (ciphertext) size the cloud bills for and the timestamp the cloud recorded —
// and List being exactly the name-only projection of the same call, so the two
// can never disagree about what a bucket contains.
func TestStoreListEntriesCarriesSizesAndTimes(t *testing.T) {
	ctx := context.Background()
	s, fake := newObservedStore(t)

	// Both write APIs, because ListEntries reports what the cloud holds and a
	// v2 blob's stored size is not its plaintext size.
	written := []struct {
		key      string
		size     int
		streamed bool
		created  time.Time
	}{
		{"users/bob", 12, false, time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)},
		{"users/alice", frameSize + 5, true, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
		{"orders/2026/january", 4096, false, time.Date(2026, 8, 9, 10, 11, 12, 0, time.UTC)},
	}
	for _, w := range written {
		var err error
		if w.streamed {
			err = s.WriteStream(ctx, w.key, bytes.NewReader(patternBytes(w.size)))
		} else {
			err = s.Write(ctx, w.key, patternBytes(w.size))
		}
		if err != nil {
			t.Fatalf("write %q: %v", w.key, err)
		}
		fake.stamp(mustStoredName(t, s, w.key), w.created)
	}

	entries, err := s.ListEntries(ctx, "")
	if err != nil {
		t.Fatalf("ListEntries: %v", err)
	}
	wantOrder := []string{"orders/2026/january", "users/alice", "users/bob"}
	got := make([]string, len(entries))
	for i, e := range entries {
		got[i] = e.Key
	}
	if !slices.Equal(got, wantOrder) {
		t.Fatalf("ListEntries = %q, want %q sorted by logical key", got, wantOrder)
	}

	byKey := map[string]Entry{}
	for _, e := range entries {
		byKey[e.Key] = e
	}
	for _, w := range written {
		e := byKey[w.key]
		stored := mustStoredName(t, s, w.key)
		if e.Stored != stored {
			t.Errorf("entry %q stored name = %q, want %q", w.key, e.Stored, stored)
		}
		obj, _ := fake.object(stored)
		if e.Size != int64(len(obj.Data)) {
			t.Errorf("entry %q size = %d, want the stored ciphertext size %d", w.key, e.Size, len(obj.Data))
		}
		if e.Size <= int64(w.size) {
			t.Errorf("entry %q size = %d, want more than its %d-byte plaintext", w.key, e.Size, w.size)
		}
		if !e.Created.Equal(w.created) {
			t.Errorf("entry %q created = %v, want %v", w.key, e.Created, w.created)
		}
	}

	// List is the projection, on every shape of prefix: aligned, partial, and
	// empty. Deriving one from the other in the test would prove nothing, so
	// both calls are made and compared.
	for _, prefix := range []string{"", "users/", "users/al", "orders/2026/january", "nowhere/"} {
		names, err := s.List(ctx, prefix)
		if err != nil {
			t.Fatalf("List(%q): %v", prefix, err)
		}
		entries, err := s.ListEntries(ctx, prefix)
		if err != nil {
			t.Fatalf("ListEntries(%q): %v", prefix, err)
		}
		projection := make([]string, len(entries))
		for i, e := range entries {
			projection[i] = e.Key
		}
		if !slices.Equal(names, projection) {
			t.Errorf("List(%q) = %q, want the ListEntries projection %q", prefix, names, projection)
		}
	}
}
