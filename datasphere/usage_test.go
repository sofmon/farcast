package datasphere

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// BucketUsage is deliberately a package function over a Provider rather than a
// Store method, and every test below is written against that shape: no Store is
// constructed, no keyring is passed, and nothing is decrypted. Whoever needs to
// know whether money is being spent must be able to ask without holding the
// keys — including the operator who has lost keys.yaml and most needs to see
// what they are still paying for.

// otherKeyring is a second instance's keyring: different name key, different
// KEK, different ids. Nothing it holds can name or open anything the test
// keyring wrote.
func otherKeyring(t *testing.T) Keyring {
	t.Helper()
	k := Keyring{
		nameKeys: []KeyEntry{testEntry(t, "a1a2a3a4a5a6a7a8", "OTHER-NAMEKEY-MATERIAL-32-BYTE!!")},
		keys:     []KeyEntry{testEntry(t, "b1b2b3b4b5b6b7b8", "OTHER-KEYRING-MATERIAL-32-BYTE!!")},
	}
	if err := k.Valid(); err != nil {
		t.Fatalf("otherKeyring is not valid: %v", err)
	}
	return k
}

// putRaw stores opaque bytes straight through the Provider — no Store, no
// keyring, no crypto. BucketUsage counts what a bucket physically holds, so its
// tests must not depend on the objects being FarCast blobs at all.
func putRaw(t *testing.T, p Provider, bucket, name string, size int) {
	t.Helper()
	if err := p.Put(context.Background(), bucket, Object{Name: name, Data: bytes.Repeat([]byte{0xa5}, size)}); err != nil {
		t.Fatalf("Put(%q): %v", name, err)
	}
}

func TestBucketUsageCountsObjectsAndStoredBytes(t *testing.T) {
	ctx := context.Background()
	_, fake := newObservedStore(t)
	const bucket = "farcast-test-bucket"

	early := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	middle := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	late := time.Date(2026, 11, 12, 13, 14, 15, 0, time.UTC)

	// Written in an order that is neither chronological nor size-ordered, and
	// handed back by the fake in reverse, so a Usage that happened to read the
	// first or last entry cannot pass.
	putRaw(t, fake, bucket, "aa", 100)
	fake.stamp("aa", middle)
	putRaw(t, fake, bucket, "bb", 250)
	fake.stamp("bb", late)
	putRaw(t, fake, bucket, "cc", 7)
	fake.stamp("cc", early)

	usage, err := BucketUsage(ctx, fake, bucket)
	if err != nil {
		t.Fatalf("BucketUsage: %v", err)
	}
	if usage.Objects != 3 {
		t.Errorf("Objects = %d, want 3", usage.Objects)
	}
	if want := int64(100 + 250 + 7); usage.StoredBytes != want {
		t.Errorf("StoredBytes = %d, want %d", usage.StoredBytes, want)
	}
	if !usage.Oldest.Equal(early) {
		t.Errorf("Oldest = %v, want %v", usage.Oldest, early)
	}
	if !usage.Newest.Equal(late) {
		t.Errorf("Newest = %v, want %v", usage.Newest, late)
	}

	// The whole bucket, not a prefix of it: a usage report that narrowed
	// cloud-side would answer a different question than the one it is asked.
	seen := fake.everything()
	if got := seen[len(seen)-1]; got != "" {
		t.Errorf("the provider was asked to list under %q, want the whole bucket", got)
	}
}

// TestBucketUsageIgnoresZeroTimestamps covers the provider that reports no
// creation time. A zero timestamp is an absent fact, and folding it into Oldest
// would date every bucket to the year 1 — which reads as a real answer and is
// not one.
func TestBucketUsageIgnoresZeroTimestamps(t *testing.T) {
	ctx := context.Background()
	_, fake := newObservedStore(t)
	const bucket = "farcast-test-bucket"

	stamped := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)
	putRaw(t, fake, bucket, "dated", 64)
	fake.stamp("dated", stamped)
	putRaw(t, fake, bucket, "undated", 32) // never stamped: Created stays zero

	usage, err := BucketUsage(ctx, fake, bucket)
	if err != nil {
		t.Fatalf("BucketUsage: %v", err)
	}
	if usage.Objects != 2 || usage.StoredBytes != 96 {
		t.Errorf("Usage = %d objects / %d bytes, want 2 / 96", usage.Objects, usage.StoredBytes)
	}
	if !usage.Oldest.Equal(stamped) || !usage.Newest.Equal(stamped) {
		t.Errorf("Oldest/Newest = %v/%v, want both %v — the undated object must not move either",
			usage.Oldest, usage.Newest, stamped)
	}

	// And a bucket where nothing is dated reports no dates rather than epoch.
	_, bare := newObservedStore(t)
	putRaw(t, bare, bucket, "undated", 32)
	usage, err = BucketUsage(ctx, bare, bucket)
	if err != nil {
		t.Fatalf("BucketUsage: %v", err)
	}
	if !usage.Oldest.IsZero() || !usage.Newest.IsZero() {
		t.Errorf("Oldest/Newest = %v/%v for an undated bucket, want both zero", usage.Oldest, usage.Newest)
	}
}

func TestBucketUsageOnAnEmptyBucket(t *testing.T) {
	ctx := context.Background()
	fake := newFakeProvider()

	usage, err := BucketUsage(ctx, fake, "farcast-test-bucket")
	if err != nil {
		t.Fatalf("BucketUsage: %v", err)
	}
	if usage.Objects != 0 || usage.StoredBytes != 0 {
		t.Errorf("Usage = %d objects / %d bytes, want an empty bucket to report zero", usage.Objects, usage.StoredBytes)
	}
	if !usage.Oldest.IsZero() || !usage.Newest.IsZero() {
		t.Errorf("Oldest/Newest = %v/%v, want both zero", usage.Oldest, usage.Newest)
	}
}

// TestBucketUsagePropagatesProviderErrors pins that a failed look is reported
// as a failed look. A usage report that swallowed the error would return a zero
// Usage that is indistinguishable from an empty bucket — and "nothing is being
// billed" is exactly the wrong thing to tell an operator who is about to tear
// an instance down.
func TestBucketUsagePropagatesProviderErrors(t *testing.T) {
	ctx := context.Background()
	fake := newFakeProvider()
	sentinel := errors.New("the cloud said no")
	fake.listErr = sentinel

	usage, err := BucketUsage(ctx, fake, "farcast-test-bucket")
	if !errors.Is(err, sentinel) {
		t.Errorf("BucketUsage error = %v, want the provider's error", err)
	}
	if usage.Objects != 0 || usage.StoredBytes != 0 || !usage.Oldest.IsZero() || !usage.Newest.IsZero() {
		t.Errorf("BucketUsage = %+v alongside its error, want a zero Usage", usage)
	}
}

// TestBucketUsageSeesObjectsTheKeyringCannotName is the reason this function
// exists, and the reason it is not a Store method.
//
// Store.List reports what the KEYRING can name. A teardown gate or a spend
// report built on it would announce an empty bucket while billable ciphertext
// sat in it — objects written under a keyring this instance no longer holds are
// still objects the cloud charges for, still objects `farcast release` must
// destroy, and still objects an operator is owed an honest count of. So this
// test drives exactly that divergence: two objects that one keyring wrote, a
// Store that cannot name a single one of them, and a BucketUsage that counts
// both anyway.
func TestBucketUsageSeesObjectsTheKeyringCannotName(t *testing.T) {
	ctx := context.Background()
	const bucket = "farcast-test-bucket"
	fake := newFakeProvider()

	owner, err := NewStore(fake, bucket, testKeyring(t))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := owner.Write(ctx, "system/config", []byte("buffered")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := owner.WriteStream(ctx, "app/deployment/blob", bytes.NewReader(patternBytes(frameSize+3))); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	var stored int64
	for _, name := range []string{
		mustStoredName(t, owner, "system/config"),
		mustStoredName(t, owner, "app/deployment/blob"),
	} {
		obj, ok := fake.object(name)
		if !ok {
			t.Fatalf("the provider holds no object under %q", name)
		}
		stored += int64(len(obj.Data))
	}

	// The objects are genuinely nameable — by the keyring that wrote them. That
	// is what makes the next assertion about the keyring rather than about the
	// objects being broken.
	if names, err := owner.List(ctx, ""); err != nil || len(names) != 2 {
		t.Fatalf("the owning Store lists %q (err %v), want both objects", names, err)
	}

	stranger, err := NewStore(fake, bucket, otherKeyring(t))
	if err != nil {
		t.Fatalf("NewStore with a second keyring: %v", err)
	}
	names, err := stranger.List(ctx, "")
	if len(names) != 0 {
		t.Errorf("a Store without the keys listed %q, want nothing it can name", names)
	}
	if err == nil {
		t.Error("a Store that could name none of the bucket's objects reported no error")
	}

	// And the count that does not need the keys.
	usage, err := BucketUsage(ctx, fake, bucket)
	if err != nil {
		t.Fatalf("BucketUsage: %v", err)
	}
	if usage.Objects != 2 {
		t.Errorf("Objects = %d, want 2 — the bucket holds them whether or not this keyring can name them", usage.Objects)
	}
	if usage.StoredBytes != stored {
		t.Errorf("StoredBytes = %d, want the %d bytes the provider actually holds", usage.StoredBytes, stored)
	}
}

// The distribution is the measurement any future size-hiding decision needs,
// and it must be exact: a padding lattice chosen from a wrong histogram is a
// frozen format change made on bad data.
func TestBucketUsageReportsTheSizeDistribution(t *testing.T) {
	ctx := context.Background()
	fake := newFakeProvider()
	sizes := []int{
		10, 900, 1024, // <=1K  (boundary is inclusive)
		1025, 2000, // <=2K
		70000,     // <=128K
		100 << 20, // larger than the last bound
	}
	for i, n := range sizes {
		if err := fake.Put(ctx, "b", Object{Name: fmt.Sprintf("o%02d", i), Data: make([]byte, n)}); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := BucketUsage(ctx, fake, "b")
	if err != nil {
		t.Fatalf("BucketUsage: %v", err)
	}
	if usage.Objects != int64(len(sizes)) {
		t.Fatalf("Objects = %d, want %d", usage.Objects, len(sizes))
	}

	// Every object lands in exactly one band, and the bands reconcile with the
	// totals — otherwise the histogram silently disagrees with the bill.
	var objects, bytes int64
	for _, b := range usage.Sizes {
		if b.Objects == 0 {
			t.Errorf("an empty bucket was reported: %+v", b)
		}
		objects += b.Objects
		bytes += b.Bytes
	}
	if objects != usage.Objects {
		t.Errorf("buckets hold %d objects, total is %d", objects, usage.Objects)
	}
	if bytes != usage.StoredBytes {
		t.Errorf("buckets hold %d bytes, total is %d", bytes, usage.StoredBytes)
	}

	byLabel := map[string]int64{}
	for _, b := range usage.Sizes {
		byLabel[b.Label()] = b.Objects
	}
	if byLabel["<=1K"] != 3 {
		t.Errorf("<=1K held %d objects, want 3 (the bound is inclusive)", byLabel["<=1K"])
	}
	if byLabel["<=2K"] != 2 {
		t.Errorf("<=2K held %d, want 2", byLabel["<=2K"])
	}
	if byLabel["larger"] != 1 {
		t.Errorf("the open-ended band held %d, want 1", byLabel["larger"])
	}
}

func TestBucketUsageOnAnEmptyBucketReportsNoBuckets(t *testing.T) {
	usage, err := BucketUsage(context.Background(), newFakeProvider(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if len(usage.Sizes) != 0 {
		t.Errorf("an empty bucket reported %d size bands", len(usage.Sizes))
	}
}
