package datasphere

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// The bucket name is the one piece of FarCast state that exists nowhere but the
// operator's record. Its random suffix is not re-derivable, its instance
// segment may be truncated away, and the name lands in a namespace shared with
// every stranger on Google Cloud. Each of those three facts is load-bearing
// somewhere else in the module, so each gets pinned here.

// mintedName is the shape every bucket name must take: the recognisable prefix
// an operator scans a console for, a label they can read, and 32 bits of
// entropy a squatter cannot guess.
var mintedName = regexp.MustCompile(`^farcast-[a-z0-9-]*[a-z0-9]-[0-9a-f]{8}$`)

// fixedReader is the entropy seam, so a minted name can be asserted exactly
// rather than by pattern alone.
type fixedReader struct{ b byte }

func (r fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy today") }

func TestMintBucketNameShape(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance string
		want     string
	}{
		{"plain", "demo", "farcast-demo-ffffffff"},
		{"dashes survive", "my-instance", "farcast-my-instance-ffffffff"},
		{"uppercase is folded", "Demo", "farcast-demo-ffffffff"},
		{"underscores become dashes", "my_instance", "farcast-my-instance-ffffffff"},
		{"illegal characters are dropped", "de.mo/1 2", "farcast-demo12-ffffffff"},
		{"leading and trailing dashes go", "-demo-", "farcast-demo-ffffffff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mintBucketName(tc.instance, fixedReader{0xff})
			if err != nil {
				t.Fatalf("mintBucketName(%q) = %v", tc.instance, err)
			}
			if got != tc.want {
				t.Errorf("mintBucketName(%q) = %q, want %q", tc.instance, got, tc.want)
			}
			if !mintedName.MatchString(got) {
				t.Errorf("%q does not match the required shape %s", got, mintedName)
			}
		})
	}
}

// TestMintBucketNameFitsTheCap covers the clause that makes the name
// non-invertible. GCS caps a bucket name at 63 characters, so a long instance
// name loses its tail — which is exactly why every ownership check in this
// module takes the instance from the caller's local record and never tries to
// read it back out of the bucket name.
func TestMintBucketNameFitsTheCap(t *testing.T) {
	long := strings.Repeat("a", 200)
	got, err := mintBucketName(long, fixedReader{0x01})
	if err != nil {
		t.Fatalf("mintBucketName = %v", err)
	}
	if len(got) != MaxBucketNameLen {
		t.Errorf("len(%q) = %d, want exactly the %d-character cap", got, len(got), MaxBucketNameLen)
	}
	if !mintedName.MatchString(got) {
		t.Errorf("%q does not match the required shape %s", got, mintedName)
	}
	if !strings.HasSuffix(got, "-01010101") {
		t.Errorf("%q lost its entropy suffix to truncation — the suffix is the only thing that makes the name unguessable", got)
	}
}

// TestMintBucketNameTruncationLeavesNoTrailingDash guards the sharp edge in the
// cap: a bucket name must end in a letter or a digit, and cutting a label at an
// arbitrary offset can land exactly on a dash. Getting this wrong produces a
// name the cloud rejects, at create time, on the operator's machine.
func TestMintBucketNameTruncationLeavesNoTrailingDash(t *testing.T) {
	// Sized so the cut falls on the dash: prefix (8) + suffix (9) leaves 46
	// characters of room, and index 45 is the dash.
	instance := strings.Repeat("a", 45) + "-" + strings.Repeat("b", 10)

	got, err := mintBucketName(instance, fixedReader{0x02})
	if err != nil {
		t.Fatalf("mintBucketName = %v", err)
	}
	if want := "farcast-" + strings.Repeat("a", 45) + "-02020202"; got != want {
		t.Errorf("mintBucketName = %q, want %q", got, want)
	}
	if !mintedName.MatchString(got) {
		t.Errorf("%q does not match the required shape %s", got, mintedName)
	}
}

// TestMintBucketNameIsNotInvertible states the property the rest of the module
// depends on, as a test rather than as a comment: two different instances can
// mint names carrying the same visible label.
func TestMintBucketNameIsNotInvertible(t *testing.T) {
	base := strings.Repeat("a", 46)
	first, err := mintBucketName(base+"-production", fixedReader{0x03})
	if err != nil {
		t.Fatal(err)
	}
	second, err := mintBucketName(base+"-staging", fixedReader{0x03})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("expected two distinct instances to truncate to the same name, got %q and %q", first, second)
	}
}

func TestMintBucketNameRejectsUnusableInstances(t *testing.T) {
	for _, instance := range []string{"", "---", "...", "!!!"} {
		if got, err := mintBucketName(instance, fixedReader{0x04}); err == nil {
			t.Errorf("mintBucketName(%q) = %q, want an error: there is nothing legible left to name a bucket after", instance, got)
		}
	}
}

func TestMintBucketNameSurfacesEntropyFailures(t *testing.T) {
	if _, err := mintBucketName("demo", failingReader{}); err == nil {
		t.Fatal("mintBucketName returned nil error with no entropy available; a predictable suffix is a squattable name")
	}
}

// TestMintBucketNameDrawsFreshEntropy pins that the suffix comes from the
// reader on every call rather than from anything derived from the instance.
func TestMintBucketNameDrawsFreshEntropy(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		got, err := MintBucketName("demo")
		if err != nil {
			t.Fatalf("MintBucketName = %v", err)
		}
		if !mintedName.MatchString(got) {
			t.Fatalf("%q does not match the required shape %s", got, mintedName)
		}
		seen[got] = true
	}
	if len(seen) < 30 {
		t.Errorf("32 mints produced only %d distinct names; the suffix is not random", len(seen))
	}
}

// TestMintBucketNameConsumesFourBytes pins the entropy width at the 32 bits the
// squatting argument rests on. Shrinking it would weaken that argument silently.
func TestMintBucketNameConsumesFourBytes(t *testing.T) {
	counter := &countingReader{}
	if _, err := mintBucketName("demo", counter); err != nil {
		t.Fatal(err)
	}
	if counter.n != 4 {
		t.Errorf("mintBucketName read %d bytes of entropy, want 4 (32 bits)", counter.n)
	}
}

type countingReader struct{ n int }

func (c *countingReader) Read(p []byte) (int, error) {
	c.n += len(p)
	return bytes.NewReader(make([]byte, len(p))).Read(p)
}
