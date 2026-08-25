package oci

import (
	"errors"
	"net/http"
	"testing"
)

func TestParseReference(t *testing.T) {
	const digest = "sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7"
	tests := []struct {
		name string
		in   string
		want Reference
	}{
		{
			name: "tag",
			in:   "gcr.io/distroless/static:nonroot",
			want: Reference{Registry: "gcr.io", Repository: "distroless/static", Tag: "nonroot"},
		},
		{
			name: "digest",
			in:   "gcr.io/distroless/static@" + digest,
			want: Reference{Registry: "gcr.io", Repository: "distroless/static", Digest: digest},
		},
		{
			name: "tag and digest",
			in:   "gcr.io/distroless/static:nonroot@" + digest,
			want: Reference{Registry: "gcr.io", Repository: "distroless/static", Tag: "nonroot", Digest: digest},
		},
		{
			name: "artifact registry path",
			in:   "europe-west1-docker.pkg.dev/proj-1/farcast-alpha/system/fatline:0.2.0",
			want: Reference{
				Registry:   "europe-west1-docker.pkg.dev",
				Repository: "proj-1/farcast-alpha/system/fatline",
				Tag:        "0.2.0",
			},
		},
		{
			name: "host with port",
			in:   "127.0.0.1:5000/farcast/fatline",
			want: Reference{Registry: "127.0.0.1:5000", Repository: "farcast/fatline", Tag: "latest"},
		},
		{
			name: "default tag",
			in:   "localhost/farcast",
			want: Reference{Registry: "localhost", Repository: "farcast", Tag: "latest"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseReference(tc.in)
			if err != nil {
				t.Fatalf("ParseReference(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseReference(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
			if got.String() != tc.in && got.Tag != "latest" {
				t.Fatalf("String() = %q, want round trip of %q", got.String(), tc.in)
			}
		})
	}
}

func TestParseReferenceRejectsBadInput(t *testing.T) {
	// A reference without a host is rejected rather than defaulted to Docker
	// Hub: which registry an instance pulls from is ADR 0007's whole subject,
	// and an implicit third party is exactly what it removes.
	for _, in := range []string{
		"",
		"fatline:1.0",
		"distroless/static",
		"gcr.io/distroless/static@sha256:short",
		"gcr.io/distroless/static@md5:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7",
		"gcr.io/Distroless/Static:tag",
		"gcr.io/distroless/static:not a tag",
	} {
		if ref, err := ParseReference(in); err == nil {
			t.Errorf("ParseReference(%q) = %+v, want an error", in, ref)
		}
	}
}

func TestReferenceIdentifierPrefersDigest(t *testing.T) {
	ref, err := ParseReference("gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7")
	if err != nil {
		t.Fatal(err)
	}
	if got := ref.Identifier(); got != ref.Digest {
		t.Fatalf("Identifier() = %q, want the digest — a pinned reference must not resolve through its tag", got)
	}
}

func TestWithDigestDropsTag(t *testing.T) {
	ref, err := ParseReference("europe-west1-docker.pkg.dev/proj/farcast-alpha/system/fatline:0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	const digest = "sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7"
	pinned := ref.WithDigest(digest)
	if pinned.Tag != "" {
		t.Fatalf("WithDigest kept tag %q; a deploy must be told a digest, not a movable pointer", pinned.Tag)
	}
	want := "europe-west1-docker.pkg.dev/proj/farcast-alpha/system/fatline@" + digest
	if pinned.String() != want {
		t.Fatalf("String() = %q, want %q", pinned.String(), want)
	}
	if ref.Tag != "0.2.0" {
		t.Fatal("WithDigest mutated the receiver")
	}
}

func TestErrorUnwrapsNotFoundOnly(t *testing.T) {
	notFound := &Error{Op: "GET manifest", Ref: "x", Status: http.StatusNotFound}
	if !errors.Is(notFound, ErrNotFound) {
		t.Fatal("a 404 must satisfy errors.Is(err, ErrNotFound) so a preflight can tell a miss from a failure")
	}
	forbidden := &Error{Op: "GET manifest", Ref: "x", Status: http.StatusForbidden}
	if errors.Is(forbidden, ErrNotFound) {
		t.Fatal("a 403 must not be reported as a miss — that would build over a permission problem")
	}
}
