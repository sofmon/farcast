package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

const carriedRepo = "proj-1/farcast-alpha/system/fatline"

// release does on the synthetic base what farcast-release does on the real one:
// the layer of a fixed binary and, from the base's documents alone, the manifest
// digest a released farcast would carry.
func release(t *testing.T, reg *testRegistry, base string) EmbeddedOptions {
	t.Helper()
	index, manifest, config := seededDocuments(t, reg, base)
	ref, err := oci.ParseReference(base)
	if err != nil {
		t.Fatal(err)
	}
	baseImage, err := oci.ImageFromDocuments(ref, index, manifest, config, ComponentPlatform)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := ComponentLayer("/fatline", []byte(fakeBinary))
	if err != nil {
		t.Fatal(err)
	}
	im, err := Assemble(baseImage, layer, "./fatline/cmd/fatline", "/fatline")
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := im.ManifestBytes()
	if err != nil {
		t.Fatal(err)
	}
	return EmbeddedOptions{
		Ref:         reg.host() + "/" + carriedRepo + ":v0.1.0",
		Package:     "./fatline/cmd/fatline",
		BinaryPath:  "/fatline",
		Layer:       layer.Blob,
		LayerDigest: layer.Descriptor.Digest,
		LayerSize:   layer.Descriptor.Size,
		DiffID:      layer.DiffID,
		Manifest:    digest,
		GoVersion:   "go1.27.4",
	}
}

func TestPushEmbeddedPushesTheReleasedImage(t *testing.T) {
	reg := newTestRegistry(t)
	base := seedBase(t, reg, "distroless/static", "nonroot")
	opts := release(t, reg, base)

	b := &Builder{base: base, Compile: func(context.Context, string, string) (Binary, error) {
		t.Error("PushEmbedded compiled something")
		return Binary{}, errors.New("no compiling here")
	}}
	pushed, err := b.PushEmbedded(t.Context(), opts, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := reg.host() + "/" + carriedRepo + "@" + opts.Manifest; pushed.Ref != want {
		t.Fatalf("Ref = %s, want %s", pushed.Ref, want)
	}
	if pushed.GoVersion != "go1.27.4" {
		t.Fatalf("GoVersion = %q", pushed.GoVersion)
	}
	byTag, ok := reg.manifest(carriedRepo, "v0.1.0")
	if !ok {
		t.Fatal("nothing at the version tag")
	}
	if sha256Ref(byTag) != opts.Manifest {
		t.Fatalf("the tag holds %s, not the released %s", sha256Ref(byTag), opts.Manifest)
	}
	if !bytes.Equal(reg.blob(carriedRepo, opts.LayerDigest), opts.Layer) {
		t.Fatal("the carried layer was not uploaded byte for byte")
	}
}

func TestPushEmbeddedRefusesBeforeUploadingWhenTheDigestDiffers(t *testing.T) {
	reg := newTestRegistry(t)
	base := seedBase(t, reg, "distroless/static", "nonroot")
	opts := release(t, reg, base)
	// Off by one hex digit.
	last := opts.Manifest[len(opts.Manifest)-1]
	swap := byte('0')
	if last == '0' {
		swap = '1'
	}
	opts.Manifest = opts.Manifest[:len(opts.Manifest)-1] + string(swap)

	_, err := (&Builder{base: base}).PushEmbedded(t.Context(), opts, "", "")
	if !errors.Is(err, ErrNotTheReleasedImage) {
		t.Fatalf("err = %v, want ErrNotTheReleasedImage", err)
	}
	if !strings.Contains(err.Error(), "nothing was pushed") || !strings.Contains(err.Error(), opts.Manifest) {
		t.Fatalf("the refusal does not say what it expected and that nothing was pushed: %v", err)
	}
	if w := reg.writes(); len(w) != 0 {
		t.Fatalf("the registry saw writes before the comparison: %v", w)
	}
}

func TestPushEmbeddedRefusesALayerThatIsNotTheReleasedOne(t *testing.T) {
	reg := newTestRegistry(t)
	base := seedBase(t, reg, "distroless/static", "nonroot")
	good := release(t, reg, base)
	before := len(reg.calls())

	cases := map[string]func(*EmbeddedOptions){
		"a changed byte": func(o *EmbeddedOptions) {
			o.Layer = bytes.Clone(o.Layer)
			o.Layer[len(o.Layer)/2] ^= 0x01
		},
		"a changed size": func(o *EmbeddedOptions) { o.LayerSize++ },
		"a wrong diffID": func(o *EmbeddedOptions) {
			sum := sha256.Sum256([]byte("another tar"))
			o.DiffID = "sha256:" + hex.EncodeToString(sum[:])
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			opts := good
			edit(&opts)
			_, err := (&Builder{base: base}).PushEmbedded(t.Context(), opts, "", "")
			if err == nil || !strings.Contains(err.Error(), "is not the one this farcast was released with; nothing was pushed") {
				t.Fatalf("err = %v, want the carried layer refused", err)
			}
			if n := len(reg.calls()) - before; n != 0 {
				t.Fatalf("the registry saw %d requests: %v", n, reg.calls()[before:])
			}
		})
	}
}

func TestPushEmbeddedRefusesARegistryThatStoresSomethingElse(t *testing.T) {
	reg := newTestRegistry(t)
	base := seedBase(t, reg, "distroless/static", "nonroot")
	opts := release(t, reg, base)
	reg.putDigestLie = "sha256:" + strings.Repeat("e", 64)

	_, err := (&Builder{base: base}).PushEmbedded(t.Context(), opts, "", "")
	if err == nil || !strings.Contains(err.Error(), reg.putDigestLie) {
		t.Fatalf("err = %v, want the registry's other digest refused", err)
	}
}

func TestPushEmbeddedRefusesAnUntaggedRef(t *testing.T) {
	reg := newTestRegistry(t)
	base := seedBase(t, reg, "distroless/static", "nonroot")
	good := release(t, reg, base)
	before := len(reg.calls())

	for _, ref := range []string{
		reg.host() + "/" + carriedRepo, // ParseReference alone would read this as :latest
		reg.host() + "/" + carriedRepo + "@" + good.Manifest,
		reg.host() + "/" + carriedRepo + ":v0.1.0@" + good.Manifest,
		"",
	} {
		opts := good
		opts.Ref = ref
		if _, err := (&Builder{base: base}).PushEmbedded(t.Context(), opts, "", ""); err == nil {
			t.Fatalf("Ref %q was accepted", ref)
		}
	}
	if n := len(reg.calls()) - before; n != 0 {
		t.Fatalf("the registry saw %d requests: %v", n, reg.calls()[before:])
	}
}

func TestPushEmbeddedRefusesAnUnpinnedBase(t *testing.T) {
	reg := newTestRegistry(t)
	base := seedBase(t, reg, "distroless/static", "nonroot")
	opts := release(t, reg, base)
	unpinned, _, _ := strings.Cut(base, "@")
	before := len(reg.calls())
	_, err := (&Builder{base: unpinned}).PushEmbedded(t.Context(), opts, "", "")
	if err == nil || !strings.Contains(err.Error(), "not pinned by digest") {
		t.Fatalf("err = %v, want an unpinned base refused", err)
	}
	if n := len(reg.calls()) - before; n != 0 {
		t.Fatalf("the registry saw %d requests", n)
	}
}

func TestPushEmbeddedKeepsCredentialsOffThePublicBase(t *testing.T) {
	public := newTestRegistry(t)
	base := seedBase(t, public, "distroless/static", "nonroot")
	instance := newTestRegistry(t)
	instance.requireAuth = true
	instance.user, instance.pass = "oauth2accesstoken", "ya29.short-lived"

	opts := release(t, public, base)
	opts.Ref = instance.host() + "/" + carriedRepo + ":v0.1.0"
	if _, err := (&Builder{base: base}).PushEmbedded(t.Context(), opts, instance.user, instance.pass); err != nil {
		t.Fatal(err)
	}
	if public.sawCredentials() {
		t.Fatal("the instance's registry token was offered to the public base registry")
	}
}

func TestReleaseAndPushEmbeddedAssembleTheSameImage(t *testing.T) {
	reg := newTestRegistry(t)
	base := seedBase(t, reg, "distroless/static", "nonroot")
	ref, err := oci.ParseReference(base)
	if err != nil {
		t.Fatal(err)
	}
	index, manifest, config := seededDocuments(t, reg, base)
	fromDocuments, err := oci.ImageFromDocuments(ref, index, manifest, config, ComponentPlatform)
	if err != nil {
		t.Fatal(err)
	}
	pulled, err := (&oci.Client{}).Pull(t.Context(), ref, ComponentPlatform)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := ComponentLayer("/technocore", []byte("a technocore"))
	if err != nil {
		t.Fatal(err)
	}
	var digests [2]string
	for i, b := range []*oci.Image{fromDocuments, pulled} {
		im, err := Assemble(b, layer, "./technocore/cmd/technocore", "/technocore")
		if err != nil {
			t.Fatal(err)
		}
		if _, digests[i], err = im.ManifestBytes(); err != nil {
			t.Fatal(err)
		}
	}
	if digests[0] != digests[1] {
		t.Fatalf("the documents path gives %s, the Pull path %s", digests[0], digests[1])
	}
}
