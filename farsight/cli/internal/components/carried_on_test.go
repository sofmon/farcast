//go:build farcast_embedded

package components

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

// TestCarriedTableIsConsistent runs only in the configuration a release ships
// (./check.sh step 3b, with the release tool's overlay): the layers this build
// carries are the ones its table describes, and they reassemble into the
// manifests it records.
func TestCarriedTableIsConsistent(t *testing.T) {
	if !Embedded() {
		t.Fatal("a farcast_embedded build says it carries nothing")
	}
	if Base() != image.BaseImage {
		t.Fatalf("the components were assembled on %s, not image.BaseImage %s", Base(), image.BaseImage)
	}
	if !regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`).MatchString(Revision()) {
		t.Fatalf("Revision() = %q, want the full commit the components were built at", Revision())
	}
	base, err := image.PinnedBase()
	if err != nil {
		t.Fatal(err)
	}
	arts := Artifacts()
	if len(arts) != len(All()) {
		t.Fatalf("carries %d components, want %d", len(arts), len(All()))
	}
	for i, a := range arts {
		if a.Component != All()[i] {
			t.Fatalf("artifact %d is %+v, want %+v", i, a.Component, All()[i])
		}
		layer, err := Layer(a.Name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(layer)
		if "sha256:"+hex.EncodeToString(sum[:]) != a.Layer || int64(len(layer)) != a.LayerSize {
			t.Fatalf("%s's layer does not match its entry", a.Name)
		}
		diffID, err := oci.DiffIDOf(layer)
		if err != nil || diffID != a.DiffID {
			t.Fatalf("%s's layer has diffID %s (%v), the table says %s", a.Name, diffID, err, a.DiffID)
		}
		im, err := image.Assemble(base, oci.Layer{
			Descriptor: oci.Descriptor{MediaType: oci.MediaTypeOCILayerGzip, Digest: a.Layer, Size: a.LayerSize},
			Blob:       layer,
			DiffID:     a.DiffID,
		}, a.Package, a.BinaryPath)
		if err != nil {
			t.Fatal(err)
		}
		_, manifest, err := im.ManifestBytes()
		if err != nil {
			t.Fatal(err)
		}
		if manifest != a.Manifest || im.Manifest.Config.Digest != a.Config {
			t.Fatalf("%s reassembles to %s (config %s); the table says %s (config %s)", a.Name, manifest, im.Manifest.Config.Digest, a.Manifest, a.Config)
		}
		if got, ok := Lookup(a.Name); !ok || got != a {
			t.Fatalf("Lookup(%s) = %+v, %v", a.Name, got, ok)
		}
	}
	if _, err := Layer("keeper"); err == nil {
		t.Fatal("Layer of an unknown component succeeded")
	}
}
