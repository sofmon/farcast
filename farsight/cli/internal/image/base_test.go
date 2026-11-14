package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

// goldenComponents are the four components as the golden tests build them:
// name, package and binary path, as components.All() names them.
var goldenComponents = []struct{ name, pkg, binaryPath string }{
	{"datasphered", "./datasphere/cmd/datasphere", "/datasphere"},
	{"fatline", "./fatline/cmd/fatline", "/fatline"},
	{"shrike", "./shrike/cmd/shrike", "/shrike"},
	{"technocore", "./technocore/cmd/technocore", "/technocore"},
}

// golden is one component's expected digests.
type golden struct{ layer, diffID, config, manifest string }

// goldenAssemble builds each golden component's layer from the binary
// "farcast golden <name>\n" and assembles it on base.
func goldenAssemble(t *testing.T, base *oci.Image) map[string]golden {
	t.Helper()
	got := map[string]golden{}
	for _, c := range goldenComponents {
		layer, err := ComponentLayer(c.binaryPath, []byte("farcast golden "+c.name+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		im, err := Assemble(base, layer, c.pkg, c.binaryPath)
		if err != nil {
			t.Fatal(err)
		}
		_, manifest, err := im.ManifestBytes()
		if err != nil {
			t.Fatal(err)
		}
		got[c.name] = golden{layer.Descriptor.Digest, layer.DiffID, im.Manifest.Config.Digest, manifest}
	}
	return got
}

func compareGoldens(t *testing.T, got, want map[string]golden) {
	t.Helper()
	for _, c := range goldenComponents {
		if got[c.name] != want[c.name] {
			t.Errorf("%s:\n got  %#v\n want %#v", c.name, got[c.name], want[c.name])
		}
	}
}

func TestPinnedBaseChainsToBaseImage(t *testing.T) {
	im, err := PinnedBase()
	if err != nil {
		t.Fatalf("PinnedBase: %v", err)
	}
	ref, err := oci.ParseReference(BaseImage)
	if err != nil {
		t.Fatal(err)
	}
	index, err := baseDocuments.ReadFile("base/index.json")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(index); "sha256:"+hex.EncodeToString(sum[:]) != ref.Digest {
		t.Fatalf("base/index.json is not the index %s pins: run farcast-release base -write", BaseImage)
	}
	var idx oci.Index
	if err := json.Unmarshal(index, &idx); err != nil {
		t.Fatal(err)
	}
	var entry string
	for _, d := range idx.Manifests {
		if d.Platform != nil && d.Platform.OS == "linux" && d.Platform.Architecture == "amd64" && d.Platform.Variant == "" {
			entry = d.Digest
		}
	}
	if im.Digest != entry {
		t.Fatalf("PinnedBase is %s, not the index's linux/amd64 entry %s", im.Digest, entry)
	}
	cfg, err := im.DecodeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OS != "linux" || cfg.Architecture != "amd64" || len(cfg.RootFS.DiffIDs) != len(im.Layers) || len(im.Layers) == 0 {
		t.Fatalf("PinnedBase's config = %+v for %d layers", cfg, len(im.Layers))
	}
	for i, l := range im.Layers {
		if l.Blob != nil || l.DiffID != cfg.RootFS.DiffIDs[i] {
			t.Fatalf("layer %d = %+v: want its descriptor and diffID, and no bytes", i, l)
		}
	}
}

// realBaseGoldens are the golden digests on the committed real-base documents
// (BaseImage's linux/amd64 manifest sha256:e754765a…, config sha256:76dd10bc…).
// The layer and diffID columns do not depend on the base. Every column was also
// recomputed outside Go's image and oci packages, from ADR 0023 M1's rules for
// the tar, config and manifest (a hand-built USTAR header, the standard library's
// gzip at BestCompression, and the base config and manifest edited and encoded as
// those rules say), and agreed. A base bump moves the config and manifest columns.
var realBaseGoldens = map[string]golden{
	"datasphered": {
		layer:    "sha256:539f3658bbbea28040c7a14162fd8f7792ba7b295f6083245837a8499f03ec8f",
		diffID:   "sha256:f55ba6a4ef5a1c647fe070996316fe9cb66e4bc58a28f2328d4426dfb4a48cd7",
		config:   "sha256:b725141de6b05715c84c7a8c28c28e02700ba8b4629622d6f14fd65daddbcd8c",
		manifest: "sha256:2b45af0130b1c1a2dd0118ef020bd6e17bcc9424f75e839f06ae4946797e7948",
	},
	"fatline": {
		layer:    "sha256:99a16ff39ef5e0e9fa5743a7bda33b096cd615cd827f291645ab5f75fab9cfef",
		diffID:   "sha256:4f185ef4a92e041e7df2a1e740580c030f786f29debf291ffcabbcaa94fbb7e8",
		config:   "sha256:ce4e13086d31d55c7aa2728417af70c1ad9dd62c7b74fde705f6e60fdd0b329f",
		manifest: "sha256:30eca891af5f844e401a19714793f6389b9c403d66f0680fe1664ffc90760449",
	},
	"shrike": {
		layer:    "sha256:6032526335f83cfb959ad38e7c74b54fb73a3db5696cfe4828084f78753fc2d4",
		diffID:   "sha256:e30dae01802eb251a99236e5a3209f09f5393a9f68c5c93f540bfc5b84976607",
		config:   "sha256:02a653fa37a530343ee7823a745b630dea615a2eb7dd04a09cb4df7adb1d5450",
		manifest: "sha256:9242228b4dd65566740ab122c39e77eb7f081e19c7261ee95c4624293028add0",
	},
	"technocore": {
		layer:    "sha256:d908c483fc42eb1c5f160393ba567ffd2e5bfe7d4e14ea15999de7c2659d729b",
		diffID:   "sha256:ddae47631617af6e4fdc2bc532283cbced296af17dc789c80142979d343dfa04",
		config:   "sha256:0e6718ee9de3451692527f3e1673c3406aba61c7cb09c8968c4e6a9c703ff223",
		manifest: "sha256:83c2fd10ef27c320c8e377396aaadd5020e269a48af72102cf9b23e6ac4691c1",
	},
}

func TestGoldenManifestDigests(t *testing.T) {
	base, err := PinnedBase()
	if err != nil {
		t.Fatalf("the golden manifests are computed on the committed base documents: %v", err)
	}
	compareGoldens(t, goldenAssemble(t, base), realBaseGoldens)
}

// syntheticBaseDocuments is a fixed, hand-written stand-in for the distroless
// base: an index with one linux/amd64 manifest, its config, and a layer
// descriptor with no bytes. Every byte is constant, so the digests assembled on
// it are goldens that a change to the layer recipe, CreatedBy, the entrypoint or
// AppendLayer moves, with no network and no committed real base.
func syntheticBaseDocuments() (pin string, index, manifest, config []byte) {
	sha := func(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
	diffID := "sha256:" + strings.Repeat("1", 64)
	config = []byte(`{"architecture":"amd64","author":"synthetic","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"],"User":"65532","WorkingDir":"/home/nonroot"},"created":"1970-01-01T00:00:00Z","history":[{"created":"1970-01-01T00:00:00Z","created_by":"synthetic base","comment":"a stand-in"}],"os":"linux","rootfs":{"type":"layers","diff_ids":["` + diffID + `"]}}`)
	manifest = fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"digest":%q,"size":%d},"layers":[{"mediaType":%q,"digest":%q,"size":104857}]}`,
		oci.MediaTypeOCIManifest, oci.MediaTypeOCIConfig, sha(config), len(config), oci.MediaTypeOCILayerGzip, "sha256:"+strings.Repeat("2", 64))
	index = fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"digest":%q,"size":%d,"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":%q,"digest":%q,"size":1,"platform":{"architecture":"arm64","os":"linux","variant":"v8"}}]}`,
		oci.MediaTypeOCIIndex, oci.MediaTypeOCIManifest, sha(manifest), len(manifest), oci.MediaTypeOCIManifest, "sha256:"+strings.Repeat("3", 64))
	return "gcr.io/distroless/static:nonroot@" + sha(index), index, manifest, config
}

// syntheticGoldens are the golden digests on syntheticBaseDocuments.
var syntheticGoldens = map[string]golden{
	"datasphered": {
		layer:    "sha256:539f3658bbbea28040c7a14162fd8f7792ba7b295f6083245837a8499f03ec8f",
		diffID:   "sha256:f55ba6a4ef5a1c647fe070996316fe9cb66e4bc58a28f2328d4426dfb4a48cd7",
		config:   "sha256:4d04a5be72e6d885a2d9ecc8e0c5004520258af914723e0e33458e180c7660f0",
		manifest: "sha256:4b8f8fbcf494662e1201252b3ee2e44dc073ec01afff36cddc48323c817167b0",
	},
	"fatline": {
		layer:    "sha256:99a16ff39ef5e0e9fa5743a7bda33b096cd615cd827f291645ab5f75fab9cfef",
		diffID:   "sha256:4f185ef4a92e041e7df2a1e740580c030f786f29debf291ffcabbcaa94fbb7e8",
		config:   "sha256:bea64bfe406998cd1be595ec7bc4b6a0456b0f9ee3112434a0aea4a3868db93e",
		manifest: "sha256:5d4b959eee9d818a5f6f309160eb8def184b7fde7835c23639a35fc35a2b729d",
	},
	"shrike": {
		layer:    "sha256:6032526335f83cfb959ad38e7c74b54fb73a3db5696cfe4828084f78753fc2d4",
		diffID:   "sha256:e30dae01802eb251a99236e5a3209f09f5393a9f68c5c93f540bfc5b84976607",
		config:   "sha256:33a8ffac69e483157055eb9dc164b4ab6e12d6efe687e3d500114db6872018e6",
		manifest: "sha256:13871cb866b9fce61894cb864e39b9f4428f687fc4257084108e7d8ac07fa17d",
	},
	"technocore": {
		layer:    "sha256:d908c483fc42eb1c5f160393ba567ffd2e5bfe7d4e14ea15999de7c2659d729b",
		diffID:   "sha256:ddae47631617af6e4fdc2bc532283cbced296af17dc789c80142979d343dfa04",
		config:   "sha256:7483879afeb63293a7dc8c3a331728babdff670e984cb6c7a1ed1a897003795e",
		manifest: "sha256:fa1558a6231ced79b78fc3d2b957eeb3743e9af0bf3ad3d63f44d0fb1f1bbb5d",
	},
}

func TestGoldenDigestsOnASyntheticBase(t *testing.T) {
	pin, index, manifest, config := syntheticBaseDocuments()
	base, err := pinnedBaseFrom(pin, index, manifest, config)
	if err != nil {
		t.Fatal(err)
	}
	got := goldenAssemble(t, base)
	compareGoldens(t, got, syntheticGoldens)
	// The layer columns are the base-independent half of the real-base goldens.
	for _, c := range goldenComponents {
		if got[c.name].layer != realBaseGoldens[c.name].layer || got[c.name].diffID != realBaseGoldens[c.name].diffID {
			t.Errorf("%s's layer is %s / %s; realBaseGoldens says %s / %s", c.name,
				got[c.name].layer, got[c.name].diffID, realBaseGoldens[c.name].layer, realBaseGoldens[c.name].diffID)
		}
	}
}

func TestPinnedBaseFromVerifiesTheDocuments(t *testing.T) {
	pin, index, manifest, config := syntheticBaseDocuments()
	if _, err := pinnedBaseFrom(pin, index, manifest, config); err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Clone(config)
	flipped[10] ^= 0x01
	if _, err := pinnedBaseFrom(pin, index, manifest, flipped); err == nil {
		t.Fatal("a config with one byte changed was accepted")
	}
	if _, err := pinnedBaseFrom(BaseImage, index, manifest, config); err == nil {
		t.Fatal("documents that do not chain to BaseImage were accepted as its documents")
	}
	unpinned, _, _ := strings.Cut(pin, "@")
	if _, err := pinnedBaseFrom(unpinned, index, manifest, config); err == nil {
		t.Fatal("an unpinned base was accepted")
	}
}
