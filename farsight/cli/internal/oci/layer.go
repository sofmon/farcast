package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"
)

// layerEpoch is the timestamp every generated tar entry carries. A build that
// embeds the wall clock produces a different digest every run, which would
// defeat the point of a content-addressed artifact chain: the same source and
// the same base must yield the same image, so that "did anything actually
// change?" is answerable by comparing digests (ADR 0007's reproducibility
// goal).
var layerEpoch = time.Unix(0, 0).UTC()

// defaultFileMode is used for a File that does not state one. Layers FarCast
// builds hold executables, so the caller normally sets 0o755 explicitly.
const defaultFileMode fs.FileMode = 0o644

// File is one regular file to place into a layer, at an absolute path inside
// the image.
type File struct {
	Path string      // absolute path in the image, e.g. "/fatline"
	Mode fs.FileMode // permission bits; zero means defaultFileMode
	Data []byte
}

// BuildLayer packs files into a gzipped tar layer and returns it with both
// digests the image format needs: the compressed digest that addresses the blob
// in the registry, and the uncompressed diffID that the image configuration
// records in its rootfs chain.
//
// The tar is deterministic — entries sorted by path, a fixed modification time,
// numeric owner 0 with no user or group names, and an explicit mode — so the
// same input always produces the same layer digest.
func BuildLayer(files []File) (Layer, error) {
	if len(files) == 0 {
		return Layer{}, errors.New("oci: BuildLayer needs at least one file")
	}
	sorted := slices.Clone(files)
	slices.SortFunc(sorted, func(a, b File) int { return strings.Compare(a.Path, b.Path) })

	var compressed bytes.Buffer
	zw, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return Layer{}, fmt.Errorf("oci: gzip writer: %w", err)
	}
	diff := sha256.New()
	tw := tar.NewWriter(io.MultiWriter(diff, zw))

	dirs := map[string]bool{}
	for _, f := range sorted {
		name := path.Clean("/" + f.Path)
		if name == "/" || name == "." {
			return Layer{}, fmt.Errorf("oci: file path %q is not a file", f.Path)
		}
		for _, dir := range ancestors(name) {
			if dirs[dir] {
				continue
			}
			dirs[dir] = true
			if err := tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir,
				Name:     strings.TrimPrefix(dir, "/") + "/",
				Mode:     0o755,
				ModTime:  layerEpoch,
			}); err != nil {
				return Layer{}, fmt.Errorf("oci: write tar directory %s: %w", dir, err)
			}
		}
		mode := f.Mode.Perm()
		if mode == 0 {
			mode = defaultFileMode
		}
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     strings.TrimPrefix(name, "/"),
			Mode:     int64(mode),
			Size:     int64(len(f.Data)),
			ModTime:  layerEpoch,
		}); err != nil {
			return Layer{}, fmt.Errorf("oci: write tar header %s: %w", f.Path, err)
		}
		if _, err := tw.Write(f.Data); err != nil {
			return Layer{}, fmt.Errorf("oci: write tar body %s: %w", f.Path, err)
		}
	}
	if err := tw.Close(); err != nil {
		return Layer{}, fmt.Errorf("oci: close tar: %w", err)
	}
	if err := zw.Close(); err != nil {
		return Layer{}, fmt.Errorf("oci: close gzip: %w", err)
	}

	blob := compressed.Bytes()
	return Layer{
		Descriptor: Descriptor{
			MediaType: MediaTypeOCILayerGzip,
			Digest:    digestOf(blob),
			Size:      int64(len(blob)),
		},
		Blob:   blob,
		DiffID: "sha256:" + hex.EncodeToString(diff.Sum(nil)),
	}, nil
}

// ancestors lists the directory entries a path needs, shallowest first, with
// the root itself excluded.
func ancestors(name string) []string {
	var dirs []string
	for dir := path.Dir(name); dir != "/" && dir != "."; dir = path.Dir(dir) {
		dirs = append(dirs, dir)
	}
	slices.Reverse(dirs)
	return dirs
}

// AppendOptions describes the image AppendLayer produces.
type AppendOptions struct {
	// Platform is written into the configuration's os and architecture. It
	// must match what the appended binary was compiled for — a mismatch is the
	// classic silent failure, where the kubelet pulls happily and the container
	// dies with an exec format error.
	Platform Platform
	// Entrypoint replaces the base image's entrypoint. Setting it also clears
	// any inherited Cmd, matching what an ENTRYPOINT instruction does, so the
	// base's default arguments cannot leak into our process's argv.
	Entrypoint []string
	// Created stamps the configuration and the history entry. Zero selects the
	// Unix epoch, which keeps the build reproducible.
	Created time.Time
	// CreatedBy is the history line recorded for the appended layer.
	CreatedBy string
}

// AppendLayer returns a new image: base with layer added on top, its
// configuration updated to match, and its manifest rebuilt. The base is not
// modified.
//
// The configuration is edited as a generic JSON document rather than through a
// typed round trip, so everything the base declares and FarCast does not
// model — its environment, its non-root user, any vendor extension — survives
// exactly. Dropping such a field silently (the base's nonroot user, say) would
// change the security posture of the running container without anything in the
// diff saying so.
//
// The manifest keeps the base's flavour (OCI or Docker v2) rather than
// normalising: mixed-flavour manifests are rejected by some registries, and the
// base's own choice is the safe one to follow.
func AppendLayer(base *Image, layer Layer, opts AppendOptions) (*Image, error) {
	switch {
	case base == nil || len(base.Config) == 0:
		return nil, errors.New("oci: AppendLayer needs a pulled base image")
	case layer.Descriptor.Digest == "" || layer.DiffID == "":
		return nil, errors.New("oci: AppendLayer needs a layer with both a digest and a diffID")
	case opts.Platform.OS == "" || opts.Platform.Architecture == "":
		return nil, errors.New("oci: AppendLayer needs a target platform")
	}

	dec := json.NewDecoder(bytes.NewReader(base.Config))
	dec.UseNumber() // keep integers byte-identical across the round trip
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("oci: decode base image config: %w", err)
	}

	created := opts.Created
	if created.IsZero() {
		created = layerEpoch
	}
	stamp := created.UTC().Format(time.RFC3339)

	doc["architecture"] = opts.Platform.Architecture
	doc["os"] = opts.Platform.OS
	if opts.Platform.Variant != "" {
		doc["variant"] = opts.Platform.Variant
	} else {
		delete(doc, "variant")
	}
	doc["created"] = stamp

	rootfs, ok := doc["rootfs"].(map[string]any)
	if !ok {
		return nil, errors.New("oci: base image config has no rootfs")
	}
	diffIDs, err := stringsOf(rootfs["diff_ids"])
	if err != nil {
		return nil, fmt.Errorf("oci: base image config rootfs.diff_ids: %w", err)
	}
	rootfs["diff_ids"] = append(diffIDs, layer.DiffID)

	createdBy := opts.CreatedBy
	if createdBy == "" {
		createdBy = "farcast: append layer"
	}
	history, _ := doc["history"].([]any)
	doc["history"] = append(history, map[string]any{"created": stamp, "created_by": createdBy})

	runCfg, ok := doc["config"].(map[string]any)
	if !ok {
		runCfg = map[string]any{}
	}
	if len(opts.Entrypoint) > 0 {
		runCfg["Entrypoint"] = slices.Clone(opts.Entrypoint)
		delete(runCfg, "Cmd")
	}
	doc["config"] = runCfg

	config, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("oci: encode image config: %w", err)
	}

	f := flavourOf(base.Manifest.MediaType)
	if layer.Descriptor.MediaType == "" ||
		layer.Descriptor.MediaType == MediaTypeOCILayerGzip ||
		layer.Descriptor.MediaType == MediaTypeDockerLayerGzip {
		layer.Descriptor.MediaType = f.layer
	}

	layers := append(slices.Clone(base.Layers), layer)
	descriptors := make([]Descriptor, 0, len(layers))
	for _, l := range layers {
		descriptors = append(descriptors, l.Descriptor)
	}

	return &Image{
		Manifest: Manifest{
			SchemaVersion: 2,
			MediaType:     f.manifest,
			// Annotations are deliberately not inherited: they describe the
			// base, and carrying them forward would make our image claim the
			// base's provenance.
			Config: Descriptor{
				MediaType: f.config,
				Digest:    digestOf(config),
				Size:      int64(len(config)),
			},
			Layers: descriptors,
		},
		Config: config,
		Layers: layers,
	}, nil
}

// stringsOf converts a generically decoded JSON array into a string slice.
func stringsOf(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	raw, ok := v.([]any)
	if !ok {
		return nil, errors.New("not an array")
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s, ok := item.(string)
		if !ok {
			return nil, errors.New("array holds a non-string")
		}
		out = append(out, s)
	}
	return out, nil
}

// flavour groups the three media types that must agree within one manifest.
type flavour struct{ manifest, config, layer string }

func flavourOf(manifestType string) flavour {
	switch manifestType {
	case MediaTypeDockerManifest, MediaTypeDockerIndex:
		return flavour{MediaTypeDockerManifest, MediaTypeDockerConfig, MediaTypeDockerLayerGzip}
	default:
		return flavour{MediaTypeOCIManifest, MediaTypeOCIConfig, MediaTypeOCILayerGzip}
	}
}
