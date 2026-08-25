// Package oci is a minimal, standard-library OCI-distribution client: exactly
// enough of the registry wire protocol to pull a digest-pinned base image, lay
// one layer of our own on top, and push the result — with no container engine
// and no third-party dependency (ADR 0007).
//
// FarCast owns this code rather than vendoring a registry library because the
// CLI holds the instance's cloud credentials and its CA key, so every module in
// its dependency tree is attack surface aimed at the operator's machine. The
// established registry libraries drag seven to nine modules each — Docker's
// config and credential-helper libraries among them — to serve a case that
// needs none of what they handle: one digest-pinned base, one target registry,
// blobs of a few megabytes, and an auth token the CLI mints itself. The cost of
// owning it is wire-protocol correctness, which is why this package is tested
// against an httptest registry rather than trusted by inspection.
//
// The package knows nothing about FarCast — it is pure protocol, and the
// FarCast-shaped decisions (which base, which paths, which platform) live in
// the image package. Registries are treated as untrusted transport, never as
// authorities: every manifest and every blob is verified against the digest
// that addressed it, so a compromised registry or an intercepted connection
// cannot substitute content behind a pin. Credentials are never logged, never
// placed in a URL, and never sent over plaintext HTTP to a non-loopback host.
package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Media types of the manifest, config, and layer flavours FarCast handles. Both
// the OCI set and the older Docker v2 set are supported because registries in
// the wild still serve either: gcr.io publishes distroless as an OCI index,
// while plenty of bases are still Docker manifest lists. An assembled image
// keeps whichever flavour its base used (see AppendLayer) — mixing them
// produces manifests some registries reject.
const (
	MediaTypeOCIManifest  = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex     = "application/vnd.oci.image.index.v1+json"
	MediaTypeOCIConfig    = "application/vnd.oci.image.config.v1+json"
	MediaTypeOCILayerGzip = "application/vnd.oci.image.layer.v1.tar+gzip"

	MediaTypeDockerManifest  = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerIndex     = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeDockerConfig    = "application/vnd.docker.container.image.v1+json"
	MediaTypeDockerLayerGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// ErrNotFound reports that a reference, manifest, or blob does not exist in the
// registry. It is a sentinel so callers can preflight — `farcast connect` asks
// "is this image already pushed?" and must tell a genuine miss (build it) from
// a permission or network failure (stop and report), never treating the second
// as the first.
var ErrNotFound = errors.New("oci: not found")

// Error is a registry response the client could not use. It carries the status
// and a truncated copy of the registry's error body for diagnosis; request
// headers are deliberately never included, since that is where credentials
// live.
type Error struct {
	Op     string // what was attempted, e.g. "GET manifest"
	Ref    string // the reference or URL involved
	Status int    // HTTP status code
	Body   string // truncated response body
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("oci: %s %s: registry returned %d", e.Op, e.Ref, e.Status)
	if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

// Unwrap maps a 404 onto ErrNotFound so callers can use errors.Is for the one
// distinction that changes control flow.
func (e *Error) Unwrap() error {
	if e.Status == http.StatusNotFound {
		return ErrNotFound
	}
	return nil
}

// Platform selects one entry out of a multi-platform index. FarCast only ever
// asks for linux/amd64 (GKE Autopilot nodes), but the field is explicit so the
// selection is a decision in the caller rather than a guess here.
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

// String renders the platform in the conventional os/arch[/variant] form.
func (p Platform) String() string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// Descriptor addresses one piece of content by digest. The digest — not the
// URL, not the tag — is the identity: everything this package fetches is
// checked against the descriptor that pointed at it.
type Descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platform  *Platform `json:"platform,omitempty"`
}

// Manifest is an OCI image manifest (or its Docker v2 equivalent — the two are
// structurally identical and differ only in media types).
type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Index is an OCI image index (or a Docker manifest list): a set of per-platform
// manifests behind one digest.
type Index struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Manifests     []Descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Layer is one image layer held in memory: the compressed bytes exactly as the
// registry stores them, the descriptor addressing them, and the digest of the
// uncompressed tar (the diffID the image config records).
//
// Keeping the compressed bytes verbatim is what makes a cross-registry copy
// possible: the base's layers are re-pushed to the instance's own registry
// byte-for-byte, so their digests — and therefore the pin — survive the move.
// Buffering in memory is deliberate; FarCast's images are a few megabytes and
// the simplicity is worth more than streaming here (ADR 0007).
type Layer struct {
	Descriptor Descriptor
	Blob       []byte
	DiffID     string
}

// Image is a complete image held in memory: its manifest, its config blob, and
// every layer's bytes.
type Image struct {
	// Manifest describes the image; its Config and Layers descriptors mirror
	// the Config and Layers fields below.
	Manifest Manifest
	// Config is the raw image-configuration JSON, addressed by
	// Manifest.Config.Digest.
	Config []byte
	// Layers are in manifest order, each verified against its descriptor.
	Layers []Layer
	// Digest is the manifest digest this image was pulled under. It is empty
	// for an image assembled locally — Push computes and returns the digest of
	// what it actually wrote, which is the value a deploy pins.
	Digest string
}

// RunConfig is the runtime section of an image configuration — the fields
// FarCast reads or sets. Everything else in the section survives untouched,
// because AppendLayer edits the configuration as a generic JSON document.
type RunConfig struct {
	Entrypoint []string `json:"Entrypoint,omitempty"`
	Cmd        []string `json:"Cmd,omitempty"`
	Env        []string `json:"Env,omitempty"`
	User       string   `json:"User,omitempty"`
	WorkingDir string   `json:"WorkingDir,omitempty"`
}

// RootFS is the layer chain of an image configuration, listed as uncompressed
// layer digests (diffIDs) in application order.
type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

// ImageConfig is the part of an OCI image configuration this package models.
// It is a read-only view for callers and tests; mutation goes through
// AppendLayer.
type ImageConfig struct {
	Architecture string    `json:"architecture"`
	OS           string    `json:"os"`
	Variant      string    `json:"variant,omitempty"`
	Config       RunConfig `json:"config"`
	RootFS       RootFS    `json:"rootfs"`
}

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repoPattern   = regexp.MustCompile(`^[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*$`)
	tagPattern    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

// Reference is a parsed image reference: a registry host, a repository path,
// and an identifier that is a tag, a digest, or both (the canonical
// `repo:tag@sha256:…` form, which is how FarCast records a pinned base while
// keeping the human-readable tag beside it).
type Reference struct {
	Registry   string // host, optionally with a port — e.g. "gcr.io", "europe-west1-docker.pkg.dev"
	Repository string // path within the registry — e.g. "distroless/static"
	Tag        string // empty when the reference is digest-only
	Digest     string // "sha256:…", empty when the reference is tag-only
}

// ParseReference parses an image reference. The registry host is mandatory:
// FarCast never talks to an implied default registry, because "which registry"
// is precisely the decision ADR 0007 makes explicit, and silently defaulting to
// Docker Hub would reintroduce a third party into the runtime path.
func ParseReference(s string) (Reference, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Reference{}, errors.New("oci: empty image reference")
	}
	var ref Reference
	if i := strings.LastIndex(s, "@"); i >= 0 {
		ref.Digest = s[i+1:]
		s = s[:i]
		if !digestPattern.MatchString(ref.Digest) {
			return Reference{}, fmt.Errorf("oci: invalid digest %q (want sha256:<64 hex>)", ref.Digest)
		}
	}
	host, rest, ok := strings.Cut(s, "/")
	if !ok || !looksLikeHost(host) {
		return Reference{}, fmt.Errorf("oci: reference %q must include a registry host (e.g. gcr.io/distroless/static)", s)
	}
	ref.Registry = host
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		ref.Tag = rest[i+1:]
		rest = rest[:i]
		if !tagPattern.MatchString(ref.Tag) {
			return Reference{}, fmt.Errorf("oci: invalid tag %q", ref.Tag)
		}
	}
	ref.Repository = rest
	if !repoPattern.MatchString(ref.Repository) {
		return Reference{}, fmt.Errorf("oci: invalid repository path %q (lowercase alphanumerics, separated by . _ - or /)", ref.Repository)
	}
	if ref.Tag == "" && ref.Digest == "" {
		ref.Tag = "latest"
	}
	return ref, nil
}

// looksLikeHost distinguishes a registry host from the first path element of a
// repository. A host either carries a dot, carries a port, or is localhost —
// the same rule every registry client uses.
func looksLikeHost(s string) bool {
	return s == "localhost" || strings.ContainsAny(s, ".:")
}

// String renders the reference in the form it was parsed from.
func (r Reference) String() string {
	s := r.Registry + "/" + r.Repository
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// Identifier returns what goes in the URL path of a manifest request: the
// digest when the reference is pinned, otherwise the tag. A pinned reference
// resolves by content, so a tag that has since moved cannot redirect it.
func (r Reference) Identifier() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

// WithDigest returns the reference pinned to digest, dropping any tag. The
// result is the form a deploy records (`repo@sha256:…`): the tag is a mutable
// pointer and has no place in what the cluster is told to run.
func (r Reference) WithDigest(digest string) Reference {
	r.Tag = ""
	r.Digest = digest
	return r
}

// digestOf returns the sha256 descriptor digest of b.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
