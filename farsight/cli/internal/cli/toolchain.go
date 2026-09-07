package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// The two third-party images an instance runs to turn a repository into a
// deployable image. Neither is FarCast's code, both run inside the instance,
// and one of them holds a credential that can write to the registry.
const (
	// kanikoRepo is where the maintained Kaniko lives. Google archived the
	// original in June 2025 (ADR 0010 decision 10); this is the fork.
	kanikoRepo = "cgr.dev/chainguard/kaniko"

	// gitRepo is a minimal, maintained image with git and a shell in it. The
	// -dev variant is the one that has the shell; the plain variant's
	// entrypoint is git itself and it cannot run the read script.
	gitRepo = "cgr.dev/chainguard/git:latest-dev"
)

// toolchainKind is one of those two images, described well enough to ask for
// it and to refuse it.
type toolchainKind struct {
	what string // "builder" / "fetcher"
	flag string // the flag that supplies it
	repo string // where a maintained one lives
	why  string // why an unpinned one is worse for THIS image specifically

	get func(*config.Toolchain) string
	set func(*config.Toolchain, string)
}

var (
	builderKind = toolchainKind{
		what: "builder",
		flag: "--builder-image",
		repo: kanikoRepo,
		why: "a builder image runs arbitrary build steps while holding a\n" +
			"credential for your registry, so resolving a tag on every build would mean silently\n" +
			"running whatever it points at next.",
		get: func(t *config.Toolchain) string { return t.Builder },
		set: func(t *config.Toolchain, v string) { t.Builder = v },
	}
	fetcherKind = toolchainKind{
		what: "fetcher",
		flag: "--fetcher-image",
		repo: gitRepo,
		why: "the fetcher decides which bytes the approval gate shows you, so a tag\n" +
			"resolved fresh on every run is a reviewer you have not reviewed.",
		get: func(t *config.Toolchain) string { return t.Fetcher },
		set: func(t *config.Toolchain, v string) { t.Fetcher = v },
	}
)

// resolveToolchainImage settles which image to run, and insists on a digest.
//
// The order is flag, then what the instance already recorded. A tag is never
// accepted: the CLI resolves it, reports the digest, and refuses — because
// resolving at run time is trust-on-first-use rather than pinning, and the
// next run would silently get whatever the tag points at then. ADR 0010
// decision 10 wants a reviewed constant; this is how the operator obtains one,
// and recording it is how they stop being asked.
func resolveToolchainImage(ctx context.Context, env *Env, meta *config.InstanceMetadata, k toolchainKind, flagValue string, newBuilder func(func(string)) imageBuilder) (string, error) {
	ref := flagValue
	if ref == "" && meta.Toolchain != nil {
		ref = k.get(meta.Toolchain)
	}
	if ref == "" {
		return "", usagef("%s is required and must be digest-pinned.\n"+
			"A maintained one lives at %s.\n"+
			"Pass that repository with a tag once and this command will report the digest to pin;\n"+
			"pass the digest and %q remembers it.", k.flag, k.repo, meta.Name)
	}
	if isDigestPinned(ref) {
		return ref, nil
	}
	b := newBuilder(func(msg string) { fprintf(env.Err, "  %s\n", msg) })
	pinned, err := b.Resolve(ctx, ref, "", "")
	if err != nil {
		return "", fmt.Errorf("resolve the %s image %q: %w", k.what, ref, err)
	}
	return "", usagef("%s %q is a tag, not a digest.\nIt resolves today to:\n\n  %s\n\nPass that, and %s",
		k.flag, ref, pinned, k.why)
}

// recordToolchainImage writes a reviewed digest into the instance's metadata,
// and reports whether that changed anything.
//
// A change is worth surfacing rather than doing quietly: the image that builds
// and reads an operator's source is not something to swap under them without
// saying so.
func recordToolchainImage(meta *config.InstanceMetadata, k toolchainKind, ref string, now time.Time) (changed bool) {
	if meta.Toolchain == nil {
		meta.Toolchain = &config.Toolchain{}
	}
	if k.get(meta.Toolchain) == ref {
		return false
	}
	k.set(meta.Toolchain, ref)
	meta.Toolchain.RecordedAt = now
	return true
}

func isDigestPinned(ref string) bool {
	_, digest, ok := strings.Cut(ref, "@")
	return ok && isSHA256(digest)
}

// isSHA256 accepts only a complete, lowercase-hex sha256 digest.
func isSHA256(s string) bool {
	hex, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(hex) != 64 {
		return false
	}
	for i := range len(hex) {
		switch ch := hex[i]; {
		case ch >= '0' && ch <= '9', ch >= 'a' && ch <= 'f':
		default:
			return false
		}
	}
	return true
}
