// Package fetch renders the Kubernetes Job that reads an application's
// ./farcast manifest inside the instance.
//
// [ADR 0010] decision 6 puts the manifest read in the instance rather than on
// the operator's machine, and decision 11 says why it needs a Job of its own:
// Kaniko's executor image is built from scratch, so it has neither a shell nor
// git, and it clones only as part of building — which is after the moment the
// operator has to approve what is about to run.
//
// So this Job runs first. It clones at the requested ref, prints the manifest
// on stdout, and reports the resolved commit SHA and a digest of the file it
// read through the Pod's termination message. The caller approves that, then
// builds the SAME commit rather than the branch name.
//
// It renders plain YAML like every other deploy package, and it never runs
// anything itself.
//
// [ADR 0010]: ../../docs/adr/0010-application-image-builds.md
package fetch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Defaults for a fetch.
const (
	// Namespace is where a fetch runs: beside FarCast's own components, for
	// the same reason a build does. It is instance machinery, it may hold a
	// repository credential, and it must not be visible to the applications
	// it is about to describe.
	Namespace = "farcast-system"

	// ServiceAccount is the identity a fetch runs as, and it is deliberately
	// NOT the builder's.
	//
	// The builder's ServiceAccount carries a Workload Identity grant that can
	// write to the instance's registry. A fetch reads one text file and
	// pushes nothing, so giving it that identity would hand a repository
	// credential to a workload that has no use for one. This account has no
	// binding at all.
	ServiceAccount = "farcast-fetcher"

	// A fetch is a shallow clone of one ref. It is bounded by the network, not
	// by CPU — but git packs objects in memory, and a repository with large
	// blobs in its tip commit will use more than a trivial figure. On a
	// cluster without bursting Autopilot raises these to its own 250m/512Mi
	// floor anyway.
	RequestCPUMilli = 200
	RequestMemMiB   = 512

	// DeadlineSeconds bounds a fetch that hangs. It is far shorter than a
	// build's: a shallow clone that has not finished in five minutes is not
	// going to, and every second of it bills.
	DeadlineSeconds = 300

	// TTLSeconds is how long a finished Job survives so a failure can be read.
	// Shorter than a build's hour — the manifest is consumed immediately, and
	// what remains is a diagnostic window.
	TTLSeconds = 900

	// ReportFile is where the fetch writes the commit SHA and the manifest
	// digest. Kubernetes surfaces it in the Pod's status, so the caller reads
	// both from the API server rather than parsing them back out of the logs
	// that carry the manifest itself.
	ReportFile = "/dev/termination-log"

	// NodeLocalDNS is the address GKE's NodeLocal DNSCache listens on. It is
	// link-local, and this package blocks link-local as a whole, so this one
	// address is allowed back on port 53 only. The 4.2 walk found this twice.
	NodeLocalDNS = "169.254.20.10/32"

	// SecretGitUser and SecretGitToken are the keys the credential Secret
	// carries. They are the same keys the build reads, because it is the same
	// Secret: one repository-scoped, read-only credential serves both halves
	// of deploying from a private repository.
	SecretGitUser  = "username"
	SecretGitToken = "token"

	// DefaultManifest is the file this reads. The manifest's name is fixed by
	// the specification, not chosen per repository.
	DefaultManifest = "farcast"

	// FSGroup owns the workspace volume.
	//
	// A fetcher image runs as a non-root user, and an emptyDir it cannot
	// write to is a clone that fails on its first file. 65532 is the nonroot
	// group Wolfi and distroless both use; an image that runs as something
	// else needs Config.FSGroup set to match, and the symptom of getting it
	// wrong is "could not create work tree dir".
	FSGroup = 65532

	// WorkDir is the writable volume the clone lands in. The root filesystem
	// is read-only, so everything git writes — the clone, the askpass helper,
	// its config — lives here and dies with the Pod.
	WorkDir = "/workspace"

	digestMarker = "@sha256:"
)

// Config parameterizes one manifest read.
type Config struct {
	// Instance is the instance this fetch belongs to, recorded as a label.
	Instance string

	// Fetcher is the git-capable image, digest-pinned.
	//
	// There is deliberately no default, for the same reason the builder has
	// none (ADR 0010 decision 10): a digest nobody in this project has
	// verified would be worse than asking the operator for one.
	Fetcher string

	// Repo is the Git URL to clone and Ref the branch, tag or commit to read.
	Repo string
	Ref  string

	// Manifest is the repository-relative path of the file to read. It
	// defaults to ./farcast and exists so a repository that keeps its
	// manifest elsewhere is a configuration rather than a fork.
	Manifest string

	// GitSecret names the Secret holding a repository-scoped, read-only Git
	// credential. Empty means the repository is public.
	GitSecret string

	// EgressHosts are the DNS names this fetch may reach, recorded for the
	// operator. The rendered policy is CIDR-shaped because Kubernetes
	// NetworkPolicy cannot express a hostname.
	EgressHosts []string

	// Namespace, JobName and FSGroup default to the constants above.
	Namespace string
	JobName   string
	FSGroup   int
}

func (c *Config) withDefaults() {
	if c.Namespace == "" {
		c.Namespace = Namespace
	}
	if c.Ref == "" {
		c.Ref = "refs/heads/main"
	}
	if c.Manifest == "" {
		c.Manifest = DefaultManifest
	}
	if c.FSGroup == 0 {
		c.FSGroup = FSGroup
	}
	if c.JobName == "" {
		c.JobName = JobName(c.Repo, c.Ref, c.Manifest)
	}
}

// Job is the name of the Job this configuration renders.
//
// It exists because JobName takes the ref, and an empty ref is defaulted
// before it is used — so a caller that computed the name from its own
// un-defaulted Config would wait on a Job that was never created. Two
// derivations of one name is the join that silently watches nothing.
func (c Config) Job() string {
	c.withDefaults()
	return c.JobName
}

// JobName is the Job a fetch runs as.
//
// It cannot be named after the deployment, because the deployment's name is
// inside the manifest this Job exists to read. So it is named after what the
// caller does know — the repository, the ref and the manifest path — with a
// hash to keep two repositories whose last path segment is "api" apart.
//
// The manifest path is in the hash because a Job's spec.template is immutable:
// two deployments from one repository at one ref, differing only in which
// manifest they read, would otherwise resolve to the same Job name and the
// second would be refused by the API server. A repository holding several
// manifests is an ordinary layout, and manifest/examples/manifest-elsewhere
// exists to demonstrate exactly it.
//
// Exported because the caller waits on, and reads both the manifest and the
// commit from, the same Job this package created. A second implementation of
// the name is the join that silently watches the wrong object.
func JobName(repo, ref, manifest string) string {
	sum := sha256.Sum256([]byte(repo + "#" + ref + "#" + manifest))
	n := "fetch-" + label(basename(repo)) + "-" + hex.EncodeToString(sum[:])[:8]
	if len(n) > 63 {
		n = n[len(n)-63:]
	}
	return strings.Trim(n, "-")
}

// basename is the repository's last path segment, without a .git suffix.
func basename(repo string) string {
	repo = strings.TrimSuffix(strings.TrimRight(repo, "/"), ".git")
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		repo = repo[i+1:]
	}
	return repo
}

// label reduces a string to something a DNS label accepts, so a repository
// named "My_Repo.v2" does not produce a Job Kubernetes refuses to create.
func label(s string) string {
	var b strings.Builder
	for i := range len(s) {
		switch ch := s[i]; {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
			b.WriteByte(ch)
		case ch >= 'A' && ch <= 'Z':
			b.WriteByte(ch + ('a' - 'A'))
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// Render produces the apply stream for one fetch: the ServiceAccount, the
// NetworkPolicy bounding what it may reach, and the Job itself.
func Render(c Config) ([]byte, error) {
	c.withDefaults()
	switch {
	case c.Instance == "":
		return nil, fmt.Errorf("fetch: the instance is required")
	case c.Repo == "":
		return nil, fmt.Errorf("fetch: no repository to read from")
	}
	if c.Fetcher == "" {
		return nil, fmt.Errorf("fetch: the fetcher image is required and must be digest-pinned")
	}
	if !hasDigest(c.Fetcher) {
		return nil, fmt.Errorf("fetch: fetcher image %q is not digest-pinned (want repo@sha256:<64 hex>); "+
			"an unpinned fetcher decides what the approval gate is shown", c.Fetcher)
	}
	if !strings.HasPrefix(c.Repo, "https://") {
		return nil, fmt.Errorf("fetch: repository %q must be https://; the fetch clones with git over HTTPS "+
			"and uses the same read-only credential the build does", c.Repo)
	}

	// Every one of these reaches a shell as an environment variable rather
	// than as script text, so a quote or a newline cannot become a command.
	// The values are still checked, because a value that would need escaping
	// is a value the operator got wrong rather than one to smuggle through.
	for _, f := range []struct{ what, value string }{
		{"repository", c.Repo},
		{"ref", c.Ref},
		{"manifest path", c.Manifest},
		{"git secret", c.GitSecret},
	} {
		if err := plain(f.what, f.value); err != nil {
			return nil, err
		}
	}

	data := templateData{
		Config: c,
		// The script is a constant with two placeholders rather than a
		// template of its own: keeping shell out of text/template means a
		// value can never be rendered INTO the script, only passed to it.
		Script:          scriptFor(WorkDir, ReportFile),
		ServiceAccount:  ServiceAccount,
		ReportFile:      ReportFile,
		WorkDir:         WorkDir,
		NodeLocalDNS:    NodeLocalDNS,
		SecretGitUser:   SecretGitUser,
		SecretGitToken:  SecretGitToken,
		RequestCPUMilli: RequestCPUMilli,
		RequestMemMiB:   RequestMemMiB,
		DeadlineSeconds: DeadlineSeconds,
		TTLSeconds:      TTLSeconds,
	}
	var buf bytes.Buffer
	if err := workloadTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("fetch: render the fetch job: %w", err)
	}
	return buf.Bytes(), nil
}

// plain rejects anything that would not survive being a YAML scalar or a shell
// word intact.
func plain(what, value string) error {
	for i := range len(value) {
		switch ch := value[i]; {
		case ch < 0x20, ch == 0x7f:
			return fmt.Errorf("fetch: the %s contains a control character", what)
		case ch == '"', ch == '\\', ch == '$', ch == '`', ch == '\'':
			return fmt.Errorf("fetch: the %s %q contains %q, which a git URL, ref or path does not need", what, value, string(ch))
		}
	}
	return nil
}

func hasDigest(image string) bool {
	_, digest, ok := strings.Cut(image, digestMarker)
	if !ok || len(digest) != 64 {
		return false
	}
	for i := range len(digest) {
		switch ch := digest[i]; {
		case ch >= '0' && ch <= '9', ch >= 'a' && ch <= 'f':
		default:
			return false
		}
	}
	return true
}

type templateData struct {
	Config
	Script          string
	ServiceAccount  string
	ReportFile      string
	WorkDir         string
	NodeLocalDNS    string
	SecretGitUser   string
	SecretGitToken  string
	RequestCPUMilli int
	RequestMemMiB   int
	DeadlineSeconds int
	TTLSeconds      int
}
