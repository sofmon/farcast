// Package build renders the Kubernetes Job that turns an application's
// Containerfile into an image in the instance's own registry.
//
// [ADR 0010] chose to build applications inside the instance rather than on the
// operator's machine, so that deploying and updating software is not tied to
// one prepared laptop. This package is that decision's workload: an ephemeral
// Job, a ServiceAccount that may push to one repository, and a NetworkPolicy
// naming everywhere the build is allowed to reach.
//
// It renders plain YAML like every other deploy package, and it never runs
// anything itself.
//
// [ADR 0010]: ../../docs/adr/0010-application-image-builds.md
package build

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// Defaults for a build.
const (
	// Namespace is where builds run: beside FarCast's own components, not in
	// the application's namespace. A build is instance machinery, it holds a
	// registry credential, and it must not be visible to — or stoppable
	// alongside — the application it produces.
	Namespace = "farcast-system"

	// ServiceAccount is the identity that pushes. It is separate from every
	// other FarCast component's: the push grant is repo-scoped and belongs to
	// exactly one workload, the same shape ADR 0008 decision 8 uses for the
	// keyholder's bucket.
	ServiceAccount = "farcast-builder"

	// A build is the one FarCast workload where conservative requests cause
	// failures rather than savings — Kaniko extracts and rewrites filesystem
	// layers, and an under-provisioned build fails slowly and then fails.
	RequestCPUMilli = 1000
	RequestMemMiB   = 2048

	// DeadlineSeconds bounds a runaway build. It is a cost control before it
	// is a correctness one: a build that hangs bills for as long as it hangs,
	// and Autopilot charges the whole request.
	DeadlineSeconds = 1800

	// TTLSeconds is how long a finished Job survives so its logs can be read.
	// ADR 0010 says the Job is deleted after the build; this is what deletes
	// it, with a window for the operator to see why a failure failed.
	TTLSeconds = 3600

	// MetadataServer is where a Workload Identity token comes from, on plain
	// HTTP.
	//
	// Allowing it is a real concession and the reason is that there is no
	// alternative: the builder pushes under its own cloud identity, and that
	// identity is minted by asking this address. Denying it and granting the
	// push are the same channel — the first live walk failed with
	// "Unauthenticated request" after the clone and the build had both
	// succeeded.
	//
	// What it grants is bounded by Workload Identity itself: with WI enabled
	// the pod's metadata server returns the identity bound to THIS
	// ServiceAccount and not the node's, so a hostile Containerfile can mint
	// a token that pushes to one repository — which is the capability the
	// build already has. Without WI it would expose the node's service
	// account, and that would be a different and much worse trade.
	MetadataServer = "169.254.169.254/32"
	MetadataPort   = 80

	// NodeLocalDNS is the address GKE's NodeLocal DNSCache listens on.
	//
	// It is link-local, and this package deliberately blocks link-local so a
	// build cannot reach the cloud metadata server at 169.254.169.254. Those
	// two facts collided on the first live walk: DNS resolution failed and the
	// build died looking up its own Git host. So this one address is allowed
	// back, on port 53 only, and the metadata server stays blocked.
	NodeLocalDNS = "169.254.20.10/32"

	// DigestFile is where Kaniko writes the digest it pushed.
	//
	// /dev/termination-log rather than a shared volume: Kubernetes surfaces
	// that file in the Pod's status, so the caller reads the digest from the
	// API server without parsing logs or mounting anything. A digest is 71
	// bytes against the 4 KiB the field allows.
	DigestFile = "/dev/termination-log"

	// SecretGitUser and SecretGitToken are the keys the credential Secret
	// carries, exported so the writer and the reader cannot disagree.
	SecretGitUser  = "username"
	SecretGitToken = "token"

	digestMarker = "@sha256:"
)

// Config parameterizes one application's build.
type Config struct {
	// Instance, Deployment and App identify what is being built. Deployment
	// and App are the manifest's top-level name and the entry's name, which
	// is also the image path ADR 0007 decision 6 fixed.
	Instance   string
	Deployment string
	App        string

	// Builder is the Kaniko image, digest-pinned.
	//
	// There is deliberately no default. Kaniko was archived by Google in June
	// 2025 and continues as a Chainguard fork (ADR 0010 decision 10), so the
	// pinned reference is a recorded constant the caller supplies and reviews
	// — inventing one here would be a digest nobody had checked.
	Builder string

	// Repo is the Git URL to clone and Ref the branch, tag or commit.
	//
	// Containerfile and ContextSubPath are both REPOSITORY-relative, which is
	// how a ./farcast manifest expresses them and how an operator thinks. The
	// translation to what Kaniko wants happens in Render — see
	// dockerfileArg.
	Repo           string
	Ref            string
	Containerfile  string
	ContextSubPath string

	// Destination is the tagged image reference to push. Kaniko reports the
	// digest it produced; the caller resolves and pins that before deploying
	// (ADR 0007 decision 4).
	Destination string

	// GitSecret names the Secret holding a repository-scoped, read-only Git
	// credential. Empty means the repository is public and no credential is
	// mounted — which is a real case and should not require inventing one.
	GitSecret string

	// EgressHosts are the DNS names the build may reach: the Git host and the
	// registry. They are recorded for the operator's benefit; the policy this
	// package renders works in CIDR terms, because Kubernetes NetworkPolicy
	// cannot express a hostname.
	EgressHosts []string

	// Namespace and JobName default to the constants above.
	Namespace string
	JobName   string
}

func (c *Config) withDefaults() {
	if c.Namespace == "" {
		c.Namespace = Namespace
	}
	if c.JobName == "" {
		c.JobName = JobName(c.Deployment, c.App)
	}
	if c.Ref == "" {
		c.Ref = "refs/heads/main"
	}
	if c.Containerfile == "" {
		c.Containerfile = "Containerfile"
	}
}

// JobName is the Job a build runs as. It is stable for a given app so a re-run
// replaces rather than accumulates, and short enough to stay a valid DNS label.
//
// Exported because the caller has to wait on, and read the digest from, the
// same Job this package created — and a second implementation of the name is
// the join that silently watches the wrong object.
func JobName(deployment, app string) string {
	n := "build-" + deployment + "-" + app
	if len(n) > 63 {
		n = n[:63]
	}
	return strings.TrimRight(n, "-")
}

// Render produces the apply stream for one build: the ServiceAccount, the
// NetworkPolicy bounding what the build may reach, and the Job itself.
func Render(c Config) ([]byte, error) {
	c.withDefaults()
	switch {
	case c.Instance == "":
		return nil, fmt.Errorf("build: the instance is required")
	case c.Deployment == "" || c.App == "":
		return nil, fmt.Errorf("build: both the deployment and the app name are required")
	case c.Repo == "":
		return nil, fmt.Errorf("build: no repository to build from")
	case c.Destination == "":
		return nil, fmt.Errorf("build: no destination to push to")
	}
	if c.Builder == "" {
		return nil, fmt.Errorf("build: the builder image is required and must be digest-pinned")
	}
	if !hasDigest(c.Builder) {
		return nil, fmt.Errorf("build: builder image %q is not digest-pinned (want repo@sha256:<64 hex>); "+
			"an unpinned builder is arbitrary code with a registry credential", c.Builder)
	}
	if hasDigest(c.Destination) {
		return nil, fmt.Errorf("build: destination %q is digest-pinned, but a digest is what the build produces", c.Destination)
	}
	if !strings.HasPrefix(c.Repo, "git://") && !strings.HasPrefix(c.Repo, "https://") {
		return nil, fmt.Errorf("build: repository %q must be git:// or https://; a local path would need the source "+
			"to be on the cluster, which is what building here avoids", c.Repo)
	}

	dockerfile, err := dockerfileArg(c.Containerfile, c.ContextSubPath)
	if err != nil {
		return nil, err
	}

	data := templateData{
		Config:          c,
		Dockerfile:      dockerfile,
		ContextURL:      contextURL(c.Repo, c.Ref),
		RequestCPUMilli: RequestCPUMilli,
		RequestMemMiB:   RequestMemMiB,
		DeadlineSeconds: DeadlineSeconds,
		TTLSeconds:      TTLSeconds,
		DigestFile:      DigestFile,
		NodeLocalDNS:    NodeLocalDNS,
		MetadataServer:  MetadataServer,
		MetadataPort:    MetadataPort,
		ServiceAccount:  ServiceAccount,
		SecretGitUser:   SecretGitUser,
		SecretGitToken:  SecretGitToken,
	}
	var buf bytes.Buffer
	if err := workloadTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("build: render the build job: %w", err)
	}
	return buf.Bytes(), nil
}

// dockerfileArg converts a repository-relative Containerfile path into what
// Kaniko's --dockerfile expects.
//
// Kaniko resolves --dockerfile relative to the build CONTEXT, and
// --context-sub-path moves that context into a subdirectory. So a path that is
// correct from the repository root is wrong the moment a sub-path is given —
// and the failure is "please provide a valid path to a Dockerfile", which
// points at the flag rather than at the sub-path that changed its meaning.
//
// Found on the first live walk, after the clone had already succeeded.
func dockerfileArg(containerfile, subPath string) (string, error) {
	if subPath == "" {
		return containerfile, nil
	}
	sub := strings.Trim(subPath, "/") + "/"
	rel := strings.TrimPrefix(strings.TrimPrefix(containerfile, "./"), sub)
	if rel == containerfile && strings.Contains(containerfile, "/") {
		// The Containerfile is not inside the context. Kaniko would refuse
		// with a message about the flag; refusing here names the real
		// mismatch instead.
		return "", fmt.Errorf("build: containerfile %q is not inside the build context %q; "+
			"a Containerfile must live within the context it is built from", containerfile, subPath)
	}
	return rel, nil
}

// contextURL is Kaniko's Git context form: the repository, then the ref after
// a fragment.
func contextURL(repo, ref string) string {
	repo = strings.TrimPrefix(repo, "https://")
	repo = strings.TrimPrefix(repo, "git://")
	return "git://" + repo + "#" + ref
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
	Dockerfile      string
	ContextURL      string
	ServiceAccount  string
	DigestFile      string
	NodeLocalDNS    string
	MetadataServer  string
	MetadataPort    int
	SecretGitUser   string
	SecretGitToken  string
	RequestCPUMilli int
	RequestMemMiB   int
	DeadlineSeconds int
	TTLSeconds      int
}

var workloadTemplate = template.Must(template.New("build").Parse(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{.ServiceAccount}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: farcast-builder
    app.kubernetes.io/managed-by: farcast
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{.JobName}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: farcast-builder
    app.kubernetes.io/managed-by: farcast
# What a build may reach.
#
# ADR 0005 denies egress by default and a build is not exempt from that
# reasoning — it is the one FarCast workload that runs code the operator wrote
# rather than code FarCast compiled, so the surface it can reach is the surface
# an untrusted Containerfile can reach.
#
# Kubernetes NetworkPolicy cannot express a hostname, so this is CIDR-shaped
# and therefore coarser than the allowlist FatLine enforces for applications.
# It is a bound rather than a boundary, and saying so is the point.
{{- if .EgressHosts}}
# Declared for this build: {{range .EgressHosts}}{{.}} {{end}}
{{- end}}
spec:
  podSelector:
    matchLabels:
      farcast.sofmon.com/build: {{.JobName}}
  policyTypes:
    - Ingress
    - Egress
  # Nothing may reach a build. It serves nothing and listens for nothing.
  ingress: []
  egress:
    # DNS, by both of the paths a GKE cluster may use.
    #
    # The namespaceSelector covers a cluster whose pods talk to kube-dns
    # directly. The ipBlock covers NodeLocal DNSCache, which listens on a
    # LINK-LOCAL address on the node — and link-local is otherwise blocked
    # below, to keep a build away from the cloud metadata server. Allowing
    # exactly this one address on port 53 keeps both properties: DNS resolves,
    # 169.254.169.254 does not.
    #
    # Found on the first live walk: without this the build failed with
    # "lookup github.com: i/o timeout", which reads like a network outage and
    # is a policy.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
        - ipBlock:
            cidr: {{.NodeLocalDNS}}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # The Workload Identity token endpoint, on plain HTTP. This is how the
    # builder authenticates its push, and it is the ONLY link-local address
    # reachable — the rule below still excludes the range as a whole.
    - to:
        - ipBlock:
            cidr: {{.MetadataServer}}
      ports:
        - protocol: TCP
          port: {{.MetadataPort}}
    # The registry it pushes to and the Git host it clones from, over TLS.
    # Both are outside the cluster, and neither can be named more precisely
    # than this without a hostname-aware policy engine.
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              # The cluster's own ranges: a build has no business reaching
              # another pod, a Service, or the node it runs on.
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
              # Link-local as a whole stays excluded here. The two
              # addresses the build genuinely needs — DNS and the Workload
              # Identity token endpoint — are allowed by their own rules
              # above, each as a /32 on one port.
              - 169.254.0.0/16
      ports:
        - protocol: TCP
          port: 443
---
apiVersion: batch/v1
kind: Job
metadata:
  name: {{.JobName}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: farcast-builder
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: {{.Deployment}}
    farcast.sofmon.com/build: {{.JobName}}
    # Builds are instance machinery, not applications. A cost shutdown stops
    # applications; stopping a half-finished build would leave an image that
    # is neither the old one nor the new one, and the Job's own deadline is
    # what bounds its cost instead.
    farcast.sofmon.com/tier: system
spec:
  # One attempt. A build failure is deterministic — a Containerfile that does
  # not compile does not compile twice — so retrying spends money to reach the
  # same error.
  backoffLimit: 0
  # A hung build bills for as long as it hangs, and Autopilot charges the whole
  # request whether it is used or not.
  activeDeadlineSeconds: {{.DeadlineSeconds}}
  ttlSecondsAfterFinished: {{.TTLSeconds}}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: farcast-builder
        app.kubernetes.io/managed-by: farcast
        app.kubernetes.io/part-of: {{.Deployment}}
        farcast.sofmon.com/build: {{.JobName}}
        farcast.sofmon.com/tier: system
    spec:
      restartPolicy: Never
      serviceAccountName: {{.ServiceAccount}}
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: kaniko
          image: {{.Builder}}
          args:
            - --context={{.ContextURL}}
{{- if .ContextSubPath}}
            - --context-sub-path={{.ContextSubPath}}
{{- end}}
            - --dockerfile={{.Dockerfile}}
            - --destination={{.Destination}}
            # Where the caller reads the digest back from, without parsing
            # logs: Kubernetes surfaces this file in the Pod's status.
            - --digest-file={{.DigestFile}}
            # One layer for the whole build. Layer caching would need a
            # persistent volume, and a build that keeps state between runs is
            # a build whose output depends on what ran before it.
            - --single-snapshot
            - --no-push-cache
{{- if .GitSecret}}
          env:
            - name: GIT_USERNAME
              valueFrom:
                secretKeyRef:
                  name: {{.GitSecret}}
                  key: {{.SecretGitUser}}
            - name: GIT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{.GitSecret}}
                  key: {{.SecretGitToken}}
{{- end}}
          resources:
            requests:
              cpu: {{.RequestCPUMilli}}m
              memory: {{.RequestMemMiB}}Mi
          securityContext:
            allowPrivilegeEscalation: false
            # readOnlyRootFilesystem is deliberately ABSENT, and this is the
            # one place FarCast cannot copy its own hardening. Kaniko builds
            # by extracting image layers into its own root filesystem and
            # running build steps against them: a read-only root does not make
            # it safer, it makes it non-functional.
            capabilities:
              # Dropped, then only what unpacking a filesystem needs. Kaniko
              # never asks for privileged mode — that is why it is admissible
              # on Autopilot at all — and every capability below is in
              # Autopilot's permitted set (ADR 0003).
              drop:
                - ALL
              add:
                - CHOWN
                - DAC_OVERRIDE
                - FOWNER
                - FSETID
                - SETGID
                - SETUID
                - MKNOD
                - SYS_CHROOT
          terminationMessagePolicy: File
`))
