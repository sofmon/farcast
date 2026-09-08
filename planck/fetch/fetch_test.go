package fetch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/sofmon/farcast/planck/build"
)

const digest = "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func sampleConfig() Config {
	return Config{
		Instance:    "p43",
		Fetcher:     "cgr.dev/chainguard/git" + digest,
		Repo:        "https://github.com/example/my-platform",
		Ref:         "refs/heads/main",
		GitSecret:   "my-platform-git",
		EgressHosts: []string{"github.com"},
	}
}

func render(t *testing.T, c Config) (string, map[string]map[string]any) {
	t.Helper()
	out, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]map[string]any{}
	for _, d := range strings.Split(string(out), "\n---\n") {
		if strings.TrimSpace(d) == "" {
			continue
		}
		var m map[string]any
		if err := yaml.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("rendered document is not valid YAML: %v\n%s", err, d)
		}
		kind, _ := m["kind"].(string)
		docs[kind] = m
	}
	return string(out), docs
}

func at(t *testing.T, doc map[string]any, path ...string) any {
	t.Helper()
	var cur any = doc
	for i, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v: level %q is not a map", path[:i], k)
		}
		cur, ok = m[k]
		if !ok {
			t.Fatalf("%v: missing key %q", path[:i], k)
		}
	}
	return cur
}

func container(t *testing.T, docs map[string]map[string]any) map[string]any {
	t.Helper()
	cs := at(t, docs["Job"], "spec", "template", "spec", "containers").([]any)
	if len(cs) != 1 {
		t.Fatalf("the fetch pod has %d containers, want 1", len(cs))
	}
	return cs[0].(map[string]any)
}

// shell is the script as the container will actually receive it, read back out
// of the parsed YAML rather than from the Go constant. Reading it from the
// constant would test the string and not the document, and a block scalar is
// exactly the place indentation turns a script into something else.
func shell(t *testing.T, docs map[string]map[string]any) string {
	t.Helper()
	as, ok := container(t, docs)["args"].([]any)
	if !ok || len(as) != 1 {
		t.Fatalf("the fetch container has %v args, want one script", container(t, docs)["args"])
	}
	return as[0].(string)
}

func env(t *testing.T, docs map[string]map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, e := range container(t, docs)["env"].([]any) {
		m := e.(map[string]any)
		if v, ok := m["value"].(string); ok {
			out[m["name"].(string)] = v
		}
	}
	return out
}

func TestRenderProducesTheWholeFetch(t *testing.T) {
	_, docs := render(t, sampleConfig())
	for _, kind := range []string{"ServiceAccount", "NetworkPolicy", "Job"} {
		if _, ok := docs[kind]; !ok {
			t.Errorf("missing a %s document", kind)
		}
	}
}

// The property that makes a fetch weaker than a build, and the reason it is a
// separate workload at all (ADR 0010 decision 11).
//
// The builder is allowed 169.254.169.254 because it must mint a token to push.
// A fetch pushes nothing. If link-local ever became reachable here, a
// repository's build steps — which have not even been reviewed yet at this
// point in `farcast run` — would be able to ask for a cloud identity.
func TestTheFetchCannotReachTheMetadataServer(t *testing.T) {
	_, docs := render(t, sampleConfig())
	rules := at(t, docs["NetworkPolicy"], "spec", "egress").([]any)

	linkLocal := "169.254.0.0/16"
	for i, r := range rules {
		for _, to := range r.(map[string]any)["to"].([]any) {
			block, ok := to.(map[string]any)["ipBlock"].(map[string]any)
			if !ok {
				continue
			}
			cidr := block["cidr"].(string)
			if cidr == build.MetadataServer {
				t.Fatalf("egress rule %d permits the metadata server; a fetch mints no token and must not be able to ask for one", i)
			}
			if cidr != "0.0.0.0/0" {
				continue
			}
			var excepted []string
			for _, e := range block["except"].([]any) {
				excepted = append(excepted, e.(string))
			}
			if !contains(excepted, linkLocal) {
				t.Fatalf("egress rule %d opens 0.0.0.0/0 without excluding %s: %v", i, linkLocal, excepted)
			}
		}
	}

	// And the whole document, in case a future rule reaches it by a shape
	// this walk of the parsed policy does not cover.
	out, _ := render(t, sampleConfig())
	if strings.Contains(out, strings.TrimSuffix(build.MetadataServer, "/32")) {
		t.Error("the rendered fetch names the metadata server's address somewhere")
	}
}

// DNS is the exception the 4.2 walk had to find twice: NodeLocal DNSCache
// listens on a link-local address, and a policy that blocks link-local blocks
// name resolution with it.
func TestTheFetchCanStillResolveNames(t *testing.T) {
	_, docs := render(t, sampleConfig())
	rules := at(t, docs["NetworkPolicy"], "spec", "egress").([]any)

	// Both protocols. A resolver falls back to TCP for a response that does
	// not fit in a datagram, and a policy that permits only one of them works
	// until a repository host's answer grows.
	reached := map[string]bool{}
	for _, r := range rules {
		m := r.(map[string]any)
		ports, ok := m["ports"].([]any)
		if !ok {
			continue
		}
		var nodeLocal bool
		for _, to := range m["to"].([]any) {
			if block, ok := to.(map[string]any)["ipBlock"].(map[string]any); ok && block["cidr"] == NodeLocalDNS {
				nodeLocal = true
			}
		}
		if !nodeLocal {
			continue
		}
		for _, p := range ports {
			pm := p.(map[string]any)
			if fmt.Sprint(pm["port"]) == "53" {
				reached[fmt.Sprint(pm["protocol"])] = true
			}
		}
	}
	for _, proto := range []string{"UDP", "TCP"} {
		if !reached[proto] {
			t.Errorf("no egress rule reaches %s on %s port 53; the fetch would fail to resolve its own Git host", NodeLocalDNS, proto)
		}
	}
}

// A fetch must not run as the builder. The builder's ServiceAccount is the one
// with a Workload Identity grant that can write to the instance's registry.
func TestTheFetchIdentityIsNotTheBuilders(t *testing.T) {
	_, docs := render(t, sampleConfig())
	sa := at(t, docs["Job"], "spec", "template", "spec", "serviceAccountName").(string)
	if sa == build.ServiceAccount {
		t.Fatalf("the fetch runs as %q, which is the builder's registry-writing identity", sa)
	}
	if got := at(t, docs["ServiceAccount"], "metadata", "name").(string); got != sa {
		t.Errorf("the Job runs as %q but the rendered ServiceAccount is %q", sa, got)
	}
}

// One Secret serves both halves of deploying a private repository. If the two
// packages ever disagreed about its keys, the fetch would succeed and the
// build would fail on a credential that is present and unreadable.
func TestTheFetchAndTheBuildReadTheSameSecretKeys(t *testing.T) {
	if SecretGitUser != build.SecretGitUser || SecretGitToken != build.SecretGitToken {
		t.Fatalf("fetch reads %q/%q but build reads %q/%q",
			SecretGitUser, SecretGitToken, build.SecretGitUser, build.SecretGitToken)
	}
}

// Nothing the operator typed may appear in the script. It reaches the shell as
// an environment variable, which is what makes a repository URL data rather
// than a command.
func TestOperatorValuesReachTheShellAsEnvironmentNotText(t *testing.T) {
	c := sampleConfig()
	c.Repo = "https://git.example.test/team/thing"
	c.Ref = "refs/tags/v1.2.3"
	c.Manifest = "deploy/farcast"
	_, docs := render(t, c)

	sh := shell(t, docs)
	for _, v := range []string{c.Repo, c.Ref, c.Manifest} {
		if strings.Contains(sh, v) {
			t.Errorf("the script contains %q verbatim; it must arrive as an environment variable", v)
		}
	}
	e := env(t, docs)
	for name, want := range map[string]string{
		"FARCAST_REPO":     c.Repo,
		"FARCAST_REF":      c.Ref,
		"FARCAST_MANIFEST": c.Manifest,
	} {
		if e[name] != want {
			t.Errorf("%s = %q, want %q", name, e[name], want)
		}
	}
}

func TestThePlaceholdersAreAllSubstituted(t *testing.T) {
	out, docs := render(t, sampleConfig())
	if strings.Contains(out, "{{") {
		t.Error("the rendered fetch still contains a template placeholder")
	}
	sh := shell(t, docs)
	if !strings.Contains(sh, ReportFile) {
		t.Errorf("the script never writes to %s, so the caller would read no commit", ReportFile)
	}
	if !strings.Contains(sh, WorkDir) {
		t.Errorf("the script never uses %s, so the clone would land on the read-only root", WorkDir)
	}
}

// The script is a YAML block scalar. One line at the wrong indentation is a
// document the API server rejects, or worse, a script whose body silently
// becomes a sibling key.
func TestTheScriptSurvivesBeingABlockScalar(t *testing.T) {
	_, docs := render(t, sampleConfig())
	sh := shell(t, docs)
	for _, want := range []string{
		"set -eu",
		"git init --quiet",
		"sha256sum",
		"path=\"$HOME/src/$FARCAST_MANIFEST\"",
		"cat \"$path\"",
	} {
		if !strings.Contains(sh, want) {
			t.Errorf("the script the container receives is missing %q:\n%s", want, sh)
		}
	}
}

// The credential is handed to git through an askpass helper, not through the
// URL. A token in the URL appears in git's error output and in the process
// table, and would need URL-encoding to survive its own punctuation.
func TestTheCredentialNeverEntersTheURL(t *testing.T) {
	_, docs := render(t, sampleConfig())
	sh := shell(t, docs)
	if !strings.Contains(sh, "GIT_ASKPASS") {
		t.Error("the script does not set GIT_ASKPASS")
	}
	if strings.Contains(sh, "$GIT_PASSWORD@") || strings.Contains(sh, "://$GIT_USERNAME") {
		t.Error("the script builds a URL containing the credential")
	}
	if !strings.Contains(sh, "GIT_TERMINAL_PROMPT=0") {
		t.Error("without GIT_TERMINAL_PROMPT=0 a private repository with no credential holds the Job until its deadline")
	}
}

func TestAPublicRepositoryMountsNoCredential(t *testing.T) {
	c := sampleConfig()
	c.GitSecret = ""
	_, docs := render(t, c)
	for _, e := range container(t, docs)["env"].([]any) {
		if name := e.(map[string]any)["name"].(string); strings.HasPrefix(name, "GIT_") {
			t.Errorf("a public repository's fetch still carries %s", name)
		}
	}
}

func TestRefuses(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"an unpinned fetcher":     func(c *Config) { c.Fetcher = "cgr.dev/chainguard/git:latest" },
		"a truncated digest":      func(c *Config) { c.Fetcher = "cgr.dev/chainguard/git@sha256:abc" },
		"no fetcher at all":       func(c *Config) { c.Fetcher = "" },
		"no repository":           func(c *Config) { c.Repo = "" },
		"no instance":             func(c *Config) { c.Instance = "" },
		"a git:// repository":     func(c *Config) { c.Repo = "git://github.com/example/thing" },
		"a local path":            func(c *Config) { c.Repo = "/home/me/thing" },
		"a quote in the repo":     func(c *Config) { c.Repo = `https://example.test/a"b` },
		"a dollar in the ref":     func(c *Config) { c.Ref = "refs/heads/$(id)" },
		"a backtick in the path":  func(c *Config) { c.Manifest = "a`id`b" },
		"a newline in the repo":   func(c *Config) { c.Repo = "https://example.test/a\nb" },
		"a backslash in the path": func(c *Config) { c.Manifest = `a\b` },
	} {
		t.Run(name, func(t *testing.T) {
			c := sampleConfig()
			mutate(&c)
			if _, err := Render(c); err == nil {
				t.Fatalf("Render accepted %s", name)
			}
		})
	}
}

func TestJobNameIsStableDistinctAndALegalLabel(t *testing.T) {
	a := JobName("https://github.com/one/api", "refs/heads/main", "farcast")
	if b := JobName("https://github.com/one/api", "refs/heads/main", "farcast"); a != b {
		t.Errorf("the same repository and ref produced %q then %q; a re-run must replace rather than accumulate", a, b)
	}
	if b := JobName("https://gitlab.test/two/api", "refs/heads/main", "farcast"); a == b {
		t.Errorf("two different repositories whose last segment is \"api\" both produced %q", a)
	}
	if b := JobName("https://github.com/one/api", "refs/heads/next", "farcast"); a == b {
		t.Errorf("two refs of the same repository both produced %q", a)
	}
	// A repository holding several manifests is an ordinary layout. Two such
	// deployments collided on this name in the Phase 4.4 walk, and because a
	// Job's spec.template is immutable the second was refused outright by the
	// API server — no build, no deployment, and an error naming neither the
	// manifest nor the collision.
	if b := JobName("https://github.com/one/api", "refs/heads/main", "services/web/farcast"); a == b {
		t.Errorf("two manifests in one repository at one ref both produced %q", a)
	}
	for _, n := range []string{
		a,
		JobName("https://example.test/team/My_Repo.v2.git", "main", "farcast"),
		JobName("https://example.test/"+strings.Repeat("long", 40), "main", "farcast"),
		JobName("https://example.test/", "main", "farcast"),
	} {
		if len(n) == 0 || len(n) > 63 {
			t.Errorf("%q is %d characters; a DNS label allows 1..63", n, len(n))
		}
		for i := range len(n) {
			switch ch := n[i]; {
			case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '-':
			default:
				t.Errorf("%q contains %q, which a DNS label does not allow", n, string(ch))
			}
		}
		if n[0] == '-' || n[len(n)-1] == '-' {
			t.Errorf("%q starts or ends with a hyphen", n)
		}
	}
}

func TestTheManifestPathDefaultsToTheSpecifiedName(t *testing.T) {
	c := sampleConfig()
	c.Manifest = ""
	_, docs := render(t, c)
	if got := env(t, docs)["FARCAST_MANIFEST"]; got != DefaultManifest {
		t.Errorf("FARCAST_MANIFEST = %q, want %q", got, DefaultManifest)
	}
}

// A fetch is metered like the machinery it is, and a cost shutdown stops
// applications. A read tiered as an application would be stopped halfway and
// report nothing.
func TestAFetchIsSystemMachinery(t *testing.T) {
	_, docs := render(t, sampleConfig())
	labels := at(t, docs["Job"], "spec", "template", "metadata", "labels").(map[string]any)
	if labels["farcast.sofmon.com/tier"] != "system" {
		t.Errorf("tier = %v, want system", labels["farcast.sofmon.com/tier"])
	}
	// The 4.1 walk's lesson: the kernel selects on the POD's labels, and a
	// label that lives only on the Job meters nothing.
	if labels["app.kubernetes.io/managed-by"] != "farcast" {
		t.Errorf("the pod template is not labelled managed-by=farcast, so the kernel would not meter it")
	}
}

func TestTheFetchIsBounded(t *testing.T) {
	_, docs := render(t, sampleConfig())
	spec := docs["Job"]["spec"].(map[string]any)
	if fmt.Sprint(spec["backoffLimit"]) != "0" {
		t.Errorf("backoffLimit = %v; a repository that does not resolve does not resolve twice", spec["backoffLimit"])
	}
	if fmt.Sprint(spec["activeDeadlineSeconds"]) != fmt.Sprint(DeadlineSeconds) {
		t.Errorf("activeDeadlineSeconds = %v, want %d", spec["activeDeadlineSeconds"], DeadlineSeconds)
	}
	if DeadlineSeconds >= build.DeadlineSeconds {
		t.Errorf("a shallow clone is given %ds, no less than a whole build's %ds", DeadlineSeconds, build.DeadlineSeconds)
	}
}

func TestTheRootFilesystemIsReadOnly(t *testing.T) {
	_, docs := render(t, sampleConfig())
	sec := container(t, docs)["securityContext"].(map[string]any)
	if sec["readOnlyRootFilesystem"] != true {
		t.Error("the fetch clones into a volume and has no reason to write to its own root")
	}
	if sec["allowPrivilegeEscalation"] != false {
		t.Error("allowPrivilegeEscalation is not false")
	}
	caps := sec["capabilities"].(map[string]any)
	if _, ok := caps["add"]; ok {
		t.Errorf("the fetch adds capabilities: %v", caps["add"])
	}
	// A read-only root is only workable because the clone lands somewhere
	// writable, and that somewhere has to be owned by the image's user.
	if at(t, docs["Job"], "spec", "template", "spec", "securityContext", "fsGroup") == nil {
		t.Error("no fsGroup, so the emptyDir is root-owned and the first write fails")
	}
}

func TestParseReport(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	const md = "sha256:ab120123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"

	r, err := ParseReport("commit=" + commit + " manifest=" + md + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if r.Commit != commit {
		t.Errorf("commit = %q, want %q", r.Commit, commit)
	}
	if r.ManifestDigest != md {
		t.Errorf("manifest = %q, want %q", r.ManifestDigest, md)
	}

	for name, msg := range map[string]string{
		"nothing at all":       "",
		"only whitespace":      "  \n ",
		"a human sentence":     "no farcast at " + commit + " in https://example.test/x",
		"no commit":            "manifest=" + md,
		"no manifest":          "commit=" + commit,
		"a short commit":       "commit=abc123 manifest=" + md,
		"an unprefixed digest": "commit=" + commit + " manifest=" + strings.TrimPrefix(md, "sha256:"),
		"a truncated digest":   "commit=" + commit + " manifest=sha256:abcd",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReport(msg); err == nil {
				t.Fatalf("ParseReport accepted %q", msg)
			}
		})
	}
}

// The manifest travels through the log and its digest through the Pod's
// status. Checking one against the other is what catches a truncated log —
// bytes that parse perfectly and are not what the instance read.
func TestVerifyCatchesAManifestThatDidNotArriveWhole(t *testing.T) {
	manifest := []byte("name: thing\napps:\n  - name: api\n    containerfile: Containerfile\n")
	sum := sha256.Sum256(manifest)
	r := Report{Commit: strings.Repeat("a", 40), ManifestDigest: "sha256:" + hex.EncodeToString(sum[:])}

	if err := r.Verify(manifest); err != nil {
		t.Fatalf("Verify rejected the bytes it was given the digest of: %v", err)
	}
	if err := r.Verify(manifest[:len(manifest)-10]); err == nil {
		t.Error("Verify accepted a truncated manifest")
	}
	if err := r.Verify(append(manifest, ' ')); err == nil {
		t.Error("Verify accepted a manifest with one byte added")
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// The Job a config renders and the Job its caller waits on must be the same
// string. Ref is defaulted inside Render, so a caller deriving the name from
// its own un-defaulted config would watch a Job that does not exist — and the
// symptom is a timeout, which reads like a slow clone.
func TestTheRenderedJobIsTheJobTheCallerCanName(t *testing.T) {
	for name, ref := range map[string]string{
		"no ref given": "",
		"a branch":     "refs/heads/next",
		"a short name": "main",
		"a commit":     strings.Repeat("a", 40),
	} {
		t.Run(name, func(t *testing.T) {
			c := sampleConfig()
			c.Ref = ref
			_, docs := render(t, c)
			rendered := at(t, docs["Job"], "metadata", "name").(string)
			if got := c.Job(); got != rendered {
				t.Fatalf("the caller would wait on %q; the rendered Job is %q", got, rendered)
			}
			// And the policy selects the same pod the Job labels.
			selector := at(t, docs["NetworkPolicy"], "spec", "podSelector", "matchLabels").(map[string]any)
			labels := at(t, docs["Job"], "spec", "template", "metadata", "labels").(map[string]any)
			if selector["farcast.sofmon.com/fetch"] != labels["farcast.sofmon.com/fetch"] {
				t.Errorf("the policy selects %v and the pod is labelled %v; the fetch would have no policy at all",
					selector["farcast.sofmon.com/fetch"], labels["farcast.sofmon.com/fetch"])
			}
		})
	}
}
