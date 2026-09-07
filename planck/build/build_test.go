package build

import (
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

const digest = "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func sampleConfig() Config {
	return Config{
		Instance:      "p42",
		Deployment:    "my-platform",
		App:           "api",
		Builder:       "cgr.dev/chainguard/kaniko" + digest,
		Repo:          "https://github.com/example/my-platform.git",
		Ref:           "refs/heads/main",
		Containerfile: "services/api/Containerfile",
		Destination:   "reg.example/farcast-p42/app/my-platform/api:abc123",
		GitSecret:     "my-platform-git",
		EgressHosts:   []string{"github.com", "reg.example"},
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
		t.Fatalf("the build pod has %d containers, want 1", len(cs))
	}
	return cs[0].(map[string]any)
}

func args(t *testing.T, docs map[string]map[string]any) []string {
	t.Helper()
	var out []string
	for _, a := range container(t, docs)["args"].([]any) {
		out = append(out, a.(string))
	}
	return out
}

func TestRenderProducesTheWholeBuild(t *testing.T) {
	_, docs := render(t, sampleConfig())
	for _, kind := range []string{"ServiceAccount", "NetworkPolicy", "Job"} {
		if _, ok := docs[kind]; !ok {
			t.Errorf("missing a %s document", kind)
		}
	}
}

// The one place FarCast cannot copy its own hardening. Kaniko builds by
// extracting image layers into its own root filesystem: a read-only root does
// not make it safer, it makes it non-functional. Every capability it does get
// is in Autopilot's permitted set, and privileged is never among them.
func TestTheBuilderGetsExactlyWhatUnpackingNeeds(t *testing.T) {
	out, docs := render(t, sampleConfig())
	sec := container(t, docs)["securityContext"].(map[string]any)

	if _, ok := sec["readOnlyRootFilesystem"]; ok {
		t.Error("readOnlyRootFilesystem is set; Kaniko writes the extracted filesystem to its own root and would fail")
	}
	if sec["allowPrivilegeEscalation"] != false {
		t.Errorf("allowPrivilegeEscalation = %v, want false", sec["allowPrivilegeEscalation"])
	}
	if strings.Contains(out, "privileged: true") {
		t.Error("Kaniko never needs privileged mode; that is why it is admissible on Autopilot at all")
	}

	caps := sec["capabilities"].(map[string]any)
	if fmt.Sprint(caps["drop"]) != "[ALL]" {
		t.Errorf("capabilities.drop = %v, want [ALL] before adding back", caps["drop"])
	}
	added := map[string]bool{}
	for _, c := range caps["add"].([]any) {
		added[c.(string)] = true
	}
	// Autopilot's permitted set (ADR 0003). Anything outside it makes the Pod
	// inadmissible, and the failure is a rejected workload rather than a
	// build error.
	permitted := map[string]bool{
		"SETPCAP": true, "MKNOD": true, "AUDIT_WRITE": true, "CHOWN": true,
		"DAC_OVERRIDE": true, "FOWNER": true, "FSETID": true, "KILL": true,
		"SETGID": true, "SETUID": true, "NET_BIND_SERVICE": true,
		"SYS_CHROOT": true, "SETFCAP": true, "SYS_PTRACE": true,
	}
	for c := range added {
		if !permitted[c] {
			t.Errorf("capability %q is not in Autopilot's permitted set; the Pod would be rejected", c)
		}
	}
	for _, needed := range []string{"CHOWN", "SETUID", "SETGID", "SYS_CHROOT"} {
		if !added[needed] {
			t.Errorf("%s is not granted; unpacking a filesystem needs it", needed)
		}
	}
}

// An unpinned builder is arbitrary code holding a registry credential.
func TestTheBuilderImageMustBeDigestPinned(t *testing.T) {
	for name, image := range map[string]string{
		"empty":   "",
		"tag":     "cgr.dev/chainguard/kaniko:latest",
		"short":   "cgr.dev/chainguard/kaniko@sha256:abc",
		"non-hex": "cgr.dev/chainguard/kaniko@sha256:" + strings.Repeat("z", 64),
	} {
		c := sampleConfig()
		c.Builder = image
		if _, err := Render(c); err == nil {
			t.Errorf("%s: builder %q was accepted", name, image)
		}
	}
}

// A digest is what the build PRODUCES; asking it to push to one is a caller
// that has confused the two ends of the pipeline.
func TestTheDestinationMustNotAlreadyBePinned(t *testing.T) {
	c := sampleConfig()
	c.Destination = "reg.example/app/x" + digest
	if _, err := Render(c); err == nil {
		t.Fatal("a digest-pinned destination was accepted")
	}
}

// The caller needs the digest back without parsing logs, and Kubernetes
// surfaces the termination message in the Pod's status.
func TestTheDigestIsReportedThroughPodStatus(t *testing.T) {
	_, docs := render(t, sampleConfig())
	if !hasArg(args(t, docs), "--digest-file="+DigestFile) {
		t.Errorf("the build does not report its digest: %v", args(t, docs))
	}
	if got := container(t, docs)["terminationMessagePolicy"]; got != "File" {
		t.Errorf("terminationMessagePolicy = %v, want File, or the digest never reaches the status", got)
	}
}

// A build is the one FarCast workload that runs code the operator wrote rather
// than code FarCast compiled, so what it can reach is what an untrusted
// Containerfile can reach.
func TestABuildReachesTheInternetAndNothingInTheCluster(t *testing.T) {
	_, docs := render(t, sampleConfig())
	np := docs["NetworkPolicy"]

	types := at(t, np, "spec", "policyTypes").([]any)
	if fmt.Sprint(types) != "[Ingress Egress]" {
		t.Fatalf("policyTypes = %v, want both", types)
	}
	if ing, ok := at(t, np, "spec", "ingress").([]any); !ok || len(ing) != 0 {
		t.Errorf("ingress = %v, want empty: a build serves nothing and listens for nothing", ing)
	}

	rules := at(t, np, "spec", "egress").([]any)
	if len(rules) != 2 {
		t.Fatalf("egress has %d rules, want 2 (DNS and outbound TLS)", len(rules))
	}

	// The outbound rule must exclude the cluster's own ranges and link-local,
	// or a Containerfile could reach another pod or the metadata server.
	var block map[string]any
	for _, r := range rules {
		to := r.(map[string]any)["to"].([]any)
		for _, dst := range to {
			if b, ok := dst.(map[string]any)["ipBlock"].(map[string]any); ok {
				block = b
			}
		}
	}
	if block == nil {
		t.Fatal("no ipBlock rule; the build could reach nothing outside the cluster")
	}
	except := fmt.Sprint(block["except"])
	for _, want := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"} {
		if !strings.Contains(except, want) {
			t.Errorf("egress does not exclude %s; a build could reach %s", want,
				map[string]string{"169.254.0.0/16": "the cloud metadata server"}[want]+"the cluster")
		}
	}
}

// Builds are instance machinery. Stopping a half-finished one leaves an image
// that is neither the old nor the new; its own deadline bounds its cost.
func TestABuildIsSystemTierAndBounded(t *testing.T) {
	_, docs := render(t, sampleConfig())
	job := docs["Job"]

	for _, path := range [][]string{{"metadata", "labels"}, {"spec", "template", "metadata", "labels"}} {
		labels := at(t, job, path...).(map[string]any)
		if labels["farcast.sofmon.com/tier"] != "system" {
			t.Errorf("%v tier = %v, want system", path, labels["farcast.sofmon.com/tier"])
		}
		if labels["app.kubernetes.io/managed-by"] != "farcast" {
			t.Errorf("%v is not labelled managed-by; the cost meter would not see the build", path)
		}
	}
	if got := at(t, job, "spec", "backoffLimit"); got != uint64(0) && got != 0 {
		t.Errorf("backoffLimit = %v, want 0: a failing build fails the same way twice", got)
	}
	for _, f := range []string{"activeDeadlineSeconds", "ttlSecondsAfterFinished"} {
		if at(t, job, "spec", f) == nil {
			t.Errorf("the Job has no %s; a hung build would bill until someone noticed", f)
		}
	}
	if got := at(t, job, "spec", "template", "spec", "restartPolicy"); got != "Never" {
		t.Errorf("restartPolicy = %v, want Never", got)
	}
}

// A public repository must not require inventing a credential.
func TestAPublicRepositoryNeedsNoSecret(t *testing.T) {
	c := sampleConfig()
	c.GitSecret = ""
	out, docs := render(t, c)
	if _, ok := container(t, docs)["env"]; ok {
		t.Error("a build with no Git secret still mounts credentials")
	}
	if strings.Contains(out, "secretKeyRef") {
		t.Error("a credential reference was rendered without a secret")
	}
}

func TestAPrivateRepositoryGetsItsCredentialFromASecret(t *testing.T) {
	_, docs := render(t, sampleConfig())
	env := container(t, docs)["env"].([]any)
	seen := map[string]string{}
	for _, e := range env {
		m := e.(map[string]any)
		ref := at(t, m, "valueFrom", "secretKeyRef").(map[string]any)
		seen[m["name"].(string)] = fmt.Sprint(ref["name"]) + "/" + fmt.Sprint(ref["key"])
	}
	if seen["GIT_PASSWORD"] != "my-platform-git/"+SecretGitToken {
		t.Errorf("GIT_PASSWORD = %q, want the token from the named Secret", seen["GIT_PASSWORD"])
	}
	if seen["GIT_USERNAME"] != "my-platform-git/"+SecretGitUser {
		t.Errorf("GIT_USERNAME = %q", seen["GIT_USERNAME"])
	}
	// The credential is never an argument: args are visible in `kubectl
	// describe` and in every log line that echoes them.
	for _, a := range args(t, docs) {
		if strings.Contains(strings.ToLower(a), "token") || strings.Contains(strings.ToLower(a), "password") {
			t.Errorf("a credential appears in an argument: %q", a)
		}
	}
}

func TestTheContextIsTheRepositoryAtARef(t *testing.T) {
	_, docs := render(t, sampleConfig())
	a := args(t, docs)
	if !hasArg(a, "--context=git://github.com/example/my-platform.git#refs/heads/main") {
		t.Errorf("context argument is wrong: %v", a)
	}
	if !hasArg(a, "--dockerfile=services/api/Containerfile") {
		t.Errorf("dockerfile argument is wrong: %v", a)
	}
	if !hasArg(a, "--destination=reg.example/farcast-p42/app/my-platform/api:abc123") {
		t.Errorf("destination argument is wrong: %v", a)
	}
}

func TestASubPathIsOnlyPassedWhenSet(t *testing.T) {
	_, docs := render(t, sampleConfig())
	for _, a := range args(t, docs) {
		if strings.HasPrefix(a, "--context-sub-path=") {
			t.Errorf("a sub-path was passed when none was configured: %q", a)
		}
	}
	c := sampleConfig()
	c.ContextSubPath = "services/api"
	_, docs = render(t, c)
	if !hasArg(args(t, docs), "--context-sub-path=services/api") {
		t.Error("the configured sub-path did not reach the builder")
	}
}

// Building here exists so the source does not have to be on the operator's
// machine; a local path would defeat that and fail confusingly in-cluster.
func TestALocalPathIsRefused(t *testing.T) {
	for _, repo := range []string{"", "/home/me/src", "./repo", "file:///tmp/x", "git@github.com:x/y.git"} {
		c := sampleConfig()
		c.Repo = repo
		if _, err := Render(c); err == nil {
			t.Errorf("repository %q was accepted", repo)
		}
	}
}

func TestRenderValidatesItsInputs(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"no instance":    func(c *Config) { c.Instance = "" },
		"no deployment":  func(c *Config) { c.Deployment = "" },
		"no app":         func(c *Config) { c.App = "" },
		"no destination": func(c *Config) { c.Destination = "" },
	} {
		c := sampleConfig()
		mutate(&c)
		if _, err := Render(c); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
	}
}

// A re-run must replace rather than accumulate Jobs, and the name has to stay
// a valid DNS label however long the manifest's names are.
func TestTheJobNameIsStableAndBounded(t *testing.T) {
	c := sampleConfig()
	_, docs := render(t, c)
	first := at(t, docs["Job"], "metadata", "name")
	_, docs = render(t, c)
	if at(t, docs["Job"], "metadata", "name") != first {
		t.Error("the job name is not stable between renders")
	}

	c.Deployment = strings.Repeat("d", 60)
	c.App = strings.Repeat("a", 60)
	_, docs = render(t, c)
	name := at(t, docs["Job"], "metadata", "name").(string)
	if len(name) > 63 {
		t.Errorf("job name is %d characters, want at most 63", len(name))
	}
	if strings.HasSuffix(name, "-") {
		t.Errorf("job name %q ends in a hyphen and is not a DNS label", name)
	}
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
