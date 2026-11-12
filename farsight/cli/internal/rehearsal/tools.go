package rehearsal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

// The fake tools (D7). The harness binary is linked as kubectl,
// gke-gcloud-auth-plugin and gcloud, and ToolMain runs it as whichever its
// argv0 names.
//
// A tool finds its rehearsal from its own argv0, which must be absolute:
// <dir>/kube/bin/kubectl and <dir>/sdk/bin/gcloud both give <dir>. It then
// refuses unless the directory it was run from is, resolved, the one the
// rehearsal recorded for it.
//
// ToolMain never consults this process's environment: tests call it in
// process with an environment of their own, so every lookup reads the PATH in
// environ, and every exec passes environ whole, with its own absolute path as
// argv0 — the next fake tool needs one to find its rehearsal.

const (
	execCredentialAPI = "client.authentication.k8s.io/v1beta1"
	tokenPrefix       = "rehearsal-token:"
	nestedTimeout     = 30 * time.Second
	// signedOut is what gcloud prints when its session has expired and it
	// cannot prompt. 'farcast world' reads it as gcloud_signed_out.
	signedOut = "ERROR: (gcloud.config.config-helper) There was a problem refreshing your current auth tokens: " +
		"Reauthentication failed. cannot prompt during non-interactive execution."
)

// ToolMain runs this binary as a fake tool when argv0's base name is kubectl,
// gke-gcloud-auth-plugin or gcloud; ok is false otherwise, and nothing ran.
func ToolMain(argv0 string, args, environ []string, stdout, stderr io.Writer) (code int, ok bool) {
	name := filepath.Base(argv0)
	switch name {
	case toolKubectl, toolPlugin, toolGCloud:
	default:
		return 0, false
	}
	t := &tool{name: name, argv0: argv0, args: args, environ: environ, stdout: stdout, stderr: stderr}
	return t.main(), true
}

type tool struct {
	name, argv0    string
	args, environ  []string
	stdout, stderr io.Writer
	spec           Spec
	logged         bool
}

func (t *tool) main() int {
	if !filepath.IsAbs(t.argv0) {
		t.say("run by a relative name; the rehearsal needs an absolute one")
		return 1
	}
	bin := filepath.Dir(filepath.Clean(t.argv0))
	root := filepath.Dir(filepath.Dir(bin))
	spec, err := LoadSpec(root)
	if err != nil {
		t.say("no rehearsal at %s: %v", root, err)
		return 1
	}
	want := spec.Dirs.SDKBin
	if t.name == toolKubectl {
		want = spec.Dirs.KubeBin
	}
	if real, err := filepath.EvalSymlinks(bin); err != nil || real != want {
		t.say("run from %s, which is not this rehearsal's own %s", bin, want)
		return 1
	}
	t.spec = spec
	switch t.name {
	case toolKubectl:
		return t.kubectl()
	case toolPlugin:
		return t.plugin()
	default:
		return t.gcloud()
	}
}

// say writes one line to stderr, as the tool.
func (t *tool) say(format string, args ...any) {
	_, _ = fmt.Fprintf(t.stderr, "fake %s: %s\n", t.name, fmt.Sprintf(format, args...))
}

// refuse says why, records the refusal in calls.log, and exits 1.
func (t *tool) refuse(reason string) int {
	t.say("%s", reason)
	t.done("refused: " + reason)
	return 1
}

// done records the call's outcome in calls.log, once.
func (t *tool) done(outcome string) {
	if t.logged {
		return
	}
	t.logged = true
	appendCall(t.spec.Dirs.Root, t.name, t.args, outcome)
}

// --------------------------------------------------------------- kubectl

func (t *tool) kubectl() int {
	if len(t.args) < 2 || t.args[0] != "--kubeconfig" {
		return t.refuse("--kubeconfig <path> must come first, as farcast's cluster runner puts it")
	}
	kubeconfig, rest := t.args[1], t.args[2:]
	if t.spec.expired(time.Now()) {
		return t.refuse(errExpired)
	}
	if reason := t.kubectlEnvironment(kubeconfig); reason != "" {
		return t.refuse(reason)
	}
	token, code := t.credential(kubeconfig)
	if code != 0 {
		return code
	}
	if !strings.EqualFold(token, tokenPrefix+t.spec.Account) {
		return t.refuse("the credential the auth plugin returned is not the pinned account's: this would have read as another identity")
	}
	if t.spec.Scenario == ScenarioSlowCluster {
		time.Sleep(time.Duration(t.spec.SlowSeconds * float64(time.Second)))
	}
	out, ok := ClusterAnswer(t.spec, rest, time.Now())
	if !ok {
		t.say("the rehearsal answers reads only; it has no answer to: %s", quoteArgs(rest))
		t.done("refused: no answer to this command")
		return 1
	}
	if _, err := t.stdout.Write(out); err != nil {
		return t.refuse("could not write its answer")
	}
	t.done("ok")
	return 0
}

// forbidden are variables that must never reach kubectl from 'farcast world',
// matched by name in any case. Every CLOUDSDK_* variable but the two the CLI
// sets is forbidden too.
var forbidden = []string{"GOOGLE_APPLICATION_CREDENTIALS", "FARCAST_CONFIG_HOME", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}

// kubectlEnvironment is why kubectl's environment is not the one 'farcast
// world' builds, or "". It names a variable, never its value.
func (t *tool) kubectlEnvironment(kubeconfig string) string {
	for _, kv := range t.environ {
		k, _, _ := strings.Cut(kv, "=")
		for _, f := range forbidden {
			if strings.EqualFold(k, f) {
				return k + " is set; farcast must not pass it to kubectl"
			}
		}
		if strings.HasPrefix(k, "CLOUDSDK_") && k != "CLOUDSDK_CONFIG" && k != "CLOUDSDK_ACTIVE_CONFIG_NAME" {
			return k + " is set; the only CLOUDSDK_ variables kubectl may get are CLOUDSDK_CONFIG and CLOUDSDK_ACTIVE_CONFIG_NAME"
		}
	}
	instanceKC := filepath.Join(t.spec.Dirs.Config, "instances", t.spec.Instance, "kubeconfig.yaml")
	if !sameFile(kubeconfig, instanceKC) {
		return "--kubeconfig does not name the rehearsal instance's own kubeconfig"
	}
	if v, ok := t.env("KUBECONFIG"); !ok || !sameFile(v, kubeconfig) {
		return "KUBECONFIG does not name the kubeconfig given with --kubeconfig"
	}
	if reason := t.gcloudDirectory(); reason != "" {
		return reason
	}
	if v, ok := t.env("CLOUDSDK_ACTIVE_CONFIG_NAME"); !ok || v == "" {
		return "CLOUDSDK_ACTIVE_CONFIG_NAME is not set, so gcloud would read as whichever configuration is active"
	}
	path, _ := t.env("PATH")
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			return "PATH holds an entry that is not an absolute directory"
		}
	}
	if found, ok := lookPathIn(toolKubectl, path); !ok || found != filepath.Clean(t.argv0) {
		return "the kubectl PATH finds first is not this one"
	}
	return ""
}

// credential runs the auth plugin the kubeconfig names, as kubectl does, and
// returns the token it gave. On failure it has already exited as kubectl
// would, and code is non-zero.
func (t *tool) credential(kubeconfig string) (token string, code int) {
	data, err := os.ReadFile(kubeconfig)
	if err != nil {
		return "", t.refuse("could not read the kubeconfig")
	}
	var kc struct {
		Users []struct {
			User struct {
				Exec *struct {
					Command string `yaml:"command"`
				} `yaml:"exec"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal(data, &kc); err != nil || len(kc.Users) == 0 || kc.Users[0].User.Exec == nil {
		return "", t.refuse("the kubeconfig names no credential plugin")
	}
	if kc.Users[0].User.Exec.Command != toolPlugin {
		return "", t.refuse("the kubeconfig's credential plugin is not " + toolPlugin)
	}
	path, _ := t.env("PATH")
	plugin, ok := lookPathIn(toolPlugin, path)
	if !ok {
		_, _ = fmt.Fprintf(t.stderr, "Unable to connect to the server: getting credentials: exec: executable %s not found\n", toolPlugin)
		t.done("refused: no " + toolPlugin + " on PATH")
		return "", 1
	}
	if real, err := filepath.EvalSymlinks(filepath.Dir(plugin)); err != nil || real != t.spec.Dirs.SDKBin {
		return "", t.refuse("the " + toolPlugin + " PATH finds first is not this rehearsal's")
	}
	out, errOut, err := t.exec(plugin)
	if err != nil {
		_, _ = fmt.Fprintf(t.stderr, "Unable to connect to the server: getting credentials: exec: executable %s failed with exit code 1\n", toolPlugin)
		_, _ = t.stderr.Write(errOut)
		t.done("refused: the auth plugin failed")
		return "", 1
	}
	var cred struct {
		Kind   string `json:"kind"`
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &cred); err != nil || cred.Kind != "ExecCredential" || cred.Status.Token == "" {
		return "", t.refuse("the auth plugin returned no credential")
	}
	return cred.Status.Token, 0
}

// ---------------------------------------------------------------- plugin

func (t *tool) plugin() int {
	if reason := t.gcloudDirectory(); reason != "" {
		return t.refuse(reason)
	}
	if len(t.args) != 0 {
		return t.refuse("it takes no arguments")
	}
	// The real plugin's precedence: a token in the environment wins over
	// gcloud. kubectl refuses the variable, so reaching this is a leak.
	token, ok := t.env("CLOUDSDK_AUTH_ACCESS_TOKEN")
	if !ok {
		path, _ := t.env("PATH")
		gcloud, found := lookPathIn(toolGCloud, path)
		if !found {
			_, _ = fmt.Fprintf(t.stderr, "exec: %q: executable file not found in $PATH\n", toolGCloud)
			t.done("refused: no gcloud on PATH")
			return 1
		}
		if real, err := filepath.EvalSymlinks(filepath.Dir(gcloud)); err != nil || real != t.spec.Dirs.SDKBin {
			return t.refuse("the gcloud PATH finds first is not this rehearsal's")
		}
		out, errOut, err := t.exec(gcloud, "config", "config-helper", "--format=json")
		if err != nil {
			_, _ = t.stderr.Write(errOut)
			t.done("refused: gcloud failed")
			return 1
		}
		var helper struct {
			Credential struct {
				AccessToken string `json:"access_token"`
			} `json:"credential"`
		}
		if err := json.Unmarshal(out, &helper); err != nil || helper.Credential.AccessToken == "" {
			return t.refuse("gcloud returned no access token")
		}
		token = helper.Credential.AccessToken
	}
	cred := map[string]any{
		"kind": "ExecCredential", "apiVersion": execCredentialAPI,
		"status": map[string]any{"token": token, "expirationTimestamp": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)},
	}
	if err := json.NewEncoder(t.stdout).Encode(cred); err != nil {
		return t.refuse("could not write the credential")
	}
	t.done("ok")
	return 0
}

// ---------------------------------------------------------------- gcloud

var configName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func (t *tool) gcloud() int {
	if reason := t.gcloudDirectory(); reason != "" {
		return t.refuse(reason)
	}
	if strings.Join(t.args, " ") != "config config-helper --format=json" {
		return t.refuse("it answers only 'config config-helper --format=json'")
	}
	if t.spec.Scenario == ScenarioSignedOut {
		_, _ = fmt.Fprintln(t.stderr, signedOut)
		t.done("refused: signed out (the signed-out scenario)")
		return 1
	}
	dir := t.spec.Dirs.GCloud
	name, ok := t.env("CLOUDSDK_ACTIVE_CONFIG_NAME")
	if !ok || name == "" {
		// As real gcloud does: the active configuration, which here is the
		// decoy.
		b, err := os.ReadFile(filepath.Join(dir, "active_config"))
		if err != nil {
			return t.refuse("no active configuration")
		}
		name = strings.TrimSpace(string(b))
	}
	if !configName.MatchString(name) {
		return t.refuse("the configuration name is not one gcloud accepts")
	}
	data, err := os.ReadFile(filepath.Join(dir, "configurations", "config_"+name))
	if err != nil {
		_, _ = fmt.Fprintf(t.stderr, "ERROR: (gcloud.config.config-helper) Cannot activate configuration [%s], it does not exist.\n", name)
		t.done("refused: no such configuration")
		return 1
	}
	account, project := iniCoreValues(data)
	// Real gcloud's precedence: the environment over the file.
	if v, ok := t.env("CLOUDSDK_CORE_ACCOUNT"); ok {
		account = v
	}
	if v, ok := t.env("CLOUDSDK_CORE_PROJECT"); ok {
		project = v
	}
	if account == "" {
		_, _ = fmt.Fprintln(t.stderr, "ERROR: (gcloud.config.config-helper) You do not currently have an active account selected.")
		t.done("refused: no account")
		return 1
	}
	out := map[string]any{
		"configuration": map[string]any{
			"active_configuration": name,
			"properties":           map[string]any{"core": map[string]any{"account": account, "project": project}},
		},
		"credential": map[string]any{
			"access_token": tokenPrefix + account,
			"token_expiry": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		},
	}
	if err := json.NewEncoder(t.stdout).Encode(out); err != nil {
		return t.refuse("could not write the configuration")
	}
	t.done("ok")
	return 0
}

// gcloudDirectory is why CLOUDSDK_CONFIG is not this rehearsal's gcloud
// directory, or "". There is no fallback to a default directory, so a fake
// run by hand from a terminal can never reach the operator's real one.
func (t *tool) gcloudDirectory() string {
	v, ok := t.env("CLOUDSDK_CONFIG")
	if !ok || v == "" {
		return "CLOUDSDK_CONFIG is not set; this rehearsal never falls back to gcloud's default directory"
	}
	if !sameFile(v, t.spec.Dirs.GCloud) {
		return "CLOUDSDK_CONFIG does not name this rehearsal's gcloud directory"
	}
	return ""
}

// iniCoreValues reads [core] account and project from a gcloud
// configuration file.
func iniCoreValues(data []byte) (account, project string) {
	section := ""
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "", strings.HasPrefix(line, "#"), strings.HasPrefix(line, ";"):
			continue
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || section != "core" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "account":
			account = strings.TrimSpace(v)
		case "project":
			project = strings.TrimSpace(v)
		}
	}
	return account, project
}

// ---------------------------------------------------------------- shared

// env is the last value environ gives key, the one a process sees.
func (t *tool) env(key string) (string, bool) {
	v, found := "", false
	for _, kv := range t.environ {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			v, found = val, true
		}
	}
	return v, found
}

// exec runs another fake tool at an absolute path, with that path as argv0
// and environ as its whole environment.
func (t *tool) exec(path string, args ...string) (stdout, stderr []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), nestedTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Args[0] = path
	cmd.Env = append([]string{}, t.environ...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// lookPathIn finds name on a PATH value as a shell would: the first absolute
// directory holding an executable regular file by that name. It is the rule
// farcast's cluster runner uses.
func lookPathIn(name, pathValue string) (string, bool) {
	for _, dir := range filepath.SplitList(pathValue) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, name)
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return p, true
	}
	return "", false
}

// sameFile reports whether two paths resolve to one.
func sameFile(a, b string) bool {
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		return false
	}
	rb, err := filepath.EvalSymlinks(b)
	return err == nil && ra == rb
}

// appendCall adds one line to calls.log: the time, the caller, its
// arguments, and the outcome. A line never holds an environment value or a
// token.
func appendCall(root, who string, args []string, outcome string) {
	line := time.Now().UTC().Format(time.RFC3339) + " " + who
	if len(args) > 0 {
		line += " " + quoteArgs(args)
	}
	line += " | " + strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, outcome) + "\n"
	f, err := os.OpenFile(filepath.Join(root, callsLog), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	_, _ = f.WriteString(line)
	_ = f.Close()
}

// quoteArgs joins arguments with spaces, Go-quoting any that is empty or is
// not plain, so one line stays one line.
func quoteArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a != "" && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-") == "" {
			out[i] = a
		} else {
			out[i] = strconv.Quote(a)
		}
	}
	return strings.Join(out, " ")
}
