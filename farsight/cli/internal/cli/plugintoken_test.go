package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// ADR 0021 Verification 5: "with a token planted in the auth plugin's cache
// under another context, and CLOUDSDK_AUTH_ACCESS_TOKEN set in the parent,
// the bearer token a local fake API server receives is never either of them."
//
// kubectl and gke-gcloud-auth-plugin are stood in for by this test binary
// itself, reached through a symlink named kubectl. It picks a bearer token the
// way the plugin does — CLOUDSDK_AUTH_ACCESS_TOKEN if set; else the token in
// the plugin's one cache entry, which sits beside the kubeconfig $KUBECONFIG
// names (or ~/.kube/config), when that entry's context is that kubeconfig's
// current context; else one gcloud mints for the active configuration's
// account, where CLOUDSDK_CORE_ACCOUNT overrides the file — and presents it to
// the API server the instance's kubeconfig names. A token it mints it caches,
// as the plugin does: it overwrites that one entry, keyed by that context,
// whichever account minted it. No cloud, no real tool.

func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "kubectl" {
		os.Exit(fakeKubectlMain(os.Args[1:]))
	}
	os.Exit(m.Run())
}

const pluginCacheFile = "gke_gcloud_auth_plugin_cache"

func fakeKubectlMain(args []string) int {
	var kubeconfig string
	rest := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--kubeconfig" && i+1 < len(args) {
			kubeconfig = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	server := yamlField(kubeconfig, "server")
	if server == "" {
		fmt.Fprintln(os.Stderr, "fake kubectl: no server in", kubeconfig)
		return 1
	}
	token, err := pluginToken()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake kubectl:", err)
		return 1
	}
	req, err := http.NewRequest(http.MethodGet, server+"/?args="+url.QueryEscape(strings.Join(rest, " ")), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake kubectl:", err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake kubectl:", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(os.Stdout, resp.Body)
	return 0
}

// pluginToken chooses a token as gke-gcloud-auth-plugin does.
func pluginToken() (string, error) {
	if t := os.Getenv("CLOUDSDK_AUTH_ACCESS_TOKEN"); t != "" {
		return t, nil
	}
	home := os.Getenv("HOME")
	kc := filepath.Join(home, ".kube", "config")
	if v := os.Getenv("KUBECONFIG"); v != "" {
		kc = filepath.SplitList(v)[0]
	}
	cacheFile := filepath.Join(filepath.Dir(kc), pluginCacheFile)
	current := yamlField(kc, "current-context")
	if raw, err := os.ReadFile(cacheFile); err == nil {
		var cache struct {
			CurrentContext string `json:"current_context"`
			AccessToken    string `json:"access_token"`
		}
		if json.Unmarshal(raw, &cache) == nil && cache.AccessToken != "" && cache.CurrentContext == current {
			return cache.AccessToken, nil
		}
	}
	dir := os.Getenv("CLOUDSDK_CONFIG")
	if dir == "" {
		dir = filepath.Join(home, ".config", "gcloud")
	}
	active := os.Getenv("CLOUDSDK_ACTIVE_CONFIG_NAME")
	if active == "" {
		b, _ := os.ReadFile(filepath.Join(dir, "active_config"))
		active = strings.TrimSpace(string(b))
	}
	raw, err := os.ReadFile(filepath.Join(dir, "configurations", "config_"+active))
	if err != nil {
		return "", fmt.Errorf("gcloud has no configuration %q", active)
	}
	account, _ := gcloudCore(raw)
	if v := os.Getenv("CLOUDSDK_CORE_ACCOUNT"); v != "" {
		account = v
	}
	token := "minted-for:" + account
	cachePluginToken(cacheFile, current, token)
	return token, nil
}

// cachePluginToken writes the plugin's one cache entry, replacing whatever was
// there: keyed by the kubeconfig's current context, never by account. A
// directory that cannot hold it is no error, as for the plugin. The write is
// renamed into place, so a concurrent read sees one entry or the other.
func cachePluginToken(cacheFile, context, token string) {
	body, err := json.Marshal(map[string]string{
		"current_context": context,
		"access_token":    token,
		"token_expiry":    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if err != nil {
		return
	}
	f, err := os.CreateTemp(filepath.Dir(cacheFile), pluginCacheFile+".*")
	if err != nil {
		return
	}
	_, werr := f.Write(body)
	if cerr := f.Close(); werr != nil || cerr != nil {
		_ = os.Remove(f.Name())
		return
	}
	if err := os.Rename(f.Name(), cacheFile); err != nil {
		_ = os.Remove(f.Name())
	}
}

// yamlField is the first "key: value" in a file, which is all a minimal
// kubeconfig needs.
func yamlField(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "- "))
		if v, ok := strings.CutPrefix(line, key+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func TestKubectlNeverPresentsAPlantedToken(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("cannot find this test binary:", err)
	}
	bin := t.TempDir()
	if err := os.Symlink(self, filepath.Join(bin, "kubectl")); err != nil {
		t.Skip("cannot link a fake kubectl:", err)
	}

	var mu sync.Mutex
	var tokens []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tokens = append(tokens, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		mu.Unlock()
		if strings.Contains(r.URL.Query().Get("args"), "configmap") {
			return // not found
		}
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	defer api.Close()

	// The operator's machine: a work kubeconfig in KUBECONFIG, a token the
	// plugin cached for the work context, a token in the environment, a work
	// account forced through CLOUDSDK_CORE_ACCOUNT, and a work configuration
	// active — every one of them a way to read as the wrong identity.
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o700); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(home, ".kube", "config")
	mustWrite(t, work, "apiVersion: v1\ncurrent-context: gke_work-prod_europe-west4_work\n")
	mustWrite(t, filepath.Join(home, ".kube", pluginCacheFile), fmt.Sprintf(
		`{"current_context":"gke_work-prod_europe-west4_work","access_token":"planted-cache-token","token_expiry":%q}`,
		time.Now().Add(time.Hour).UTC().Format(time.RFC3339)))
	gdir := fakeGCloudDir(t, "work",
		gcloudConfig{Name: "work", Account: "someone@work.example", Project: "proj-atlas"},
		gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-atlas"})

	dir := config.Dir(t.TempDir())
	meta := installedInstance(t, dir, "atlas")
	meta.Project, meta.GCloudAccount = "proj-atlas", "operator@example.org"
	meta.Kernel = &config.Kernel{Deployed: true, Applied: true, Namespaces: []string{"farcast-system"}}
	if err := dir.SaveInstanceMetadata("atlas", meta); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceKubeconfig("atlas", []byte(
		"apiVersion: v1\ncurrent-context: farcast-atlas\nclusters:\n- cluster:\n    server: "+api.URL+"\n  name: farcast-atlas\n")); err != nil {
		t.Fatal(err)
	}

	parent := []string{
		"PATH=" + bin, "HOME=" + home, "KUBECONFIG=" + work,
		"CLOUDSDK_CONFIG=" + gdir, "CLOUDSDK_ACTIVE_CONFIG_NAME=work",
		"CLOUDSDK_AUTH_ACCESS_TOKEN=planted-env-token", "CLOUDSDK_CORE_ACCOUNT=someone@work.example",
		"GOOGLE_APPLICATION_CREDENTIALS=" + filepath.Join(home, "key.json"),
		"GORACE=atexit_sleep_ms=0", // the fake is race-built; cluster.Env passes GORACE
	}
	cmd := &worldCommand{
		now:     func() time.Time { return vectorNow },
		stamp:   func() buildStamp { return vectorStamp },
		environ: func() []string { return parent },
	}
	env, out := testEnv(dir, output.ModeJSON)
	if err := cmd.Run(context.Background(), env, []string{"atlas"}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Sections map[string]sectionStatus `json:"sections"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Sections["apps"].Read {
		t.Fatalf("the apps section was not read through the fake kubectl: %+v", doc.Sections["apps"])
	}

	mu.Lock()
	defer mu.Unlock()
	if len(tokens) == 0 {
		t.Fatal("the fake API server was never asked")
	}
	for _, tok := range tokens {
		if tok != "minted-for:operator@example.org" {
			t.Errorf("the API server received %q; every read must run as the pinned account", tok)
		}
	}
}

// The token-cache regression (ADR 0023 M0, the design's S1). The plugin keeps
// one cache entry beside the kubeconfig KUBECONFIG names, keyed by its current
// context and not by account. An unpinned command, run as whichever gcloud
// configuration is active, keeps the parent's KUBECONFIG; so the token it
// caches is never in the entry 'world' reads, and 'world', pinned to the
// recorded account, presents that account's token and no other.
func TestWorldNeverReusesATokenAnUnpinnedCommandCached(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("cannot find this test binary:", err)
	}
	bin := t.TempDir()
	if err := os.Symlink(self, filepath.Join(bin, "kubectl")); err != nil {
		t.Skip("cannot link a fake kubectl:", err)
	}

	var mu sync.Mutex
	var tokens []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tokens = append(tokens, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		mu.Unlock()
		if strings.Contains(r.URL.Query().Get("args"), "configmap") {
			return // not found
		}
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	defer api.Close()
	received := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := tokens
		tokens = nil
		return out
	}

	// The operator's machine: no KUBECONFIG, a work kubeconfig at the default
	// path, and the work configuration active. The account recorded for the
	// instance is P; the active one is W.
	const (
		accountW = "someone@work.example"
		accountP = "operator@example.org"
	)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(home, ".kube", "config"), "apiVersion: v1\ncurrent-context: gke_work-prod_europe-west4_work\n")
	gdir := fakeGCloudDir(t, "work",
		gcloudConfig{Name: "work", Account: accountW, Project: "proj-atlas"},
		gcloudConfig{Name: "personal", Account: accountP, Project: "proj-atlas"})

	dir := config.Dir(t.TempDir())
	meta := installedInstance(t, dir, "atlas")
	meta.Project, meta.GCloudAccount = "proj-atlas", accountP
	meta.Kernel = &config.Kernel{Deployed: true, Applied: true, Namespaces: []string{"farcast-system"}}
	if err := dir.SaveInstanceMetadata("atlas", meta); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceKubeconfig("atlas", []byte(
		"apiVersion: v1\ncurrent-context: farcast-atlas\nclusters:\n- cluster:\n    server: "+api.URL+"\n  name: farcast-atlas\n")); err != nil {
		t.Fatal(err)
	}

	// cluster.New reads this process's environment, as every command but
	// 'world' does. Whatever the developer's shell exported that would choose
	// an identity is removed first.
	for _, k := range []string{"KUBECONFIG", "CLOUDSDK_ACTIVE_CONFIG_NAME", "CLOUDSDK_AUTH_ACCESS_TOKEN", "CLOUDSDK_CORE_ACCOUNT"} {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	t.Setenv("HOME", home)
	t.Setenv("CLOUDSDK_CONFIG", gdir)
	t.Setenv("GORACE", "atexit_sleep_ms=0") // the fake is race-built; cluster.Env passes GORACE

	// An unpinned command reads the cluster first, as W.
	if _, err := cluster.New(dir.InstanceKubeconfigPath("atlas")).Workloads(context.Background(), "farcast-system"); err != nil {
		t.Fatalf("the unpinned read: %v", err)
	}
	if got := received(); len(got) != 1 || got[0] != "minted-for:"+accountW {
		t.Fatalf("the unpinned read presented %q; it runs as the active configuration, W", got)
	}

	// Then 'world', pinned to P.
	cmd := &worldCommand{
		now:     func() time.Time { return vectorNow },
		stamp:   func() buildStamp { return vectorStamp },
		environ: os.Environ,
	}
	env, out := testEnv(dir, output.ModeJSON)
	if err := cmd.Run(context.Background(), env, []string{"atlas"}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Sections map[string]sectionStatus `json:"sections"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Sections["apps"].Read {
		t.Fatalf("the apps section was not read through the fake kubectl: %+v", doc.Sections["apps"])
	}
	got := received()
	if len(got) == 0 {
		t.Fatal("world never asked the fake API server")
	}
	for _, tok := range got {
		if tok != "minted-for:"+accountP {
			t.Errorf("world presented %q; it must present only the pinned account's token, never one an unpinned command cached", tok)
		}
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
