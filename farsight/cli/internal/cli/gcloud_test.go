package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// The gcloud identity guard (ADR 0021 decision 9, amended 2026-11-12).

func guardMeta() *config.InstanceMetadata {
	return &config.InstanceMetadata{Name: "atlas", Project: "proj-atlas", GCloudAccount: "operator@example.org"}
}

func choose(t *testing.T, meta *config.InstanceMetadata, environ ...string) (gcloudChoice, error) {
	t.Helper()
	return chooseGCloud(environ, "atlas", meta)
}

func TestTheGuardChoosesTheConfigurationThatHasBothTheAccountAndTheProject(t *testing.T) {
	dir := fakeGCloudDir(t, "work",
		gcloudConfig{Name: "work", Account: "someone@work.example", Project: "work-prod"},
		gcloudConfig{Name: "zz-personal", Account: "Operator@Example.org", Project: "proj-atlas"},
		gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-atlas"},
		gcloudConfig{Name: "other", Account: "operator@example.org", Project: "proj-other"},
	)
	c, err := choose(t, guardMeta(), "CLOUDSDK_CONFIG="+dir)
	if err != nil {
		t.Fatal(err)
	}
	// Two match; the lexicographically first wins, the same on every run.
	if c.Config != "personal" || c.Dir != dir || c.Source != "$CLOUDSDK_CONFIG" {
		t.Errorf("chose %+v", c)
	}
}

// The active configuration is never consulted: neither active_config nor
// CLOUDSDK_ACTIVE_CONFIG_NAME moves the choice, and a work configuration that
// is active is not read as.
func TestTheGuardNeverReadsAsTheActiveConfiguration(t *testing.T) {
	dir := fakeGCloudDir(t, "work",
		gcloudConfig{Name: "work", Account: "someone@work.example", Project: "proj-atlas"},
		gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-atlas"},
	)
	c, err := choose(t, guardMeta(), "CLOUDSDK_CONFIG="+dir, "CLOUDSDK_ACTIVE_CONFIG_NAME=work", "CLOUDSDK_CORE_ACCOUNT=someone@work.example")
	if err != nil {
		t.Fatal(err)
	}
	if c.Config != "personal" {
		t.Errorf("chose %q; the active configuration must not decide", c.Config)
	}
}

func TestTheGuardRefusesBeforeAnythingRuns(t *testing.T) {
	right := gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-atlas"}
	for _, tc := range []struct {
		name    string
		meta    func(*config.InstanceMetadata)
		configs []gcloudConfig
		says    string
	}{
		{"no pinned account", func(m *config.InstanceMetadata) { m.GCloudAccount = "" }, []gcloudConfig{right}, "no pinned gcloud account"},
		{"no recorded project", func(m *config.InstanceMetadata) { m.Project = "" }, []gcloudConfig{right}, "records no cloud project"},
		{"another project", nil, []gcloudConfig{{Name: "personal", Account: "operator@example.org", Project: "proj-old"}}, "proj-old"},
		{"the right project, another account", nil, []gcloudConfig{{Name: "work", Account: "someone@work.example", Project: "proj-atlas"}},
			"the account differs from the one recorded"},
		{"a configuration with no account", nil, []gcloudConfig{{Name: "bare", Project: "proj-atlas"}}, "no account"},
		{"no configurations at all", nil, nil, "there are no gcloud configurations"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta := guardMeta()
			if tc.meta != nil {
				tc.meta(meta)
			}
			dir := fakeGCloudDir(t, "", tc.configs...)
			_, err := choose(t, meta, "CLOUDSDK_CONFIG="+dir)
			if kindOf(err) != kindGCloudMismatch {
				t.Fatalf("kind %q (%v), want gcloud_mismatch", kindOf(err), err)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the refusal does not say %q: %v", tc.says, err)
			}
			for _, email := range []string{"operator@example.org", "someone@work.example"} {
				if strings.Contains(err.Error(), email) {
					t.Errorf("the refusal names an account: %v", err)
				}
			}
		})
	}
}

// Without CLOUDSDK_CONFIG the directory is ~/.config/gcloud, and the message
// says so without the home directory's path.
func TestTheGuardReadsTheDefaultDirectory(t *testing.T) {
	home := t.TempDir()
	writeGCloudDir(t, home+"/.config/gcloud", "", gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-atlas"})
	c, err := choose(t, guardMeta(), "HOME="+home)
	if err != nil || c.Config != "personal" || c.Source != "~/.config/gcloud" || c.Dir != home+"/.config/gcloud" {
		t.Fatalf("chose %+v, %v", c, err)
	}
	meta := guardMeta()
	meta.Project = "elsewhere"
	if _, err := choose(t, meta, "HOME="+home); err == nil || strings.Contains(err.Error(), home) {
		t.Errorf("a refusal from the default directory: %v", err)
	}
}

func TestGCloudCoreReadsOnlyTheCoreSection(t *testing.T) {
	account, project := gcloudCore([]byte("# comment\n[compute]\naccount = wrong\n[core]\n  account= me@example.org \n; x\nproject =p1\n[other]\nproject = wrong\n"))
	if account != "me@example.org" || project != "p1" {
		t.Errorf("account=%q project=%q", account, project)
	}
}

// kubectl's environment pins the identity: the instance's own kubeconfig, the
// directory the guard read, the configuration it chose — and nothing that
// would choose another identity behind it.
func TestKubectlEnvironmentPinsTheIdentity(t *testing.T) {
	parent := []string{
		"PATH=/usr/local/bin:/usr/bin", "HOME=/Users/op", "LANG=en_GB.UTF-8",
		"KUBECONFIG=/Users/op/.kube/work", "CLOUDSDK_AUTH_ACCESS_TOKEN=planted", "CLOUDSDK_CORE_ACCOUNT=someone@work.example",
		"CLOUDSDK_CORE_PROJECT=work-prod", "CLOUDSDK_CONFIG=/Users/op/.config/gcloud-work", "CLOUDSDK_ACTIVE_CONFIG_NAME=work",
		"GOOGLE_APPLICATION_CREDENTIALS=/Users/op/key.json", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE=/tmp/t",
	}
	env := kubectlEnv(parent, "/cfg/instances/atlas/kubeconfig.yaml", gcloudChoice{Dir: "/Users/op/.config/gcloud", Config: "personal"})
	want := []string{
		"PATH=/usr/local/bin:/usr/bin", "HOME=/Users/op", "LANG=en_GB.UTF-8",
		"KUBECONFIG=/cfg/instances/atlas/kubeconfig.yaml",
		"CLOUDSDK_CONFIG=/Users/op/.config/gcloud",
		"CLOUDSDK_ACTIVE_CONFIG_NAME=personal",
	}
	if !slices.Equal(env, want) {
		t.Errorf("environment\n got %q\nwant %q", env, want)
	}
}

// The world command builds that environment and hands it to the cluster
// client — and refuses before building any client when the guard refuses.
func TestWorldRunsKubectlOnlyUnderTheGuard(t *testing.T) {
	f := newWorldFixture(t)
	f.run(t)
	if envValueOf(f.kenv, "KUBECONFIG") != f.dir.InstanceKubeconfigPath("atlas") ||
		envValueOf(f.kenv, "CLOUDSDK_ACTIVE_CONFIG_NAME") != "personal" || envValueOf(f.kenv, "CLOUDSDK_CONFIG") == "" {
		t.Errorf("kubectl's environment: %q", f.kenv)
	}

	f = newWorldFixture(t)
	built := false
	f.cmd.newCluster = func(string, []string) worldCluster { built = true; return f.cl }
	if _, err := f.dir.UpdateInstanceMetadata("atlas", func(m *config.InstanceMetadata) error {
		m.Project = "proj-moved"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(f.dir, output.ModeJSON)
	err := f.cmd.Run(context.Background(), env, []string{"atlas"})
	if kindOf(err) != kindGCloudMismatch || built || f.connects != 0 {
		t.Errorf("a read under the wrong project: kind %q, cluster built %v, dials %d (%v)", kindOf(err), built, f.connects, err)
	}
}

// pin-gcloud records the account, only when a configuration has it with the
// instance's project, and the listing then says it is pinned — never what to.
func TestPinGCloud(t *testing.T) {
	dir := vectorConfigDir(t)
	meta := vectorMeta()
	meta.GCloudAccount = ""
	writeRecord(t, dir, meta)
	gdir := fakeGCloudDir(t, "work",
		gcloudConfig{Name: "work", Account: "someone@work.example", Project: "work-prod"},
		gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-atlas"})
	cmd := func(account string) *instancesCommand {
		c := instancesVectorCommand()
		c.environ = func() []string { return []string{"CLOUDSDK_CONFIG=" + gdir} }
		c.account = account
		return c
	}

	env, _ := testEnv(dir, output.ModeJSON)
	err := cmd("someone@work.example").Run(context.Background(), env, []string{"pin-gcloud", "atlas"})
	if kindOf(err) != kindGCloudMismatch || strings.Contains(err.Error(), "someone@work.example") {
		t.Fatalf("pinning an account no configuration has with the project: kind %q, %v", kindOf(err), err)
	}
	if m, _ := dir.LoadInstanceMetadata("atlas"); m.GCloudAccount != "" {
		t.Fatalf("a refused pin was written: %q", m.GCloudAccount)
	}

	env, out := testEnv(dir, output.ModeJSON)
	if err := cmd("operator@example.org").Run(context.Background(), env, []string{"pin-gcloud", "atlas"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "operator@example.org") || !strings.Contains(out.String(), `"configuration":"personal"`) {
		t.Errorf("pin result: %s", out.String())
	}
	if m, _ := dir.LoadInstanceMetadata("atlas"); m.GCloudAccount != "operator@example.org" {
		t.Errorf("pinned %q", m.GCloudAccount)
	}

	got := runInstancesJSON(t, dir)
	var listing struct {
		Instances []map[string]any `json:"instances"`
	}
	if err := json.Unmarshal(got, &listing); err != nil {
		t.Fatal(err)
	}
	if listing.Instances[0]["gcloud_pinned"] != true || strings.Contains(string(got), "operator@example.org") {
		t.Errorf("the listing after a pin: %s", got)
	}

	for _, tc := range []struct {
		args    []string
		account string
	}{
		{[]string{"pin-gcloud"}, "x@y"},
		{[]string{"pin-gcloud", "atlas"}, ""},
		{[]string{"pin-gcloud", "atlas", "extra"}, "x@y"},
		{nil, "x@y"},
		{[]string{"atlas"}, ""},
	} {
		env, _ := testEnv(dir, output.ModeJSON)
		if err := cmd(tc.account).Run(context.Background(), env, tc.args); exitCodeOf(err) != 2 {
			t.Errorf("instances %v --account %q: %v, want a usage error", tc.args, tc.account, err)
		}
	}
	env, _ = testEnv(dir, output.ModeJSON)
	if err := cmd("x@y").Run(context.Background(), env, []string{"pin-gcloud", "nowhere"}); kindOf(err) != kindNotFound {
		t.Errorf("pinning an instance this machine does not hold: %v", err)
	}
}

// A configuration can carry the pinned account and the instance's project and
// still authenticate as someone else: [auth] impersonate_service_account,
// access_token_file and credential_file_override all make gcloud hand out
// another identity's token. Such a configuration is never chosen, even when
// it sorts first, and the refusal says why without naming any account.
func TestTheGuardNeverChoosesAConfigurationThatAuthenticatesAsAnotherIdentity(t *testing.T) {
	for _, override := range authOverrides {
		t.Run(override, func(t *testing.T) {
			dir := fakeGCloudDir(t, "",
				gcloudConfig{Name: "a-work-" + override, Account: "operator@example.org", Project: "proj-atlas", Override: override},
				gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-atlas"},
			)
			c, err := choose(t, guardMeta(), "CLOUDSDK_CONFIG="+dir)
			if err != nil || c.Config != "personal" {
				t.Fatalf("chose %+v, %v; want personal, which sets no [auth] override", c, err)
			}

			only := fakeGCloudDir(t, "",
				gcloudConfig{Name: "a-work-" + override, Account: "operator@example.org", Project: "proj-atlas", Override: override})
			_, err = choose(t, guardMeta(), "CLOUDSDK_CONFIG="+only)
			if kindOf(err) != kindGCloudMismatch {
				t.Fatalf("kind %q (%v), want gcloud_mismatch", kindOf(err), err)
			}
			if !strings.Contains(err.Error(), "[auth] "+override) {
				t.Errorf("the refusal does not say why: %v", err)
			}
			for _, account := range []string{"operator@example.org", "robot@work-prod.iam.gserviceaccount.com"} {
				if strings.Contains(err.Error(), account) {
					t.Errorf("the refusal names an account: %v", err)
				}
			}
		})
	}
}

func TestGCloudAuthOverrideReadsOnlyTheAuthSection(t *testing.T) {
	for _, tc := range []struct {
		file, want string
	}{
		{"[core]\naccount = me@example.org\n", ""},
		{"[core]\nimpersonate_service_account = sa@x.iam.gserviceaccount.com\n", ""},
		{"[auth]\nimpersonate_service_account =\n", ""},
		{"[auth]\ndisable_credentials = False\n", ""},
		{"[AUTH]\n Credential_File_Override = /k.json\n", "credential_file_override"},
		{"[auth]\naccess_token_file = /t\nimpersonate_service_account = sa@x\n", "access_token_file"},
	} {
		if got := gcloudAuthOverride([]byte(tc.file)); got != tc.want {
			t.Errorf("%q: override %q, want %q", tc.file, got, tc.want)
		}
	}
}

// pin-gcloud uses the same rule: an account whose only matching configuration
// authenticates as another identity cannot be pinned.
func TestPinGCloudRefusesAConfigurationWithAnAuthOverride(t *testing.T) {
	dir := vectorConfigDir(t)
	meta := vectorMeta()
	meta.GCloudAccount = ""
	writeRecord(t, dir, meta)
	gdir := fakeGCloudDir(t, "",
		gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-atlas", Override: "impersonate_service_account"})
	c := instancesVectorCommand()
	c.environ = func() []string { return []string{"CLOUDSDK_CONFIG=" + gdir} }
	c.account = "operator@example.org"
	env, _ := testEnv(dir, output.ModeJSON)
	err := c.Run(context.Background(), env, []string{"pin-gcloud", "atlas"})
	if kindOf(err) != kindGCloudMismatch || !strings.Contains(err.Error(), "[auth] impersonate_service_account") {
		t.Fatalf("kind %q, %v", kindOf(err), err)
	}
	if m, _ := dir.LoadInstanceMetadata("atlas"); m.GCloudAccount != "" {
		t.Errorf("a refused pin was written: %q", m.GCloudAccount)
	}
}

// A gcloud directory that cannot be read is named the way the operator set
// it — "$CLOUDSDK_CONFIG" or "~/.config/gcloud" — never by its absolute path:
// the refusal is printed as a document.
func TestGCloudReadErrorsNameNoAbsolutePath(t *testing.T) {
	home := t.TempDir()
	gdir := filepath.Join(home, ".config", "gcloud")
	writeGCloudDir(t, gdir, "", gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-atlas"})
	confs := filepath.Join(gdir, "configurations")
	file := filepath.Join(confs, "config_personal")
	for _, tc := range []struct {
		name     string
		path     string
		environ  []string
		mode     os.FileMode
		restore  os.FileMode
		mentions string
	}{
		{"the directory, by default", confs, []string{"HOME=" + home}, 0o000, 0o700, "~/.config/gcloud"},
		{"one file, under CLOUDSDK_CONFIG", file, []string{"CLOUDSDK_CONFIG=" + gdir}, 0o000, 0o600, "$CLOUDSDK_CONFIG"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(tc.path, tc.mode); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Chmod(tc.path, tc.restore) }()
			if _, err := os.ReadFile(file); err == nil {
				t.Skip("running as a user who can read through mode 000; the test would prove nothing")
			}
			_, err := choose(t, guardMeta(), tc.environ...)
			if kindOf(err) != kindGCloudMismatch {
				t.Fatalf("kind %q (%v), want gcloud_mismatch", kindOf(err), err)
			}
			if strings.Contains(err.Error(), home) || !strings.Contains(err.Error(), tc.mentions) {
				t.Errorf("the refusal: %v; want it to say %q and never %q", err, tc.mentions, home)
			}
		})
	}
}
