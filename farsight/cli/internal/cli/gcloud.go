package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// The gcloud identity guard (ADR 0021 decision 9, amended 2026-11-12, "The
// cloud identity is pinned").
//
// kubectl reaches a GKE cluster through gke-gcloud-auth-plugin, which asks
// gcloud for a token as whichever gcloud configuration is active. On an
// operator's Mac that is often a work identity. So every read 'world' makes
// runs as the account the instance's record pins, under a configuration whose
// account is that account and whose project is the instance's — chosen by
// reading gcloud's own configuration files, never by running gcloud, and never
// by asking which configuration happens to be active.

// gcloudConfig is one named gcloud configuration, as its file states it.
type gcloudConfig struct {
	Name    string
	Account string
	Project string
	// Override names the [auth] property this configuration sets that makes
	// gcloud hand out another identity's token whatever its account says —
	// impersonate_service_account, access_token_file or
	// credential_file_override — or is empty when it sets none.
	Override string
}

// gcloudChoice is the configuration a read runs under, and where it was read.
type gcloudChoice struct {
	// Dir is the gcloud configuration directory the guard read. kubectl's
	// gcloud is pointed at this same directory, so the two cannot check
	// different files.
	Dir string
	// Source names Dir without its absolute path: "$CLOUDSDK_CONFIG" or
	// "~/.config/gcloud". It is what messages say, so they are the same on
	// every machine.
	Source string
	// Config is the chosen configuration's name.
	Config string
}

// gcloudDirFrom resolves gcloud's configuration directory from an environment:
// CLOUDSDK_CONFIG when it is set, else ~/.config/gcloud.
func gcloudDirFrom(environ []string) (dir, source string, err error) {
	if v := envValueOf(environ, "CLOUDSDK_CONFIG"); v != "" {
		abs, err := filepath.Abs(v)
		if err != nil {
			return "", "", fmt.Errorf("resolve CLOUDSDK_CONFIG: %w", err)
		}
		return abs, "$CLOUDSDK_CONFIG", nil
	}
	home := envValueOf(environ, "HOME")
	if home == "" {
		if home, err = os.UserHomeDir(); err != nil {
			return "", "", fmt.Errorf("cannot find the home directory gcloud keeps its configuration in: %w", err)
		}
	}
	return filepath.Join(home, ".config", "gcloud"), "~/.config/gcloud", nil
}

// envValueOf is the last value environ gives key, the one a process sees.
func envValueOf(environ []string, key string) string {
	v := ""
	for _, kv := range environ {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			v = val
		}
	}
	return v
}

// readGCloudConfigs reads every configurations/config_<name> file under dir,
// sorted by name. A directory with no configurations is an empty list, not an
// error: the guard then refuses for want of a match, and says so.
//
// A file that cannot be read is named by source — "$CLOUDSDK_CONFIG" or
// "~/.config/gcloud" — and never by its absolute path: the refusal is printed
// as a document, and a document carries no home directory.
func readGCloudConfigs(dir, source string) ([]gcloudConfig, error) {
	entries, err := os.ReadDir(filepath.Join(dir, "configurations"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read gcloud's configurations in %s: %w", source, withoutPath(err))
	}
	var out []gcloudConfig
	for _, e := range entries {
		name, ok := strings.CutPrefix(e.Name(), "config_")
		if !ok || name == "" || !e.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "configurations", e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read gcloud configuration %q in %s: %w", name, source, withoutPath(err))
		}
		account, project := gcloudCore(data)
		out = append(out, gcloudConfig{Name: name, Account: account, Project: project, Override: gcloudAuthOverride(data)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// withoutPath is a file error's own reason, without the path it names.
func withoutPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// eachINI calls f with every key and value of a gcloud configuration file, an
// INI file, and the section it is in, lower-cased. Comments and blank lines
// are skipped.
func eachINI(data []byte, f func(section, key, value string)) {
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "", strings.HasPrefix(line, "#"), strings.HasPrefix(line, ";"):
			continue
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		f(section, strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v))
	}
}

// gcloudCore reads the account and project from the [core] section of a
// gcloud configuration file. Every other section is skipped.
func gcloudCore(data []byte) (account, project string) {
	eachINI(data, func(section, key, value string) {
		if section != "core" {
			return
		}
		switch key {
		case "account":
			account = value
		case "project":
			project = value
		}
	})
	return account, project
}

// authOverrides are the [auth] properties that make gcloud authenticate as
// something other than the configuration's [core] account: a service account
// it impersonates, a token read from a file, or another credential file. A
// configuration that sets one only looks like the pinned account.
var authOverrides = []string{"access_token_file", "credential_file_override", "impersonate_service_account"}

// gcloudAuthOverride is the first of authOverrides a configuration file sets
// to a value, or empty.
func gcloudAuthOverride(data []byte) string {
	set := map[string]bool{}
	eachINI(data, func(section, key, value string) {
		if section == "auth" && value != "" {
			set[key] = true
		}
	})
	for _, k := range authOverrides {
		if set[k] {
			return k
		}
	}
	return ""
}

// sameAccount compares gcloud accounts as email addresses: case does not make
// two accounts different.
func sameAccount(a, b string) bool {
	return a != "" && strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// matchingConfigs are the configurations whose account is account and whose
// project is project, in name order — leaving out any that sets an [auth]
// override, whose token would belong to another identity whatever its
// account says.
func matchingConfigs(configs []gcloudConfig, account, project string) []gcloudConfig {
	var out []gcloudConfig
	for _, c := range configs {
		if sameAccount(c.Account, account) && c.Project == project && c.Override == "" {
			out = append(out, c)
		}
	}
	return out
}

// consideredText says what each configuration was, for a refusal: its name
// and project, and whether its account is the one recorded — never the
// account itself.
func consideredText(configs []gcloudConfig, account string) string {
	if len(configs) == 0 {
		return "there are no gcloud configurations"
	}
	parts := make([]string, 0, len(configs))
	for _, c := range configs {
		project := c.Project
		if project == "" {
			project = "no project"
		} else {
			project = "project " + project
		}
		switch {
		case c.Account == "":
			parts = append(parts, fmt.Sprintf("%s (%s, no account)", c.Name, project))
		case !sameAccount(c.Account, account):
			parts = append(parts, fmt.Sprintf("%s (%s; the account differs from the one recorded)", c.Name, project))
		case c.Override != "":
			parts = append(parts, fmt.Sprintf("%s (%s; it sets [auth] %s, so it reads as another identity)", c.Name, project, c.Override))
		default:
			parts = append(parts, fmt.Sprintf("%s (%s)", c.Name, project))
		}
	}
	return "considered: " + strings.Join(parts, ", ")
}

// chooseGCloud picks the configuration an instance's cluster is read under, or
// refuses with gcloud_mismatch before anything runs.
//
// It refuses when the instance pins no account, when it records no project,
// and when no configuration has both — a configuration that has both but sets
// an [auth] override does not count, since gcloud would hand out another
// identity's token for it. Several matching configurations are
// told apart by name, the lexicographically first winning, so the choice is
// the same on every run. The active configuration — active_config, or
// CLOUDSDK_ACTIVE_CONFIG_NAME — is never consulted: that is exactly the
// "work identity that happens to be active" the ADR forbids reading as.
func chooseGCloud(environ []string, name string, meta *config.InstanceMetadata) (gcloudChoice, error) {
	if strings.TrimSpace(meta.GCloudAccount) == "" {
		return gcloudChoice{}, withKind(kindGCloudMismatch, fmt.Errorf(
			"instance %q has no pinned gcloud account, so it is not read as anyone; nothing was read. "+
				"Pin one from a terminal: farcast instances pin-gcloud %s --account <email>", name, name))
	}
	if meta.Project == "" {
		return gcloudChoice{}, withKind(kindGCloudMismatch, fmt.Errorf(
			"instance %q records no cloud project, so no gcloud configuration can be checked against it; nothing was read", name))
	}
	dir, source, err := gcloudDirFrom(environ)
	if err != nil {
		return gcloudChoice{}, withKind(kindGCloudMismatch, err)
	}
	configs, err := readGCloudConfigs(dir, source)
	if err != nil {
		return gcloudChoice{}, withKind(kindGCloudMismatch, err)
	}
	match := matchingConfigs(configs, meta.GCloudAccount, meta.Project)
	if len(match) == 0 {
		return gcloudChoice{}, withKind(kindGCloudMismatch, fmt.Errorf(
			"no gcloud configuration in %s has the account recorded for %q together with its project %q (%s); nothing was read. "+
				"Create one with that account and project, or pin another account with 'farcast instances pin-gcloud %s --account <email>'",
			source, name, meta.Project, consideredText(configs, meta.GCloudAccount), name))
	}
	return gcloudChoice{Dir: dir, Source: source, Config: match[0].Name}, nil
}

// kubectlEnv is the whole environment kubectl runs with for a read: this
// process's own, minus every variable that would choose an identity or a
// cluster behind the guard's back, plus the three that pin them.
//
//   - KUBECONFIG names the instance's own kubeconfig, so the auth plugin's
//     token cache — keyed by the current context of $KUBECONFIG, not by
//     kubectl's --kubeconfig — is keyed by this instance's context, never by
//     a work cluster's.
//   - CLOUDSDK_CONFIG names the directory the guard read, so gcloud checks
//     the same files.
//   - CLOUDSDK_ACTIVE_CONFIG_NAME names the configuration the guard chose.
//
// Dropped: KUBECONFIG, every CLOUDSDK_* variable (CLOUDSDK_AUTH_ACCESS_TOKEN
// and CLOUDSDK_CORE_ACCOUNT among them, which gcloud honours over its files),
// and GOOGLE_APPLICATION_CREDENTIALS.
func kubectlEnv(parent []string, kubeconfig string, c gcloudChoice) []string {
	out := make([]string, 0, len(parent)+3)
	for _, kv := range parent {
		k, _, _ := strings.Cut(kv, "=")
		if k == "KUBECONFIG" || k == "GOOGLE_APPLICATION_CREDENTIALS" || strings.HasPrefix(k, "CLOUDSDK_") {
			continue
		}
		out = append(out, kv)
	}
	return append(out,
		"KUBECONFIG="+kubeconfig,
		"CLOUDSDK_CONFIG="+c.Dir,
		"CLOUDSDK_ACTIVE_CONFIG_NAME="+c.Config,
	)
}
