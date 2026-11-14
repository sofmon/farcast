package cluster

import (
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// GCloud pins the gcloud configuration kubectl's auth plugin acts as. The zero value is
// unpinned: the parent's CLOUDSDK_CONFIG and CLOUDSDK_ACTIVE_CONFIG_NAME, if set, pass through.
type GCloud struct {
	Dir    string // CLOUDSDK_CONFIG
	Config string // CLOUDSDK_ACTIVE_CONFIG_NAME; non-empty means pinned
}

// pinned reports whether g names a configuration.
func (g GCloud) pinned() bool { return g.Config != "" }

// windowsKeys pass through on Windows only: what a Windows process needs to
// start at all and to find its user's directories. Untested until ADR 0023 M4.
var windowsKeys = []string{"SYSTEMROOT", "USERPROFILE", "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "PATHEXT", "COMSPEC"}

// Env is kubectl's WHOLE environment, built from an allowlist (ADR 0023 M0); nothing else
// from parent reaches it. Sorted by key; each key once.
//
// What passes, and why:
//   - PATH, with every relative or empty entry removed and the order kept: kubectl, the
//     auth plugin its kubeconfig names and the gcloud the plugin runs are all found by
//     bare name, and a binary planted in the working directory must never be one of them.
//   - HOME and TMPDIR, only when absolute; LANG and LC_*.
//   - KUBECONFIG. Pinned, it names kubeconfig. Unpinned, it is the parent's, unchanged, or
//     absent. kubectl is always given --kubeconfig, so KUBECONFIG reaches only the auth
//     plugin, which keys its one token-cache entry by the current context of the file
//     KUBECONFIG names. An unpinned command that named the instance's kubeconfig there
//     would fill the very entry 'world' reads, under whichever identity is active; so only
//     'world', which is pinned, names it (ADR 0021 decision 9).
//   - KUBERC=off: no kuberc file can add flags or aliases to a call.
//   - CLOUDSDK_CONFIG and CLOUDSDK_ACTIVE_CONFIG_NAME: from gcloud when it is pinned, else
//     the parent's. They choose the gcloud configuration, which is today's identity for
//     every command but 'world' until ADR 0023's M2.
//   - GORACE: only race-instrumented Go binaries read it. A released kubectl or plugin is
//     not one; the rehearsal's fakes are, and without it each of their exits sleeps a
//     second.
//   - On Windows, the variables a process needs there (windowsKeys).
//
// Everything else is dropped: KUBECTL_* and KUBECACHEDIR, every other CLOUDSDK_*
// (CLOUDSDK_AUTH_ACCESS_TOKEN, CLOUDSDK_CORE_ACCOUNT and CLOUDSDK_PYTHON among them),
// GOOGLE_*, the proxies in either case, FARCAST_CONFIG_HOME, DYLD_*, LD_*, PYTHON*,
// BASH_ENV, ENV, SSL_CERT_* and REQUESTS_CA_BUNDLE.
func Env(parent []string, kubeconfig string, gcloud GCloud) []string {
	windows := runtime.GOOS == "windows"
	// The last value a key has is the one a process reading its environment
	// sees. Windows keys are case-insensitive, so they are compared upper-cased
	// there and written in the allowlist's case.
	last := map[string]string{}
	var order []string
	for _, kv := range parent {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		if windows {
			k = strings.ToUpper(k)
		}
		if _, seen := last[k]; !seen {
			order = append(order, k)
		}
		last[k] = v
	}

	out := map[string]string{}
	if v, ok := last["PATH"]; ok {
		if p := absoluteEntries(v); p != "" {
			out["PATH"] = p
		}
	}
	for _, k := range []string{"HOME", "TMPDIR"} {
		if v, ok := last[k]; ok && filepath.IsAbs(v) {
			out[k] = v
		}
	}
	for _, k := range order {
		if k == "LANG" || strings.HasPrefix(k, "LC_") {
			out[k] = last[k]
		}
	}
	if v, ok := last["GORACE"]; ok {
		out["GORACE"] = v
	}
	if gcloud.pinned() {
		out["KUBECONFIG"] = kubeconfig
		out["CLOUDSDK_ACTIVE_CONFIG_NAME"] = gcloud.Config
		if gcloud.Dir != "" {
			out["CLOUDSDK_CONFIG"] = gcloud.Dir
		}
	} else {
		for _, k := range []string{"KUBECONFIG", "CLOUDSDK_CONFIG", "CLOUDSDK_ACTIVE_CONFIG_NAME"} {
			if v, ok := last[k]; ok {
				out[k] = v
			}
		}
	}
	if windows {
		for _, k := range windowsKeys {
			if v, ok := last[k]; ok {
				out[k] = v
			}
		}
	}
	out["KUBERC"] = "off"

	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, k := range keys {
		env = append(env, k+"="+out[k])
	}
	return env
}

// absoluteEntries is a PATH value with every empty or relative entry removed,
// the order kept.
func absoluteEntries(path string) string {
	var keep []string
	for _, dir := range filepath.SplitList(path) {
		if dir != "" && filepath.IsAbs(dir) {
			keep = append(keep, dir)
		}
	}
	return strings.Join(keep, string(filepath.ListSeparator))
}

// withKubercOff is env with any KUBERC entry removed and KUBERC=off appended
// last. Env already sets it; this enforces it in the one place every kubectl
// call passes through, whatever environment a caller handed NewWithEnv.
func withKubercOff(env []string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if strings.EqualFold(k, "KUBERC") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "KUBERC=off")
}
