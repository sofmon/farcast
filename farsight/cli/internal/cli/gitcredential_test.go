package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	pbuild "github.com/sofmon/farcast/planck/build"
	pfetch "github.com/sofmon/farcast/planck/fetch"
)

// The git-credential fixture (ADR 0023 M2.8, design §33, A33-29 to A33-33):
// the Git credential's name, and a username and a token that are markers:
// no plan, result or error may carry either, but the username where A33-30
// allows it (the question, and the confirm line after digest:).
const (
	gitCredentialName     = "repo-git"
	gitCredentialUsername = "GITCRED-USERNAME-MARKER"
	gitCredentialToken    = "GITCRED-TOKEN-MARKER"
	// gitCredentialSeededUID is the uid of the Git credential
	// gitCredentialSeeded puts in a cluster.
	gitCredentialSeededUID = "00000000-0000-4000-8000-0000000000e1"
)

// gitCredentialPath is the Git credential's Secret, as the API addresses it.
var gitCredentialPath = "/api/v1/namespaces/" + gitCredentialNamespace + "/secrets/" + gitCredentialName

// gitCredentialSetFlags are git-credential set's flags for the fixture's
// credential, its token read from stdin (-), which a test's fake readToken
// answers in its place (gitCredentialTokenOf), or a pipe does.
func gitCredentialSetFlags() []string {
	return []string{"--name", gitCredentialName, "--username", gitCredentialUsername, "--token-file", "-"}
}

// gitCredentialTokenOf is a readToken that answers raw, whatever the path.
func gitCredentialTokenOf(raw string) func(*Env, string) ([]byte, error) {
	return func(*Env, string) ([]byte, error) { return []byte(raw), nil }
}

// gitCredentialLabels are the two labels a Git credential farcast wrote
// carries, as a stored object's metadata holds them.
func gitCredentialLabels() map[string]any {
	return map[string]any{gitCredentialManagedBy: "farcast", gitCredentialComponent: gitCredentialLabel}
}

// gitCredentialSeeded puts the fixture's Git credential in s, as
// git-credential set left it, at gitCredentialSeededUID.
func gitCredentialSeeded(s *kubetest.Server) {
	secretIn(s, gitCredentialName, gitCredentialSeededUID, gitCredentialLabels())
}

// secretIn puts the Secret farcast-system/name in s, at uid, with labels
// (nil for none).
func secretIn(s *kubetest.Server, name, uid string, labels map[string]any) {
	md := map[string]any{"name": name, "namespace": gitCredentialNamespace, "uid": uid}
	if labels != nil {
		md["labels"] = labels
	}
	s.Put(map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": md, "type": "Opaque",
		"data": map[string]any{"username": base64.StdEncoding.EncodeToString([]byte("seeded"))}})
}

// gitCredentialRun is one run of git-credential set or rm on writeInstance's
// fixture, its writer the package's loopback default: its flags, the output
// mode, stdin (no terminal when nil), and edit, when set, which sets the
// command's other seams once its flags are parsed.
type gitCredentialRun struct {
	action string
	flags  []string
	mode   output.Mode
	in     io.Reader
	edit   func(c *gitCredentialCommand)
}

// run runs it against dir, and returns what it printed and its error.
func (g gitCredentialRun) run(t *testing.T, dir config.Dir) (stdout, stderr string, err error) {
	t.Helper()
	cmd := withFlags(t, &gitCredentialCommand{action: g.action}, g.flags...)
	if g.edit != nil {
		g.edit(cmd)
	}
	env, out, errb := testEnvBoth(dir, g.mode)
	if g.in != nil {
		env.In = g.in
	}
	err = cmd.Run(t.Context(), env, []string{writeName})
	return out.String(), errb.String(), err
}

// planned is g's plan, printed in JSON with --plan.
func (g gitCredentialRun) planned(t *testing.T, dir config.Dir) plan.Document {
	t.Helper()
	p := g
	p.flags, p.mode = append(slices.Clone(g.flags), "--plan"), output.ModeJSON
	stdout, stderr, err := p.run(t, dir)
	if err != nil {
		t.Fatalf("git-credential %s --plan: %v\n%s", g.action, err, stderr)
	}
	return printedDocument(t, []byte(stdout))
}

// confirmed is g run with --confirm and its own plan's digest.
func (g gitCredentialRun) confirmed(t *testing.T, dir config.Dir) (stdout, stderr string, err error) {
	t.Helper()
	c := g
	c.flags = append(slices.Clone(g.flags), "--confirm", g.planned(t, dir).Digest)
	return c.run(t, dir)
}

// interactive is edit that also answers the terminal seam yes.
func interactive(edit func(c *gitCredentialCommand)) func(c *gitCredentialCommand) {
	return func(c *gitCredentialCommand) {
		c.interactive = func(*Env) bool { return true }
		if edit != nil {
			edit(c)
		}
	}
}

// setRun is git-credential set of the fixture's credential, its token raw.
func setRun(raw string) gitCredentialRun {
	return gitCredentialRun{action: plan.GitCredentialSet, flags: gitCredentialSetFlags(), mode: output.ModeJSON,
		edit: func(c *gitCredentialCommand) { c.readToken = gitCredentialTokenOf(raw) }}
}

// rmRun is git-credential rm of the fixture's credential.
func rmRun() gitCredentialRun {
	return gitCredentialRun{action: plan.GitCredentialRm, flags: []string{"--name", gitCredentialName}, mode: output.ModeJSON}
}

// requestsTo is every request s saw of method on path.
func requestsTo(s *kubetest.Server, method, path string) []kubetest.Request {
	var out []kubetest.Request
	for _, r := range s.Requests() {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

// appliedSecret is an applied Git credential's body, decoded.
type appliedSecret struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string            `yaml:"name"`
		Namespace string            `yaml:"namespace"`
		Labels    map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Type string            `yaml:"type"`
	Data map[string]string `yaml:"data"`
}

func decodeSecret(t *testing.T, body []byte) appliedSecret {
	t.Helper()
	var s appliedSecret
	if err := yaml.Unmarshal(body, &s); err != nil {
		t.Fatalf("the applied Secret does not decode: %v", err)
	}
	return s
}

// decoded is a data value, base64-decoded.
func decoded(t *testing.T, v string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("a data value is not base64: %v", err)
	}
	return string(b)
}

// ADR 0023 M2.8 (design §33, A33-29, A33-30 step 2; rows 114 and 114a):
// --yes never writes or deletes a Git credential. git-credential set and rm,
// with --yes or -y, are refused with their usage error, exit 2, before
// anything is read or sent, naming the instance, or <instance> for a line
// that names none or no valid one; through the router too, printing nothing
// on stdout. Both flags are registered, so that they can be refused.
func TestGitCredentialRefusesYes(t *testing.T) {
	for _, action := range []string{plan.GitCredentialSet, plan.GitCredentialRm} {
		flags := []string{"--name", gitCredentialName}
		if action == plan.GitCredentialSet {
			flags = gitCredentialSetFlags()
		}
		for _, yes := range []string{"--yes", "-y"} {
			for _, tc := range []struct {
				args  []string
				shown string
			}{
				{[]string{writeName}, writeName},
				{[]string{"../other"}, "<instance>"},
				{nil, "<instance>"},
				{[]string{writeName, "extra"}, "<instance>"},
			} {
				t.Run(action+" "+yes+" "+strings.Join(tc.args, " "), func(t *testing.T) {
					s := kubetest.New(t)
					dir, _ := writeInstance(t, s, true)
					reads := observeConfigReads(t)
					cmd := withFlags(t, &gitCredentialCommand{action: action}, append(slices.Clone(flags), yes)...)
					env, out, errb := testEnvBoth(dir, output.ModeJSON)
					err := cmd.Run(t.Context(), env, tc.args)
					want := fmt.Sprintf(msgGitCredentialYes, action, action, tc.shown)
					var ue *usageError
					if !errors.As(err, &ue) || err.Error() != want || exitCodeOf(err) != 2 {
						t.Fatalf("git-credential %s %s = %v; want the usage error %q", action, yes, err, want)
					}
					if got := reads(); len(got) != 0 || out.Len()+errb.Len() != 0 || len(s.Requests()) != 0 {
						t.Errorf("read %q, printed %q %q and sent %d requests before refusing", got, out, errb, len(s.Requests()))
					}
				})
			}
			t.Run(action+" "+yes+" through the router", func(t *testing.T) {
				s := kubetest.New(t)
				dir, _ := writeInstance(t, s, true)
				before := treeFiles(t, string(dir))
				stdout, stderr, code := farcastIn(t, dir, append([]string{"git-credential", action, writeName}, append(slices.Clone(flags), yes)...)...)
				if code != 2 || stdout != "" || !strings.Contains(stderr, fmt.Sprintf(msgGitCredentialYes, action, action, writeName)) {
					t.Errorf("exit %d, %q %q; want exit 2 and the --yes refusal", code, stdout, stderr)
				}
				if len(s.Requests()) != 0 {
					t.Errorf("sent %d requests", len(s.Requests()))
				}
				sameFiles(t, "git-credential "+action+" "+yes, before, treeFiles(t, string(dir)))
			})
		}
		fs := commandFlags(&gitCredentialCommand{action: action})
		if fs.Lookup("yes") == nil || fs.Lookup("y") == nil {
			t.Errorf("git-credential %s does not register --yes and -y, so they could not be refused", action)
		}
	}
}

// ADR 0023 M2.8 (design §33, A33-29): the usage checks, each a usage error,
// exit 2, before anything is read or sent: the argument count; a name that
// is not a DNS-1123 subdomain; for set, a username that is not 1 to 256
// printable bytes with no whitespace, and no --token-file. Each refuses in
// every mode, --plan included, and no refusal quotes a username.
func TestGitCredentialRefusesWhatItsUsageRefuses(t *testing.T) {
	long := strings.Repeat("a", 254)
	for _, tc := range []struct {
		name   string
		action string
		args   []string
		flags  []string
		want   string
	}{
		{"no instance", plan.GitCredentialRm, nil, []string{"--name", gitCredentialName}, "git-credential rm takes one instance name"},
		{"two instances", plan.GitCredentialSet, []string{writeName, "other"}, gitCredentialSetFlags(), "git-credential set takes one instance name"},
		{"no name", plan.GitCredentialRm, []string{writeName}, nil, fmt.Sprintf(msgGitCredentialName, "")},
		{"an upper-case name", plan.GitCredentialRm, []string{writeName}, []string{"--name", "Repo-git"}, fmt.Sprintf(msgGitCredentialName, "Repo-git")},
		{"an underscore", plan.GitCredentialSet, []string{writeName}, []string{"--name", "repo_git", "--username", "u", "--token-file", "-"},
			fmt.Sprintf(msgGitCredentialName, "repo_git")},
		{"a name ending in -", plan.GitCredentialRm, []string{writeName}, []string{"--name", "repo-"}, fmt.Sprintf(msgGitCredentialName, "repo-")},
		{"an empty label", plan.GitCredentialRm, []string{writeName}, []string{"--name", "repo..git"}, fmt.Sprintf(msgGitCredentialName, "repo..git")},
		{"254 characters", plan.GitCredentialRm, []string{writeName}, []string{"--name", long}, fmt.Sprintf(msgGitCredentialName, long)},
		{"no username", plan.GitCredentialSet, []string{writeName}, []string{"--name", gitCredentialName, "--token-file", "-"}, msgGitCredentialUsername},
		{"a username with a space", plan.GitCredentialSet, []string{writeName},
			[]string{"--name", gitCredentialName, "--username", gitCredentialUsername + " x", "--token-file", "-"}, msgGitCredentialUsername},
		{"a username with a tab", plan.GitCredentialSet, []string{writeName},
			[]string{"--name", gitCredentialName, "--username", gitCredentialUsername + "\tx", "--token-file", "-"}, msgGitCredentialUsername},
		{"a username with a control byte", plan.GitCredentialSet, []string{writeName},
			[]string{"--name", gitCredentialName, "--username", gitCredentialUsername + "\x1b", "--token-file", "-"}, msgGitCredentialUsername},
		{"a username beyond ASCII", plan.GitCredentialSet, []string{writeName},
			[]string{"--name", gitCredentialName, "--username", gitCredentialUsername + "é", "--token-file", "-"}, msgGitCredentialUsername},
		{"a username of 257 bytes", plan.GitCredentialSet, []string{writeName},
			[]string{"--name", gitCredentialName, "--username", strings.Repeat("u", 257), "--token-file", "-"}, msgGitCredentialUsername},
		{"no --token-file", plan.GitCredentialSet, []string{writeName}, []string{"--name", gitCredentialName, "--username", gitCredentialUsername}, msgGitCredentialNoFile},
	} {
		for _, answer := range [][]string{nil, {"--plan"}, {"--confirm", sampleDigest}} {
			t.Run(tc.name+" "+strings.Join(answer, " "), func(t *testing.T) {
				s := kubetest.New(t)
				dir, _ := writeInstance(t, s, true)
				reads := observeConfigReads(t)
				g := gitCredentialRun{action: tc.action, flags: append(slices.Clone(tc.flags), answer...), mode: output.ModeJSON, edit: interactive(nil)}
				cmd := withFlags(t, &gitCredentialCommand{action: g.action}, g.flags...)
				g.edit(cmd)
				env, out, errb := testEnvBoth(dir, g.mode)
				err := cmd.Run(t.Context(), env, tc.args)
				var ue *usageError
				if !errors.As(err, &ue) || err.Error() != tc.want || exitCodeOf(err) != 2 {
					t.Fatalf("= %v; want the usage error %q", err, tc.want)
				}
				if strings.Contains(err.Error(), gitCredentialUsername) {
					t.Errorf("the refusal quotes the username: %q", err)
				}
				if got := reads(); len(got) != 0 || out.Len()+errb.Len() != 0 || len(s.Requests()) != 0 {
					t.Errorf("read %q, printed %q %q and sent %d requests before refusing", got, out, errb, len(s.Requests()))
				}
			})
		}
	}
	// 253 characters, in labels, is a name.
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(name) != 253 {
		t.Fatalf("guard: the name is %d characters", len(name))
	}
	_, dir := planFixture(t, planCommandNamed(t, "git-credential rm", "a credential farcast wrote"))
	g := gitCredentialRun{action: plan.GitCredentialRm, flags: []string{"--name", name}}
	if b := decodedBound(t, g.planned(t, dir)); b.Options[0].Value != name {
		t.Errorf("the plan binds --name=%q", b.Options[0].Value)
	}
}

// ADR 0023 M2.8 (design §33, A33-29, row 115): a Git credential may not
// take the name of a Secret FarCast's renderers write. Every Secret of every
// rendered stream (renderedStreams), but a Git credential's own, is refused
// as --name by git-credential set and rm, with A33-29's usage error, exit
// 2, in every mode, before anything is read: no list is kept here, so a
// renderer's new Secret that the command does not refuse fails this test.
func TestGitCredentialRefusesEveryRenderedSecretName(t *testing.T) {
	var names []string
	ours := 0
	for _, rs := range renderedStreams(t) {
		docs, err := kube.SplitStream(rs.stream)
		if err != nil {
			t.Fatalf("%s: %v", rs.name, err)
		}
		for _, d := range docs {
			if d.Kind.Kind != "Secret" {
				continue
			}
			if renderedObjectOf(t, d).Metadata.Labels[gitCredentialComponent] == gitCredentialLabel {
				ours++
				continue
			}
			if !slices.Contains(names, d.Name) {
				names = append(names, d.Name)
			}
		}
	}
	// A guard on the derivation, not the list: the renderers' Secrets are
	// FatLine's, the keyholder's and the applications' egress credentials,
	// and the Git credential's own stream is there and set apart.
	for _, want := range []string{"fatline-mtls", "datasphered-mtls", "api-egress"} {
		if !slices.Contains(names, want) {
			t.Errorf("renderedStreams renders no Secret %s, so this test derives too little: %q", want, names)
		}
	}
	if ours != 1 {
		t.Errorf("renderedStreams renders %d Git credentials; want git-credential set's", ours)
	}
	for _, name := range names {
		for _, action := range []string{plan.GitCredentialSet, plan.GitCredentialRm} {
			for _, answer := range [][]string{nil, {"--plan"}, {"--confirm", sampleDigest}} {
				t.Run(action+" "+name+" "+strings.Join(answer, " "), func(t *testing.T) {
					s := kubetest.New(t)
					dir, _ := writeInstance(t, s, true)
					flags := []string{"--name", name}
					if action == plan.GitCredentialSet {
						flags = append(flags, "--username", gitCredentialUsername, "--token-file", "-")
					}
					reads := observeConfigReads(t)
					g := gitCredentialRun{action: action, flags: append(flags, answer...), mode: output.ModeJSON, edit: interactive(nil)}
					stdout, stderr, err := g.run(t, dir)
					want := fmt.Sprintf(msgGitCredentialReserved, gitCredentialNamespace, name)
					var ue *usageError
					if !errors.As(err, &ue) || err.Error() != want || exitCodeOf(err) != 2 {
						t.Fatalf("git-credential %s --name %s = %v; want the usage error %q", action, name, err, want)
					}
					if got := reads(); len(got) != 0 || stdout+stderr != "" || len(s.Requests()) != 0 {
						t.Errorf("read %q, printed %q %q and sent %d requests before refusing", got, stdout, stderr, len(s.Requests()))
					}
				})
			}
		}
	}
}

// ADR 0023 M2.8 (design §33, A33-30 step 5, row 139; review S-S5-1 and
// C-S5-3): --token-file - reads the token from stdin, so where stdin is a
// terminal it would be read with echo on, and so would a --token-file path
// that names a character device, such as a terminal (/dev/tty, or
// /dev/stdin from one, which is a symbolic link on macOS).
//   - With stdin a terminal, an interactive run and a --confirm run of set
//     each refuse -, and with stdin no terminal each refuses a path that
//     names a device, or a symbolic link to one, exit 2, before the record is
//     read and before anything is sent; a --plan run, which reads no token,
//     accepts either, and reads none.
//   - With stdin a terminal, a --confirm run of set given a file reads the
//     file and applies it: step 5's stdin refusal is for - alone.
//   - A path that names a device only once step 5 has passed, one swapped
//     since, is refused by the read itself with its own text, exit 1, after
//     the Secret's read and with nothing applied. The read refuses a device
//     it opened before reading a byte of it, which /dev/null cannot show:
//     TestGitCredentialReadRefusesATerminalBeforeReadingIt shows it on a
//     pseudo-terminal.
func TestGitCredentialRefusesATokenFileFromTheTerminal(t *testing.T) {
	tty, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tty.Close() }()
	if !isTerminal(tty) || !namesADevice(os.DevNull) {
		t.Fatalf("%s is not taken for a terminal here, so this test would prove nothing", os.DevNull)
	}
	// link is a symbolic link to a device: a check of the link itself, not
	// of what it names, would let it through.
	link := filepath.Join(t.TempDir(), "token-link")
	if err := os.Symlink(os.DevNull, link); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 || info.Mode()&os.ModeCharDevice != 0 {
		t.Fatalf("%s is not a symbolic link here, so its rows would prove nothing", link)
	}
	for _, tc := range []struct {
		name    string
		mode    output.Mode
		answer  []string
		file    string // --token-file; stdin is tty for -, and no terminal for a path
		refused string // the usage error's text, or "" for none
	}{
		{"interactive", output.ModeHuman, nil, "-", msgGitCredentialStdinTerminal},
		{"--confirm", output.ModeJSON, []string{"--confirm", sampleDigest}, "-", msgGitCredentialStdinTerminal},
		{"--confirm, human", output.ModeHuman, []string{"--confirm", sampleDigest}, "-", msgGitCredentialStdinTerminal},
		{"--plan", output.ModeHuman, []string{"--plan"}, "-", ""},
		{"--plan, json", output.ModeJSON, []string{"--plan"}, "-", ""},
		{"a device, interactive", output.ModeHuman, nil, os.DevNull, msgGitCredentialTokenDevice},
		{"a device, --confirm", output.ModeJSON, []string{"--confirm", sampleDigest}, os.DevNull, msgGitCredentialTokenDevice},
		{"a device, --plan", output.ModeJSON, []string{"--plan"}, os.DevNull, ""},
		{"a link to a device, interactive", output.ModeHuman, nil, link, msgGitCredentialTokenDevice},
		{"a link to a device, --confirm", output.ModeJSON, []string{"--confirm", sampleDigest}, link, msgGitCredentialTokenDevice},
		{"a link to a device, --plan", output.ModeJSON, []string{"--plan"}, link, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, true)
			var tokens int
			in := io.Reader(tty)
			if tc.file != "-" {
				in = strings.NewReader("")
			}
			flags := []string{"--name", gitCredentialName, "--username", gitCredentialUsername, "--token-file", tc.file}
			g := gitCredentialRun{action: plan.GitCredentialSet, flags: append(flags, tc.answer...), mode: tc.mode, in: in,
				edit: func(c *gitCredentialCommand) {
					if tc.file != "-" {
						// stdin is no terminal here, so the run is interactive
						// only by the seam.
						c.interactive = func(*Env) bool { return tc.answer == nil }
					}
					c.readToken = func(env *Env, path string) ([]byte, error) {
						tokens++
						return gitCredentialTokenOf(gitCredentialToken)(env, path)
					}
				}}
			reads := observeConfigReads(t)
			stdout, stderr, err := g.run(t, dir)
			if tokens != 0 || len(s.Requests()) != 0 {
				t.Errorf("read the token %d times and sent %d requests", tokens, len(s.Requests()))
			}
			if tc.refused == "" {
				if err != nil || !strings.Contains(stdout, "digest") {
					t.Errorf("--plan with --token-file %s = %v, %q %q; want the plan", tc.file, err, stdout, stderr)
				}
				return
			}
			var ue *usageError
			if !errors.As(err, &ue) || err.Error() != tc.refused || exitCodeOf(err) != 2 {
				t.Fatalf("= %v; want the usage error %q", err, tc.refused)
			}
			for _, p := range reads() {
				if strings.HasPrefix(p, dir.InstancePath(writeName)) {
					t.Errorf("read %s before refusing", p)
				}
			}
			if stdout+stderr != "" {
				t.Errorf("printed %q %q before refusing", stdout, stderr)
			}
		})
	}
	t.Run("a file, with stdin a terminal", func(t *testing.T) {
		for _, out := range []struct {
			name string
			mode output.Mode
		}{{"json", output.ModeJSON}, {"human", output.ModeHuman}} {
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, true)
			p := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(p, []byte(gitCredentialToken+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			g := gitCredentialRun{action: plan.GitCredentialSet, mode: out.mode, in: tty,
				flags: []string{"--name", gitCredentialName, "--username", gitCredentialUsername, "--token-file", p}}
			_, stderr, err := g.confirmed(t, dir)
			applied := requestsTo(s, http.MethodPatch, gitCredentialPath)
			if err != nil || len(applied) != 1 {
				t.Fatalf("-o %s: = %v, %d applies; want the file read and applied once\n%s", out.name, err, len(applied), stderr)
			}
			if got := decoded(t, decodeSecret(t, applied[0].Body).Data[pfetch.SecretGitToken]); got != gitCredentialToken {
				t.Errorf("-o %s: the applied token is not the file's", out.name)
			}
		}
	})
	t.Run("a path swapped for a device after step 5", func(t *testing.T) {
		s := kubetest.New(t)
		dir, _ := writeInstance(t, s, true)
		swapped := filepath.Join(t.TempDir(), "token-swapped")
		file := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(file, []byte(gitCredentialToken), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(file, swapped); err != nil {
			t.Fatal(err)
		}
		g := gitCredentialRun{action: plan.GitCredentialSet, mode: output.ModeJSON,
			flags: []string{"--name", gitCredentialName, "--username", gitCredentialUsername, "--token-file", swapped},
			edit: func(c *gitCredentialCommand) {
				// The writer opens at step 9, past step 5's check: the link
				// is pointed at a device then.
				c.newCluster = func(r clusterRef) (gitCredentialCluster, error) {
					if err := os.Remove(swapped); err != nil {
						return nil, err
					}
					if err := os.Symlink(os.DevNull, swapped); err != nil {
						return nil, err
					}
					return gitCredentialWriterDefault(r)
				}
			}}
		_, _, err := g.confirmed(t, dir)
		want := "read the token from --token-file: " + swapped + " is a device, such as a terminal, which would show the token as it is typed; nothing was written"
		var ue *usageError
		if err == nil || err.Error() != want || errors.As(err, &ue) || exitCodeOf(err) != 1 {
			t.Fatalf("= %v; want %q, exit 1", err, want)
		}
		if got, applied := len(requestsTo(s, http.MethodGet, gitCredentialPath)), len(requestsTo(s, http.MethodPatch, gitCredentialPath)); got != 1 || applied != 0 {
			t.Errorf("%d reads of the Secret and %d applies; want the read before the refusal, and nothing applied", got, applied)
		}
	})
	t.Run("the read refuses a device", func(t *testing.T) {
		env, _, _ := testEnvBoth(config.Dir(t.TempDir()), output.ModeJSON)
		raw, err := readGitToken(env, os.DevNull)
		if want := os.DevNull + " is a device, such as a terminal, which would show the token as it is typed"; err == nil || err.Error() != want || raw != nil {
			t.Errorf("readGitToken(%s) = %q, %v; want it refused with %q, nothing read", os.DevNull, raw, err, want)
		}
		// A file is read as it was.
		p := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(p, []byte("tok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if raw, err := readGitToken(env, p); err != nil || string(raw) != "tok\n" {
			t.Errorf("readGitToken(a file) = %q, %v", raw, err)
		}
	})
}

// ADR 0023 M2.8 (design §33, A33-30, A33-32, row 111): the token is never on
// argv or in a plan, and the username only where A33-30 allows it.
//   - git-credential set registers no flag that takes a value but --name,
//     --username and --token-file, so there is no --token.
//   - Its plan, in JSON and as a human reads it, holds neither marker, but
//     the confirm line after digest:, which repeats the command as typed,
//     --username among it. Its write binds the SHA-256 of the Secret rendered
//     from the placeholders, never the real one's, and two tokens and two
//     usernames plan the same bytes.
//   - Its --confirm, through the router with the token in a file, prints
//     neither marker in its result, on stderr or in any request's query;
//     only the apply's body holds the token, in base64.
//   - Every refusal (the username's, the token's, another Secret's, a refused
//     apply) prints neither marker.
func TestGitCredentialTokenNeverOnArgvOrInThePlan(t *testing.T) {
	t.Run("the flags", func(t *testing.T) {
		valued := map[string][]string{}
		for _, action := range []string{plan.GitCredentialSet, plan.GitCredentialRm} {
			global := unboundFlags()
			commandFlags(&gitCredentialCommand{action: action}).VisitAll(func(f *flag.Flag) {
				if !global[f.Name] && !isBoolFlag(f) {
					valued[action] = append(valued[action], f.Name)
				}
			})
			slices.Sort(valued[action])
		}
		if got := valued[plan.GitCredentialSet]; !slices.Equal(got, []string{"name", "token-file", "username"}) {
			t.Errorf("git-credential set's own flags that take a value are %q; want --name, --token-file and --username alone", got)
		}
		if got := valued[plan.GitCredentialRm]; !slices.Equal(got, []string{"name"}) {
			t.Errorf("git-credential rm's own flags that take a value are %q; want --name alone", got)
		}
	})

	tokenFile := func(t *testing.T, raw string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	line := func(dir config.Dir, username, file string, extra ...string) []string {
		return append([]string{"farcast", "--config", string(dir), "git-credential", "set", writeName,
			"--name", gitCredentialName, "--username", username, "--token-file", file}, extra...)
	}
	markers := []string{gitCredentialUsername, gitCredentialToken, base64.StdEncoding.EncodeToString([]byte(gitCredentialToken))}

	t.Run("the plan", func(t *testing.T) {
		s := kubetest.New(t)
		dir, _ := writeInstance(t, s, true)
		file := tokenFile(t, gitCredentialToken+"\n")
		js, stderr, code := runLine(line(dir, gitCredentialUsername, file, "-o", "json", "--plan"))
		if code != 0 {
			t.Fatalf("--plan: exit %d, %s", code, stderr)
		}
		human, _, _ := runLine(line(dir, gitCredentialUsername, file, "--plan"))
		for _, m := range markers {
			if strings.Contains(js, m) {
				t.Errorf("the JSON plan holds %q:\n%s", m, js)
			}
		}
		before, after, ok := strings.Cut(human, "\ndigest: ")
		if !ok || strings.Contains(before, gitCredentialUsername) || strings.Contains(human, gitCredentialToken) {
			t.Errorf("the plan's rendering holds a marker before digest:, or the token anywhere:\n%s", human)
		}
		if !strings.Contains(after, "--username "+gitCredentialUsername+" ") {
			t.Errorf("the confirm line does not repeat --username as typed:\n%s", after)
		}
		b := decodedBound(t, printedDocument(t, []byte(js)))
		user, token := gitCredentialPlaceholders(gitCredentialName)
		placeholder, err := renderGitCredential(gitCredentialName, user, token)
		if err != nil {
			t.Fatal(err)
		}
		real, err := renderGitCredential(gitCredentialName, []byte(gitCredentialUsername), []byte(gitCredentialToken))
		if err != nil {
			t.Fatal(err)
		}
		writes := applyWrites(b)
		want, notWant := sha256.Sum256(placeholder), sha256.Sum256(real)
		if len(writes) != 1 || writes[0].SHA256 != hex.EncodeToString(want[:]) || writes[0].SHA256 == hex.EncodeToString(notWant[:]) {
			t.Errorf("the plan's write is %+v; want the placeholder rendering's SHA-256 %x", writes, want)
		}
		other, _, _ := runLine(line(dir, "another-user", tokenFile(t, "another-token\n"), "-o", "json", "--plan"))
		if printedDocument(t, []byte(other)).Digest != printedDocument(t, []byte(js)).Digest {
			t.Errorf("another username and token plan another plan:\n%s\n%s", js, other)
		}
		if len(s.Requests()) != 0 {
			t.Errorf("the plans sent %d requests", len(s.Requests()))
		}
		vector, err := os.ReadFile(filepath.Join("testdata", "plan", "git_credential_set.json"))
		if err != nil || bytes.Contains(vector, []byte(vectorGitUsername)) {
			t.Errorf("the git_credential_set vector (%v) holds its --username marker", err)
		}
	})

	t.Run("the confirm", func(t *testing.T) {
		s := kubetest.New(t)
		dir, _ := writeInstance(t, s, true)
		file := tokenFile(t, gitCredentialToken+"\n")
		js, _, _ := runLine(line(dir, gitCredentialUsername, file, "-o", "json", "--plan"))
		digest := printedDocument(t, []byte(js)).Digest
		for _, mode := range []string{"json", "human"} {
			stdout, stderr, code := runLine(line(dir, gitCredentialUsername, file, "-o", mode, "--confirm", digest))
			if code != 0 {
				t.Fatalf("--confirm -o %s: exit %d, %s", mode, code, stderr)
			}
			for _, m := range markers {
				if strings.Contains(stdout, m) || strings.Contains(stderr, m) {
					t.Errorf("--confirm -o %s printed %q:\n%s\n%s", mode, m, stdout, stderr)
				}
			}
		}
		applies := 0
		for _, r := range s.Requests() {
			for _, m := range markers {
				if strings.Contains(r.RawQuery, m) {
					t.Errorf("%s %s?%s carries %q in its query", r.Method, r.Path, r.RawQuery, m)
				}
			}
			if r.Method == http.MethodPatch {
				applies++
				if decoded(t, decodeSecret(t, r.Body).Data[pfetch.SecretGitToken]) != gitCredentialToken {
					t.Error("the apply's token is not the file's, trimmed")
				}
			}
		}
		if applies != 2 {
			t.Errorf("%d applies; want one per --confirm", applies)
		}
	})

	t.Run("the refusals", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			username string
			raw      string
			prepare  func(s *kubetest.Server)
			want     string
		}{
			{"the username's", gitCredentialUsername + " " + gitCredentialToken, gitCredentialToken, nil, msgGitCredentialUsername},
			{"the token's", gitCredentialUsername, gitCredentialToken + "\x01", nil, msgGitCredentialToken},
			{"another Secret's", gitCredentialUsername, gitCredentialToken, func(s *kubetest.Server) {
				secretIn(s, gitCredentialName, gitCredentialSeededUID, nil)
			}, fmt.Sprintf(msgGitCredentialSetForeign, gitCredentialNamespace, gitCredentialName)},
			{"a refused apply", gitCredentialUsername, gitCredentialToken, func(s *kubetest.Server) {
				s.FailNextApply(http.StatusUnprocessableEntity, kube.Status{})
			}, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := kubetest.New(t)
				dir, _ := writeInstance(t, s, true)
				file := tokenFile(t, tc.raw)
				// The plan is made with a valid username where the run's is
				// refused, so the refusal is the run's own.
				planUser := tc.username
				if tc.want == msgGitCredentialUsername {
					planUser = gitCredentialUsername
				}
				js, _, _ := runLine(line(dir, planUser, file, "-o", "json", "--plan"))
				if tc.prepare != nil {
					tc.prepare(s)
				}
				stdout, stderr, code := runLine(line(dir, tc.username, file, "-o", "json", "--confirm", printedDocument(t, []byte(js)).Digest))
				if code == 0 {
					t.Fatalf("%s refusal: exit 0, %s", tc.name, stdout)
				}
				for _, out := range []string{stdout, stderr} {
					for _, m := range markers {
						if strings.Contains(out, m) {
							t.Errorf("the %s refusal printed %q:\n%s", tc.name, m, out)
						}
					}
				}
				if tc.want != "" && !strings.Contains(stdout+stderr, tc.want) {
					t.Errorf("the %s refusal printed %q %q; want %q", tc.name, stdout, stderr, tc.want)
				}
			})
		}
	})
}

// ADR 0023 M2.8 (design §33, A33-31, row 112a): set writes only over a Git
// credential farcast wrote, or where there is none. After consent it reads
// the Secret's metadata as the writer, and a Secret in farcast-system that
// does not carry both labels (an operator's unlabelled registry-pull,
// farcast's label without the component's, the component's alone, or the
// component's under another manager) is
// refused, internal, before the token is read, in A33-31's words: nothing is
// applied, and the Secret is as it was. Interactively it is refused after
// the question. A Secret that carries both is written over. A name a
// renderer writes is a usage error before anything is read.
func TestGitCredentialSetRefusesAnotherSecret(t *testing.T) {
	for _, tc := range []struct {
		name    string
		secret  string
		labels  map[string]any
		refused bool
	}{
		{"an operator's Secret", "registry-pull", nil, true},
		{"farcast's label alone", "other-cred", map[string]any{gitCredentialManagedBy: "farcast"}, true},
		{"the component's label alone", "other-cred", map[string]any{gitCredentialComponent: gitCredentialLabel}, true},
		{"another manager's Git credential", "other-cred", map[string]any{gitCredentialManagedBy: "helm", gitCredentialComponent: gitCredentialLabel}, true},
		{"a Git credential farcast wrote", gitCredentialName, gitCredentialLabels(), false},
	} {
		for _, how := range []string{"--confirm", "interactive"} {
			t.Run(tc.name+", "+how, func(t *testing.T) {
				s := kubetest.New(t)
				secretIn(s, tc.secret, gitCredentialSeededUID, tc.labels)
				dir, _ := writeInstance(t, s, true)
				var tokens int
				g := gitCredentialRun{action: plan.GitCredentialSet, mode: output.ModeJSON,
					flags: []string{"--name", tc.secret, "--username", gitCredentialUsername, "--token-file", "-"},
					edit: func(c *gitCredentialCommand) {
						c.readToken = func(env *Env, path string) ([]byte, error) {
							tokens++
							return gitCredentialTokenOf(gitCredentialToken)(env, path)
						}
					}}
				var stderr string
				var err error
				if how == "interactive" {
					g.edit, g.in = interactive(g.edit), strings.NewReader("y\n")
					_, stderr, err = g.run(t, dir)
				} else {
					_, stderr, err = g.confirmed(t, dir)
				}
				path := "/api/v1/namespaces/" + gitCredentialNamespace + "/secrets/" + tc.secret
				applied := len(requestsTo(s, http.MethodPatch, path))
				if !tc.refused {
					if err != nil || applied != 1 || tokens != 1 {
						t.Fatalf("over a Git credential farcast wrote = %v, %d applies, %d token reads; want it written", err, applied, tokens)
					}
					return
				}
				want := fmt.Sprintf(msgGitCredentialSetForeign, gitCredentialNamespace, tc.secret)
				if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal {
					t.Fatalf("= %v (kind %s); want %q, internal", err, kindOf(classified(err)), want)
				}
				if applied != 0 || tokens != 0 || len(requestsTo(s, http.MethodGet, path)) != 1 {
					t.Errorf("%d applies, %d token reads, %d reads of the Secret; want its one read and nothing else", applied, tokens, len(requestsTo(s, http.MethodGet, path)))
				}
				if how == "interactive" && !strings.Contains(stderr, "[y/N]") {
					t.Errorf("refused before the question: %q", stderr)
				}
				k, _ := kube.KindOf("v1", "Secret")
				w, err := openWriter(clusterRef{Dir: dir, Meta: mustMeta(t, dir), Identity: kube.Writer})
				if err != nil {
					t.Fatal(err)
				}
				o, err := w.GetMeta(t.Context(), k, gitCredentialNamespace, tc.secret)
				if err != nil || o.Metadata.UID != gitCredentialSeededUID || isGitCredential(o) {
					t.Errorf("the Secret is now %+v (%v); want it as it was", o.Metadata, err)
				}
			})
		}
	}
	for _, name := range []string{"fatline-mtls", "web-egress"} {
		t.Run(name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, true)
			g := gitCredentialRun{action: plan.GitCredentialSet, mode: output.ModeJSON,
				flags: []string{"--name", name, "--username", gitCredentialUsername, "--token-file", "-", "--plan"}}
			_, _, err := g.run(t, dir)
			if want := fmt.Sprintf(msgGitCredentialReserved, gitCredentialNamespace, name); err == nil || err.Error() != want || exitCodeOf(err) != 2 {
				t.Errorf("--name %s = %v; want the usage error %q", name, err, want)
			}
		})
	}
}

// mustMeta is the fixture's record, loaded.
func mustMeta(t *testing.T, dir config.Dir) *config.InstanceMetadata {
	t.Helper()
	meta, err := dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

// ADR 0023 M2.8 (design §33, A33-31, row 112): rm deletes only a Git
// credential farcast wrote. A Secret that does not carry both labels with
// their values, one another manager labelled a Git credential included, is
// refused after its read, internal, in A33-31's words, with no DELETE sent,
// and stays; one that does is deleted.
func TestGitCredentialRmDeletesOnlyItsOwn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		labels  map[string]any
		deleted bool
	}{
		{"an operator's Secret", nil, false},
		{"farcast's label alone", map[string]any{gitCredentialManagedBy: "farcast"}, false},
		{"the component's label alone", map[string]any{gitCredentialComponent: gitCredentialLabel}, false},
		{"another component", map[string]any{gitCredentialManagedBy: "farcast", gitCredentialComponent: "mtls"}, false},
		{"another manager's Git credential", map[string]any{gitCredentialManagedBy: "helm", gitCredentialComponent: gitCredentialLabel}, false},
		{"a Git credential farcast wrote", gitCredentialLabels(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := kubetest.New(t)
			secretIn(s, gitCredentialName, gitCredentialSeededUID, tc.labels)
			dir, _ := writeInstance(t, s, true)
			stdout, _, err := rmRun().confirmed(t, dir)
			deletes := len(requestsTo(s, http.MethodDelete, gitCredentialPath))
			k, _ := kube.KindOf("v1", "Secret")
			w, werr := openWriter(clusterRef{Dir: dir, Meta: mustMeta(t, dir), Identity: kube.Writer})
			if werr != nil {
				t.Fatal(werr)
			}
			_, gerr := w.GetMeta(t.Context(), k, gitCredentialNamespace, gitCredentialName)
			if tc.deleted {
				var r gitCredentialResult
				if err != nil || deletes != 1 || gerr == nil || json.Unmarshal([]byte(stdout), &r) != nil || r.Note != "" || r.Action != plan.GitCredentialRm {
					t.Fatalf("rm of a Git credential farcast wrote = %v, %d deletes, the Secret's read %v, the result %q; want it deleted", err, deletes, gerr, stdout)
				}
				return
			}
			want := fmt.Sprintf(msgGitCredentialRmForeign, gitCredentialNamespace, gitCredentialName)
			if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal {
				t.Fatalf("= %v (kind %s); want %q, internal", err, kindOf(classified(err)), want)
			}
			if deletes != 0 || gerr != nil || stdout != "" {
				t.Errorf("%d deletes, the Secret's read %v, printed %q; want it kept, and nothing deleted", deletes, gerr, stdout)
			}
		})
	}
}

// ADR 0023 M2.8 (design §33, A33-31, row 113): rm's one DELETE is
// preconditioned on the uid its read found: after the Secret's GET, one
// DELETE of it, as the writer, with no query and exactly the DeleteOptions
// whose precondition is that uid.
func TestGitCredentialRmCarriesTheUidPrecondition(t *testing.T) {
	for _, how := range []string{"--confirm", "interactive"} {
		t.Run(how, func(t *testing.T) {
			s := kubetest.New(t)
			gitCredentialSeeded(s)
			dir, _ := writeInstance(t, s, true)
			g := rmRun()
			var err error
			if how == "interactive" {
				g.edit, g.in = interactive(nil), strings.NewReader("y\n")
				_, _, err = g.run(t, dir)
			} else {
				_, _, err = g.confirmed(t, dir)
			}
			if err != nil {
				t.Fatal(err)
			}
			var sent []string
			var deletes []kubetest.Request
			for _, r := range s.Requests() {
				if r.Path == "/token" {
					continue
				}
				sent = append(sent, r.Method+" "+r.Path+" as "+r.As)
				if r.Method == http.MethodDelete {
					deletes = append(deletes, r)
				}
			}
			if want := []string{"GET " + gitCredentialPath + " as writer", "DELETE " + gitCredentialPath + " as writer"}; !slices.Equal(sent, want) {
				t.Errorf("rm sent %q; want %q", sent, want)
			}
			body := `{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"` + gitCredentialSeededUID + `"}}`
			if len(deletes) != 1 || deletes[0].RawQuery != "" || string(deletes[0].Body) != body {
				t.Errorf("the delete sent %+v; want no query and %s", deletes, body)
			}
		})
	}
}

// ADR 0023 M2.8 (design §33, A33-31, row 124): a Git credential replaced
// between rm's read and its delete is not deleted. The DELETE, on the uid
// read, meets the replacement's uid and is answered 409: rm refuses with
// A33-31's words, cluster_rejected, never plan_changed, exit 1, and the
// replacement stays.
func TestGitCredentialRmSaysAReplacedSecretWasNotDeleted(t *testing.T) {
	const replacedUID = "00000000-0000-4000-8000-0000000000e2"
	for _, how := range []string{"--confirm", "interactive"} {
		t.Run(how, func(t *testing.T) {
			var s *kubetest.Server
			var replaced atomic.Bool
			s = kubetest.New(t, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
				if r.Method == http.MethodDelete && r.Path == gitCredentialPath && !replaced.Swap(true) {
					// Another writer deleted it and made another between the
					// read and the delete.
					secretIn(s, gitCredentialName, replacedUID, gitCredentialLabels())
				}
				return 0, nil, false
			}))
			gitCredentialSeeded(s)
			dir, _ := writeInstance(t, s, true)
			g := rmRun()
			var stdout string
			var err error
			if how == "interactive" {
				g.edit, g.in = interactive(nil), strings.NewReader("y\n")
				stdout, _, err = g.run(t, dir)
			} else {
				stdout, _, err = g.confirmed(t, dir)
			}
			want := fmt.Sprintf(msgGitCredentialReplaced, gitCredentialNamespace, gitCredentialName)
			if err == nil || err.Error() != want || kindOf(classified(err)) != kindClusterRejected || exitCodeOf(err) != 1 || stdout != "" {
				t.Fatalf("= %v (kind %s, exit %d), printing %q; want %q, cluster_rejected", err, kindOf(classified(err)), exitCodeOf(err), stdout, want)
			}
			k, _ := kube.KindOf("v1", "Secret")
			w, werr := openWriter(clusterRef{Dir: dir, Meta: mustMeta(t, dir), Identity: kube.Writer})
			if werr != nil {
				t.Fatal(werr)
			}
			if o, err := w.GetMeta(t.Context(), k, gitCredentialNamespace, gitCredentialName); err != nil || o.Metadata.UID != replacedUID {
				t.Errorf("the replacement is now %+v (%v); want it kept", o.Metadata, err)
			}
		})
	}
}

// ADR 0023 M2.8 (design §33, A33-31, row 118): rm of a Git credential that
// is not there succeeds, with A33-31's note: one its read finds absent,
// with no DELETE sent, and one its DELETE finds gone (404).
func TestGitCredentialRmOfAnAbsentSecretSucceeds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(s *kubetest.Server)
		deletes int
	}{
		{"its read finds none", nil, 0},
		{"its delete finds none", func(s *kubetest.Server) {
			gitCredentialSeeded(s)
			s.Fail(http.MethodDelete, gitCredentialPath, http.StatusNotFound, kube.Status{})
		}, 1},
	} {
		for mode, how := range map[output.Mode]string{output.ModeJSON: "json", output.ModeHuman: "human"} {
			t.Run(tc.name+" "+how, func(t *testing.T) {
				s := kubetest.New(t)
				if tc.prepare != nil {
					tc.prepare(s)
				}
				dir, _ := writeInstance(t, s, true)
				g := rmRun()
				g.mode = mode
				stdout, _, err := g.confirmed(t, dir)
				note := fmt.Sprintf(msgGitCredentialNotThere, gitCredentialNamespace, gitCredentialName)
				if err != nil {
					t.Fatalf("rm of an absent Git credential = %v; want success", err)
				}
				if got := len(requestsTo(s, http.MethodDelete, gitCredentialPath)); got != tc.deletes {
					t.Errorf("%d deletes; want %d", got, tc.deletes)
				}
				if mode == output.ModeHuman {
					if stdout != "✓ "+note+"\n" {
						t.Errorf("printed %q; want the note", stdout)
					}
					return
				}
				var r gitCredentialResult
				if err := json.Unmarshal([]byte(stdout), &r); err != nil || r != (gitCredentialResult{Instance: writeName, Action: plan.GitCredentialRm,
					Namespace: gitCredentialNamespace, Name: gitCredentialName, Note: note}) {
					t.Errorf("printed %s (%v); want the result with the note", stdout, err)
				}
			})
		}
	}
}

// ADR 0023 M2.8 (design §33, A33-30, row 116): the token is read only after
// consent: interactively after the question was answered yes, and under
// --confirm after the comparison, each after the Secret's read; never under
// --plan, for a question answered no, or for a --confirm whose plan changed.
// The question is A33-30's, naming the username; rm's names none.
func TestGitCredentialReadsTheTokenOnlyAfterConsent(t *testing.T) {
	type read struct {
		asked bool // the question was on stderr when the token was read
		sent  int  // how many reads of the Secret the server had seen
	}
	for _, tc := range []struct {
		name   string
		answer []string
		in     string
		reads  int
	}{
		{"--plan", []string{"--plan"}, "", 0},
		{"a question answered no", nil, "n\n", 0},
		{"a question answered yes", nil, "y\n", 1},
		{"--confirm of a plan that changed", []string{"--confirm", sampleDigest}, "", 0},
		{"--confirm", []string{"--confirm"}, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, true)
			var reads []read
			var errb *bytes.Buffer
			edit := func(c *gitCredentialCommand) {
				c.interactive = func(*Env) bool { return len(tc.answer) == 0 }
				c.readToken = func(env *Env, path string) ([]byte, error) {
					reads = append(reads, read{asked: strings.Contains(errb.String(), "[y/N]"), sent: len(requestsTo(s, http.MethodGet, gitCredentialPath))})
					return gitCredentialTokenOf(gitCredentialToken)(env, path)
				}
			}
			answer := tc.answer
			if slices.Equal(answer, []string{"--confirm"}) {
				answer = []string{"--confirm", setRun(gitCredentialToken).planned(t, dir).Digest}
			}
			cmd := withFlags(t, &gitCredentialCommand{action: plan.GitCredentialSet}, append(gitCredentialSetFlags(), answer...)...)
			edit(cmd)
			env, _, e := testEnvBoth(dir, output.ModeJSON)
			errb, env.In = e, strings.NewReader(tc.in)
			err := cmd.Run(t.Context(), env, []string{writeName})
			if len(reads) != tc.reads {
				t.Fatalf("read the token %d times (%v); want %d", len(reads), err, tc.reads)
			}
			for _, r := range reads {
				if r.sent != 1 || (len(tc.answer) == 0 && !r.asked) {
					t.Errorf("read the token with %d reads of the Secret sent, the question asked %t; want after both", r.sent, r.asked)
				}
			}
			switch tc.name {
			case "a question answered no":
				if err != nil || !strings.HasSuffix(errb.String(), "[y/N]: Aborted.\n") || len(s.Requests()) != 0 {
					t.Errorf("= %v, %q, %d requests; want it aborted, with nothing sent", err, errb, len(s.Requests()))
				}
			case "--confirm of a plan that changed":
				if kindOf(classified(err)) != kindPlanChanged || len(s.Requests()) != 0 {
					t.Errorf("= %v (kind %s), %d requests; want plan_changed, with nothing sent", err, kindOf(classified(err)), len(s.Requests()))
				}
			}
			if len(tc.answer) == 0 {
				question := `Write the Git credential farcast-system/repo-git (user GITCRED-USERNAME-MARKER) into "atlas"'s cluster? ` +
					"Every build and fetch that names it with --git-secret can read it, and so can the cloud provider, for as long as it exists. [y/N]: "
				if !strings.HasPrefix(errb.String(), question) {
					t.Errorf("asked %q; want %q", errb, question)
				}
			}
		})
	}
	t.Run("rm's question", func(t *testing.T) {
		s := kubetest.New(t)
		dir, _ := writeInstance(t, s, true)
		g := rmRun()
		g.edit, g.in = interactive(nil), strings.NewReader("n\n")
		_, stderr, err := g.run(t, dir)
		question := `Delete the Git credential farcast-system/repo-git from "atlas"'s cluster? [y/N]: Aborted.` + "\n"
		if err != nil || stderr != question || len(s.Requests()) != 0 {
			t.Errorf("= %v, %q, %d requests; want %q, with nothing sent", err, stderr, len(s.Requests()), question)
		}
	})
}

// ADR 0023 M2.8 (design §33, A33-29, A33-30, row 117): set writes the keys
// the fetch and build Jobs read. The applied document is one data: Secret of
// type Opaque, farcast-system/<name>, labelled as a Git credential farcast
// wrote, whose keys are pfetch's SecretGitUser and SecretGitToken, pbuild's
// too, and which the Jobs rendered with --git-secret <name> read; it is the
// plan's document but for its data. Its username is --username's, and its
// token --token-file's, read from a file or from stdin (-), with one
// trailing \n or \r\n trimmed and the result saying so, in JSON and as a
// human reads it. A token that is empty, longer than 4096 bytes or holds a
// control byte once trimmed, a second newline, a lone trailing \r and a tab
// included, is refused, with nothing applied, and a file longer than the
// longest token and its \r\n is refused, never cut; and so is a
// --token-file that cannot be read.
func TestGitCredentialWritesTheKeysTheJobsRead(t *testing.T) {
	if pfetch.SecretGitUser != pbuild.SecretGitUser || pfetch.SecretGitToken != pbuild.SecretGitToken {
		t.Fatalf("the fetch Job reads %s and %s, the build Job %s and %s", pfetch.SecretGitUser, pfetch.SecretGitToken, pbuild.SecretGitUser, pbuild.SecretGitToken)
	}
	for _, tc := range []struct {
		name, raw   string
		stdin       bool
		token       string
		trimmed, ok bool
	}{
		{"a file ending in a newline", "tok\n", false, "tok", true, true},
		{"a file ending in \\r\\n", "tok\r\n", false, "tok", true, true},
		{"a file with no newline", "tok", false, "tok", false, true},
		{"stdin", "tok\n", true, "tok", true, true},
		{"4096 bytes and a newline", strings.Repeat("t", 4096) + "\n", false, strings.Repeat("t", 4096), true, true},
		{"4096 bytes and \\r\\n", strings.Repeat("t", 4096) + "\r\n", false, strings.Repeat("t", 4096), true, true},
		{"two newlines", "tok\n\n", false, "", false, false},
		{"4097 bytes", strings.Repeat("t", 4097), false, "", false, false},
		// Longer than the read's bound once trimmed, so refused, never cut.
		{"4096 bytes, a newline and one byte more", strings.Repeat("t", 4096) + "\nx", false, "", false, false},
		{"4096 bytes, \\r\\n and one byte more", strings.Repeat("t", 4096) + "\r\nx", false, "", false, false},
		{"a newline alone", "\n", false, "", false, false},
		{"nothing", "", true, "", false, false},
		{"a DEL", "to\x7fk", false, "", false, false},
		{"a carriage return inside", "to\rk", false, "", false, false},
		{"a file ending in \\r", "tok\r", false, "", false, false},
		{"a tab", "to\tk", false, "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, true)
			path, in := "-", io.Reader(strings.NewReader(tc.raw))
			if !tc.stdin {
				path, in = filepath.Join(t.TempDir(), "token"), nil
				if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			g := gitCredentialRun{action: plan.GitCredentialSet, mode: output.ModeJSON, in: in,
				flags: []string{"--name", gitCredentialName, "--username", gitCredentialUsername, "--token-file", path}}
			doc := g.planned(t, dir)
			stdout, _, err := g.confirmed(t, dir)
			applies := requestsTo(s, http.MethodPatch, gitCredentialPath)
			if !tc.ok {
				if err == nil || err.Error() != msgGitCredentialToken || len(applies) != 0 {
					t.Fatalf("= %v, %d applies; want %q, with nothing applied", err, len(applies), msgGitCredentialToken)
				}
				return
			}
			if err != nil || len(applies) != 1 {
				t.Fatalf("= %v, %d applies; want the Secret applied", err, len(applies))
			}
			secret := decodeSecret(t, applies[0].Body)
			if secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Type != "Opaque" || secret.Metadata.Name != gitCredentialName ||
				secret.Metadata.Namespace != gitCredentialNamespace || secret.Metadata.Labels[gitCredentialManagedBy] != "farcast" ||
				secret.Metadata.Labels[gitCredentialComponent] != gitCredentialLabel || len(secret.Metadata.Labels) != 2 {
				t.Errorf("the applied Secret is %+v", secret)
			}
			var keys []string
			for k := range secret.Data {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			if !slices.Equal(keys, []string{pfetch.SecretGitToken, pfetch.SecretGitUser}) ||
				decoded(t, secret.Data[pfetch.SecretGitUser]) != gitCredentialUsername || decoded(t, secret.Data[pfetch.SecretGitToken]) != tc.token {
				t.Errorf("the applied Secret's keys are %q, or its values are not the username and the token trimmed", keys)
			}
			var r gitCredentialResult
			if err := json.Unmarshal([]byte(stdout), &r); err != nil || r != (gitCredentialResult{Instance: writeName, Action: plan.GitCredentialSet,
				Namespace: gitCredentialNamespace, Name: gitCredentialName, TrimmedNewline: tc.trimmed}) {
				t.Errorf("printed %s (%v); want the result, the newline trimmed %t", stdout, err, tc.trimmed)
			}
			// The plan's document, but for its data.
			writes := applyWrites(decodedBound(t, doc))
			user, token := gitCredentialPlaceholders(gitCredentialName)
			planned, err := renderGitCredential(gitCredentialName, user, token)
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(planned); len(writes) != 1 || writes[0].SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatalf("the plan's write %+v is not the placeholder rendering's", writes)
			}
			if !bytes.Equal(masked(applies[0].Body), masked(planned)) || bytes.Equal(applies[0].Body, planned) {
				t.Errorf("the applied Secret is not the planned one but for its data:\n%s\n%s", applies[0].Body, planned)
			}
			// As a human reads it: the Secret and the instance, then the
			// trimmed newline, as secret set says it.
			human := g
			human.mode = output.ModeHuman
			if tc.stdin {
				human.in = strings.NewReader(tc.raw)
			}
			hout, _, err := human.confirmed(t, dir)
			want := "✓ wrote the Git credential " + gitCredentialNamespace + "/" + gitCredentialName + " into instance " + writeName + "'s cluster\n"
			if tc.trimmed {
				want += "  A trailing newline was removed from the token.\n"
			}
			if err != nil || hout != want {
				t.Errorf("-o human printed %q (%v); want %q", hout, err, want)
			}
		})
	}
	t.Run("the Jobs read it", func(t *testing.T) {
		build, err := pbuild.Render(pbuild.Config{
			Instance: writeName, Deployment: "shop", App: "api", Builder: builderDigest,
			Repo: "https://github.com/example/shop", Ref: "0123456789abcdef0123456789abcdef01234567",
			Containerfile: "api/Containerfile", ContextSubPath: "api", Destination: "registry.example/app/shop/api:0123456",
			GitSecret: gitCredentialName, EgressHosts: []string{"github.com", "registry.example"},
		})
		if err != nil {
			t.Fatal(err)
		}
		fetch, err := pfetch.Render(pfetch.Config{Instance: writeName, Fetcher: fetcherDigest, Repo: "https://github.com/example/shop",
			Ref: "main", GitSecret: gitCredentialName, EgressHosts: []string{"github.com"}})
		if err != nil {
			t.Fatal(err)
		}
		for name, stream := range map[string][]byte{"build": build, "fetch": fetch} {
			for _, key := range []string{pfetch.SecretGitUser, pfetch.SecretGitToken} {
				if !bytes.Contains(stream, []byte("name: "+gitCredentialName+"\n                  key: "+key+"\n")) {
					t.Errorf("the %s Job does not read the key %s of %s", name, key, gitCredentialName)
				}
			}
			docs, err := kube.SplitStream(stream)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(docs, func(d kube.Document) bool { return d.Kind.Kind == "Job" && d.Namespace == gitCredentialNamespace }) {
				t.Errorf("the %s Job does not run in %s, where the credential is", name, gitCredentialNamespace)
			}
		}
	})
	t.Run("a --token-file that cannot be read", func(t *testing.T) {
		s := kubetest.New(t)
		dir, _ := writeInstance(t, s, true)
		g := gitCredentialRun{action: plan.GitCredentialSet, mode: output.ModeJSON,
			flags: []string{"--name", gitCredentialName, "--username", gitCredentialUsername, "--token-file", filepath.Join(t.TempDir(), "absent")}}
		_, _, err := g.confirmed(t, dir)
		if err == nil || !strings.HasPrefix(err.Error(), "read the token from --token-file: ") || !strings.HasSuffix(err.Error(), "; nothing was written") ||
			len(requestsTo(s, http.MethodPatch, gitCredentialPath)) != 0 {
			t.Errorf("= %v; want the read refused, with nothing applied", err)
		}
	})
}

// ADR 0023 M2.8 (design §33, A33-30): a token holds no control byte. Each
// byte below 0x20 and 0x7f, inside a token, is refused, and a token of every
// other byte, 0x20 to 0xff, is taken as it is.
func TestGitCredentialRefusesEveryControlByte(t *testing.T) {
	for b := 0; b <= 0x7f; b++ {
		if b >= 0x20 && b < 0x7f {
			continue
		}
		if token, _, ok := gitToken([]byte{'t', 'o', byte(b), 'k'}); ok {
			t.Errorf("a token holding the byte %#02x is taken, as %q", b, token)
		}
	}
	var every []byte
	for b := 0x20; b <= 0xff; b++ {
		if b != 0x7f {
			every = append(every, byte(b))
		}
	}
	if token, trimmed, ok := gitToken(every); !ok || trimmed || !bytes.Equal(token, every) {
		t.Errorf("a token of every byte but the control bytes = %q, trimmed %t, taken %t; want it taken as it is", token, trimmed, ok)
	}
}

// ADR 0023 M2.8 (design §33, A33-30): a username of 1 to 256 printable bytes
// with no whitespace is taken, at both ends of each bound: 256 bytes, and
// '!' and '~', the lowest and the highest byte it may hold. Each is planned,
// and its --confirm applies a Secret holding that username.
func TestGitCredentialTakesEveryUsernameItsShapeAllows(t *testing.T) {
	for _, username := range []string{strings.Repeat("u", 256), "x!~y", "!", "~"} {
		t.Run(fmt.Sprintf("%d bytes from %q", len(username), username[:1]), func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, true)
			g := setRun(gitCredentialToken)
			g.flags = []string{"--name", gitCredentialName, "--username", username, "--token-file", "-"}
			_, stderr, err := g.confirmed(t, dir)
			applies := requestsTo(s, http.MethodPatch, gitCredentialPath)
			if err != nil || len(applies) != 1 {
				t.Fatalf("= %v, %d applies; want it applied\n%s", err, len(applies), stderr)
			}
			if got := decoded(t, decodeSecret(t, applies[0].Body).Data[pfetch.SecretGitUser]); got != username {
				t.Errorf("the applied username is %q; want %q", got, username)
			}
		})
	}
}

// endlessToken is a stdin that never ends, as /dev/zero or `yes |` would be:
// every read fills its buffer with 't'. It ends after limit bytes all the
// same, so a read that does not stop at its bound fails a test rather than
// hanging it. read counts the bytes it gave.
type endlessToken struct {
	limit int
	read  int
}

func (e *endlessToken) Read(p []byte) (int, error) {
	if e.read >= e.limit {
		return 0, io.EOF
	}
	n := min(len(p), e.limit-e.read)
	for i := range n {
		p[i] = 't'
	}
	e.read += n
	return n, nil
}

// ADR 0023 M2.8 (design §33, A33-30): the token's read is bounded. A
// --token-file - whose stdin never ends is read for exactly 4096 + 2 + 1
// bytes, the design's bound, one more than the longest token and its \r\n,
// then refused with A33-30's text, with nothing applied. The bound is the
// design's number, not maxGitTokenRead, so a constant raised past it is
// seen: no accept or refuse decision would show it.
func TestGitCredentialReadsATokenOnlyToItsBound(t *testing.T) {
	s := kubetest.New(t)
	dir, _ := writeInstance(t, s, true)
	stdin := &endlessToken{limit: 1 << 20}
	g := gitCredentialRun{action: plan.GitCredentialSet, flags: gitCredentialSetFlags(), mode: output.ModeJSON, in: stdin}
	_, _, err := g.confirmed(t, dir)
	if err == nil || err.Error() != msgGitCredentialToken || len(requestsTo(s, http.MethodPatch, gitCredentialPath)) != 0 {
		t.Errorf("= %v; want %q, with nothing applied", err, msgGitCredentialToken)
	}
	const bound = 4096 + 2 + 1
	if stdin.read != bound {
		t.Errorf("read %d bytes of a stdin that never ends; want exactly %d, the design's bound", stdin.read, bound)
	}
}

// ADR 0023 M2.8 (design §33, A33-30 step 12; review S-S5-3): a token read
// that does not end, such as a --token-file that is a FIFO no writer opens,
// does not keep set waiting once its context is done, as an interrupt makes
// it: set returns the context's error, as the token's read, and applies
// nothing.
func TestGitCredentialStopsWaitingForTheTokenWhenCancelled(t *testing.T) {
	s := kubetest.New(t)
	dir, _ := writeInstance(t, s, true)
	digest := setRun(gitCredentialToken).planned(t, dir).Digest
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	defer free()
	cmd := withFlags(t, &gitCredentialCommand{action: plan.GitCredentialSet}, append(gitCredentialSetFlags(), "--confirm", digest)...)
	cmd.readToken = func(*Env, string) ([]byte, error) {
		close(entered)
		<-release
		return []byte(gitCredentialToken), nil
	}
	env, _, _ := testEnvBoth(dir, output.ModeJSON)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.Run(ctx, env, []string{writeName}) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("set returned %v before reading the token", err)
	case <-time.After(10 * time.Second):
		t.Fatal("set did not read the token")
	}
	cancel()
	var err error
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		free()
		t.Fatalf("set still waited for the token 5 s after its context was cancelled, and returned %v once it was read", <-done)
	}
	if !errors.Is(err, context.Canceled) || !strings.HasPrefix(err.Error(), "read the token from --token-file: ") ||
		!strings.HasSuffix(err.Error(), "; nothing was written") {
		t.Errorf("= %v; want the token's read, cancelled", err)
	}
	if got := len(requestsTo(s, http.MethodPatch, gitCredentialPath)); got != 0 {
		t.Errorf("%d applies; want none", got)
	}
}

// ADR 0023 M2.8 (design §33, A33-33): what set's Usage says: a Kubernetes
// Secret, not DataSphere, which the cloud provider can read for as long as
// it exists; a repository-scoped, read-only token; never taken from argv;
// a plan names the Secret by namespace and name only; and the window
// between the read and the apply. The group's Usage says the first four.
func TestGitCredentialUsageSaysWhatItIs(t *testing.T) {
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	set := flat((&gitCredentialCommand{action: plan.GitCredentialSet}).Usage())
	group := flat(newGitCredentialCommand().Usage())
	for _, tc := range []struct {
		point string
		text  string
		group bool
	}{
		{"a Kubernetes Secret, not DataSphere", "It is a Kubernetes Secret, not DataSphere storage ('farcast secret')", true},
		{"read by the cloud provider", "the cloud provider can read it for as long as it exists", true},
		{"a repository-scoped, read-only token", "a token scoped to the one repository, read-only", true},
		{"never argv", "The token is never taken from argv", true},
		{"the plan names the Secret only", "A plan names the Secret by its namespace and name only", true},
		{"the read-to-apply window", "The read and the apply are two calls: a Secret another writer puts there between them is written over.", false},
	} {
		if !strings.Contains(set, tc.text) {
			t.Errorf("set's Usage does not say %s (%q):\n%s", tc.point, tc.text, set)
		}
		if tc.group && !strings.Contains(group, tc.text) {
			t.Errorf("the group's Usage does not say %s (%q):\n%s", tc.point, tc.text, group)
		}
	}
}

// ADR 0023 M2.8 (design §33, A33-29): the Git credential's document reads as
// strings wherever YAML could read another type. A name DNS-1123 allows that
// YAML reads as a boolean, a number or null, and a token whose base64 is all
// digits, render to a document the apply's checks accept, whose name is the
// name and whose data values are strings that decode to the username and
// the token.
func TestGitCredentialRendersEveryValueAsAString(t *testing.T) {
	digits, err := base64.StdEncoding.DecodeString("1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := gitToken(digits); !ok {
		t.Fatalf("guard: the token whose base64 is 1234 is refused")
	}
	for _, name := range []string{"true", "false", "yes", "no", "on", "off", "null", "123", "1e5", "0x1f", "1.5", "007"} {
		t.Run(name, func(t *testing.T) {
			b, err := renderGitCredential(name, []byte("u"), digits)
			if err != nil {
				t.Fatal(err)
			}
			docs, err := kube.SplitStream(b)
			if err != nil || len(docs) != 1 || docs[0].Name != name || docs[0].Namespace != gitCredentialNamespace {
				t.Fatalf("SplitStream = %d documents, %v; want the Secret %s", len(docs), err, name)
			}
			var doc struct {
				Data map[string]any `yaml:"data"`
			}
			if err := yaml.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			token, ok := doc.Data[pfetch.SecretGitToken].(string)
			if user, uok := doc.Data[pfetch.SecretGitUser].(string); !ok || !uok || decoded(t, user) != "u" || decoded(t, token) != string(digits) {
				t.Errorf("the data values are %T and %T, or do not decode to the username and the token", doc.Data[pfetch.SecretGitUser], doc.Data[pfetch.SecretGitToken])
			}
		})
	}
}

// ADR 0023 M2.8 (design §33, A33-29 to A33-31): git-credential's texts are
// the design's, word for word, and carry no value but the ones A33-30
// allows: each, filled in for the fixture, is the text the design pins. The
// CLI README quotes the token's refusals word for word.
func TestGitCredentialSaysWhatTheDesignPins(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{fmt.Sprintf(msgGitCredentialYes, "set", "set", "atlas"), "git-credential set cannot be run with --yes: it writes a credential every build and fetch can read; " +
			"confirm it in a terminal, or review 'farcast git-credential set atlas --plan' and pass --confirm <digest>"},
		{msgGitCredentialTerminal, "git-credential needs a terminal to confirm, or --plan and then --confirm <digest>"},
		{msgGitCredentialStdinTerminal, "--token-file - reads the token from stdin, which is a terminal here; give a file, or pipe the token: " +
			"--plan first, then --confirm <digest> with the token on stdin"},
		// Step 5's second refusal, from M2.8b's review (S-S5-1, C-S5-3), for
		// the design's amendment of A33-30.
		{msgGitCredentialTokenDevice, "--token-file names a device, such as a terminal, which would show the token as it is typed; give a file, " +
			"or pipe the token: --plan first, then --confirm <digest> with the token on stdin"},
		{fmt.Sprintf(msgGitCredentialName, "Repo"), `--name "Repo" is not a Secret name (a DNS-1123 subdomain: lowercase letters, digits, '-' and '.', at most 253 characters)`},
		{fmt.Sprintf(msgGitCredentialReserved, "farcast-system", "fatline-mtls"), "farcast-system/fatline-mtls is a Secret FarCast renders, not a Git credential; choose another --name"},
		{msgGitCredentialUsername, "--username must be 1 to 256 printable bytes with no whitespace; nothing was read or written"},
		{msgGitCredentialToken, "the token read from --token-file is empty, longer than 4096 bytes, or holds a control byte; nothing was written"},
		{fmt.Sprintf(msgGitCredentialSetPrompt, "farcast-system", "repo-git", "x-access-token", "atlas"), `Write the Git credential farcast-system/repo-git (user x-access-token) into "atlas"'s cluster? ` +
			"Every build and fetch that names it with --git-secret can read it, and so can the cloud provider, for as long as it exists."},
		{fmt.Sprintf(msgGitCredentialRmPrompt, "farcast-system", "repo-git", "atlas"), `Delete the Git credential farcast-system/repo-git from "atlas"'s cluster?`},
		{fmt.Sprintf(msgGitCredentialNotThere, "farcast-system", "repo-git"), "farcast-system/repo-git was not there"},
		{fmt.Sprintf(msgGitCredentialReplaced, "farcast-system", "repo-git"), "farcast-system/repo-git was replaced between its read and its delete; nothing was deleted; run it again"},
		{fmt.Sprintf(msgGitCredentialSetForeign, "farcast-system", "repo-git"), "farcast-system/repo-git exists and is not a Git credential farcast wrote; nothing was written; " +
			"choose another --name, or delete it from Cloud Shell"},
		{fmt.Sprintf(msgGitCredentialRmForeign, "farcast-system", "repo-git"), "farcast-system/repo-git is not a Git credential farcast wrote; nothing was deleted; " +
			"choose another --name, or delete it from Cloud Shell"},
	} {
		if tc.got != tc.want {
			t.Errorf("the text is\n  %q\nwant\n  %q", tc.got, tc.want)
		}
	}
	user, token := gitCredentialPlaceholders("repo-git")
	if string(user) != "farcast-placeholder:git_username:farcast-system/repo-git" || string(token) != "farcast-placeholder:git_token:farcast-system/repo-git" {
		t.Errorf("the placeholders are %q and %q", user, token)
	}

	// The README, this module's specification, quotes the token's refusals
	// as they are: step 5's two, the token's own, and the read's when it
	// opens a device (review FC-CF-3).
	t.Run("the README quotes the token's refusals", func(t *testing.T) {
		raw, err := os.ReadFile("../../README.md")
		if err != nil {
			t.Fatal(err)
		}
		readme := strings.Join(strings.Fields(string(raw)), " ")
		env, _, _ := testEnvBoth(config.Dir(t.TempDir()), output.ModeJSON)
		_, opened := readGitToken(env, os.DevNull)
		if opened == nil {
			t.Fatalf("readGitToken(%s) refused nothing", os.DevNull)
		}
		atOpen := "read the token from --token-file: " + strings.Replace(opened.Error(), os.DevNull, "<path>", 1) + "; nothing was written"
		for _, text := range []string{msgGitCredentialStdinTerminal, msgGitCredentialTokenDevice, msgGitCredentialToken, atOpen} {
			if !strings.Contains(readme, "`"+text+"`") {
				t.Errorf("farsight/cli/README.md does not quote %q", text)
			}
		}
	})
}
