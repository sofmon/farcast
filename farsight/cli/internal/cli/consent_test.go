package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/planck"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
)

// sampleDigest is a well-formed plan digest.
const sampleDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// consentFlagSet is a command's flag set as kernel meter and kernel confirm
// register it: --yes and -y through the deployer, then --plan and --confirm
// through the deployer's consent.
func consentFlagSet(d *fatlineDeployer) *flag.FlagSet {
	fs := flag.NewFlagSet("consent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	d.setYesFlag(fs, "yes")
	d.consent.register(fs)
	return fs
}

// TestConsentAnswersAreExclusive: --plan, --confirm and --yes (or -y) are
// three answers, and two or three of them together are design §9.2's usage
// error. The count is of parsed values: --yes -y is one answer, and
// --yes=false --plan is a plan. (ADR 0023 M2.6a: rows here parse the
// flags; the commands that have plans add rows through the router.)
func TestConsentAnswersAreExclusive(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		mode   consentMode
		digest string
		err    string
	}{
		{nil, consentNone, "", ""},
		{[]string{"--plan"}, consentPlan, "", ""},
		{[]string{"-plan"}, consentPlan, "", ""},
		{[]string{"--confirm", sampleDigest}, consentConfirm, sampleDigest, ""},
		{[]string{"--confirm=" + sampleDigest}, consentConfirm, sampleDigest, ""},
		{[]string{"--yes"}, consentNone, "", ""},
		{[]string{"-y"}, consentNone, "", ""},
		{[]string{"--yes", "-y"}, consentNone, "", ""},
		{[]string{"--yes=false", "--plan"}, consentPlan, "", ""},
		{[]string{"-y=false", "--confirm", sampleDigest}, consentConfirm, sampleDigest, ""},
		{[]string{"--plan=false", "--confirm", sampleDigest}, consentConfirm, sampleDigest, ""},
		{[]string{"--plan=false", "--yes"}, consentNone, "", ""},

		{[]string{"--plan", "--yes"}, 0, "", msgConsentExclusive},
		{[]string{"--plan", "-y"}, 0, "", msgConsentExclusive},
		{[]string{"--plan", "--confirm", sampleDigest}, 0, "", msgConsentExclusive},
		{[]string{"--confirm", sampleDigest, "--yes"}, 0, "", msgConsentExclusive},
		{[]string{"--confirm", sampleDigest, "-y"}, 0, "", msgConsentExclusive},
		{[]string{"--plan", "--confirm", sampleDigest, "--yes"}, 0, "", msgConsentExclusive},
		{[]string{"-y", "--confirm=" + sampleDigest, "-plan"}, 0, "", msgConsentExclusive},
		{[]string{"--plan=true", "--yes=true"}, 0, "", msgConsentExclusive},
	} {
		var d fatlineDeployer
		fs := consentFlagSet(&d)
		if err := fs.Parse(tc.args); err != nil {
			t.Fatalf("%q: %v", tc.args, err)
		}
		mode, digest, err := d.consent.mode(d.assumeYes)
		if tc.err != "" {
			if err == nil || err.Error() != tc.err || exitCodeOf(err) != 2 {
				t.Errorf("%q: mode = %v, %v (exit %d), want the usage error %q", tc.args, mode, err, exitCodeOf(err), tc.err)
			}
			continue
		}
		if err != nil || mode != tc.mode || digest != tc.digest {
			t.Errorf("%q: mode = %v, %q, %v, want %v, %q", tc.args, mode, digest, err, tc.mode, tc.digest)
		}
	}

	t.Run("the commands", consentAnswersOnTheCommands)
}

// TestConfirmRefusesAMalformedDigest: --confirm takes a digest exactly as a
// plan prints it, and refuses anything else with design §9.2's text, not the
// flag package's. An empty --confirm is given, not absent; the answers are
// counted before the digest is read, so an empty --confirm beside --yes is
// two answers. (ADR 0023 M2.6a: rows here parse the flags; the commands
// that have plans add rows that read nothing.)
func TestConfirmRefusesAMalformedDigest(t *testing.T) {
	hex := strings.TrimPrefix(sampleDigest, "sha256:")
	for _, tc := range []struct {
		args []string
		err  string
	}{
		{[]string{"--confirm="}, msgConsentMalformed},
		{[]string{"--confirm", ""}, msgConsentMalformed},
		{[]string{"--confirm", "sha256:" + strings.ToUpper(hex)}, msgConsentMalformed},
		{[]string{"--confirm", "sha256:" + hex[:63]}, msgConsentMalformed},
		{[]string{"--confirm", sampleDigest + "0"}, msgConsentMalformed},
		{[]string{"--confirm", "SHA256:" + hex}, msgConsentMalformed},
		{[]string{"--confirm", hex}, msgConsentMalformed},
		{[]string{"--confirm", " " + sampleDigest}, msgConsentMalformed},
		{[]string{"--confirm", "", "--yes"}, msgConsentExclusive},
		{[]string{"--confirm=", "--plan"}, msgConsentExclusive},
	} {
		var d fatlineDeployer
		fs := consentFlagSet(&d)
		if err := fs.Parse(tc.args); err != nil {
			t.Fatalf("%q: the flag package refused it: %v", tc.args, err)
		}
		mode, digest, err := d.consent.mode(d.assumeYes)
		if err == nil || err.Error() != tc.err || exitCodeOf(err) != 2 {
			t.Errorf("%q: mode = %v, %q, %v (exit %d), want the usage error %q", tc.args, mode, digest, err, exitCodeOf(err), tc.err)
		}
	}

	// A --confirm with no value at all is the flag package's own usage error.
	var d fatlineDeployer
	if err := consentFlagSet(&d).Parse([]string{"--confirm"}); err == nil || !strings.Contains(err.Error(), "flag needs an argument") {
		t.Errorf("a bare --confirm parsed: %v", err)
	}

	t.Run("the commands", malformedDigestOnTheCommands)
}

// TestConsentFlagsRegisterStartsWithNoAnswer: registering the flags again,
// as each parse of a command line does, starts from no answer, as BoolVar
// does for --plan: a --confirm parsed before is not still given.
func TestConsentFlagsRegisterStartsWithNoAnswer(t *testing.T) {
	var d fatlineDeployer
	if err := consentFlagSet(&d).Parse([]string{"--confirm", sampleDigest}); err != nil {
		t.Fatal(err)
	}
	if err := consentFlagSet(&d).Parse([]string{"--plan"}); err != nil {
		t.Fatal(err)
	}
	if mode, _, err := d.consent.mode(d.assumeYes); err != nil || mode != consentPlan {
		t.Errorf("after a new parse of --plan alone, mode = %v, %v; want a plan", mode, err)
	}
}

// seenValue wraps a flag's value to record what it was last set to: a
// flag.Func value prints nothing of its own.
type seenValue struct {
	flag.Value
	set  bool
	last string
}

func (v *seenValue) Set(s string) error {
	v.set, v.last = true, s
	return v.Value.Set(s)
}

func (v *seenValue) IsBoolFlag() bool { return isBoolFlag(&flag.Flag{Value: v.Value}) }

// routedLine is a command line as the router parses it.
type routedLine struct {
	opts    globalOpts
	name    string
	args    []string
	flags   *flag.FlagSet
	confirm *seenValue
}

// routeLine parses argv exactly as run does, through the default registry,
// for a command that has a plan: every command a confirm line can name
// registers --plan and --confirm (ADR 0023 M2.6), and one that does not is
// refused.
func routeLine(argv []string) (routedLine, error) {
	var r routedLine
	gfs := flag.NewFlagSet("farcast", flag.ContinueOnError)
	gfs.SetOutput(io.Discard)
	r.opts.registerRoot(gfs)
	if err := gfs.Parse(argv); err != nil {
		return r, err
	}
	rest := gfs.Args()
	if len(rest) == 0 {
		return r, errors.New("no command")
	}
	r.name = rest[0]
	cmd, ok := defaultRegistry().Lookup(r.name)
	if !ok {
		return r, errors.New("unknown command " + r.name)
	}
	r.flags = flag.NewFlagSet(r.name, flag.ContinueOnError)
	r.flags.SetOutput(io.Discard)
	r.opts.registerCommon(r.flags)
	cmd.SetFlags(r.flags)
	if g, ok := cmd.(subFlagged); ok {
		g.SetSubFlags(r.flags, rest[1:])
	}
	f := r.flags.Lookup("confirm")
	if f == nil || r.flags.Lookup("plan") == nil {
		return r, errors.New(r.name + " registers no --plan and --confirm")
	}
	r.confirm = &seenValue{Value: f.Value}
	f.Value = r.confirm
	args, err := parseInterspersed(r.flags, rest[1:])
	r.args = args
	return r, err
}

// shellWords splits line as a POSIX shell would, and fails the test on any
// character the shell would read as more than itself outside quotes.
func shellWords(t *testing.T, line string) []string {
	t.Helper()
	var words []string
	var cur strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case quoted:
			if ch == '\'' {
				quoted = false
				continue
			}
			cur.WriteByte(ch)
		case ch == '\'':
			quoted, inWord = true, true
		case ch == '\\':
			if i+1 == len(line) {
				t.Fatalf("a trailing backslash in %q", line)
			}
			i++
			cur.WriteByte(line[i])
			inWord = true
		case ch == ' ':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case strings.IndexByte("$`\"*?[]~#;&|<>(){}!\t\n", ch) >= 0:
			t.Fatalf("%q holds %q unquoted, which a shell reads as more than itself", line, ch)
		case ch == '=' && !inWord:
			// zsh, macOS's default shell, reads an unquoted word that begins
			// with = as the path of the command it names (EQUALS, on by
			// default).
			t.Fatalf("%q begins a word with = unquoted, which zsh reads as a command's path", line)
		default:
			cur.WriteByte(ch)
			inWord = true
		}
	}
	if quoted {
		t.Fatalf("an unterminated quote in %q", line)
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// TestTheConfirmLineRunsTheSameCommand: the line a plan ends with, split as
// a shell splits it and parsed as the router parses it, is the same command
// with the same operands and flags, --plan unset and --confirm the plan's
// digest; and with no printable command line it is the fallback, which
// names no argument. (ADR 0023 M2.6a: rows here parse the line; the
// commands that have plans add rows that run it through run().)
func TestTheConfirmLineRunsTheSameCommand(t *testing.T) {
	const other = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	fallback := "To do exactly this: run the same command with --confirm " + sampleDigest
	for _, tc := range []struct {
		name string
		argv []string
		want []string // the words after "farcast"; nil for the fallback
	}{
		{"--plan", []string{"kernel", "meter", "atlas", "extra", "--plan"}, []string{"kernel", "meter", "atlas", "extra"}},
		{"-plan", []string{"kernel", "meter", "atlas", "-plan", "extra"}, []string{"kernel", "meter", "atlas", "extra"}},
		{"--plan=true", []string{"kernel", "meter", "atlas", "extra", "--plan=true"}, []string{"kernel", "meter", "atlas", "extra"}},
		{"-plan=1", []string{"kernel", "meter", "-plan=1", "atlas", "extra"}, []string{"kernel", "meter", "atlas", "extra"}},
		{"--plan=false then --plan", []string{"kernel", "meter", "atlas", "--plan=false", "extra", "--plan"}, []string{"kernel", "meter", "atlas", "extra"}},
		{"a bool flag beside it", []string{"kernel", "meter", "--plan", "atlas", "--remove", "extra"}, []string{"kernel", "meter", "atlas", "--remove", "extra"}},
		{"--yes=false kept", []string{"kernel", "meter", "atlas", "extra", "--yes=false", "--plan"}, []string{"kernel", "meter", "atlas", "extra", "--yes=false"}},
		{"--source --plan", []string{"connect", "atlas", "--source", "--plan", "--plan"}, []string{"connect", "atlas", "--source", "--plan"}},
		{"--source --confirm", []string{"connect", "atlas", "--source", "--confirm", "--plan"}, []string{"connect", "atlas", "--source", "--confirm"}},
		{"-- --plan", []string{"kernel", "meter", "atlas", "--plan", "--", "--plan"}, []string{"kernel", "meter", "atlas", "--", "--plan"}},
		{"-- then flags again", []string{"kernel", "meter", "atlas", "--", "-x", "--plan", "--remove"}, []string{"kernel", "meter", "atlas", "--", "-x", "--remove"}},
		{"a trailing --", []string{"kernel", "meter", "atlas", "extra", "--plan", "--"}, []string{"kernel", "meter", "atlas", "extra"}},
		{"global --config before the command", []string{"--config", "/tmp/farcast config", "kernel", "confirm", "atlas", "--amount", "1.5", "--plan"},
			[]string{"--config", "/tmp/farcast config", "kernel", "confirm", "atlas", "--amount", "1.5"}},
		{"a --config beginning with =", []string{"--config", "=cfg", "kernel", "meter", "atlas", "extra", "--plan"},
			[]string{"--config", "=cfg", "kernel", "meter", "atlas", "extra"}},
		{"global flags on both sides", []string{"-o", "json", "--config=/tmp/x", "kernel", "confirm", "atlas", "--plan", "-o", "human", "--from=2026-11-01"},
			[]string{"-o", "json", "--config=/tmp/x", "kernel", "confirm", "atlas", "-o", "human", "--from=2026-11-01"}},
		{"a path with a space and a quote", []string{"connect", "atlas", "--source", "/tmp/my dir/it's", "--plan"},
			[]string{"connect", "atlas", "--source", "/tmp/my dir/it's"}},
		{"run --confirm <F>", []string{"run", "atlas", "github.com/example/my-platform", "--fetcher-image", fetcherDigest, "--confirm", other},
			[]string{"run", "atlas", "github.com/example/my-platform", "--fetcher-image", fetcherDigest}},
		{"run --confirm=<F>", []string{"run", "--confirm=" + other, "atlas", "github.com/example/my-platform"},
			[]string{"run", "atlas", "github.com/example/my-platform"}},
		{"reader grant", []string{"reader", "grant", "atlas", "--plan"}, []string{"reader", "grant", "atlas"}},
		{"an unprintable token", []string{"connect", "atlas", "--source", "/tmp/a\x1b[2Kb", "--plan"}, nil},
		{"a bidi override", []string{"connect", "atlas", "--source", "/tmp/a\u202eb", "--plan"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig, err := routeLine(tc.argv)
			if err != nil {
				t.Fatalf("the router refuses %q: %v", tc.argv, err)
			}
			if orig.flags.Lookup("plan").Value.String() != "true" && !orig.confirm.set {
				t.Fatalf("%q is neither a plan nor a confirm", tc.argv)
			}
			line := confirmLine(&Env{Argv: tc.argv, Flags: orig.flags}, sampleDigest)
			if tc.want == nil {
				if line != fallback {
					t.Fatalf("line = %q, want the fallback %q", line, fallback)
				}
				return
			}
			const prefix = "To do exactly this: farcast "
			if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, " --confirm "+sampleDigest) {
				t.Fatalf("line = %q", line)
			}
			words := shellWords(t, strings.TrimPrefix(line, prefix))
			if got := words[:len(words)-2]; !slices.Equal(got, tc.want) {
				t.Errorf("the line's words are %q, want %q", got, tc.want)
			}

			again, err := routeLine(words)
			if err != nil {
				t.Fatalf("the router refuses the confirm line %q: %v", line, err)
			}
			if again.name != orig.name || !slices.Equal(again.args, orig.args) || again.opts != orig.opts {
				t.Errorf("the confirm line runs %s %q %+v, the plan was %s %q %+v",
					again.name, again.args, again.opts, orig.name, orig.args, orig.opts)
			}
			if !again.confirm.set || again.confirm.last != sampleDigest {
				t.Errorf("the confirm line confirms %q (set %t), want %s", again.confirm.last, again.confirm.set, sampleDigest)
			}
			if v := again.flags.Lookup("plan").Value.String(); v != "false" {
				t.Errorf("the confirm line sets --plan to %s", v)
			}
			orig.flags.VisitAll(func(f *flag.Flag) {
				if f.Name == "plan" || f.Name == "confirm" {
					return
				}
				if got := again.flags.Lookup(f.Name).Value.String(); got != f.Value.String() {
					t.Errorf("--%s: the confirm line sets %q, the plan had %q", f.Name, got, f.Value.String())
				}
			})
		})
	}

	// A command called directly, with no command line, gets the fallback.
	if got := confirmLine(&Env{}, sampleDigest); got != fallback {
		t.Errorf("with no command line, the line = %q, want %q", got, fallback)
	}

	t.Run("through run()", confirmLineOnTheCommands)
}

// TestShellWordIsReadAsItself: bare when every byte is one a shell reads as
// itself and the first is not =, which zsh reads as a command's path;
// single-quoted otherwise, with a single quote closed, escaped and reopened.
func TestShellWordIsReadAsItself(t *testing.T) {
	for in, want := range map[string]string{
		"atlas":             "atlas",
		"--from=2026-11-01": "--from=2026-11-01",
		"europe-west4-docker.pkg.dev/p/r@sha256:ab": "europe-west4-docker.pkg.dev/p/r@sha256:ab",
		"a,b:c+d%e_f": "a,b:c+d%e_f",
		"":            "''",
		"a b":         "'a b'",
		"it's":        `'it'\''s'`,
		"$HOME":       "'$HOME'",
		"~/x":         "'~/x'",
		"a*b":         "'a*b'",
		"#x":          "'#x'",
		`"q"`:         `'"q"'`,
		"a;b|c&d":     "'a;b|c&d'",
		"résumé":      "'résumé'",
		"=ls":         "'=ls'",
		"=":           "'='",
		"a=ls":        "a=ls",
	} {
		got := shellWord(in)
		if got != want {
			t.Errorf("shellWord(%q) = %s, want %s", in, got, want)
			continue
		}
		if words := shellWords(t, got); len(words) != 1 || words[0] != in {
			t.Errorf("a shell reads shellWord(%q) = %s as %q", in, got, words)
		}
	}
}

// TestNewBoundBindsTheRecordAndThisFarCast: a plan binds the protocol, this
// farcast's stamp, the command and instance, and the target as the record
// names it, with the uid the plan read.
func TestNewBoundBindsTheRecordAndThisFarCast(t *testing.T) {
	if got, want := planStamp(), plan.Stamp(currentStamp()); got != want {
		t.Errorf("planStamp() = %+v, want this farcast's %+v", got, want)
	}
	saved := planStamp
	t.Cleanup(func() { planStamp = saved })
	planStamp = func() plan.Stamp { return plan.Stamp{Version: "v-test", Commit: "c-test"} }

	created := time.Date(2026, 3, 4, 5, 6, 7, 890, time.FixedZone("x", 3600))
	meta := &config.InstanceMetadata{
		Name: "atlas", Provider: "gke", Project: "proj-atlas", Region: "europe-west4",
		Cluster: "farcast-atlas", Endpoint: "gke-1a2b3c.europe-west4.gke.goog", CreatedAt: created,
	}
	got := newBound("kernel confirm", meta, "reader", "u-1")
	want := plan.Bound{
		Protocol: plan.Protocol, FarCast: plan.Stamp{Version: "v-test", Commit: "c-test"},
		Command: "kernel confirm", Instance: "atlas",
		Target: plan.Target{
			Provider: "gke", Project: "proj-atlas", Region: "europe-west4", Cluster: "farcast-atlas",
			Endpoint: "gke-1a2b3c.europe-west4.gke.goog", CreatedAt: "2026-03-04T04:06:07Z", SystemNamespaceUID: "u-1",
		},
		ClusterIdentity: "reader",
	}
	if g, w := mustCanonical(t, got), mustCanonical(t, want); g != w {
		t.Errorf("newBound = %s\nwant %s", g, w)
	}
}

// mustCanonical is b's canonical encoding.
func mustCanonical(t *testing.T, b plan.Bound) string {
	t.Helper()
	c, err := plan.Canonical(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(c)
}

// TestNoticesPrintOnceInTheCommandsWords: outside --plan, a plan's notices
// print on stderr, each once, as written, in the plan's order, and nothing
// else of the plan does (A23-26).
func TestNoticesPrintOnceInTheCommandsWords(t *testing.T) {
	b := plan.Bound{Facts: []plan.Fact{
		plan.NoticeFact{Type: plan.TypeNotice, Text: "Already metering extra."},
		plan.MeterFact{Type: plan.TypeMeter, Add: []string{"extra"}},
		&plan.NoticeFact{Type: plan.TypeNotice, Text: "Warning: one\nand two"},
		plan.NoticeFact{Type: plan.TypeNotice, Text: "Rotation <is> & stays"},
	}}
	var w bytes.Buffer
	printNotices(&w, b)
	if want := "Already metering extra.\nWarning: one\nand two\nRotation <is> & stays\n"; w.String() != want {
		t.Errorf("printed %q, want %q", w.String(), want)
	}
}

// wiredCommands is every writeCommands row, each of which registers --plan
// and --confirm: ADR 0023 M2.6 wired all eleven (M2.6a kernel meter, kernel
// confirm and reader grant, M2.6b connect, redeploy and build, M2.6c kernel
// deploy, storage deploy, storage key pin and storage key rotate, M2.6d run),
// and M2.8's git-credential set and rm are the twelfth and thirteenth (design
// §33, A33-32); ADR 0023 M2.9a removed M2.7's migrate (design A37-10). The
// list is derived, not written here: the rows are checked against the commands with plans that
// farcast's router reaches (consentCommands), so a row that registers no
// --plan or no --confirm, a row whose command is not the router's, and a
// command with a plan that has no row each fail the test that asked (design
// §28's step 9b).
func wiredCommands(t *testing.T) []writeCommand {
	t.Helper()
	planned := consentCommands(t)
	var wired []writeCommand
	for _, wc := range writeCommands() {
		cmd := wc.cmd()
		fs := commandFlags(cmd)
		if fs.Lookup("plan") == nil || fs.Lookup("confirm") == nil {
			t.Errorf("%s writes to the cluster and does not register both --plan and --confirm", wc.name)
			continue
		}
		real, ok := planned[wc.name]
		switch {
		case !ok:
			t.Errorf("writeCommands' %s is no command with a plan that farcast's router reaches", wc.name)
			continue
		case reflect.TypeOf(cmd) != reflect.TypeOf(real):
			t.Errorf("writeCommands' %s runs a %T; farcast's router runs a %T", wc.name, cmd, real)
		}
		delete(planned, wc.name)
		wired = append(wired, wc)
	}
	for name := range planned {
		t.Errorf("%s has a plan and no writeCommands row, so no consent test runs it", name)
	}
	return wired
}

// commandLine is wc as one farcast command line against dir, its own --yes
// dropped, then extra.
func commandLine(dir config.Dir, wc writeCommand, extra ...string) []string {
	line := []string{"farcast", "--config", string(dir)}
	line = append(line, strings.Fields(wc.name)...)
	line = append(line, wc.args...)
	for _, f := range wc.flags {
		if f != "--yes" && f != "-y" {
			line = append(line, f)
		}
	}
	return append(line, extra...)
}

// runLine runs one command line through the router.
func runLine(line []string) (stdout, stderr string, code int) {
	return runLineIn(line, "")
}

// runLineIn is runLine with stdin, which is no terminal, reading stdin.
func runLineIn(line []string, stdin string) (stdout, stderr string, code int) {
	var out, errb bytes.Buffer
	code = run(context.Background(), line, strings.NewReader(stdin), &out, &errb)
	return out.String(), errb.String(), code
}

// runDirect runs wc's command as the router would, its flags and extra
// parsed, without the router's own reads, in JSON mode: what a test needs
// to show that nothing was read.
func runDirect(t *testing.T, dir config.Dir, wc writeCommand, extra ...string) (stdout, stderr []byte, err error) {
	t.Helper()
	var flags []string
	for _, f := range wc.flags {
		if f != "--yes" && f != "-y" {
			flags = append(flags, f)
		}
	}
	cmd := withFlags(t, wc.cmd(), append(flags, extra...)...)
	env, o, e := testEnvBoth(dir, output.ModeJSON)
	err = cmd.Run(t.Context(), env, wc.args)
	return o.Bytes(), e.Bytes(), err
}

// consentAnswersOnTheCommands is TestConsentAnswersAreExclusive's rows for
// the commands that have plans, through the router (A23-16): every pair and the triple of --plan,
// --confirm <d> and --yes (or -y) is design §9.2's usage error, exit 2,
// printing nothing on stdout under -o json and changing no file. --yes -y is
// one answer, and --yes=false --plan is a plan. connect runs as a first
// deploy, and redeploy over the material the instance holds, with the
// deployer's defaults faked, so their plans read a fake registry. A --yes
// that reaches an apply sends it refused (FailNextApply, A30-31) and stops
// there, never waiting on a workload or dialling.
func consentAnswersOnTheCommands(t *testing.T) {
	fakeDeployDefaults(t)
	for _, wc := range wiredCommands(t) {
		t.Run(wc.name, func(t *testing.T) {
			s := kubetest.New(t, kubetest.WithSettledWorkloads())
			dir, meta := writeInstance(t, s, true)
			if wc.edit != nil {
				wc.edit(meta)
				if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
					t.Fatal(err)
				}
			}
			if wc.prepare != nil {
				wc.prepare(t, dir)
			}
			before := treeFiles(t, string(dir))
			for _, yes := range []string{"--yes", "-y"} {
				for _, answers := range [][]string{
					{"--plan", "--confirm", sampleDigest},
					{"--plan", yes},
					{yes, "--plan"},
					{"--confirm", sampleDigest, yes},
					{"--confirm=" + sampleDigest, yes},
					{"--plan", "--confirm", sampleDigest, yes},
					{"--yes", "-y", "--plan"},
					{"--confirm=", yes},
				} {
					stdout, stderr, code := runLine(commandLine(dir, wc, append([]string{"-o", "json"}, answers...)...))
					if code != 2 || !strings.Contains(stderr, msgConsentExclusive) || stdout != "" {
						t.Errorf("%s %q: exit %d, stdout %q, stderr %q; want exit 2 and %q", wc.name, answers, code, stdout, stderr, msgConsentExclusive)
					}
				}
			}
			if got := s.Requests(); len(got) != 0 {
				t.Errorf("%s sent %d requests for answers it refused", wc.name, len(got))
			}
			sameFiles(t, wc.name+" given two answers", before, treeFiles(t, string(dir)))

			// One answer each.
			stdout, stderr, code := runLine(commandLine(dir, wc, "-o", "json", "--yes=false", "--plan"))
			if code != 0 || printedDocument(t, []byte(stdout)).Kind != plan.Kind {
				t.Errorf("%s --yes=false --plan: exit %d, %q %q; want a plan", wc.name, code, stdout, stderr)
			}
			s.FailNextApply(http.StatusInternalServerError, kube.Status{})
			if _, stderr, _ := runLine(commandLine(dir, wc, "--yes", "-y")); strings.Contains(stderr, msgConsentExclusive) {
				t.Errorf("%s --yes -y is two answers: %q", wc.name, stderr)
			}
			if applied := len(appliedRequests(s)); applied > 1 {
				t.Errorf("%s --yes -y sent %d applies; want at most its first, refused", wc.name, applied)
			}
		})
	}
}

// malformedDigestOnTheCommands is TestConfirmRefusesAMalformedDigest's rows
// for the commands that have plans (A23-16): each malformed digest is design §9.2's usage error before the
// command reads anything, and an empty --confirm beside --yes is two answers.
func malformedDigestOnTheCommands(t *testing.T) {
	hex := strings.TrimPrefix(sampleDigest, "sha256:")
	for _, wc := range wiredCommands(t) {
		t.Run(wc.name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, true)
			for _, tc := range []struct {
				args []string
				want string
			}{
				{[]string{"--confirm="}, msgConsentMalformed},
				{[]string{"--confirm", ""}, msgConsentMalformed},
				{[]string{"--confirm", "sha256:" + strings.ToUpper(hex)}, msgConsentMalformed},
				{[]string{"--confirm", "sha256:" + hex[:63]}, msgConsentMalformed},
				{[]string{"--confirm", "", "--yes"}, msgConsentExclusive},
			} {
				reads := observeConfigReads(t)
				stdout, _, err := runDirect(t, dir, wc, tc.args...)
				var ue *usageError
				if !errors.As(err, &ue) || err.Error() != tc.want || exitCodeOf(err) != 2 {
					t.Errorf("%s %q = %v; want the usage error %q", wc.name, tc.args, err, tc.want)
				}
				if got := reads(); len(got) != 0 || len(stdout) != 0 {
					t.Errorf("%s %q read %q and printed %q before refusing", wc.name, tc.args, got, stdout)
				}
			}
		})
	}
}

// ADR 0023 M2.6 (A23-16): a command that defines --plan never ignores it.
// --plan beside --yes is the three-way usage error on every one, raised
// before the command reads its record, so consent.mode runs first; and its
// help shows both flags on its usage line.
func TestAPlanFlagIsNeverIgnored(t *testing.T) {
	for _, wc := range wiredCommands(t) {
		t.Run(wc.name, func(t *testing.T) {
			if usage := wc.cmd().Usage(); !strings.Contains(strings.SplitN(usage, "\n\n", 2)[0], "[--plan | --confirm <digest>]") {
				t.Errorf("%s's usage line does not show --plan and --confirm:\n%s", wc.name, usage)
			}
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, true)
			reads := observeConfigReads(t)
			_, _, err := runDirect(t, dir, wc, "--plan", "--yes")
			if err == nil || err.Error() != msgConsentExclusive || exitCodeOf(err) != 2 {
				t.Errorf("%s --plan --yes = %v; want %q", wc.name, err, msgConsentExclusive)
			}
			if got := reads(); len(got) != 0 {
				t.Errorf("%s read %q before it read its answers", wc.name, got)
			}
		})
	}

	t.Run("through the router", planFlagThroughTheRouter)
	t.Run("through the router, a top-level command", planFlagOfATopLevelCommand)
}

// planFlagThroughTheRouter is TestAPlanFlagIsNeverIgnored's rows through the
// router. A global flag's value placed between a group and its subcommand
// can name a sibling (`kernel --config confirm meter …`, run where a config
// directory is named confirm), and the router then reads the line with the
// sibling's flags: --plan would be the sibling's and ignored, so kernel
// meter would apply, and --confirm would never be compared. Each such line
// is refused, exit 2, with nothing run, sent or written, whichever group
// and level it is in (S-R5-1): the kernel group's, the storage group's and
// the storage key group's, each command with a plan among the subcommands
// and among the siblings (ADR 0023 M2.6c). The same lines with the global
// flag before the group or after the subcommand, or naming the subcommand
// itself, are a plan; kernel deploy's and the storage commands' read the
// cluster as the reader (fakeDeployDefaults' loopback reader).
func planFlagThroughTheRouter(t *testing.T) {
	fakeDeployDefaults(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	var servers []*kubetest.Server
	for _, name := range []string{"confirm", "meter", "grant", "pin", "deploy", "rotate"} {
		s := kubetest.New(t)
		systemNamespace(s)
		dir, _ := writeInstance(t, s, true)
		// storage deploy's plan checks the instance's material.
		writeMaterial(t, dir)
		if err := os.Rename(string(dir), filepath.Join(cwd, name)); err != nil {
			t.Fatal(err)
		}
		servers = append(servers, s)
	}
	before := treeFiles(t, cwd)
	for _, tc := range []struct {
		line                []string
		sub, sibling, group string
	}{
		{[]string{"kernel", "--config", "confirm", "meter", writeName, writeNewNamespace, "--plan"}, "meter", "confirm", "kernel"},
		{[]string{"kernel", "--config", "confirm", "meter", writeName, writeNewNamespace, "--confirm", sampleDigest}, "meter", "confirm", "kernel"},
		{[]string{"kernel", "--config", "meter", "deploy", writeName, "--plan"}, "deploy", "meter", "kernel"},
		{[]string{"kernel", "--config", "deploy", "meter", writeName, writeNewNamespace, "--plan"}, "meter", "deploy", "kernel"},
		{[]string{"kernel", "--config", "deploy", "confirm", writeName, "--confirm", sampleDigest}, "confirm", "deploy", "kernel"},
		{[]string{"reader", "--config", "grant", "init", writeName, "--plan"}, "init", "grant", "reader"},
		{[]string{"storage", "key", "--config", "pin", "list", writeName}, "list", "pin", "key"},
		{[]string{"storage", "--config", "deploy", "key", "pin", writeName, "--plan"}, "key", "deploy", "storage"},
		{[]string{"storage", "key", "--config", "rotate", "pin", writeName, "--plan"}, "pin", "rotate", "key"},
		{[]string{"storage", "key", "--config", "pin", "rotate", writeName, "--confirm", sampleDigest}, "rotate", "pin", "key"},
	} {
		stdout, stderr, code := runLine(append([]string{"farcast"}, tc.line...))
		want := fmt.Sprintf(msgGroupFlagsMismatch, tc.sub, tc.sibling, tc.sibling, tc.group)
		if code != 2 || stdout != "" || !strings.Contains(stderr, want) {
			t.Errorf("farcast %q: exit %d, stdout %q, stderr %q; want exit 2 and %q", tc.line, code, stdout, stderr, want)
		}
	}
	for _, s := range servers {
		if got := s.Requests(); len(got) != 0 {
			t.Errorf("a line read with a sibling's flags sent %d requests", len(got))
		}
	}
	sameFiles(t, "lines read with a sibling's flags", before, treeFiles(t, cwd))

	for _, line := range [][]string{
		{"--config", "confirm", "kernel", "meter", writeName, writeNewNamespace, "--plan"},
		{"kernel", "meter", "--config", "confirm", writeName, writeNewNamespace, "--plan"},
		{"kernel", "--config", "meter", "meter", writeName, writeNewNamespace, "--plan"},
		{"kernel", "deploy", "--config", "meter", writeName, "--plan"},
		{"kernel", "--config", "deploy", "deploy", writeName, "--plan"},
		{"storage", "--config", "deploy", "deploy", writeName, "--plan"},
		{"storage", "--config", "pin", "key", "pin", writeName, "--plan"},
		{"storage", "key", "pin", "--config", "rotate", writeName, "--plan"},
		{"storage", "key", "--config", "rotate", "rotate", writeName, "--plan"},
	} {
		stdout, stderr, code := runLine(append([]string{"farcast"}, line...))
		if code != 0 || !strings.Contains(stdout, "\ndigest: sha256:") {
			t.Errorf("farcast %q: exit %d, %q %q; want a plan", line, code, stdout, stderr)
		}
	}
	sameFiles(t, "the plans", before, treeFiles(t, cwd))
}

// planFlagOfATopLevelCommand is TestAPlanFlagIsNeverIgnored's rows through
// the router for the top-level commands that have plans (ADR 0023 M2.6b),
// beside planFlagThroughTheRouter's for the groups: such a command has no
// sibling whose flags could read its line, so a global flag's value naming
// another command, before the command or after it, is that flag's value, and
// the command named plans, its --plan never another's. The config
// directories are named after the commands: "build" holds an instance not
// yet connected, and "connect" one connected, with its material.
func planFlagOfATopLevelCommand(t *testing.T) {
	// A test binary carries no components, so connect and redeploy plan a
	// build of a checkout: this one, named by --source, as the directory
	// the lines run in holds none.
	checkout, err := image.FindSource("")
	if err != nil {
		t.Fatal(err)
	}
	fakeDeployDefaults(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	var servers []*kubetest.Server
	for _, d := range []struct {
		name string
		wc   writeCommand
	}{{"build", writeCommandNamed(t, "connect")}, {"connect", writeCommandNamed(t, "redeploy")}} {
		s := kubetest.New(t)
		dir, meta := writeInstance(t, s, true)
		if d.wc.edit != nil {
			d.wc.edit(meta)
			if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
				t.Fatal(err)
			}
		}
		if d.wc.prepare != nil {
			d.wc.prepare(t, dir)
		}
		if err := os.Rename(string(dir), filepath.Join(cwd, d.name)); err != nil {
			t.Fatal(err)
		}
		servers = append(servers, s)
	}
	before := treeFiles(t, cwd)
	build := []string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest}
	for _, tc := range []struct {
		line    []string
		command string
	}{
		{[]string{"--config", "build", "connect", writeName, "--source", checkout, "--plan"}, "connect"},
		{[]string{"connect", "--config", "build", writeName, "--source", checkout, "--plan"}, "connect"},
		{[]string{"--config", "connect", "redeploy", writeName, "--source", checkout, "--plan"}, "redeploy"},
		{[]string{"redeploy", writeName, "--config", "connect", "--source", checkout, "--plan"}, "redeploy"},
		{append([]string{"--config", "connect", "build", writeName, "--plan"}, build...), "build"},
		{append([]string{"build", writeName, "--config", "connect"}, append(slices.Clone(build), "--plan")...), "build"},
	} {
		stdout, stderr, code := runLine(append([]string{"farcast", "-o", "json"}, tc.line...))
		if code != 0 {
			t.Errorf("farcast %q: exit %d, %q; want %s's plan", tc.line, code, stderr, tc.command)
			continue
		}
		if b := decodedBound(t, printedDocument(t, []byte(stdout))); b.Command != tc.command || b.Instance != writeName {
			t.Errorf("farcast %q planned %q of %q; want %s's plan", tc.line, b.Command, b.Instance, tc.command)
		}
	}
	// connect's and redeploy's plans read no cluster; build's reads it as
	// the instance's reader alone (ADR 0023 M2.8, design §33 A33-21).
	for _, s := range servers {
		for _, r := range s.Requests() {
			if r.As != "reader" || (r.Path != "/token" && r.Method != http.MethodGet) {
				t.Errorf("a plan sent %s %s as %q; a plan reads as the reader alone", r.Method, r.Path, r.As)
			}
		}
	}
	sameFiles(t, "the top-level commands' plans", before, treeFiles(t, cwd))
}

// ADR 0023 M2.6 (A23-16): a refusal for want of a terminal names the route
// that needs none, --plan and then --confirm. The gates are reader grant's,
// connect's (its cost question, and the build question it shares with
// every deployer command, each of which since M2.6c has a plan; a deployer
// that registers no consent flags names none (consentFlags.suffix)),
// redeploy's (its change question, and that build question), build's (its
// cost question), run's (its review), kernel deploy's (its cost question,
// below the floor or not, and the build question), storage deploy's (its
// cost question, and the build question), storage key pin's (lowering the
// pin with --replace), storage key rotate's (its question) and
// git-credential set's and rm's (M2.8, design §33, A33-30: their
// questions): kernel meter and kernel
// confirm ask nothing, so a run without a terminal is not refused (A23-9).
//
// The gates are derived, not only listed (design §28's step 9b): every
// usage error in this package's source that names the route
// (suffixedRefusals) must be a gate here, with the rows that reach it, and
// every gate here must be one; every command with a plan is gated here or
// asks nothing; and a method of a command with a plan that asks for --yes
// without naming the route fails. run's refusal of --yes at the limit
// (A28-1) is no refusal for want of a terminal: it names --plan in its own
// words, which TestYesNeverDeploysAtTheLimit pins.
func TestNonInteractiveRefusalsNameThePlan(t *testing.T) {
	gates := []struct {
		command string
		texts   []string // its refusals' formats
		rows    func(t *testing.T)
	}{
		{"connect", []string{msgConnectCostYes, msgBuildYes + consentSuffix}, connectRefusalsNameThePlan},
		{"redeploy", []string{msgRedeployYes}, redeployRefusalsNameThePlan},
		{"build", []string{msgBuildCostYes}, buildRefusalNamesThePlan},
		{"run", []string{msgRunYes}, runRefusalNamesThePlan},
		{"kernel deploy", []string{msgKernelCostYes, msgKernelBelowFloorYes}, kernelDeployRefusalsNameThePlan},
		{"storage deploy", []string{msgKeyholderCostYes, msgGrantBucketTerminal}, storageDeployRefusalNamesThePlan},
		{"storage key pin", []string{msgKeyPinLowerYes}, keyPinRefusalNamesThePlan},
		{"storage key rotate", []string{msgRotateYes}, rotateRefusalNamesThePlan},
		{"reader grant", []string{msgReaderGrantTerminal}, readerGrantRefusalNamesThePlan},
		{"git-credential set", []string{msgGitCredentialTerminal}, gitCredentialRefusalNamesThePlan("git-credential set")},
		{"git-credential rm", []string{msgGitCredentialTerminal}, gitCredentialRefusalNamesThePlan("git-credential rm")},
	}
	planned := consentCommands(t)
	gated := map[string]bool{}
	var listed []string
	for _, g := range gates {
		if _, ok := planned[g.command]; !ok {
			t.Errorf("%s is gated here and is no command with a plan", g.command)
		}
		gated[g.command] = true
		for _, text := range g.texts {
			if !strings.HasSuffix(text, consentSuffix) {
				t.Errorf("%s's non-interactive refusal %q does not end with %q", g.command, text, consentSuffix)
			}
			listed = append(listed, text)
		}
	}
	found := suffixedRefusals(t, planned)
	for _, text := range found {
		if !slices.Contains(listed, text) {
			t.Errorf("the refusal %q names the plan's route and is in no gate here: add it, with the rows that reach it", text)
		}
	}
	for _, text := range listed {
		if !slices.Contains(found, text) {
			t.Errorf("the gate %q is no usage error of this package's source", text)
		}
	}
	for _, g := range gates {
		t.Run(g.command, g.rows)
	}

	for _, wc := range wiredCommands(t) {
		if gated[wc.name] {
			continue
		}
		t.Run(wc.name+" asks nothing", func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			var c Command
			fc := &fakeCluster{}
			switch wc.name {
			case "kernel meter":
				meteredInstance(t, dir, writeName, tcdeploy.DefaultNamespace)
				c = meterCmd(fc)
			case "kernel confirm":
				kernelInstance(t, dir, writeName)
				c = withFlags(t, confirmCmd(fc), wc.flags...)
			default:
				t.Fatalf("%s has a plan and is in no row here", wc.name)
			}
			env, _, errb := testEnvBoth(dir, output.ModeHuman) // stdin is no terminal
			if err := c.Run(t.Context(), env, wc.args); err != nil || len(fc.applied) != 1 || strings.Contains(errb.String(), "[y/N]") {
				t.Errorf("%s without a terminal = %v, applying %d streams, saying %q; want it done, unasked", wc.name, err, len(fc.applied), errb)
			}
		})
	}
}

// readerGrantRefusalNamesThePlan is TestNonInteractiveRefusalsNameThePlan's
// row for reader grant: with no terminal it refuses, exit 2, naming the
// plan's route, through the router.
func readerGrantRefusalNamesThePlan(t *testing.T) {
	dir := readerRecordFor(t, grantName, "proj-test1")
	if _, err := dir.UpdateInstanceMetadata(grantName, func(m *config.InstanceMetadata) error {
		m.Reader = &config.Reader{Email: readerEmail(grantName, "proj-test1"), KeyID: readerTestKeyID}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := farcastIn(t, dir, "reader", "grant", grantName); code != 2 ||
		!strings.Contains(stderr, "farcast reader: reader grant needs a terminal to confirm, or --plan and then --confirm <digest>\n") {
		t.Errorf("reader grant without a terminal: exit %d, %q", code, stderr)
	}
}

// gitCredentialRefusalNamesThePlan is TestNonInteractiveRefusalsNameThePlan's
// row for git-credential set or rm (ADR 0023 M2.8, design §33, A33-30 step
// 4): with no terminal and no answer it refuses, exit 2, naming the plan's
// route, through the router, before it reads the record or sends anything.
func gitCredentialRefusalNamesThePlan(name string) func(t *testing.T) {
	return func(t *testing.T) {
		s := kubetest.New(t)
		dir, _ := writeInstance(t, s, true)
		wc := writeCommandNamed(t, name)
		reads := observeConfigReads(t)
		stdout, stderr, code := farcastIn(t, dir, append(append(strings.Fields(name), wc.args...), wc.flags...)...)
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "farcast git-credential: "+msgGitCredentialTerminal+"\n") {
			t.Errorf("%s without a terminal: exit %d, %q %q", name, code, stdout, stderr)
		}
		for _, p := range reads() {
			if strings.HasPrefix(p, dir.InstancePath(writeName)) {
				t.Errorf("%s without a terminal read %s", name, p)
			}
		}
		if got := s.Requests(); len(got) != 0 {
			t.Errorf("%s without a terminal sent %d requests", name, len(got))
		}
	}
}

// confirmLineOnTheCommands is TestTheConfirmLineRunsTheSameCommand's rows
// through run(), for the commands that have plans: the line a plan prints, split as a shell splits
// it and run as farcast runs it, recomputes the same plan, so it passes the
// comparison. A plan that applies then opens the writer and sends its first
// apply, which kubetest refuses (FailNextApply, A30-31): one refused apply,
// nothing stored, exit 1. One that writes nothing says so and exits 0; a
// blocked plan prints no line.
//
// A row whose command has fakes behind its seams (connect's, redeploy's,
// build's) cannot run through the router, which sets none: connect's
// reconnect would dial the carrier. connect runs here as a first deploy
// instead, and redeploy and build as writeCommands has them, with the
// deployer's defaults faked; each stops at its refused apply and never
// dials.
//
// kernel deploy's and the storage commands' rows (ADR 0023 M2.6c) run
// through the router as planCommands has them, their fakes left to the
// router's defaults: the deployer's faked, the plan's reader the loopback
// one, the key pin reached as the writer against the fixture's kubetest
// (realPinOpener), and the keyholder and the storage mint refused. kernel
// deploy and storage deploy stop at their refused apply, after the reader's
// reads and the writer's preflight, and storage deploy's pin create as its
// plan lists it. storage key pin writes its pin and hands it to no replica,
// exit 0; storage key rotate with no keyholder mints and saves, exit 0; and
// with one it mints, saves and cannot open the keyholder, so its rotation is
// unfinished, exit 1. Each got past the comparison.
//
// run's fetch plans (ADR 0023 M2.6d) run through the router as planCommands
// has them: the line of one that is not blocked opens the reader, then the
// writer, and stops at its refused apply of the fetch. Its deploy plan has
// its own row (runConfirmLinesRunTheSameCommand): the fetch plan's line
// prints the deploy plan, whose line confirms it alone.
//
// git-credential's rows (ADR 0023 M2.8, design §33, A33-30) run through the
// router too, the writer the package's loopback default: their plans read
// nothing, and the line reads the Secret's metadata as the writer. set's
// line, its token piped to it on stdin (--token-file -), stops at its
// refused apply; rm's deletes the Git credential its fixture holds, exit 0.
func confirmLineOnTheCommands(t *testing.T) {
	pinPlanClock(t)
	pinRunClock(t)
	fp, _ := fakeDeployDefaults(t)
	realPinOpener(t)
	var rows []planCommand
	for _, name := range []string{"connect", "redeploy", "build"} {
		wc := writeCommandNamed(t, name)
		var flags []string
		for _, f := range wc.flags {
			if f != "--yes" {
				flags = append(flags, f)
			}
		}
		row := planCommand{name: name, shape: "through the router", args: wc.args, flags: flags, edit: wc.edit, prepare: wc.prepare}
		if name == "build" {
			// build's plan reads the cluster as the reader (ADR 0023
			// M2.8, design §33 A33-21).
			row.readsCluster, row.identity, row.seed = true, "reader", builderAccountSeeded
		}
		rows = append(rows, row)
	}
	readsCluster := []string{"kernel deploy", "storage deploy", "storage key pin", "storage key rotate"}
	for _, row := range planCommands() {
		switch {
		case row.fakes == nil:
			rows = append(rows, row)
		case slices.Contains(readsCluster, row.name) || row.name == "run" || strings.HasPrefix(row.name, "git-credential "):
			row.fakes, row.cmd = nil, nil
			rows = append(rows, row)
		}
	}
	for _, row := range rows {
		t.Run(row.String(), func(t *testing.T) {
			s, dir := planFixture(t, row)
			// The registry the ensure answers is the one the record names.
			meta, err := dir.LoadInstanceMetadata(writeName)
			if err != nil {
				t.Fatal(err)
			}
			fp.registry = &planck.Registry{Ref: registryRefFor(meta), Prefix: meta.Registry.Prefix}
			wc := writeCommand{name: row.name, args: row.args, flags: row.flags}
			stdout, stderr, code := runLine(commandLine(dir, wc, "--plan"))
			if code != 0 {
				t.Fatalf("%s --plan: exit %d, %s", row, code, stderr)
			}
			line := confirmLineOf(stdout)
			if strings.Contains(stdout, "\nblocked: --confirm would refuse this plan") {
				if line != "" {
					t.Errorf("a blocked plan offers %q", line)
				}
				return
			}
			words := shellWords(t, line)
			if len(words) < 3 || words[0] != "farcast" || words[len(words)-2] != "--confirm" || words[len(words)-1] != digestLine(t, stdout) {
				t.Fatalf("the confirm line is %q", line)
			}
			if slices.Contains(words, "--plan") {
				t.Errorf("the confirm line still plans: %q", line)
			}
			// What the plan writes, in JSON, before the confirm line writes it.
			jsonPlan, _, _ := runLine(commandLine(dir, wc, "-o", "json", "--plan"))
			planned := decodedBound(t, printedDocument(t, []byte(jsonPlan)))
			reads := len(s.Requests())
			s.FailNextApply(http.StatusInternalServerError, kube.Status{})
			stdin := ""
			if strings.HasPrefix(row.name, "git-credential ") {
				// set's line reads its token from stdin, piped, after the
				// comparison.
				stdin = gitCredentialToken + "\n"
			}
			out, errb, code := runLineIn(words, stdin)
			if strings.Contains(errb, "the plan for this command is now") {
				t.Fatalf("the confirm line computed another plan: %s", errb)
			}
			noop := row.shape == "already metered" || row.shape == "an empty window"
			switch {
			case row.name == "git-credential rm":
				if code != 0 || !strings.Contains(out, "deleted the Git credential") {
					t.Errorf("the confirm line: exit %d, %q %q; want the credential deleted", code, out, errb)
				}
			case noop && (code != 0 || out == ""):
				t.Errorf("the confirm line of a plan that writes nothing: exit %d, %q %q", code, out, errb)
			case row.name == "storage key pin" || row.String() == "storage key rotate/no keyholder":
				if code != 0 || out == "" {
					t.Errorf("the confirm line: exit %d, %q %q; want it done", code, out, errb)
				}
			case row.String() == "storage key rotate/with a keyholder":
				if code != 1 || !strings.Contains(errb, "the hand-over did not happen") {
					t.Errorf("the confirm line: exit %d, %q; want it past the comparison, its keyholder refused", code, errb)
				}
			case row.String() == "storage deploy/a first deploy":
				// Its storage mint, which the router leaves at its refusing
				// default, comes after the writer's pin read and before any
				// write.
				if code != 1 || !strings.Contains(errb, "create storage for") {
					t.Errorf("the confirm line: exit %d, %q; want it past the comparison, its storage mint refused", code, errb)
				}
			case !noop && (code != 1 || !strings.Contains(errb, "documents were applied before")):
				t.Errorf("the confirm line: exit %d, %q; want it past the comparison, at its first apply, refused", code, errb)
			}
			switch {
			case strings.HasPrefix(row.name, "git-credential "):
				// The writer alone, and only after the comparison: the
				// Secret's read, then set's refused apply or rm's delete.
				var sent []string
				for _, r := range s.Requests()[reads:] {
					if r.As != "writer" {
						t.Errorf("%s --confirm sent %s %s as %q; want the writer alone", row, r.Method, r.Path, r.As)
					}
					if r.Path != "/token" {
						sent = append(sent, r.Method+" "+r.Path)
					}
				}
				last := "PATCH " + gitCredentialPath
				if row.name == "git-credential rm" {
					last = "DELETE " + gitCredentialPath
				}
				if want := []string{"GET " + gitCredentialPath, last}; !slices.Equal(sent, want) {
					t.Errorf("%s --confirm sent %q; want %q", row, sent, want)
				}
			case noop || row.String() == "storage key rotate/no keyholder":
				onlyThePlansSent(t, row, s.Requests()[reads:], consentConfirm)
			case row.String() == "storage deploy/a first deploy":
				confirmed := s.Requests()[reads:]
				firstWriter := slices.IndexFunc(confirmed, func(r kubetest.Request) bool { return r.As == "writer" })
				onlyThePlansSent(t, row, confirmed[:max(firstWriter, 0)], consentConfirm)
				var sent []string
				for _, r := range confirmed[max(firstWriter, 0):] {
					if r.Path != "/token" {
						sent = append(sent, r.Method+" "+r.Path)
					}
				}
				if want := []string{"GET /api/v1/namespaces", "GET " + pinPath}; firstWriter < 0 || !slices.Equal(sent, want) {
					t.Errorf("%s sent as the writer %q; want %q", row, sent, want)
				}
			case !row.readsCluster || row.name == "build" || row.name == "kernel deploy" || row.name == "storage deploy":
				// The plan's reads, if it reads, then the writer: its
				// preflight, if it makes one, and storage deploy's pin
				// create, as its plan lists it, before its refused apply.
				readerReqs, writerReqs := stoppedAtTheFirstApply(t, row.String(), s.Requests()[reads:])
				onlyThePlansSent(t, row, readerReqs, consentConfirm)
				var sent []string
				for _, r := range writerReqs {
					sent = append(sent, r.Method+" "+r.Path)
				}
				var want []string
				switch row.name {
				case "kernel meter", "kernel confirm", "reader grant":
				case "storage deploy":
					// Since ADR 0023 M2.8 its first apply is the keyholder's
					// account, the plan's first applied document, before the
					// pin (design §33, A33-26).
					want = []string{"GET /api/v1/namespaces", "GET " + pinPath}
					all := s.Requests()
					if first := factPath(t, applyWrites(planned)[0]); all[len(all)-1].Path != first {
						t.Errorf("%s's first apply was of %s; want the plan's first document, %s", row, all[len(all)-1].Path, first)
					}
				default:
					want = []string{"GET /api/v1/namespaces"}
				}
				if !slices.Equal(sent, want) {
					t.Errorf("%s sent as the writer before its first apply %q; want %q", row, sent, want)
				}
			default:
				// The recomputation reads as the reader, and only then does
				// the writer reach the pin.
				confirmed := s.Requests()[reads:]
				firstWriter := slices.IndexFunc(confirmed, func(r kubetest.Request) bool { return r.As == "writer" })
				for i, r := range confirmed {
					reading := firstWriter < 0 || i < firstWriter
					if (reading && r.As != "reader") || (!reading && r.As != "writer") {
						t.Errorf("%s --confirm sent %s %s as %q at %d; want the reader's reads, then the writer's", row, r.Method, r.Path, r.As, i)
					}
				}
				if firstWriter < 1 {
					t.Errorf("%s --confirm's requests begin with the writer's, at %d", row, firstWriter)
				}
			}
		})
	}
	t.Run("run/its deploy plan", runConfirmLinesRunTheSameCommand)
}

// confirmLineOf is the command line a printed plan ends with, after "To do
// exactly this: ", or "" for one that prints none.
func confirmLineOf(stdout string) string {
	var line string
	for l := range strings.Lines(stdout) {
		if rest, ok := strings.CutPrefix(l, "To do exactly this: "); ok {
			line = strings.TrimSuffix(rest, "\n")
		}
	}
	return line
}
