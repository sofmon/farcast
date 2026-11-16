package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
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

// routeLine parses argv exactly as run does, through the default registry.
// A command that does not register --plan and --confirm yet gets them here,
// so every command's flags can carry a confirm line.
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
	if r.flags.Lookup("plan") == nil {
		var c consentFlags
		c.register(r.flags)
	}
	f := r.flags.Lookup("confirm")
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

// wiredCommands is every writeCommands row whose fresh flag set defines
// --plan: the commands wired so far (A23-14). In ADR 0023 M2.6a they are
// exactly kernel meter, kernel confirm and reader grant; the other eight
// register no consent flag yet, so --plan is an unknown flag on them.
func wiredCommands(t *testing.T) []writeCommand {
	t.Helper()
	var wired []writeCommand
	var names []string
	for _, wc := range writeCommands() {
		fs := flag.NewFlagSet(wc.name, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		wc.cmd().SetFlags(fs)
		if fs.Lookup("plan") != nil {
			if fs.Lookup("confirm") == nil {
				t.Errorf("%s registers --plan without --confirm", wc.name)
			}
			wired = append(wired, wc)
			names = append(names, wc.name)
		}
	}
	if want := []string{"kernel meter", "kernel confirm", "reader grant"}; !slices.Equal(names, want) {
		t.Errorf("the commands with plans are %q; ADR 0023 M2.6a wires %q", names, want)
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
	var out, errb bytes.Buffer
	code = run(context.Background(), line, strings.NewReader(""), &out, &errb)
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
// one answer, and --yes=false --plan is a plan.
func consentAnswersOnTheCommands(t *testing.T) {
	noKubectl(t)
	for _, wc := range wiredCommands(t) {
		t.Run(wc.name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, true)
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
			if _, stderr, _ := runLine(commandLine(dir, wc, "--yes", "-y")); strings.Contains(stderr, msgConsentExclusive) {
				t.Errorf("%s --yes -y is two answers: %q", wc.name, stderr)
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
// before the command reads its record, so consent.mode runs first.
func TestAPlanFlagIsNeverIgnored(t *testing.T) {
	for _, wc := range wiredCommands(t) {
		t.Run(wc.name, func(t *testing.T) {
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
}

// planFlagThroughTheRouter is TestAPlanFlagIsNeverIgnored's rows through the
// router. A global flag's value placed between a group and its subcommand
// can name a sibling (`kernel --config confirm meter …`, run where a config
// directory is named confirm), and the router then reads the line with the
// sibling's flags: --plan would be the sibling's and ignored, so kernel
// meter would apply, and --confirm would never be compared. Each such line
// is refused, exit 2, with nothing run, sent or written, whichever group
// and level it is in (S-R5-1). The same lines with the global flag before
// the group or after the subcommand, or naming the subcommand itself, are a
// plan.
func planFlagThroughTheRouter(t *testing.T) {
	ran := strayKubectl(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	var servers []*kubetest.Server
	for _, name := range []string{"confirm", "meter", "grant", "pin"} {
		s := kubetest.New(t)
		dir, _ := writeInstance(t, s, true)
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
		{[]string{"reader", "--config", "grant", "init", writeName, "--plan"}, "init", "grant", "reader"},
		{[]string{"storage", "key", "--config", "pin", "list", writeName}, "list", "pin", "key"},
	} {
		stdout, stderr, code := runLine(append([]string{"farcast"}, tc.line...))
		want := fmt.Sprintf(msgGroupFlagsMismatch, tc.sub, tc.sibling, tc.sibling, tc.group)
		if code != 2 || stdout != "" || !strings.Contains(stderr, want) {
			t.Errorf("farcast %q: exit %d, stdout %q, stderr %q; want exit 2 and %q", tc.line, code, stdout, stderr, want)
		}
	}
	if ran() {
		t.Error("a line read with a sibling's flags ran kubectl")
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
	} {
		stdout, stderr, code := runLine(append([]string{"farcast"}, line...))
		if code != 0 || !strings.Contains(stdout, "\ndigest: sha256:") {
			t.Errorf("farcast %q: exit %d, %q %q; want a plan", line, code, stdout, stderr)
		}
	}
	sameFiles(t, "the plans", before, treeFiles(t, cwd))
}

// ADR 0023 M2.6 (A23-16): a refusal for want of a terminal names the route
// that needs none, --plan and then --confirm. reader grant's is the one gate
// among the commands wired so far: kernel meter and kernel confirm ask
// nothing, so a run without a terminal is not refused (A23-9).
func TestNonInteractiveRefusalsNameThePlan(t *testing.T) {
	gates := map[string]string{"reader grant": msgReaderGrantTerminal}
	for name, text := range gates {
		if !strings.HasSuffix(text, consentSuffix) {
			t.Errorf("%s's non-interactive refusal %q does not end with %q", name, text, consentSuffix)
		}
	}

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

	for _, wc := range wiredCommands(t) {
		if _, gated := gates[wc.name]; gated {
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

// confirmLineOnTheCommands is TestTheConfirmLineRunsTheSameCommand's rows
// through run(), for the commands that have plans: the line a plan prints, split as a shell splits
// it and run as farcast runs it, recomputes the same plan, so it passes the
// comparison. A plan that writes then stops at the writer's applyReady (this
// test's PATH holds no kubectl), and one that writes nothing says so and
// exits 0; a blocked plan prints no line.
func confirmLineOnTheCommands(t *testing.T) {
	noKubectl(t)
	pinPlanClock(t)
	for _, row := range planCommands() {
		t.Run(row.String(), func(t *testing.T) {
			s, dir := planFixture(t, row)
			wc := writeCommand{name: row.name, args: row.args, flags: row.flags}
			stdout, stderr, code := runLine(commandLine(dir, wc, "--plan"))
			if code != 0 {
				t.Fatalf("%s --plan: exit %d, %s", row, code, stderr)
			}
			var line string
			for l := range strings.Lines(stdout) {
				if rest, ok := strings.CutPrefix(l, "To do exactly this: "); ok {
					line = strings.TrimSuffix(rest, "\n")
				}
			}
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
			out, errb, code := runLine(words)
			if strings.Contains(errb, "the plan for this command is now") {
				t.Fatalf("the confirm line computed another plan: %s", errb)
			}
			noop := row.shape == "already metered" || row.shape == "an empty window"
			switch {
			case noop && (code != 0 || out == ""):
				t.Errorf("the confirm line of a plan that writes nothing: exit %d, %q %q", code, out, errb)
			case !noop && (code != 1 || !strings.Contains(errb, msgCannotApply+msgKubectlMissing)):
				t.Errorf("the confirm line: exit %d, %q; want it past the comparison, at applyReady", code, errb)
			}
			if got := s.Requests(); len(got) != 0 {
				t.Errorf("%s sent %d requests", row, len(got))
			}
		})
	}
}
