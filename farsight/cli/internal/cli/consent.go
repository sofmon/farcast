package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
)

// The consent protocol (ADR 0023 decision 8, M2.6; design §9.2, as A23-16 and
// A23-17 amend it).
//
// A command that writes to a cluster computes everything it would do as a
// plan.Bound. --plan prints it and changes nothing. --confirm <digest>
// computes it again from live state and executes only when the new digest is
// the one given, so what runs is exactly what the operator read. An
// interactive run, and --yes, keep today's gates.
//
// The three answers are exclusive: --plan, --confirm and --yes each say what
// the operator decided, and two of them together say two things.

// The usage texts of design §9.2.
const (
	msgConsentExclusive = "--plan, --confirm and --yes are three different answers; give one"
	msgConsentMalformed = "--confirm takes the digest a plan printed: sha256: and 64 lowercase hex characters"
)

// consentSuffix ends every non-interactive refusal of a command that has a
// plan, after its "pass --yes …" clause where it has one: the route that
// needs no terminal and no --yes (A23-16).
const consentSuffix = ", or --plan and then --confirm <digest>"

// The help of the two flags.
const (
	planUsage    = "print the plan of what this would do, and change nothing"
	confirmUsage = "do exactly what the plan with this digest said, refusing if it has changed"
)

// msgPlanAgain ends every plan_changed refusal raised after the comparison
// (A23-16, A24-2): what changed was found only once the confirmed plan ran,
// so the way on is a new plan.
const msgPlanAgain = "run the same command with --plan instead of --confirm"

// consentFlags is --plan and --confirm <digest> on one command.
type consentFlags struct {
	plan bool
	// confirm is --confirm's value, kept as given; confirmGiven says the flag
	// was given at all, so --confirm= and --confirm '' are a malformed digest
	// rather than no answer.
	confirm      string
	confirmGiven bool
	// registered says register ran: the command has a plan, so a refusal
	// for want of a terminal that it shares with commands that have none
	// yet (confirmBuild's) names the plan's route on it alone (suffix).
	registered bool
}

// register adds --plan and --confirm to fs. --confirm's callback only stores
// what it was given and never fails, so a malformed digest is refused by
// mode, with design §9.2's text, rather than by the flag package with its
// own. A bare --confirm with no value is still the flag package's usage error.
// Like BoolVar, it starts both flags from their defaults: no answer.
func (f *consentFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&f.plan, "plan", false, planUsage)
	f.confirm, f.confirmGiven, f.registered = "", false, true
	fs.Func("confirm", confirmUsage, func(v string) error {
		f.confirm, f.confirmGiven = v, true
		return nil
	})
}

// suffix is consentSuffix on a command that has a plan, and "" on one that
// has none yet: the end of a non-interactive refusal shared by both kinds
// (A23-16: each part adds the suffix only for the commands it wires).
func (f *consentFlags) suffix() string {
	if f.registered {
		return consentSuffix
	}
	return ""
}

// consentMode is the answer a command was given.
type consentMode int

const (
	// consentNone: no --plan and no --confirm; today's prompt, or --yes.
	consentNone consentMode = iota
	// consentPlan: --plan, which prints the plan and writes nothing.
	consentPlan
	// consentConfirm: --confirm <digest>, which executes the plan only if
	// its digest is still the one given.
	consentConfirm
)

// mode is the answer the parsed flags give, with --confirm's digest. yes is
// the command's own --yes, as parsed: the count is of values, not of flags
// given, so --yes=false --plan is one answer, a plan, and --yes -y is one.
// Every command with a plan calls it right after its argument-count check,
// before it reads anything. Two answers or more, or a digest that is not
// sha256: and 64 lowercase hex characters, are usage errors; the count is
// checked first, so an empty --confirm beside --yes is two answers.
func (f *consentFlags) mode(yes bool) (consentMode, string, error) {
	answers := 0
	for _, given := range []bool{f.plan, f.confirmGiven, yes} {
		if given {
			answers++
		}
	}
	if answers > 1 {
		return consentNone, "", usagef(msgConsentExclusive)
	}
	switch {
	case f.confirmGiven:
		digest, err := plan.ParseDigest(f.confirm)
		if err != nil {
			return consentNone, "", usagef(msgConsentMalformed)
		}
		return consentConfirm, digest, nil
	case f.plan:
		return consentPlan, "", nil
	}
	return consentNone, "", nil
}

// msgPlanNeedsReader is a plan's refusal when it would read the cluster and
// the instance has no reader 'reader grant' has verified (design §7.3, as
// A23-21 words it): the command, the answer (--plan or --confirm), the
// instance, the reader's state as 'instances' prints it, and what to do
// from that state (readerRemedy).
const msgPlanNeedsReader = "'farcast %s %s' reads the cluster as instance %q's reader, whose state is %s; %s, or run the command in a terminal"

// requireGrantedReader refuses a plan that reads the cluster as the
// instance's reader when that reader is not one 'reader grant' has verified
// read-only (ADR 0023 M2.6, A23-1, A23-21). Under --plan and --confirm every
// plan whose cluster_identity is reader calls it before its reader seam, and
// before credentials.yaml or any provider is opened, so the refusal reads no
// key and sends nothing; there is no fallback to the writer. command is the
// plan's Bound.Command. An interactive or --yes run reads as the writer it
// opened, and needs no reader: m consentNone is never refused.
//
// The reader's state is told from the record and the presence of reader.key
// (readerStateOf), never by opening the key; an error telling it is returned
// as it is. A granted reader passes, and openCluster's own refusals stand for
// it: a record that names another reader than the derived one, an unsafe
// record, a reader.key that cannot be read.
func requireGrantedReader(dir config.Dir, meta *config.InstanceMetadata, command string, m consentMode) error {
	if m == consentNone {
		return nil
	}
	name := meta.Name
	state, err := ungrantedReader(dir, meta)
	if err != nil || state == "" {
		return err
	}
	answer := "--plan"
	if m == consentConfirm {
		answer = "--confirm"
	}
	return refuse(errCredentialMissing, msgPlanNeedsReader, command, answer, name, strings.ReplaceAll(state, "_", " "), readerRemedy(state, name))
}

// ungrantedReader is the state of the instance's reader when it is not one
// 'reader grant' has verified, as readerStateOf tells it from the record and
// the presence of reader.key, never by opening the key; "" when it is one.
// An error telling it is returned as it is.
func ungrantedReader(dir config.Dir, meta *config.InstanceMetadata) (string, error) {
	state, err := readerStateOf(dir, meta.Name, meta)
	if err != nil || state == readerGranted {
		return "", err
	}
	return state, nil
}

// readerRemedy is what the operator does about a reader in state, for the
// instance name: the steps of 'farcast reader' that remain from there
// (A23-21). A state that is not one of the four (granted needs none) is
// given the last step's.
func readerRemedy(state, name string) string {
	switch state {
	case readerNone:
		return fmt.Sprintf("run 'farcast reader init %s', the printed Cloud Shell script, 'farcast reader record' and 'farcast reader grant'", name)
	case readerKeyMissing:
		return fmt.Sprintf("copy reader.key from the machine that made it, or run 'farcast reader init %s --rotate'", name)
	case readerNotUploaded:
		return fmt.Sprintf("run the printed Cloud Shell script, then 'farcast reader record %s --key-id <id>' and 'farcast reader grant %s'", name, name)
	}
	return fmt.Sprintf("run 'farcast reader grant %s'", name)
}

// planStamp is the farcast a plan binds (design §9.3): a bundled and a
// terminal farcast cannot confirm each other's plans. A variable, so the plan
// vectors bind a fixed stamp.
var planStamp = func() plan.Stamp { return plan.Stamp(currentStamp()) }

// planTarget is the instance a plan is about, as its record names it, with
// the uid of farcast-system the plan read: "" for a plan that reads no
// cluster. The values are the record's own, unscrubbed (A23-4).
func planTarget(meta *config.InstanceMetadata, systemNamespaceUID string) plan.Target {
	return plan.Target{
		Provider:           meta.Provider,
		Project:            meta.Project,
		Region:             meta.Region,
		Cluster:            meta.Cluster,
		Endpoint:           meta.Endpoint,
		CreatedAt:          plan.Time(meta.CreatedAt),
		SystemNamespaceUID: systemNamespaceUID,
	}
}

// newBound opens command's plan for the instance meta records: the protocol,
// this farcast's stamp, and the target. identity is who the plan reads the
// cluster as ("reader" or "none"), and systemNamespaceUID the uid of
// farcast-system it read ("" for none). The command adds its stage, options,
// facts and blocks.
func newBound(command string, meta *config.InstanceMetadata, identity, systemNamespaceUID string) plan.Bound {
	return plan.Bound{
		Protocol:        plan.Protocol,
		FarCast:         planStamp(),
		Command:         command,
		Instance:        meta.Name,
		Target:          planTarget(meta, systemNamespaceUID),
		ClusterIdentity: identity,
	}
}

// applyFacts is a write fact for each document of an apply stream, in the
// stream's order: what it is and where it goes, as the stream's own check
// identifies it (kube.SplitStream), and the SHA-256 of the document's bytes
// as rendered. Every one is an apply, forced (§5.3, Choice 6 (c)) and at no
// resourceVersion.
func applyFacts(stream []byte) ([]plan.Fact, error) {
	return applyFactsAt(stream, "")
}

// applyFactsAt is applyFacts for a stream rendered at the resourceVersion
// rv it was read at, "" for none: the stream is split as cluster.ApplyAt
// splits it (kube.AllowResourceVersion(rv)), so its one document may carry
// rv, and each fact binds rv (ADR 0023 M2.7, A30-40). run's egress policy is
// the one such stream.
func applyFactsAt(stream []byte, rv string) ([]plan.Fact, error) {
	docs, err := kube.SplitStream(stream, kube.AllowResourceVersion(rv))
	if err != nil {
		return nil, err
	}
	facts := make([]plan.Fact, 0, len(docs))
	for _, d := range docs {
		sum := sha256.Sum256(d.Raw)
		facts = append(facts, plan.WriteFact{
			Type: plan.TypeWrite, API: d.Kind.APIVersion, Kind: d.Kind.Kind, Namespace: d.Namespace, Name: d.Name,
			Method: plan.WriteApply, Force: true, ResourceVersion: rv, SHA256: hex.EncodeToString(sum[:]),
		})
	}
	return facts, nil
}

// noticeFact is a line a command prints, as a plan carries it: under --plan
// only the plan shows it (A23-26).
func noticeFact(text string) plan.NoticeFact {
	return plan.NoticeFact{Type: plan.TypeNotice, Text: text}
}

// blockOf is a refusal carried in a plan (A23-18): the plan prints it, and
// --confirm refuses with it. Its kind is the one the router would give the
// error, so it is always one of the closed set; its message is the error's
// own text.
func blockOf(err error) plan.Block {
	return plan.Block{Kind: kindOf(classified(err)), Message: err.Error()}
}

// planChanged is --confirm's refusal when the recomputed plan is not the one
// confirmed: kind plan_changed, naming both digests.
func planChanged(now, given string) error {
	return withKind(kindPlanChanged, fmt.Errorf("the plan for this command is now %s, not the %s given to --confirm: "+
		"something it binds has changed since the plan was made; run it with --plan to review the new one. Nothing was written.",
		now, given))
}

// changedAfterPlan is the refusal of a command that finds, after its plan
// was decided and before it writes what the plan said, that something the
// plan relied on is no longer so. Under --confirm the plan changed: kind
// plan_changed, ending with msgPlanAgain. An interactive or --yes run made
// its plan a moment before and consented to it, not to a digest: internal,
// with msg alone.
func changedAfterPlan(m consentMode, msg string) error {
	if m == consentConfirm {
		return withKind(kindPlanChanged, errors.New(msg+"; "+msgPlanAgain))
	}
	return errors.New(msg)
}

// refuseBlocked is --confirm's refusal of a plan that carries blocks: the
// first one's kind and message.
func refuseBlocked(b plan.Bound) error {
	return withKind(b.Blocked[0].Kind, errors.New(b.Blocked[0].Message))
}

// confirmPlan is --confirm's check of the plan it recomputed: its digest must
// be the one given (planChanged otherwise), and then it must carry no block
// (refuseBlocked). The digest is compared first, so a blocked plan that
// changed says it changed.
func confirmPlan(b plan.Bound, given string) error {
	now, err := boundDigest(b)
	if err != nil {
		return err
	}
	if now != given {
		return planChanged(now, given)
	}
	if len(b.Blocked) > 0 {
		return refuseBlocked(b)
	}
	return nil
}

// boundDigest is the digest of the plan b: of its canonical bytes.
func boundDigest(b plan.Bound) (string, error) {
	c, err := plan.Canonical(b)
	if err != nil {
		return "", err
	}
	return plan.DigestOf(c), nil
}

// printPlan is --plan's output: the document in JSON, the rendering in human
// mode. now is the command's own clock, for generated_at. A blocked plan is
// printed too, and is not an error: --plan exits 0 (A23-7).
func printPlan(env *Env, b plan.Bound, now time.Time) error {
	r, err := newPlanResult(env, b, now)
	if err != nil {
		return err
	}
	return env.Printer.Print(r)
}

// newPlanResult is b printed at now, with the line that confirms it.
func newPlanResult(env *Env, b plan.Bound, now time.Time) (planResult, error) {
	doc, err := plan.NewDocument(b, now)
	if err != nil {
		return planResult{}, err
	}
	return planResult{Document: doc, typed: b, confirm: confirmLine(env, doc.Digest)}, nil
}

// printNotices prints the plan's notices in an interactive, --yes or
// --confirm run (A23-26): once each, in the command's own words, on stderr,
// before the prompt or, under --confirm, right after the comparison. Under
// --plan they are facts and nothing prints them but the plan.
func printNotices(w io.Writer, b plan.Bound) {
	for _, f := range b.Facts {
		if n, ok := factValue(f).(plan.NoticeFact); ok {
			fprintln(w, n.Text)
		}
	}
}

// confirmLine is the rendering's last line: the command line that confirms
// the plan whose digest is digest (design §9.6, A23-17). It is the command
// line the plan was printed for, with every token that sets --plan or
// --confirm dropped, then --confirm <digest>; so the deploy plan that
// 'run --confirm <fetch digest>' prints carries its own digest only.
//
// The tokens are read as the router read them: the global flags up to the
// command name are kept as they were, and after it each token is classified
// by the command's own flag set, so a value-taking flag's value is never read
// as a flag (--source --plan sets source), and the one token after a bare --
// is an operand (-- --plan). With no command line (a test that calls Run
// directly), or a token that would not print as itself, it is the fallback,
// which names no argument.
func confirmLine(env *Env, digest string) string {
	words, ok := confirmWords(env.Argv, env.Flags)
	if !ok {
		return "To do exactly this: run the same command with --confirm " + digest
	}
	quoted := make([]string, 0, len(words)+3)
	quoted = append(quoted, "farcast")
	for _, w := range words {
		quoted = append(quoted, shellWord(w))
	}
	quoted = append(quoted, "--confirm", digest)
	return "To do exactly this: " + strings.Join(quoted, " ")
}

// confirmWords is argv with every token that sets plan or confirm dropped,
// classified by fs as the router's parse classifies it; false when it cannot
// be rebuilt.
func confirmWords(argv []string, fs *flag.FlagSet) ([]string, bool) {
	if argv == nil || fs == nil {
		return nil, false
	}
	for _, a := range argv {
		if !output.Printable(a) {
			return nil, false
		}
	}

	// The global flags before the command name, parsed as run parses them.
	var opts globalOpts
	gfs := flag.NewFlagSet("farcast", flag.ContinueOnError)
	gfs.SetOutput(io.Discard)
	opts.registerRoot(gfs)
	if err := gfs.Parse(argv); err != nil {
		return nil, false
	}
	rest := gfs.Args()
	if len(rest) == 0 {
		return nil, false
	}
	at := len(argv) - len(rest)
	words := append([]string(nil), argv[:at+1]...)

	for i := at + 1; i < len(argv); {
		t := argv[i]
		if t == "--" {
			// parseInterspersed: the flag package stops at --, the next token
			// is an operand, and parsing resumes after it. A -- with nothing
			// after it changes nothing, and is dropped so it cannot make the
			// appended --confirm an operand.
			if i+1 < len(argv) {
				words = append(words, t, argv[i+1])
			}
			i += 2
			continue
		}
		if len(t) < 2 || t[0] != '-' {
			words = append(words, t)
			i++
			continue
		}
		name := strings.TrimPrefix(t[1:], "-")
		if name == "" || name[0] == '-' || name[0] == '=' {
			return nil, false
		}
		hasValue := false
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name, hasValue = name[:eq], true
		}
		f := fs.Lookup(name)
		if f == nil {
			return nil, false
		}
		takesNext := !hasValue && !isBoolFlag(f)
		if takesNext && i+1 >= len(argv) {
			return nil, false
		}
		if name != "plan" && name != "confirm" {
			words = append(words, t)
			if takesNext {
				words = append(words, argv[i+1])
			}
		}
		i++
		if takesNext {
			i++
		}
	}
	return words, true
}

// isBoolFlag is the flag package's own test of a flag that takes no value
// after it.
func isBoolFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// shellSafe is a word every POSIX shell, and zsh, reads as itself, unquoted.
// An = may not begin it: zsh, macOS's default shell, reads an unquoted word
// that begins with = as the path of the command it names (its EQUALS
// option, on by default), so `--config =ls` would run with /bin/ls.
var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_@%+:,./-][A-Za-z0-9_@%+=:,./-]*$`)

// shellWord is s as a POSIX shell word: bare when it is safe, single-quoted
// otherwise, with each single quote written as a closing quote, an
// escaped quote, and an opening quote.
func shellWord(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
