package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	pbuild "github.com/sofmon/farcast/planck/build"
	pfetch "github.com/sofmon/farcast/planck/fetch"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// farcast git-credential set and rm (ADR 0023 M2.8, design §9.8 as §33's
// A33-29 to A33-33 amend it): the Git credential the fetch and build Jobs
// read for a private repository, written into the cluster and deleted
// through a plan, so a private repository needs no kubectl. It is newly
// automated, so --yes never covers it.

// gitCredentialNamespace is where a Git credential goes: where the fetch and
// build Jobs run and resolve their secretKeyRef. There is no --namespace.
const gitCredentialNamespace = pfetch.Namespace

// The two labels a Git credential carries, by which set and rm tell one
// farcast wrote from any other Secret.
const (
	gitCredentialManagedBy = "app.kubernetes.io/managed-by"
	gitCredentialComponent = "app.kubernetes.io/component"
	gitCredentialLabel     = "git-credential"
)

// The token's bounds (A33-30): 1 to maxGitToken bytes once one trailing
// newline is trimmed, read up to maxGitTokenRead bytes, one more than the
// longest token followed by \r\n (two bytes), so a longer file is refused,
// not cut.
const (
	maxGitToken     = 4096
	maxGitTokenRead = maxGitToken + 2 + 1
	maxGitUsername  = 256
)

// The texts of design §33, A33-29 to A33-31. None carries the username, the
// token or a byte count of either, but the set prompt, which shows the
// username (A33-30).
const (
	// msgGitCredentialYes is the --yes refusal: the action, the action
	// again, and the instance, or <instance> for a name that is not one.
	msgGitCredentialYes = "git-credential %s cannot be run with --yes: it writes a credential every build and fetch can read; " +
		"confirm it in a terminal, or review 'farcast git-credential %s %s --plan' and pass --confirm <digest>"
	msgGitCredentialTerminal = "git-credential needs a terminal to confirm" + consentSuffix
	// msgGitCredentialStdinTerminal refuses --token-file - where stdin is a
	// terminal, in a mode that reads the token: it would be read with echo
	// on (A33-30 step 5).
	msgGitCredentialStdinTerminal = "--token-file - reads the token from stdin, which is a terminal here; give a file, " +
		"or pipe the token: --plan first, then --confirm <digest> with the token on stdin"
	// msgGitCredentialTokenDevice refuses a --token-file path that names a
	// character device, such as a terminal (/dev/tty, or /dev/stdin from
	// one), in a mode that reads the token: it would be read with echo on, as
	// --token-file - would (A33-30 step 5's reason).
	msgGitCredentialTokenDevice = "--token-file names a device, such as a terminal, which would show the token as it is typed; give a file, " +
		"or pipe the token: --plan first, then --confirm <digest> with the token on stdin"
	msgGitCredentialName     = "--name %q is not a Secret name (a DNS-1123 subdomain: lowercase letters, digits, '-' and '.', at most 253 characters)"
	msgGitCredentialReserved = "%s/%s is a Secret FarCast renders, not a Git credential; choose another --name"
	msgGitCredentialUsername = "--username must be 1 to 256 printable bytes with no whitespace; nothing was read or written"
	msgGitCredentialNoFile   = "git-credential set reads the token from --token-file, a file or - for stdin, and never from argv; give --token-file"
	msgGitCredentialToken    = "the token read from --token-file is empty, longer than 4096 bytes, or holds a control byte; nothing was written"
	// The questions: the namespace, the name, then for set the username
	// (terminalText), and the instance.
	msgGitCredentialSetPrompt = "Write the Git credential %s/%s (user %s) into %q's cluster? Every build and fetch that names it with --git-secret can read it, " +
		"and so can the cloud provider, for as long as it exists."
	msgGitCredentialRmPrompt = "Delete the Git credential %s/%s from %q's cluster?"
	// rm's answers (A33-31), each the namespace and the name.
	msgGitCredentialNotThere = "%s/%s was not there"
	msgGitCredentialReplaced = "%s/%s was replaced between its read and its delete; nothing was deleted; run it again"
	// The label refusals (A33-31), internal.
	msgGitCredentialSetForeign = "%s/%s exists and is not a Git credential farcast wrote; nothing was written; choose another --name, or delete it from Cloud Shell"
	msgGitCredentialRmForeign  = "%s/%s is not a Git credential farcast wrote; nothing was deleted; choose another --name, or delete it from Cloud Shell"
)

// The Secrets FarCast's renderers write, which a Git credential may not be
// named (A33-29): FatLine's and the keyholder's mTLS material, and every
// application's egress credential, <app>-egress.
// TestGitCredentialRefusesEveryRenderedSecretName derives the names from the
// renderers, so one a renderer adds and this list lacks fails it.
var (
	gitCredentialReservedNames  = []string{"fatline-mtls", "datasphered-mtls"}
	gitCredentialReservedSuffix = "-egress"
)

// secretNameShape is a DNS-1123 subdomain, the shape of a Secret's name:
// dot-separated labels of lowercase letters, digits and '-', each beginning
// and ending with a letter or a digit; its length, at most 253, is checked
// apart.
var secretNameShape = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// gitCredentialCluster is what git-credential needs of the instance's
// writer (A33-31, A33-39): the Secret's metadata, set's apply, and rm's
// uid-preconditioned delete.
type gitCredentialCluster interface {
	GetMeta(ctx context.Context, k kube.Kind, namespace, name string) (kube.Object, error)
	Apply(ctx context.Context, manifests []byte) error
	DeleteSecret(ctx context.Context, namespace, name, uid string) error
}

// The cluster client is git-credential's writer by default.
var _ gitCredentialCluster = (*cluster.Client)(nil)

// gitCredentialWriterDefault is gitCredentialCommand.newCluster's default:
// the instance's writer (openWriter), the installer's stored service-account
// key. Opening it sends nothing. A variable, so the package's tests reach no
// cluster through it but one they started (refusingdefaults_test.go).
var gitCredentialWriterDefault = func(r clusterRef) (gitCredentialCluster, error) {
	// A refusal returns a nil writer, never a nil *cluster.Client inside a
	// non-nil one.
	cl, err := openWriter(r)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// newGitCredentialCommand builds the `farcast git-credential` group.
func newGitCredentialCommand() Command {
	subs := NewRegistry()
	subs.Register(&gitCredentialCommand{action: plan.GitCredentialSet})
	subs.Register(&gitCredentialCommand{action: plan.GitCredentialRm})
	return &group{
		name:     "git-credential",
		synopsis: "A private repository's Git credential in the cluster (set, rm)",
		subs:     subs,
		usage: `
Usage: farcast git-credential <set|rm> <instance> --name <secret> [flags]

The Git credential the instance's fetch and build Jobs read when 'farcast
run' or 'farcast build' names it with --git-secret <secret>: one Kubernetes
Secret in farcast-system, holding a username and a token.

  farcast git-credential set <instance> --name <secret> --username <user> --token-file <path|->
      writes it
  farcast git-credential rm <instance> --name <secret>
      deletes it, if farcast wrote it

Subcommands:
  set  Write a Git credential into the cluster
  rm   Delete a Git credential farcast wrote

It is a Kubernetes Secret, not DataSphere storage ('farcast secret'): the
cloud provider can read it for as long as it exists. Give it a token scoped
to the one repository, read-only. The token is never taken from argv. A plan
names the Secret by its namespace and name only. Each asks in a terminal, or
takes --plan and then --confirm <digest>; --yes is refused.`,
	}
}

// gitCredentialCommand is `git-credential set` or `git-credential rm`, by
// action (design §33, A33-29). Both are newly automated, so --yes never
// covers either: each asks in a terminal, or takes --plan and then
// --confirm <digest>. Its plan reads the record alone (cluster_identity
// none); the writer, opened after consent, reads the Secret's metadata, and
// set applies it while rm deletes it on the uid it read.
type gitCredentialCommand struct {
	action string // plan.GitCredentialSet or plan.GitCredentialRm

	name      string
	username  string // set only; never bound, never in a plan
	tokenFile string // set only; never bound, never in a plan
	yes       bool
	consent   consentFlags

	newCluster  func(clusterRef) (gitCredentialCluster, error) // default: gitCredentialWriterDefault
	interactive func(*Env) bool                                // default: isInteractive
	// readToken reads --token-file's bytes, at most maxGitTokenRead of them:
	// the file, or env.In for -. It is called once, only after consent and
	// after the Secret's read (A33-30 step 12), in a goroutine of its own
	// that Run stops waiting for when its context is done.
	readToken func(env *Env, path string) ([]byte, error) // default: readGitToken
	now       func() time.Time                            // default: time.Now
}

func (c *gitCredentialCommand) Name() string { return c.action }

func (c *gitCredentialCommand) Synopsis() string {
	if c.action == plan.GitCredentialRm {
		return "Delete a Git credential farcast wrote"
	}
	return "Write a Git credential into the cluster"
}

func (c *gitCredentialCommand) Usage() string {
	if c.action == plan.GitCredentialRm {
		return strings.TrimSpace(`
Usage: farcast git-credential rm <instance> --name <secret> [--plan | --confirm <digest>]

Delete the Git credential farcast-system/<secret> that 'farcast
git-credential set' wrote.

After consent it reads the Secret's metadata, and refuses one that does not
carry farcast's two labels for a Git credential
(app.kubernetes.io/managed-by: farcast and app.kubernetes.io/component:
git-credential), deleting nothing. It deletes on the uid it read, so a Secret
replaced since that read is not deleted, and is said to be. A Secret that is
not there is no error.

In a terminal it asks first. --yes is refused. --plan prints the delete and
reads nothing; --confirm <digest> does exactly that plan, asking nothing. The
delete runs in-process as the installer service account (the key 'farcast
install --credentials' stored).`)
	}
	return strings.TrimSpace(`
Usage: farcast git-credential set <instance> --name <secret> --username <user> --token-file <path|-> [--plan | --confirm <digest>]

Write a Git credential into the instance's cluster: the Secret
farcast-system/<secret>, holding the username and the token under the keys
username and token, which the fetch and build Jobs read when 'farcast run' or
'farcast build' names it with --git-secret <secret>.

It is a Kubernetes Secret, not DataSphere storage ('farcast secret'): the
cloud provider can read it for as long as it exists. Give it a token scoped
to the one repository, read-only, and delete it with 'farcast git-credential
rm' when it is no longer needed.

The token is never taken from argv: --token-file names a file, or - for
stdin, and it is read only after consent. One trailing newline, \n or \r\n,
is removed, and the result says so; the token must then be 1 to 4096 bytes
with no control byte. The username is not a credential: it is on argv, in
the question and in the confirm line, and nowhere else. A plan names the
Secret by its namespace and name only, and binds neither the username nor
the token, nor any hash of either.

In a terminal it asks first, naming the username. --yes is refused: it
writes a credential every build and fetch can read. --plan prints what it
would write, and reads neither the token nor the cluster. --confirm <digest>
writes exactly that plan, asking nothing, the token read from --token-file.
--token-file - is refused where stdin is a terminal, and so is a
--token-file that names a character device, such as a terminal, but under
--plan: pipe the token to the --confirm run instead.

After consent it reads the Secret's metadata, and writes only over a Secret
that carries farcast's two labels for a Git credential
(app.kubernetes.io/managed-by: farcast and app.kubernetes.io/component:
git-credential), or none at all. The read and the apply are two calls: a
Secret another writer puts there between them is written over. The apply is
a forced server-side apply, in-process as the installer service account (the
key 'farcast install --credentials' stored).`)
}

func (c *gitCredentialCommand) SetFlags(fs *flag.FlagSet) {
	const yesUsage = "refused: git-credential changes a credential every build and fetch can read, so it asks in a terminal, or takes --plan and then --confirm <digest>"
	fs.StringVar(&c.name, "name", "", "the Secret's name, in farcast-system")
	if c.action == plan.GitCredentialSet {
		fs.StringVar(&c.username, "username", "", "the Git username the token goes with")
		fs.StringVar(&c.tokenFile, "token-file", "", "the file the token is read from after consent, or - for stdin; never argv")
	}
	fs.BoolVar(&c.yes, "yes", false, yesUsage)
	fs.BoolVar(&c.yes, "y", false, yesUsage)
	c.consent.register(fs)
}

func (c *gitCredentialCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = gitCredentialWriterDefault
	}
	if c.interactive == nil {
		c.interactive = isInteractive
	}
	if c.readToken == nil {
		c.readToken = readGitToken
	}
	if c.now == nil {
		c.now = time.Now
	}
}

// readGitToken is readToken's default: at most maxGitTokenRead bytes of the
// file path, or of stdin for -. A path that opens a device, such as a
// terminal, is refused before a byte is read, so a path swapped for one
// after step 5's check still shows nothing as it is typed. The path is
// opened with O_NOCTTY, so a run that leads its own session with no
// controlling terminal, as one started by setsid or launchd, does not take
// the terminal it then refuses as its own; Windows ignores the flag. An
// error names the path, and never a byte read.
func readGitToken(env *Env, path string) ([]byte, error) {
	src := env.In
	if path != "-" {
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOCTTY, 0)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		if isTerminal(f) {
			return nil, fmt.Errorf("%s is a device, such as a terminal, which would show the token as it is typed", path)
		}
		src = f
	}
	return io.ReadAll(io.LimitReader(src, maxGitTokenRead))
}

// namesADevice says path, followed through any symbolic link, is a device,
// such as a terminal, as isTerminal tests a file it opened: a character
// device. A path that cannot be examined is not one here; its read refuses
// it, after consent.
func namesADevice(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// tokenRead is one read of the token, as readToken answered it.
type tokenRead struct {
	raw []byte
	err error
}

// readTokenUnlessCancelled is readToken, given up when ctx is done: a
// --token-file that is a FIFO no writer opens, or a pipe that never closes,
// would otherwise keep the command waiting after an interrupt cancelled
// ctx. The read goes on in its goroutine, and its answer is dropped.
func (c *gitCredentialCommand) readTokenUnlessCancelled(ctx context.Context, env *Env) ([]byte, error) {
	got := make(chan tokenRead, 1)
	go func() {
		raw, err := c.readToken(env, c.tokenFile)
		got <- tokenRead{raw: raw, err: err}
	}()
	select {
	case r := <-got:
		return r.raw, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// gitCredentialResult is what git-credential did: the instance, the action,
// the Secret by its namespace and name, and nothing of the username or the
// token, nor a byte count (A33-30). TrimmedNewline says set removed one
// trailing newline from the token, as secret set reports it; Note is rm's
// msgGitCredentialNotThere when there was nothing to delete, and "" otherwise.
type gitCredentialResult struct {
	Instance       string `json:"instance"`
	Action         string `json:"action"`
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	TrimmedNewline bool   `json:"trimmed_newline"`
	Note           string `json:"note"`
}

func (r gitCredentialResult) Human(w io.Writer) error {
	secret := terminalText(r.Namespace) + "/" + terminalText(r.Name)
	switch {
	case r.Note != "":
		fprintf(w, "✓ %s\n", terminalText(r.Note))
	case r.Action == plan.GitCredentialRm:
		fprintf(w, "✓ deleted the Git credential %s from instance %s's cluster\n", secret, terminalText(r.Instance))
	default:
		fprintf(w, "✓ wrote the Git credential %s into instance %s's cluster\n", secret, terminalText(r.Instance))
		if r.TrimmedNewline {
			fprintln(w, "  A trailing newline was removed from the token.")
		}
	}
	return nil
}

// checkUsage is A33-29's usage checks, before anything is read: the
// argument count, the name's shape, a name FarCast's renderers write, and
// for set both data flags given and the username's shape.
func (c *gitCredentialCommand) checkUsage(args []string) error {
	if len(args) != 1 {
		return usagef("git-credential %s takes one instance name", c.action)
	}
	if len(c.name) > 253 || !secretNameShape.MatchString(c.name) {
		return usagef(msgGitCredentialName, c.name)
	}
	if reservedSecretName(c.name) {
		return usagef(msgGitCredentialReserved, gitCredentialNamespace, c.name)
	}
	if c.action != plan.GitCredentialSet {
		return nil
	}
	if !gitUsernameShape(c.username) {
		return usagef(msgGitCredentialUsername)
	}
	if c.tokenFile == "" {
		return usagef(msgGitCredentialNoFile)
	}
	return nil
}

// reservedSecretName says name is a Secret FarCast's renderers write.
func reservedSecretName(name string) bool {
	for _, r := range gitCredentialReservedNames {
		if name == r {
			return true
		}
	}
	return strings.HasSuffix(name, gitCredentialReservedSuffix)
}

// gitUsernameShape is 1 to 256 printable bytes with no whitespace: ASCII
// from '!' to '~' (A33-30).
func gitUsernameShape(u string) bool {
	if len(u) == 0 || len(u) > maxGitUsername {
		return false
	}
	for i := 0; i < len(u); i++ {
		if u[i] < '!' || u[i] > '~' {
			return false
		}
	}
	return true
}

// gitToken is the token read from raw: one trailing \n or \r\n trimmed, and
// whether one was; ok is false for a token that is empty, longer than
// maxGitToken bytes, or holds a control byte (A33-30).
func gitToken(raw []byte) (token []byte, trimmed, ok bool) {
	token = raw
	switch {
	case bytes.HasSuffix(token, []byte("\r\n")):
		token, trimmed = token[:len(token)-2], true
	case bytes.HasSuffix(token, []byte("\n")):
		token, trimmed = token[:len(token)-1], true
	}
	if len(token) == 0 || len(token) > maxGitToken {
		return nil, trimmed, false
	}
	for _, b := range token {
		if b < 0x20 || b == 0x7f {
			return nil, trimmed, false
		}
	}
	return token, trimmed, true
}

// gitCredentialPlaceholders are the username and the token a plan renders
// its Secret with (A33-29): neither is known, or read, before consent.
func gitCredentialPlaceholders(name string) (username, token []byte) {
	subject := gitCredentialNamespace + "/" + name
	return []byte("farcast-placeholder:git_username:" + subject), []byte("farcast-placeholder:git_token:" + subject)
}

// renderGitCredential is the Git credential's one document (A33-29): a
// data: Secret of type Opaque in farcast-system, its keys the ones the fetch
// and build Jobs read (pfetch's and pbuild's, which are equal), labelled as
// a Git credential farcast wrote. Every value is double-quoted, so a name or
// a base64 value YAML would read as another type stays a string.
func renderGitCredential(name string, username, token []byte) ([]byte, error) {
	if len(name) > 253 || !secretNameShape.MatchString(name) {
		return nil, fmt.Errorf("a Git credential's name %q is not a Secret name; farcast renders nothing from it", name)
	}
	if pfetch.SecretGitUser != pbuild.SecretGitUser || pfetch.SecretGitToken != pbuild.SecretGitToken {
		return nil, errors.New("the fetch and build Jobs read a Git credential under different keys; farcast renders nothing for them")
	}
	enc := base64.StdEncoding.EncodeToString
	return fmt.Appendf(nil, `apiVersion: v1
kind: Secret
metadata:
  name: "%s"
  namespace: "%s"
  labels:
    %s: farcast
    %s: %s
type: Opaque
data:
  %s: "%s"
  %s: "%s"
`, name, gitCredentialNamespace, gitCredentialManagedBy, gitCredentialComponent, gitCredentialLabel,
		pfetch.SecretGitUser, enc(username), pfetch.SecretGitToken, enc(token)), nil
}

// isGitCredential says o carries both labels a Git credential farcast wrote
// carries.
func isGitCredential(o kube.Object) bool {
	l := o.Metadata.Labels
	return l[gitCredentialManagedBy] == "farcast" && l[gitCredentialComponent] == gitCredentialLabel
}

// plan is git-credential's plan (A33-29): it reads the record alone, never
// the cluster, the terminal or the token. Its option is --name; its facts
// are the git_credential fact, then for set the write of its Secret
// rendered from the placeholders, and for rm the delete.
func (c *gitCredentialCommand) plan(meta *config.InstanceMetadata) (plan.Bound, error) {
	b := newBound("git-credential "+c.action, meta, "none", "")
	b.Options = []plan.Option{{Flag: "name", Value: c.name}}
	b.Facts = []plan.Fact{plan.GitCredentialFact{Type: plan.TypeGitCredential, Action: c.action, Namespace: gitCredentialNamespace, Name: c.name}}
	if c.action == plan.GitCredentialRm {
		b.Facts = append(b.Facts, plan.WriteFact{Type: plan.TypeWrite, API: "v1", Kind: "Secret",
			Namespace: gitCredentialNamespace, Name: c.name, Method: plan.WriteDelete})
		return b, nil
	}
	username, token := gitCredentialPlaceholders(c.name)
	stream, err := renderGitCredential(c.name, username, token)
	if err != nil {
		return plan.Bound{}, err
	}
	writes, err := applyFacts(stream)
	if err != nil {
		return plan.Bound{}, err
	}
	b.Facts = append(b.Facts, writes...)
	return b, nil
}

// Run is A33-30's order: the answer; --yes refused; the usage checks; a run
// with no terminal and no answer refused; --token-file - from a terminal, or
// a path that names a character device, refused; the record, then the plan;
// --plan prints it and --confirm compares it; the writer opens, which sends
// nothing; the question; the Secret's read, the first call to the cluster;
// and set's token, read then, and given up if the context is done first.
func (c *gitCredentialCommand) Run(ctx context.Context, env *Env, args []string) (err error) {
	// 1. The answers are counted first, so --yes beside --plan or --confirm
	// is the three-way usage error, not the --yes refusal (A23-16).
	mode, digest, err := c.consent.mode(c.yes)
	if err != nil {
		return err
	}
	// 2.
	if c.yes {
		shown := "<instance>"
		if len(args) == 1 && validateInstanceName(args[0]) == nil {
			shown = args[0]
		}
		return usagef(msgGitCredentialYes, c.action, c.action, shown)
	}
	// 3.
	if err := c.checkUsage(args); err != nil {
		return err
	}
	name := args[0]
	c.ensureDefaults()
	// 4.
	if mode == consentNone && !c.interactive(env) {
		return usagef(msgGitCredentialTerminal)
	}
	// 5. isInteractive is not the test: a --confirm or -o json run whose
	// stdin is a terminal is not interactive, and would read the token from
	// that terminal with echo on. A path that names a character device, such
	// as a terminal (/dev/tty, or /dev/stdin from one, whose symbolic link is
	// followed), would do the same, and is refused here too, and again when
	// it is opened (readGitToken). Under --plan nothing is read, so neither
	// is refused there.
	if c.action == plan.GitCredentialSet && mode != consentPlan {
		if c.tokenFile == "-" && isTerminal(env.In) {
			return usagef(msgGitCredentialStdinTerminal)
		}
		if c.tokenFile != "-" && namesADevice(c.tokenFile) {
			return usagef(msgGitCredentialTokenDevice)
		}
	}

	// 6.
	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("no such instance %q (run 'farcast install' first): %w", name, err)
	}
	if err := recordNamed(meta, name); err != nil {
		return err
	}
	// A 403 the writer met says whose it was, once (A20-9).
	defer func() { err = writerRefused(err, meta) }()

	// 7. and 8.
	b, err := c.plan(meta)
	if err != nil {
		return err
	}
	switch mode {
	case consentPlan:
		return printPlan(env, b, c.now())
	case consentConfirm:
		if err := confirmPlan(b, digest); err != nil {
			return err
		}
	}

	// 9. Opening the writer is local and sends nothing, so an instance this
	// machine cannot write as is refused before anything is asked.
	cl, err := c.newCluster(clusterRef{Dir: env.ConfigDir, Meta: meta, Identity: kube.Writer, Warn: env.Err})
	if err != nil {
		return err
	}

	// 10. --confirm is the consent: the operator read the plan this one is.
	if mode == consentNone {
		question := fmt.Sprintf(msgGitCredentialRmPrompt, gitCredentialNamespace, c.name, name)
		if c.action == plan.GitCredentialSet {
			question = fmt.Sprintf(msgGitCredentialSetPrompt, gitCredentialNamespace, c.name, terminalText(c.username), name)
		}
		ok, err := newPrompter(env.In, env.Err).yesNo(question)
		if err != nil {
			return err
		}
		if !ok {
			fprintln(env.Err, "Aborted.")
			return nil
		}
	}

	// 11.
	secrets, _ := kube.KindOf("v1", "Secret")
	obj, err := cl.GetMeta(ctx, secrets, gitCredentialNamespace, c.name)
	present := true
	switch {
	case errors.Is(err, tkube.ErrNotFound):
		present = false
	case err != nil:
		return fmt.Errorf("read the Secret %s/%s: %w", gitCredentialNamespace, c.name, err)
	}
	result := gitCredentialResult{Instance: name, Action: c.action, Namespace: gitCredentialNamespace, Name: c.name}
	if c.action == plan.GitCredentialRm {
		return c.remove(ctx, env, cl, obj, present, result)
	}

	// 12.
	if present && !isGitCredential(obj) {
		return fmt.Errorf(msgGitCredentialSetForeign, gitCredentialNamespace, c.name)
	}
	raw, err := c.readTokenUnlessCancelled(ctx, env)
	if err != nil {
		return fmt.Errorf("read the token from --token-file: %w; nothing was written", err)
	}
	token, trimmed, ok := gitToken(raw)
	if !ok {
		return errors.New(msgGitCredentialToken)
	}
	stream, err := renderGitCredential(c.name, []byte(c.username), token)
	if err != nil {
		return err
	}
	if err := cl.Apply(ctx, stream); err != nil {
		return fmt.Errorf("apply the Git credential %s/%s: %w", gitCredentialNamespace, c.name, err)
	}
	result.TrimmedNewline = trimmed
	return env.Printer.Print(result)
}

// remove is rm past its read (A33-31): a Secret that is not there, read or
// deleted, is success with msgGitCredentialNotThere; one without both labels
// is refused, internal; and the delete is preconditioned on the uid read, so
// a Secret replaced since is a 409, cluster_rejected, with nothing deleted.
func (c *gitCredentialCommand) remove(ctx context.Context, env *Env, cl gitCredentialCluster, obj kube.Object, present bool, result gitCredentialResult) error {
	notThere := func() error {
		result.Note = fmt.Sprintf(msgGitCredentialNotThere, gitCredentialNamespace, c.name)
		return env.Printer.Print(result)
	}
	if !present {
		return notThere()
	}
	if !isGitCredential(obj) {
		return fmt.Errorf(msgGitCredentialRmForeign, gitCredentialNamespace, c.name)
	}
	err := cl.DeleteSecret(ctx, gitCredentialNamespace, c.name, obj.Metadata.UID)
	switch {
	case errors.Is(err, tkube.ErrNotFound):
		return notThere()
	case errors.Is(err, tkube.ErrConflict):
		return withKind(kindClusterRejected, refuse(tkube.ErrConflict, msgGitCredentialReplaced, gitCredentialNamespace, c.name))
	case err != nil:
		return fmt.Errorf("delete the Secret %s/%s: %w", gitCredentialNamespace, c.name, err)
	}
	return env.Printer.Print(result)
}
