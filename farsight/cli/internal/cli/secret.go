package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/storage"
)

// `farcast secret` — the values an application must not carry in its image.
//
// A secret is an ordinary object in the instance's encrypted storage, written
// from this machine with the operator's own keys, under the reserved subtree
// <scope>/secrets/<app>/. It is encrypted before the cloud sees it, stored
// under an opaque name, and it never exists as a Kubernetes Secret — which is
// base64 in etcd, encrypted at rest under a key the cloud provider holds.
//
// What that buys is set out in ADR 0018, which moved the boundary from the
// instance to the APPLICATION: each one has its own scope under
// app/<namespace>/<app>/, so a neighbour's keys cannot compute the stored name
// of this secret and its leaf does not reach the scope to ask. The keyholder
// also refuses application writes and deletes under the subtree, so a secret
// is created and removed here and nowhere else — including by the application
// it belongs to.
//
// Like `farcast storage`, this runs entirely on the operator's machine and
// needs no tunnel and no running cluster.

// maxSecretBytes bounds what this command will store as a secret.
//
// It is deliberately small. A secret is a credential an application holds in
// memory; something larger is a file, and files belong in `farcast storage`
// where they stream. The cap also makes an accidental `farcast secret set …
// --from-file ./backup.tar` fail loudly instead of silently succeeding.
const maxSecretBytes = 64 << 10

func newSecretCommand() Command {
	subs := NewRegistry()
	subs.Register(&secretSetCommand{})
	subs.Register(&secretLsCommand{})
	subs.Register(&secretRmCommand{})
	return &group{
		name:     "secret",
		synopsis: "Application secrets, encrypted at rest in the instance's storage (set, ls, rm)",
		subs:     subs,
		usage: `
Usage: farcast secret <set|ls|rm> [flags] [arguments]

Provision the values an application must not carry in its image: database
passwords, API tokens, signing keys. An application reads them through the SDK
with farcast.Secrets(); it cannot write or delete one.

Each secret is an object in the instance's encrypted storage, written from
this machine with this instance's keys. The cloud provider holds ciphertext
under an opaque name, and nothing is ever placed in a Kubernetes Secret.

Subcommands:
  set   Store a secret, reading the value from stdin
  ls    List secret names (never values)
  rm    Delete a secret

There is no 'get'. Reading a secret back to a terminal puts it in scrollback,
in a screen share, and in whatever captured the session; the application is
what reads secrets. This is a guard rail rather than a lock — the keyring is
yours, so 'farcast storage cp' can always recover the bytes if you truly need
them, deliberately and with the key in hand.

Each application has its own scope — its own keys, under app/<namespace>/<app>/
— so a neighbour cannot compute the stored name of this secret, let alone open
it. Name an application as <namespace>/<application>: the same manifest
deployed twice is two applications with two sets of keys.`,
	}
}

// appRef is an application named the way a secret's key already names it:
// the deployment namespace it was deployed into, and its own name.
//
// Both halves are required because both are real. The same manifest deployed
// into two namespaces is two sets of applications with two sets of scopes, and
// a secret set for one is not a secret for the other — so a command that took
// only the application name would be guessing which one an operator meant.
type appRef struct{ Namespace, App string }

func (a appRef) String() string { return a.Namespace + "/" + a.App }

// parseAppRef reads a <namespace>/<application> operand.
func parseAppRef(operand string) (appRef, error) {
	ns, app, ok := strings.Cut(operand, "/")
	if !ok {
		return appRef{}, usagef("name the application as <namespace>/<application> (for example %q), not %q",
			"my-platform/api", operand)
	}
	if err := validateAppName(ns); err != nil {
		return appRef{}, err
	}
	if err := validateAppName(app); err != nil {
		return appRef{}, err
	}
	return appRef{Namespace: ns, App: app}, nil
}

// appScope resolves one application's slice of the instance's storage.
//
// The scope is the boundary, so this is also the check that the application
// exists: a scope is minted when `farcast run` deploys it, and a secret set
// for an application that was never deployed would sit under keys nothing
// holds — readable by the operator, invisible to everyone else, and silently
// wrong at exactly the moment somebody relied on it.
func appScope(session *storage.Session, ref appRef) (datasphere.Scope, error) {
	name, err := datasphere.AppScopeName(ref.Namespace, ref.App)
	if err != nil {
		return datasphere.Scope{}, err
	}
	scope, ok := session.Keyring.ScopeNamed(name)
	if !ok {
		return datasphere.Scope{}, fmt.Errorf(
			"instance %q has no storage scope for %s, so it has nowhere to keep a secret.\n"+
				"A scope is minted when the application is deployed: run 'farcast run %s <repository>' first.",
			session.Instance, ref, session.Instance)
	}
	return scope, nil
}

// secretKey builds the object key for one application's named secret.
//
// The application is named by the scope the key is already inside, so the path
// carries no second copy of it. When every application shared one scope the
// name had to be in the path, because the path was the only thing telling one
// application's secrets from another's.
func secretKey(scope datasphere.Scope, name string) (string, error) {
	if err := datasphere.ValidateSecretName(name); err != nil {
		return "", err
	}
	return scope.Prefix + datasphere.SecretsSegment + datasphere.ScopePrefixSuffix + name, nil
}

// validateAppName holds a namespace or application operand to the manifest's
// own rule, since that is what was deployed. A secret filed under a name no
// application can have is one nothing will ever read.
func validateAppName(app string) error {
	if app == "" {
		return usagef("an application name is required")
	}
	if len(app) > 63 || app[0] < 'a' || app[0] > 'z' {
		return usagef("%q is not an application name (lowercase letters, digits and dashes, starting with a letter)", app)
	}
	for i := 0; i < len(app); i++ {
		c := app[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return usagef("%q is not an application name (lowercase letters, digits and dashes, starting with a letter)", app)
		}
	}
	if app[len(app)-1] == '-' {
		return usagef("%q is not an application name (it must not end with a dash)", app)
	}
	return nil
}

// openSecrets is the preamble every subcommand shares. A verb that writes
// mints the keyring if there is not one yet, exactly as `storage cp` does; a
// verb that only reads never brings key material into existence as a side
// effect of listing.
func openSecrets(ctx context.Context, env *Env, instance string, mint bool) (*storage.Session, error) {
	if _, err := env.ConfigDir.LoadInstanceMetadata(instance); err != nil {
		return nil, fmt.Errorf("load instance %q: %w", instance, err)
	}
	return openSession(ctx, env, instance, mint)
}

// ------------------------------------------------------------------ set

type secretSetCommand struct {
	fromFile string
	raw      bool
	force    bool
}

func (*secretSetCommand) Name() string     { return "set" }
func (*secretSetCommand) Synopsis() string { return "Store a secret, reading the value from stdin" }

func (*secretSetCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast secret set <instance> <namespace>/<app> <NAME> [flags]

Store a secret for one application. The value is read from stdin, or from a
file with --from-file:

  printf '%s' "$PASSWORD" | farcast secret set prod my-platform/api DB_PASSWORD
  farcast secret set prod my-platform/api TLS_KEY --from-file ./key.pem

There is no --value flag on purpose. A value on the command line is visible to
every process on the machine while the command runs, and it lands in shell
history.

Flags:
      --from-file PATH   Read the value from a file instead of stdin
      --raw              Keep a trailing newline (by default one is removed)
      --force            Replace a secret that already exists

A trailing newline is the shell's, not yours: 'echo x |' appends one and it
would become part of the credential. One is removed and the removal is
reported; --raw keeps it.

The name may use letters, digits, '_', '-' and '.', up to 128 bytes. It is
appended to the application's own prefix, so it carries no path separators.

The application's scope is minted when 'farcast run' deploys it, so a secret
for an application that was never deployed is refused rather than stored
somewhere nothing will look.`)
}

func (c *secretSetCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.fromFile, "from-file", "", "read the value from a file instead of stdin")
	fs.BoolVar(&c.raw, "raw", false, "keep a trailing newline")
	fs.BoolVar(&c.force, "force", false, "replace a secret that already exists")
}

func (c *secretSetCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 3 {
		return usagef("secret set takes an instance, a <namespace>/<application> and a name")
	}
	instance, name := args[0], args[2]
	ref, err := parseAppRef(args[1])
	if err != nil {
		return err
	}

	value, trimmed, err := c.read(env)
	if err != nil {
		return err
	}
	if len(value) == 0 {
		// An empty secret is indistinguishable from a mistake, and the SDK
		// has no way to report "set, but to nothing". Refuse here, where the
		// operator can see why.
		return fmt.Errorf("refusing to store an empty value for %q; to remove a secret use 'farcast secret rm'", name)
	}

	session, err := openSecrets(ctx, env, instance, true)
	if err != nil {
		return err
	}
	scope, err := appScope(session, ref)
	if err != nil {
		return err
	}
	key, err := secretKey(scope, name)
	if err != nil {
		return err
	}
	exists, err := objectExists(ctx, session, key)
	if err != nil {
		return err
	}
	if exists && !c.force {
		return usagef("%s already has a secret named %q; pass --force to replace it", ref, name)
	}
	store, err := session.StoreFor(key)
	if err != nil {
		return err
	}
	if err := store.Write(ctx, key, value); err != nil {
		return fmt.Errorf("store the secret: %w", err)
	}
	return env.Printer.Print(secretSetResult{
		Instance: instance, App: ref.String(), Name: name, Bytes: len(value),
		Replaced: exists, TrimmedNewline: trimmed,
	})
}

// read collects the value, from a file or from stdin, and never from argv.
func (c *secretSetCommand) read(env *Env) (value []byte, trimmed bool, err error) {
	src := env.In
	if c.fromFile != "" {
		f, ferr := os.Open(c.fromFile)
		if ferr != nil {
			return nil, false, ferr
		}
		defer func() { _ = f.Close() }()
		src = f
	} else if env.Printer.Mode == output.ModeHuman && isTerminal(env.In) {
		// Without this the command sits there looking hung while the operator
		// waits for a prompt that was never coming.
		fprintln(env.Err, "Reading the secret from stdin; end with Ctrl-D (or pass --from-file).")
	}
	// One byte over the cap is read so the cap can be reported as exceeded
	// rather than silently truncating the value — a truncated credential is
	// the worst of both outcomes.
	value, err = io.ReadAll(io.LimitReader(src, maxSecretBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(value) > maxSecretBytes {
		return nil, false, fmt.Errorf("a secret must be at most %d bytes; something this large is a file, and files belong in 'farcast storage cp'", maxSecretBytes)
	}
	if !c.raw && len(value) > 0 && value[len(value)-1] == '\n' {
		return value[:len(value)-1], true, nil
	}
	return value, false, nil
}

type secretSetResult struct {
	Instance       string `json:"instance"`
	App            string `json:"app"`
	Name           string `json:"name"`
	Bytes          int    `json:"bytes"`
	Replaced       bool   `json:"replaced"`
	TrimmedNewline bool   `json:"trimmed_newline"`
}

func (r secretSetResult) Human(w io.Writer) error {
	verb := "stored"
	if r.Replaced {
		verb = "replaced"
	}
	fprintf(w, "✓ %s %s for %s (%d bytes, encrypted before the cloud saw it)\n", verb, r.Name, r.App, r.Bytes)
	if r.TrimmedNewline {
		fprintln(w, "  A trailing newline was removed; pass --raw to keep one.")
	}
	// Not "on its next start": the SDK holds no cache, so a running
	// application picks this up on its next read. Saying otherwise sent an
	// operator to restart a workload that did not need restarting — and, worse,
	// implied a rotation would NOT take effect until one, which is the sort of
	// thing somebody relies on while revoking a credential.
	fprintf(w, "  %s picks it up on its next read of farcast.Secrets().Get(ctx, %q) — no restart needed.\n", r.App, r.Name)
	return nil
}

// ------------------------------------------------------------------- ls

type secretLsCommand struct{}

func (*secretLsCommand) Name() string     { return "ls" }
func (*secretLsCommand) Synopsis() string { return "List secret names (never values)" }

func (*secretLsCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast secret ls <instance> [<namespace>/<app>]

List which secrets exist, for one application or for all of them. Names only:
this command never reads a value, and never decrypts one.`)
}

func (*secretLsCommand) SetFlags(*flag.FlagSet) {}

func (*secretLsCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) == 0 || len(args) > 2 {
		return usagef("secret ls takes an instance and an optional <namespace>/<application>")
	}
	instance := args[0]
	session, err := openSecrets(ctx, env, instance, false)
	if err != nil {
		return err
	}

	// Every application scope, or the one named. There is no longer a single
	// subtree holding every application's secrets — each one's are inside its
	// own scope, under its own keys — so a listing asks each scope in turn.
	scopes := session.Keyring.Scopes()
	if len(args) == 2 {
		ref, err := parseAppRef(args[1])
		if err != nil {
			return err
		}
		scope, err := appScope(session, ref)
		if err != nil {
			return err
		}
		scopes = []datasphere.Scope{scope}
	}

	entries := make([]secretEntry, 0)
	for _, scope := range scopes {
		ns, app, ok := datasphere.ParseAppScopePrefix(scope.Prefix)
		if !ok {
			// Not an application scope. Skipped rather than reported: it is
			// somebody else's key space, and this command speaks about
			// applications.
			continue
		}
		prefix := scope.Prefix + datasphere.SecretsSegment + datasphere.ScopePrefixSuffix
		store, serr := session.StoreFor(prefix)
		if serr != nil {
			return serr
		}
		keys, lerr := store.List(ctx, prefix)
		if lerr != nil {
			return fmt.Errorf("list %s's secrets: %w", appRef{ns, app}, lerr)
		}
		for _, key := range keys {
			entries = append(entries, secretEntry{App: appRef{ns, app}.String(), Name: strings.TrimPrefix(key, prefix)})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].App != entries[j].App {
			return entries[i].App < entries[j].App
		}
		return entries[i].Name < entries[j].Name
	})
	return env.Printer.Print(secretLsResult{Instance: instance, Secrets: entries})
}

type secretEntry struct {
	App  string `json:"app"`
	Name string `json:"name"`
}

type secretLsResult struct {
	Instance string        `json:"instance"`
	Secrets  []secretEntry `json:"secrets"`
}

func (r secretLsResult) Human(w io.Writer) error {
	if len(r.Secrets) == 0 {
		fprintln(w, "no secrets")
		return nil
	}
	for _, s := range r.Secrets {
		fprintf(w, "  %-28s %s\n", s.App, s.Name)
	}
	fprintf(w, "\n%d secret(s). Values are never printed by this command.\n", len(r.Secrets))
	return nil
}

// ------------------------------------------------------------------- rm

type secretRmCommand struct{ assumeYes bool }

func (*secretRmCommand) Name() string     { return "rm" }
func (*secretRmCommand) Synopsis() string { return "Delete a secret" }

func (*secretRmCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast secret rm <instance> <namespace>/<app> <NAME> [-y]

Delete a secret. The delete is immediate and final — soft delete is disabled
on the bucket by design — and an application that requires this secret will
fail to start after its next restart.

Flags:
  -y, --yes   Skip the confirmation (required when non-interactive)`)
}

func (c *secretRmCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation")
}

func (c *secretRmCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 3 {
		return usagef("secret rm takes an instance, a <namespace>/<application> and a name")
	}
	instance, name := args[0], args[2]
	ref, err := parseAppRef(args[1])
	if err != nil {
		return err
	}
	session, err := openSecrets(ctx, env, instance, false)
	if err != nil {
		return err
	}
	scope, err := appScope(session, ref)
	if err != nil {
		return err
	}
	key, err := secretKey(scope, name)
	if err != nil {
		return err
	}
	exists, err := objectExists(ctx, session, key)
	if err != nil {
		return err
	}
	if !exists {
		// Reported, not silently successful: an operator who mistyped the
		// name would otherwise believe they had revoked a credential that is
		// still live.
		return fmt.Errorf("%s has no secret named %q", ref, name)
	}
	if !c.assumeYes {
		interactive := env.Printer.Mode == output.ModeHuman && isTerminal(env.In)
		if !interactive {
			return usagef("refusing to delete %s's %q without confirmation; pass --yes", ref, name)
		}
		fprintf(env.Err, "Deleting %s's %q is immediate and final, and it will fail to start without it.\n", ref, name)
		answer, perr := newPrompter(env.In, env.Err).line(fmt.Sprintf("Type the secret's name to confirm (%s)", name))
		if perr != nil {
			return perr
		}
		if strings.TrimSpace(answer) != name {
			fprintln(env.Err, "Aborted.")
			return nil
		}
	}
	store, err := session.StoreFor(key)
	if err != nil {
		return err
	}
	if err := store.Delete(ctx, key); err != nil {
		return fmt.Errorf("delete the secret: %w", err)
	}
	return env.Printer.Print(secretRmResult{Instance: instance, App: ref.String(), Name: name, Status: "deleted"})
}

type secretRmResult struct {
	Instance string `json:"instance"`
	App      string `json:"app"`
	Name     string `json:"name"`
	Status   string `json:"status"`
}

func (r secretRmResult) Human(w io.Writer) error {
	fprintf(w, "✓ deleted %s's %q — immediate and final\n", r.App, r.Name)
	return nil
}
