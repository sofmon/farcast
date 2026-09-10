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
	"github.com/sofmon/farcast/farsight/cli/internal/config"
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
// What that buys and what it does not is set out in ADR 0017. The short
// version: the boundary is the INSTANCE. Every application in an instance
// shares one storage scope and the keyholder's data path cannot tell them
// apart, so an application can read its neighbours' secrets. The keyholder
// does refuse application writes and deletes under the subtree, so a secret is
// created and removed here and nowhere else.
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

What this protects against, and what it does not, is ADR 0017. Applications in
one instance share a storage scope, so a secret is confidential from the cloud
and from outside the instance — not from another application inside it.`,
	}
}

// secretsRoot resolves where an instance's secrets live.
//
// It reads the prefix from the KEYRING, because that is the material that
// actually encrypts the object, and cross-checks it against what the deploy
// recorded. A divergence is refused rather than reconciled: applications are
// handed the recorded prefix (Planck renders it into their ConfigMap), so
// writing under the other one would store secrets nothing can read, and there
// is no way to tell from here which of the two is the mistake.
func secretsRoot(session *storage.Session, meta *config.InstanceMetadata) (string, error) {
	scope, ok := session.Keyring.ScopeNamed(datasphere.DefaultScopeName)
	if !ok {
		return "", fmt.Errorf("instance %q has no %q scope in its keyring, so there is nowhere for an application to read a secret from; "+
			"run 'farcast storage deploy %s' to create the keyholder and its scope",
			session.Instance, datasphere.DefaultScopeName, session.Instance)
	}
	root := scope.Prefix + datasphere.SecretsSegment + datasphere.ScopePrefixSuffix
	if meta.Keyholder != nil && meta.Keyholder.ScopePrefix != "" && meta.Keyholder.ScopePrefix != scope.Prefix {
		return "", fmt.Errorf("instance %q records the keyholder serving %q while the keyring's %q scope owns %q; "+
			"applications are given the recorded prefix, so a secret written here would be one nothing can read",
			session.Instance, meta.Keyholder.ScopePrefix, scope.Name, scope.Prefix)
	}
	return root, nil
}

// secretKey builds the object key for one application's named secret.
func secretKey(root, app, name string) (string, error) {
	if err := validateAppName(app); err != nil {
		return "", err
	}
	if err := datasphere.ValidateSecretName(name); err != nil {
		return "", err
	}
	return root + app + datasphere.ScopePrefixSuffix + name, nil
}

// validateAppName holds the app operand to the manifest's own rule for an
// application name, since that is what the deployed ConfigMap will carry. A
// secret filed under a name no application can have is one nothing will ever
// read.
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
	return nil
}

// openSecrets is the preamble every subcommand shares. A verb that writes
// mints the keyring if there is not one yet, exactly as `storage cp` does; a
// verb that only reads never brings key material into existence as a side
// effect of listing.
func openSecrets(ctx context.Context, env *Env, instance string, mint bool) (*storage.Session, string, error) {
	meta, err := env.ConfigDir.LoadInstanceMetadata(instance)
	if err != nil {
		return nil, "", fmt.Errorf("load instance %q: %w", instance, err)
	}
	session, err := openSession(ctx, env, instance, mint)
	if err != nil {
		return nil, "", err
	}
	root, err := secretsRoot(session, meta)
	if err != nil {
		return nil, "", err
	}
	return session, root, nil
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
Usage: farcast secret set <instance> <app> <NAME> [flags]

Store a secret for one application. The value is read from stdin, or from a
file with --from-file:

  printf '%s' "$PASSWORD" | farcast secret set prod api DB_PASSWORD
  farcast secret set prod api TLS_KEY --from-file ./key.pem

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
appended to the application's own prefix, so it carries no path separators.`)
}

func (c *secretSetCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.fromFile, "from-file", "", "read the value from a file instead of stdin")
	fs.BoolVar(&c.raw, "raw", false, "keep a trailing newline")
	fs.BoolVar(&c.force, "force", false, "replace a secret that already exists")
}

func (c *secretSetCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 3 {
		return usagef("secret set takes an instance, an application and a name")
	}
	instance, app, name := args[0], args[1], args[2]

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

	session, root, err := openSecrets(ctx, env, instance, true)
	if err != nil {
		return err
	}
	key, err := secretKey(root, app, name)
	if err != nil {
		return err
	}
	exists, err := objectExists(ctx, session, key)
	if err != nil {
		return err
	}
	if exists && !c.force {
		return usagef("%s already has a secret named %q; pass --force to replace it", app, name)
	}
	store, err := session.StoreFor(key)
	if err != nil {
		return err
	}
	if err := store.Write(ctx, key, value); err != nil {
		return fmt.Errorf("store the secret: %w", err)
	}
	return env.Printer.Print(secretSetResult{
		Instance: instance, App: app, Name: name, Bytes: len(value),
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
Usage: farcast secret ls <instance> [<app>]

List which secrets exist, for one application or for all of them. Names only:
this command never reads a value, and never decrypts one.`)
}

func (*secretLsCommand) SetFlags(*flag.FlagSet) {}

func (*secretLsCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) == 0 || len(args) > 2 {
		return usagef("secret ls takes an instance and an optional application")
	}
	instance := args[0]
	session, root, err := openSecrets(ctx, env, instance, false)
	if err != nil {
		return err
	}
	prefix := root
	if len(args) == 2 {
		if err := validateAppName(args[1]); err != nil {
			return err
		}
		prefix = root + args[1] + datasphere.ScopePrefixSuffix
	}
	store, err := session.StoreFor(prefix)
	if err != nil {
		return err
	}
	keys, err := store.List(ctx, prefix)
	if err != nil {
		return fmt.Errorf("list secrets: %w", err)
	}
	entries := make([]secretEntry, 0, len(keys))
	for _, key := range keys {
		app, name, ok := strings.Cut(strings.TrimPrefix(key, root), datasphere.ScopePrefixSuffix)
		if !ok {
			// A key under the subtree that is not <app>/<name>. It is
			// reported rather than hidden: something wrote it, and an
			// operator who cannot see it cannot remove it.
			entries = append(entries, secretEntry{Name: strings.TrimPrefix(key, root), Unattributed: true})
			continue
		}
		entries = append(entries, secretEntry{App: app, Name: name})
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
	App          string `json:"app,omitempty"`
	Name         string `json:"name"`
	Unattributed bool   `json:"unattributed,omitempty"`
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
		switch {
		case s.Unattributed:
			fprintf(w, "  %-20s %s (not under an application prefix)\n", "?", s.Name)
		default:
			fprintf(w, "  %-20s %s\n", s.App, s.Name)
		}
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
Usage: farcast secret rm <instance> <app> <NAME> [-y]

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
		return usagef("secret rm takes an instance, an application and a name")
	}
	instance, app, name := args[0], args[1], args[2]
	session, root, err := openSecrets(ctx, env, instance, false)
	if err != nil {
		return err
	}
	key, err := secretKey(root, app, name)
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
		return fmt.Errorf("%s has no secret named %q", app, name)
	}
	if !c.assumeYes {
		interactive := env.Printer.Mode == output.ModeHuman && isTerminal(env.In)
		if !interactive {
			return usagef("refusing to delete %s's %q without confirmation; pass --yes", app, name)
		}
		fprintf(env.Err, "Deleting %s's %q is immediate and final, and %s will fail to start without it.\n", app, name, app)
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
	return env.Printer.Print(secretRmResult{Instance: instance, App: app, Name: name, Status: "deleted"})
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
