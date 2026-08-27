package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// `farcast storage key` — the instance's storage keyring.
//
// This is the CLI's only third level, and it earns it because the noun
// changes. ls/cp/rm/usage address objects in a bucket; these verbs address the
// file whose loss is the permanent loss of every one of them. Flattening them
// would seat a keyring verb next to `storage rm` in the same tab-completion
// neighbourhood, and `storage rotate` would read as though it rotated data.

// rotationScopeWarning is what `key rotate` and `key rekey` must say, because
// an operator who believes rotation undoes a compromise has been actively
// misled by a command that looked like it helped.
const rotationScopeWarning = `Rotation is nonce hygiene and keyring retirement, NOT compromise recovery:
  - data and names already stored under a compromised key stay exposed to
    whoever captured the ciphertext; no rotation or sweep recovers that
  - future data is protected once the cloud credentials are rotated too
  - names stay exposed until name-key rotation exists`

func newStorageKeyCommand() Command {
	subs := NewRegistry()
	subs.Register(&keyListCommand{})
	subs.Register(&keyExportCommand{})
	subs.Register(&keyImportCommand{})
	subs.Register(&keyRotateCommand{})
	subs.Register(&keyRekeyCommand{})
	return &group{
		name:     "key",
		synopsis: "Manage the instance's storage keyring",
		subs:     subs,
		usage: `
Usage: farcast storage key <list|export|import|rotate|rekey> <instance> [flags]

The instance's storage keyring lives at <instance>/datasphere/keys.yaml, beside
the data-plane CA key. Losing it is the permanent, unrecoverable loss of every
object in the bucket — FarCast keeps no copy anywhere, by design.

Subcommands:
  list     Show the key ids the keyring holds
  export   Write a passphrase-armored copy
  import   Merge an armored copy into the live keyring
  rotate   Add a new key-encryption key and make it active
  rekey    Rewrite stored objects under the active key-encryption key

The supported backup is the one you already owe the CA key: copy the instance
directory offline. export is for the case that does not cover — moving a
keyring between machines, where the file is in transit through somewhere
neither end controls.`,
	}
}

// keyringOf loads an instance's keyring without touching the cloud. The key
// verbs that do not need a bucket must not require one to be reachable.
func keyringOf(env *Env, instance string) (datasphere.Keyring, error) {
	data, err := env.ConfigDir.LoadInstanceKeyring(instance)
	if err != nil {
		return datasphere.Keyring{}, fmt.Errorf("read the storage keyring for %q: %w\n%s", instance, err, datasphere.KeyLossWarning)
	}
	return datasphere.ParseKeyring(data)
}

func oneInstance(verb string, args []string) (string, error) {
	if len(args) != 1 {
		return "", usagef("storage key %s takes one instance name", verb)
	}
	return strings.TrimSuffix(args[0], ":"), nil
}

// ---------------------------------------------------------------- list

type keyListCommand struct{}

func (*keyListCommand) Name() string     { return "list" }
func (*keyListCommand) Synopsis() string { return "Show the key ids the keyring holds" }
func (*keyListCommand) Usage() string {
	return "Usage: farcast storage key list <instance>\n\nShow the keyring's key ids. No key material is ever printed."
}
func (*keyListCommand) SetFlags(*flag.FlagSet) {}

func (*keyListCommand) Run(_ context.Context, env *Env, args []string) error {
	instance, err := oneInstance("list", args)
	if err != nil {
		return err
	}
	keyring, err := keyringOf(env, instance)
	if err != nil {
		return err
	}
	result := keyListResult{Instance: instance}
	for i, e := range keyring.NameKeys() {
		result.NameKeys = append(result.NameKeys, keyInfo{ID: e.ID.String(), Created: stamp(e.Created), Active: i == 0})
	}
	for i, e := range keyring.KEKs() {
		result.Keys = append(result.Keys, keyInfo{ID: e.ID.String(), Created: stamp(e.Created), Active: i == 0})
	}
	return env.Printer.Print(result)
}

type keyInfo struct {
	ID      string `json:"id"`
	Created string `json:"created,omitempty"`
	Active  bool   `json:"active"`
}

type keyListResult struct {
	Instance string    `json:"instance"`
	NameKeys []keyInfo `json:"name_keys"`
	Keys     []keyInfo `json:"keys"`
}

func (r keyListResult) Human(w io.Writer) error {
	fprintf(w, "keyring for %q\n", r.Instance)
	show := func(label string, keys []keyInfo) {
		fprintf(w, "  %s\n", label)
		for _, k := range keys {
			marker := " "
			if k.Active {
				marker = "*"
			}
			fprintf(w, "   %s %s  %s\n", marker, k.ID, k.Created)
		}
	}
	show("name keys (stable — addressing cannot rotate)", r.NameKeys)
	show("key-encryption keys (* = wraps new writes)", r.Keys)
	return nil
}

// ---------------------------------------------------------------- export

type keyExportCommand struct {
	out            string
	passphraseFile string
}

func (*keyExportCommand) Name() string     { return "export" }
func (*keyExportCommand) Synopsis() string { return "Write a passphrase-armored copy of the keyring" }

func (*keyExportCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage key export <instance> --out <path> --passphrase-file <path>

Write a passphrase-armored copy of the instance's keyring.

Flags:
      --out <path>               Where to write the export (required)
      --passphrase-file <path>   File holding the passphrase; "-" reads stdin

The passphrase is read from a file or stdin, never typed at a prompt: reading
one from a terminal portably would mean either a new dependency in the binary
that holds your cloud credentials or shelling out to stty, and neither is
worth it for one command. Use a mode-0600 file you delete afterwards, or pipe
it in.

The export is written 0600 and refuses to overwrite an existing file.`)
}

func (c *keyExportCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.out, "out", "", "where to write the export")
	fs.StringVar(&c.passphraseFile, "passphrase-file", "", "file holding the passphrase")
}

func (c *keyExportCommand) Run(_ context.Context, env *Env, args []string) error {
	instance, err := oneInstance("export", args)
	if err != nil {
		return err
	}
	if c.out == "" {
		return usagef("storage key export requires --out")
	}
	passphrase, err := readPassphrase(env, c.passphraseFile)
	if err != nil {
		return err
	}
	keyring, err := keyringOf(env, instance)
	if err != nil {
		return err
	}
	armored, err := datasphere.ExportKeyring(keyring, passphrase)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(c.out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; refusing to overwrite it", c.out)
		}
		return err
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(armored); err != nil {
		return err
	}
	fprintf(env.Err, "The passphrase is the only thing protecting this file. %s\n", datasphere.KeyLossWarning)
	return env.Printer.Print(keySimpleResult{Instance: instance, Path: c.out, Status: "exported"})
}

// ---------------------------------------------------------------- import

type keyImportCommand struct {
	passphraseFile string
}

func (*keyImportCommand) Name() string     { return "import" }
func (*keyImportCommand) Synopsis() string { return "Merge an armored copy into the live keyring" }

func (*keyImportCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage key import <instance> <file> --passphrase-file <path>

Merge an armored keyring into the instance's live one.

Import is MERGE-ONLY and there is no flag to change that. It adds entries the
live keyring lacks and never overwrites or removes one, and it refuses
outright if a key id appears on both sides with different material.

That is a security control, not a convenience. A blob's key id is
cloud-writable, so a tampering cloud can make any object demand a key the
keyring lacks — and the natural "restore from backup", done as a replacement,
would destroy every key added since that backup.`)
}

func (c *keyImportCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.passphraseFile, "passphrase-file", "", "file holding the passphrase")
}

func (c *keyImportCommand) Run(_ context.Context, env *Env, args []string) error {
	if len(args) != 2 {
		return usagef("storage key import takes an instance and a file")
	}
	instance, path := strings.TrimSuffix(args[0], ":"), args[1]
	passphrase, err := readPassphrase(env, c.passphraseFile)
	if err != nil {
		return err
	}
	armored, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	incoming, err := datasphere.ImportKeyring(armored, passphrase)
	if err != nil {
		return err
	}
	// An absent keyring is not an error here, and getting that wrong would be
	// actively dangerous. Merging into nothing is trivially safe — the result
	// is exactly what was imported — while refusing pushes the operator toward
	// the one path that loses data: running a storage command to mint a keyring
	// first, whose fresh NAME key then becomes the active one. Since a Store
	// addresses objects only under the active name key, every imported object
	// would afterwards be unlistable and unreadable while the keyring looked
	// perfectly healthy.
	var live datasphere.Keyring
	held, err := env.ConfigDir.InstanceKeyringExists(instance)
	if err != nil {
		return err
	}
	if held {
		if live, err = keyringOf(env, instance); err != nil {
			return err
		}
	}
	before := len(live.KEKs()) + len(live.NameKeys())
	merged, err := live.Merge(incoming)
	if err != nil {
		return err
	}
	data, err := merged.Marshal()
	if err != nil {
		return err
	}
	if held {
		if err := env.ConfigDir.SaveInstanceKeyring(instance, data); err != nil {
			return err
		}
	} else if err := env.ConfigDir.CreateInstanceKeyring(instance, data); err != nil {
		return err
	}
	added := len(merged.KEKs()) + len(merged.NameKeys()) - before
	fprintln(env.Err, "removed: nothing — import is merge-only, by design.")
	return env.Printer.Print(keyImportResult{Instance: instance, Added: added, MergeOnly: true, Removed: []string{}, Status: "imported"})
}

type keyImportResult struct {
	Instance  string   `json:"instance"`
	Added     int      `json:"added"`
	Removed   []string `json:"removed"`
	MergeOnly bool     `json:"merge_only"`
	Status    string   `json:"status"`
}

func (r keyImportResult) Human(w io.Writer) error {
	fprintf(w, "✓ merged %d new key(s) into the keyring for %q\n", r.Added, r.Instance)
	return nil
}

// ---------------------------------------------------------------- rotate

type keyRotateCommand struct {
	assumeYes bool
}

func (*keyRotateCommand) Name() string     { return "rotate" }
func (*keyRotateCommand) Synopsis() string { return "Add a key-encryption key and make it active" }

func (*keyRotateCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage key rotate <instance> [-y]

Add a new key-encryption key and make it the one that wraps new writes. Every
existing key stays in the keyring, so every stored object stays readable.

` + rotationScopeWarning + `

Run 'farcast storage key rekey' afterwards to move existing objects onto the
new key, which is what eventually lets the old one be retired.`)
}

func (c *keyRotateCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation")
}

func (c *keyRotateCommand) Run(_ context.Context, env *Env, args []string) error {
	instance, err := oneInstance("rotate", args)
	if err != nil {
		return err
	}
	keyring, err := keyringOf(env, instance)
	if err != nil {
		return err
	}
	// The scope warning goes before the confirmation, not after the result: a
	// warning printed once the deed is done is read by nobody who was already
	// sure they knew what rotation did.
	fprintf(env.Err, "%s\n", rotationScopeWarning)
	if !c.assumeYes {
		if env.Printer.Mode != output.ModeHuman || !isTerminal(env.In) {
			return usagef("refusing to rotate without confirmation; pass --yes")
		}
		ok, err := newPrompter(env.In, env.Err).yesNo("Add a new key-encryption key")
		if err != nil {
			return err
		}
		if !ok {
			fprintln(env.Err, "Aborted.")
			return nil
		}
	}
	entry, err := datasphere.NewKey()
	if err != nil {
		return err
	}
	data, err := keyring.AddKEK(entry).Marshal()
	if err != nil {
		return err
	}
	if err := env.ConfigDir.SaveInstanceKeyring(instance, data); err != nil {
		return err
	}
	return env.Printer.Print(keyRotateResult{
		Instance: instance, RotatedTo: entry.ID.String(),
		Next: fmt.Sprintf("farcast storage key rekey %s", instance), Status: "rotated",
	})
}

type keyRotateResult struct {
	Instance  string `json:"instance"`
	RotatedTo string `json:"rotated_to"`
	Next      string `json:"next"`
	Status    string `json:"status"`
}

func (r keyRotateResult) Human(w io.Writer) error {
	fprintf(w, "✓ %q now wraps new writes under %s\n", r.Instance, r.RotatedTo)
	fprintf(w, "  existing objects still read under their original keys; move them with:\n      %s\n", r.Next)
	return nil
}

// ---------------------------------------------------------------- rekey

type keyRekeyCommand struct {
	assumeYes bool
	dryRun    bool
}

func (*keyRekeyCommand) Name() string { return "rekey" }
func (*keyRekeyCommand) Synopsis() string {
	return "Rewrite objects under the active key-encryption key"
}

func (*keyRekeyCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage key rekey <instance>[:<prefix>] [--dry-run] [-y]

Rewrite each stored object's header so its data key is wrapped under the
active key-encryption key. The encrypted body is not touched.

This is the most expensive command in the CLI: a cloud object cannot be
patched in place, so changing 68 bytes of header costs a full download and a
full upload of every object. --dry-run reports what it would move first.

It is resumable and safe to interrupt — every object stays readable throughout,
because the old keys remain in the keyring.

` + rotationScopeWarning)
}

func (c *keyRekeyCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation")
	fs.BoolVar(&c.dryRun, "dry-run", false, "report what would move, change nothing")
}

func (c *keyRekeyCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("storage key rekey takes one <instance>[:<prefix>] argument")
	}
	loc, err := parseLocator(env.ConfigDir, args[0])
	if err != nil {
		return err
	}
	if !loc.Remote {
		return usagef("storage key rekey takes an instance, not a local path: %q", args[0])
	}
	session, err := openSession(ctx, env, loc.Instance, false)
	if err != nil {
		return err
	}
	entries, listErr := session.Store.ListEntries(ctx, loc.Key)
	if listErr != nil {
		fprintf(env.Err, "Warning: %v\n", listErr)
	}
	var bytes int64
	for _, e := range entries {
		bytes += e.Size
	}
	if c.dryRun {
		return env.Printer.Print(keyRekeyResult{
			Instance: loc.Instance, Candidates: len(entries), Bytes: bytes, DryRun: true, Status: "would rekey",
		})
	}

	fprintf(env.Err, "%s\n", rotationScopeWarning)
	if !c.assumeYes {
		if env.Printer.Mode != output.ModeHuman || !isTerminal(env.In) {
			return usagef("refusing to rekey %d object(s) without confirmation; pass --yes", len(entries))
		}
		fprintf(env.Err, "This reads and rewrites %d object(s), %s in total.\n", len(entries), humanBytes(bytes))
		ok, err := newPrompter(env.In, env.Err).yesNo("Proceed")
		if err != nil {
			return err
		}
		if !ok {
			fprintln(env.Err, "Aborted.")
			return nil
		}
	}

	result := keyRekeyResult{Instance: loc.Instance, Candidates: len(entries), Bytes: bytes, Status: "rekeyed"}
	for _, e := range entries {
		moved, err := session.Store.Rekey(ctx, e.Key)
		if err != nil {
			// Report where it stopped: every object is still readable, so a
			// re-run picks up from here rather than starting over.
			return fmt.Errorf("rekey stopped at %q after %d rewritten: %w; every object remains readable — re-run to continue", e.Key, result.Rewritten, err)
		}
		if moved {
			result.Rewritten++
		} else {
			result.Skipped++
		}
	}
	return env.Printer.Print(result)
}

type keyRekeyResult struct {
	Instance   string `json:"instance"`
	Candidates int    `json:"candidates"`
	Rewritten  int    `json:"rewritten"`
	Skipped    int    `json:"skipped"`
	Bytes      int64  `json:"bytes"`
	DryRun     bool   `json:"dry_run,omitempty"`
	Status     string `json:"status"`
}

func (r keyRekeyResult) Human(w io.Writer) error {
	if r.DryRun {
		fprintf(w, "would rekey %d object(s), reading and rewriting %s\n", r.Candidates, humanBytes(r.Bytes))
		return nil
	}
	fprintf(w, "✓ rekeyed %q\n  rewritten: %d\n  already active: %d\n", r.Instance, r.Rewritten, r.Skipped)
	return nil
}

type keySimpleResult struct {
	Instance string `json:"instance"`
	Path     string `json:"path,omitempty"`
	Status   string `json:"status"`
}

func (r keySimpleResult) Human(w io.Writer) error {
	fprintf(w, "✓ %s %q", r.Status, r.Instance)
	if r.Path != "" {
		fprintf(w, " to %s (mode 0600)", r.Path)
	}
	fprintln(w, "")
	return nil
}

// readPassphrase reads a passphrase from a file or stdin.
//
// Never from a terminal prompt: doing that portably means either a new
// dependency in the binary that holds the operator's cloud credentials and the
// instance's CA key, or shelling out to stty. Neither is worth it for one
// command when a mode-0600 file the operator already controls does the job and
// a pipeline can use "-".
func readPassphrase(env *Env, path string) (string, error) {
	if path == "" {
		return "", usagef("--passphrase-file is required (use \"-\" to read stdin)")
	}
	var (
		data []byte
		err  error
	)
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(env.In, 4096))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return "", err
	}
	passphrase := strings.TrimRight(string(data), "\r\n")
	if passphrase == "" {
		return "", usagef("the passphrase is empty")
	}
	return passphrase, nil
}
