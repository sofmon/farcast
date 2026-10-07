package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/storage"
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
	k, _, err := keyringAndBytesOf(env, instance)
	return k, err
}

// keyringAndBytesOf is keyringOf for a command that will write the keyring
// back: it keeps the bytes it read, which the write must still find on disk.
func keyringAndBytesOf(env *Env, instance string) (datasphere.Keyring, []byte, error) {
	data, err := env.ConfigDir.LoadInstanceKeyring(instance)
	if err != nil {
		return datasphere.Keyring{}, nil, fmt.Errorf("read the storage keyring for %q: %w\n%s", instance, err, datasphere.KeyLossWarning)
	}
	k, err := datasphere.ParseKeyring(data)
	return k, data, err
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
	// Every scope's keys too. Since ADR 0018 decision 5 each application has
	// its own scope, so the master keys are a small minority of what the
	// keyring holds — and a scope's NAME key is one of the unrotatable ones.
	// An operator deciding whether a rotation covered everything has to be
	// able to see them.
	for _, s := range keyring.Scopes() {
		sk := scopeKeys{Name: s.Name, Prefix: s.Prefix, Created: stamp(s.Created)}
		for i, e := range s.Keyring().NameKeys() {
			sk.NameKeys = append(sk.NameKeys, keyInfo{ID: e.ID.String(), Created: stamp(e.Created), Active: i == 0})
		}
		for i, e := range s.Keyring().KEKs() {
			sk.Keys = append(sk.Keys, keyInfo{ID: e.ID.String(), Created: stamp(e.Created), Active: i == 0})
		}
		result.Scopes = append(result.Scopes, sk)
	}
	return env.Printer.Print(result)
}

type keyInfo struct {
	ID      string `json:"id"`
	Created string `json:"created,omitempty"`
	Active  bool   `json:"active"`
}

// scopeKeys is one scope's key ids. A scope owns a subtree of the key space
// and has its own name key and KEK, so it is a separate listing rather than
// more rows under the instance's own.
type scopeKeys struct {
	Name     string    `json:"name"`
	Prefix   string    `json:"prefix"`
	Created  string    `json:"created,omitempty"`
	NameKeys []keyInfo `json:"name_keys"`
	Keys     []keyInfo `json:"keys"`
}

type keyListResult struct {
	Instance string      `json:"instance"`
	NameKeys []keyInfo   `json:"name_keys"`
	Keys     []keyInfo   `json:"keys"`
	Scopes   []scopeKeys `json:"scopes,omitempty"`
}

func (r keyListResult) Human(w io.Writer) error {
	fprintf(w, "keyring for %q\n", r.Instance)
	show := func(indent, label string, keys []keyInfo) {
		fprintf(w, "%s%s\n", indent, label)
		for _, k := range keys {
			marker := " "
			if k.Active {
				marker = "*"
			}
			fprintf(w, "%s %s %s  %s\n", indent, marker, k.ID, k.Created)
		}
	}
	show("  ", "name keys (stable — addressing cannot rotate)", r.NameKeys)
	show("  ", "key-encryption keys (* = wraps new writes)", r.Keys)
	for _, s := range r.Scopes {
		fprintf(w, "  scope %s  (%s)\n", s.Name, s.Prefix)
		show("    ", "name keys (stable — addressing cannot rotate)", s.NameKeys)
		show("    ", "key-encryption keys (* = wraps new writes)", s.Keys)
	}
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
	var raw []byte
	held, err := env.ConfigDir.InstanceKeyringExists(instance)
	if err != nil {
		return err
	}
	if held {
		if live, raw, err = keyringAndBytesOf(env, instance); err != nil {
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
		if err := env.ConfigDir.SaveInstanceKeyring(instance, raw, data); err != nil {
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
	// newKeyholder reaches the keyholder for the hand-over; nil dials it.
	newKeyholder keyholderOpener
}

func (*keyRotateCommand) Name() string     { return "rotate" }
func (*keyRotateCommand) Synopsis() string { return "Add new key-encryption keys and put them in use" }

func (*keyRotateCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage key rotate <instance> [-y]

Add a new key-encryption key to the instance's own key space AND to every
application's scope, and make each the one that wraps new writes. Every
existing key stays in the keyring, so every stored object stays readable.

A serving keyholder is handed the new keys in two steps. Every serving
replica first holds them with the old ones still in use; only once each has
confirmed is any told to use them — and only then does this machine's keyring
make them active too, since this machine writes to storage as well. A new key
in use on one replica and absent from another would leave the second unable to
read what the first writes. If a replica misses the first step — or every
replica is sealed, so none could stop a keeper re-seeding the old keys —
nothing changes for any application: the new keys stay held, unused, this
exits non-zero, and running it again once every replica is serving and
answers finishes a rotation with fresh ones. A sealed replica is left sealed and receives the
keys on the next 'farcast storage unseal'.

This is what retires what a lost keeper device holds: its bundle carries the
scope keys from before the rotation, and opens nothing written afterwards.

` + rotationScopeWarning + `

Once the new keys are in use, run 'farcast storage key rekey' to move existing
objects onto them. Then re-enrol every keeper: each one's bundle predates the
rotation.`)
}

func (c *keyRotateCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation")
}

func (c *keyRotateCommand) Run(ctx context.Context, env *Env, args []string) error {
	instance, err := oneInstance("rotate", args)
	if err != nil {
		return err
	}
	keyring, raw, err := keyringAndBytesOf(env, instance)
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
		ok, err := newPrompter(env.In, env.Err).yesNo("Add new key-encryption keys")
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
	// The master AND every scope. Rotating the master alone — all this command
	// once did — reached nothing an application wrote and nothing a keeper's
	// bundle holds, since every application object lives under a scope.
	rotated, scopes, err := keyring.AddKEK(entry).RotateScopeKEKs()
	if err != nil {
		return err
	}
	previous := make(map[string]datasphere.KeyID, len(scopes))
	for _, r := range scopes {
		previous[r.Scope] = r.Previous
	}
	held, err := rotated.WithScopeActive(previous)
	if err != nil {
		return err
	}
	// Every save is a replace of exactly the file this command last read or
	// wrote. Rotate holds its keyring across a prompt and a network round
	// trip, and a 'farcast run' or 'key import' in between writes keys.yaml
	// too: written over, the scope run just minted — and handed to the
	// keyholder — would exist only in the replicas' memory.
	last := raw
	save := func(k datasphere.Keyring) error {
		data, err := k.Marshal()
		if err != nil {
			return err
		}
		if err := env.ConfigDir.SaveInstanceKeyring(instance, last, data); err != nil {
			return err
		}
		last = data
		return nil
	}
	// Saved before any replica sees the new keys — they exist nowhere else
	// until this write lands — and saved HELD, not in use. This machine writes
	// to storage too ('secret set', 'storage cp'), under whatever its keyring
	// makes active, so it must not use an application's new key before every
	// replica can read it. It is saved again, with the keys in use, once they
	// all hold them. The instance's own key space is never in the keyholder,
	// so its new key is in use at once.
	if err := save(held); err != nil {
		if errors.Is(err, config.ErrKeyringChanged) {
			return fmt.Errorf("keys.yaml changed while rotate waited (another farcast command wrote it), so nothing was rotated — run it again: %w", err)
		}
		return err
	}

	result := keyRotateResult{
		Instance: instance, RotatedTo: entry.ID.String(),
		Next: fmt.Sprintf("farcast storage key rekey %s", instance), Status: "rotated", Active: true,
	}
	for _, r := range scopes {
		result.Scopes = append(result.Scopes, scopeRotated{Scope: r.Scope, Previous: r.Previous.String(), Active: r.Active.String()})
	}

	meta, merr := env.ConfigDir.LoadInstanceMetadata(instance)
	switch {
	case len(scopes) == 0:
		// Nothing a keyholder holds changed.
	case merr != nil:
		result.Active = false
		result.Keyholder = fmt.Sprintf("not handed the new keys: the instance's metadata could not be read (%v)", merr)
	case meta.Keyholder == nil || !meta.Keyholder.Deployed:
		// No replica to split from: the keyholder receives these keys, in
		// use, when it is deployed and unsealed.
		if err := save(rotated); err != nil {
			return err
		}
		result.Keyholder = "none deployed; it receives the new keys when it is deployed and unsealed"
	default:
		var pushedHeld *datasphere.Keyring
		res := handOverKeys(ctx, env, meta, c.newKeyholder, rotated, handOverOptions{
			rotated: previous,
			beforeHold: func(k datasphere.Keyring) error {
				pushedHeld = &k
				return save(k)
			},
			beforeActivate: func() error { return save(rotated) },
		})
		result.Keyholder = describeRotation(res, instance)
		// In use means some replica writes under the new keys. A push that
		// reached none leaves this machine alone on them — beside replicas
		// that may all restart into a keeper's older keys — so it goes back
		// to what the replicas use.
		result.Active = res.Activated && len(res.Loaded) > 0
		switch {
		case !res.Activated || len(res.Loaded) > 0 || pushedHeld == nil:
		case len(res.Unconfirmed) > 0:
			// A replica that refused may yet have taken them, and then not
			// said: putting this machine back could leave it behind its own
			// fleet. Every replica holds the new keys, so leaving it on them
			// splits nothing.
			result.Keyholder += ". This machine's keyring stays on the new keys: a replica that refused them did not say afterwards what it holds"
		default:
			if err := save(*pushedHeld); err != nil {
				result.Keyholder += fmt.Sprintf(". This machine's keyring could NOT be put back (%v): it writes under the new keys, which no replica uses", err)
			}
		}
		switch {
		case !result.Active && res.Cause == heldNoneServing:
			// Two steps: the unseal hands over the keys held, and only a
			// rotation puts new ones in use.
			result.Next = fmt.Sprintf("farcast storage unseal %s, then farcast storage key rotate %s", instance, instance)
			result.Unfinished = fmt.Sprintf("every replica is sealed, so the applications' new keys are not in use: run 'farcast storage unseal %s', then 'farcast storage key rotate %s' again", instance, instance)
		case !result.Active && res.ForeignCopy:
			result.Next = ""
			result.Unfinished = "a replica serves another machine's copy of a scope this machine minted too, so the applications' new keys are not in use: " +
				"rotate from the machine that deployed it"
		case !result.Active && res.Problem != "":
			result.Unfinished = fmt.Sprintf("the hand-over did not happen (above), so the applications' new keys are not in use: once what it names is fixed, 'farcast storage key rotate %s' again", instance)
		case result.Active && (len(res.HeldOnly) > 0 || len(res.Unreached)+len(res.Refused) > 0):
			result.Status = "partial"
			result.Next = fmt.Sprintf("farcast storage unseal %s", instance)
			result.Unfinished = fmt.Sprintf("not every replica writes under the new keys yet; 'farcast storage unseal %s' finishes it", instance)
		}
	}
	if !result.Active {
		result.Status = "held"
		if strings.HasPrefix(result.Next, "farcast storage key rekey") {
			result.Next = fmt.Sprintf("farcast storage key rotate %s", instance)
		}
		if result.Unfinished == "" {
			result.Unfinished = fmt.Sprintf("the applications' new keys are not in use yet; 'farcast storage key rotate %s' again, once every replica is serving and answers, finishes a rotation", instance)
		}
	}
	// Only a rotation that reached a scope changes what a keeper's bundle
	// must hold; the instance's own key space is never in one.
	if merr == nil && len(scopes) > 0 {
		result.Reenrol = keepersToReenrol(meta)
	}
	if err := env.Printer.Print(result); err != nil {
		return err
	}
	if result.Unfinished != "" {
		// Not success: what an operator rotates for — retiring what a lost
		// keeper holds — has not happened everywhere, and a 'rotate && rekey'
		// must stop here.
		return rotationUnfinished(result.Unfinished)
	}
	return nil
}

// rotationUnfinished is a rotation that did not reach every serving replica,
// saying what finishes it.
type rotationUnfinished string

func (r rotationUnfinished) Error() string { return string(r) }

// keepersToReenrol names every keeper device that has not been revoked — each one
// holding a bundle a rotation or a new application has just made stale.
func keepersToReenrol(meta *config.InstanceMetadata) []string {
	var out []string
	for _, k := range meta.Keepers {
		if !k.Revoked {
			out = append(out, k.Device)
		}
	}
	return out
}

// describeRotation says, in one line, where the new keys are and what is left.
func describeRotation(res handOverResult, instance string) string {
	again := fmt.Sprintf("'farcast storage key rotate %s'", instance)
	unused := "The applications' new keys are held and unused everywhere, this machine included (the instance key space's new key is in use here already)"
	switch {
	case res.Problem != "" && res.ForeignCopy:
		return fmt.Sprintf("not handed the new keys: %s. %s", res.Problem, unused)
	case res.Problem != "":
		return fmt.Sprintf("not handed the new keys: %s. %s. Run %s again once that is fixed", res.Problem, unused, again)
	case !res.Activated && res.Cause == heldNoneServing:
		return fmt.Sprintf("%s: %s, and with none serving nothing would stop a keeper re-seeding the keys from before. "+
			"Run 'farcast storage unseal %s', then %s again", unused, res.Reason, instance, again)
	case !res.Activated && res.Cause == heldUnrecorded:
		return fmt.Sprintf("every replica took the new keys to hold, but %s. %s. Run %s again once keys.yaml can be written; "+
			"the keys minted now stay held and unused", res.Reason, unused, again)
	case !res.Activated && res.Cause == heldChanged:
		return fmt.Sprintf("every replica took the new keys to hold, but %s (see 'farcast storage state %s'). %s. Run %s again; "+
			"the keys minted now stay held and unused", res.Reason, instance, unused, again)
	case !res.Activated:
		return fmt.Sprintf("the new keys are held by %d of %d replicas and in use on none, because %s (see 'farcast storage state %s'). %s. "+
			"Run %s again once every replica is serving and answers; the keys minted now stay held and unused",
			len(res.Loaded), res.Total, res.Reason, instance, unused, again)
	case len(res.Loaded) == 0:
		return fmt.Sprintf("every replica that answered took the new keys to hold, but the push that would have them use the keys reached none "+
			"(see 'farcast storage state %s'). %s. Run %s again once every replica is serving and answers", instance, unused, again)
	case res.Complete():
		return fmt.Sprintf("all %d replicas hold the new keys and write under them (generation %d)", res.Total, res.Generation)
	default:
		line := fmt.Sprintf("%d of %d replicas write under the new keys (generation %d)", len(res.Loaded), res.Total, res.Generation)
		if n := len(res.HeldOnly); n > 0 {
			line += fmt.Sprintf("; %d hold them without using them yet, and still read everything — 'farcast storage unseal %s' finishes it", n, instance)
		}
		if n := len(res.Unreached) + len(res.Refused) - len(res.HeldOnly); n > 0 {
			line += fmt.Sprintf("; %d took them to hold and then did not answer — 'farcast storage state %s' says what each holds, and 'farcast storage unseal %s' brings it to the new keys", n, instance, instance)
		}
		if len(res.Waiting) > 0 {
			line += fmt.Sprintf("; %d sealed, and receive them on the next 'farcast storage unseal %s'", len(res.Waiting), instance)
		}
		return line
	}
}

type scopeRotated struct {
	Scope    string `json:"scope"`
	Previous string `json:"previous"`
	Active   string `json:"active"`
}

type keyRotateResult struct {
	Instance  string         `json:"instance"`
	RotatedTo string         `json:"rotated_to"`
	Scopes    []scopeRotated `json:"scopes,omitempty"`
	// Active reports whether the applications' new keys are in use. When it
	// is false they are held, by this machine and by whichever replicas took
	// them, and wrap nothing yet.
	Active    bool   `json:"active"`
	Keyholder string `json:"keyholder,omitempty"`
	// Unfinished says what is left, when the rotation is not in use on
	// every replica that serves.
	Unfinished string   `json:"unfinished,omitempty"`
	Reenrol    []string `json:"reenrol,omitempty"`
	Next       string   `json:"next"`
	Status     string   `json:"status"`
}

func (r keyRotateResult) Human(w io.Writer) error {
	if r.Active {
		fprintf(w, "✓ %q now wraps new writes under new keys\n", r.Instance)
	} else {
		fprintf(w, "! %q holds new application keys that are NOT in use yet\n", r.Instance)
	}
	fprintf(w, "  instance key space   %s\n", r.RotatedTo)
	for _, sc := range r.Scopes {
		fprintf(w, "  scope %-14s %s -> %s\n", sc.Scope, sc.Previous, sc.Active)
	}
	if r.Keyholder != "" {
		fprintf(w, "  keyholder: %s\n", r.Keyholder)
	}
	if r.Active && r.Unfinished == "" {
		fprintf(w, "  existing objects still read under their original keys; move them with:\n      %s\n", r.Next)
	}
	if len(r.Reenrol) > 0 {
		if r.Active {
			fprintf(w, "\nEvery keeper's bundle predates this rotation. Re-enrol each device — until\n")
			fprintf(w, "you do, it refuses to re-seed, and a restarted replica waits for an unseal:\n")
		} else {
			fprintf(w, "\nA keeper refuses to re-seed once a serving replica holds a key its bundle lacks,\n")
			fprintf(w, "so the ones enrolled before this may already refuse. Re-enrol each device once a\n")
			fprintf(w, "rotation has finished:\n")
		}
		for _, d := range r.Reenrol {
			fprintf(w, "      farcast keeper enroll %s %s --out <path> --passphrase-file <path>\n", r.Instance, d)
		}
	}
	if len(r.Scopes) > 0 {
		fprintf(w, "\nNames stay where they were: a scope's name key cannot rotate, so anything that\n")
		fprintf(w, "held an old bundle can still compute where that scope's objects are stored.\n")
	}
	return nil
}

// ---------------------------------------------------------------- rekey

type keyRekeyCommand struct {
	assumeYes bool
	dryRun    bool
	// newKeyholder reaches the keyholder for the gate; nil dials it.
	newKeyholder keyholderOpener
}

func (*keyRekeyCommand) Name() string { return "rekey" }
func (*keyRekeyCommand) Synopsis() string {
	return "Rewrite objects under the active key-encryption keys"
}

func (*keyRekeyCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage key rekey <instance>[:<prefix>] [--dry-run] [-y]

Rewrite each stored object's header so its data key is wrapped under the
active key-encryption key of the key space it lives in — the instance's own,
or its application's scope. The encrypted body is not touched.

This is the most expensive command in the CLI: a cloud object cannot be
patched in place, so changing 68 bytes of header costs a full download and a
full upload of every object. --dry-run reports what it would move first.

It refuses to move an application's objects until every keyholder replica is
serving and holds that application's current key. A replica without it could
not read a single object rekey moved. 'farcast storage unseal' brings every
replica up to the current keys.

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
	// The bare instance is what this command's own usage, and rotate's next
	// step, have always printed. parseLocator reads a colon-less operand as a
	// local path, so the form the CLI told operators to type was refused.
	loc, err := instanceLocator(env.ConfigDir, "storage key rekey", args[0])
	if err != nil {
		return err
	}
	session, err := openSession(ctx, env, loc.Instance, false)
	if err != nil {
		return err
	}
	// Every key space, not the master alone. Listing only the master used to
	// drop every application object as one this keyring did not write — so
	// rekey rewrote nothing, and said "rekeyed".
	entries, listErr := listForRekey(ctx, session, loc.Key)
	if listErr != nil {
		fprintf(env.Err, "Warning: %v\n", listErr)
	}
	var bytes int64
	touched := map[string]bool{}
	for _, e := range entries {
		bytes += e.Size
		if e.Scope != "" {
			touched[e.Scope] = true
		}
	}
	gateErr := c.gate(ctx, env, loc.Instance, session.Keyring, touched)
	if c.dryRun {
		res := keyRekeyResult{
			Instance: loc.Instance, Candidates: len(entries), Bytes: bytes, Scopes: len(touched),
			DryRun: true, Status: "would rekey",
		}
		if gateErr != nil {
			res.Blocked = gateErr.Error()
		}
		return env.Printer.Print(res)
	}
	if gateErr != nil {
		return gateErr
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

	result := keyRekeyResult{Instance: loc.Instance, Candidates: len(entries), Bytes: bytes, Scopes: len(touched), Status: "rekeyed"}
	for _, e := range entries {
		// Each object through the key space that NAMED it — its scope's, or
		// the master's — and so under that space's active KEK.
		moved, err := e.Store.Rekey(ctx, e.Key)
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

// rekeyEntry is one stored object and the key space that named it.
type rekeyEntry struct {
	datasphere.Entry
	Store *datasphere.Store
	Scope string // empty for the instance's own key space
}

// listForRekey lists every object under prefix across every key space, keeping
// the store that named each one.
//
// The store has to come from the listing, not from the object's key. Routing
// by key picks the scope whose prefix covers it — and an object the master
// wrote before that scope existed (a `storage cp` into app/, ahead of the
// `farcast run` that minted the scope) sits under that prefix with a name only
// the master's name key computes. Re-deriving its store sent rekey to the scope,
// which found nothing there, and the whole sweep stopped.
func listForRekey(ctx context.Context, session *storage.Session, prefix string) ([]rekeyEntry, error) {
	spaces, err := session.KeySpaces()
	if err != nil {
		return nil, err
	}
	var out []rekeyEntry
	var errs []error
	named := map[string]bool{}
	scoped := scopePrefixes(session)
	for _, space := range spaces {
		// The instance's own space is listed whatever the prefix. A listing
		// skips it inside a scope, but an object the master wrote before the
		// scope existed lives exactly there, and only the master names it —
		// so a rekey of that prefix would pass it over, count nothing, and
		// leave it under the retired key.
		if space.Prefix != "" && !spaceCanHold(space.Prefix, prefix, scoped) {
			continue
		}
		found, err := space.Store.ListEntries(ctx, prefix)
		if err != nil {
			errs = append(errs, err)
		}
		for _, e := range found {
			named[e.Stored] = true
			out = append(out, rekeyEntry{Entry: e, Store: space.Store, Scope: space.Scope})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, unnamedOnly(errs, named)
}

// gate refuses to move any application's objects onto a key the keyholder
// does not hold — or onto a key that is not the one being rotated to.
//
// Rekey wraps each object's data key under its scope's ACTIVE KEK, in this
// machine's keyring. Three things have to be true for that to retire anything:
//
//   - That active key is the newest the scope holds. After a rotation that did
//     not finish, this machine's keyring holds the new key unused and the old
//     one active, so rekey would move nothing anywhere a lost keeper's bundle
//     cannot follow — and say "rekeyed".
//   - Every replica holds it, or the objects rekey moves become unreadable to
//     the applications that replica serves.
//   - Every replica writes under it, or each keeps writing new objects under
//     the old key, undoing the rotation one write at a time.
//
// A sealed replica blocks it too. It holds no keys now, and the keys it next
// holds depend on who unseals it: 'storage unseal' brings the current ones,
// but a keeper enrolled before the rotation would bring the old ones.
func (c *keyRekeyCommand) gate(ctx context.Context, env *Env, instance string, keyring datasphere.Keyring, touched map[string]bool) error {
	if len(touched) == 0 {
		return nil // the instance's own key space: no keyholder ever holds it
	}
	names := slices.Sorted(maps.Keys(touched))
	var problems, remedies []string
	remedy := func(r string) {
		if !slices.Contains(remedies, r) {
			remedies = append(remedies, r)
		}
	}
	for _, name := range names {
		if scope, ok := keyring.ScopeNamed(name); ok && unfinishedRotation(scope) {
			problems = append(problems, fmt.Sprintf("this machine's keyring holds a newer key for %s than the one it uses — a rotation that did not finish, "+
				"so rekey would move its objects onto the key being retired", name))
			remedy(fmt.Sprintf("farcast storage key rotate %s", instance))
		}
	}

	meta, err := env.ConfigDir.LoadInstanceMetadata(instance)
	if err != nil {
		return err
	}
	if meta.Keyholder != nil && meta.Keyholder.Deployed {
		open := c.newKeyholder
		if open == nil {
			open = openKeyholder
		}
		client, done, err := open(ctx, env, instance)
		if err != nil {
			return fmt.Errorf("rekey cannot confirm the keyholder holds the current keys, so it moves nothing: %w", err)
		}
		defer done()
		for i := range replicaCount(meta) {
			st, err := client.State(ctx, i)
			switch {
			case err != nil:
				problems = append(problems, fmt.Sprintf("replica %d did not answer (%v)", i, err))
				remedy(fmt.Sprintf("farcast storage state %s   (to see why it does not answer)", instance))
			case st.Sealed():
				problems = append(problems, fmt.Sprintf("replica %d is %s", i, st.Phase))
				remedy(fmt.Sprintf("farcast storage unseal %s", instance))
			case outdatedImage(st):
				problems = append(problems, fmt.Sprintf("replica %d runs a keyholder image older than this CLI and does not say which keys it holds", i))
				// deploy restarts the replicas sealed; the unseal after it is
				// the next remedy line.
				remedy(fmt.Sprintf("farcast storage deploy %s", instance))
				remedy(fmt.Sprintf("farcast storage unseal %s", instance))
			default:
				for _, name := range names {
					d, differs := scopeAgainst(name, st.Keys, keyring)
					if !differs {
						continue
					}
					problems = append(problems, fmt.Sprintf("replica %d %s", i, d.Note))
					switch d.Kind {
					case diffForeignCopy:
						remedy(fmt.Sprintf("(nothing on this machine: rekey %s from the machine that deployed it)", name))
					case diffBehind:
						remedy(fmt.Sprintf("farcast storage unseal %s   (it refuses, and says how to bring this keyring up to date)", instance))
					default:
						remedy(fmt.Sprintf("farcast storage unseal %s", instance))
					}
				}
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	// The fleet first: a rotation run while a replica is sealed or silent
	// stops at the hold again.
	rotate := fmt.Sprintf("farcast storage key rotate %s", instance)
	if i := slices.Index(remedies, rotate); i >= 0 {
		remedies = append(append(remedies[:i:i], remedies[i+1:]...), rotate)
	}
	return fmt.Errorf("rekey moves nothing until this machine's newest keys are the ones every keyholder replica holds and uses:\n  - %s\n"+
		"Run:\n\n  %s\n\nthen rekey again",
		strings.Join(problems, "\n  - "), strings.Join(remedies, "\n  "))
}

// unfinishedRotation reports whether a scope holds a key-encryption key minted
// after the one it uses: a rotation's key, held and never put in use.
func unfinishedRotation(s datasphere.Scope) bool {
	keks := s.Keyring().KEKs()
	for _, e := range keks[1:] {
		if e.Created.After(keks[0].Created) {
			return true
		}
	}
	return false
}

type keyRekeyResult struct {
	Instance   string `json:"instance"`
	Candidates int    `json:"candidates"`
	Rewritten  int    `json:"rewritten"`
	Skipped    int    `json:"skipped"`
	Bytes      int64  `json:"bytes"`
	// Scopes counts the application scopes the objects belong to.
	Scopes int  `json:"scopes"`
	DryRun bool `json:"dry_run,omitempty"`
	// Blocked is why a real run would refuse, reported by a dry run.
	Blocked string `json:"blocked,omitempty"`
	Status  string `json:"status"`
}

func (r keyRekeyResult) Human(w io.Writer) error {
	if r.DryRun {
		fprintf(w, "would rekey %d object(s) across %d application scope(s), reading and rewriting %s\n", r.Candidates, r.Scopes, humanBytes(r.Bytes))
		if r.Blocked != "" {
			fprintf(w, "\nbut a real run would refuse: %s\n", r.Blocked)
		}
		return nil
	}
	fprintf(w, "✓ rekeyed %q\n  rewritten: %d\n  already active: %d\n", r.Instance, r.Rewritten, r.Skipped)
	if r.Candidates > 0 && r.Rewritten == 0 {
		// Not an error: every object was already under its active key. It is
		// also exactly what rekey printed when it could not see a single
		// application object, so it says which it was.
		fprintf(w, "  every one of the %d object(s) was already under its key space's active KEK\n", r.Candidates)
	}
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
