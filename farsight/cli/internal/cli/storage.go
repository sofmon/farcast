package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/storage"
)

// `farcast storage` — the instance's encrypted disk.
//
// Everything written here is encrypted before the cloud sees it and stored
// under an opaque name; the CLI gets no say in that, because DataSphere's
// encrypting Store is the only path there is.
//
// The group runs entirely on the operator's machine — the recorded bucket, the
// stored cloud credentials, the local keyring — so it works on an instance
// that has never been connected, and it needs no tunnel and no cluster.

// group is a two-level command: it parses a subcommand name and delegates.
// `storage` and `storage key` are the same type instantiated twice, so the
// third level costs a value rather than a pattern.
type group struct {
	name     string
	synopsis string
	usage    string
	subs     *Registry
}

func (g *group) Name() string     { return g.name }
func (g *group) Synopsis() string { return g.synopsis }
func (g *group) Usage() string    { return strings.TrimSpace(g.usage) }

// SetFlags registers nothing: a group's flags belong to its subcommands, and
// claiming them here would silently swallow a subcommand's own.
func (g *group) SetFlags(*flag.FlagSet) {}

// SetSubFlags contributes the named subcommand's flags to the router's flag
// set, so one parse handles the whole line — global flags, the subcommand's
// own, and operands, in any order — exactly as it does for a one-level
// command. See subFlagged.
//
// The subcommand is found by name rather than by position, so a global flag
// placed before it (`farcast storage --output json ls prod:`) still resolves.
// The first match wins, which is the subcommand: an operand that happens to
// share a subcommand's name can only appear after it.
func (g *group) SetSubFlags(fs *flag.FlagSet, args []string) {
	for i, arg := range args {
		sub, ok := g.subs.Lookup(arg)
		if !ok {
			continue
		}
		sub.SetFlags(fs)
		// `storage key export --out …` is three levels; the middle one has no
		// flags of its own but still owns the level that does.
		if nested, ok := sub.(subFlagged); ok {
			nested.SetSubFlags(fs, args[i+1:])
		}
		return
	}
}

// Run dispatches to the subcommand. The router has already parsed this line's
// flags — the subcommand's included, via SetSubFlags — so what arrives here is
// operands, and re-parsing them would reset every flag it just set.
func (g *group) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) == 0 {
		return usagef("%s requires a subcommand (%s)", g.name, strings.Join(g.subNames(), ", "))
	}
	sub, ok := g.subs.Lookup(args[0])
	if !ok {
		return usagef("unknown %s subcommand %q (want %s)", g.name, args[0], strings.Join(g.subNames(), ", "))
	}
	return sub.Run(ctx, env, args[1:])
}

func (g *group) subNames() []string {
	names := make([]string, 0)
	for _, c := range g.subs.Commands() {
		names = append(names, c.Name())
	}
	sort.Strings(names)
	return names
}

// newStorageCommand builds the `farcast storage` group.
func newStorageCommand() Command {
	subs := NewRegistry()
	subs.Register(&storageLsCommand{})
	subs.Register(&storageCpCommand{})
	subs.Register(&storageRmCommand{})
	subs.Register(&storageUsageCommand{})
	subs.Register(&storageDeployCommand{})
	subs.Register(&storageStateCommand{})
	subs.Register(&storageSealCommand{})
	subs.Register(&storageUnsealCommand{})
	subs.Register(newStorageKeyCommand())
	return &group{
		name:     "storage",
		synopsis: "The instance's encrypted disk (ls, cp, rm, usage, deploy, state, unseal, seal, key)",
		subs:     subs,
		usage: `
Usage: farcast storage <ls|cp|rm|usage|deploy|state|unseal|seal|key> [flags] [arguments]

The instance's encrypted disk. Everything stored is encrypted before the cloud
sees it, under an opaque name; the provider holds ciphertext and nothing else.

Objects are addressed scp-style as <instance>:<key>:

  prod:app/reports/q3.csv    one object
  prod:app/reports/          a /-aligned prefix
  prod:                      the whole bucket
  ./q3.csv                   a local file

Subcommands:
  ls      List the objects under a prefix
  cp      Copy between local files and an instance, in either direction
  rm      Delete objects
  usage   Report what storage holds and what it costs
  deploy  Deploy the in-cluster keyholder
  state   Report each keyholder replica's seal state
  unseal  Hand the keyholder its key material
  seal    Make the keyholder forget its key material
  key     Manage the instance's storage keyring

Storage runs on this machine against the recorded bucket, so it needs no
tunnel and no running cluster. Provider, project, region and credentials all
come from the recorded instance: there are no cloud flags and no --bucket.`,
	}
}

// locator is an operand: either a local path or a remote <instance>:<key>.
type locator struct {
	Remote   bool
	Instance string
	Key      string
	Path     string
}

// parseLocator decides whether an operand names an object or a file.
//
// An operand is remote iff its first ':' falls before any path separator and
// the text before it names an instance that exists in local state. When BOTH
// readings are genuinely available — an instance "prod" exists and a local
// file literally named "prod:x" exists — it refuses rather than guesses,
// because a wrong guess here either uploads the wrong bytes or overwrites the
// wrong file, and neither is recoverable.
func parseLocator(dir config.Dir, operand string) (locator, error) {
	colon := strings.Index(operand, ":")
	slash := strings.IndexAny(operand, `/\`)
	if colon < 0 || (slash >= 0 && slash < colon) {
		return locator{Path: operand}, nil
	}
	instance, key := operand[:colon], operand[colon+1:]
	exists, err := dir.InstanceExists(instance)
	if err != nil {
		return locator{}, err
	}
	_, localErr := os.Lstat(operand)
	switch {
	case exists && localErr == nil:
		// Both readings are real. Refusing beats guessing: one guess uploads
		// the wrong bytes, the other overwrites the wrong file.
		return locator{}, usagef("%q is both instance %q and a local file; write ./%s for the file", operand, instance, operand)
	case exists:
		return locator{Remote: true, Instance: instance, Key: key}, nil
	case localErr == nil:
		return locator{Path: operand}, nil
	default:
		// Instance-shaped, no such instance, and no such file. Saying "that is
		// not a local path" would be technically true and useless; the operator
		// almost certainly mistyped an instance name.
		return locator{}, fmt.Errorf("no such instance %q (and no local file %q)", instance, operand)
	}
}

// instanceLocator resolves an operand for a verb whose operand can only name
// an instance.
//
// `ls` and `usage` have no local reading at all, so a bare "prod" is ambiguous
// with nothing — and both spell the colon as optional in their own usage
// lines (`<instance>[:<prefix>]`, `<instance>`). parseLocator alone cannot
// accept that form, because an operand with no colon is a local path by
// construction, which would leave both commands rejecting the invocation they
// document.
func instanceLocator(dir config.Dir, verb, operand string) (locator, error) {
	if !strings.ContainsAny(operand, `:/\`) {
		exists, err := dir.InstanceExists(operand)
		if err != nil {
			return locator{}, err
		}
		if !exists {
			return locator{}, fmt.Errorf("no such instance %q", operand)
		}
		return locator{Remote: true, Instance: operand}, nil
	}
	loc, err := parseLocator(dir, operand)
	if err != nil {
		return locator{}, err
	}
	if !loc.Remote {
		return locator{}, usagef("%s takes an instance, not a local path: %q", verb, operand)
	}
	return loc, nil
}

// openSession resolves an instance's storage for a command.
func openSession(ctx context.Context, env *Env, instance string, mint bool) (*storage.Session, error) {
	session, err := storage.Open(ctx, storage.Options{Dir: env.ConfigDir, Instance: instance, Mint: mint})
	if err != nil {
		return nil, err
	}
	reportSession(env, session)
	return session, nil
}

// reportSession says, exactly once, what an Open brought into existence. The
// key-loss warning is emitted verbatim and in every output mode, because the
// one moment an operator will act on it is the moment the file appears.
func reportSession(env *Env, session *storage.Session) {
	if session.KeyringMinted {
		fprintf(env.Err, "Created the storage keyring for %q at %s (mode 0600).\n",
			session.Instance, env.ConfigDir.InstanceKeyringPath(session.Instance))
		fprintf(env.Err, "WARNING: %s\n", datasphere.KeyLossWarning)
		fprintf(env.Err, "Back it up the way you back up the instance's CA key: copy %s offline.\n",
			env.ConfigDir.InstancePath(session.Instance))
	}
	if session.BucketCreated {
		fprintf(env.Err, "Created storage bucket %s in %s.\n", session.Bucket, session.Location)
		// Cost is surfaced, never gated: gating cents trains an operator to
		// click through the gates that gu ard real money.
		fprintf(env.Err, "  $0.00 until data is written, then Standard single-region storage per GiB-month plus operations.\n")
		fprintf(env.Err, "  Soft delete is disabled by design: deletes are immediate and final.\n")
	}
	for _, notice := range session.Notices {
		fprintf(env.Err, "Warning: %s\n", notice)
	}
}

// ---------------------------------------------------------------- ls

type storageLsCommand struct {
	long   bool
	tokens bool
}

func (*storageLsCommand) Name() string     { return "ls" }
func (*storageLsCommand) Synopsis() string { return "List the objects under a prefix" }

func (*storageLsCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage ls <instance>[:<prefix>] [flags]

List the logical keys stored under a prefix, sorted.

Flags:
  -l, --long     Show stored size and age alongside each key
      --tokens   Also show the opaque name each key is stored under

--tokens is the transparency surface: hold the stored name next to the logical
one and see for yourself that the cloud holds neither the name nor the data.`)
}

func (c *storageLsCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.long, "long", false, "show size and age")
	fs.BoolVar(&c.long, "l", false, "show size and age")
	fs.BoolVar(&c.tokens, "tokens", false, "also show the opaque stored name")
}

func (c *storageLsCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("storage ls takes one <instance>[:<prefix>] argument")
	}
	loc, err := instanceLocator(env.ConfigDir, "storage ls", args[0])
	if err != nil {
		return err
	}
	session, err := openSession(ctx, env, loc.Instance, false)
	if err != nil {
		return err
	}

	entries, listErr := session.Store.ListEntries(ctx, loc.Key)
	if listErr != nil {
		// Names that did resolve are still reported: hiding them would turn one
		// unreadable object into an unusable listing.
		fprintf(env.Err, "Warning: %v\n", listErr)
	}
	out := make([]storageObject, 0, len(entries))
	var total int64
	for _, e := range entries {
		total += e.Size
		item := storageObject{Key: e.Key, StoredBytes: e.Size}
		if !e.Created.IsZero() {
			item.Created = e.Created.UTC().Format(time.RFC3339)
		}
		if c.tokens {
			item.StoredName = e.Stored
		}
		out = append(out, item)
	}
	return env.Printer.Print(storageLsResult{
		Instance: loc.Instance, Bucket: session.Bucket, Prefix: loc.Key,
		Objects: out, Count: len(out), StoredBytes: total,
		long: c.long, tokens: c.tokens,
	})
}

type storageObject struct {
	Key         string `json:"key"`
	StoredBytes int64  `json:"stored_bytes"`
	Created     string `json:"created,omitempty"`
	StoredName  string `json:"stored_name,omitempty"`
}

type storageLsResult struct {
	Instance    string          `json:"instance"`
	Bucket      string          `json:"bucket"`
	Prefix      string          `json:"prefix,omitempty"`
	Objects     []storageObject `json:"objects"`
	Count       int             `json:"count"`
	StoredBytes int64           `json:"stored_bytes"`

	long   bool
	tokens bool
}

func (r storageLsResult) Human(w io.Writer) error {
	for _, o := range r.Objects {
		switch {
		case r.long && r.tokens:
			fprintf(w, "%10s  %-8s  %s\t%s\n", humanBytes(o.StoredBytes), age(o.Created), o.StoredName, o.Key)
		case r.long:
			fprintf(w, "%10s  %-8s  %s\n", humanBytes(o.StoredBytes), age(o.Created), o.Key)
		case r.tokens:
			fprintf(w, "%s\t%s\n", o.StoredName, o.Key)
		default:
			fprintf(w, "%s\n", o.Key)
		}
	}
	if r.Count > 0 {
		fprintf(w, "%d object(s), %s stored\n", r.Count, humanBytes(r.StoredBytes))
	}
	return nil
}

// age renders an RFC 3339 timestamp as an operator-scale age.
func age(stamp string) string {
	if stamp == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return "-"
	}
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// ---------------------------------------------------------------- usage

type storageUsageCommand struct{}

func (*storageUsageCommand) Name() string     { return "usage" }
func (*storageUsageCommand) Synopsis() string { return "Report what storage holds and what it costs" }

func (*storageUsageCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage usage <instance>

Report what the instance's bucket physically holds and what it costs.

The count comes from the provider with no keyring involved, so this works even
for an operator who has lost keys.yaml — they can no longer read their data,
but they can still see what they are paying for and stop paying it.

Cost figures are estimates against a built-in price table and are prefixed ~;
the table's date is printed with them. Verify against the provider's own
pricing before relying on a number.`)
}

func (*storageUsageCommand) SetFlags(*flag.FlagSet) {}

func (*storageUsageCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("storage usage takes one instance argument")
	}
	loc, err := instanceLocator(env.ConfigDir, "storage usage", args[0])
	if err != nil {
		return err
	}
	if loc.Key != "" {
		// Refused rather than ignored, and refused rather than implemented.
		// Scoping to a prefix means mapping stored names back to logical ones,
		// which needs the keyring — and usage's whole value to an operator who
		// has lost theirs is that it still works. A silently ignored operand
		// would be worse than either.
		return usagef("storage usage reports the whole bucket; it cannot scope to a prefix, because that would need the keyring and usage deliberately runs without one")
	}
	session, err := storage.Open(ctx, storage.Options{Dir: env.ConfigDir, Instance: loc.Instance, WithoutKeyring: true})
	if err != nil {
		return err
	}
	usage, err := datasphere.BucketUsage(ctx, session.Provider, session.Bucket)
	if err != nil {
		return err
	}
	return env.Printer.Print(storageUsageResult{
		Instance: loc.Instance, Bucket: session.Bucket, Location: session.Location,
		Objects: usage.Objects, StoredBytes: usage.StoredBytes,
		MonthlyUSD: monthlyStorageUSD(usage.StoredBytes), PricesAsOf: priceTableAsOf,
		Oldest: stamp(usage.Oldest), Newest: stamp(usage.Newest),
	})
}

// The built-in price table. Estimates are only as good as this, so it carries
// its own date and every figure derived from it is marked as an estimate. A
// stale price presented as fact is worse than no price at all.
const (
	priceTableAsOf     = "2026-01-15"
	usdPerGiBMonth     = 0.020
	pricingReference   = "https://cloud.google.com/storage/pricing"
	bytesPerGiB        = 1 << 30
	monthlyUSDRounding = 10000
)

func monthlyStorageUSD(storedBytes int64) float64 {
	return float64(storedBytes) / bytesPerGiB * usdPerGiBMonth
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

type storageUsageResult struct {
	Instance    string  `json:"instance"`
	Bucket      string  `json:"bucket"`
	Location    string  `json:"location,omitempty"`
	Objects     int64   `json:"objects"`
	StoredBytes int64   `json:"stored_bytes"`
	MonthlyUSD  float64 `json:"monthly_usd_estimate"`
	PricesAsOf  string  `json:"prices_as_of"`
	Oldest      string  `json:"oldest,omitempty"`
	Newest      string  `json:"newest,omitempty"`
}

func (r storageUsageResult) Human(w io.Writer) error {
	fprintf(w, "storage for %q — %s", r.Instance, r.Bucket)
	if r.Location != "" {
		fprintf(w, " (%s)", r.Location)
	}
	fprintln(w, "")
	fprintf(w, "  objects   %d\n", r.Objects)
	fprintf(w, "  stored    %s   ← what the provider bills\n", humanBytes(r.StoredBytes))
	if r.Oldest != "" {
		fprintf(w, "  written   %s … %s\n", r.Oldest, r.Newest)
	}
	fprintf(w, "  cost      ~$%.4f / month at $%.3f/GiB-month\n", r.MonthlyUSD, usdPerGiBMonth)
	fprintf(w, "  prices as of %s — verify against %s\n", r.PricesAsOf, pricingReference)
	return nil
}

// ---------------------------------------------------------------- rm

type storageRmCommand struct {
	recursive bool
	assumeYes bool
}

func (*storageRmCommand) Name() string     { return "rm" }
func (*storageRmCommand) Synopsis() string { return "Delete objects" }

func (*storageRmCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage rm <instance>:<key>… [flags]

Delete stored objects. Deletes are immediate and final: soft delete is
disabled on the bucket by design, so there is no undelete window.

Flags:
  -r, --recursive   Treat the argument as a prefix and delete everything under it
  -y, --yes         Skip the confirmation (required when non-interactive)`)
}

func (c *storageRmCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.recursive, "recursive", false, "delete everything under a prefix")
	fs.BoolVar(&c.recursive, "r", false, "delete everything under a prefix")
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation")
}

func (c *storageRmCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) == 0 {
		return usagef("storage rm requires at least one <instance>:<key>")
	}
	instance, keys, err := remoteOperands(env.ConfigDir, args)
	if err != nil {
		return err
	}
	session, err := openSession(ctx, env, instance, false)
	if err != nil {
		return err
	}

	targets := keys
	if c.recursive {
		targets, err = expandPrefixes(ctx, session, keys)
		if err != nil {
			return err
		}
	}
	if len(targets) == 0 {
		return env.Printer.Print(storageRmResult{Instance: instance, Bucket: session.Bucket, Status: "nothing to delete"})
	}
	interactive := env.Printer.Mode == output.ModeHuman && isTerminal(env.In)
	if c.recursive {
		ok, err := c.confirm(interactive, env, targets)
		if err != nil {
			return err
		}
		if !ok {
			fprintln(env.Err, "Aborted.")
			return nil
		}
	}
	for _, key := range targets {
		if err := session.Store.Delete(ctx, key); err != nil {
			return fmt.Errorf("delete %q: %w", key, err)
		}
	}
	return env.Printer.Print(storageRmResult{
		Instance: instance, Bucket: session.Bucket, Deleted: len(targets), Status: "deleted",
	})
}

func (c *storageRmCommand) confirm(interactive bool, env *Env, targets []string) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	if !interactive {
		return false, usagef("refusing to delete %d object(s) without confirmation; pass --yes", len(targets))
	}
	for i, key := range targets {
		if i == 10 {
			fprintf(env.Err, "  … and %d more\n", len(targets)-10)
			break
		}
		fprintf(env.Err, "  %s\n", key)
	}
	fprintln(env.Err, "Deletes are immediate and final — soft delete is disabled on this bucket by design,")
	fprintln(env.Err, "and stored data derives from nothing.")
	answer, err := newPrompter(env.In, env.Err).line(fmt.Sprintf("Type the number of objects to delete (%d)", len(targets)))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(answer) == fmt.Sprint(len(targets)), nil
}

type storageRmResult struct {
	Instance string `json:"instance"`
	Bucket   string `json:"bucket"`
	Deleted  int    `json:"deleted"`
	Status   string `json:"status"`
}

func (r storageRmResult) Human(w io.Writer) error {
	if r.Deleted == 0 {
		fprintln(w, "nothing to delete")
		return nil
	}
	fprintf(w, "✓ deleted %d object(s) — immediate and final\n", r.Deleted)
	return nil
}

// remoteOperands requires every operand to be remote and on one instance.
func remoteOperands(dir config.Dir, args []string) (string, []string, error) {
	var instance string
	keys := make([]string, 0, len(args))
	for _, arg := range args {
		loc, err := parseLocator(dir, arg)
		if err != nil {
			return "", nil, err
		}
		if !loc.Remote {
			return "", nil, usagef("%q is not an <instance>:<key>", arg)
		}
		if instance == "" {
			instance = loc.Instance
		} else if instance != loc.Instance {
			return "", nil, usagef("all objects must be on one instance; got %q and %q", instance, loc.Instance)
		}
		keys = append(keys, loc.Key)
	}
	return instance, keys, nil
}

// expandPrefixes resolves prefixes to the keys they cover.
func expandPrefixes(ctx context.Context, session *storage.Session, prefixes []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, prefix := range prefixes {
		entries, err := session.Store.ListEntries(ctx, prefix)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !seen[e.Key] {
				seen[e.Key] = true
				out = append(out, e.Key)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// ---------------------------------------------------------------- cp

type storageCpCommand struct {
	recursive    bool
	force        bool
	skipExisting bool
}

func (*storageCpCommand) Name() string     { return "cp" }
func (*storageCpCommand) Synopsis() string { return "Copy between local files and an instance" }

func (*storageCpCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage cp <src> <dst> [flags]

Copy in either direction between local files and an instance's storage.
Exactly one of <src> and <dst> must be an <instance>:<key>.

  farcast storage cp ./q3.csv prod:app/reports/q3.csv
  farcast storage cp prod:app/reports/q3.csv ./q3.csv
  farcast storage cp -r ./exports prod:app/exports/

Flags:
  -r, --recursive       Copy a directory to a prefix, or a prefix to a directory
      --force           Replace an existing destination
      --skip-existing   Leave existing destinations alone

cp never overwrites silently, in either direction: the remote side has no
undelete, and the local side is somebody's file. Objects stream, so size is
not a consideration. A failed download leaves nothing at the destination — it
is staged beside the target and renamed only once the last byte authenticates.`)
}

func (c *storageCpCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.recursive, "recursive", false, "copy a directory or prefix")
	fs.BoolVar(&c.recursive, "r", false, "copy a directory or prefix")
	fs.BoolVar(&c.force, "force", false, "replace an existing destination")
	fs.BoolVar(&c.skipExisting, "skip-existing", false, "leave existing destinations alone")
}

func (c *storageCpCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 2 {
		return usagef("storage cp takes a source and a destination")
	}
	if c.force && c.skipExisting {
		return usagef("--force and --skip-existing ask for opposite things")
	}
	src, err := parseLocator(env.ConfigDir, args[0])
	if err != nil {
		return err
	}
	dst, err := parseLocator(env.ConfigDir, args[1])
	if err != nil {
		return err
	}
	switch {
	case src.Remote && dst.Remote:
		return usagef("copying between two instances is not supported; copy out and back in")
	case !src.Remote && !dst.Remote:
		return usagef("neither %q nor %q names an instance; use <instance>:<key> for the remote side", args[0], args[1])
	case !src.Remote:
		return c.upload(ctx, env, src, dst)
	default:
		return c.download(ctx, env, src, dst)
	}
}

func (c *storageCpCommand) upload(ctx context.Context, env *Env, src, dst locator) error {
	session, err := openSession(ctx, env, dst.Instance, true)
	if err != nil {
		return err
	}
	plan, err := uploadPlan(src.Path, dst.Key, c.recursive)
	if err != nil {
		return err
	}
	copied, skipped := 0, 0
	var bytesCopied int64
	for _, item := range plan {
		exists, err := objectExists(ctx, session, item.key)
		if err != nil {
			return err
		}
		if exists {
			switch {
			case c.skipExisting:
				skipped++
				continue
			case !c.force:
				return usagef("%s:%s already exists; pass --force to replace it or --skip-existing to leave it", dst.Instance, item.key)
			}
		}
		file, err := os.Open(item.path)
		if err != nil {
			return err
		}
		err = session.Store.WriteStream(ctx, item.key, file)
		_ = file.Close()
		if err != nil {
			return fmt.Errorf("upload %s: %w", item.path, err)
		}
		copied++
		bytesCopied += item.size
	}
	return env.Printer.Print(storageCpResult{
		Direction: "upload", Instance: dst.Instance, Bucket: session.Bucket,
		Objects: copied, Skipped: skipped, Bytes: bytesCopied, Status: "copied",
	})
}

func (c *storageCpCommand) download(ctx context.Context, env *Env, src, dst locator) error {
	session, err := openSession(ctx, env, src.Instance, false)
	if err != nil {
		return err
	}
	keys := []string{src.Key}
	if c.recursive {
		keys, err = expandPrefixes(ctx, session, []string{src.Key})
		if err != nil {
			return err
		}
	}
	copied, skipped := 0, 0
	for _, key := range keys {
		target, err := localTarget(dst.Path, src.Key, key, c.recursive)
		if err != nil {
			// A key that will not map to a safe path is named and skipped, not
			// mangled and not written outside the destination: after 3.2 a key
			// may have been written by an application inside the instance, and
			// a recursive download must never be a path-traversal primitive.
			fprintf(env.Err, "Warning: %v\n", err)
			skipped++
			continue
		}
		if _, err := os.Lstat(target); err == nil {
			switch {
			case c.skipExisting:
				skipped++
				continue
			case !c.force:
				return usagef("%s already exists; pass --force to replace it or --skip-existing to leave it", target)
			}
		}
		if err := downloadTo(ctx, session, key, target); err != nil {
			return err
		}
		copied++
	}
	return env.Printer.Print(storageCpResult{
		Direction: "download", Instance: src.Instance, Bucket: session.Bucket,
		Objects: copied, Skipped: skipped, Status: "copied",
	})
}

// downloadTo streams one object to a local path, staging it first.
//
// Staging is load-bearing rather than tidy: the streaming format authenticates
// per frame, so damage is detected only when the reader reaches it — after
// earlier frames have been written. A partial file that looks plausible is
// worse than no file, so nothing appears at the destination unless the whole
// object authenticated.
func downloadTo(ctx context.Context, session *storage.Session, key, target string) error {
	if dir := filepath.Dir(target); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	staged, err := os.CreateTemp(filepath.Dir(target), ".farcast-download-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = staged.Close()
		_ = os.Remove(staged.Name())
	}()
	// Decrypted plaintext is not something to leave world-readable.
	if err := staged.Chmod(0o600); err != nil {
		return err
	}
	if err := session.Store.ReadStream(ctx, key, staged); err != nil {
		return fmt.Errorf("download %q: %w", key, err)
	}
	if err := staged.Close(); err != nil {
		return err
	}
	return os.Rename(staged.Name(), target)
}

type uploadItem struct {
	path string
	key  string
	size int64
}

// uploadPlan resolves what a copy will write.
func uploadPlan(source, key string, recursive bool) ([]uploadItem, error) {
	info, err := os.Stat(source)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if recursive {
			return nil, usagef("%s is not a directory", source)
		}
		return []uploadItem{{path: source, key: key, size: info.Size()}}, nil
	}
	if !recursive {
		return nil, usagef("%s is a directory; pass --recursive", source)
	}
	prefix := strings.TrimSuffix(key, "/")
	var plan []uploadItem
	err = filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		stat, err := d.Info()
		if err != nil {
			return err
		}
		remote := filepath.ToSlash(rel)
		if prefix != "" {
			remote = prefix + "/" + remote
		}
		plan = append(plan, uploadItem{path: path, key: remote, size: stat.Size()})
		return nil
	})
	return plan, err
}

// localTarget maps a logical key to a local path under root, refusing anything
// that would escape it.
func localTarget(root, prefix, key string, recursive bool) (string, error) {
	if !recursive {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return filepath.Join(root, filepath.Base(filepath.FromSlash(key))), nil
		}
		return root, nil
	}
	rel := strings.TrimPrefix(key, prefix)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return "", fmt.Errorf("skipping %q: it does not name a file under the prefix", key)
	}
	target := filepath.Join(root, filepath.FromSlash(rel))
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	// Strictly inside, and never the root itself: a key of "." maps to the
	// destination directory, and writing an object there would replace the
	// directory being copied into with a file (or, when it does not exist yet,
	// stage the temporary beside it rather than within it). Both are outcomes
	// an application inside the instance must not be able to cause by choosing
	// a key.
	if !strings.HasPrefix(absTarget, absRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("skipping %q: it does not map to a path inside %s", key, root)
	}
	return target, nil
}

// objectExists reports whether a logical key already holds an object.
//
// It asks the provider for that one stored name rather than reading the object.
// Reading it would download and decrypt every byte — up to the buffered cap —
// purely to decide whether to refuse, and a recursive upload would pay that per
// file. The listing carries no plaintext, so the keyring is not involved beyond
// deriving the name.
func objectExists(ctx context.Context, session *storage.Session, key string) (bool, error) {
	stored, err := session.Store.StoredName(key)
	if err != nil {
		return false, err
	}
	infos, err := session.Provider.List(ctx, session.Bucket, stored)
	if err != nil {
		return false, err
	}
	for _, info := range infos {
		// A prefix listing can return neighbours whose stored name merely
		// starts with this one, so the match has to be exact.
		if info.Name == stored {
			return true, nil
		}
	}
	return false, nil
}

type storageCpResult struct {
	Direction string `json:"direction"`
	Instance  string `json:"instance"`
	Bucket    string `json:"bucket"`
	Objects   int    `json:"objects"`
	Skipped   int    `json:"skipped,omitempty"`
	Bytes     int64  `json:"bytes,omitempty"`
	Status    string `json:"status"`
}

func (r storageCpResult) Human(w io.Writer) error {
	fprintf(w, "✓ %sed %d object(s)", r.Direction, r.Objects)
	if r.Bytes > 0 {
		fprintf(w, " (%s)", humanBytes(r.Bytes))
	}
	if r.Skipped > 0 {
		fprintf(w, ", skipped %d", r.Skipped)
	}
	fprintln(w, "")
	return nil
}
