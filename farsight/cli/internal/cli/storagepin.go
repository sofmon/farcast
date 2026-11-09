package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/sofmon/farcast/datasphere"
	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// The in-cluster key pin (ADR 0008 finding 4), from the operator's side.
//
// A restarted keyholder holds nothing to compare a bundle with, so a keeper
// enrolled before a rotation used to re-seed the old keys into a fleet that
// restarted all at once. The pin is the reference that survives the restart: a
// ConfigMap of key-encryption-key IDs, written here whenever this machine's
// keyring gains or retires a key, and read by every replica when it starts.
//
// Two rules make it safe to enforce on every push, and every write here keeps
// both:
//
//   - Never ahead. The pin is written only from a keyring that is already
//     saved, and only once the hand-over has checked it against the fleet, so
//     everything this machine pushes next passes it. A pin written from a
//     keyring that is then put back would lock this machine out of its own
//     replicas.
//   - Never behind. A write reads the pin first and refuses if this keyring
//     lacks a key it requires, or writes under one it retired: this machine is
//     behind the instance, and lowering the pin to match would re-admit
//     exactly the stale bundles it exists to refuse.
//
// Retiring is the one step with an order of its own: a key is retired only
// once the rotation that replaced it is final, never while it might still be
// put back.

// pinStore is the slice of the cluster client the key pin needs.
type pinStore interface {
	ConfigMapData(ctx context.Context, namespace, name string) (map[string]string, string, bool, error)
	CreateConfigMap(ctx context.Context, manifest []byte) error
	ReplaceConfigMap(ctx context.Context, manifest []byte) error
}

// pinStoreOpener reaches an instance's pin. A seam, so no test shells out.
type pinStoreOpener func(kubeconfigPath string) (pinStore, error)

// defaultPinStore is what a command without its own seam uses. Tests replace
// it, so that no test can shell out to kubectl.
var defaultPinStore pinStoreOpener = openPinStore

// openPinStore refuses before running anything when there is no kubeconfig,
// so a command without one fails here rather than in kubectl.
func openPinStore(kubeconfigPath string) (pinStore, error) {
	if _, err := os.Stat(kubeconfigPath); err != nil {
		return nil, fmt.Errorf("this machine has no kubeconfig for the instance (%v)", err)
	}
	return cluster.New(kubeconfigPath), nil
}

// pinFor is the pin a keyring implies. Require is every key-encryption key of
// every scope; Retired is, per scope, each key created strictly before the one
// the scope writes under — the same reliance on Created the hand-over already
// has, and keys created in the same second are never retired, which is the
// safe direction. The instance's own key space is never in a bundle, so never
// in the pin.
func pinFor(k datasphere.Keyring) dskeyholder.Pin {
	var p dskeyholder.Pin
	for _, s := range k.Scopes() {
		keks := s.Keyring().KEKs()
		if len(keks) == 0 {
			continue
		}
		active := keks[0]
		for _, e := range keks {
			p.Require = append(p.Require, e.ID)
			if e.Created.Before(active.Created) {
				p.Retired = append(p.Retired, e.ID)
			}
		}
	}
	return p
}

// pinBehind is a keyring the pin already refuses.
type pinBehind struct {
	// Missing are keys the pin requires and this keyring lacks.
	Missing []string
	// RetiredActive are keys this keyring writes under that the pin retired.
	RetiredActive []string
}

func (b *pinBehind) Error() string {
	var parts []string
	if len(b.Missing) > 0 {
		parts = append(parts, fmt.Sprintf("it lacks %s", plural(len(b.Missing), "key", "keys")+" the instance's key pin requires ("+strings.Join(b.Missing, ", ")+")"))
	}
	if len(b.RetiredActive) > 0 {
		parts = append(parts, "it writes under "+strings.Join(b.RetiredActive, ", ")+", which the pin has retired")
	}
	return "this keyring is behind the instance's key pin: " + strings.Join(parts, "; ")
}

// pinVerdict compares a keyring with a pin: what the pin requires that the
// keyring lacks, and which keys the keyring writes under that the pin retired.
func pinVerdict(cur dskeyholder.Pin, k datasphere.Keyring) *pinBehind {
	held := map[datasphere.KeyID]bool{}
	var active []datasphere.KeyID
	for _, s := range k.Scopes() {
		keks := s.Keyring().KEKs()
		for i, e := range keks {
			held[e.ID] = true
			if i == 0 {
				active = append(active, e.ID)
			}
		}
	}
	var b pinBehind
	for _, id := range cur.Require {
		if !held[id] {
			b.Missing = append(b.Missing, id.String())
		}
	}
	for _, id := range active {
		if slices.Contains(cur.Retired, id) && !slices.Contains(b.RetiredActive, id.String()) {
			b.RetiredActive = append(b.RetiredActive, id.String())
		}
	}
	if len(b.Missing) == 0 && len(b.RetiredActive) == 0 {
		return nil
	}
	slices.Sort(b.Missing)
	slices.Sort(b.RetiredActive)
	return &b
}

// readPin reads the instance's pin. present is false when there is none.
// An unreadable value is returned as invalid, with no pin.
func readPin(ctx context.Context, ps pinStore) (pin dskeyholder.Pin, present bool, version string, invalid error, err error) {
	data, rv, found, err := ps.ConfigMapData(ctx, dsdeploy.DefaultNamespace, dsdeploy.PinConfigMapName(""))
	if err != nil {
		return dskeyholder.Pin{}, false, "", nil, fmt.Errorf("read the key pin: %w", err)
	}
	if !found {
		return dskeyholder.Pin{}, false, "", nil, nil
	}
	// Read without the replicas' size cap: a well-formed pin that grew past
	// it is still the instance's pin, and treating it as corrupt would let
	// any keyring overwrite it — lower it — as a "repair".
	p, present, perr := dskeyholder.ParsePinAnySize(data[dsdeploy.PinKey])
	return p, present, rv, perr, nil
}

// pinWrite is what writePin did.
type pinWrite struct {
	Pin     dskeyholder.Pin
	Changed bool
	// Repaired is set when the pin that was there could not be read, and was
	// rewritten from this keyring.
	Repaired bool
}

// writePin raises the instance's pin to this keyring: everything it holds
// required, and — withRetired — every key older than a scope's active one
// retired. It only ever raises. A keyring the pin already refuses is
// pinBehind, and nothing is written; replace writes exactly this keyring's pin
// regardless, which is the operator lowering it deliberately.
//
// The write is a create over "absent" or a replace at the version it read,
// so another writer in between is a conflict and not an overwrite; it re-reads
// and tries again a bounded number of times.
func writePin(ctx context.Context, ps pinStore, k datasphere.Keyring, withRetired, replace bool) (pinWrite, error) {
	mine := pinFor(k)
	var lastErr error
	for range 3 {
		cur, present, rv, invalid, err := readPin(ctx, ps)
		if err != nil {
			return pinWrite{}, err
		}
		desired := dskeyholder.Pin{Require: mine.Require}
		if withRetired {
			desired.Retired = mine.Retired
		}
		if present && invalid == nil && !replace {
			if b := pinVerdict(cur, k); b != nil {
				return pinWrite{}, b
			}
			desired = desired.Union(dskeyholder.Pin{Require: cur.Require, Retired: cur.Retired})
			if desired.Equal(cur) {
				return pinWrite{Pin: cur}, nil
			}
		}
		// Never ahead: everything this machine pushes next must pass it.
		if err := desired.Admits(heldKeys(k)); err != nil {
			return pinWrite{}, fmt.Errorf("the key pin this keyring implies refuses the keyring itself, so it was not written: %w", err)
		}
		// And never one a replica cannot read: an oversize pin is refused by
		// every replica as unreadable, which turns every keeper away.
		if n := len(desired.Marshal()); n > dskeyholder.MaxPinBytes {
			return pinWrite{}, fmt.Errorf("the key pin would be %d bytes, more than the %d a replica reads — this keyring holds %d key-encryption keys; "+
				"nothing was written", n, dskeyholder.MaxPinBytes, len(desired.Require))
		}
		manifest, err := dsdeploy.RenderPin(dsdeploy.DefaultNamespace, dsdeploy.DefaultName, desired.Marshal(), rv)
		if err != nil {
			return pinWrite{}, err
		}
		write := ps.CreateConfigMap
		if rv != "" {
			write = ps.ReplaceConfigMap
		}
		if lastErr = write(ctx, manifest); lastErr == nil {
			return pinWrite{Pin: desired, Changed: true, Repaired: invalid != nil}, nil
		}
		// Re-read: a write that landed and lost its answer is success, and a
		// conflict is another writer to take into account.
		if again, ok, _, inv, err := readPin(ctx, ps); err == nil && ok && inv == nil && again.Equal(desired) {
			return pinWrite{Pin: desired, Changed: true, Repaired: invalid != nil}, nil
		}
	}
	return pinWrite{}, fmt.Errorf("the key pin changed while this command wrote it, or could not be written: %w", lastErr)
}

// pinRaiser is a keyholder client that can hand a running replica the pin.
type pinRaiser interface {
	RaisePin(ctx context.Context, ordinal int, pin string, replace bool) (keyholder.State, error)
}

// pinRaise is one replica's answer to a live raise.
type pinRaise struct {
	Ordinal int    `json:"ordinal"`
	Raised  bool   `json:"raised"`
	Note    string `json:"note,omitempty"`
}

// raisePins hands every replica the pin now, rather than when it next starts.
// A replica that was sealed when the pin moved and stays sealed would
// otherwise keep the old one for as long as it waits — the window a lost
// keeper's bundle needs.
//
// A replica's answer is checked, not assumed: one that kept a pin above this
// keyring's — a raise unions, and a replica may have taken a higher pin from
// somewhere this command never saw — is said to be that, not "enforcing it".
func raisePins(ctx context.Context, client sealStateClient, total int, pin dskeyholder.Pin, replace bool, instance string, held map[string][]string) []pinRaise {
	rows := make([]pinRaise, 0, total)
	r, ok := client.(pinRaiser)
	for i := range total {
		if !ok {
			rows = append(rows, pinRaise{Ordinal: i, Note: "not raised live: this client cannot; it loads the pin when it next restarts"})
			continue
		}
		st, err := r.RaisePin(ctx, i, pin.Marshal(), replace)
		var got dskeyholder.Pin
		reported := false
		if err == nil && st.Pin != nil {
			got, reported = pinFromReport(st.Pin)
		}
		switch {
		case keyholder.Unsupported(err):
			rows = append(rows, pinRaise{Ordinal: i, Note: fmt.Sprintf("runs a keyholder image that predates the key pin; 'farcast storage deploy %s' updates it", instance)})
		case err != nil:
			rows = append(rows, pinRaise{Ordinal: i, Note: fmt.Sprintf("did not take the pin live (%v); it loads it when it next restarts", err)})
		case reported && got.Admits(held) != nil:
			rows = append(rows, pinRaise{Ordinal: i, Note: fmt.Sprintf("still enforces a pin above this keyring's (%v) — "+
				"'farcast storage key pin %s --replace' lowers it, if the keys it requires are gone from every machine", got.Admits(held), instance)})
		case st.Pin != nil && st.Pin.ServingBelow:
			rows = append(rows, pinRaise{Ordinal: i, Raised: true, Note: "took the pin, and serves keys it refuses — 'farcast storage unseal' brings it to this machine's keys"})
		default:
			rows = append(rows, pinRaise{Ordinal: i, Raised: true})
		}
	}
	return rows
}

// pinRemedy is how an operator re-arms a pin a command could not write.
func pinRemedy(instance string) string {
	return fmt.Sprintf("'farcast storage key pin %s'", instance)
}

// ---------------------------------------------------------------- pin

type keyPinCommand struct {
	replace   bool
	assumeYes bool
	// newPinStore and newKeyholder are seams; nil reaches the cluster and the
	// tunnel.
	newPinStore  pinStoreOpener
	newKeyholder keyholderOpener
}

func (*keyPinCommand) Name() string { return "pin" }
func (*keyPinCommand) Synopsis() string {
	return "Write the in-cluster key pin from this keyring"
}

func (*keyPinCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage key pin <instance> [--replace] [-y]

Write the instance's key pin from this machine's keyring and hand it to every
keyholder replica now.

The pin is the list of key IDs every bundle pushed to the keyholder must hold,
and the ones no scope may write under any more. It is what lets a replica that
restarted — holding nothing to compare with — refuse a keeper enrolled before
a rotation or a new application. It is IDs only: no key, nothing derived from
one, and no scope name. 'storage key rotate', 'run' and 'storage deploy' keep
it up to date; this is for when one of them could not write it, or when the
pin's ConfigMap was deleted.

It only ever raises the pin. If this keyring is behind it — it lacks a key the
pin requires, or writes under one it retired — it refuses: this machine is
behind the instance. --replace lowers the pin to this keyring's, for when the
keys it requires are gone from every machine; it asks first, and says what it
lowers.

Reaching the pin needs kubectl and this instance's cloud credentials, like
'farcast run'. Unseal never touches it: 'farcast storage unseal --below-pin'
is the way past a pin that cannot be met, with no cloud access at all.`)
}

func (c *keyPinCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.replace, "replace", false, "lower the pin to this keyring's, after confirmation")
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation --replace asks for")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation --replace asks for")
}

func (c *keyPinCommand) Run(ctx context.Context, env *Env, args []string) error {
	instance, err := oneInstance("pin", args)
	if err != nil {
		return err
	}
	meta, err := env.ConfigDir.LoadInstanceMetadata(instance)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", instance, err)
	}
	if meta.Keyholder == nil || !meta.Keyholder.Deployed {
		return fmt.Errorf("instance %q has no keyholder deployed; 'farcast storage deploy %s' writes the pin with it", instance, instance)
	}
	keys, err := keyringOf(env, instance)
	if err != nil {
		return err
	}
	open := c.newPinStore
	if open == nil {
		open = defaultPinStore
	}
	ps, err := open(env.ConfigDir.InstanceKubeconfigPath(instance))
	if err != nil {
		return fmt.Errorf("the key pin could not be reached: %w", err)
	}

	res := keyPinResult{Instance: instance}
	w, err := writePin(ctx, ps, keys, true, false)
	var behind *pinBehind
	switch {
	case errors.As(err, &behind) && !c.replace:
		return fmt.Errorf("%v. Nothing was written: lowering the pin would re-admit the bundles it refuses. %s",
			behind, behindRemedy(behind, instance))
	case errors.As(err, &behind):
		fprintf(env.Err, "%v.\n", behind)
		fprintf(env.Err, "--replace lowers the pin to this keyring's. Every bundle that lacks those keys is admitted again,\n"+
			"a lost keeper's included, until a rotation from here raises it.\n")
		if ok, perr := c.confirmLower(env); perr != nil || !ok {
			return perr
		}
		if w, err = writePin(ctx, ps, keys, true, true); err != nil {
			return err
		}
		res.Lowered = slices.Concat(behind.Missing, behind.RetiredActive)
	case err != nil:
		return err
	}
	res.Written, res.Repaired = w.Changed, w.Repaired
	res.Require, res.Retired = len(w.Pin.Require), len(w.Pin.Retired)

	openKH := c.newKeyholder
	if openKH == nil {
		openKH = openKeyholder
	}
	client, done, kerr := openKH(ctx, env, instance)
	if kerr != nil {
		res.Live = fmt.Sprintf("not handed to the replicas live (%v); each loads it when it next restarts", kerr)
		return env.Printer.Print(res)
	}
	defer done()
	// --replace lowers what the REPLICAS enforce, not only the ConfigMap: a
	// replica holds the pin it was last handed until it restarts, and one
	// that missed a lowering — or took a higher pin the ConfigMap no longer
	// has — keeps refusing this keyring however often the ConfigMap is
	// rewritten.
	replace := res.Lowered != nil
	if c.replace && !replace {
		var above []string
		for i := range replicaCount(meta) {
			st, err := client.State(ctx, i)
			if err != nil || st.Pin == nil || st.Pin.Status != dskeyholder.PinValid {
				continue
			}
			if p, ok := pinFromReport(st.Pin); ok && !p.Equal(w.Pin) {
				above = append(above, fmt.Sprintf("replica %d", i))
			}
		}
		if len(above) > 0 {
			fprintf(env.Err, "%s enforce a pin other than this keyring's. --replace replaces it with this keyring's.\n", strings.Join(above, " and "))
			if ok, err := c.confirmLower(env); err != nil || !ok {
				return err
			}
			replace, res.Lowered = true, above
		}
	}
	res.Replicas = raisePins(ctx, client, replicaCount(meta), w.Pin, replace, instance, heldKeys(keys))
	return env.Printer.Print(res)
}

// confirmLower asks before a pin is lowered, unless --yes said so already.
func (c *keyPinCommand) confirmLower(env *Env) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	if env.Printer.Mode != output.ModeHuman || !isTerminal(env.In) {
		return false, usagef("refusing to lower the key pin without confirmation; pass --yes")
	}
	ok, err := newPrompter(env.In, env.Err).yesNo("Lower the key pin")
	if err == nil && !ok {
		fprintln(env.Err, "Aborted.")
	}
	return ok, err
}

type keyPinResult struct {
	Instance string     `json:"instance"`
	Written  bool       `json:"written"`
	Repaired bool       `json:"repaired,omitempty"`
	Lowered  []string   `json:"lowered,omitempty"`
	Require  int        `json:"require"`
	Retired  int        `json:"retired"`
	Live     string     `json:"live,omitempty"`
	Replicas []pinRaise `json:"replicas,omitempty"`
}

func (r keyPinResult) Human(w io.Writer) error {
	switch {
	case r.Lowered != nil:
		fprintf(w, "! lowered the key pin of %q; it no longer requires or retires %s\n", r.Instance, strings.Join(r.Lowered, ", "))
	case r.Repaired:
		fprintf(w, "✓ rewrote the key pin of %q from this keyring; the one there could not be read\n", r.Instance)
	case r.Written:
		fprintf(w, "✓ raised the key pin of %q\n", r.Instance)
	default:
		fprintf(w, "✓ the key pin of %q already matches this keyring\n", r.Instance)
	}
	fprintf(w, "  requires %s, retires %s\n", plural(r.Require, "key", "keys"), plural(r.Retired, "key", "keys"))
	if r.Live != "" {
		fprintf(w, "  replicas: %s\n", r.Live)
	}
	for _, row := range r.Replicas {
		switch {
		case row.Raised && row.Note == "":
			fprintf(w, "  replica %d  enforcing it\n", row.Ordinal)
		default:
			fprintf(w, "  replica %d  %s\n", row.Ordinal, row.Note)
		}
	}
	return nil
}

// pinOnDeploy is storage deploy's half: the pin must exist before the replicas
// start, or TechnoCore — which may create ConfigMaps in farcast-system — could
// create it first. With no keyring yet there is nothing to require, and an
// empty pin is written so the ConfigMap is this machine's.
func pinOnDeploy(ctx context.Context, ps pinStore, env *Env, instance string) (pinWrite, error) {
	raw, err := env.ConfigDir.LoadInstanceKeyring(instance)
	if err != nil {
		cur, present, rv, invalid, rerr := readPin(ctx, ps)
		if rerr != nil {
			return pinWrite{}, rerr
		}
		if present && invalid == nil {
			return pinWrite{Pin: cur}, nil
		}
		empty := dskeyholder.Pin{}
		manifest, merr := dsdeploy.RenderPin(dsdeploy.DefaultNamespace, dsdeploy.DefaultName, empty.Marshal(), rv)
		if merr != nil {
			return pinWrite{}, merr
		}
		write := ps.CreateConfigMap
		if rv != "" {
			write = ps.ReplaceConfigMap
		}
		if err := write(ctx, manifest); err != nil {
			return pinWrite{}, fmt.Errorf("write the key pin: %w", err)
		}
		return pinWrite{Pin: empty, Changed: true, Repaired: invalid != nil}, nil
	}
	k, err := datasphere.ParseKeyring(raw)
	if err != nil {
		return pinWrite{}, err
	}
	return writePin(ctx, ps, k, true, false)
}

// pinMeta reports whether an instance has a keyholder whose pin to keep.
func pinMeta(meta *config.InstanceMetadata) bool {
	return meta != nil && meta.Keyholder != nil && meta.Keyholder.Deployed
}
