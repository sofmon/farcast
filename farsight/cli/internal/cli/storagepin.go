package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	tkube "github.com/sofmon/farcast/technocore/kube"
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

// pinPlanReader is what a plan reads the key pin through (ADR 0023 M2.6,
// A23-20): the pin's ConfigMap, and farcast-system's uid, which a plan that
// reads the cluster binds as its target. Under --plan and --confirm it is
// the instance's reader (openPinPlanReader by default); an interactive or
// --yes run of storage deploy passes the pinStore it opened as the writer.
type pinPlanReader interface {
	ConfigMapData(ctx context.Context, namespace, name string) (map[string]string, string, bool, error)
	preflighter
}

// pinStore is the slice of the cluster client the key pin needs: what a plan
// reads it through, and its create and replace, which only the writer makes.
// Through it the writer's NamespaceUID is reachable too.
type pinStore interface {
	pinPlanReader
	CreateConfigMap(ctx context.Context, manifest []byte) error
	ReplaceConfigMap(ctx context.Context, manifest []byte) error
}

// openPinPlanReader is the plan reader of storage deploy and storage key pin
// when a command's own is unset (A23-20): openReaderDefault, the instance's
// cluster as its reader, never the writer. A refusal returns a nil reader,
// never a nil *cluster.Client inside a non-nil one.
func openPinPlanReader(r clusterRef) (pinPlanReader, error) {
	cl, err := openReaderDefault(r)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// pinStoreOpener reaches an instance's pin. A seam, so a test reaches a fake.
type pinStoreOpener func(clusterRef) (pinStore, error)

// defaultPinStore is what a command without its own seam uses. Tests replace
// it, so that no test reaches a cluster it did not set up.
var defaultPinStore pinStoreOpener = openPinStore

// openPinStore reaches the pin in-process as the instance's writer, the
// installer's stored service-account key (ADR 0023 M2.5): its read, create
// and replace need no kubectl. Every refusal openCluster makes is local and
// sends nothing.
func openPinStore(r clusterRef) (pinStore, error) {
	cl, err := openWriter(r)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// scopeKEKs is one scope's key-encryption keys, the active one first (ADR
// 0023 M2.6, A23-32): what the pin a keyring implies, the keys a replica
// holds once it holds the keyring, and the verdict of a pin on the keyring
// are computed from, so a plan computes them alike from a keyring it read
// and from the one a deploy will mint, which has no scopes.
type scopeKEKs struct {
	Name string
	KEKs []datasphere.KeyEntry
}

// kekLists is a keyring's scopes as scopeKEKs, in its order.
func kekLists(k datasphere.Keyring) []scopeKEKs {
	scopes := k.Scopes()
	lists := make([]scopeKEKs, 0, len(scopes))
	for _, s := range scopes {
		lists = append(lists, scopeKEKs{Name: s.Name, KEKs: s.Keyring().KEKs()})
	}
	return lists
}

// pinFor is the pin a keyring implies (pinOfKEKs).
func pinFor(k datasphere.Keyring) dskeyholder.Pin {
	return pinOfKEKs(kekLists(k))
}

// pinOfKEKs is the pin the key lists imply. Require is every key-encryption
// key of every scope; Retired is, per scope, each key created strictly
// before the one the scope writes under — the same reliance on Created the
// hand-over already has, and keys created in the same second are never
// retired, which is the safe direction. The instance's own key space is
// never in a bundle, so never in the pin.
func pinOfKEKs(lists []scopeKEKs) dskeyholder.Pin {
	var p dskeyholder.Pin
	for _, s := range lists {
		if len(s.KEKs) == 0 {
			continue
		}
		active := s.KEKs[0]
		for _, e := range s.KEKs {
			p.Require = append(p.Require, e.ID)
			if e.Created.Before(active.Created) {
				p.Retired = append(p.Retired, e.ID)
			}
		}
	}
	return p
}

// heldOf is what a replica reports once it holds the key lists: scope name
// to the hex IDs of every KEK the scope holds, the active one first.
func heldOf(lists []scopeKEKs) map[string][]string {
	out := make(map[string][]string, len(lists))
	for _, s := range lists {
		ids := make([]string, len(s.KEKs))
		for i, e := range s.KEKs {
			ids[i] = e.ID.String()
		}
		out[s.Name] = ids
	}
	return out
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

// pinVerdict compares a keyring with a pin (verdictOf).
func pinVerdict(cur dskeyholder.Pin, k datasphere.Keyring) *pinBehind {
	return verdictOf(cur, kekLists(k))
}

// verdictOf compares key lists with a pin: what the pin requires that they
// lack, and which keys they write under that the pin retired.
func verdictOf(cur dskeyholder.Pin, lists []scopeKEKs) *pinBehind {
	held := map[datasphere.KeyID]bool{}
	var active []datasphere.KeyID
	for _, s := range lists {
		for i, e := range s.KEKs {
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
func readPin(ctx context.Context, ps pinPlanReader) (pin dskeyholder.Pin, present bool, version string, invalid error, err error) {
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

// pinWrite is what a pin write did (writePinLoop, writePinOnce, pinOnDeploy).
type pinWrite struct {
	Pin     dskeyholder.Pin
	Changed bool
	// Repaired is set when the pin that was there could not be read, and was
	// rewritten from this keyring.
	Repaired bool
	// Created is set when there was no pin — no ConfigMap, or an empty one —
	// and one was written. That is not a raise, and is not reported as one.
	Created bool
}

// pinMethodNone is a pin decision that writes nothing: the pin there is
// already the one decided (A23-42).
const pinMethodNone = "none"

// pinDecision is the pin a write leaves, decided from the pin read and the
// keyring before anything is written (ADR 0023 M2.6, A23-42): what a plan
// binds as its pin fact and its pin write, what --confirm writes once
// (writePinOnce), and what the loop of an interactive or --yes run writes on
// each attempt (writePinLoop).
type pinDecision struct {
	// pin is the pin written, or the one there when nothing is.
	pin dskeyholder.Pin
	// method is plan.WriteCreate (no ConfigMap), plan.WriteReplace (at rv,
	// the resourceVersion the pin was read at) or pinMethodNone.
	method, rv string
	// created is set when there was no pin — no ConfigMap, or an empty one —
	// and one is written; repaired when the one there could not be read, and
	// is rewritten.
	created, repaired bool
}

// writes reports whether the decision writes the pin.
func (d pinDecision) writes() bool { return d.method != pinMethodNone }

// written is the decision as pinWrite reports it once its write landed.
func (d pinDecision) written() pinWrite {
	return pinWrite{Pin: d.pin, Changed: true, Repaired: d.repaired, Created: d.created}
}

// writeMethod is the write of a pin read at rv: a create over "absent" (""),
// a replace at the version read otherwise, so another writer in between is a
// conflict and never an overwrite.
func writeMethod(rv string) string {
	if rv == "" {
		return plan.WriteCreate
	}
	return plan.WriteReplace
}

// decidePin is the pin a keyring's key lists leave on the instance, given
// the pin read (cur, present, rv, invalid; readPin): everything they hold
// required, and — withRetired — every key older than a scope's active one
// retired. It only ever raises: a readable pin is unioned in, and lists it
// already refuses are pinBehind, with nothing decided; replace decides
// exactly the lists' pin regardless, which is the operator lowering it
// deliberately. A pin that refuses the lists themselves, or that no replica
// could read, is refused too. It is pure: it reads and writes nothing.
func decidePin(cur dskeyholder.Pin, present bool, rv string, invalid error, lists []scopeKEKs, withRetired, replace bool) (pinDecision, error) {
	mine := pinOfKEKs(lists)
	desired := dskeyholder.Pin{Require: mine.Require}
	if withRetired {
		desired.Retired = mine.Retired
	}
	if present && invalid == nil && !replace {
		if b := verdictOf(cur, lists); b != nil {
			return pinDecision{}, b
		}
		desired = desired.Union(dskeyholder.Pin{Require: cur.Require, Retired: cur.Retired})
		if desired.Equal(cur) {
			return pinDecision{pin: cur, method: pinMethodNone, rv: rv}, nil
		}
	}
	// Never ahead: everything this machine pushes next must pass it.
	if err := desired.Admits(heldOf(lists)); err != nil {
		return pinDecision{}, fmt.Errorf("the key pin this keyring implies refuses the keyring itself, so it was not written: %w", err)
	}
	// And never one a replica cannot read: an oversize pin is refused by
	// every replica as unreadable, which turns every keeper away.
	if n := len(desired.Marshal()); n > dskeyholder.MaxPinBytes {
		return pinDecision{}, fmt.Errorf("the key pin would be %d bytes, more than the %d a replica reads — this keyring holds %d key-encryption keys; "+
			"nothing was written", n, dskeyholder.MaxPinBytes, len(desired.Require))
	}
	return pinDecision{pin: desired, method: writeMethod(rv), rv: rv, created: !present && invalid == nil, repaired: invalid != nil}, nil
}

// emptyPinDecision is storage deploy's pin with no keyring on this machine
// (a bucket recorded and no keys.yaml, pinOnDeploy's first branch): a pin
// that is there and readable is kept, whatever it requires, and otherwise
// the empty pin is written, so the ConfigMap is this machine's.
func emptyPinDecision(cur dskeyholder.Pin, present bool, rv string, invalid error) pinDecision {
	if present && invalid == nil {
		return pinDecision{pin: cur, method: pinMethodNone, rv: rv}
	}
	return pinDecision{pin: dskeyholder.Pin{}, method: writeMethod(rv), rv: rv, repaired: invalid != nil}
}

// pinDocument is pin's ConfigMap at rv: the body of its create, or of its
// replace at that resourceVersion.
func pinDocument(pin dskeyholder.Pin, rv string) ([]byte, error) {
	return dsdeploy.RenderPin(dsdeploy.DefaultNamespace, dsdeploy.DefaultName, pin.Marshal(), rv)
}

// writePinAt writes pin read at rv: a create when rv is "", a replace at rv
// otherwise (writeMethod).
func writePinAt(ctx context.Context, ps pinStore, pin dskeyholder.Pin, rv string) error {
	manifest, err := pinDocument(pin, rv)
	if err != nil {
		return err
	}
	if writeMethod(rv) == plan.WriteCreate {
		return ps.CreateConfigMap(ctx, manifest)
	}
	return ps.ReplaceConfigMap(ctx, manifest)
}

// writePinLoop raises the instance's pin to this keyring (decidePin), for an
// interactive or --yes run: it reads the pin, decides, and writes, and on a
// failed write re-reads — a write that landed and lost its answer is
// success, and a conflict is another writer to take into account — and tries
// again, a bounded number of times, unioning with whatever that writer
// raised.
func writePinLoop(ctx context.Context, ps pinStore, k datasphere.Keyring, withRetired, replace bool) (pinWrite, error) {
	lists := kekLists(k)
	var lastErr error
	for range 3 {
		cur, present, rv, invalid, err := readPin(ctx, ps)
		if err != nil {
			return pinWrite{}, err
		}
		dec, err := decidePin(cur, present, rv, invalid, lists, withRetired, replace)
		if err != nil {
			return pinWrite{}, err
		}
		if !dec.writes() {
			return pinWrite{Pin: dec.pin}, nil
		}
		if lastErr = writePinAt(ctx, ps, dec.pin, dec.rv); lastErr == nil {
			return dec.written(), nil
		}
		// Re-read: a write that landed and lost its answer is success, and a
		// conflict is another writer to take into account.
		if again, ok, _, inv, err := readPin(ctx, ps); err == nil && ok && inv == nil && again.Equal(dec.pin) {
			return dec.written(), nil
		}
	}
	return pinWrite{}, fmt.Errorf("the key pin changed while this command wrote it, or could not be written: %w", lastErr)
}

// msgPinChanged is --confirm's refusal when the pin is not the one its plan
// read (A23-23 step 4, A23-42): a writer's read after the comparison that
// finds it moved, and a write at the planned version that conflicts.
const msgPinChanged = "the instance's key pin changed since the plan was made; nothing was written over it; " + msgPlanAgain

// writePinOnce writes the planned pin once, at the resourceVersion the plan
// read it at, for --confirm (ADR 0023 M2.6, A23-42): a create when rv is "",
// a replace at rv otherwise, with no union and no retry. A failed write is
// read again: a present, readable pin equal to the planned one is a write
// that landed and lost its answer, and counts as written; a conflict
// (tkube.ErrConflict, AlreadyExists or a stale resourceVersion) is another
// writer, and is plan_changed (msgPinChanged), with nothing written over it;
// any other failure keeps its own kind.
func writePinOnce(ctx context.Context, ps pinStore, planned dskeyholder.Pin, rv string) (pinWrite, error) {
	err := writePinAt(ctx, ps, planned, rv)
	if err == nil {
		return pinWrite{Pin: planned, Changed: true}, nil
	}
	if again, ok, _, inv, rerr := readPin(ctx, ps); rerr == nil && ok && inv == nil && again.Equal(planned) {
		return pinWrite{Pin: planned, Changed: true}, nil
	}
	if errors.Is(err, tkube.ErrConflict) {
		return pinWrite{}, withKind(kindPlanChanged, errors.New(msgPinChanged))
	}
	return pinWrite{}, fmt.Errorf("write the key pin: %w", err)
}

// pinOnce is a planned pin decision executed under --confirm: written once
// (writePinOnce), or, when the plan writes none, nothing.
func pinOnce(ctx context.Context, ps pinStore, dec pinDecision) (pinWrite, error) {
	if !dec.writes() {
		return pinWrite{Pin: dec.pin}, nil
	}
	w, err := writePinOnce(ctx, ps, dec.pin, dec.rv)
	if err != nil {
		return pinWrite{}, err
	}
	w.Repaired, w.Created = dec.repaired, dec.created
	return w, nil
}

// checkPlannedPin is --confirm's read of the pin as the writer, right after
// the comparison and the writer's open, before anything irreversible (ADR
// 0023 M2.6, A23-23 step 4): a plan that writes the pin requires it still
// at the version the plan read ("" for none there), and one that writes none
// requires the pin there, readable and equal to the plan's. Otherwise it
// refuses, plan_changed, with nothing written (msgPinChanged).
func checkPlannedPin(ctx context.Context, ps pinPlanReader, dec pinDecision) error {
	cur, present, rv, invalid, err := readPin(ctx, ps)
	if err != nil {
		return err
	}
	if dec.writes() && rv == dec.rv {
		return nil
	}
	if !dec.writes() && present && invalid == nil && cur.Equal(dec.pin) {
		return nil
	}
	return withKind(kindPlanChanged, errors.New(msgPinChanged))
}

// keyIDStrings is ids as a plan binds them: 16 hex characters each, in the
// order the pin is written in (sorted, each once).
func keyIDStrings(ids []datasphere.KeyID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// pinFacts are a plan's pin fact for the decision, and, when it writes the
// pin, the pin's write: a create, or a replace at the resourceVersion read,
// whose sha256 is the ConfigMap's as it would be sent (A23-42, A23-44).
// lowering holds the ids the pin no longer requires or retires (A23-32),
// none when it only rises.
func pinFacts(dec pinDecision, lowering []string) ([]plan.Fact, error) {
	facts := []plan.Fact{plan.PinFact{
		Type: plan.TypePin, Require: keyIDStrings(dec.pin.Require), Retired: keyIDStrings(dec.pin.Retired),
		Lowering: append([]string{}, lowering...), Repairing: dec.repaired,
	}}
	if !dec.writes() {
		return facts, nil
	}
	doc, err := pinDocument(dec.pin, dec.rv)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(doc)
	rv := ""
	if dec.method == plan.WriteReplace {
		rv = dec.rv
	}
	return append(facts, plan.WriteFact{
		Type: plan.TypeWrite, API: "v1", Kind: "ConfigMap", Namespace: dsdeploy.DefaultNamespace, Name: dsdeploy.PinConfigMapName(""),
		Method: dec.method, ResourceVersion: rv, SHA256: hex.EncodeToString(sum[:]),
	}), nil
}

// placeholderEntry is the n-th key-encryption key (from 1) a plan has a
// command mint into scope, whose key list is list (design §9.4, A23-32): the
// placeholder id (placeholderKeyID), created one second after the newest key
// in list, or at the epoch for an empty one. A pin decided over it retires
// every key the scope held, as one decided over the real key does once
// --confirm has waited past the newest (waitPastNewestKey). It holds no key
// material: it is an id and a time, for a plan, and is never saved.
func placeholderEntry(scope string, n int, list []datasphere.KeyEntry) datasphere.KeyEntry {
	created := time.Unix(0, 0).UTC()
	if len(list) > 0 {
		newest := list[0].Created
		for _, e := range list[1:] {
			if e.Created.After(newest) {
				newest = e.Created
			}
		}
		created = newest.Add(time.Second)
	}
	return datasphere.KeyEntry{ID: placeholderKeyID(scope, n), Created: created}
}

// mappedBack is p with every id that ids maps replaced by what it maps to:
// a pin decided over the keys a command minted, as its plan listed it, over
// their placeholder ids (A23-32). --confirm writes a pin only when this
// Equals the pin its plan listed.
func mappedBack(p dskeyholder.Pin, ids map[datasphere.KeyID]datasphere.KeyID) dskeyholder.Pin {
	back := func(in []datasphere.KeyID) []datasphere.KeyID {
		out := make([]datasphere.KeyID, len(in))
		for i, id := range in {
			if to, ok := ids[id]; ok {
				id = to
			}
			out[i] = id
		}
		return out
	}
	return dskeyholder.Pin{Require: back(p.Require), Retired: back(p.Retired)}
}

// msgClockBehind is --confirm's refusal when this machine's clock is more
// than a second behind the newest key of a scope it would mint into (A23-32):
// the scope, and that key's time.
const msgClockBehind = "this machine's clock is behind the newest key in scope %q (%s); nothing was minted"

// waitPastNewestKey is --confirm's wait before it mints into the scopes of
// lists (A23-32): until the second now reads is strictly after the newest
// key's Created in every one of them, at most one second. A key is created
// at the second the clock reads, and a pin retires only the keys created
// strictly before a scope's active one, so a key minted in the second of the
// newest would retire nothing its plan said it retires. A clock further
// behind than a second is refused, before anything is minted (msgClockBehind,
// internal). now and sleep are the command's clock: time.Now and
// sleepContext outside tests.
func waitPastNewestKey(ctx context.Context, now func() time.Time, sleep func(context.Context, time.Duration) error, lists []scopeKEKs) error {
	var newest time.Time
	scope, found := "", false
	for _, s := range lists {
		for _, e := range s.KEKs {
			if !found || e.Created.After(newest) {
				newest, scope, found = e.Created, s.Name, true
			}
		}
	}
	if !found {
		return nil
	}
	past := newest.Truncate(time.Second).Add(time.Second)
	for range 2 {
		wait := past.Sub(now())
		if wait <= 0 {
			return nil
		}
		if wait > time.Second {
			break
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
	return fmt.Errorf(msgClockBehind, scope, newest.UTC().Format(time.RFC3339))
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
			// The error carries the replica's words, and the Note is printed
			// as it is — on stdout by 'storage key pin', and in the warnings
			// of rotate and run — so they go in quoted, as one line.
			rows = append(rows, pinRaise{Ordinal: i, Note: fmt.Sprintf("did not take the pin live (%s); it loads it when it next restarts", terminalText(err.Error()))})
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
	// consent is --plan and --confirm <digest> (ADR 0023 M2.6c).
	consent consentFlags
	// newPinStore and newKeyholder are seams; nil reaches the cluster as the
	// instance's writer, and the tunnel (openKeyholderDefault).
	newPinStore  pinStoreOpener
	newKeyholder keyholderOpener
	// newPlanReader opens what the plan reads the pin through under --plan
	// and --confirm: the instance's reader (ADR 0023 M2.6, A23-20),
	// openPinPlanReader when unset, and never the writer.
	newPlanReader func(clusterRef) (pinPlanReader, error)
	// now is the clock a printed plan is dated by (generated_at).
	now func() time.Time
}

// ensureDefaults sets the seams a test left unset.
func (c *keyPinCommand) ensureDefaults() {
	if c.newKeyholder == nil {
		c.newKeyholder = openKeyholderDefault
	}
	if c.newPlanReader == nil {
		c.newPlanReader = openPinPlanReader
	}
	if c.now == nil {
		c.now = time.Now
	}
}

// openKeyholderDefault is the keyholder opener of the commands that take it
// from here when their seam is unset: storage key pin and storage key rotate
// (ADR 0023 M2.6c). It is openKeyholder, which dials the instance's tunnel;
// a variable, so the package's tests refuse it, and no test dials a carrier
// by leaving the seam unset.
var openKeyholderDefault keyholderOpener = openKeyholder

func (*keyPinCommand) Name() string { return "pin" }
func (*keyPinCommand) Synopsis() string {
	return "Write the in-cluster key pin from this keyring"
}

func (*keyPinCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage key pin <instance> [--replace] [-y] [--plan | --confirm <digest>]

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

The pin is reached in-process, as the instance's installer service account,
with the key 'farcast install --credentials' stored; it needs no kubectl.
Unseal never touches it: 'farcast storage unseal --below-pin' is the way past
a pin that cannot be met, with no cloud access at all.

--plan prints the pin it would write, whether it lowers it and what it
drops, and the ConfigMap write, with the plan's digest, and changes nothing.
It reads the pin and the cluster as the instance's reader, which 'farcast
reader grant' must have verified read-only (there is no fallback to the
installer's account), and the keyring's key ids. A keyring behind the pin is
a block without --replace: the plan says so, and its --confirm refuses it.
Which replicas are handed the pin is decided when the command runs, outside
the plan.

--confirm <digest> does exactly the plan with that digest, asking nothing,
and refuses, having written nothing, if anything it binds has changed since:
it computes the plan again as the reader, opens the writer only after the
comparison, and writes the pin once, at the version the plan read. With
--replace its plan is the consent to lowering the pin, and the replicas found
enforcing another; --yes never covers that in a plan's place.`)
}

func (c *keyPinCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.replace, "replace", false, "lower the pin to this keyring's, after confirmation")
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation --replace asks for")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation --replace asks for")
	c.consent.register(fs)
}

// The texts of storage key pin's refusals and notices (A23-3, A23-44).
const (
	// msgKeyPinBehind is the refusal of a keyring behind the pin without
	// --replace: the verdict, and what fixes it (behindRemedy).
	msgKeyPinBehind = "%v. Nothing was written: lowering the pin would re-admit the bundles it refuses. %s"
	// msgKeyPinLowers is what --replace admits again, said before it lowers
	// the pin, after the verdict's own line.
	msgKeyPinLowers = "--replace lowers the pin to this keyring's. Every bundle that lacks those keys is admitted again,\n" +
		"a lost keeper's included, until a rotation from here raises it."
	// msgKeyPinLowerYes is confirmLower's refusal without a terminal.
	msgKeyPinLowerYes = "refusing to lower the key pin without confirmation; pass --yes" + consentSuffix
	// msgKeyPinHandOver is the notice every plan carries: the hand-over is
	// decided when the command runs.
	msgKeyPinHandOver = "the pin is handed to the keyholder replicas that are serving; which replicas answer is decided when the command runs, outside this plan"
	// msgKeyPinReplaceReplicas is the notice of a plan with --replace
	// (A23-3): its confirmation lowers the replicas found enforcing another.
	msgKeyPinReplaceReplicas = "with --replace, a keyholder replica found enforcing a pin other than this one is handed this one in its place, " +
		"which lowers what it enforces; which replicas are found is decided when the command runs, outside this plan"
)

func (c *keyPinCommand) Run(ctx context.Context, env *Env, args []string) (err error) {
	// A 403 the writer met says whose it was, once (A20-9); one a plan's
	// reader met says so already (A23-22), and writerRefused leaves it.
	var meta *config.InstanceMetadata
	defer func() { err = writerRefused(err, meta) }()
	instance, err := oneInstance("pin", args)
	if err != nil {
		return err
	}
	mode, digest, err := c.consent.mode(c.assumeYes)
	if err != nil {
		return err
	}
	c.ensureDefaults()
	meta, err = env.ConfigDir.LoadInstanceMetadata(instance)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", instance, err)
	}
	if err := recordNamed(meta, instance); err != nil {
		return err
	}
	if meta.Keyholder == nil || !meta.Keyholder.Deployed {
		return fmt.Errorf("instance %q has no keyholder deployed; 'farcast storage deploy %s' writes the pin with it", instance, instance)
	}
	keys, err := keyringOf(env, instance)
	if err != nil {
		return err
	}
	ref := clusterRef{Dir: env.ConfigDir, Meta: meta, Warn: env.Err}
	if mode == consentNone {
		// An interactive or --yes run keeps its loop and its question
		// (A23-44): it writes as the writer, from the pin each attempt reads.
		ref.Identity = kube.Writer
		ps, err := pinStoreFor(c.newPinStore, ref, nil)
		if err != nil {
			return fmt.Errorf("the key pin could not be reached: %w", err)
		}
		return c.writeAsked(ctx, env, meta, keys, ps)
	}

	// --plan and --confirm read the pin as the instance's reader, which
	// 'reader grant' must have verified (A23-21); the writer is never opened
	// for a plan, and under --confirm only after the comparison (A23-23).
	if err := requireGrantedReader(env.ConfigDir, meta, "storage key pin", mode); err != nil {
		return err
	}
	ref.Identity = kube.Reader
	rd, err := c.newPlanReader(ref)
	if err != nil {
		return err
	}
	p, b, err := c.plan(ctx, meta, keys, rd, mode)
	if err != nil {
		return err
	}
	if mode == consentPlan {
		return printPlan(env, b, c.now())
	}
	if err := confirmPlan(b, digest); err != nil {
		return err
	}
	// What the plan says, once, right after the comparison (A23-26).
	if p.warning != "" {
		fprintln(env.Err, p.warning)
	}
	// The writer, after the comparison: its preflight reads farcast-system's
	// uid, which must be the plan's, then the pin, which must be where the
	// plan read it. It applies nothing, so it needs no kubectl.
	ref.Identity = kube.Writer
	ps, err := pinStoreFor(c.newPinStore, ref, nil)
	if err != nil {
		return fmt.Errorf("the key pin could not be reached: %w", err)
	}
	uid, err := preflightUID(ctx, ps)
	if err != nil {
		return err
	}
	if err := confirmedCluster(meta, b, uid); err != nil {
		return err
	}
	if err := checkPlannedPin(ctx, ps, p.pin); err != nil {
		return err
	}
	w, err := pinOnce(ctx, ps, p.pin)
	if err != nil {
		return err
	}
	res := keyPinResult{Instance: instance, Written: w.Changed, Repaired: w.Repaired, Created: w.Created,
		Require: len(w.Pin.Require), Retired: len(w.Pin.Retired)}
	if len(p.lowering) > 0 {
		res.Lowered = p.lowering
	}
	// With --replace, the plan is the consent to lowering the replicas
	// found enforcing another pin (A23-3): nothing is asked.
	return c.handOver(ctx, env, meta, keys, res, w.Pin, false)
}

// writeAsked is an interactive or --yes run, as it has always written the
// pin (A23-44): raised by writePinLoop; from a keyring behind it, refused
// without --replace, and with it lowered once confirmLower agrees; then
// handed to the replicas, any found enforcing another pin lowered under
// --replace once confirmLower agrees again.
func (c *keyPinCommand) writeAsked(ctx context.Context, env *Env, meta *config.InstanceMetadata, keys datasphere.Keyring, ps pinStore) error {
	instance := meta.Name
	res := keyPinResult{Instance: instance}
	w, err := writePinLoop(ctx, ps, keys, true, false)
	var behind *pinBehind
	switch {
	case errors.As(err, &behind) && !c.replace:
		return fmt.Errorf(msgKeyPinBehind, behind, behindRemedy(behind, instance))
	case errors.As(err, &behind):
		fprintln(env.Err, keyPinLowerWarning(behind))
		if ok, perr := c.confirmLower(env); perr != nil || !ok {
			return perr
		}
		if w, err = writePinLoop(ctx, ps, keys, true, true); err != nil {
			return err
		}
		res.Lowered = slices.Concat(behind.Missing, behind.RetiredActive)
	case err != nil:
		return err
	}
	res.Written, res.Repaired, res.Created = w.Changed, w.Repaired, w.Created
	res.Require, res.Retired = len(w.Pin.Require), len(w.Pin.Retired)
	return c.handOver(ctx, env, meta, keys, res, w.Pin, true)
}

// keyPinLowerWarning is what --replace says before it lowers the pin from a
// keyring behind it: the verdict, and what lowering admits again.
func keyPinLowerWarning(behind *pinBehind) string {
	return fmt.Sprintf("%v.\n%s", behind, msgKeyPinLowers)
}

// handOver hands the pin written to every keyholder replica now, and prints
// the result. --replace lowers what the REPLICAS enforce, not only the
// ConfigMap: a replica holds the pin it was last handed until it restarts,
// and one that missed a lowering — or took a higher pin the ConfigMap no
// longer has — keeps refusing this keyring however often the ConfigMap is
// rewritten. ask is false under --confirm, whose plan is the consent to
// lowering them (A23-3), and true otherwise (confirmLower).
func (c *keyPinCommand) handOver(ctx context.Context, env *Env, meta *config.InstanceMetadata, keys datasphere.Keyring, res keyPinResult, pin dskeyholder.Pin, ask bool) error {
	instance := meta.Name
	client, done, kerr := c.newKeyholder(ctx, env, instance)
	if kerr != nil {
		res.Live = fmt.Sprintf("not handed to the replicas live (%v); each loads it when it next restarts", kerr)
		return env.Printer.Print(res)
	}
	defer done()
	replace := res.Lowered != nil
	if c.replace && !replace {
		var above []string
		for i := range replicaCount(meta) {
			st, err := client.State(ctx, i)
			if err != nil || st.Pin == nil || st.Pin.Status != dskeyholder.PinValid {
				continue
			}
			if p, ok := pinFromReport(st.Pin); ok && !p.Equal(pin) {
				above = append(above, fmt.Sprintf("replica %d", i))
			}
		}
		if len(above) > 0 {
			fprintf(env.Err, "%s enforce a pin other than this keyring's. --replace replaces it with this keyring's.\n", strings.Join(above, " and "))
			if ask {
				if ok, err := c.confirmLower(env); err != nil || !ok {
					return err
				}
			}
			replace, res.Lowered = true, above
		}
	}
	res.Replicas = raisePins(ctx, client, replicaCount(meta), pin, replace, instance, heldKeys(keys))
	return env.Printer.Print(res)
}

// preparedKeyPin is every decision storage key pin's --confirm executes,
// made once by its plan (A23-44).
type preparedKeyPin struct {
	pin pinDecision
	// lowering is what --replace drops from a pin this keyring is behind:
	// the keys it lacks, then the retired keys it writes under; none
	// otherwise.
	lowering []string
	// warning is what an interactive run says before it lowers the pin
	// (keyPinLowerWarning), or "".
	warning string
}

// plan is storage key pin's plan (design §9.4, A23-44). It reads the pin and
// farcast-system's uid through rd — the reader under --plan and --confirm,
// its errors the reader's (planRead) — and decides the pin from this
// keyring, as an interactive run's first write would: raised, the union
// with the pin there. A keyring behind the pin blocks it without --replace;
// with --replace the pin is this keyring's own, lowering what the pin
// required or retired that the keyring does not. A pin that refuses the
// keyring itself, or that no replica could read, blocks it too. Its facts
// are the pin, its write when the pin changes, and its notices. It reads no
// terminal and writes nothing.
func (c *keyPinCommand) plan(ctx context.Context, meta *config.InstanceMetadata, keys datasphere.Keyring, rd pinPlanReader, m consentMode) (preparedKeyPin, plan.Bound, error) {
	name := meta.Name
	var p preparedKeyPin
	cur, present, rv, invalid, err := readPin(ctx, rd)
	if err != nil {
		return p, plan.Bound{}, planRead(m, err, name)
	}
	uid, err := rd.NamespaceUID(ctx, dsdeploy.DefaultNamespace)
	if err != nil {
		return p, plan.Bound{}, planRead(m, fmt.Errorf("read the uid of the instance's %s namespace: %w", dsdeploy.DefaultNamespace, err), name)
	}
	b := newBound("storage key pin", meta, "reader", uid)
	b.Options = []plan.Option{{Flag: "replace", Value: strconv.FormatBool(c.replace)}}

	lists := kekLists(keys)
	dec, err := decidePin(cur, present, rv, invalid, lists, true, false)
	var behind *pinBehind
	switch {
	case errors.As(err, &behind) && c.replace:
		p.lowering = slices.Concat(behind.Missing, behind.RetiredActive)
		p.warning = keyPinLowerWarning(behind)
		dec, err = decidePin(cur, present, rv, invalid, lists, true, true)
	case errors.As(err, &behind):
		err = fmt.Errorf(msgKeyPinBehind, behind, behindRemedy(behind, name))
	}
	if err != nil {
		b.Blocked = []plan.Block{blockOf(err)}
		return preparedKeyPin{}, b, nil
	}
	p.pin = dec
	facts, err := pinFacts(dec, p.lowering)
	if err != nil {
		return p, plan.Bound{}, err
	}
	if p.warning != "" {
		facts = append(facts, noticeFact(p.warning))
	}
	facts = append(facts, noticeFact(msgKeyPinHandOver))
	if c.replace {
		facts = append(facts, noticeFact(msgKeyPinReplaceReplicas))
	}
	b.Facts = facts
	return p, b, nil
}

// confirmLower asks before a pin is lowered, unless --yes said so already.
func (c *keyPinCommand) confirmLower(env *Env) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	if env.Printer.Mode != output.ModeHuman || !isTerminal(env.In) {
		return false, usagef(msgKeyPinLowerYes)
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
	Created  bool       `json:"created,omitempty"`
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
	case r.Created:
		fprintf(w, "✓ wrote the key pin of %q from this keyring; there was none\n", r.Instance)
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

// pinOnDeploy is storage deploy's half, in an interactive or --yes run: the
// pin must exist before the replicas start, or TechnoCore — which may create
// ConfigMaps in farcast-system — could create it first. With no keyring yet
// there is nothing to require, and an empty pin is written so the ConfigMap
// is this machine's (emptyPinDecision); with one, the pin is raised to it
// (writePinLoop). Under --confirm the plan's decision is written once
// instead (pinOnce).
func pinOnDeploy(ctx context.Context, ps pinStore, env *Env, instance string) (pinWrite, error) {
	raw, err := env.ConfigDir.LoadInstanceKeyring(instance)
	if err != nil {
		cur, present, rv, invalid, rerr := readPin(ctx, ps)
		if rerr != nil {
			return pinWrite{}, rerr
		}
		dec := emptyPinDecision(cur, present, rv, invalid)
		if !dec.writes() {
			return pinWrite{Pin: dec.pin}, nil
		}
		if err := writePinAt(ctx, ps, dec.pin, dec.rv); err != nil {
			return pinWrite{}, fmt.Errorf("write the key pin: %w", err)
		}
		return dec.written(), nil
	}
	k, err := datasphere.ParseKeyring(raw)
	if err != nil {
		return pinWrite{}, err
	}
	return writePinLoop(ctx, ps, k, true, false)
}

// pinMeta reports whether an instance has a keyholder whose pin to keep.
func pinMeta(meta *config.InstanceMetadata) bool {
	return meta != nil && meta.Keyholder != nil && meta.Keyholder.Deployed
}
