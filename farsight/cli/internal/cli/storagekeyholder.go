package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
)

// The application scope's name and prefix now live in datasphere, so the
// keyring minting that creates the scope and the keyholder that serves it
// cannot disagree about which prefix it owns.
const ()

// keyholderDialer opens the operator's tunnel and returns a client for the
// instance's keyholder replicas.
//
// Every keyholder command goes through here, which is also where the one
// dependency the ADR calls a recovery floor becomes visible: an unseal rides
// FatLine, so an instance whose tunnel is down cannot be unsealed at all.
func keyholderClient(ctx context.Context, env *Env, name string) (*keyholder.Client, func(), error) {
	conn, mtls, err := instanceTunnel(ctx, env, name)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"cannot reach %q through FatLine: %w\n"+
				"Storage cannot be unsealed while the tunnel is down, and applications keep receiving ErrStorageSealed until it returns.\n"+
				"Check 'farcast connect %s --status'.", name, err, name)
	}
	client, err := keyholder.New(keyholder.Conn(conn), name, mtls.CACertPEM, mtls.ClientCertPEM, mtls.ClientKeyPEM)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return client, func() { _ = conn.Close() }, nil
}

// partialFailure turns a fan-out result into an error unless every replica
// answered.
//
// "Most of them worked" is not success for either verb, and the two failures
// are different but equally unacceptable. A partial UNSEAL leaves replicas
// that will serve nothing, so an operator who walked away would find storage
// still broken. A partial SEAL is worse: an operator sealing in response to a
// suspicion must never be told it worked while a replica still holds the keys.
func partialFailure(verb string, done, total int) error {
	if done >= total {
		return nil
	}
	switch verb {
	case "unseal":
		return fmt.Errorf("%d of %d replicas confirmed holding this machine's keys; each other one is listed above with what went wrong", done, total)
	default:
		return fmt.Errorf("%d of %d replicas were sealed; the rest may still hold key material", done, total)
	}
}

// replicaCount reports how many keyholder replicas the operator deployed.
func replicaCount(meta *config.InstanceMetadata) int {
	if meta.Keyholder != nil && meta.Keyholder.Replicas > 0 {
		return meta.Keyholder.Replicas
	}
	return 2
}

// ---------------------------------------------------------------- state

type storageStateCommand struct {
	// newKeyholder reaches the replicas; nil dials them.
	newKeyholder keyholderOpener
}

func (*storageStateCommand) Name() string     { return "state" }
func (*storageStateCommand) Synopsis() string { return "Report each keyholder replica's seal state" }

func (*storageStateCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage state <instance>

Ask every keyholder replica what it is holding.

A replica is either unsealed, restart-sealed, or under an operator hold.
Sealed is a normal state of a healthy instance, not a fault: key material
lives only in memory, so any restart leaves a replica sealed until someone
unseals it. Applications receive ErrStorageSealed meanwhile; nothing is lost.

This reads through the FatLine tunnel and changes nothing.`)
}

func (*storageStateCommand) SetFlags(*flag.FlagSet) {}

func (c *storageStateCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("storage state takes one instance argument")
	}
	name := args[0]
	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if meta.Keyholder == nil || !meta.Keyholder.Deployed {
		return fmt.Errorf("instance %q has no keyholder deployed; run 'farcast storage deploy %s'", name, name)
	}
	open := c.newKeyholder
	if open == nil {
		open = openKeyholder
	}
	client, done, err := open(ctx, env, name)
	if err != nil {
		return err
	}
	defer done()

	// What a serving replica holds is compared with this machine's keyring,
	// when this machine has one. The generation cannot say whether a replica
	// holds the current keys — anything holding a bundle can push one at any
	// generation it likes — but the key IDs can.
	keys, kerr := keyringOf(env, name)
	states := make([]replicaState, 0, replicaCount(meta))
	for i := range replicaCount(meta) {
		st, err := client.State(ctx, i)
		if err != nil {
			states = append(states, replicaState{Ordinal: i, Error: err.Error()})
			continue
		}
		rs := replicaState{
			Ordinal: i, Phase: st.Phase, Since: st.Since,
			Generation: st.Generation, HoldReason: st.HoldReason, Scopes: st.Scopes,
		}
		switch {
		case outdatedImage(st):
			rs.Outdated = true
		case kerr == nil && !st.Sealed():
			v := keysAgainst(st, keys)
			rs.KeysDiffer, rs.KeysBehind = v.note(), v.behind()
			current := rs.KeysDiffer == ""
			rs.KeysCurrent = &current
		}
		states = append(states, rs)
	}
	return env.Printer.Print(stateResult{Instance: name, Replicas: states,
		Recorded: meta.Keyholder.Generation})
}

type replicaState struct {
	Ordinal    int       `json:"ordinal"`
	Phase      string    `json:"phase,omitempty"`
	Since      time.Time `json:"since,omitzero"`
	Generation uint64    `json:"generation,omitempty"`
	HoldReason string    `json:"hold_reason,omitempty"`
	Scopes     []string  `json:"scopes,omitempty"`
	// KeysCurrent reports whether a serving replica holds exactly this
	// machine's keyring, and KeysDiffer how it does not. Absent when it could
	// not be checked.
	KeysCurrent *bool  `json:"keys_current,omitempty"`
	KeysDiffer  string `json:"keys_differ,omitempty"`
	// KeysBehind marks a replica holding keys newer than this machine's
	// keyring, which an unseal from here refuses rather than fixes.
	KeysBehind bool `json:"keys_behind,omitempty"`
	// Outdated marks a replica whose keyholder image cannot say which keys it
	// holds.
	Outdated bool   `json:"outdated,omitempty"`
	Note     string `json:"note,omitempty"`
	Error    string `json:"error,omitempty"`
}

type stateResult struct {
	Instance string         `json:"instance"`
	Recorded uint64         `json:"recorded_generation"`
	Replicas []replicaState `json:"replicas"`
}

func (r stateResult) Human(w io.Writer) error {
	sealed, differ, behind, outdated, foreign := 0, 0, 0, 0, 0
	for _, s := range r.Replicas {
		switch {
		case s.Error != "":
			fprintf(w, "  replica %d  unreachable — %s\n", s.Ordinal, s.Error)
			sealed++
		case s.Phase == "unsealed":
			fprintf(w, "  replica %d  unsealed   generation %d, scopes %s\n",
				s.Ordinal, s.Generation, strings.Join(s.Scopes, ","))
			switch {
			case s.Outdated:
				outdated++
				fprintf(w, "             its keyholder image is older than this CLI and does not say which keys it holds\n")
			case s.KeysDiffer != "":
				differ++
				if s.KeysBehind {
					behind++
				}
				if strings.Contains(s.KeysDiffer, "minted separately") {
					foreign++
				}
				fprintf(w, "             KEYS DIFFER FROM THIS MACHINE'S KEYRING: it %s\n", s.KeysDiffer)
			}
		default:
			reason := s.Phase
			if s.HoldReason != "" {
				reason += " — " + s.HoldReason
			}
			fprintf(w, "  replica %d  %s\n", s.Ordinal, reason)
			sealed++
		}
	}
	if sealed == len(r.Replicas) {
		fprintf(w, "\nEvery replica is sealed: applications are receiving ErrStorageSealed.\n"+
			"Nothing is lost — run 'farcast storage unseal %s' to restore service.\n", r.Instance)
	} else if sealed > 0 {
		fprintf(w, "\n%d of %d replicas are sealed. Storage is serving, with less headroom than it should have.\n",
			sealed, len(r.Replicas))
	}
	if outdated > 0 {
		fprintf(w, "\n%d replica(s) run a keyholder image older than this CLI, so nothing can check what they hold\n"+
			"and 'farcast storage unseal' refuses to push to them. 'farcast storage deploy %s' updates it —\n"+
			"the replicas restart sealed — and then 'farcast storage unseal %s'.\n", outdated, r.Instance, r.Instance)
	}
	switch {
	case foreign > 0:
		fprintf(w, "\n%d replica(s) serve another machine's copy of a scope this machine minted too. Nothing here\n"+
			"reconciles the two: work with that application from the machine that deployed it.\n", foreign)
	case behind > 0:
		fprintf(w, "\n%d replica(s) serve keys this machine's keyring does not have, so 'farcast storage unseal %s'\n"+
			"refuses from here, and says why and what to do. Running it from the machine that changed\n"+
			"the keys works as it is.\n", behind, r.Instance)
	case differ > 0:
		fprintf(w, "\n%d replica(s) serve keys other than this machine's keyring. 'farcast storage unseal %s'\n"+
			"brings them to it. A replica serving keys from before a rotation was given older material:\n"+
			"a hand-over that did not finish, or a lost or revoked keeper.\n", differ, r.Instance)
	}
	return nil
}

// ---------------------------------------------------------------- seal

type storageSealCommand struct {
	hold   bool
	reason string
}

func (*storageSealCommand) Name() string     { return "seal" }
func (*storageSealCommand) Synopsis() string { return "Make the keyholder forget its key material" }

func (*storageSealCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage seal <instance> [--hold] [--reason TEXT]

Make every keyholder replica forget its key material. Applications receive
ErrStorageSealed until it is unsealed again; nothing stored is lost.

Without --hold the replicas land restart-sealed, which a keeper device may
later clear unattended (phase 5.4). With --hold they land under an operator
hold that only an operator can clear.

A hold does NOT survive a restart. Keeping it would need cloud-resident state,
which would serve the very adversary a hold is aimed at — so a replica that
restarts comes back merely restart-sealed, and a keeper could reseed it.`)
}

func (c *storageSealCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.hold, "hold", false, "seal as a deliberate operator hold that no keeper may clear")
	fs.StringVar(&c.reason, "reason", "", "why (recorded in the replica's reported state)")
}

func (c *storageSealCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("storage seal takes one instance argument")
	}
	name := args[0]
	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	client, done, err := keyholderClient(ctx, env, name)
	if err != nil {
		return err
	}
	defer done()

	var failed int
	states := make([]replicaState, 0, replicaCount(meta))
	for i := range replicaCount(meta) {
		st, err := client.Seal(ctx, i, c.hold, c.reason)
		if err != nil {
			failed++
			states = append(states, replicaState{Ordinal: i, Error: err.Error()})
			continue
		}
		states = append(states, replicaState{Ordinal: i, Phase: st.Phase, HoldReason: st.HoldReason})
	}
	if err := env.Printer.Print(sealResult{Instance: name, Hold: c.hold, Replicas: states}); err != nil {
		return err
	}
	return partialFailure("seal", len(states)-failed, len(states))
}

type sealResult struct {
	Instance string         `json:"instance"`
	Hold     bool           `json:"hold"`
	Replicas []replicaState `json:"replicas"`
}

func (r sealResult) Human(w io.Writer) error {
	for _, s := range r.Replicas {
		if s.Error != "" {
			fprintf(w, "  replica %d  NOT SEALED — %s\n", s.Ordinal, s.Error)
			continue
		}
		fprintf(w, "  replica %d  %s\n", s.Ordinal, s.Phase)
	}
	if r.Hold {
		fprintf(w, "\nThis hold lives only until the pod restarts. A restarted replica comes back\n"+
			"restart-sealed, which a keeper device may clear unattended.\n")
	}
	return nil
}

// ---------------------------------------------------------------- unseal

type storageUnsealCommand struct {
	// newKeyholder reaches the replicas; nil dials them.
	newKeyholder keyholderOpener
	unchecked    bool
}

func (*storageUnsealCommand) Name() string     { return "unseal" }
func (*storageUnsealCommand) Synopsis() string { return "Hand the keyholder its key material" }

func (*storageUnsealCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage unseal <instance> [--unchecked]

Hand every keyholder replica the key material for the instance's application
scopes, so applications can read and write again. A replica that is already
serving is brought to this machine's keys.

The push travels through the FatLine tunnel inside its own session that
terminates in the keyholder, and is sealed to one specific replica process
answering a single-use challenge — so it cannot be replayed, cannot be pushed
into another instance, and never exists in FatLine's memory.

Every replica is asked what it holds before anything is pushed. If a serving
replica lacks a key this keyring makes active, every replica is first given
the keys to hold, and only once each confirms is any told to use them — so no
replica ever writes under a key another cannot read. If a serving replica
holds keys this machine's keyring lacks, or uses a newer one, unseal refuses:
this keyring is behind the instance's, and pushing it would take those keys
away.

A replica that does not say what it holds is never pushed, and while one is
silent a SEALED replica is not unsealed either: the silent one may be serving
keys this keyring lacks — another machine's rotation — and a replica unsealed
beside it from this keyring could not read what it writes. --unchecked
unseals the sealed replicas anyway, for when this machine's keyring is known
to be the instance's current one and storage must come back now.

This command changes nothing in the cluster. It deploys nothing, applies
nothing and restarts nothing; if the keyholder is absent it says so and stops.
That separation is deliberate: the command you reach for at 03:00 has one job
and no way to make things worse.`)
}

func (c *storageUnsealCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.unchecked, "unchecked", false, "unseal sealed replicas although another replica did not answer")
}

func (c *storageUnsealCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("storage unseal takes one instance argument")
	}
	name := args[0]
	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if meta.Keyholder == nil || !meta.Keyholder.Deployed {
		return fmt.Errorf(
			"instance %q has no keyholder deployed, so there is nothing to unseal.\n"+
				"Run 'farcast storage deploy %s' first — unseal deliberately changes nothing in the cluster.",
			name, name)
	}

	// The tunnel is reached first, deliberately. An unseal cannot deliver
	// anything without it, and finding that out before touching keys.yaml
	// means a failed recovery leaves the most dangerous file in the system
	// exactly as it was.
	open := c.newKeyholder
	if open == nil {
		open = openKeyholder
	}
	client, done, err := open(ctx, env, name)
	if err != nil {
		return err
	}
	defer done()

	// Unseal reads the keyring and nothing else. It deliberately does NOT
	// resolve the provider or the bucket: recovery must not depend on the
	// cloud being reachable, or on this machine holding cloud credentials at
	// the moment an operator needs storage back.
	raw, err := env.ConfigDir.LoadInstanceKeyring(name)
	if err != nil {
		return fmt.Errorf(
			"instance %q has no keyring on this machine, so there is no key material to hand over: %w\n"+
				"Storage keys live only here. If this machine is not the one that installed the instance, "+
				"import them with 'farcast storage key import'.", name, err)
	}
	keys, err := datasphere.ParseKeyring(raw)
	if err != nil {
		return err
	}

	// Scopes are minted per application by `farcast run`; an unseal hands
	// over what exists and never brings a key space into being as a side
	// effect of recovery. A keyring with no scopes is an instance with no
	// applications, and its bundle is empty rather than refused — that
	// keyholder still unseals, and is ready for the first application.
	res := handOverKeys(ctx, env, meta, reuseKeyholder(client), keys, handOverOptions{unseal: true, unchecked: c.unchecked})
	if res.Problem != "" {
		return fmt.Errorf("nothing was pushed: %s", res.Problem)
	}
	if err := env.Printer.Print(unsealResult{
		Instance: name, Scopes: len(keys.Scopes()), Generation: res.Generation,
		Loaded: len(res.Loaded), Total: res.Total, Replicas: res.Rows, NotYetActive: res.Reason,
	}); err != nil {
		return err
	}
	if res.RecordErr != nil {
		return res.RecordErr
	}
	if !res.Activated {
		took := "every replica took"
		if res.Cause == heldMissed {
			took = fmt.Sprintf("%d of %d replicas took", len(res.Loaded), res.Total)
		}
		return fmt.Errorf("%s this machine's keys to hold, but %s, so none was told to write under the newest yet. "+
			"Nothing is split — each serving replica holds every key the others write under. Run 'farcast storage unseal %s' again once every replica answers",
			took, res.Reason, name)
	}
	if len(res.LeftSealed) > 0 {
		return fmt.Errorf("%d replica(s) were left sealed: another replica did not answer, so whether it serves keys this machine's keyring lacks "+
			"cannot be checked, and a replica unsealed beside it from an older keyring could not read what it writes. "+
			"Run 'farcast storage unseal %s' again once every replica answers — or, if this machine's keyring is known to be the instance's current one, "+
			"with --unchecked to unseal them now", len(res.LeftSealed), name)
	}
	if n := len(res.HeldOnly); n > 0 && len(res.Loaded)+n == res.Total {
		return fmt.Errorf("%d of %d replicas write under this machine's newest keys; the other %d hold them without using them yet, and still read everything. "+
			"Run 'farcast storage unseal %s' again once they answer", len(res.Loaded), res.Total, n, name)
	}
	// A partial unseal is a failure, and the loaded replicas are NOT rolled
	// back: undoing them would turn a transient network error into an outage.
	return partialFailure("unseal", len(res.Loaded), res.Total)
}

type unsealResult struct {
	Instance   string         `json:"instance"`
	Scopes     int            `json:"scopes"`
	Generation uint64         `json:"generation"`
	Loaded     int            `json:"loaded"`
	Total      int            `json:"total"`
	Replicas   []replicaState `json:"replicas"`
	// NotYetActive says why the replicas hold this keyring's newest keys
	// without writing under them.
	NotYetActive string `json:"not_yet_active,omitempty"`
}

func (r unsealResult) Human(w io.Writer) error {
	for _, s := range r.Replicas {
		switch {
		case s.Error != "":
			fprintf(w, "  replica %d  NOT UNSEALED — %s\n", s.Ordinal, s.Error)
		case s.Note != "":
			fprintf(w, "  replica %d  %s — %s\n", s.Ordinal, s.Phase, s.Note)
		default:
			fprintf(w, "  replica %d  %s   generation %d\n", s.Ordinal, s.Phase, s.Generation)
		}
	}
	switch r.Scopes {
	case 0:
		// Not a failure. A keyholder with no application scopes is an
		// instance with no applications: it unseals, becomes ready, and holds
		// the first scope the moment `farcast run` mints one.
		fprintf(w, "\n%d of %d replicas are unsealed at generation %d, holding no application scopes:\n",
			r.Loaded, r.Total, r.Generation)
		fprintf(w, "this instance has no applications yet. 'farcast run' mints a scope for each one.\n")
	default:
		fprintf(w, "\n%d of %d replicas hold %d application scope(s) at generation %d.\n",
			r.Loaded, r.Total, r.Scopes, r.Generation)
	}
	if r.NotYetActive != "" {
		fprintf(w, "They do not write under this keyring's newest keys yet: %s.\n", r.NotYetActive)
	}
	fprintf(w, "Key material is held in RAM only: any restart seals that replica again.\n")
	return nil
}

// keyholderOpener reaches an instance's keyholder replicas. It is a seam so a
// hand-over can be tested without a tunnel.
type keyholderOpener func(ctx context.Context, env *Env, instance string) (sealStateClient, func(), error)

func openKeyholder(ctx context.Context, env *Env, instance string) (sealStateClient, func(), error) {
	return keyholderClient(ctx, env, instance)
}

// reuseKeyholder hands a hand-over a client the caller already opened, and
// leaves closing it to the caller.
func reuseKeyholder(client sealStateClient) keyholderOpener {
	return func(context.Context, *Env, string) (sealStateClient, func(), error) { return client, func() {}, nil }
}

// handOverStep is one push of a keyring to the fleet, replica by replica.
type handOverStep struct {
	Generation uint64
	// Loaded hold exactly the keys that were sent.
	Loaded []int
	// Waiting are sealed and were left alone — by a hand-over, never by an
	// unseal. The next 'storage unseal' brings them up to date.
	Waiting []int
	// Unreached did not answer.
	Unreached []int
	// Refused declined the push, or accepted it without installing the keys.
	Refused []int
	// Rows is each replica's line, for a command that prints them.
	Rows []replicaState
}

// everyServingReplicaHolds reports whether every replica that could serve an
// application took this step. A sealed one serves nothing, so it does not
// count against it.
func (s handOverStep) everyServingReplicaHolds() bool {
	return len(s.Unreached) == 0 && len(s.Refused) == 0
}

// handOverResult is what a hand-over did.
type handOverResult struct {
	// Problem is set when nothing was pushed at all: the keyholder could not
	// be reached, or — Unsafe — this keyring cannot be safely pushed to what
	// the replicas serve, which an unseal would refuse just the same.
	Problem string
	Unsafe  bool
	Total   int
	// handOverStep is the last push made: the keyring itself, or — when
	// Activated is false — the one that gave the replicas its keys to hold.
	handOverStep
	// Held is the first of two pushes, when the keyring made some scope
	// active on a key a serving replica did not hold: every replica was given
	// the keys to hold before any was told to use them. Nil when one push did.
	Held *handOverStep
	// Activated reports whether the keyring itself was pushed. When it was
	// not, Cause says which of the held* reasons stopped it and Reason says
	// it in words.
	Activated bool
	Cause     string
	Reason    string
	// HeldOnly took the held keys and then missed the push that would have
	// had them use the newest: serving, reading everything, and writing under
	// an older key until the next unseal reaches them.
	HeldOnly []int
	// RecordErr is set when a replica took a generation and recording it on
	// this machine failed.
	RecordErr error
	// ForeignCopy is set when a serving replica holds another machine's
	// copy of a scope this keyring holds — minted twice.
	ForeignCopy bool
	// Unconfirmed refused the keyring itself and then did not say what it
	// holds, so whether the push landed is not known.
	Unconfirmed []int
	// LeftSealed are sealed replicas an unseal did not unseal, because
	// another replica did not answer and could not be checked against.
	LeftSealed []int
}

// Why a hand-over that held its new keys back did not go on to use them.
const (
	// heldMissed: a serving replica did not take the held keys.
	heldMissed = "missed"
	// heldNoneServing: no replica took them, every one being sealed — and
	// with none serving, nothing would stop a keeper re-seeding the keys from
	// before.
	heldNoneServing = "none-serving"
	// heldChanged: asked again, a serving replica no longer held them.
	heldChanged = "changed"
	// heldUnrecorded: this machine could not record them as in use.
	heldUnrecorded = "unrecorded"
)

// Complete reports whether every replica now holds, and uses, the keys sent.
func (r handOverResult) Complete() bool {
	return r.Problem == "" && r.Activated && len(r.Loaded) == r.Total
}

// handOverOptions is what makes one hand-over differ from another.
type handOverOptions struct {
	// unseal pushes every replica, sealed or not, as an operator unseal.
	// Without it only a serving replica is pushed, with the hand-over intent,
	// which a sealed one refuses: pushing a bundle to a sealed keyholder IS an
	// unseal, and a deploy or a rotation must never perform one.
	unseal bool
	// rotated names scopes whose active key a rotation just minted, each
	// with the key that was in use before it. Each goes over held-but-unused
	// first even where no serving replica would notice the difference: a
	// replica that did not answer might be serving, and cannot hold a key
	// minted a moment ago.
	rotated map[string]datasphere.KeyID
	// beforeHold runs before the first push of a held keyring, with that
	// keyring. What the replicas are about to write under is what this
	// machine must write under too, so a rotation saves it here.
	beforeHold func(held datasphere.Keyring) error
	// beforeActivate runs once every replica holds every key the keyring
	// makes active, and before any is told to use one. A rotation saves its
	// keyring here: until then this machine's own writes must stay under a
	// key every replica holds.
	beforeActivate func() error
	// unchecked lets an unseal unseal a sealed replica although another
	// replica did not answer — the operator's override, naming the risk.
	unchecked bool
}

// handOverKeys gives the keyholder fleet a keyring without ever leaving one
// replica writing under a key another cannot read.
//
// It is what 'farcast run' (a new application's scope), 'farcast storage key
// rotate' (new keys) and 'farcast storage unseal' (whatever this machine
// holds) all do, and it has to get four things right that each of them once
// got wrong on its own:
//
//   - Nothing is pushed blind. Every replica is asked what it holds first,
//     and a keyring that is behind what a serving replica holds — keys or a
//     scope it lacks, or an older key active — is refused: pushing it would
//     take keys away from a replica that is using them.
//
//   - No replica is told to write under a key another serving replica lacks.
//     Replicas are pushed one at a time and any of them can fail, so a key
//     that is new to the fleet goes over in two pushes: the keyring with that
//     key held but not active, and — only if every serving replica took that,
//     and still holds it when asked again — the keyring itself. If the second
//     push then reaches only some replicas, every replica holds both keys and
//     reads everything any of them wrote.
//
//   - A strictly fresh generation each push. A replica that already holds a
//     generation treats the same number again as a retry and installs
//     nothing, while answering success. The generation clears both the record
//     and every replica's own report, and is recorded whenever any replica
//     takes it.
//
//   - Proof, not a status code. A replica counts as loaded only if the keys
//     it reports afterwards are the ones it was sent.
func handOverKeys(ctx context.Context, env *Env, meta *config.InstanceMetadata, open keyholderOpener, keys datasphere.Keyring, opts handOverOptions) (res handOverResult) {
	if open == nil {
		open = openKeyholder
	}
	res.Total = replicaCount(meta)

	client, done, err := open(ctx, env, meta.Name)
	if err != nil {
		res.Problem = fmt.Sprintf("the keyholder could not be reached: %v", err)
		return res
	}
	defer done()

	h := &handOver{ctx: ctx, env: env, meta: meta, client: client, opts: opts, total: res.Total,
		highest: meta.Keyholder.Generation}
	defer h.record(&res)
	defer func() { res.LeftSealed = h.leftSealed }()

	states := h.read()
	plan, err := planHandOver(meta.Name, keys, states, opts.rotated)
	if err != nil {
		var fc foreignCopy
		res.Problem, res.Unsafe, res.ForeignCopy = err.Error(), true, errors.As(err, &fc)
		return res
	}
	// An unseal unseals a sealed replica only when every other replica could
	// be checked. One that did not answer may be serving keys this keyring
	// lacks — another machine's rotation — and a replica unsealed beside it
	// from this keyring would split from it. The keeper holds back for the
	// same reason; an operator may say otherwise.
	h.leaveSealed = opts.unseal && len(h.unanswered) > 0 && !opts.unchecked
	if plan.held != nil {
		if opts.beforeHold != nil {
			if err := opts.beforeHold(*plan.held); err != nil {
				res.Problem = fmt.Sprintf("this machine could not record the keys it was about to hand over: %v", err)
				return res
			}
		}
		step, err := h.push(*plan.held, states)
		if err != nil {
			res.Problem = err.Error()
			return res
		}
		res.handOverStep, res.Held = step, &step
		switch {
		case !step.everyServingReplicaHolds():
			res.Cause = heldMissed
			res.Reason = fmt.Sprintf("%d replica(s) did not take them", len(step.Unreached)+len(step.Refused))
			return res
		case len(step.Loaded) == 0:
			// A keeper re-seeds a restarted replica unless a SERVING one
			// holds a key its bundle lacks. With none serving there is
			// nothing to stop it putting the old keys back — so this machine
			// must not start writing under the new ones.
			res.Cause = heldNoneServing
			res.Reason = "every replica is sealed, so none holds them"
			return res
		}
		// Asked again, because a replica can restart between the two pushes
		// and be re-seeded — by a keeper, with older keys — before the second
		// one tells the others to use a key it no longer holds.
		h.second = true
		states = h.read()
		again, err := planHandOver(meta.Name, keys, states, nil)
		silentNew := -1
		for i, st := range states {
			if st == nil && !slices.Contains(res.Held.Loaded, i) {
				silentNew = i
				break
			}
		}
		switch {
		case !slices.ContainsFunc(states, func(st *keyholder.State) bool { return st != nil }):
			res.Cause = heldMissed
			res.Reason = "no replica answered when they were to be used"
			return res
		case !slices.ContainsFunc(states, func(st *keyholder.State) bool { return st != nil && !st.Sealed() }):
			// Every replica that took them restarted before they were to be
			// used: the same reason not to as above.
			res.Cause = heldNoneServing
			res.Reason = "every replica was sealed by the time they were to be used"
			return res
		case silentNew >= 0:
			// It never took them — it was sealed, or silent, at the first
			// push — and it may have been re-seeded since, from a bundle
			// without them. Nothing about it is known, which is no ground
			// for using a key it cannot hold.
			res.Cause = heldMissed
			res.Reason = fmt.Sprintf("replica %d, which never took them, did not answer when they were to be used", silentNew)
			return res
		case err != nil:
			res.Cause, res.Reason = heldChanged, err.Error()
			return res
		case again.held != nil:
			res.Cause = heldChanged
			res.Reason = fmt.Sprintf("by the time they were to be used, a serving replica no longer held %s's", strings.Join(again.scopes, ", "))
			return res
		}
	}
	if opts.beforeActivate != nil {
		if err := opts.beforeActivate(); err != nil {
			res.Cause = heldUnrecorded
			res.Reason = fmt.Sprintf("this machine could not save its keyring with them in use: %v", err)
			return res
		}
	}
	step, err := h.push(keys, states)
	if err != nil {
		if plan.held == nil {
			res.Problem = err.Error()
		} else {
			res.Cause, res.Reason = heldUnrecorded, err.Error()
		}
		return res
	}
	res.handOverStep, res.Activated = step, true
	h.confirmRefused(&res, keys)
	if res.Held != nil {
		// A replica that took the held keys and then missed this push is
		// serving them — not unsealed-or-not as this push alone would say.
		for i, row := range res.Rows {
			st := states[row.Ordinal]
			if row.Error == "" || st == nil || st.Sealed() || !slices.Contains(res.Held.Loaded, row.Ordinal) {
				continue
			}
			res.HeldOnly = append(res.HeldOnly, row.Ordinal)
			res.Rows[i] = replicaState{Ordinal: row.Ordinal, Phase: "unsealed",
				Note: "holds this machine's keys, still writing under an older one (" + row.Error + ")"}
		}
	}
	return res
}

// handOver is one hand-over in progress.
type handOver struct {
	ctx    context.Context
	env    *Env
	meta   *config.InstanceMetadata
	client sealStateClient
	opts   handOverOptions
	total  int
	// highest is the highest generation any replica reported or was sent;
	// taken is the highest one a replica installed.
	highest, taken uint64
	// unanswered is why each replica that did not answer the last read
	// did not.
	unanswered map[int]error
	// second marks the read after a held push.
	second bool
	// leaveSealed keeps an unseal from unsealing a sealed replica, and
	// leftSealed is each one it kept sealed.
	leaveSealed bool
	leftSealed  []int
}

// confirmRefused asks each replica that refused the keyring itself what it
// holds. A push can land and its answer be lost; counted as refused, a
// rotation would put this machine back on keys a replica already uses.
func (h *handOver) confirmRefused(res *handOverResult, keys datasphere.Keyring) {
	want := heldKeys(keys)
	for _, i := range slices.Clone(res.Refused) {
		st, err := h.client.State(h.ctx, i)
		switch {
		case err != nil:
			res.Unconfirmed = append(res.Unconfirmed, i)
		case !st.Sealed() && sameKeys(st.Keys, want):
			res.Refused = slices.DeleteFunc(res.Refused, func(r int) bool { return r == i })
			res.Loaded = append(res.Loaded, i)
			slices.Sort(res.Loaded)
			h.taken = max(h.taken, st.Generation)
			for j, row := range res.Rows {
				if row.Ordinal == i {
					res.Rows[j] = replicaState{Ordinal: i, Phase: st.Phase, Generation: st.Generation, Scopes: st.Scopes}
				}
			}
		}
	}
}

func (h *handOver) warn(format string, args ...any) {
	// An unseal prints every replica's row instead.
	if !h.opts.unseal {
		fprintf(h.env.Err, format, args...)
	}
}

// read asks every replica what it holds. A replica that does not answer is
// nil.
func (h *handOver) read() []*keyholder.State {
	states := make([]*keyholder.State, h.total)
	h.unanswered = map[int]error{}
	for i := range h.total {
		st, err := h.client.State(h.ctx, i)
		if err != nil {
			if h.second {
				h.warn("warning: keyholder replica %d did not answer when asked again: %v\n", i, err)
			} else {
				h.warn("warning: keyholder replica %d did not answer, so it is not handed the keys: %v\n", i, err)
			}
			h.unanswered[i] = err
			continue
		}
		states[i] = &st
		h.highest = max(h.highest, st.Generation)
	}
	return states
}

// push sends one keyring to every replica it may reach, at a generation none
// of them has seen.
func (h *handOver) push(keys datasphere.Keyring, states []*keyholder.State) (handOverStep, error) {
	h.highest++
	step := handOverStep{Generation: h.highest}
	// The bundle is built from COPIES. A bundle shares its scopes' key bytes,
	// and wiping it afterwards wipes them wherever else they live — here, in
	// the keyring the next push sends and a rotation then saves. Without the
	// copy the second push of a hand-over carries zeroed keys, and the
	// operator's own keyring is written to disk with them.
	scopes := keys.Scopes()
	for i := range scopes {
		scopes[i] = scopes[i].Clone()
	}
	bundle, err := datasphere.NewBundle(h.meta.Name, step.Generation, scopes)
	if err != nil {
		for _, sc := range scopes {
			sc.Zero()
		}
		return step, err
	}
	defer bundle.Zero()
	payload, err := bundle.Marshal()
	if err != nil {
		return step, err
	}
	defer clear(payload)
	want := heldKeys(keys)
	intent := keyholder.IntentHandOver
	if h.opts.unseal {
		intent = keyholder.IntentOperator
	}

	ledgerPath := h.env.ConfigDir.InstanceUnsealLedgerPath(h.meta.Name)
	for i, st := range states {
		// Never pushed blind, not even by an unseal. A replica that did not
		// say what it holds could be serving keys this keyring lacks, and an
		// operator push replaces everything a replica holds.
		if st == nil {
			step.Unreached = append(step.Unreached, i)
			step.Rows = append(step.Rows, replicaState{Ordinal: i,
				Error: fmt.Sprintf("did not say what it holds (%v), so it was not pushed", h.unanswered[i])})
			continue
		}
		// A hand-over pushes only what it saw serving; an unseal, every
		// replica that answered — unless one did not.
		if st.Sealed() && (!h.opts.unseal || h.leaveSealed) {
			step.Waiting = append(step.Waiting, i)
			row := replicaState{Ordinal: i, Phase: st.Phase}
			if h.leaveSealed {
				row = replicaState{Ordinal: i, Error: st.Phase + ", and left so: another replica did not answer, so this keyring could not be checked against it"}
				if !slices.Contains(h.leftSealed, i) {
					h.leftSealed = append(h.leftSealed, i)
				}
			}
			step.Rows = append(step.Rows, row)
			continue
		}
		pushed, perr := h.client.Unseal(h.ctx, i, payload, intent)
		entry := keyholder.LedgerEntry{
			Time: time.Now().UTC(), Instance: h.meta.Name, Ordinal: i,
			Intent: intent, Generation: step.Generation, Result: "ok", Boot: st.Boot,
		}
		if pushed.Boot != "" {
			// The process this push landed in. 'keeper status' counts reseeds
			// per DISTINCT process, so an entry with no boot is invisible to
			// exactly the reconstruction an incident needs.
			entry.Boot = pushed.Boot
		}
		switch {
		case !h.opts.unseal && keyholder.NotServing(perr):
			// Sealed between the read and the push, and the keyholder refused
			// to be unsealed by a hand-over — as it must.
			entry.Result = "refused"
			step.Waiting = append(step.Waiting, i)
			step.Rows = append(step.Rows, replicaState{Ordinal: i, Phase: "sealed"})
		case perr != nil:
			entry.Result = "refused"
			h.warn("warning: keyholder replica %d refused the keys: %v\n", i, perr)
			step.Refused = append(step.Refused, i)
			step.Rows = append(step.Rows, replicaState{Ordinal: i, Error: perr.Error()})
		case outdatedImage(pushed):
			// It may well hold them. Nothing can tell, and a hand-over that
			// cannot confirm a replica holds a key must not let another use it.
			entry.Result, entry.Phase = "unverified", pushed.Phase
			why := fmt.Sprintf("took generation %d, but runs a keyholder image too old to report which keys it holds — 'farcast storage deploy %s' updates it",
				step.Generation, h.meta.Name)
			h.warn("warning: keyholder replica %d %s\n", i, why)
			step.Refused = append(step.Refused, i)
			step.Rows = append(step.Rows, replicaState{Ordinal: i, Error: why})
		case !sameKeys(pushed.Keys, want):
			// A 200 that installed nothing is the failure a fresh generation
			// exists to prevent, and it must never read as success.
			entry.Result, entry.Phase = "not-installed", pushed.Phase
			why := fmt.Sprintf("answered generation %d but does not report the keys it was sent", pushed.Generation)
			h.warn("warning: keyholder replica %d %s\n", i, why)
			step.Refused = append(step.Refused, i)
			step.Rows = append(step.Rows, replicaState{Ordinal: i, Error: why})
		default:
			entry.Phase = pushed.Phase
			step.Loaded = append(step.Loaded, i)
			step.Rows = append(step.Rows, replicaState{Ordinal: i, Phase: pushed.Phase,
				Generation: pushed.Generation, Scopes: pushed.Scopes})
			h.taken = max(h.taken, step.Generation)
		}
		// The ledger records where key material went, and this is a place it
		// goes — including a push that was refused. A push nobody wrote down is
		// the one an audit cannot account for later.
		if lerr := keyholder.AppendLedger(ledgerPath, entry); lerr != nil {
			fprintf(h.env.Err, "warning: the unseal ledger could not be written: %v\n", lerr)
		}
	}
	return step, nil
}

// record saves the highest generation a replica took.
//
// Only one a replica actually took. Recording before the push meant an unseal
// that failed on every replica — the keyholder crash-looping without its
// bucket grant, retried by an operator — burned a generation each time and
// left the record describing a handover that never happened (the Phase 4.4
// walk). Recording after can only leave the record BEHIND the cluster, the
// safe direction: the next push reads every replica's own generation first.
func (h *handOver) record(res *handOverResult) {
	if h.taken <= h.meta.Keyholder.Generation {
		return
	}
	h.meta.Keyholder.Generation = h.taken
	h.meta.UpdatedAt = time.Now().UTC()
	if err := h.env.ConfigDir.SaveInstanceMetadata(h.meta.Name, h.meta); err != nil {
		res.RecordErr = fmt.Errorf("the keyholder took generation %d but recording it failed: %w", h.taken, err)
		h.warn("warning: %v\n", res.RecordErr)
	}
}

// handOverPlan is what a hand-over pushes first.
type handOverPlan struct {
	// held is the keyring with some scopes' active key moved back to one
	// every serving replica holds, when the keyring's own cannot be used yet.
	// Nil when the keyring can go over in one push.
	held *datasphere.Keyring
	// scopes are the ones held back.
	scopes []string
}

// planHandOver decides, from what every replica holds, whether this keyring
// may be pushed at all, and whether it has to go over in two pushes.
//
// A replica that did not answer is not consulted: nothing can be. That is
// why a rotation's new keys always go over in two pushes (rotated) — an
// unanswered replica cannot hold a key minted a moment ago — while a keyring
// whose active keys every replica took before is pushed to it in one.
func planHandOver(instance string, keys datasphere.Keyring, states []*keyholder.State, rotated map[string]datasphere.KeyID) (handOverPlan, error) {
	ours := make(map[string]map[string]datasphere.KeyEntry, len(keys.Scopes()))
	for _, s := range keys.Scopes() {
		entries := map[string]datasphere.KeyEntry{}
		for _, e := range s.Keyring().KEKs() {
			entries[e.ID.String()] = e
		}
		ours[s.Name] = entries
	}
	for i, st := range states {
		if st == nil || st.Sealed() {
			continue
		}
		if outdatedImage(*st) {
			return handOverPlan{}, fmt.Errorf("replica %d runs a keyholder older than this CLI: it does not say which keys it holds, "+
				"so nothing can check that a push would leave every replica able to read what the others write. "+
				"Run 'farcast storage deploy %s' to update it — the replicas restart sealed — and then 'farcast storage unseal %s'",
				i, instance, instance)
		}
		for _, name := range slices.Sorted(maps.Keys(st.Keys)) {
			theirs := st.Keys[name]
			mine, ok := ours[name]
			if !ok {
				return handOverPlan{}, keyringBehind(i, behindScope, "serves scope "+name+", which this machine's keyring does not hold", instance)
			}
			if len(theirs) > 0 && !slices.ContainsFunc(theirs, func(id string) bool { _, ok := mine[id]; return ok }) {
				return handOverPlan{}, mintedTwice(i, name)
			}
			for _, id := range theirs {
				if _, ok := mine[id]; !ok {
					return handOverPlan{}, keyringBehind(i, behindKey, fmt.Sprintf("holds key %s for %s, which this machine's keyring does not", id, name), instance)
				}
			}
			if len(theirs) > 0 {
				scope, _ := keys.ScopeNamed(name)
				active := scope.Keyring().KEKs()[0]
				if using := mine[theirs[0]]; using.ID != active.ID && using.Created.After(active.Created) {
					return handOverPlan{}, keyringBehind(i, behindActive, fmt.Sprintf("writes %s under key %s, which is newer than the one this machine's keyring makes active", name, theirs[0]), instance)
				}
			}
		}
	}

	hold := map[string]datasphere.KeyID{}
	var scopes []string
	for _, s := range keys.Scopes() {
		var holders [][]string
		for _, st := range states {
			if st == nil || st.Sealed() {
				continue
			}
			if ids, ok := st.Keys[s.Name]; ok {
				holders = append(holders, ids)
			}
		}
		heldByAll := func(id datasphere.KeyID) bool {
			for _, ids := range holders {
				if !slices.Contains(ids, id.String()) {
					return false
				}
			}
			return true
		}
		inUse := func(id datasphere.KeyID) bool {
			for _, ids := range holders {
				if len(ids) > 0 && ids[0] == id.String() {
					return true
				}
			}
			return false
		}
		keks := s.Keyring().KEKs()
		previous, isRotated := rotated[s.Name]
		if !isRotated && heldByAll(keks[0].ID) {
			continue
		}
		// Meanwhile, a key something already WRITES under — a serving
		// replica, or this machine, whose active key before a rotation went
		// into use only once every replica held it — and every serving
		// replica holds: nothing else is known to be on every replica. A key
		// held but unused may be one an earlier, unfinished rotation gave to
		// some replicas only, and choosing it would make this push the one
		// that puts it in use. Of those, the newest.
		var chosen *datasphere.KeyEntry
		for j := range keks {
			used := inUse(keks[j].ID) || (isRotated && keks[j].ID == previous)
			if heldByAll(keks[j].ID) && used && (chosen == nil || keks[j].Created.After(chosen.Created)) {
				chosen = &keks[j]
			}
		}
		if chosen == nil && len(holders) == 0 && isRotated {
			// No serving replica to ask: the key in use before the rotation.
			for j := range keks {
				if keks[j].ID == previous {
					chosen = &keks[j]
				}
			}
		}
		if chosen == nil {
			return handOverPlan{}, fmt.Errorf("no key that a serving replica writes %s under is held by every other, so there is none they could all safely use. "+
				"'farcast storage seal %s' and then 'farcast storage unseal %s' starts every replica from this machine's keys", s.Name, instance, instance)
		}
		hold[s.Name] = chosen.ID
		scopes = append(scopes, s.Name)
	}
	if len(hold) == 0 {
		return handOverPlan{}, nil
	}
	held, err := keys.WithScopeActive(hold)
	if err != nil {
		return handOverPlan{}, err
	}
	return handOverPlan{held: &held, scopes: scopes}, nil
}

// keyringBehind refuses a push of a keyring older than what a serving replica
// holds.
//
// This machine's keyring is not the only one: another operator machine can
// rotate, or deploy an application, and a copy restored from backup is older
// than the instance it belongs to. Pushing such a keyring takes keys away from
// a replica that is using them — or moves it back onto an older key, one a
// lost keeper may hold — and the generation cannot catch it, because each
// push clears whatever generation the replicas report.
//
// What fixes it depends on what is missing. A scope another machine deployed
// arrives with an import. A key another machine rotated arrives with one too,
// but an import keeps this machine's active key — so after it, this keyring is
// still behind on which key is in use, and only a rotation from here (or the
// command run from the machine that rotated) gets past that.
func keyringBehind(replica int, kind behindKind, what, instance string) error {
	importIt := "'farcast storage key export' on the machine that changed the keys, then 'farcast storage key import' here"
	var consequence, remedy string
	switch kind {
	case behindScope:
		consequence = "take an application's scope away from a replica serving it — everything written under it would become unreadable"
		remedy = "Bring this keyring up to date first: " + importIt
	case behindKey:
		consequence = "take a key away from a replica using it — everything written under it would become unreadable"
		remedy = "Import it first (" + importIt + "). An import keeps this machine's active key, so then either run this from the machine that rotated, " +
			"or run 'farcast storage key rotate " + instance + "' here to move every replica onto a key newer than both"
	default:
		consequence = "move every replica back onto an older key — one a lost keeper may hold"
		remedy = "An import keeps this machine's active key, so it cannot fix this: run this from the machine that rotated, " +
			"or run 'farcast storage key rotate " + instance + "' here to move every replica onto a key newer than both"
	}
	msg := fmt.Sprintf("replica %d %s. This keyring is behind the instance's — another machine rotated or deployed an application, "+
		"or this one was restored or imported from an older copy — and pushing it would %s. %s", replica, what, consequence, remedy)
	if kind != behindActive {
		msg += fmt.Sprintf(". If those keys are gone from every machine, 'farcast storage seal %s' and then an unseal from here is the deliberate way past this, "+
			"and whatever was written under them stays unreadable", instance)
	}
	return errors.New(msg)
}

// mintedTwice refuses a push of a scope a serving replica holds a different
// copy of: two machines each deployed the application before syncing, and
// each minted it. The two copies share no key — and no name key, so objects
// one names the other cannot even find. Nothing on this machine reconciles
// them: an import refuses a scope minted twice, and a rotation here adds a key
// to this machine's copy, not the replicas'.
func mintedTwice(replica int, scope string) error {
	return foreignCopy(fmt.Sprintf("replica %d serves a copy of %s minted separately from this machine's — the two share no key, "+
		"so pushing this one would leave everything written under the replicas' copy unreadable. Neither an import (it refuses a scope minted twice) "+
		"nor a rotation here can reconcile them: run this from the machine that deployed it, whose keyring the replicas serve", replica, scope))
}

// foreignCopy is mintedTwice's refusal, so a caller can tell it from one this
// machine can fix.
type foreignCopy string

func (f foreignCopy) Error() string { return string(f) }

// behindKind is what a keyring behind a serving replica lacks.
type behindKind int

const (
	behindScope  behindKind = iota // a scope
	behindKey                      // a key of a scope it holds
	behindActive                   // nothing, but it uses an older key
)

// outdatedImage reports a serving replica that does not say which keys it
// holds: a keyholder image from before key reporting. Nothing about it can be
// compared, so nothing is planned around it.
func outdatedImage(st keyholder.State) bool {
	return !st.Sealed() && len(st.Scopes) > 0 && st.Keys == nil
}

// heldKeys is what a replica reports once it holds this keyring: scope name
// to the hex IDs of every KEK the scope holds, the active one first.
func heldKeys(k datasphere.Keyring) map[string][]string {
	out := make(map[string][]string, len(k.Scopes()))
	for _, s := range k.Scopes() {
		keks := s.Keyring().KEKs()
		ids := make([]string, len(keks))
		for i, e := range keks {
			ids[i] = e.ID.String()
		}
		out[s.Name] = ids
	}
	return out
}

// sameKeys reports whether a replica holds exactly the keys expected: the
// same scopes, each with the same active key and the same keys behind it.
func sameKeys(got, want map[string][]string) bool {
	return maps.EqualFunc(got, want, scopeKeysMatch)
}

// scopeKeysMatch is sameKeys for one scope. The order behind the active key
// means nothing — a key is found by its ID — but which one is first decides
// every write, and a key missing from the rest is one this replica cannot
// read.
func scopeKeysMatch(got, want []string) bool {
	if len(got) == 0 || len(got) != len(want) || got[0] != want[0] {
		return false
	}
	have := make(map[string]bool, len(got))
	for _, id := range got {
		have[id] = true
	}
	for _, id := range want {
		if !have[id] {
			return false
		}
	}
	return len(have) == len(want)
}

// scopeVerdict is how one scope on a serving replica differs from this
// machine's keyring.
type scopeVerdict struct {
	Scope string
	Kind  string // one of the diff* kinds
	Note  string
}

const (
	// diffBehind: the replica holds a key or scope this keyring lacks, or
	// writes under a newer key than this keyring uses. This keyring is behind.
	diffBehind = "behind"
	// diffNoScope: the replica does not hold the scope at all.
	diffNoScope = "no-scope"
	// diffNoCurrent: it lacks the key this keyring writes under.
	diffNoCurrent = "no-current"
	// diffNoOther: it lacks a key this keyring holds without using it.
	diffNoOther = "no-other"
	// diffOlderActive: it holds every key, and writes under an older one.
	diffOlderActive = "older-active"
	// diffForeignCopy: it serves a copy of the scope another machine minted.
	diffForeignCopy = "foreign-copy"
)

// replicaVerdict is every way a serving replica differs from this machine's
// keyring.
type replicaVerdict []scopeVerdict

func (v replicaVerdict) note() string {
	notes := make([]string, len(v))
	for i, d := range v {
		notes[i] = d.Note
	}
	return strings.Join(notes, "; ")
}

// behind reports a verdict an unseal from this machine refuses rather than
// fixes.
func (v replicaVerdict) behind() bool {
	return slices.ContainsFunc(v, func(d scopeVerdict) bool { return d.Kind == diffBehind || d.Kind == diffForeignCopy })
}

// keysAgainst compares what a serving replica holds with this machine's
// keyring. An empty verdict means it holds exactly that.
//
// "Behind" is decided first and the same way planHandOver decides it, so
// 'storage state' never promises an unseal will fix what unseal refuses.
func keysAgainst(st keyholder.State, keys datasphere.Keyring) replicaVerdict {
	want := heldKeys(keys)
	names := slices.Sorted(maps.Keys(want))
	for name := range st.Keys {
		if _, ok := want[name]; !ok {
			names = append(names, name)
		}
	}
	var out replicaVerdict
	for _, name := range names {
		if d, ok := scopeAgainst(name, st.Keys, keys); ok {
			out = append(out, d)
		}
	}
	return out
}

// scopeAgainst is keysAgainst for one scope.
func scopeAgainst(name string, held map[string][]string, keys datasphere.Keyring) (scopeVerdict, bool) {
	got, theirs := held[name]
	scope, ours := keys.ScopeNamed(name)
	v := scopeVerdict{Scope: name}
	if !ours {
		v.Kind, v.Note = diffBehind, fmt.Sprintf("holds scope %s, which this machine's keyring does not — this keyring is behind the instance's", name)
		return v, true
	}
	mine := heldKeys(keys)[name]
	switch {
	case theirs && len(got) > 0 && !slices.ContainsFunc(got, func(id string) bool { return slices.Contains(mine, id) }):
		v.Kind, v.Note = diffForeignCopy, fmt.Sprintf("serves a copy of %s minted separately from this machine's — run storage commands for it from the machine that deployed it", name)
	case !theirs:
		v.Kind, v.Note = diffNoScope, fmt.Sprintf("lacks scope %s: that application's requests are refused through it", name)
	case slices.ContainsFunc(got, func(id string) bool { return !slices.Contains(mine, id) }):
		v.Kind, v.Note = diffBehind, fmt.Sprintf("holds a key for %s this machine's keyring does not — this keyring is behind the instance's", name)
	case len(got) > 0 && got[0] != mine[0] && newerThanActive(scope, got[0]):
		v.Kind, v.Note = diffBehind, fmt.Sprintf("writes %s under a newer key than this machine's keyring uses — this keyring is behind the instance's", name)
	case !slices.Contains(got, mine[0]):
		v.Kind, v.Note = diffNoCurrent, fmt.Sprintf("lacks %s's current key: objects written under it fail through this replica", name)
	case len(got) != len(mine):
		// Older, or a rotation's key held and not yet used: either way this
		// is true, and for the second "anything" is nothing.
		v.Kind, v.Note = diffNoOther, fmt.Sprintf("lacks a key of %s that this machine holds without using it for new writes: anything already wrapped under it fails through this replica", name)
	case got[0] != mine[0]:
		v.Kind, v.Note = diffOlderActive, fmt.Sprintf("holds every key of %s but writes under an older one: a hand-over that did not finish. It still reads everything", name)
	default:
		return v, false
	}
	return v, true
}

// newerThanActive reports whether a key the scope holds was minted after the
// one it makes active.
func newerThanActive(s datasphere.Scope, id string) bool {
	keks := s.Keyring().KEKs()
	for _, e := range keks {
		if e.ID.String() == id {
			return e.Created.After(keks[0].Created)
		}
	}
	return false
}
