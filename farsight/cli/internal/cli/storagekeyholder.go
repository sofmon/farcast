package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/fatline/tunnel"
)

// DefaultScope is the slice of storage an instance's applications share in
// phase 3.2. Per-application scopes arrive at 4.x; until then one scope keeps
// application data cryptographically separate from the operator's own objects,
// which is the property that matters first.
const (
	DefaultScopeName   = "app"
	DefaultScopePrefix = "app/"
)

// keyholderDialer opens the operator's tunnel and returns a client for the
// instance's keyholder replicas.
//
// Every keyholder command goes through here, which is also where the one
// dependency the ADR calls a recovery floor becomes visible: an unseal rides
// FatLine, so an instance whose tunnel is down cannot be unsealed at all.
func keyholderClient(ctx context.Context, env *Env, name string) (*keyholder.Client, func(), error) {
	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return nil, nil, fmt.Errorf("load instance %q: %w", name, err)
	}
	if meta.Carrier == nil || meta.Carrier.Endpoint == "" {
		return nil, nil, fmt.Errorf("instance %q has no tunnel; run 'farcast connect %s' first", name, name)
	}
	mtls, err := env.ConfigDir.LoadInstanceMTLS(name)
	if err != nil {
		return nil, nil, fmt.Errorf("load the mTLS identity for %q: %w", name, err)
	}
	id, err := clientIdentity(mtls, name)
	if err != nil {
		return nil, nil, err
	}
	conn, err := tunnel.Connect(ctx, "https://"+meta.Carrier.Endpoint, id)
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
		return fmt.Errorf("%d of %d replicas were unsealed; the rest still hold no key material", done, total)
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

type storageStateCommand struct{}

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

func (*storageStateCommand) Run(ctx context.Context, env *Env, args []string) error {
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
	client, done, err := keyholderClient(ctx, env, name)
	if err != nil {
		return err
	}
	defer done()

	states := make([]replicaState, 0, replicaCount(meta))
	for i := range replicaCount(meta) {
		st, err := client.State(ctx, i)
		if err != nil {
			states = append(states, replicaState{Ordinal: i, Error: err.Error()})
			continue
		}
		states = append(states, replicaState{
			Ordinal: i, Phase: st.Phase, Since: st.Since,
			Generation: st.Generation, HoldReason: st.HoldReason, Scopes: st.Scopes,
		})
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
	Error      string    `json:"error,omitempty"`
}

type stateResult struct {
	Instance string         `json:"instance"`
	Recorded uint64         `json:"recorded_generation"`
	Replicas []replicaState `json:"replicas"`
}

func (r stateResult) Human(w io.Writer) error {
	sealed := 0
	for _, s := range r.Replicas {
		switch {
		case s.Error != "":
			fmt.Fprintf(w, "  replica %d  unreachable — %s\n", s.Ordinal, s.Error)
			sealed++
		case s.Phase == "unsealed":
			fmt.Fprintf(w, "  replica %d  unsealed   generation %d, scopes %s\n",
				s.Ordinal, s.Generation, strings.Join(s.Scopes, ","))
		default:
			reason := s.Phase
			if s.HoldReason != "" {
				reason += " — " + s.HoldReason
			}
			fmt.Fprintf(w, "  replica %d  %s\n", s.Ordinal, reason)
			sealed++
		}
	}
	if sealed == len(r.Replicas) {
		fmt.Fprintf(w, "\nEvery replica is sealed: applications are receiving ErrStorageSealed.\n"+
			"Nothing is lost — run 'farcast storage unseal %s' to restore service.\n", r.Instance)
	} else if sealed > 0 {
		fmt.Fprintf(w, "\n%d of %d replicas are sealed. Storage is serving, with less headroom than it should have.\n",
			sealed, len(r.Replicas))
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
			fmt.Fprintf(w, "  replica %d  NOT SEALED — %s\n", s.Ordinal, s.Error)
			continue
		}
		fmt.Fprintf(w, "  replica %d  %s\n", s.Ordinal, s.Phase)
	}
	if r.Hold {
		fmt.Fprintf(w, "\nThis hold lives only until the pod restarts. A restarted replica comes back\n"+
			"restart-sealed, which a keeper device may clear unattended.\n")
	}
	return nil
}

// ---------------------------------------------------------------- unseal

type storageUnsealCommand struct{}

func (*storageUnsealCommand) Name() string     { return "unseal" }
func (*storageUnsealCommand) Synopsis() string { return "Hand the keyholder its key material" }

func (*storageUnsealCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage unseal <instance>

Hand every keyholder replica the key material for the instance's application
scope, so applications can read and write again.

The push travels through the FatLine tunnel inside its own session that
terminates in the keyholder, and is sealed to one specific replica process
answering a single-use challenge — so it cannot be replayed, cannot be pushed
into another instance, and never exists in FatLine's memory.

This command changes nothing in the cluster. It deploys nothing, applies
nothing and restarts nothing; if the keyholder is absent it says so and stops.
That separation is deliberate: the command you reach for at 03:00 has one job
and no way to make things worse.`)
}

func (*storageUnsealCommand) SetFlags(*flag.FlagSet) {}

func (*storageUnsealCommand) Run(ctx context.Context, env *Env, args []string) error {
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
	client, done, err := keyholderClient(ctx, env, name)
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
	scope, generation, err := ensureScope(env, name, meta, keys)
	if err != nil {
		return err
	}
	bundle, err := datasphere.NewBundle(name, generation, []datasphere.Scope{scope})
	if err != nil {
		return err
	}
	defer bundle.Zero()
	payload, err := bundle.Marshal()
	if err != nil {
		return err
	}
	defer clear(payload)

	ledgerPath := env.ConfigDir.InstanceUnsealLedgerPath(name)
	total := replicaCount(meta)
	states := make([]replicaState, 0, total)
	loaded := 0
	for i := range total {
		st, pushErr := client.Unseal(ctx, i, payload, "operator-unseal")
		entry := keyholder.LedgerEntry{
			Time: time.Now().UTC(), Instance: name, Ordinal: i,
			Intent: "operator-unseal", Generation: generation, Result: "ok",
		}
		if pushErr != nil {
			entry.Result = "refused"
			states = append(states, replicaState{Ordinal: i, Error: pushErr.Error()})
		} else {
			entry.Phase = st.Phase
			loaded++
			states = append(states, replicaState{Ordinal: i, Phase: st.Phase, Generation: st.Generation, Scopes: st.Scopes})
		}
		if lerr := keyholder.AppendLedger(ledgerPath, entry); lerr != nil {
			fmt.Fprintf(env.Err, "warning: the unseal ledger could not be written: %v\n", lerr)
		}
	}

	if err := env.Printer.Print(unsealResult{
		Instance: name, Scope: scope.Name, Generation: generation,
		Loaded: loaded, Total: total, Replicas: states,
	}); err != nil {
		return err
	}
	// A partial unseal is a failure, and the loaded replicas are NOT rolled
	// back: undoing them would turn a transient network error into an outage.
	return partialFailure("unseal", loaded, total)
}

// ensureScope returns the scope to push, minting and RECORDING it first if the
// instance has none.
//
// The recording happens before any push, and that ordering is the point: key
// material handed to a cluster but not written into keys.yaml is material
// whose data nobody can ever find again.
func ensureScope(env *Env, name string, meta *config.InstanceMetadata, keys datasphere.Keyring) (datasphere.Scope, uint64, error) {
	scope, ok := keys.ScopeNamed(DefaultScopeName)
	if !ok {
		fresh, err := datasphere.NewScope(DefaultScopeName, DefaultScopePrefix)
		if err != nil {
			return datasphere.Scope{}, 0, err
		}
		grown, err := keys.AddScope(fresh)
		if err != nil {
			return datasphere.Scope{}, 0, err
		}
		encoded, err := grown.Marshal()
		if err != nil {
			return datasphere.Scope{}, 0, err
		}
		if err := env.ConfigDir.SaveInstanceKeyring(name, encoded); err != nil {
			return datasphere.Scope{}, 0, fmt.Errorf("recording the new scope: %w", err)
		}
		fmt.Fprintf(env.Err, "Minted the %q scope and recorded it in the keyring. %s\n",
			DefaultScopeName, datasphere.KeyLossWarning)
		scope = fresh
	}

	generation := meta.Keyholder.Generation + 1
	meta.Keyholder.Scope = scope.Name
	meta.Keyholder.ScopePrefix = scope.Prefix
	meta.Keyholder.Generation = generation
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return datasphere.Scope{}, 0, fmt.Errorf("recording the unseal generation: %w", err)
	}
	return scope, generation, nil
}

type unsealResult struct {
	Instance   string         `json:"instance"`
	Scope      string         `json:"scope"`
	Generation uint64         `json:"generation"`
	Loaded     int            `json:"loaded"`
	Total      int            `json:"total"`
	Replicas   []replicaState `json:"replicas"`
}

func (r unsealResult) Human(w io.Writer) error {
	for _, s := range r.Replicas {
		if s.Error != "" {
			fmt.Fprintf(w, "  replica %d  NOT UNSEALED — %s\n", s.Ordinal, s.Error)
			continue
		}
		fmt.Fprintf(w, "  replica %d  %s   generation %d\n", s.Ordinal, s.Phase, s.Generation)
	}
	fmt.Fprintf(w, "\n%d of %d replicas hold the %q scope at generation %d.\n",
		r.Loaded, r.Total, r.Scope, r.Generation)
	fmt.Fprintf(w, "Key material is held in RAM only: any restart seals that replica again.\n")
	return nil
}
