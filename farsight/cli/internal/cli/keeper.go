package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keeper"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
)

// keeperTunnel dials FatLine with the DEVICE's own leaf.
//
// It is deliberately not instanceTunnel: that one reads instance metadata and
// the operator's mTLS material out of the config directory, and a keeper device
// holds neither. Everything this needs came in the enrolment packet, which is
// what lets a keeper be a machine that has never installed anything.
func keeperTunnel(ctx context.Context, cfg keeper.Config, caPEM, leafCert, leafKey []byte) (*tunnel.Conn, error) {
	cert, err := tls.X509KeyPair(leafCert, leafKey)
	if err != nil {
		return nil, fmt.Errorf("keeper: this device's certificate and key do not form a pair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		// Without the instance CA there is no way to tell FatLine from
		// anything else answering on that address, and the system roots would
		// accept exactly that.
		return nil, fmt.Errorf("keeper: this device holds no usable CA certificate for %q", cfg.Instance)
	}
	return tunnel.Connect(ctx, "https://"+cfg.Carrier, tunnel.ClientIdentity{
		Cert: cert, CA: pool, ServerName: cfg.ServerName,
	})
}

// `farcast keeper` — the devices that re-seed a restart-sealed instance
// without waking anyone.
//
// [ADR 0008](../../../../docs/adr/0008-in-cluster-key-delivery.md) concedes
// that in-cluster storage availability is bounded by the operator's response
// time: after a 03:00 node upgrade, applications get ErrStorageSealed until a
// human runs `storage unseal`. A keeper is the lawful automation of that — an
// operator-owned device supplying an input the cloud does not hold — and the
// product stance the ADR records is that running FarCast as a server needs at
// least two of them.
//
// Two verbs run on the OPERATOR's machine (enroll, revoke) because they need
// the CA key. Two run on the KEEPER device (install, run). status runs on
// either and reads whatever ledgers that machine has.

func newKeeperCommand() Command {
	subs := NewRegistry()
	subs.Register(&keeperEnrollCommand{})
	subs.Register(&keeperInstallCommand{})
	subs.Register(&keeperRunCommand{})
	subs.Register(&keeperStatusCommand{})
	subs.Register(&keeperRevokeCommand{})
	return &group{
		name:     "keeper",
		synopsis: "Devices that re-seed a restart-sealed instance unattended (enroll, install, run, status, revoke)",
		subs:     subs,
		usage: `
Usage: farcast keeper <enroll|install|run|status|revoke> [flags] [arguments]

A keeper is an operator-owned device that hands a restarted keyholder its key
material back, so storage recovers in minutes instead of whenever somebody
wakes up. Running FarCast as a server needs at least two enrolled keepers.

Subcommands:
  enroll   Issue a device its own leaf and bundle       (operator's machine)
  install  Accept an enrolment packet on this device    (keeper device)
  run      Keep an instance: watch, and re-seed         (keeper device)
  status   Reconcile what this machine's ledgers record (either)
  revoke   Withdraw a device from the fleet             (operator's machine)

What a keeper holds is a derived scope bundle and its own device leaf — exactly
what an unsealed keyholder already holds in RAM, and nothing more. It never
holds the master keyring, and never the CA key, so a stolen keeper can re-seed
and cannot enrol another device.

What a keeper does NOT do is clear a deliberate seal. "Sealed because it
restarted" and "sealed because you said so" are different states, and only the
first is a keeper's to remedy.

Every push lands in an append-only ledger on the device, and beyond a budget a
keeper refuses instead of re-seeding. The budget is a tripwire, not a barrier —
a patient adversary stays under it — so 'keeper status' reconciles the ledgers
against how many times the cluster actually restarted, and says when the two
disagree.`,
	}
}

// ------------------------------------------------------------- enroll

type keeperEnrollCommand struct {
	out            string
	passphraseFile string
	budget         int
	window         time.Duration
}

func (*keeperEnrollCommand) Name() string     { return "enroll" }
func (*keeperEnrollCommand) Synopsis() string { return "Issue a device its own leaf and bundle" }

func (*keeperEnrollCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast keeper enroll <instance> <device> --out <path> --passphrase-file <path>

Enrol one device as a keeper. Run this on the machine that holds the instance's
CA key and keyring — no other machine can do it, which is the point.

It writes a passphrase-armored packet carrying that device's own certificate,
the scope bundle it will re-seed with, and how to reach and verify the instance.
Carry it to the device on whatever medium you trust and run 'keeper install'.

Flags:
      --out <path>               Where to write the packet
      --passphrase-file <path>   File holding the passphrase; "-" reads stdin
      --budget <n>               Reseeds allowed per window (default 8)
      --window <duration>        The budget window (default 720h, 30 days)

The packet never goes through the instance. FarCast does not distribute the
material it is fed, and an instance that handed out bundles would be exactly
the solicitation endpoint this design exists to avoid.

The device's certificate expires in 90 days. That is the fleet's only automatic
revocation, and re-enrolling is how a device keeps keeping.`)
}

func (c *keeperEnrollCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.out, "out", "", "where to write the packet")
	fs.StringVar(&c.passphraseFile, "passphrase-file", "", "file holding the passphrase")
	fs.IntVar(&c.budget, "budget", keeper.DefaultBudget, "reseeds allowed per window")
	fs.DurationVar(&c.window, "window", keeper.DefaultWindow, "the budget window")
}

func (c *keeperEnrollCommand) Run(_ context.Context, env *Env, args []string) error {
	if len(args) != 2 {
		return usagef("keeper enroll takes an instance and a device name")
	}
	name, device := args[0], args[1]
	if err := keeper.ValidateDevice(device); err != nil {
		return err
	}
	if c.out == "" {
		return usagef("--out is required: the packet is a file you carry to the device")
	}
	passphrase, err := readPassphrase(env, c.passphraseFile)
	if err != nil {
		return err
	}

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if meta.Carrier == nil || meta.Carrier.Endpoint == "" {
		return fmt.Errorf("instance %q has no tunnel, so a keeper would have nothing to dial; run 'farcast connect %s'", name, name)
	}
	if meta.Keyholder == nil || !meta.Keyholder.Deployed {
		return fmt.Errorf("instance %q has no keyholder, so there is nothing for a keeper to re-seed; run 'farcast storage deploy %s'", name, name)
	}
	mtls, err := env.ConfigDir.LoadInstanceMTLS(name)
	if err != nil {
		return fmt.Errorf("read the instance CA, which is what issues a keeper its identity: %w", err)
	}
	if len(mtls.CAKeyPEM) == 0 {
		return fmt.Errorf("this machine holds no CA key for %q, so it cannot enrol a keeper; enrolment happens where the CA lives", name)
	}

	raw, err := env.ConfigDir.LoadInstanceKeyring(name)
	if err != nil {
		return fmt.Errorf("instance %q has no keyring on this machine, so there is no bundle to give a keeper: %w", name, err)
	}
	keys, err := datasphere.ParseKeyring(raw)
	if err != nil {
		return err
	}
	// Every scope the keyring holds, because a keeper re-seeds an instance
	// rather than an application: one that carried a subset would restore
	// storage for some applications and leave others sealed, which is a
	// half-recovery nobody asked for. A keyring with no scopes yields an
	// empty bundle, which is what an instance with no applications has.
	scopes := keys.Scopes()

	// The keeper's bundle carries the generation the instance is ALREADY at,
	// not the next one. A keeper restores what was there; advancing a
	// generation is an operator's act, and a device that did it on its own
	// would rewrite the counter the operator reconciles against.
	generation := meta.Keyholder.Generation
	bundle, err := datasphere.NewBundle(name, generation, scopes)
	if err != nil {
		return err
	}
	defer bundle.Zero()
	payload, err := bundle.Marshal()
	if err != nil {
		return err
	}
	defer clear(payload)

	leafCert, leafKey, err := identity.IssueKeeperClient(mtls.CACertPEM, mtls.CAKeyPEM, name, device)
	if err != nil {
		return err
	}
	defer clear(leafKey)
	expires := leafExpiry(leafCert)

	packet := &keeper.Packet{
		Version: 1, Instance: name, Device: device,
		Carrier: meta.Carrier.Endpoint, ServerName: identity.ServerName(name),
		CACertPEM: mtls.CACertPEM, LeafCertPEM: leafCert, LeafKeyPEM: leafKey,
		Bundle: payload, Generation: generation,
		Budget: c.budget, Window: c.window, IssuedAt: time.Now().UTC(),
	}
	sealed, err := keeper.Seal(packet, passphrase)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(c.out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Never overwrite. The file that is already there may be another
			// device's packet, and a packet is the only copy of a leaf's
			// private key that ever exists outside the device it is for.
			return fmt.Errorf("%s already exists; refusing to overwrite it", c.out)
		}
		return err
	}
	if _, err := file.Write(sealed); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	if _, err := env.ConfigDir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
		m.Keepers = upsertKeeper(m.Keepers, config.Keeper{
			Device: device, EnrolledAt: time.Now().UTC(), Expires: expires,
			Generation: generation, Budget: c.budget,
		})
		return nil
	}); err != nil {
		return fmt.Errorf("the packet was written but recording the enrolment failed: %w", err)
	}

	fprintf(env.Err, "The passphrase is the only thing protecting %s. %s\n", c.out, datasphere.KeyLossWarning)
	return env.Printer.Print(keeperEnrollResult{
		Instance: name, Device: device, Path: c.out,
		Generation: generation, Budget: c.budget, Window: c.window.String(), Expires: expires,
		Fleet: activeKeepers(meta.Keepers, device),
	})
}

type keeperEnrollResult struct {
	Instance   string    `json:"instance"`
	Device     string    `json:"device"`
	Path       string    `json:"path"`
	Generation uint64    `json:"generation"`
	Budget     int       `json:"budget"`
	Window     string    `json:"window"`
	Expires    time.Time `json:"expires,omitzero"`
	Fleet      int       `json:"fleet"`
}

func (r keeperEnrollResult) Human(w io.Writer) error {
	fprintf(w, "✓ enrolled %q as a keeper of %q\n", r.Device, r.Instance)
	fprintf(w, "  packet      %s (mode 0600)\n", r.Path)
	fprintf(w, "  bundle      generation %d\n", r.Generation)
	fprintf(w, "  budget      %d reseeds per %s\n", r.Budget, r.Window)
	if !r.Expires.IsZero() {
		fprintf(w, "  expires     %s — re-enrol before then or this device stops keeping\n",
			r.Expires.UTC().Format(time.RFC3339))
	}
	fprintf(w, "\nOn the device: farcast keeper install %s --passphrase-file <path>\n", r.Path)
	if r.Fleet < 2 {
		fprintf(w, "\n%q now has %d enrolled keeper. Running FarCast as a server wants at least two:\n"+
			"one device is one power cut away from the sealed window this exists to close.\n", r.Instance, r.Fleet)
	}
	return nil
}

// ------------------------------------------------------------ install

type keeperInstallCommand struct {
	passphraseFile string
	acceptRisk     bool
}

func (*keeperInstallCommand) Name() string     { return "install" }
func (*keeperInstallCommand) Synopsis() string { return "Accept an enrolment packet on this device" }

func (*keeperInstallCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast keeper install <packet> --passphrase-file <path> [--accept-backup-risk]

Accept an enrolment packet on the device that will do the keeping.

The material comes to rest unarmored, and that is what a keeper is: a device
that re-seeds at 03:00 cannot hold a passphrase behind a human. What protects
it instead is the platform — mode 0600 inside a 0700 directory, marked as
excluded from the backup pipeline — and the fact that only a derived bundle
was ever put there.

Flags:
      --passphrase-file <path>   File holding the passphrase; "-" reads stdin
      --accept-backup-risk       Install even though the exclusion is unverifiable

Installing into a synced folder (iCloud Drive, Dropbox, and their kin) is
refused outright and cannot be overridden: a synced directory uploads the
bundle continuously, to the kind of cloud this design exists to keep it off.`)
}

func (c *keeperInstallCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.passphraseFile, "passphrase-file", "", "file holding the passphrase")
	fs.BoolVar(&c.acceptRisk, "accept-backup-risk", false, "install without a verifiable backup exclusion")
}

func (c *keeperInstallCommand) Run(_ context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("keeper install takes one packet file")
	}
	passphrase, err := readPassphrase(env, c.passphraseFile)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	packet, err := keeper.Open(data, passphrase)
	if err != nil {
		return err
	}
	defer packet.Zero()

	dir := env.ConfigDir.KeeperDir(packet.Instance)
	store, err := keeper.Install(dir, packet, c.acceptRisk)
	if err != nil {
		return err
	}
	cfg, err := store.Config()
	if err != nil {
		return err
	}
	return env.Printer.Print(keeperInstallResult{
		Instance: cfg.Instance, Device: cfg.Device, Dir: store.Dir(),
		Generation: cfg.Generation, Budget: cfg.Budget, Window: cfg.Window.String(),
		BackupExcluded: cfg.BackupExcluded, BackupNote: cfg.BackupNote,
	})
}

type keeperInstallResult struct {
	Instance       string `json:"instance"`
	Device         string `json:"device"`
	Dir            string `json:"dir"`
	Generation     uint64 `json:"generation"`
	Budget         int    `json:"budget"`
	Window         string `json:"window"`
	BackupExcluded bool   `json:"backup_excluded"`
	BackupNote     string `json:"backup_note,omitempty"`
}

func (r keeperInstallResult) Human(w io.Writer) error {
	fprintf(w, "✓ this device is now keeper %q of %q\n", r.Device, r.Instance)
	fprintf(w, "  state       %s (mode 0700)\n", r.Dir)
	fprintf(w, "  bundle      generation %d\n", r.Generation)
	fprintf(w, "  budget      %d reseeds per %s\n", r.Budget, r.Window)
	if r.BackupExcluded {
		fprintf(w, "  backup      excluded, and the exclusion was read back\n")
	} else {
		fprintf(w, "  backup      NOT verifiably excluded — %s\n", r.BackupNote)
		fprintf(w, "              You accepted this. Keep the directory off every backup and sync path yourself.\n")
	}
	fprintf(w, "\nStart keeping:  farcast keeper run %s\n", r.Instance)
	return nil
}

// ---------------------------------------------------------------- run

type keeperRunCommand struct {
	interval time.Duration
	once     bool
}

func (*keeperRunCommand) Name() string     { return "run" }
func (*keeperRunCommand) Synopsis() string { return "Keep an instance: watch, and re-seed" }

func (*keeperRunCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast keeper run <instance> [--interval <duration>] [--once]

Watch an instance and hand its keyholder key material back whenever it comes
back sealed from a restart.

Flags:
      --interval <duration>   How often to check (default 15m)
      --once                  Check once and exit, for a timer or a test

The check is OUTBOUND-ONLY: this device dials FatLine and nothing listens here.
Every flow of key material starts on your hardware, and leaves a ledger entry
the cloud can neither reach nor erase.

The interval is jittered by up to a quarter of itself. A fleet polling on the
dot sketches which of your devices are awake and from which networks, and the
carrier's flow logs are somebody else's to read.

It will not clear a deliberate seal, and beyond its budget it refuses and says
so rather than re-seeding. A refusal is the alarm — widening the budget is not
the fix for it.`)
}

func (c *keeperRunCommand) SetFlags(fs *flag.FlagSet) {
	fs.DurationVar(&c.interval, "interval", 15*time.Minute, "how often to check")
	fs.BoolVar(&c.once, "once", false, "check once and exit")
}

func (c *keeperRunCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("keeper run takes one instance argument")
	}
	name := args[0]
	store, err := keeper.OpenStore(env.ConfigDir.KeeperDir(name))
	if err != nil {
		return fmt.Errorf("%w\nEnrol this device on the machine that holds %q's CA key, then 'farcast keeper install'", err, name)
	}
	cfg, err := store.Config()
	if err != nil {
		return err
	}
	if c.once {
		_, err := keeperCheck(ctx, env, store, cfg)
		return err
	}
	fprintf(env.Err, "Keeping %q as %q — checking about every %s, outbound only.\n", cfg.Instance, cfg.Device, c.interval)
	for {
		if _, err := keeperCheck(ctx, env, store, cfg); err != nil {
			// A failed check is reported and never fatal. The one job of this
			// process is to be running when the cluster next needs it, and a
			// keeper that exited on an unreachable tunnel would be absent for
			// exactly the outage it exists for.
			fprintf(env.Err, "check failed: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(jitter(c.interval)):
		}
	}
}

// jitter spreads a poll by up to a quarter of the interval, in both
// directions. See the usage text: a fleet's cadence is metadata.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Minute
	}
	spread := int64(d / 4)
	if spread <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(2*spread)-spread)
}

// keeperCheck is one pass over the instance's replicas.
func keeperCheck(ctx context.Context, env *Env, store *keeper.Store, cfg keeper.Config) ([]keeper.Decision, error) {
	caPEM, leafCert, leafKey, bundle, err := store.Material()
	if err != nil {
		return nil, err
	}
	defer clear(bundle)
	defer clear(leafKey)

	conn, err := keeperTunnel(ctx, cfg, caPEM, leafCert, leafKey)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %q: %w", cfg.Instance, err)
	}
	defer func() { _ = conn.Close() }()

	client, err := keyholder.New(keyholder.Conn(conn), cfg.Instance, caPEM, leafCert, leafKey)
	if err != nil {
		return nil, err
	}

	entries, err := keyholder.ReadLedger(store.LedgerPath())
	if err != nil {
		return nil, err
	}
	decisions := make([]keeper.Decision, 0, keeperReplicas)
	for i := range keeperReplicas {
		budget := keeper.Budget(entries, cfg.Budget, cfg.Window, time.Now().UTC())
		st, stErr := client.State(ctx, i)
		d := keeper.Decide(st, stErr, i, cfg.Generation, budget)
		decisions = append(decisions, d)
		if d.Action != keeper.ActionReseed {
			keeperReport(env, cfg, d, st)
			continue
		}
		pushed, pushErr := client.Unseal(ctx, i, bundle, keeper.IntentReseed)
		entry := keyholder.LedgerEntry{
			Time: time.Now().UTC(), Instance: cfg.Instance, Ordinal: i,
			Intent: keeper.IntentReseed, Generation: cfg.Generation,
			Device: cfg.Device, Boot: st.Boot, Result: "ok",
		}
		if pushErr != nil {
			entry.Result = "refused"
			d.Action, d.Reason = keeper.ActionUnknown, pushErr.Error()
		} else {
			entry.Phase = pushed.Phase
			// The boot the push actually landed in, which is what the audit
			// counts. It should equal what State reported a moment ago, and
			// recording the push's own answer means a replica that restarted
			// between the two is recorded as the process it really seeded.
			if pushed.Boot != "" {
				entry.Boot = pushed.Boot
			}
		}
		decisions[len(decisions)-1] = d
		if lerr := keyholder.AppendLedger(store.LedgerPath(), entry); lerr != nil {
			// Loud, because the ledger is the control. A push nobody recorded
			// is the one an audit cannot account for later.
			fprintf(env.Err, "WARNING: a reseed was not recorded in the ledger: %v\n", lerr)
		}
		entries = append(entries, entry)
		keeperReport(env, cfg, d, st)
	}
	return decisions, nil
}

// keeperReplicas is how many replicas a keeper checks.
//
// A keeper device does not hold instance metadata — it is not the operator's
// machine — so it cannot read the deployed replica count. Two is what ADR 0008
// decision 6 specifies and what `storage deploy` renders; a replica that is not
// there answers with a dial error, which the pass reports and moves past.
const keeperReplicas = 2

func keeperReport(env *Env, cfg keeper.Config, d keeper.Decision, st keyholder.State) {
	switch d.Action {
	case keeper.ActionNone:
		if env.Verbose {
			fprintf(env.Err, "replica %d: %s\n", d.Ordinal, d.Reason)
		}
	case keeper.ActionReseed:
		fprintf(env.Err, "replica %d: re-seeded %s at generation %d (process %s)\n",
			d.Ordinal, cfg.Instance, cfg.Generation, shortBoot(st.Boot))
	default:
		fprintf(env.Err, "replica %d: %s — %s\n", d.Ordinal, d.Action, d.Reason)
	}
}

func shortBoot(b string) string {
	if len(b) > 8 {
		return b[:8]
	}
	if b == "" {
		return "unlabelled"
	}
	return b
}

// ------------------------------------------------------------- status

type keeperStatusCommand struct{}

func (*keeperStatusCommand) Name() string     { return "status" }
func (*keeperStatusCommand) Synopsis() string { return "Reconcile what this machine's ledgers record" }

func (*keeperStatusCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast keeper status [instance]

Reconcile the reseed ledgers this machine holds against how many times the
cluster actually restarted.

The question it answers is not "how often did we re-seed" but "how many
DISTINCT keyholder processes did we re-seed". A process is sealed once per
restart, so one reseed per process is a cluster restarting and a keeper doing
its job — and two pushes into the SAME process means something asked for key
material that a live process already held.

That is detection by audit. It runs when you run it, it is not a live alert,
and against a cloud that reads the keyholder's memory directly it says nothing
at all. Read it anyway: the reseed budget is a tripwire a patient adversary
simply stays under, which leaves this.`)
}

func (*keeperStatusCommand) SetFlags(*flag.FlagSet) {}

func (*keeperStatusCommand) Run(_ context.Context, env *Env, args []string) error {
	if len(args) > 1 {
		return usagef("keeper status takes at most one instance")
	}
	names, err := env.ConfigDir.ListKeepers()
	if err != nil {
		return err
	}
	if len(args) == 1 {
		names = []string{args[0]}
	}

	results := make([]keeperStatusEntry, 0, len(names))
	for _, name := range names {
		entry := keeperStatusEntry{Instance: name}
		store, err := keeper.OpenStore(env.ConfigDir.KeeperDir(name))
		if err != nil {
			entry.Error = err.Error()
			results = append(results, entry)
			continue
		}
		cfg, err := store.Config()
		if err != nil {
			entry.Error = err.Error()
			results = append(results, entry)
			continue
		}
		ledger, err := keyholder.ReadLedger(store.LedgerPath())
		if err != nil {
			entry.Error = err.Error()
			results = append(results, entry)
			continue
		}
		audit := keeper.Reconcile(name, ledger)
		budget := keeper.Budget(ledger, cfg.Budget, cfg.Window, time.Now().UTC())
		entry.Device, entry.Generation = cfg.Device, cfg.Generation
		entry.BackupExcluded, entry.BackupNote = cfg.BackupExcluded, cfg.BackupNote
		entry.Reseeds, entry.Boots, entry.Refused = audit.Reseeds, audit.Boots, audit.Refused
		entry.Unlabelled = audit.Unlabelled
		entry.BudgetUsed, entry.BudgetLimit = budget.Used, budget.Limit
		for _, d := range audit.Divergent {
			entry.Divergent = append(entry.Divergent, fmt.Sprintf(
				"process %s re-seeded %d times (last %s)", shortBoot(d.Boot), d.Count, d.Last.UTC().Format(time.RFC3339)))
		}
		results = append(results, entry)
	}

	// An operator's own machine also holds the fleet roster, when this is the
	// machine that enrolled them.
	fleet := map[string][]config.Keeper{}
	if instances, err := env.ConfigDir.ListInstances(); err == nil {
		for _, in := range instances {
			if meta, err := env.ConfigDir.LoadInstanceMetadata(in); err == nil && len(meta.Keepers) > 0 {
				fleet[in] = meta.Keepers
			}
		}
	}
	return env.Printer.Print(keeperStatusResult{Keeping: results, Fleet: fleetRows(fleet)})
}

type keeperStatusEntry struct {
	Instance       string   `json:"instance"`
	Device         string   `json:"device,omitempty"`
	Generation     uint64   `json:"generation,omitempty"`
	Reseeds        int      `json:"reseeds"`
	Boots          int      `json:"boots"`
	Refused        int      `json:"refused"`
	Unlabelled     int      `json:"unlabelled,omitempty"`
	BudgetUsed     int      `json:"budget_used"`
	BudgetLimit    int      `json:"budget_limit"`
	BackupExcluded bool     `json:"backup_excluded"`
	BackupNote     string   `json:"backup_note,omitempty"`
	Divergent      []string `json:"divergent,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type fleetRow struct {
	Instance string    `json:"instance"`
	Device   string    `json:"device"`
	Expires  time.Time `json:"expires,omitzero"`
	Revoked  bool      `json:"revoked,omitempty"`
}

type keeperStatusResult struct {
	Keeping []keeperStatusEntry `json:"keeping"`
	Fleet   []fleetRow          `json:"fleet,omitempty"`
}

func fleetRows(fleet map[string][]config.Keeper) []fleetRow {
	rows := make([]fleetRow, 0)
	for instance, keepers := range fleet {
		for _, k := range keepers {
			rows = append(rows, fleetRow{Instance: instance, Device: k.Device, Expires: k.Expires, Revoked: k.Revoked})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Instance != rows[j].Instance {
			return rows[i].Instance < rows[j].Instance
		}
		return rows[i].Device < rows[j].Device
	})
	return rows
}

func (r keeperStatusResult) Human(w io.Writer) error {
	if len(r.Keeping) == 0 && len(r.Fleet) == 0 {
		fprintln(w, "This machine keeps nothing and has enrolled nobody.")
		return nil
	}
	for _, e := range r.Keeping {
		if e.Error != "" {
			fprintf(w, "%s: %s\n", e.Instance, e.Error)
			continue
		}
		fprintf(w, "%s (as %q, bundle generation %d)\n", e.Instance, e.Device, e.Generation)
		fprintf(w, "  reseeds     %d into %d distinct keyholder processes", e.Reseeds, e.Boots)
		if e.Refused > 0 {
			fprintf(w, ", %d refused", e.Refused)
		}
		fprintln(w, "")
		fprintf(w, "  budget      %d of %d used\n", e.BudgetUsed, e.BudgetLimit)
		if !e.BackupExcluded {
			fprintf(w, "  backup      NOT verifiably excluded — %s\n", e.BackupNote)
		}
		if e.Unlabelled > 0 {
			fprintf(w, "  unlabelled  %d reseed(s) name no process, so they cannot be reconciled\n", e.Unlabelled)
		}
		if len(e.Divergent) == 0 {
			fprintf(w, "  audit       nothing to explain — no process was re-seeded twice\n")
		} else {
			fprintf(w, "  audit       %d PROCESS(ES) RE-SEEDED MORE THAN ONCE:\n", len(e.Divergent))
			for _, d := range e.Divergent {
				fprintf(w, "                %s\n", d)
			}
			fprintf(w, "              A process is sealed once per restart. A second push into a live one\n")
			fprintf(w, "              means something asked for key material it already held.\n")
		}
	}
	if len(r.Fleet) > 0 {
		fprintln(w, "\nEnrolled from this machine:")
		for _, f := range r.Fleet {
			status := ""
			switch {
			case f.Revoked:
				status = "  REVOKED"
			case !f.Expires.IsZero() && time.Until(f.Expires) < 14*24*time.Hour:
				status = fmt.Sprintf("  expires %s — re-enrol", f.Expires.UTC().Format("2006-01-02"))
			case !f.Expires.IsZero():
				status = "  until " + f.Expires.UTC().Format("2006-01-02")
			}
			fprintf(w, "  %-12s %s%s\n", f.Instance, f.Device, status)
		}
	}
	return nil
}

// ------------------------------------------------------------- revoke

type keeperRevokeCommand struct{ assumeYes bool }

func (*keeperRevokeCommand) Name() string     { return "revoke" }
func (*keeperRevokeCommand) Synopsis() string { return "Withdraw a device from the fleet" }

func (*keeperRevokeCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast keeper revoke <instance> <device> [-y]

Withdraw a device from the fleet.

Read what this does, because it is narrower than the word suggests. It marks
the device revoked in this machine's records, so it stops counting toward the
fleet and an audit can still attribute its old ledger entries. It does not
reach into the cluster, and the device's certificate stays cryptographically
valid until it expires.

What actually retires a stolen device's BUNDLE is 'farcast storage rekey': it
changes the scope keys, after which the material that device holds opens
nothing written since. That is the answer to a lost device, and this command
prints it rather than implying it already happened.`)
}

func (c *keeperRevokeCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation")
}

func (c *keeperRevokeCommand) Run(_ context.Context, env *Env, args []string) error {
	if len(args) != 2 {
		return usagef("keeper revoke takes an instance and a device name")
	}
	name, device := args[0], args[1]
	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	var found *config.Keeper
	for i := range meta.Keepers {
		if meta.Keepers[i].Device == device {
			found = &meta.Keepers[i]
		}
	}
	if found == nil {
		return fmt.Errorf("%q has no enrolled keeper named %q", name, device)
	}
	if found.Revoked {
		return fmt.Errorf("%q's keeper %q is already revoked", name, device)
	}
	remaining := activeKeepers(meta.Keepers, "") - 1
	if !c.assumeYes {
		interactive := env.Printer.Mode == output.ModeHuman && isTerminal(env.In)
		if !interactive {
			return usagef("refusing to revoke %q without confirmation; pass --yes", device)
		}
		fprintf(env.Err, "Revoking %q leaves %q with %d active keeper(s).\n", device, name, remaining)
		answer, perr := newPrompter(env.In, env.Err).line(fmt.Sprintf("Type the device name to confirm (%s)", device))
		if perr != nil {
			return perr
		}
		if strings.TrimSpace(answer) != device {
			fprintln(env.Err, "Aborted.")
			return nil
		}
	}
	if _, err := env.ConfigDir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
		for i := range m.Keepers {
			if m.Keepers[i].Device == device {
				m.Keepers[i].Revoked = true
				m.Keepers[i].RevokedAt = time.Now().UTC()
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return env.Printer.Print(keeperRevokeResult{
		Instance: name, Device: device, Expires: found.Expires, Remaining: remaining,
	})
}

type keeperRevokeResult struct {
	Instance  string    `json:"instance"`
	Device    string    `json:"device"`
	Expires   time.Time `json:"leaf_expires,omitzero"`
	Remaining int       `json:"remaining"`
}

func (r keeperRevokeResult) Human(w io.Writer) error {
	fprintf(w, "✓ %q is revoked in this machine's records — %d active keeper(s) left for %q\n",
		r.Device, r.Remaining, r.Instance)
	fprintln(w, "\nThis did not reach the cluster, and it did not invalidate the device's certificate.")
	if !r.Expires.IsZero() {
		fprintf(w, "That certificate stops working on its own at %s.\n", r.Expires.UTC().Format(time.RFC3339))
	}
	fprintf(w, "If the device was lost, retire what it HOLDS:\n\n  farcast storage rekey %s\n\n", r.Instance)
	fprintln(w, "Rekey changes the scope keys, so that device's bundle opens nothing written afterwards.")
	fprintln(w, "It does not reach backwards: anything it already read, it already read.")
	if r.Remaining < 2 {
		fprintf(w, "\n%q now has %d active keeper(s). Enrol another before you rely on unattended recovery.\n",
			r.Instance, r.Remaining)
	}
	return nil
}

// ------------------------------------------------------------- helpers

func upsertKeeper(list []config.Keeper, k config.Keeper) []config.Keeper {
	for i := range list {
		if list[i].Device == k.Device {
			// Re-enrolment replaces the row and clears a revocation: the
			// operator has just issued this device a fresh leaf, which is a
			// deliberate readmission rather than an accident.
			list[i] = k
			return list
		}
	}
	return append(list, k)
}

// activeKeepers counts the fleet, optionally including one about to be added.
func activeKeepers(list []config.Keeper, adding string) int {
	n, seen := 0, false
	for _, k := range list {
		if k.Revoked {
			continue
		}
		n++
		if k.Device == adding {
			seen = true
		}
	}
	if adding != "" && !seen {
		n++
	}
	return n
}

// leafExpiry reads a leaf's NotAfter, which is the fleet's only automatic
// revocation. A certificate that will not parse yields the zero time rather
// than an error: enrolment has already succeeded by this point, and the date is
// a convenience for the operator, not a precondition.
func leafExpiry(certPEM []byte) time.Time {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}
	}
	return cert.NotAfter.UTC()
}
