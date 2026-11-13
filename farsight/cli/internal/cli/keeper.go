package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"slices"
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
	id, err := keeperIdentity(cfg, caPEM, leafCert, leafKey)
	if err != nil {
		return nil, err
	}
	return tunnel.Connect(ctx, "https://"+cfg.Carrier, id)
}

// keeperIdentity is the local half of keeperTunnel: what this device presents,
// and the CA it checks FatLine against. Its failures are this device's own,
// which no retry mends; the dial's are not.
func keeperIdentity(cfg keeper.Config, caPEM, leafCert, leafKey []byte) (tunnel.ClientIdentity, error) {
	cert, err := tls.X509KeyPair(leafCert, leafKey)
	if err != nil {
		return tunnel.ClientIdentity{}, fmt.Errorf("keeper: this device's certificate and key do not form a pair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		// Without the instance CA there is no way to tell FatLine from
		// anything else answering on that address, and the system roots would
		// accept exactly that.
		return tunnel.ClientIdentity{}, fmt.Errorf("keeper: this device holds no usable CA certificate for %q", cfg.Instance)
	}
	return tunnel.ClientIdentity{Cert: cert, CA: pool, ServerName: cfg.ServerName}, nil
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
// Enrolment is by request (ADR 0020 decision 3). The device makes its own key
// and a request for it (request); the operator's machine certifies that key
// once the operator has confirmed its fingerprint against the device's screen
// (enroll), and the device installs the certificate beside its key (install).
// No private key ever travels. Two verbs run on the OPERATOR's machine (enroll,
// revoke) because they need the CA key. Three run on the KEEPER device
// (request, install, run). status runs on either and reads whatever ledgers
// that machine has.

func newKeeperCommand() Command {
	subs := NewRegistry()
	subs.Register(&keeperRequestCommand{})
	subs.Register(&keeperEnrollCommand{})
	subs.Register(&keeperInstallCommand{})
	subs.Register(&keeperRunCommand{})
	subs.Register(&keeperStatusCommand{})
	subs.Register(&keeperRevokeCommand{})
	subs.Register(&keeperUninstallCommand{})
	return &group{
		name:     "keeper",
		synopsis: "Devices that re-seed a restart-sealed instance unattended (request, enroll, install, run, status, revoke, uninstall)",
		subs:     subs,
		usage: `
Usage: farcast keeper <request|enroll|install|run|status|revoke|uninstall> [flags] [arguments]

A keeper is an operator-owned device that hands a restarted keyholder its key
material back, so storage recovers in minutes instead of whenever somebody
wakes up. Running FarCast as a server needs at least two enrolled keepers.

Subcommands:
  request  Make this device a key, and the request that enrols it (keeper device)
  enroll   Certify a request's key, and issue the bundle (operator's machine)
  install  Accept an enrolment packet on this device    (keeper device)
  run      Keep an instance: watch, and re-seed         (keeper device)
  status   Reconcile what this machine's ledgers record (either)
  revoke   Withdraw a device from the fleet             (operator's machine)
  uninstall Wipe this device's bundle and key, keep its ledger (keeper device)

Enrolment is by request (ADR 0020): the device makes its own key and sends a
request carrying only the public half; the operator confirms the key's
fingerprint against the device's screen before certifying it; and install
refuses a certificate for any other key. FarCast never sends the device's key
anywhere: no request, packet or command carries it. On a desktop it is a 0600
file, not bound to hardware, and with --accept-backup-risk a backup may still
copy it.

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
	request        string
	keySHA256      string
	// interactive says whether a person is at the terminal to type the
	// device's fingerprint; nil is isInteractive. A seam, so the prompt is
	// tested without a terminal.
	interactive func(*Env) bool
}

func (*keeperEnrollCommand) Name() string { return "enroll" }
func (*keeperEnrollCommand) Synopsis() string {
	return "Certify a device's requested key, and issue it the bundle"
}

func (*keeperEnrollCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast keeper enroll <instance> <device> --request <path> [--key-sha256 <hex>] --out <path> --passphrase-file <path>

Enrol one device as a keeper, from the request it made. Run this on the machine
that holds the instance's CA key and keyring — no other machine can do it,
which is the point.

The device made its own key with 'farcast keeper request' and printed the
key's fingerprint; the request file carries only the public half. A request
travels unauthenticated, so the key is certified only once you confirm the
fingerprint against the device's screen: pass it as --key-sha256, or, at a
terminal, type it when asked — all 16 groups, or at least the last 8. Nothing
of it is shown before it matches, so it cannot be copied from this screen.

A key is never reused: one already certified for another device or instance,
one certified before a revoke, and a device's older key are refused. Re-issuing
to a device's newest key — a lost packet, made again from the request still on
hand — is allowed while the device is not revoked.

It writes a passphrase-armored packet carrying the device's certificate, the
scope bundle it will re-seed with, and how to reach and verify the instance,
and no private key. Carry it to the device and run 'keeper install' there.

Flags:
      --request <path>           The request the device made
      --key-sha256 <hex>         The fingerprint the device printed (else asked)
      --out <path>               Where to write the packet
      --passphrase-file <path>   File holding the passphrase; "-" reads stdin
      --budget <n>               Reseeds allowed per window (default 8)
      --window <duration>        The budget window (default 720h, 30 days)

The packet never goes through the instance. FarCast does not distribute the
material it is fed, and an instance that handed out bundles would be exactly
the solicitation endpoint this design exists to avoid.

The device's certificate expires in 90 days. That is the fleet's only automatic
revocation, and re-enrolling — from a new request — is how a device keeps
keeping.`)
}

func (c *keeperEnrollCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.request, "request", "", "the request the device made")
	fs.StringVar(&c.keySHA256, "key-sha256", "", "the key fingerprint the device printed")
	fs.StringVar(&c.out, "out", "", "where to write the packet")
	fs.StringVar(&c.passphraseFile, "passphrase-file", "", "file holding the passphrase")
	fs.IntVar(&c.budget, "budget", keeper.DefaultBudget, "reseeds allowed per window")
	fs.DurationVar(&c.window, "window", keeper.DefaultWindow, "the budget window")
}

// maxRequestFile bounds what enroll reads of a request file. A P-256 request is
// under a kilobyte; identity.ParseRequest refuses anything over this.
const maxRequestFile = 64 << 10

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
	if c.request == "" {
		return usagef("--request is required: run 'farcast keeper request %s --out <path>' on the device, and carry the request here", name)
	}
	var confirmed string
	if c.keySHA256 != "" {
		fp, err := identity.ParseFingerprint(c.keySHA256)
		if err != nil {
			return usagef("--key-sha256: %v", err)
		}
		confirmed = fp
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

	// The request. Refused, it says why and nothing of its key: a refused
	// request's fingerprint is no one's to confirm.
	req, err := readKeeperRequest(c.request)
	if err != nil {
		return err
	}
	fp := req.KeySHA256

	// ADR 0020 decision 3: a key is never certified across devices,
	// instances or a revoke — against every instance this machine records.
	records, err := keeperRecords(env)
	if err != nil {
		return err
	}
	if err := keyCertifiedElsewhere(records, name, device, fp); err != nil {
		return fmt.Errorf("%w; nothing was issued", err)
	}

	// The confirmation. The request's fingerprint is the sender's claim until
	// it matches what the device shows, and it is printed only once it has:
	// shown first, it could be copied back from the line above, or from the
	// scrollback of a failed attempt, which confirms nothing.
	if err := c.confirm(env, device, fp, confirmed); err != nil {
		return err
	}
	first, second := fingerprintLines(fp)
	fprintf(env.Err, "key sha256  %s\n            %s — confirmed against %s\n", first, second, device)

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

	leafCert, err := identity.IssueKeeperClient(mtls.CACertPEM, mtls.CAKeyPEM, name, device, payload, req.DER)
	if err != nil {
		return err
	}
	expires := leafExpiry(leafCert)
	// The token Shrike's tunnel table will attribute this leaf's streams by.
	// Computed and recorded here because this is the only moment this
	// machine holds the leaf: it goes to the device, and without the token
	// the operator could never say which device a stream was. Before the
	// packet is written, so a failure leaves no device holding a leaf this
	// machine cannot name.
	leafToken, err := identity.LeafTokenPEM(leafCert)
	if err != nil {
		return err
	}

	packet := &keeper.Packet{
		Version: 2, Instance: name, Device: device,
		Carrier: meta.Carrier.Endpoint, ServerName: identity.ServerName(name),
		CACertPEM: mtls.CACertPEM, LeafCertPEM: leafCert,
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
			// device's packet, and a packet carries a bundle: whoever holds it
			// with its passphrase reads what the bundle's keys open.
			return fmt.Errorf("%s already exists; refusing to overwrite it", c.out)
		}
		return err
	}
	if _, err := file.Write(sealed); err != nil {
		_ = file.Close()
		_ = os.Remove(c.out)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(c.out)
		return err
	}

	// The record, re-checked against this instance's rows as they are now:
	// UpdateInstanceMetadata reloads and retries rather than locking, so this
	// closure is where a concurrent enroll or revoke of this instance shows.
	var refused error
	if _, err := env.ConfigDir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
		if err := keyCertifiedElsewhere(map[string][]config.Keeper{name: m.Keepers}, name, device, fp); err != nil {
			refused = err
			return err
		}
		m.Keepers = upsertKeeper(m.Keepers, config.Keeper{
			Device: device, EnrolledAt: time.Now().UTC(), Expires: expires,
			Generation: generation, Budget: c.budget, Window: c.window,
			LeafTokens: []string{leafToken}, KeySHA256: []string{fp},
		})
		return nil
	}); err != nil {
		// Either way the packet is this command's own file (created O_EXCL
		// above), its certificate has gone nowhere else, and it is removed:
		// a certificate whose key no record holds is one decision 3's
		// record-based refusals cannot see, and whose leaf token nobody can
		// name. It holds no private key, so removing it loses nothing that
		// running enroll again does not make.
		_ = os.Remove(c.out)
		if refused != nil {
			return fmt.Errorf("%w; the packet was removed, and its certificate never left this machine", refused)
		}
		return fmt.Errorf("recording the enrolment failed (%w); the packet was removed, and its certificate never left this machine: run enroll again", err)
	}

	warnPacketDisclosure(env.Err, c.out, name)
	return env.Printer.Print(keeperEnrollResult{
		Instance: name, Device: device, Path: c.out,
		Generation: generation, Budget: c.budget, Window: c.window.String(), window: c.window, Expires: expires,
		Fleet: activeKeepers(meta.Keepers, device), KeySHA256: fp,
	})
}

// readKeeperRequest reads and checks a device's enrolment request. A refusal
// names the request's fault and never its key.
func readKeeperRequest(path string) (identity.Request, error) {
	f, err := os.Open(path)
	if err != nil {
		return identity.Request{}, fmt.Errorf("read the request: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRequestFile+1))
	_ = f.Close()
	if err != nil {
		return identity.Request{}, fmt.Errorf("read the request: %w", err)
	}
	req, err := identity.ParseRequest(data)
	if err != nil {
		var re *identity.RequestError
		if errors.As(err, &re) {
			return identity.Request{}, fmt.Errorf("the request from %s was refused (%s): %s; nothing was issued", path, re.Refusal, re.Detail)
		}
		return identity.Request{}, fmt.Errorf("the request from %s was refused: %w; nothing was issued", path, err)
	}
	return req, nil
}

// confirm holds the request's key to the fingerprint the device printed:
// --key-sha256 when given, else typed at a terminal. It prints nothing of the
// request's fingerprint, before or in a refusal.
func (c *keeperEnrollCommand) confirm(env *Env, device, fp, given string) error {
	if given != "" {
		if given != fp {
			return fmt.Errorf("the request's key is not the one --key-sha256 names; nothing was issued. "+
				"If you copied the fingerprint from %s's screen, the request was replaced on its way here: make a new one on the device", device)
		}
		return nil
	}
	interactive := c.interactive
	if interactive == nil {
		interactive = isInteractive
	}
	if !interactive(env) {
		return usagef("refusing to issue without confirming the request's key: pass --key-sha256 <the fingerprint 'farcast keeper request' printed on %s>", device)
	}
	answer, err := newPrompter(env.In, env.Err).line(fmt.Sprintf(
		"Type the fingerprint 'farcast keeper request' printed on %s (all 16 groups, or at least the last 8)", device))
	if err != nil {
		return err
	}
	ok, err := identity.FingerprintSuffixMatches(fp, answer)
	if err != nil {
		return fmt.Errorf("type at least the last 8 groups of the fingerprint as %s shows it; nothing was issued", device)
	}
	if !ok {
		return fmt.Errorf("the request's key does not end with what was typed; nothing was issued. "+
			"If you typed it from %s's screen, the request was replaced on its way here: make a new one on the device", device)
	}
	return nil
}

// keeperRecords is every instance's keeper rows on this machine. An instance
// directory with no record holds no rows and is skipped; a record that will
// not load fails closed, naming the instance: a key it would have refused is
// not certified because it could not be read.
func keeperRecords(env *Env) (map[string][]config.Keeper, error) {
	names, err := env.ConfigDir.ListInstances()
	if err != nil {
		return nil, fmt.Errorf("cannot check the key against this machine's records (%v); nothing was issued", err)
	}
	records := make(map[string][]config.Keeper, len(names))
	for _, in := range names {
		m, err := env.ConfigDir.LoadInstanceMetadata(in)
		if errors.Is(err, config.ErrNoInstanceRecord) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("cannot check the key against %s's records (%v); nothing was issued", in, err)
		}
		records[in] = m.Keepers
	}
	return records, nil
}

// keyCertifiedElsewhere applies ADR 0020 decision 3 to a key about to be
// certified for instance/device, against the rows this machine records: a key
// is never certified across devices, instances or a revoke. In order:
//
//   - one in any row's RevokedKeySHA256, this device's included, is refused:
//     that list outlives the re-enrolment that clears the row's Revoked flag;
//   - one recorded for another device, of this instance or another, is
//     refused;
//   - one recorded for this device is a re-issue, allowed only to the
//     device's newest key while the device is not revoked.
func keyCertifiedElsewhere(records map[string][]config.Keeper, instance, device, fp string) error {
	instances := make([]string, 0, len(records))
	for in := range records {
		instances = append(instances, in)
	}
	sort.Strings(instances)
	for _, in := range instances {
		for _, k := range records[in] {
			if slices.Contains(k.RevokedKeySHA256, fp) {
				return fmt.Errorf("this key was certified for %s/%s before it was revoked; a key is never reused across a revoke", in, k.Device)
			}
		}
	}
	for _, in := range instances {
		for _, k := range records[in] {
			if in == instance && k.Device == device {
				continue
			}
			if slices.Contains(k.KeySHA256, fp) {
				return fmt.Errorf("this key is already certified for %s/%s; a device makes a new key for each instance and each request", in, k.Device)
			}
		}
	}
	for _, k := range records[instance] {
		if k.Device != device || !slices.Contains(k.KeySHA256, fp) {
			continue
		}
		if k.Revoked {
			return fmt.Errorf("this key was certified for %s/%s before it was revoked; a key is never reused across a revoke", instance, device)
		}
		if k.KeySHA256[len(k.KeySHA256)-1] != fp {
			return fmt.Errorf("this key is an older key of %s; it made a newer one since, so enrol from a new request", device)
		}
	}
	return nil
}

// warnPacketDisclosure is what enroll says about the packet it wrote (ADR 0020
// Consequences). The hazard is disclosure, not loss, and since ADR 0020 it is
// the bundle's alone: the packet carries a derived bundle and a certificate,
// never a private key and never keys.yaml. Losing it loses nothing; whoever
// holds it with the passphrase can read what the bundle's keys open, and
// cannot present the device's leaf, whose key never left the device —
// provided the key it certifies is the one the operator confirmed. What
// retires the bundle is said in the words 'keeper revoke' uses: revoking does
// not, rotating does, and nothing undoes what was read before.
func warnPacketDisclosure(w io.Writer, path, instance string) {
	fprintf(w, "WARNING: the passphrase is the only thing protecting %s. Anyone holding the packet and the\n", path)
	fprintf(w, "passphrase can read what is stored under the keys its bundle carries. It holds no private key, so it\n")
	fprintf(w, "cannot re-seed through the tunnel, provided the key it certifies is the one you confirmed. 'farcast keeper\n")
	fprintf(w, "revoke' does not retire the bundle; rotating the keys does ('farcast storage key rotate %s', then\n", instance)
	fprintf(w, "'farcast storage key rekey %s'), and nothing undoes what was read before. Losing the packet loses\n", instance)
	fprintf(w, "nothing: make a new request on the device and enrol it again.\n")
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
	// KeySHA256 is the confirmed fingerprint of the key the certificate
	// certifies.
	KeySHA256 string `json:"key_sha256"`

	// window is Window as a duration, for the human line. JSON keeps the
	// flag's own syntax ("720h0m0s"), which a script can parse back.
	window time.Duration
}

func (r keeperEnrollResult) Human(w io.Writer) error {
	fprintf(w, "✓ enrolled %q as a keeper of %q\n", r.Device, r.Instance)
	fprintf(w, "  packet      %s (mode 0600)\n", r.Path)
	fprintf(w, "  key sha256  …%s (confirmed)\n", identity.FingerprintTail(r.KeySHA256))
	fprintf(w, "  bundle      generation %d\n", r.Generation)
	fprintf(w, "  budget      %s per %s\n", plural(r.Budget, "reseed", "reseeds"), humanWindowOr(r.window, r.Window))
	if !r.Expires.IsZero() {
		fprintf(w, "  expires     %s — re-enrol before then, from a new request, or this device stops keeping\n",
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

Accept an enrolment packet on the device that will do the keeping: the device
that ran 'farcast keeper request' for it.

Install writes only the certificate and the bundle, beside the key 'keeper
request' made here, and moves that key into place. The packet carries no key.
A certificate for any other key is refused as a security event, with nothing
installed: either the packet is another device's, or the request was replaced
on its way to the operator and someone else's key was certified under this
device's name. The certificate must also chain to the packet's CA as a client
certificate.

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

	// Open validated the packet's instance name (keeper.ValidateInstance)
	// before it is joined into this path.
	dir := env.ConfigDir.KeeperDir(packet.Instance)
	store, err := keeper.Install(dir, packet, c.acceptRisk)
	if err != nil {
		// A *keeper.ForeignKeyError is returned as it is: its message is
		// the security event, and what to do about it.
		return err
	}
	cfg, err := store.Config()
	if err != nil {
		return err
	}
	return env.Printer.Print(keeperInstallResult{
		Instance: cfg.Instance, Device: cfg.Device, Dir: store.Dir(),
		Generation: cfg.Generation, Budget: cfg.Budget, Window: cfg.Window.String(), window: cfg.Window,
		BackupExcluded: cfg.BackupExcluded, BackupNote: cfg.BackupNote,
		KeySHA256: cfg.KeySHA256, KeyStore: cfg.KeyStore,
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
	KeySHA256      string `json:"key_sha256"`
	KeyStore       string `json:"key_store"`

	// window is Window as a duration, for the human line (see keeperEnrollResult).
	window time.Duration
}

// humanWindowOr names a budget window in days for a person, falling back to
// the recorded string when the duration was not carried.
func humanWindowOr(d time.Duration, recorded string) string {
	if d > 0 {
		return keeper.HumanWindow(d)
	}
	return recorded
}

// backupNote prints a keeper's recorded backup reason. Records written before
// the reason lost its package prefix still carry "keeper: ", which reads as a
// log line in the middle of a sentence.
func backupNote(s string) string { return strings.TrimPrefix(s, "keeper: ") }

func (r keeperInstallResult) Human(w io.Writer) error {
	fprintf(w, "✓ this device is now keeper %q of %q\n", r.Device, r.Instance)
	fprintf(w, "  state       %s (mode 0700)\n", r.Dir)
	if r.KeySHA256 != "" {
		fprintf(w, "  key sha256  …%s, made on this device and certified\n", identity.FingerprintTail(r.KeySHA256))
	}
	fprintf(w, "  bundle      generation %d\n", r.Generation)
	fprintf(w, "  budget      %s per %s\n", plural(r.Budget, "reseed", "reseeds"), humanWindowOr(r.window, r.Window))
	if r.BackupExcluded {
		fprintf(w, "  backup      excluded, and the exclusion was read back\n")
	} else {
		fprintf(w, "  backup      NOT verifiably excluded — %s\n", backupNote(r.BackupNote))
		fprintf(w, "              You accepted this. Keep the directory off every backup and sync path yourself.\n")
	}
	fprintf(w, "\nStart keeping:  farcast keeper run %s\n", r.Instance)
	return nil
}

// ---------------------------------------------------------------- run

type keeperRunCommand struct {
	interval time.Duration
	once     bool
	// check is one pass; nil is keeperCheck. A seam, so the exit status of
	// --once and the loop's refusal to exit are tested without a tunnel.
	check func(ctx context.Context, env *Env, store *keeper.Store, cfg keeper.Config) (keeperPassResult, error)
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

With --once, the exit status says what the pass found:
  0   kept: every replica serves, was re-seeded, or is held by the operator
  3   cannot keep until a person acts: a stale bundle, an unreadable pin, a
      spent budget, or a leaf that does not bind its bundle or has expired
  4   incomplete: a replica or the tunnel did not answer, or another keeper
      pass on this device was running; the next pass retries
  1   a fault on this device: its store, ledger or bundle could not be read,
      or its ledger would not take a write
A re-seed is recorded in the ledger before it is pushed, and is not pushed
when that write fails. A ledger that would not take a write outranks 3 and 4:
that pass still reports every replica, exits 1, and its error names what else
it found. A push refused after its bundle was sent counts against the budget
as one that landed: whatever answered had the bundle.
Without --once it never exits on any of these: it reports, and checks again.

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
		return fmt.Errorf("%w\nMake a request here ('farcast keeper request %s --out <path>'), enrol it on the machine that holds %q's CA key, "+
			"then 'farcast keeper install' here", err, name, name)
	}
	cfg, err := store.Config()
	if err != nil {
		return err
	}
	if !cfg.WipedAt.IsZero() {
		return fmt.Errorf("%w on %s (%s); its ledger remains, and 'farcast keeper status %s' still reads it",
			keeper.ErrWiped, cfg.WipedAt.Format("2006-01-02"), cfg.WipedReason, name)
	}
	check := c.check
	if check == nil {
		check = keeperCheck
	}
	// One pass at a time on this device (keeper.Store.LockPass): a pass that
	// finds another running is incomplete, and the next one retries.
	check = lockedPass(check)
	if c.once {
		pass, err := check(ctx, env, store, cfg)
		if err != nil {
			// A fault on this device outranks what the pass found: a timer
			// that read 3 or 4 here would never learn that the ledger — the
			// control — stopped counting. What the pass found is kept in the
			// one line a timer's log keeps, as text only (%v), so it cannot
			// carry its own exit code over the fault's.
			if perr := keeperPassError(cfg.Instance, pass); perr != nil {
				return fmt.Errorf("%w (the pass also found: %v)", err, perr)
			}
			return err
		}
		return keeperPassError(cfg.Instance, pass)
	}
	fprintf(env.Err, "Keeping %q as %q — checking about every %s, outbound only.\n", cfg.Instance, cfg.Device, c.interval)
	for {
		// The pass's outcome is not consulted here, on purpose: it has been
		// reported, and a keeper that exited on a refusal or an unreachable
		// tunnel would be absent for the next restart, which is what it is for.
		if _, err := check(ctx, env, store, cfg); err != nil {
			if errors.Is(err, keeper.ErrWiped) {
				// Wiped while running — an uninstall, or a release on this
				// machine. Nothing is left to keep.
				return err
			}
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

// lockedPass is check run under this device's pass lock. A pass that finds
// another running makes no call to any replica and writes nothing: it comes
// back as incomplete (exit 4 with --once), and the loop reports it and checks
// again.
func lockedPass(check func(context.Context, *Env, *keeper.Store, keeper.Config) (keeperPassResult, error)) func(context.Context, *Env, *keeper.Store, keeper.Config) (keeperPassResult, error) {
	return func(ctx context.Context, env *Env, store *keeper.Store, cfg keeper.Config) (keeperPassResult, error) {
		release, err := store.LockPass()
		if errors.Is(err, keeper.ErrPassRunning) {
			return keeperPassResult{}, &exitCodeError{code: exitIncomplete, err: fmt.Errorf("%w, so this one made no push; the next one retries", err)}
		}
		if err != nil {
			return keeperPassResult{}, err
		}
		defer release()
		return check(ctx, env, store, cfg)
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

// keeperPassResult is what one pass found: each replica's decision, and the
// fleet's verdict on this device's bundle, which can refuse it while every
// replica serves and no decision says so.
type keeperPassResult struct {
	Decisions []keeper.Decision
	Fleet     keeper.Fleet
}

// keeperPassError is --once's answer: nil when the pass kept the instance,
// and otherwise an error carrying the exit code that says whether a person
// must act (3) or the next pass retries (4). What each replica got has already
// been reported; this is the one line a timer's log keeps.
func keeperPassError(instance string, pass keeperPassResult) error {
	switch keeper.PassOutcome(pass.Decisions, pass.Fleet) {
	case keeper.OutcomeKept:
		return nil
	case keeper.OutcomeIncomplete:
		why := "a replica did not answer"
		for _, d := range pass.Decisions {
			if d.Action.Outcome() == keeper.OutcomeIncomplete {
				// A reason can carry a replica's words — a State or push
				// error, a refusal — and this error keeps its newlines when
				// printed: quoted, it stays one line. The same below, and for
				// the fleet's verdict, which can name a scope a replica serves.
				why = fmt.Sprintf("replica %d: %s — %s", d.Ordinal, d.Action, terminalText(d.Reason))
				break
			}
		}
		return &exitCodeError{code: exitIncomplete, err: fmt.Errorf("the pass over %q did not finish (%s); the next one retries", instance, why)}
	default:
		why := terminalText(pass.Fleet.Refusal())
		if why == "" {
			for _, d := range pass.Decisions {
				if d.Action.Outcome() == keeper.OutcomeCannotKeep {
					why = fmt.Sprintf("replica %d: %s — %s", d.Ordinal, d.Action, terminalText(d.Reason))
					break
				}
			}
		}
		return &exitCodeError{code: exitCannotKeep, err: fmt.Errorf("this device cannot keep %q: %s", instance, why)}
	}
}

// keeperCheck is one pass over the instance's replicas.
func keeperCheck(ctx context.Context, env *Env, store *keeper.Store, cfg keeper.Config) (keeperPassResult, error) {
	caPEM, leafCert, leafKey, bundle, err := store.Material()
	if err != nil {
		return keeperPassResult{}, err
	}
	defer clear(bundle)
	defer clear(leafKey)
	if err := keeperLeafUsable(leafCert, bundle, time.Now()); err != nil {
		return keeperPassResult{}, err
	}

	id, err := keeperIdentity(cfg, caPEM, leafCert, leafKey)
	if err != nil {
		return keeperPassResult{}, err
	}
	conn, err := tunnel.Connect(ctx, "https://"+cfg.Carrier, id)
	if err != nil {
		return keeperPassResult{}, &exitCodeError{code: exitIncomplete, err: fmt.Errorf("cannot reach %q: %w", cfg.Instance, err)}
	}
	defer func() { _ = conn.Close() }()

	client, err := keyholder.New(keyholder.Conn(conn), cfg.Instance, caPEM, leafCert, leafKey)
	if err != nil {
		return keeperPassResult{}, err
	}
	return keeperCheckWith(ctx, env, store, cfg, client, bundle)
}

// keeperLeafUsable is what a keeper checks of its own leaf before dialling.
// Each failure is one every keyholder would answer the same way on every
// pass, so it is a person's to act on (exit 3) and not a retry's. Saying so
// here is cheaper and clearer than a refusal per replica per pass — and an
// expired leaf would otherwise fail at the TLS handshake, which looks exactly
// like a tunnel that did not answer, forever.
func keeperLeafUsable(leafPEM, bundle []byte, now time.Time) error {
	if err := leafBindsBundle(leafPEM, bundle); err != nil {
		return &exitCodeError{code: exitCannotKeep, err: err}
	}
	if exp := leafExpiry(leafPEM); !exp.IsZero() && now.After(exp) {
		return &exitCodeError{code: exitCannotKeep, err: fmt.Errorf(
			"this device's certificate expired on %s, and every keyholder refuses it; re-enrol it from a new request ('farcast keeper request' here, then 'farcast keeper enroll' on the operator's machine)",
			exp.Format(time.RFC3339))}
	}
	return nil
}

// keeperCheckWith is everything a keeper decides and does once it can reach
// the replicas. It is split from the dial so that the decision — above all,
// the fleet-wide staleness verdict handed to every Decide — runs under test:
// that wiring is what stops a keeper enrolled before a rotation putting the
// retired keys back into a replica that restarted, and nothing could reach it
// while it lived behind a real tunnel.
//
// Its one error that comes back WITH a pass is a ledger write that failed —
// before a push, which is then not made, or after one, whose outcome is then
// unknown to the ledger: the pass finished, and what it found is still worth
// saying.
func keeperCheckWith(ctx context.Context, env *Env, store *keeper.Store, cfg keeper.Config, client sealStateClient, bundle []byte) (keeperPassResult, error) {
	entries, err := keyholder.ReadLedger(store.LedgerPath())
	if err != nil {
		return keeperPassResult{}, err
	}
	// Every replica first. Whether this device's bundle is out of date is a
	// question about the whole fleet: a replica that restarted holds nothing
	// to compare against, and the one that did not is what says the keys moved.
	states := make([]keyholder.State, keeperReplicas)
	stErrs := make([]error, keeperReplicas)
	for i := range keeperReplicas {
		states[i], stErrs[i] = client.State(ctx, i)
	}
	parsed, err := datasphere.ParseBundle(bundle)
	if err != nil {
		return keeperPassResult{}, fmt.Errorf("this device's bundle could not be read: %w", err)
	}
	fleet := keeper.FleetOf(parsed, states, stErrs)
	parsed.Zero()
	// The fleet's verdict on this bundle, once per pass and whether or not
	// any replica is sealed: a keeper learns it is stale at the rotation,
	// not at the next restart. Each replica it stops then points here.
	if why := fleet.Refusal(); why != "" {
		fprintf(env.Err, "this device: %s — %s\n", keeper.ActionStale, terminalText(why))
	}

	decisions := make([]keeper.Decision, 0, keeperReplicas)
	// unrecorded is the first ledger write that failed. The pass goes on —
	// every replica is still decided and reported — and ends in that error.
	var unrecorded error
	for i := range keeperReplicas {
		budget := keeper.Budget(entries, cfg.Budget, cfg.Window, time.Now().UTC())
		st, stErr := states[i], stErrs[i]
		d := keeper.Decide(st, stErr, i, cfg.Generation, budget, fleet)
		decisions = append(decisions, d)
		if d.Action != keeper.ActionReseed {
			keeperReport(env, cfg, d, st)
			continue
		}
		// The push is recorded before it is made, and not made when that
		// fails. Recorded afterwards, a ledger that reads but no longer
		// writes — mode 0400 after a restore, a read-only remount, a full
		// disk — would let every pass push and never count it, since the
		// budget is read back from the ledger; a cluster that restarts its
		// replicas between passes would then be re-seeded without limit.
		//
		// Both entries carry one random push id, and only this push's outcome
		// settles this pending entry: another keeper process on this device
		// can announce a push to the same replica in between, and pairing by
		// replica would let its outcome settle this one.
		push := keeper.NewPushID()
		intent := keyholder.LedgerEntry{
			Time: time.Now().UTC(), Instance: cfg.Instance, Ordinal: i,
			Intent: keeper.IntentReseed, Generation: cfg.Generation,
			Device: cfg.Device, Boot: st.Boot, Result: keeper.ResultPending, Push: push,
		}
		if lerr := keyholder.AppendLedger(store.LedgerPath(), intent); lerr != nil {
			if unrecorded == nil {
				unrecorded = fmt.Errorf("this device's ledger did not take the entry a re-seed is recorded in before it is pushed, so none was: %w", lerr)
			}
			d.Action, d.Reason = keeper.ActionLedgerUnwritable, "restart-sealed, and not re-seeded: this device's ledger cannot record the push"
			decisions[len(decisions)-1] = d
			keeperReport(env, cfg, d, st)
			continue
		}
		entries = append(entries, intent)
		pushed, pushErr := client.Unseal(ctx, i, bundle, keeper.IntentReseed)
		entry := keyholder.LedgerEntry{
			Time: time.Now().UTC(), Instance: cfg.Instance, Ordinal: i,
			Intent: keeper.IntentReseed, Generation: cfg.Generation,
			Device: cfg.Device, Boot: st.Boot, Result: "ok", Push: push,
		}
		// A refusal is recorded by whether the bundle had been sent when it
		// came: a refusal after sending counts against the budget and in the
		// audit like a push, because whatever answered the challenge had the
		// bundle (keeper.ResultRefusedAfterSend). Only a push that sent
		// nothing is a plain "refused".
		refused := keeper.ResultRefusedAfterSend
		if keyholder.NothingSent(pushErr) {
			refused = "refused"
		}
		// The reasons below that carry pushErr carry a replica's words. They
		// leave this function only through keeperReport and keeperPassError,
		// and each quotes a reason as one line.
		switch {
		case keyholder.AlreadyServing(pushErr):
			// Unsealed between the read and the push — by the operator, or by
			// another keeper. Nothing to do, and the pass kept the instance;
			// the bundle was still sent, so the push counts (above).
			entry.Result = refused
			d.Action, d.Reason = keeper.ActionNone, "already serving: another pusher reached it first"
		case keyholder.PinUnreadable(pushErr):
			// It restarted between the read and the push and cannot read its
			// pin: it refuses every re-seed whatever the bundle, so a
			// re-enrolment would change nothing.
			entry.Result = refused
			d.Action, d.Reason = keeper.ActionPinUnreadable, keeper.PinUnreadableReason()
		case keyholder.BelowPin(pushErr), keyholder.KeeperBundle(pushErr):
			// The keyholder's own refusal of this device's bundle: the pin
			// moved past it since the read, or the leaf does not bind it.
			// Either way only a re-enrolment changes the answer.
			entry.Result = refused
			d.Action, d.Reason = keeper.ActionStale, pushErr.Error()+"; re-enrol this device"
		case pushErr != nil:
			entry.Result = refused
			d.Action, d.Reason = keeper.ActionUnknown, pushErr.Error()
		default:
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
			// Loud, because the ledger is the control. The pending entry
			// above stands for this push, so the budget still counts it — as
			// a success, whatever it was — and the audit reads it as
			// unconfirmed.
			fprintf(env.Err, "WARNING: the outcome of a reseed was not recorded in the ledger; it counts against the budget as done: %v\n", lerr)
			if unrecorded == nil {
				unrecorded = fmt.Errorf("the outcome of a re-seed was not recorded in this device's ledger, so the budget counts it as done and an audit reads it as unconfirmed: %w", lerr)
			}
		} else {
			// The rest of this pass budgets from what the ledger holds, as the
			// next pass will: a lost outcome leaves its pending entry standing.
			entries = append(entries, entry)
		}
		keeperReport(env, cfg, d, st)
	}
	pass := keeperPassResult{Decisions: decisions, Fleet: fleet}
	if unrecorded != nil {
		// A fault on this device, and not a warning: the ledger is the
		// control, and a keeper on a timer that exited 0 here would leave a
		// ledger that no longer takes writes with nobody told. Every replica
		// was still decided and reported above; the pass comes back beside
		// the error so --once can name what else it found.
		return pass, unrecorded
	}
	return pass, nil
}

// leafBindsBundle checks that this device's leaf names the bundle it holds.
// The keyholder refuses a keeper's push of any other bundle — and of any
// bundle at all from a leaf that names none, which is a keeper enrolled
// before the binding existed.
func leafBindsBundle(leafPEM, bundle []byte) error {
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		return errors.New("this device's leaf is unreadable; re-enrol it")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("this device's leaf is unreadable (%v); re-enrol it", err)
	}
	want := identity.KeeperBundleURIPrefix + identity.KeeperBundleDigest(bundle)
	for _, u := range cert.URIs {
		if u.String() == want {
			return nil
		}
	}
	return errors.New("this device's leaf does not bind the bundle it holds — it was enrolled before the keyholder required that — " +
		"so every keyholder refuses its re-seeds; re-enrol it from a new request ('farcast keeper request' here, then 'farcast keeper enroll' on the operator's machine)")
}

// keeperReplicas is how many replicas a keeper checks.
//
// A keeper device does not hold instance metadata — it is not the operator's
// machine — so it cannot read the deployed replica count. Two is what ADR 0008
// decision 6 specifies and what `storage deploy` renders; a replica that is not
// there answers with a dial error, which the pass reports and moves past.
const keeperReplicas = 2

// keeperReport says what one replica got. Its words are partly the
// keyholder's — a phase, a boot label, a refusal's message, an operator's hold
// reason — read back through the tunnel, so each goes through terminalText:
// this lands in the device's terminal or its journal.
func keeperReport(env *Env, cfg keeper.Config, d keeper.Decision, st keyholder.State) {
	switch d.Action {
	case keeper.ActionNone:
		if env.Verbose {
			fprintf(env.Err, "replica %d: %s\n", d.Ordinal, terminalText(d.Reason))
		}
	case keeper.ActionReseed:
		fprintf(env.Err, "replica %d: re-seeded %s at generation %d (process %s)\n",
			d.Ordinal, cfg.Instance, cfg.Generation, terminalText(shortBoot(st.Boot)))
	default:
		if d.FleetWide {
			// The why is the fleet's, printed once above this pass's replicas.
			fprintf(env.Err, "replica %d: %s — %s, and not re-seeded: this device's bundle is refused (above)\n",
				d.Ordinal, d.Action, terminalText(st.Phase))
			return
		}
		fprintf(env.Err, "replica %d: %s — %s\n", d.Ordinal, d.Action, terminalText(d.Reason))
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
		dir := env.ConfigDir.KeeperDir(name)
		// A request made here and not installed yet: beside a keeper (a
		// renewal), or alone — a device on its way to being one, which is
		// said as such and not as an error.
		pending, perr := keeper.PendingRequest(dir)
		if pending != nil {
			entry.Pending = &pendingRequest{RequestedAt: pending.CreatedAt, KeySHA256: pending.KeySHA256}
		}
		store, err := keeper.OpenStore(dir)
		if err != nil {
			if entry.Pending == nil {
				if perr != nil {
					err = perr
				}
				entry.Error = err.Error()
			}
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
		entry.KeySHA256 = cfg.KeySHA256
		entry.Wiped, entry.WipedReason = cfg.WipedAt, cfg.WipedReason
		entry.BackupExcluded, entry.BackupNote = cfg.BackupExcluded, cfg.BackupNote
		entry.Reseeds, entry.Boots, entry.Refused = audit.Reseeds, audit.Boots, audit.Refused
		entry.Unlabelled, entry.Unconfirmed = audit.Unlabelled, audit.Unconfirmed
		entry.RefusedAfterSend = audit.RefusedAfterSend
		entry.BudgetUsed, entry.BudgetLimit = budget.Used, budget.Limit
		for _, d := range audit.Divergent {
			entry.Divergent = append(entry.Divergent, divergentRow(d))
			if d.Unconfirmed > 0 || d.RefusedAfterSend > 0 {
				entry.DivergentQualified = true
			}
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
	return env.Printer.Print(keeperStatusResult{
		Keeping: results, Fleet: fleetRows(fleet), FleetBudget: fleetBudgets(fleet, time.Now()),
	})
}

// divergentRow is one process the audit found re-seeded more than once, and
// which of those pushes were not plain successes: an unconfirmed one may never
// have landed (a keeper stopped between recording it and making it), and one
// refused after sending may have lost a race to another pusher. Neither rules
// a solicitation out, so the row stays and says so.
func divergentRow(d keeper.BootCount) string {
	row := fmt.Sprintf("process %s re-seeded %d times (last %s)", terminalText(shortBoot(d.Boot)), d.Count, d.Last.UTC().Format(time.RFC3339))
	var of []string
	if d.Unconfirmed > 0 {
		of = append(of, fmt.Sprintf("%d unconfirmed", d.Unconfirmed))
	}
	if d.RefusedAfterSend > 0 {
		of = append(of, fmt.Sprintf("%d refused after the bundle was sent", d.RefusedAfterSend))
	}
	if len(of) > 0 {
		row += ": " + strings.Join(of, ", ")
	}
	return row
}

type keeperStatusEntry struct {
	Instance    string `json:"instance"`
	Device      string `json:"device,omitempty"`
	Generation  uint64 `json:"generation,omitempty"`
	Reseeds     int    `json:"reseeds"`
	Boots       int    `json:"boots"`
	Refused     int    `json:"refused"`
	Unlabelled  int    `json:"unlabelled,omitempty"`
	Unconfirmed int    `json:"unconfirmed,omitempty"`
	// RefusedAfterSend counts pushes refused after their bundle was sent;
	// each is in Reseeds too. Refused is the pushes that sent nothing.
	RefusedAfterSend int      `json:"refused_after_send,omitempty"`
	BudgetUsed       int      `json:"budget_used"`
	BudgetLimit      int      `json:"budget_limit"`
	BackupExcluded   bool     `json:"backup_excluded"`
	BackupNote       string   `json:"backup_note,omitempty"`
	Divergent        []string `json:"divergent,omitempty"`
	// DivergentQualified is set when a Divergent row counts a push that was
	// unconfirmed or refused after sending, which the human view explains.
	DivergentQualified bool `json:"-"`
	// Wiped is when this device's bundle and key were wiped; its ledger and
	// record remain, which is what this entry reads.
	Wiped       time.Time `json:"wiped,omitzero"`
	WipedReason string    `json:"wiped_reason,omitempty"`
	Error       string    `json:"error,omitempty"`
	// KeySHA256 is the fingerprint of the key this device made and its
	// certificate certifies; empty on a record from before ADR 0020.
	KeySHA256 string `json:"key_sha256,omitempty"`
	// Pending is a request made on this device and not installed yet: the
	// whole of an entry for a device on its way to being a keeper, or a
	// renewal beside an installed one.
	Pending *pendingRequest `json:"pending,omitempty"`
}

// pendingRequest is what status says of a request waiting on this device.
type pendingRequest struct {
	RequestedAt time.Time `json:"requested_at"`
	KeySHA256   string    `json:"key_sha256"`
}

type fleetRow struct {
	Instance string    `json:"instance"`
	Device   string    `json:"device"`
	Expires  time.Time `json:"expires,omitzero"`
	Revoked  bool      `json:"revoked,omitempty"`
	Budget   int       `json:"budget,omitempty"`
	Window   string    `json:"window,omitempty"`
	// KeySHA256 is the newest key this machine certified for the device.
	KeySHA256 string `json:"key_sha256,omitempty"`
}

// fleetBudget is what an instance's keepers may push between them in one
// window: the sum of their budgets. Budgets add across a fleet while each
// device refuses only against its own (ADR 0008 finding 6), so this is the
// figure the restart count is weighed against — two devices at 8 a month
// admit 16 re-seeds a month, which no single device's status would show.
//
// It is a total of LIMITS. What each device has used is in its own ledger,
// on that device; the machine that enrolled the fleet holds none of them.
type fleetBudget struct {
	Instance string `json:"instance"`
	// Window is "" for keepers recorded before the window was, whose budget
	// cannot be added to anyone else's.
	Window  string `json:"window"`
	Devices int    `json:"devices"`
	Reseeds int    `json:"reseeds"`
}

type keeperStatusResult struct {
	Keeping     []keeperStatusEntry `json:"keeping"`
	Fleet       []fleetRow          `json:"fleet,omitempty"`
	FleetBudget []fleetBudget       `json:"fleet_budget,omitempty"`
}

func fleetRows(fleet map[string][]config.Keeper) []fleetRow {
	rows := make([]fleetRow, 0)
	for instance, keepers := range fleet {
		for _, k := range keepers {
			row := fleetRow{Instance: instance, Device: k.Device, Expires: k.Expires, Revoked: k.Revoked, Budget: k.Budget}
			if n := len(k.KeySHA256); n > 0 {
				row.KeySHA256 = k.KeySHA256[n-1]
			}
			if k.Window > 0 {
				row.Window = keeper.HumanWindow(k.Window)
			}
			rows = append(rows, row)
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

// fleetBudgets totals each instance's budgets per window, over the keepers
// that can still push: a revoked device is out of the operator's count, and
// an expired leaf fails the handshake before any budget is consulted.
func fleetBudgets(fleet map[string][]config.Keeper, now time.Time) []fleetBudget {
	type key struct {
		instance string
		window   time.Duration
	}
	sums := map[key]*fleetBudget{}
	for instance, keepers := range fleet {
		for _, k := range keepers {
			if k.Revoked || (!k.Expires.IsZero() && !now.Before(k.Expires)) {
				continue
			}
			kk := key{instance, k.Window}
			b := sums[kk]
			if b == nil {
				b = &fleetBudget{Instance: instance}
				if k.Window > 0 {
					b.Window = keeper.HumanWindow(k.Window)
				}
				sums[kk] = b
			}
			b.Devices++
			b.Reseeds += k.Budget
		}
	}
	out := make([]fleetBudget, 0, len(sums))
	for _, b := range sums {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Instance != out[j].Instance {
			return out[i].Instance < out[j].Instance
		}
		return out[i].Window < out[j].Window
	})
	return out
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
		if e.Device == "" && e.Pending != nil {
			fprintf(w, "%s: not a keeper yet — %s\n", e.Instance, pendingLine(e.Pending))
			continue
		}
		fprintf(w, "%s (as %q, bundle generation %d)\n", e.Instance, e.Device, e.Generation)
		if e.KeySHA256 != "" {
			fprintf(w, "  key         …%s, made on this device\n", identity.FingerprintTail(e.KeySHA256))
		}
		if e.Pending != nil {
			fprintf(w, "  renewal     %s\n", pendingLine(e.Pending))
		}
		if !e.Wiped.IsZero() {
			fprintf(w, "  material    wiped %s (%s) — this device no longer keeps it\n", e.Wiped.Format("2006-01-02"), e.WipedReason)
		}
		fprintf(w, "  reseeds     %d into %s", e.Reseeds, plural(e.Boots, "distinct keyholder process", "distinct keyholder processes"))
		if e.Refused > 0 {
			fprintf(w, ", %d refused", e.Refused)
		}
		fprintln(w, "")
		fprintf(w, "  budget      %d of %d used\n", e.BudgetUsed, e.BudgetLimit)
		if !e.BackupExcluded {
			fprintf(w, "  backup      NOT verifiably excluded — %s\n", backupNote(e.BackupNote))
		}
		if e.Unlabelled > 0 {
			fprintf(w, "  unlabelled  %d reseed(s) name no process, so they cannot be reconciled\n", e.Unlabelled)
		}
		if e.Unconfirmed > 0 {
			fprintf(w, "  unconfirmed %d push(es) recorded before they were made and never after, counted above as re-seeds\n", e.Unconfirmed)
		}
		if e.RefusedAfterSend > 0 {
			fprintf(w, "  after send  %d push(es) refused after the bundle was sent, counted above as re-seeds\n", e.RefusedAfterSend)
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
			if e.DivergentQualified {
				fprintf(w, "              An unconfirmed push may never have landed — a keeper stopped between\n")
				fprintf(w, "              recording a push and making it reads the same — and one refused after\n")
				fprintf(w, "              sending may have lost a race to another pusher. Neither rules it out.\n")
			}
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
			budget := ""
			if f.Budget > 0 && !f.Revoked {
				budget = fmt.Sprintf("  budget %d", f.Budget)
				if f.Window != "" {
					budget += " per " + f.Window
				}
			}
			fprintf(w, "  %-12s %s%s%s\n", f.Instance, f.Device, status, budget)
		}
		for _, b := range r.FleetBudget {
			if b.Window == "" {
				fprintf(w, "  %-12s fleet budget: %d reseed(s) across %d device(s) enrolled before windows were recorded — re-enrol them to total it\n",
					b.Instance, b.Reseeds, b.Devices)
				continue
			}
			fprintf(w, "  %-12s fleet budget: up to %s per %s across %d device(s)\n",
				b.Instance, plural(b.Reseeds, "reseed", "reseeds"), b.Window, b.Devices)
		}
		if len(r.FleetBudget) > 0 {
			fprintln(w, "  The fleet budget is a total of limits, not of use: each device's ledger is on that device.")
		}
	}
	return nil
}

// pendingLine says what status knows of a request waiting on this device.
func pendingLine(p *pendingRequest) string {
	return fmt.Sprintf("request pending since %s, key …%s; carry it to the operator's machine",
		p.RequestedAt.UTC().Format("2006-01-02"), identity.FingerprintTail(p.KeySHA256))
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

What retires a lost device's BUNDLE is rotating the keys it holds, and this
command prints how rather than implying it already happened:

  farcast storage key rotate <instance>   new keys for every application; the
                                          bundle opens nothing written after
  farcast storage key rekey <instance>    moves existing objects onto them
  farcast keeper request ...              on every keeper you keep, a new key:
  farcast keeper enroll ... --request     their bundles predate the rotation

Every key the device was certified for is recorded as revoked, and stays
refused: re-enrolling the device later readmits it only with a new key from a
new request, never one it held before.

What that does not undo is printed too. Names stay computable, because a
scope's name key cannot rotate. Rekey covers only what is already stored.

Until 'farcast storage key rotate' writes the instance's key pin, the device
can re-seed a keyholder replica that restarts, with the keys it holds — which
are today's keys. A replica already serving refuses a re-seed. Once the pin is
written, every replica refuses the device's bundle (below-pin), serving, sealed
or restarted, and its leaf binds that one bundle, so it has no other to push.

The pin protects only while a replica has loaded it: one that starts without it
checks nothing. 'farcast storage state' reports that as "none loaded", and
'farcast storage key pin' restores it. Until its certificate expires the device
can still reach the keyholder and read each replica's state; it cannot release
an operator's hold.`)
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
				// Every key the device held, kept where a re-enrolment
				// cannot clear it: that clears Revoked, deliberately, and a
				// key certified before the revoke must stay refused (ADR 0020
				// decision 3).
				m.Keepers[i].RevokedKeySHA256 = appendNew(m.Keepers[i].RevokedKeySHA256, m.Keepers[i].KeySHA256...)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return env.Printer.Print(keeperRevokeResult{
		Instance: name, Device: device, Expires: found.Expires, Remaining: remaining,
		Remedy: revokeRemedy(name),
	})
}

// revokeRemedy is what retires a revoked device's bundle, in the order it has
// to happen. The command it used to print, 'farcast storage rekey', does not
// exist; and rekey on its own moves objects onto keys a rotation has to mint
// first — on the 2026-10-06 walk the pair rewrote nothing, because neither
// reached an application's scope.
func revokeRemedy(instance string) []string {
	return append([]string{
		"farcast storage key rotate " + instance,
		"farcast storage key rekey " + instance,
	}, reenrolLines(instance, nil)...)
}

// reenrolLines is how a keeper is enrolled again since ADR 0020, as every
// command that advises it prints it: a new request on each device, then
// enroll by request on this machine — per device when they are named, and
// once with <device> when they are not.
func reenrolLines(instance string, devices []string) []string {
	lines := []string{"farcast keeper request " + instance + " --out <path>   (on each device)"}
	if len(devices) == 0 {
		return append(lines, "farcast keeper enroll "+instance+" <device> --request <path> --out <path> --passphrase-file <path>   (each keeper you keep)")
	}
	for _, d := range devices {
		lines = append(lines, "farcast keeper enroll "+instance+" "+d+" --request <path> --out <path> --passphrase-file <path>")
	}
	return lines
}

type keeperRevokeResult struct {
	Instance  string    `json:"instance"`
	Device    string    `json:"device"`
	Expires   time.Time `json:"leaf_expires,omitzero"`
	Remaining int       `json:"remaining"`
	// Remedy is what retires the device's bundle, in order. It is in the
	// result rather than only in the prose, so a script that revokes a device
	// is told the same thing a person is.
	Remedy []string `json:"remedy"`
}

func (r keeperRevokeResult) Human(w io.Writer) error {
	fprintf(w, "✓ %q is revoked in this machine's records — %d active keeper(s) left for %q\n",
		r.Device, r.Remaining, r.Instance)
	fprintln(w, "\nThis did not reach the cluster, and it did not invalidate the device's certificate.")
	if !r.Expires.IsZero() {
		fprintf(w, "That certificate stops working on its own at %s.\n", r.Expires.UTC().Format(time.RFC3339))
	}
	fprintln(w, "\nIf the device was lost, retire what it HOLDS — its bundle carries every application's keys:")
	fprintln(w)
	for _, step := range r.Remedy {
		fprintf(w, "  %s\n", step)
	}
	fprintln(w, "\nRotate gives every application new keys, so the bundle opens nothing written")
	fprintln(w, "afterwards; rekey moves what is already stored onto them. What that does not undo:")
	fprintln(w, "  - it does not reach backwards: anything the device already read, or that")
	fprintln(w, "    anyone captured before the rekey, stays exposed")
	fprintln(w, "  - names: a scope's name key cannot rotate, so the bundle can still compute")
	fprintln(w, "    where each application's objects are stored")
	fprintln(w, "  - until the rotation writes the instance's key pin, the device can re-seed a")
	fprintln(w, "    keyholder replica that restarts, with the keys it holds, which are today's.")
	fprintln(w, "    A replica already serving refuses a re-seed.")
	fprintln(w, "  - once the pin is written, every replica refuses the device's bundle")
	fprintln(w, "    (below-pin), and its leaf binds that one bundle, so it has no other to push.")
	fprintln(w, "  - the pin protects only while a replica has loaded it; one that starts without")
	fprintf(w, "    it checks nothing. 'farcast storage state %s' reports that as \"none loaded\",\n", r.Instance)
	fprintf(w, "    and 'farcast storage key pin %s' restores it.\n", r.Instance)
	if !r.Expires.IsZero() {
		fprintf(w, "  - until its certificate expires (%s), the device can still reach the\n", r.Expires.UTC().Format("2006-01-02"))
	} else {
		fprintln(w, "  - until its certificate expires, the device can still reach the")
	}
	fprintln(w, "    keyholder and read each replica's state; it cannot release an operator's hold.")
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
			//
			// Except the leaf tokens, which accumulate. The earlier leaf is
			// still valid in the cluster until its own NotAfter, and a stream
			// it opens must still be named as this device's. The fingerprints
			// of the keys certified accumulate too, oldest first and once
			// each, and the keys revoked are carried over unchanged: nothing
			// ever clears them (ADR 0020 decision 3).
			k.LeafTokens = append(slices.Clone(list[i].LeafTokens), k.LeafTokens...)
			k.KeySHA256 = appendNew(slices.Clone(list[i].KeySHA256), k.KeySHA256...)
			k.RevokedKeySHA256 = appendNew(slices.Clone(list[i].RevokedKeySHA256), k.RevokedKeySHA256...)
			list[i] = k
			return list
		}
	}
	return append(list, k)
}

// appendNew appends each of add not already in list, keeping list's order. A
// re-issue to the same key moves nothing: the order is when each key was first
// certified, and the newest is last.
func appendNew(list []string, add ...string) []string {
	for _, a := range add {
		if !slices.Contains(list, a) {
			list = append(list, a)
		}
	}
	return list
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

// ------------------------------------------------------------- uninstall

type keeperUninstallCommand struct{ assumeYes bool }

func (*keeperUninstallCommand) Name() string { return "uninstall" }
func (*keeperUninstallCommand) Synopsis() string {
	return "Wipe this device's bundle and leaf key, and keep its ledger"
}

func (*keeperUninstallCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast keeper uninstall <instance> [-y]

Run on a keeper DEVICE. Delete the files here that could open anything — the
bundle and the leaf's private key, and a pending request's key — and stop
keeping the instance. A directory holding only a pending request is accepted
too: its key and record are discarded.

The ledger stays, and so does the record 'farcast keeper status' needs to read
it: it is the evidence of what this device did with key material, and a device
that erased its own history on the way out would remove exactly what an audit
reads afterwards. The certificates stay too; they are public.

This does not revoke the device — the operator's 'farcast keeper revoke' does
that, on the machine that enrolled it — and it reaches nothing in the cluster.
To keep the instance once more, make a new request ('farcast keeper request'),
have it enrolled, and install the packet that comes back.`)
}

func (c *keeperUninstallCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation")
}

func (c *keeperUninstallCommand) Run(_ context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("keeper uninstall takes one instance argument")
	}
	name := args[0]
	if err := keeper.ValidateInstance(name); err != nil {
		return err
	}
	dir := env.ConfigDir.KeeperDir(name)
	store, err := keeper.OpenStore(dir)
	if err != nil {
		// A device on its way to being a keeper holds a request's key and
		// nothing else; uninstalling it discards that.
		pending, perr := keeper.PendingRequest(dir)
		if perr != nil || pending == nil {
			return err
		}
		store = nil
	}
	if !c.assumeYes {
		interactive := env.Printer.Mode == output.ModeHuman && isTerminal(env.In)
		if !interactive {
			return usagef("refusing to uninstall %q's keeper without confirmation; pass --yes", name)
		}
		answer, perr := newPrompter(env.In, env.Err).line(fmt.Sprintf("Type the instance name to wipe this device's bundle and key for it (%s)", name))
		if perr != nil {
			return perr
		}
		if strings.TrimSpace(answer) != name {
			fprintln(env.Err, "Aborted.")
			return nil
		}
	}
	if store == nil {
		if err := keeper.DiscardRequest(dir); err != nil {
			return err
		}
		return env.Printer.Print(keeperUninstallResult{Instance: name, Dir: dir, Status: "discarded"})
	}
	if err := store.Wipe("uninstalled on this device", time.Now()); err != nil {
		return err
	}
	return env.Printer.Print(keeperUninstallResult{Instance: name, Dir: store.Dir(), Ledger: store.LedgerPath(), Status: "wiped"})
}

type keeperUninstallResult struct {
	Instance string `json:"instance"`
	Dir      string `json:"dir"`
	Ledger   string `json:"ledger,omitempty"`
	Status   string `json:"status"` // wiped | discarded
}

func (r keeperUninstallResult) Human(w io.Writer) error {
	if r.Status == "discarded" {
		fprintf(w, "✓ this device's pending request for %q is discarded: its key is deleted, and a packet issued for it will be refused here\n", r.Instance)
		return nil
	}
	fprintf(w, "✓ this device no longer keeps %q: its bundle and leaf key are wiped\n", r.Instance)
	fprintf(w, "  ledger kept at %s — 'farcast keeper status %s' still reads it\n", r.Ledger, r.Instance)
	return nil
}
