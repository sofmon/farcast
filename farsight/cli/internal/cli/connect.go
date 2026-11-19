package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/fatline"
	"github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/planck"
	"github.com/sofmon/farcast/technocore/pricing"
)

// registryMonthlyCost is what the instance's image registry costs, surfaced but
// never gated (ADR 0007 decision 8): FatLine's image is ~20 MB and same-region
// pulls are free, so it rounds to zero against the ~$18/mo carrier. Gating cents
// would train the operator to click through the gate that matters.
const registryMonthlyCost = "~$0"

// fatlineMonthlyUSD is what FatLine's own Pods cost, standing, at the requests
// its manifest declares. It is surfaced next to the carrier because it is the
// same order of magnitude as nothing else connect creates, and because ADR 0009
// decision 11 doubled it: the tunnel now runs two replicas so that a node drain
// cannot leave storage unsealable. An operator agreeing to a standing cost
// should see the whole standing cost, not the largest line of it.
//
// It is the POD's requests, which since 2.2's sidecar means FatLine plus the
// Shrike monitor beside it. Autopilot bills the Pod.
var fatlineMonthlyUSD = pricing.WorkloadMonthlyUSD(deploy.DefaultReplicas, deploy.PodRequestCPUMilli, deploy.PodRequestMemMiB)

// tunnelConn is the slice of *tunnel.Conn connect needs (injectable).
type tunnelConn interface {
	Status(ctx context.Context) (fatline.ConnStatus, error)
	Close() error
}

type connectCommand struct {
	// The image resolution and cluster-apply machinery connect shares with
	// redeploy: the two must not drift on where FatLine's image comes from.
	fatlineDeployer

	carrier string
	// warmupRetry and warmupWindow are seams: the walk that motivated the
	// warm-up takes two minutes to reproduce, and a unit suite must not.
	warmupRetry  time.Duration
	warmupWindow time.Duration
	statusOnly   bool

	// Seams, overridable in tests; defaulted by newConnectCommand / ensureDefaults.
	dial func(ctx context.Context, endpoint string, id tunnel.ClientIdentity) (tunnelConn, error)
}

func newConnectCommand() *connectCommand {
	c := &connectCommand{}
	c.ensureDefaults()
	return c
}

func (c *connectCommand) ensureDefaults() {
	c.fatlineDeployer.ensureDefaults()
	if c.carrier == "" {
		c.carrier = "nlb"
	}
	if c.dial == nil {
		c.dial = connectDialDefault
	}
}

// connectDialDefault is connect's dial of the carrier when its seam is
// unset: the real tunnel. It is a package variable for the reason
// openProviderDefault is (A23-49): the package's tests replace it with one
// that refuses, so no test dials a carrier by leaving the seam unset.
var connectDialDefault = func(ctx context.Context, endpoint string, id tunnel.ClientIdentity) (tunnelConn, error) {
	conn, err := tunnel.Connect(ctx, endpoint, id)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// carrierWarmup bounds how long a freshly bound load balancer is given to
// start forwarding. GCP usually programs one within a minute of the address
// appearing; two is slack, not an expectation.
const carrierWarmup = 2 * time.Minute

// carrierRetry is how long to wait between attempts while it warms up.
const carrierRetry = 10 * time.Second

// dialCarrier opens the tunnel, waiting for a just-bound carrier to start
// forwarding if it has to.
func (c *connectCommand) dialCarrier(ctx context.Context, env *Env, endpoint string, id tunnel.ClientIdentity, warmup bool) (tunnelConn, error) {
	conn, err := c.dial(ctx, "https://"+endpoint, id)
	if err == nil || !warmup {
		return conn, err
	}
	fprintf(env.Err, "The load balancer has its address but is not forwarding yet; waiting up to %s.\n", carrierWarmup)

	retry, window := c.warmupRetry, c.warmupWindow
	if retry <= 0 {
		retry = carrierRetry
	}
	if window <= 0 {
		window = carrierWarmup
	}
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retry):
		}
		if conn, err = c.dial(ctx, "https://"+endpoint, id); err == nil {
			return conn, nil
		}
	}
	return nil, err
}

func (*connectCommand) Name() string     { return "connect" }
func (*connectCommand) Synopsis() string { return "Open a FatLine tunnel to an instance" }

func (*connectCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast connect <instance> [flags] [--plan | --confirm <digest>]

Establish the FatLine mutually-authenticated tunnel into an instance. The first
connect bootstraps: it mints the instance's per-instance mTLS identity (the CA
key stays on this machine), ensures the instance's own image registry, pushes
FatLine's and Shrike's images there — the images this farcast carries, checked
against the digests it was released with — deploys FatLine into the cluster, and
provisions its public point of presence: a standing ~$18/month load balancer,
confirmed against the cost limit. Later connects reuse all of it and re-dial.

A farcast built from source carries no images. With no --source, it keeps an
operator or development build recorded for this instance, and compiles any
image it does not keep from a farcast checkout on this machine with its Go,
after its build confirmation (which --yes answers), recording it as a
development build.

To change what an already-connected instance runs, use 'farcast redeploy': this
command opens the tunnel, that one replaces the workload inside it.

Flags:
  --carrier <nlb>   Data-plane carrier (default nlb: public mTLS load balancer)
  --status          Only dial the bound carrier and report status (no bootstrap,
                    and no registry access at all); it writes nothing, so it
                    has no plan
  -y, --yes         Skip the load-balancer cost confirmation and, for --source
                    or a source build, the build confirmation (required
                    non-interactively, unless --plan and then --confirm). It
                    never implies --embedded
  --fatline-image   FatLine image to deploy, digest-pinned
                    (repository@sha256:…) (default: the image this farcast
                    carries, pushed to the instance registry's system/fatline)
  --source <dir>    farcast checkout to build the images from with this
                    machine's Go (a release farcast needs none); recorded as
                    operator-built
  --embedded        Deploy the images this farcast carries, replacing an
                    operator-built image or one another farcast version
                    deployed (never implied by --yes). Beside --fatline-image
                    it governs Shrike's image alone
  --plan            Print what this connect would do, and change nothing: its
                    cost, each image and where it comes from, what it mints,
                    its registry calls, each document it would apply, and what
                    it would print, with the plan's digest. It reads the
                    instance's recorded registry with the installer's key, and
                    no cluster; a reconnect's plan, the registry ensure alone,
                    reads neither. It needs the registry recorded, and never
                    plans FatLine without Shrike
  --confirm <digest>
                    Do exactly the plan with that digest, asking nothing, and
                    refuse, having written nothing, if anything it binds has
                    changed since. Its plan is the consent: one that lists the
                    replacement of an image another farcast version deployed
                    replaces it, with or without --embedded

A plan binds a source build's checkout directory and Go, not what the checkout
holds when --confirm runs.

With --output json the command prints one JSON result and never prompts.`)
}

// The texts of connect's consent (ADR 0023 M2.6, A23-8, A23-35).
const (
	// msgStatusHasNoPlan refuses --status beside --plan or --confirm.
	msgStatusHasNoPlan = "--status only dials the bound carrier and reports; it writes nothing, so it has no plan to print or confirm"
	// msgConnectCostYes is the cost gate's refusal without a terminal and
	// without --yes: the carrier's and FatLine's monthly cost.
	msgConnectCostYes = "connecting provisions a public load balancer (~$%s/mo) and runs FatLine continuously (~$%s/mo); pass --yes to confirm" + consentSuffix
	// msgMaterialAppeared refuses a mint over mTLS material that appeared
	// after the plan, which said mint, was made.
	msgMaterialAppeared = "instance %q's mTLS material appeared after the plan was made, and its plan would mint over it; nothing was written"
	// msgReconnectEnsureFailed is a reconnect's --confirm when the registry
	// ensure its plan bound failed: the status was printed, and the command
	// fails.
	msgReconnectEnsureFailed = "the registry ensure this plan bound did not succeed: %w; the connection status above was read, and nothing else was written"
)

func (c *connectCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.carrier, "carrier", "nlb", "data-plane carrier (nlb: public mTLS load balancer)")
	fs.BoolVar(&c.statusOnly, "status", false, "only dial the bound carrier and report status")
	c.setYesFlag(fs, "skip the load-balancer cost confirmation and, for --source or a source build, the build confirmation")
	c.setImageFlags(fs)
	c.consent.register(fs)
}

// connectState is which of its three jobs a connect does (A23-35).
type connectState int

const (
	// connectFirst is the first deploy: FatLine and its billable carrier.
	connectFirst connectState = iota
	// connectResume finishes a bootstrap that deployed FatLine and was
	// stopped before its carrier was recorded (an interrupted IP wait): the
	// first deploy's steps without its cost question.
	connectResume
	// connectAgain is a reconnect: the registry ensure, then the dial.
	connectAgain
)

func connectStateOf(meta *config.InstanceMetadata) connectState {
	switch {
	case !meta.FatLineDeployed:
		return connectFirst
	case meta.Carrier == nil:
		return connectResume
	}
	return connectAgain
}

// preparedConnect is every decision a connect executes, made once by its
// plan: interactive runs, --yes and --confirm all execute from it.
type preparedConnect struct {
	state    connectState
	identity identityDecision
	// cost is the first deploy's cost fact, which its question is asked from.
	cost plan.CostFact
	// workloadImages are FatLine's and Shrike's images, the registry the
	// plan read (nil for a reconnect, and for a break-glass plan that
	// deploys FatLine alone), and what deciding them said, which the command
	// prints once outside a plan: before it asks anything or, under
	// --confirm, right after the comparison (A23-26).
	workloadImages
}

func (c *connectCommand) Run(ctx context.Context, env *Env, args []string) (err error) {
	// A 403 the writer met says whose it was, once (A20-9).
	var meta *config.InstanceMetadata
	defer func() { err = writerRefused(err, meta) }()
	c.ensureDefaults()
	if len(args) == 0 {
		return usagef("connect requires an instance name")
	}
	if len(args) > 1 {
		return usagef("connect takes one instance name; got %d arguments", len(args))
	}
	mode, digest, err := c.consent.mode(c.assumeYes)
	if err != nil {
		return err
	}
	if c.statusOnly && mode != consentNone {
		return usagef(msgStatusHasNoPlan)
	}
	if c.carrier != "nlb" {
		return usagef("unsupported carrier %q (only \"nlb\" is implemented in this phase)", c.carrier)
	}
	// The same rules redeploy, kernel deploy and storage deploy apply to their
	// image flags, before anything is loaded.
	if err := c.checkImageFlags(); err != nil {
		return err
	}
	name := args[0]

	meta, err = env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("no such instance %q (run 'farcast install' first): %w", name, err)
	}
	if err := recordNamed(meta, name); err != nil {
		return err
	}
	if meta.Status == config.InstanceDeleting {
		return fmt.Errorf("instance %q is being released", name)
	}

	connected := meta.FatLineDeployed && meta.Carrier != nil
	if c.statusOnly && !connected {
		return fmt.Errorf("instance %q is not connected yet — run 'farcast connect %s' first", name, name)
	}
	// The image flags only reach the cluster through a bootstrap, and a
	// reconnect does not bootstrap. Saying so is the point: silently accepting
	// --fatline-image on a reconnect would report success while the old image
	// keeps running, which is exactly the wrong answer when the flag is being
	// used to roll out a FatLine fix. `farcast redeploy` is the command that
	// does honour them against a connected instance.
	if c.statusOnly || connected {
		switch {
		case c.fatlineImage != "" && c.statusOnly:
			return usagef("--status only dials the bound carrier and reports; it deploys nothing, so --fatline-image has no effect")
		case c.sourceDir != "" && c.statusOnly:
			return usagef("--status only dials the bound carrier and reports; it builds nothing, so --source has no effect")
		case c.embedded && c.statusOnly:
			return usagef("--status only dials the bound carrier and reports; it deploys nothing, so --embedded has no effect")
		case c.fatlineImage != "":
			return usagef("FatLine is already deployed for %q, and --fatline-image only applies to the first connect; "+
				"run 'farcast redeploy %s --fatline-image …' to change the running image", name, name)
		case c.sourceDir != "":
			return usagef("FatLine is already deployed for %q, so this connect builds nothing; --source only applies to the first connect; "+
				"run 'farcast redeploy %s --source …' to rebuild FatLine's image and roll it out", name, name)
		case c.embedded:
			return usagef("FatLine is already deployed for %q, so this connect deploys nothing; run 'farcast redeploy %s --embedded' to replace its image", name, name)
		}
	}
	// --status reports and writes nothing: no plan, no registry access at
	// all, and a trust root loaded, never minted.
	if c.statusOnly {
		mtls, err := ensureIdentity(env, name, true)
		if err != nil {
			return err
		}
		return c.report(ctx, env, name, meta, mtls, false)
	}

	var cl clusterApplier
	if !connected {
		// A first deploy or a resume writes to the cluster, so an instance
		// whose objects were last written with kubectl's client-side apply
		// is refused first, in every mode (design A30-20). A reconnect and
		// --status write nothing to it, and never refuse for it.
		if err := refuseUnmigrated(name, meta); err != nil {
			return err
		}
		// A farcast whose carried components it must not push is refused here,
		// in every mode, --plan included, before any plan is computed (A23-10):
		// the first moment connect knows it will deploy, and before it mints,
		// asks or reads the registry. A reconnect deploys nothing, so it is
		// never refused for it.
		if err := c.precheck(); err != nil {
			return err
		}
		// An interactive or --yes run opens the writer, and reads once as it,
		// before its plan (ADR 0023 M2.5); --plan never does, and --confirm
		// right after the comparison (A23-23).
		if mode == consentNone {
			if cl, err = c.readyWriter(ctx, env, meta); err != nil {
				return err
			}
			defer afterWrites(env, name, cl)
		}
	}
	// The identity is decided before the registry is taken, as redeploy
	// decides it: a trust root that is refused (a CA certificate that cannot
	// be read, or is not P-256, or material missing one of its six files)
	// refuses the connect before a record that names no registry is given
	// one, a Google write. Deciding reads the CA certificate alone (A23-25)
	// and looks for the other five files without opening them (A26-2).
	id, err := decideIdentity(env, name, connected)
	if err != nil {
		return err
	}
	var reg *registryAccess
	if !connected {
		if reg, err = c.registryForPlan(ctx, env, name, meta, mode, "connect"); err != nil {
			return err
		}
	}

	p, b, err := c.plan(ctx, env, meta, id, reg)
	if err != nil {
		if mode == consentNone {
			return p.refusal(env, c.embedded, err)
		}
		return err
	}
	switch mode {
	case consentPlan:
		return printPlan(env, b, c.now())
	case consentConfirm:
		if err := confirmPlan(b, digest); err != nil {
			return err
		}
	}
	// What deciding the images said, once (say): before anything is asked
	// or, under --confirm, right after the comparison (A23-26). An
	// interactive or --yes run refuses a version skew there, before it says
	// the lines of the decision it refuses.
	if err := p.say(env, c.embedded || mode == consentConfirm); err != nil {
		return err
	}
	if connected {
		return c.reconnect(ctx, env, name, meta, p, mode)
	}
	if mode == consentConfirm {
		if cl, err = c.readyWriter(ctx, env, meta); err != nil {
			return err
		}
		defer afterWrites(env, name, cl)
	} else if err := c.consented(env, name, p); err != nil {
		return err
	}
	mtls, err := c.bootstrap(ctx, env, cl, name, meta, p, mode)
	if err != nil {
		return err
	}
	// Retried, and only on a bootstrap. A public L4 load balancer has an IP
	// some time before it forwards to anything: `bootstrap` waits for the
	// address to be ASSIGNED, which is the only thing the cloud API will tell
	// it, and the data path is programmed afterwards. Dialling immediately
	// therefore fails on a perfectly healthy instance — the 5.2 walk hit it
	// on a first connect, with both FatLine pods Running and the Service's
	// endpoints already populated, and the error read as a network fault.
	return c.report(ctx, env, name, meta, mtls, true)
}

// plan is connect's plan (design §9.4, A23-35), in one of three states. A
// first deploy binds its cost, FatLine's and Shrike's images, what it mints
// when the instance has no mTLS material, the registry's cloud facts, each
// document of FatLine's workload rendered over placeholders, and its notices.
// A resume binds the same without the cost, and a restart of FatLine when it
// mints over the deployed one. A reconnect binds the registry ensure alone.
// It reads the record, through id the instance's CA certificate (never
// ca.key, decided by Run before the registry is taken), and, through reg,
// the registry; it writes nothing, and reads no cluster and no terminal.
// connect has no block.
//
// On an error the prepared decisions hold what was decided before it, so an
// interactive or --yes run says what it always said first (refusal).
func (c *connectCommand) plan(ctx context.Context, env *Env, meta *config.InstanceMetadata, id identityDecision,
	reg *registryAccess) (preparedConnect, plan.Bound, error) {
	name := meta.Name
	p := preparedConnect{state: connectStateOf(meta), identity: id}
	b := newBound("connect", meta, "none", "")
	b.Options = sortedOptions(append(c.imageOptions(),
		plan.Option{Flag: "carrier", Value: c.carrier},
		plan.Option{Flag: "status", Value: strconv.FormatBool(c.statusOnly)}))

	var err error
	if p.state == connectAgain {
		b.Facts = registryFacts(meta)
		return p, b, nil
	}

	if p.workloadImages, err = c.decideWorkloadImages(ctx, env, reg, meta); err != nil {
		return p, plan.Bound{}, err
	}
	writes, err := p.writeFacts(deploy.CarrierLoadBalancer, placeholderMTLS(name, p.identity))
	if err != nil {
		return p, plan.Bound{}, err
	}

	var facts []plan.Fact
	if p.state == connectFirst {
		p.cost = connectCost(meta)
		facts = append(facts, p.cost)
	}
	facts = append(facts, p.imageFacts(meta)...)
	if p.identity.mint {
		facts = append(facts, identityMints(name)...)
		if p.state == connectResume {
			facts = append(facts, plan.RestartFact{Type: plan.TypeRestart, Component: components.FatLine.Name, Because: plan.RestartBecause})
		}
	}
	facts = append(facts, p.cloudFacts(meta)...)
	facts = append(facts, writes...)
	b.Facts = append(facts, p.noticeFacts()...)
	return p, b, nil
}

// consented is an interactive or --yes run's consent to its plan, asked from
// it: a component another farcast version deployed is refused unless
// --embedded was given, before anything is asked (ADR 0023 decision 4; --yes
// never implies it), as say already refused it, before its lines; then the
// first deploy's cost; then each build.
func (c *connectCommand) consented(env *Env, name string, p preparedConnect) error {
	if err := p.skewRefusal(c.embedded); err != nil {
		return err
	}
	if p.state == connectFirst { // only the first, billable deploy is gated
		ok, err := c.confirmCost(env, name, p.cost)
		if err != nil {
			return err
		}
		if !ok {
			fprintln(env.Err, "Aborted.")
			return fmt.Errorf("load-balancer cost not confirmed")
		}
	}
	return c.buildConsents(env, p.workloadImages)
}

// reconnect re-ensures the registry and dials what is already running
// (A23-35). It opens no writer. An ensure that fails is a warning — a
// stored installer credential that predates ADR 0007's role must not break
// a working reconnect — except under --confirm, whose plan bound that
// ensure: the status still prints, and the command then fails. An instance
// installed with Application Default Credentials is such a failure,
// credential_missing: the deployer's ensure refuses its blank key before
// the provider opens, so a reconnect never ensures as this machine's ADC
// (A26-1). Its plan reads no key; only this ensure does.
func (c *connectCommand) reconnect(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata, p preparedConnect, m consentMode) error {
	mtls, err := realizeIdentity(env, name, p.identity, m)
	if err != nil {
		return err
	}
	// The instance's own registry (ADR 0007), re-ensured defensively.
	_, ensureErr := c.ensureRegistry(ctx, env, name, meta)
	if ensureErr != nil {
		fprintf(env.Err, "Warning: %s\n", output.ErrorText(ensureErr.Error()))
		fprintln(env.Err, "Continuing: this connect deploys nothing, so it needs no image from the registry.")
	}
	// `--status` and a re-connect do NOT retry: there the carrier has been up
	// for a while, so a timeout is real news and waiting two minutes to
	// report it would be the wrong answer.
	if err := c.report(ctx, env, name, meta, mtls, false); err != nil {
		return err
	}
	if ensureErr != nil && m == consentConfirm {
		return fmt.Errorf(msgReconnectEnsureFailed, ensureErr)
	}
	return nil
}

// report dials the bound carrier and prints the connection status. warmup
// waits for a just-bound carrier to start forwarding (dialCarrier).
func (c *connectCommand) report(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata, mtls config.MTLSMaterial, warmup bool) error {
	id, err := clientIdentity(mtls, name)
	if err != nil {
		return err
	}
	conn, err := c.dialCarrier(ctx, env, meta.Carrier.Endpoint, id, warmup)
	if err != nil {
		return fmt.Errorf("connect to %q: %w", name, err)
	}
	defer func() { _ = conn.Close() }()
	st, err := conn.Status(ctx)
	if err != nil {
		return fmt.Errorf("query status of %q: %w", name, err)
	}

	return env.Printer.Print(connectResult{
		Name:      name,
		Connected: st.Connected,
		Carrier:   meta.Carrier.Type,
		Endpoint:  meta.Carrier.Endpoint,
		Identity:  identity.OperatorURI(name),
		Active:    st.Active,
		Allowlist: st.Allowlist,
		Node:      st.Node,
		Registry:  registryPrefix(meta),
		Image:     deployedImage(meta),
		costLimit: meta.CostLimit,
	})
}

// identityDecision is what decideIdentity found: whether the command mints
// the instance's mTLS material, or the CA certificate of the material it has.
type identityDecision struct {
	mint      bool
	caCertPEM []byte
}

// decideIdentity decides whether a command mints the per-instance mTLS
// material or uses what this machine holds (ADR 0023 M2.6, A23-35). It reads
// whether the material exists and, when it does, the CA certificate alone,
// never ca.key: a plan opens no private key (A23-25). Material it would load
// must be whole: each of its six files is looked for without being opened
// (config.Dir.CheckInstanceMTLS, A26-2), so a missing ca.key, or any other
// missing file, is refused here, before a registry is ensured, anything is
// asked or a plan is printed, and not first when realizeIdentity loads it
// after consent. Its refusals are errors in every mode (A23-18).
//
// Minting is connect's alone: every other command passes connected=true and
// so can only ever take the load-or-explain path. A trust root is created
// once, deliberately, by the command whose job is to establish the boundary.
func decideIdentity(env *Env, name string, connected bool) (identityDecision, error) {
	exists, err := env.ConfigDir.InstanceMTLSExists(name)
	if err != nil {
		return identityDecision{}, fmt.Errorf("check identity for %q: %w", name, err)
	}
	if !exists && connected {
		// FatLine is already running and trusts the CA that was minted when it
		// was deployed. Minting a fresh one here would produce a client
		// certificate that instance can only reject, and would overwrite the
		// record of what it actually trusts — so say plainly that the trust
		// root is gone rather than manufacturing a useless one.
		return identityDecision{}, fmt.Errorf(
			"instance %q is deployed but its mTLS material is missing from local state; "+
				"the CA it trusts cannot be recovered — restore the instance directory from a backup, or 'farcast release %s' and reinstall",
			name, name)
	}
	if !exists {
		return identityDecision{mint: true}, nil
	}
	ca, err := env.ConfigDir.LoadInstanceCACert(name)
	if err != nil {
		return identityDecision{}, fmt.Errorf("load identity for %q: %w", name, err)
	}
	if err := requireP256(name, ca); err != nil {
		return identityDecision{}, err
	}
	if err := env.ConfigDir.CheckInstanceMTLS(name); err != nil {
		return identityDecision{}, fmt.Errorf("load identity for %q: %w", name, err)
	}
	return identityDecision{caCertPEM: ca}, nil
}

// requireP256 is ADR 0020's check of an instance's CA: the instance PKI is
// ECDSA P-256. A store minted before it holds an Ed25519 CA, which Apple's
// TLS can neither present nor accept and FatLine no longer loads; there is
// no CA rotation, so the way out is a new instance. Refused before anything
// is dialled or applied, for connect and redeploy alike.
func requireP256(name string, caCertPEM []byte) error {
	if err := identity.RequireP256CA(caCertPEM); err != nil {
		return fmt.Errorf("instance %q: %w — 'farcast release %s', then 'farcast install'", name, err, name)
	}
	return nil
}

// realizeIdentity makes the decision real, after consent (A23-35): it mints
// and saves the material the plan said to mint, or loads what this machine
// holds. SaveInstanceMTLS overwrites, so before minting it looks again:
// material that appeared since the plan was made is never minted over
// (plan_changed under --confirm; internal otherwise), and nothing is
// written.
func realizeIdentity(env *Env, name string, dec identityDecision, m consentMode) (config.MTLSMaterial, error) {
	if !dec.mint {
		mat, err := env.ConfigDir.LoadInstanceMTLS(name)
		if err != nil {
			return config.MTLSMaterial{}, fmt.Errorf("load identity for %q: %w", name, err)
		}
		if err := requireP256(name, mat.CACertPEM); err != nil {
			return config.MTLSMaterial{}, err
		}
		return mat, nil
	}
	exists, err := env.ConfigDir.InstanceMTLSExists(name)
	if err != nil {
		return config.MTLSMaterial{}, fmt.Errorf("check identity for %q: %w", name, err)
	}
	if exists {
		return config.MTLSMaterial{}, changedAfterPlan(m, fmt.Sprintf(msgMaterialAppeared, name))
	}
	mat, err := identity.Mint(name)
	if err != nil {
		return config.MTLSMaterial{}, err
	}
	mtls := toConfigMTLS(mat)
	if err := env.ConfigDir.SaveInstanceMTLS(name, mtls); err != nil {
		return config.MTLSMaterial{}, fmt.Errorf("save identity for %q: %w", name, err)
	}
	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Minted data-plane identity for %q (the CA key stays local).\n", name)
	}
	return mtls, nil
}

// ensureIdentity is decideIdentity and realizeIdentity at once, for a
// command with no plan to put between them: it mints on a first connect and
// loads thereafter.
func ensureIdentity(env *Env, name string, connected bool) (config.MTLSMaterial, error) {
	dec, err := decideIdentity(env, name, connected)
	if err != nil {
		return config.MTLSMaterial{}, err
	}
	return realizeIdentity(env, name, dec, consentNone)
}

// identityMints are a plan's mint facts when the instance has no mTLS
// material: its CA, FatLine's server leaf and the operator's client leaf.
// Their bytes are in no plan.
func identityMints(name string) []plan.Fact {
	return []plan.Fact{
		plan.MintFact{Type: plan.TypeMint, What: plan.MintInstanceCA, Subject: name},
		plan.MintFact{Type: plan.TypeMint, What: plan.MintFatLineLeaf, Subject: identity.ServerName(name)},
		plan.MintFact{Type: plan.TypeMint, What: plan.MintOperatorLeaf, Subject: identity.OperatorURI(name)},
	}
}

// placeholderMTLS is the material a plan renders FatLine's workload with
// (A23-30): the instance's CA certificate as itself when it exists, a
// placeholder when the command mints it, and FatLine's server leaf and key
// always as placeholders, whether the command mints or loads them, so a plan
// opens no key. What it changes in the rendering is only what may differ
// from the real one: the Secret's data and the mTLS hash (A23-31).
func placeholderMTLS(name string, dec identityDecision) config.MTLSMaterial {
	server := identity.ServerName(name)
	ca := dec.caCertPEM
	if dec.mint {
		ca = []byte("farcast-placeholder:instance_ca:" + name + ":cert")
	}
	return config.MTLSMaterial{
		CACertPEM:     ca,
		ServerCertPEM: []byte("farcast-placeholder:fatline_leaf:" + server + ":cert"),
		ServerKeyPEM:  []byte("farcast-placeholder:fatline_leaf:" + server + ":key"),
	}
}

// bootstrap deploys FatLine and provisions its public carrier, through cl, the
// writer Run opened, executing only from the plan's decisions (A23-35): the
// identity, the registry ensure, the images, the workload rendered with the
// real material, then the apply, the record, the rollout, the IP and the
// carrier. It records the (billable) load balancer before waiting for its
// IP, so an interrupted wait never strands an unrecorded cost — the same
// cost-pillar ordering as install. It returns the material the dial uses.
func (c *connectCommand) bootstrap(ctx context.Context, env *Env, cl clusterApplier, name string, meta *config.InstanceMetadata, p preparedConnect, m consentMode) (config.MTLSMaterial, error) {
	mtls, err := realizeIdentity(env, name, p.identity, m)
	if err != nil {
		return config.MTLSMaterial{}, err
	}
	// Shrike ships with the boundary, not after it. It was built at 2.2 and
	// deployed by nothing until now, so every connected instance enforced
	// egress correctly and told no one when something was refused.
	img, shrikeImg, err := c.realizeWorkloadImages(ctx, env, name, meta, p.workloadImages, m)
	if err != nil {
		return config.MTLSMaterial{}, err
	}

	manifests, err := renderWorkload(img.Ref, shrikeImg.Ref, deploy.CarrierLoadBalancer, mtls)
	if err != nil {
		return config.MTLSMaterial{}, err
	}

	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Deploying FatLine to %q…\n", name)
	}
	if err := cl.Apply(ctx, manifests); err != nil {
		return config.MTLSMaterial{}, fmt.Errorf("deploy FatLine: %w", err)
	}
	// The load balancer now exists (billable) — record it before the wait,
	// together with the exact images the cluster was told to run and where
	// they came from (ADR 0023 decision 4).
	meta.FatLineDeployed = true
	recordDeployedImage(meta, img.Ref)
	recordSystemImage(meta, components.FatLine.Name, img.Record)
	recordSystemImage(meta, components.Shrike.Name, shrikeImg.Record)
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		// The ordering above exists precisely so a billable resource is never
		// unrecorded; silently dropping this error would defeat it. The connect
		// continues — the load balancer is already real either way — but the
		// operator has to know that local state may not name it.
		fprintf(env.Err, "Warning: FatLine is deployed and its load balancer is billable, but recording that locally failed: %s\n", output.ErrorText(err.Error()))
		fprintf(env.Err, "Re-run 'farcast connect %s' to record it; 'farcast release %s' still tears the instance down.\n", name, name)
	}

	if err := cl.RolloutStatus(ctx, deploy.DefaultNamespace, deploy.DefaultName, fatlineRolloutTimeout); err != nil {
		return config.MTLSMaterial{}, fmt.Errorf("FatLine rollout: %w", err)
	}
	if isInteractive(env) || env.Verbose {
		fprintln(env.Err, "Waiting for the load balancer to receive a public IP…")
	}
	ip, err := cl.WaitExternalIP(ctx, deploy.DefaultNamespace, deploy.DefaultName, 5*time.Minute)
	if err != nil {
		return config.MTLSMaterial{}, err
	}

	meta.Carrier = &config.Carrier{
		Type:       "nlb",
		Endpoint:   fmt.Sprintf("%s:%d", ip, deploy.DefaultTunnelPort),
		ServerName: identity.ServerName(name),
	}
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return config.MTLSMaterial{}, fmt.Errorf("record carrier: %w", err)
	}
	return mtls, nil
}

// The standing workloads of connect's cost fact, as it names them.
const (
	costWhatCarrier = "the public mTLS load balancer"
	costWhatFatLine = "FatLine and its Shrike monitor"
)

// connectCost is the first deploy's cost fact (A23-33): the load balancer and
// FatLine's replicas, standing, against the instance's cost limit, and the
// instance's floor fully provisioned, with whether the limit is below it,
// computed without printing. The question and the refusal are asked from it
// (connectCostQuestion, msgConnectCostYes), so they say what the plan binds.
func connectCost(meta *config.InstanceMetadata) plan.CostFact {
	f := fullFloorCost(meta)
	f.Standing = []plan.StandingCost{
		{What: costWhatCarrier, Replicas: 1, MonthCents: cents(pricing.CarrierMonthlyUSD)},
		{What: costWhatFatLine, Replicas: deploy.DefaultReplicas, CPUMilli: int64(deploy.PodRequestCPUMilli),
			MemMiB: int64(deploy.PodRequestMemMiB), MonthCents: cents(fatlineMonthlyUSD)},
	}
	return f
}

// fullFloorCost is the cost fact of connect, build and kernel deploy before
// their own workloads are added (A23-33): floorCost over the instance's floor
// fully provisioned.
func fullFloorCost(meta *config.InstanceMetadata) plan.CostFact {
	return floorCost(meta, floorFull(meta))
}

// floorCost is a cost fact before the command's own workloads are added: the
// instance's cost limit, no standing and no one-off cost, the command's floor,
// with whether the limit is below it (warnIfBelowFloor's condition, computed
// without printing), and the rate card's region and date. run states its
// floor as its review does, the instance as it stands with its applications
// in it.
func floorCost(meta *config.InstanceMetadata, floor instanceFloor) plan.CostFact {
	return plan.CostFact{
		Type: plan.TypeCost, Currency: meta.CostLimit.Currency, Period: meta.CostLimit.Period,
		LimitCents:      cents(meta.CostLimit.Amount),
		Standing:        []plan.StandingCost{},
		OneOff:          []plan.OneOffCost{},
		FloorMonthCents: cents(floor.Total),
		BelowFloor:      meta.CostLimit.Amount > 0 && meta.CostLimit.Amount < floor.Total,
		Pricing:         plan.Pricing{Region: pricing.Region, AsOf: pricing.AsOf},
	}
}

// connectCostQuestion is the cost gate's question, from the cost fact, in
// exact cents.
func connectCostQuestion(name string, f plan.CostFact) string {
	carrier, fl := f.Standing[0], f.Standing[1]
	return fmt.Sprintf("Connecting %q provisions a public mTLS load balancer (~$%s/month) and runs FatLine's %d replicas "+
		"continuously (~$%s/month) — ~$%s/month standing, against the cost limit %s/%s.",
		name, amount(carrier.MonthCents), fl.Replicas, amount(fl.MonthCents),
		amount(carrier.MonthCents+fl.MonthCents), money(f.Currency, f.LimitCents), terminalText(f.Period))
}

// confirmCost gates the billable load balancer, from the plan's cost fact.
// --yes proceeds; a non-interactive session without --yes is a usage error
// (no money spent without consent), which names the plan's route.
func (c *connectCommand) confirmCost(env *Env, name string, f plan.CostFact) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	if !isInteractive(env) {
		return false, usagef(msgConnectCostYes, amount(f.Standing[0].MonthCents), amount(f.Standing[1].MonthCents))
	}
	fprintln(env.Err, connectCostQuestion(name, f))
	return newPrompter(env.In, env.Err).yesNo("Provision it and connect?")
}

// Registry plumbing shared by install (creates), connect (re-ensures) and
// release (deletes), so all three name the instance's registry identically.

// registrySpec describes the registry Planck should ensure. The cluster is named
// because the pull grant lands on that cluster's node identity, and the labels
// match install's cluster labels so one instance reads as one recognisable set
// of resources in the cloud console and in a bill.
func registrySpec(meta *config.InstanceMetadata) planck.RegistrySpec {
	return planck.RegistrySpec{
		Name:     meta.Name,
		Location: meta.Region,
		Cluster:  planck.ClusterRef{Name: meta.Cluster, Location: meta.Region},
		Labels:   instanceLabels(meta.Name),
	}
}

// registryRefFor identifies the instance's registry for teardown. It prefers the
// recorded repository and falls back to the instance name and region, so an
// instance whose record predates the registry still has one to delete — the
// provider derives the same name from either.
func registryRefFor(meta *config.InstanceMetadata) planck.RegistryRef {
	ref := planck.RegistryRef{Name: meta.Name, Location: meta.Region}
	if meta.Registry == nil {
		return ref
	}
	if meta.Registry.Repository != "" {
		ref.Name = meta.Registry.Repository
	}
	if meta.Registry.Location != "" {
		ref.Location = meta.Registry.Location
	}
	return ref
}

// recordRegistry stores an ensured registry in metadata, preserving whatever
// image is already recorded as deployed.
func recordRegistry(meta *config.InstanceMetadata, reg *planck.Registry) {
	if meta.Registry == nil {
		meta.Registry = &config.Registry{}
	}
	meta.Registry.Prefix = reg.Prefix
	meta.Registry.Repository = reg.Ref.Name
	meta.Registry.Location = reg.Ref.Location
	meta.Registry.Puller = reg.Puller
}

// recordDeployedImage remembers the exact reference the cluster was told to run,
// so local state can answer "what is running?" without asking the cluster — and
// so a digest that was pinned at deploy time stays visible afterwards.
func recordDeployedImage(meta *config.InstanceMetadata, ref string) {
	if meta.Registry == nil {
		meta.Registry = &config.Registry{}
	}
	meta.Registry.FatLineDigest = ref
}

func registryPrefix(meta *config.InstanceMetadata) string {
	if meta.Registry == nil {
		return ""
	}
	return meta.Registry.Prefix
}

func deployedImage(meta *config.InstanceMetadata) string {
	if meta.Registry == nil {
		return ""
	}
	return meta.Registry.FatLineDigest
}

func toConfigMTLS(m *identity.Material) config.MTLSMaterial {
	return config.MTLSMaterial{
		CACertPEM:     m.CACertPEM,
		CAKeyPEM:      m.CAKeyPEM,
		ClientCertPEM: m.ClientCertPEM,
		ClientKeyPEM:  m.ClientKeyPEM,
		ServerCertPEM: m.ServerCertPEM,
		ServerKeyPEM:  m.ServerKeyPEM,
	}
}

// clientIdentity assembles the tunnel dial identity from stored material —
// without the CLI touching FatLine's internal crypto.
func clientIdentity(m config.MTLSMaterial, name string) (tunnel.ClientIdentity, error) {
	mat := &identity.Material{
		Instance:      name,
		ServerName:    identity.ServerName(name),
		CACertPEM:     m.CACertPEM,
		ClientCertPEM: m.ClientCertPEM,
		ClientKeyPEM:  m.ClientKeyPEM,
	}
	cert, pool, serverName, err := mat.DialTLS()
	if err != nil {
		return tunnel.ClientIdentity{}, err
	}
	return tunnel.ClientIdentity{Cert: cert, CA: pool, ServerName: serverName}, nil
}

func isInteractive(env *Env) bool {
	return env.Printer.Mode == output.ModeHuman && isTerminal(env.In)
}

type connectResult struct {
	Name      string   `json:"name"`
	Connected bool     `json:"connected"`
	Carrier   string   `json:"carrier"`
	Endpoint  string   `json:"endpoint"`
	Identity  string   `json:"identity"`
	Active    int      `json:"active"`
	Allowlist []string `json:"allowlist,omitempty"`
	// Node is where the FatLine replica that answered runs. The load
	// balancer hands a connection to one replica, so it says nothing about
	// the other. Empty from a FatLine that does not report it.
	Node      string           `json:"node,omitempty"`
	Registry  string           `json:"registry,omitempty"`
	Image     string           `json:"image,omitempty"`
	costLimit config.CostLimit // unexported: not serialized; used for the human cost line
}

func (r connectResult) Human(w io.Writer) error {
	status := "connected"
	if !r.Connected {
		status = "reached (boundary reports not-connected)"
	}
	fprintf(w, "✓ %s to %q\n", status, r.Name)
	// The endpoint, the registry and the image are the record's, so they go
	// through terminalText too (ADR 0023 M2.6d, A28-3).
	fprintf(w, "  carrier:     public mTLS NLB  %s\n", terminalText(r.Endpoint))
	fprintf(w, "  identity:    %s\n", r.Identity)
	fprintf(w, "  active:      %d streams\n", r.Active)
	// The allowlist and the node are FatLine's own report, read through the
	// tunnel, so they go through terminalText; --json carries them as they came.
	if len(r.Allowlist) > 0 {
		fprintf(w, "  allowlist:   %d hosts (%s)\n", len(r.Allowlist), terminalText(strings.Join(r.Allowlist, ", ")))
	} else {
		fprintln(w, "  allowlist:   0 hosts (deny-by-default)")
	}
	if r.Node != "" {
		fprintf(w, "  relayed by:  the FatLine replica on %s\n", terminalText(r.Node))
	}
	if r.Registry != "" {
		fprintf(w, "  registry:    %s\n", terminalText(r.Registry))
	}
	if r.Image != "" {
		fprintf(w, "  image:       %s\n", terminalText(r.Image))
	}
	fprintf(w, "  cost:        load balancer ~$%.0f/mo + FatLine and Shrike ~$%.0f/mo + registry %s/mo (limit: %s %.0f/%s)\n",
		pricing.CarrierMonthlyUSD, fatlineMonthlyUSD, registryMonthlyCost, r.costLimit.Currency, r.costLimit.Amount, r.costLimit.Period)
	return nil
}
