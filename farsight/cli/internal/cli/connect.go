package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/fatline"
	"github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/planck"
)

// nlbMonthlyUSD is the standing cost estimate for the public mTLS load balancer
// (ADR 0005), surfaced and confirmed against the instance's cost limit.
const nlbMonthlyUSD = 18

// registryMonthlyCost is what the instance's image registry costs, surfaced but
// never gated (ADR 0007 decision 8): FatLine's image is ~20 MB and same-region
// pulls are free, so it rounds to zero against the ~$18/mo carrier. Gating cents
// would train the operator to click through the gate that matters.
const registryMonthlyCost = "~$0"

// tunnelConn is the slice of *tunnel.Conn connect needs (injectable).
type tunnelConn interface {
	Status(ctx context.Context) (fatline.ConnStatus, error)
	Close() error
}

type connectCommand struct {
	// The image resolution and cluster-apply machinery connect shares with
	// redeploy: the two must not drift on where FatLine's image comes from.
	fatlineDeployer

	carrier    string
	statusOnly bool

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
		c.dial = func(ctx context.Context, endpoint string, id tunnel.ClientIdentity) (tunnelConn, error) {
			conn, err := tunnel.Connect(ctx, endpoint, id)
			if err != nil {
				return nil, err
			}
			return conn, nil
		}
	}
}

func (*connectCommand) Name() string     { return "connect" }
func (*connectCommand) Synopsis() string { return "Open a FatLine tunnel to an instance" }

func (*connectCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast connect <instance> [flags]

Establish the FatLine mutually-authenticated tunnel into an instance. The first
connect bootstraps: it mints the instance's per-instance mTLS identity (the CA
key stays on this machine), ensures the instance's own image registry, puts
FatLine's image there — compiled from a farcast checkout on this machine, with
no container engine involved — deploys FatLine into the cluster, and provisions
its public point of presence: a standing ~$18/month load balancer, confirmed
against the cost limit. Later connects reuse all of it and re-dial.

To change what an already-connected instance runs, use 'farcast redeploy': this
command opens the tunnel, that one replaces the workload inside it.

Flags:
  --carrier <nlb>   Data-plane carrier (default nlb: public mTLS load balancer)
  --status          Only dial the bound carrier and report status (no bootstrap,
                    and no registry access at all)
  -y, --yes         Skip the load-balancer cost confirmation and the build
                    confirmation (required non-interactively)
  --fatline-image   FatLine container image to deploy (default: this instance's
                    own registry, at system/fatline for this farcast version)
  --source <dir>    farcast checkout to build FatLine's image from
                    (default: auto-detected from the working directory)

With --output json the command prints one JSON result and never prompts.`)
}

func (c *connectCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.carrier, "carrier", "nlb", "data-plane carrier (nlb: public mTLS load balancer)")
	fs.BoolVar(&c.statusOnly, "status", false, "only dial the bound carrier and report status")
	c.setYesFlag(fs, "skip the load-balancer cost and build confirmations")
	c.setImageFlags(fs)
}

func (c *connectCommand) Run(ctx context.Context, env *Env, args []string) error {
	c.ensureDefaults()
	if len(args) == 0 {
		return usagef("connect requires an instance name")
	}
	if len(args) > 1 {
		return usagef("connect takes one instance name; got %d arguments", len(args))
	}
	if c.carrier != "nlb" {
		return usagef("unsupported carrier %q (only \"nlb\" is implemented in this phase)", c.carrier)
	}
	// The same opposed intents redeploy rejects: "deploy exactly this" versus
	// "build from here and deploy that". Image resolution is shared between the
	// two commands, and it answers --fatline-image before it ever considers
	// --source, so accepting both here would silently honour one of them.
	if c.fatlineImage != "" && c.sourceDir != "" {
		return usagef("--fatline-image deploys an image as given and --source builds a new one; pass one or the other")
	}
	name := args[0]

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("no such instance %q (run 'farcast install' first): %w", name, err)
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
		case c.fatlineImage != "":
			return usagef("FatLine is already deployed for %q, and --fatline-image only applies to the first connect; "+
				"run 'farcast redeploy %s --fatline-image …' to change the running image", name, name)
		case c.sourceDir != "":
			return usagef("FatLine is already deployed for %q, so this connect builds nothing; --source only applies to the first connect; "+
				"run 'farcast redeploy %s --source …' to rebuild FatLine's image and roll it out", name, name)
		}
	}

	// 1) Data-plane identity: mint on first connect, else load. This follows the
	// not-connected checks above so that a --status probe never mints anything:
	// the instance's CA is its trust root, and a read-only health query has no
	// business creating one as a side effect.
	mtls, err := ensureIdentity(env, name, connected)
	if err != nil {
		return err
	}

	// 2) The instance's own registry (ADR 0007), re-ensured defensively. Not on
	// --status: a health probe must work with no registry access whatsoever.
	var reg *registryAccess
	if !c.statusOnly {
		var rerr error
		if reg, rerr = c.ensureRegistry(ctx, env, name, meta); rerr != nil {
			if c.needsRegistry(connected) {
				return rerr
			}
			// This connect neither pushes nor pulls, so a permission-denied
			// ensure — an instance whose stored installer credential predates
			// ADR 0007's role — must not break a working reconnect.
			fprintf(env.Err, "Warning: %v\n", rerr)
			fprintln(env.Err, "Continuing: this connect deploys nothing, so it needs no image from the registry.")
		}
	}

	// 3) Bootstrap FatLine + bind the carrier, unless that is already done.
	if !c.statusOnly && !connected {
		if err := c.bootstrap(ctx, env, name, meta, mtls, reg); err != nil {
			return err
		}
	}

	// 4) Dial the bound carrier and report status.
	id, err := clientIdentity(mtls, name)
	if err != nil {
		return err
	}
	conn, err := c.dial(ctx, "https://"+meta.Carrier.Endpoint, id)
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
		Registry:  registryPrefix(meta),
		Image:     deployedImage(meta),
		costLimit: meta.CostLimit,
	})
}

// needsRegistry reports whether this connect cannot proceed without the
// instance's registry. Only a bootstrap that has to source FatLine's image from
// it does: a reconnect re-dials what is already running, and an explicit
// --fatline-image names an image the operator vouches for.
func (c *connectCommand) needsRegistry(connected bool) bool {
	return !connected && c.fatlineImage == ""
}

// ensureIdentity mints the per-instance mTLS material on first connect (the CA
// key never leaves this machine) and loads it thereafter.
//
// Minting is connect's alone: every other command passes connected=true and so
// can only ever take the load-or-explain path below. A trust root is created
// once, deliberately, by the command whose job is to establish the boundary.
func ensureIdentity(env *Env, name string, connected bool) (config.MTLSMaterial, error) {
	exists, err := env.ConfigDir.InstanceMTLSExists(name)
	if err != nil {
		return config.MTLSMaterial{}, fmt.Errorf("check identity for %q: %w", name, err)
	}
	if !exists && connected {
		// FatLine is already running and trusts the CA that was minted when it
		// was deployed. Minting a fresh one here would produce a client
		// certificate that instance can only reject, and would overwrite the
		// record of what it actually trusts — so say plainly that the trust
		// root is gone rather than manufacturing a useless one.
		return config.MTLSMaterial{}, fmt.Errorf(
			"instance %q is deployed but its mTLS material is missing from local state; "+
				"the CA it trusts cannot be recovered — restore the instance directory from a backup, or 'farcast release %s' and reinstall",
			name, name)
	}
	if exists {
		m, err := env.ConfigDir.LoadInstanceMTLS(name)
		if err != nil {
			return config.MTLSMaterial{}, fmt.Errorf("load identity for %q: %w", name, err)
		}
		return m, nil
	}
	mat, err := identity.Mint(name)
	if err != nil {
		return config.MTLSMaterial{}, err
	}
	m := toConfigMTLS(mat)
	if err := env.ConfigDir.SaveInstanceMTLS(name, m); err != nil {
		return config.MTLSMaterial{}, fmt.Errorf("save identity for %q: %w", name, err)
	}
	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Minted data-plane identity for %q (the CA key stays local).\n", name)
	}
	return m, nil
}

// bootstrap deploys FatLine and provisions its public carrier. It records the
// (billable) load balancer before waiting for its IP, so an interrupted wait
// never strands an unrecorded cost — the same cost-pillar ordering as install.
func (c *connectCommand) bootstrap(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata, mtls config.MTLSMaterial, reg *registryAccess) error {
	if !meta.FatLineDeployed { // only gate the first, billable deploy
		ok, err := c.confirmCost(env, meta)
		if err != nil {
			return err
		}
		if !ok {
			fprintln(env.Err, "Aborted.")
			return fmt.Errorf("load-balancer cost not confirmed")
		}
	}

	img, err := c.resolveImage(ctx, env, reg)
	if err != nil {
		return err
	}

	manifests, err := renderWorkload(img, deploy.CarrierLoadBalancer, mtls)
	if err != nil {
		return err
	}

	cl := c.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Deploying FatLine to %q…\n", name)
	}
	if err := cl.Apply(ctx, manifests); err != nil {
		return fmt.Errorf("deploy FatLine: %w", err)
	}
	// The load balancer now exists (billable) — record it before the wait,
	// together with the exact image the cluster was told to run.
	meta.FatLineDeployed = true
	recordDeployedImage(meta, img)
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		// The ordering above exists precisely so a billable resource is never
		// unrecorded; silently dropping this error would defeat it. The connect
		// continues — the load balancer is already real either way — but the
		// operator has to know that local state may not name it.
		fprintf(env.Err, "Warning: FatLine is deployed and its load balancer is billable, but recording that locally failed: %v\n", err)
		fprintf(env.Err, "Re-run 'farcast connect %s' to record it; 'farcast release %s' still tears the instance down.\n", name, name)
	}

	if err := cl.RolloutStatus(ctx, deploy.DefaultNamespace, deploy.DefaultName, fatlineRolloutTimeout); err != nil {
		return fmt.Errorf("FatLine rollout: %w", err)
	}
	if isInteractive(env) || env.Verbose {
		fprintln(env.Err, "Waiting for the load balancer to receive a public IP…")
	}
	ip, err := cl.WaitExternalIP(ctx, deploy.DefaultNamespace, deploy.DefaultName, 5*time.Minute)
	if err != nil {
		return err
	}

	meta.Carrier = &config.Carrier{
		Type:       "nlb",
		Endpoint:   fmt.Sprintf("%s:%d", ip, deploy.DefaultTunnelPort),
		ServerName: identity.ServerName(name),
	}
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return fmt.Errorf("record carrier: %w", err)
	}
	return nil
}

// confirmCost gates the billable load balancer. --yes proceeds; a non-interactive
// session without --yes is a usage error (no money spent without consent).
func (c *connectCommand) confirmCost(env *Env, meta *config.InstanceMetadata) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	if !isInteractive(env) {
		return false, usagef("connecting provisions a public load balancer (~$%d/mo); pass --yes to confirm", nlbMonthlyUSD)
	}
	fprintf(env.Err, "Connecting %q provisions a public mTLS load balancer (~$%d/month, against the cost limit %s %.0f/%s).\n",
		meta.Name, nlbMonthlyUSD, meta.CostLimit.Currency, meta.CostLimit.Amount, meta.CostLimit.Period)
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
	Name      string           `json:"name"`
	Connected bool             `json:"connected"`
	Carrier   string           `json:"carrier"`
	Endpoint  string           `json:"endpoint"`
	Identity  string           `json:"identity"`
	Active    int              `json:"active"`
	Allowlist []string         `json:"allowlist,omitempty"`
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
	fprintf(w, "  carrier:     public mTLS NLB  %s\n", r.Endpoint)
	fprintf(w, "  identity:    %s\n", r.Identity)
	fprintf(w, "  active:      %d streams\n", r.Active)
	if len(r.Allowlist) > 0 {
		fprintf(w, "  allowlist:   %d hosts (%s)\n", len(r.Allowlist), strings.Join(r.Allowlist, ", "))
	} else {
		fprintln(w, "  allowlist:   0 hosts (deny-by-default)")
	}
	if r.Registry != "" {
		fprintf(w, "  registry:    %s\n", r.Registry)
	}
	if r.Image != "" {
		fprintf(w, "  image:       %s\n", r.Image)
	}
	fprintf(w, "  cost:        load balancer ~$%d/mo + registry %s/mo (limit: %s %.0f/%s)\n",
		nlbMonthlyUSD, registryMonthlyCost, r.costLimit.Currency, r.costLimit.Amount, r.costLimit.Period)
	return nil
}
