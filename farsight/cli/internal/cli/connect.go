package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/fatline"
	"github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/planck"
	_ "github.com/sofmon/farcast/planck/providers" // register cloud adapters (gke)
)

// nlbMonthlyUSD is the standing cost estimate for the public mTLS load balancer
// (ADR 0005), surfaced and confirmed against the instance's cost limit.
const nlbMonthlyUSD = 18

// registryMonthlyCost is what the instance's image registry costs, surfaced but
// never gated (ADR 0007 decision 8): FatLine's image is ~20 MB and same-region
// pulls are free, so it rounds to zero against the ~$18/mo carrier. Gating cents
// would train the operator to click through the gate that matters.
const registryMonthlyCost = "~$0"

const (
	// fatlineImagePath is where FarCast's own images live inside an instance
	// registry (ADR 0007 decision 6: system/<component>). Phase-4 application
	// images land under app/<deployment>/<app> beside it, which is why the one
	// path segment is spent now rather than migrated later.
	fatlineImagePath = "system/fatline"

	// fatlinePackage and fatlineBinary describe the build the CLI performs when
	// that image is missing: one statically linked Go binary laid onto a
	// digest-pinned distroless base. There are no Containerfile steps to
	// execute, which is precisely why no container engine is needed (ADR 0007
	// decision 5).
	fatlinePackage = "./fatline/cmd/fatline"
	fatlineBinary  = "/fatline"
)

// clusterApplier is the slice of the cluster client connect needs (injectable).
type clusterApplier interface {
	Apply(ctx context.Context, manifests []byte) error
	RolloutStatus(ctx context.Context, namespace, name string, timeout time.Duration) error
	WaitExternalIP(ctx context.Context, namespace, name string, timeout time.Duration) (string, error)
}

// tunnelConn is the slice of *tunnel.Conn connect needs (injectable).
type tunnelConn interface {
	Status(ctx context.Context) (fatline.ConnStatus, error)
	Close() error
}

// imageBuilder is the slice of *image.Builder connect needs (injectable): look
// a reference up, and — when it is missing — build and push it.
type imageBuilder interface {
	Resolve(ctx context.Context, ref, user, pass string) (string, error)
	BuildAndPush(ctx context.Context, opts image.Options, user, pass string) (string, error)
}

// registryAccess is the instance's ensured registry plus the ability to mint a
// credential for it.
//
// The credential is minted on demand rather than up front, and only by the paths
// that actually push or pull: it lives in memory for one registry call and is
// never written anywhere (ADR 0007 decision 5), because a push credential for
// the instance's registry is a supply-chain foothold on everything the cluster
// runs. Not minting one on a reconnect also means one less cloud call and one
// less way for a reconnect to fail.
type registryAccess struct {
	provider planck.RegistryProvider
	registry *planck.Registry
}

// credentials mints the short-lived push/pull credential. For Artifact Registry
// the username is a fixed literal and the password is a ~60-minute OAuth2 token
// derived in-process from the stored service-account key.
func (a *registryAccess) credentials(ctx context.Context) (user, pass string, err error) {
	tok, err := a.provider.RegistryToken(ctx)
	if err != nil {
		return "", "", fmt.Errorf("mint a registry credential: %w", err)
	}
	return tok.Username, tok.Password, nil
}

type connectCommand struct {
	carrier      string
	statusOnly   bool
	assumeYes    bool
	fatlineImage string
	sourceDir    string

	// Seams, overridable in tests; defaulted by newConnectCommand / ensureDefaults.
	newCluster   func(kubeconfigPath string) clusterApplier
	dial         func(ctx context.Context, endpoint string, id tunnel.ClientIdentity) (tunnelConn, error)
	openProvider func(meta *config.InstanceMetadata, creds *config.InstanceCredentials) (planck.Provider, error)
	newBuilder   func(progress func(string)) imageBuilder
	findSource   func(dir string) (string, error)
}

func newConnectCommand() *connectCommand {
	c := &connectCommand{}
	c.ensureDefaults()
	return c
}

func (c *connectCommand) ensureDefaults() {
	if c.carrier == "" {
		c.carrier = "nlb"
	}
	if c.newCluster == nil {
		c.newCluster = func(kc string) clusterApplier { return cluster.New(kc) }
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
	if c.openProvider == nil {
		c.openProvider = func(meta *config.InstanceMetadata, creds *config.InstanceCredentials) (planck.Provider, error) {
			return planck.Open(meta.Provider, planck.Config{
				Project:     meta.Project,
				Location:    meta.Region,
				Credentials: []byte(creds.ServiceAccountKey),
			})
		}
	}
	if c.newBuilder == nil {
		c.newBuilder = func(progress func(string)) imageBuilder {
			return &image.Builder{Progress: progress}
		}
	}
	if c.findSource == nil {
		c.findSource = image.FindSource
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
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the load-balancer cost and build confirmations")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the load-balancer cost and build confirmations")
	// The default is empty rather than a ref: it depends on the instance, which
	// is not known until Run loads its metadata (see resolveImage).
	fs.StringVar(&c.fatlineImage, "fatline-image", "", "FatLine container image to deploy (default: the instance registry's system/fatline)")
	fs.StringVar(&c.sourceDir, "source", "", "farcast checkout to build FatLine's image from (default: auto-detected)")
}

// instanceFatlineImage is the default image reference: the instance's own
// registry, at the fixed system path, tagged with this CLI's version.
//
// There is deliberately no central fallback. The ghcr.io default this replaces
// made every instance's network boundary depend on an artifact feed Sofmon
// controls — a standing central dependency and a supply-chain injection point
// aimed at FatLine itself (ADR 0007 decision 4). The tag is what the operator
// reads; the digest is what gets deployed.
func instanceFatlineImage(prefix string) string {
	return prefix + "/" + fatlineImagePath + ":" + imageTag(buildinfo.Get().Version)
}

// imageTag renders a build version as a valid OCI tag.
//
// A tag is [A-Za-z0-9_][A-Za-z0-9._-]{0,127}, which a Go build version does not
// always satisfy: a source build carries a pseudo-version, and one built from a
// tree with uncommitted files ends in "+dirty" — a '+' no registry will accept.
// Folding the unrepresentable characters is right rather than lax, because the
// tag is only the human-readable label here; the digest is what is deployed and
// recorded (ADR 0007 decision 4), so the tag never has to be an exact identity.
func imageTag(version string) string {
	var b strings.Builder
	for _, r := range version {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	tag := b.String()
	if tag == "" {
		return "unknown"
	}
	// The first character may not be '.' or '-'.
	if c := tag[0]; c == '.' || c == '-' {
		tag = "v" + tag
	}
	if len(tag) > 128 {
		tag = tag[:128]
	}
	return tag
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
	// used to roll out a FatLine fix.
	if c.statusOnly || connected {
		switch {
		case c.fatlineImage != "" && c.statusOnly:
			return usagef("--status only dials the bound carrier and reports; it deploys nothing, so --fatline-image has no effect")
		case c.sourceDir != "" && c.statusOnly:
			return usagef("--status only dials the bound carrier and reports; it builds nothing, so --source has no effect")
		case c.fatlineImage != "":
			return usagef("FatLine is already deployed for %q, and --fatline-image only applies to the first connect; "+
				"changing the running image is not yet supported (release and reinstall, or update it in the cluster directly)", name)
		case c.sourceDir != "":
			return usagef("FatLine is already deployed for %q, so there is nothing to build; --source only applies to the first connect", name)
		}
	}

	// 1) Data-plane identity: mint on first connect, else load. This follows the
	// not-connected checks above so that a --status probe never mints anything:
	// the instance's CA is its trust root, and a read-only health query has no
	// business creating one as a side effect.
	mtls, err := c.ensureIdentity(env, name, connected)
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
func (c *connectCommand) ensureIdentity(env *Env, name string, connected bool) (config.MTLSMaterial, error) {
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

// ensureRegistry ensures the instance's image registry and mints a credential
// for it, recording the result locally.
//
// connect re-ensures on every run instead of trusting install to have done it
// (ADR 0007 decision 1): an instance installed before instances had registries
// converges here, rather than failing later as an unexplained ImagePullBackOff
// inside the cluster. The ensure is idempotent, and it is not cost-gated — the
// registry is cents at most (decision 8), unlike the load balancer below.
func (c *connectCommand) ensureRegistry(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata) (*registryAccess, error) {
	creds, err := env.ConfigDir.LoadInstanceCredentials(name)
	if err != nil {
		return nil, fmt.Errorf("load credentials for %q: %w", name, err)
	}
	p, err := c.openProvider(meta, creds)
	if err != nil {
		return nil, err
	}
	rp, ok := p.(planck.RegistryProvider)
	if !ok {
		return nil, fmt.Errorf("provider %q has no image registry: %w", meta.Provider, planck.ErrRegistryUnsupported)
	}
	reg, err := rp.EnsureRegistry(ctx, registrySpec(meta))
	if err != nil {
		return nil, fmt.Errorf("ensure the image registry for %q: %w", name, err)
	}
	recordRegistry(meta, reg)
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return nil, fmt.Errorf("record the image registry: %w", err)
	}
	return &registryAccess{provider: rp, registry: reg}, nil
}

// resolveImage decides what the cluster will be told to run.
//
// The default comes from the instance's own registry and is deployed **pinned
// by digest**: a Deployment that names a tag can be redirected by whoever can
// write that tag, so pinning is what makes a registry-write compromise unable to
// swap FatLine under a running instance (ADR 0007 decision 4). A preflight miss
// is not a failure but an invitation — with a checkout present the CLI builds
// and pushes the image in place, since the operator's machine is FarCast's build
// anchor.
func (c *connectCommand) resolveImage(ctx context.Context, env *Env, reg *registryAccess) (string, error) {
	if c.fatlineImage != "" {
		return c.fatlineImage, nil // the operator named it; deploy exactly that
	}
	if reg == nil { // guarded by needsRegistry; belt and braces
		return "", errors.New("no image registry for this instance and no --fatline-image given")
	}
	ref := instanceFatlineImage(reg.registry.Prefix)
	user, pass, err := reg.credentials(ctx)
	if err != nil {
		return "", err
	}
	b := c.newBuilder(c.progressTo(env))

	pinned, err := b.Resolve(ctx, ref, user, pass)
	switch {
	case err == nil:
		return pinned, nil
	case !errors.Is(err, image.ErrNotFound):
		// Only a literal "absent" counts as a miss. Building over a permission
		// failure would bury it under a long, doomed push.
		return "", fmt.Errorf("look up %s: %w", ref, err)
	}

	source, err := c.findSource(c.sourceDir)
	if err != nil {
		return "", fmt.Errorf("%s is not in the instance's registry yet and there is no farcast checkout to build it from "+
			"(run connect from a farcast checkout, or pass --source <dir>): %w", ref, err)
	}
	ok, err := c.confirmBuild(env, ref, source)
	if err != nil {
		return "", err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return "", fmt.Errorf("%s is not in the instance's registry and building it was declined", ref)
	}
	return b.BuildAndPush(ctx, image.Options{
		SourceDir:  source,
		Package:    fatlinePackage,
		Ref:        ref,
		BinaryPath: fatlineBinary,
		Entrypoint: []string{fatlineBinary},
	}, user, pass)
}

// confirmBuild gates building FatLine's image from source. It is not a cost
// gate — registry storage is ~$0 (ADR 0007 decision 8) — it is a consent gate:
// the build compiles *this* checkout and pushes the result into the one place
// the instance runs code from, so the operator should know it is happening and
// from where.
func (c *connectCommand) confirmBuild(env *Env, ref, source string) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	if !isInteractive(env) {
		return false, usagef("%s is not in the instance's registry yet; pass --yes to build it from %s and push it there", ref, source)
	}
	fprintf(env.Err, "FatLine's image %s is not in the instance's registry yet.\n", ref)
	fprintf(env.Err, "It would be compiled from %s with the local Go toolchain (no container engine) and pushed there.\n", source)
	return newPrompter(env.In, env.Err).yesNo("Build and push it now?")
}

// progressTo returns the sink for build progress: stderr while the operator is
// watching, nothing otherwise — stdout carries only the command's result.
func (c *connectCommand) progressTo(env *Env) func(string) {
	if !isInteractive(env) && !env.Verbose {
		return nil
	}
	return func(line string) { fprintf(env.Err, "  %s\n", line) }
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

	manifests, err := deploy.Render(deploy.Config{
		Image:         img,
		Carrier:       deploy.CarrierLoadBalancer,
		CACertPEM:     mtls.CACertPEM,
		ServerCertPEM: mtls.ServerCertPEM,
		ServerKeyPEM:  mtls.ServerKeyPEM,
	})
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

	if err := cl.RolloutStatus(ctx, deploy.DefaultNamespace, deploy.DefaultName, 3*time.Minute); err != nil {
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
