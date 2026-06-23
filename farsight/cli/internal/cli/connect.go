package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/fatline"
	"github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
)

// nlbMonthlyUSD is the standing cost estimate for the public mTLS load balancer
// (ADR 0005), surfaced and confirmed against the instance's cost limit.
const nlbMonthlyUSD = 18

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

type connectCommand struct {
	carrier      string
	statusOnly   bool
	assumeYes    bool
	fatlineImage string

	// Seams, overridable in tests; defaulted by newConnectCommand / ensureDefaults.
	newCluster func(kubeconfigPath string) clusterApplier
	dial       func(ctx context.Context, endpoint string, id tunnel.ClientIdentity) (tunnelConn, error)
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
	if c.fatlineImage == "" {
		c.fatlineImage = defaultFatlineImage()
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
}

func (*connectCommand) Name() string     { return "connect" }
func (*connectCommand) Synopsis() string { return "Open a FatLine tunnel to an instance" }

func (*connectCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast connect <instance> [flags]

Establish the FatLine mutually-authenticated tunnel into an instance. The first
connect bootstraps: it mints the instance's per-instance mTLS identity (the CA
key stays on this machine), deploys FatLine into the cluster, and provisions its
public point of presence — a standing ~$18/month load balancer, confirmed
against the cost limit. Later connects reuse all of it and re-dial.

Flags:
  --carrier <nlb>   Data-plane carrier (default nlb: public mTLS load balancer)
  --status          Only dial the bound carrier and report status (no bootstrap)
  -y, --yes         Skip the load-balancer cost confirmation (required non-interactively)
  --fatline-image   FatLine container image to deploy

With --output json the command prints one JSON result and never prompts.`)
}

func (c *connectCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.carrier, "carrier", "nlb", "data-plane carrier (nlb: public mTLS load balancer)")
	fs.BoolVar(&c.statusOnly, "status", false, "only dial the bound carrier and report status")
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the load-balancer cost confirmation")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the load-balancer cost confirmation")
	fs.StringVar(&c.fatlineImage, "fatline-image", defaultFatlineImage(), "FatLine container image to deploy")
}

func defaultFatlineImage() string {
	return "ghcr.io/sofmon/farcast/fatline:" + buildinfo.Get().Version
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

	// 1) Data-plane identity: mint on first connect, else load.
	mtls, err := c.ensureIdentity(env, name)
	if err != nil {
		return err
	}

	// 2) Bootstrap FatLine + bind the carrier, unless that is already done.
	connected := meta.FatLineDeployed && meta.Carrier != nil
	switch {
	case c.statusOnly && !connected:
		return fmt.Errorf("instance %q is not connected yet — run 'farcast connect %s' first", name, name)
	case !c.statusOnly && !connected:
		if err := c.bootstrap(ctx, env, name, meta, mtls); err != nil {
			return err
		}
	}

	// 3) Dial the bound carrier and report status.
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
		costLimit: meta.CostLimit,
	})
}

// ensureIdentity mints the per-instance mTLS material on first connect (the CA
// key never leaves this machine) and loads it thereafter.
func (c *connectCommand) ensureIdentity(env *Env, name string) (config.MTLSMaterial, error) {
	exists, err := env.ConfigDir.InstanceMTLSExists(name)
	if err != nil {
		return config.MTLSMaterial{}, fmt.Errorf("check identity for %q: %w", name, err)
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
func (c *connectCommand) bootstrap(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata, mtls config.MTLSMaterial) error {
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

	manifests, err := deploy.Render(deploy.Config{
		Image:         c.fatlineImage,
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
	// The load balancer now exists (billable) — record it before the wait.
	meta.FatLineDeployed = true
	meta.UpdatedAt = time.Now().UTC()
	_ = env.ConfigDir.SaveInstanceMetadata(name, meta)

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
	fprintf(w, "  cost:        load balancer ~$%d/mo (limit: %s %.0f/%s)\n",
		nlbMonthlyUSD, r.costLimit.Currency, r.costLimit.Amount, r.costLimit.Period)
	return nil
}
