package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/planck"
	_ "github.com/sofmon/farcast/planck/providers" // register cloud adapters (gke)
)

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

	// fatlineRolloutTimeout bounds the wait for FatLine's Pods to become ready.
	// Both the first deploy and a redeploy use it, so an operator never has to
	// learn two different patience budgets for the same workload.
	fatlineRolloutTimeout = 3 * time.Minute
)

// clusterApplier is the slice of the cluster client the deploying commands need
// (injectable). WaitExternalIP belongs to the first deploy only — a redeploy
// never re-provisions the carrier — but it stays on the one seam so tests can
// assert that it was *not* called.
type clusterApplier interface {
	Apply(ctx context.Context, manifests []byte) error
	RolloutStatus(ctx context.Context, namespace, name string, timeout time.Duration) error
	WaitExternalIP(ctx context.Context, namespace, name string, timeout time.Duration) (string, error)
}

// imageBuilder is the slice of *image.Builder these commands need (injectable):
// look a reference up, and — when it is missing — build and push it.
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

// fatlineDeployer is what `connect` and `redeploy` have in common: the flags and
// the seams that decide *which* FatLine image an instance runs and how it gets
// into the cluster.
//
// It is one shared type rather than two copies because those two commands must
// never drift on image resolution. That path is the supply chain for the
// instance's network boundary — which registry is consulted, what counts as a
// miss rather than a failure, what may be built, and the rule that a deploy is
// always pinned by digest (ADR 0007 decision 4). A second, subtly different copy
// of those rules is exactly how a tag-pinned deploy or an unconfirmed build
// would eventually sneak in.
type fatlineDeployer struct {
	assumeYes    bool
	fatlineImage string
	sourceDir    string

	// Seams, overridable in tests; defaulted by ensureDefaults.
	newCluster   func(kubeconfigPath string) clusterApplier
	openProvider func(meta *config.InstanceMetadata, creds *config.InstanceCredentials) (planck.Provider, error)
	newBuilder   func(progress func(string)) imageBuilder
	findSource   func(dir string) (string, error)
}

func (d *fatlineDeployer) ensureDefaults() {
	if d.newCluster == nil {
		d.newCluster = func(kc string) clusterApplier { return cluster.New(kc) }
	}
	if d.openProvider == nil {
		d.openProvider = func(meta *config.InstanceMetadata, creds *config.InstanceCredentials) (planck.Provider, error) {
			return planck.Open(meta.Provider, planck.Config{
				Project:     meta.Project,
				Location:    meta.Region,
				Credentials: []byte(creds.ServiceAccountKey),
			})
		}
	}
	if d.newBuilder == nil {
		d.newBuilder = func(progress func(string)) imageBuilder {
			return &image.Builder{Progress: progress}
		}
	}
	if d.findSource == nil {
		d.findSource = image.FindSource
	}
}

// setImageFlags registers the two image flags on a command's flag set. They are
// declared once so their names, defaults and meaning cannot drift between the
// command that first deploys FatLine and the one that replaces it.
func (d *fatlineDeployer) setImageFlags(fs *flag.FlagSet) {
	// The default is empty rather than a ref: it depends on the instance, which
	// is not known until Run loads its metadata (see resolveImage).
	fs.StringVar(&d.fatlineImage, "fatline-image", "", "FatLine container image to deploy (default: the instance registry's system/fatline)")
	fs.StringVar(&d.sourceDir, "source", "", "farcast checkout to build FatLine's image from (default: auto-detected)")
}

// setYesFlag registers -y/--yes. The usage string is the caller's, because what
// the flag waives differs: connect's gate is about money, redeploy's is about
// changing what the boundary runs.
func (d *fatlineDeployer) setYesFlag(fs *flag.FlagSet, usage string) {
	fs.BoolVar(&d.assumeYes, "yes", false, usage)
	fs.BoolVar(&d.assumeYes, "y", false, usage)
}

// ensureRegistry ensures the instance's image registry and returns a handle able
// to mint a credential for it, recording the result locally.
//
// Both commands re-ensure on every run instead of trusting install to have done
// it (ADR 0007 decision 1): an instance installed before instances had
// registries converges here, rather than failing later as an unexplained
// ImagePullBackOff inside the cluster. The ensure is idempotent, and it is not
// cost-gated — the registry is cents at most (decision 8), unlike connect's load
// balancer.
func (d *fatlineDeployer) ensureRegistry(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata) (*registryAccess, error) {
	creds, err := env.ConfigDir.LoadInstanceCredentials(name)
	if err != nil {
		return nil, fmt.Errorf("load credentials for %q: %w", name, err)
	}
	p, err := d.openProvider(meta, creds)
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
func (d *fatlineDeployer) resolveImage(ctx context.Context, env *Env, reg *registryAccess) (string, error) {
	if d.fatlineImage != "" {
		return d.fatlineImage, nil // the operator named it; deploy exactly that
	}
	if reg == nil { // guarded by each command's needs-the-registry rule; belt and braces
		return "", errors.New("no image registry for this instance and no --fatline-image given")
	}
	ref := instanceFatlineImage(reg.registry.Prefix)
	user, pass, err := reg.credentials(ctx)
	if err != nil {
		return "", err
	}
	b := d.newBuilder(d.progressTo(env))

	// An explicitly named --source is a request to build, not merely a hint
	// about where source lives. It has to be, because the tag is derived from
	// the *CLI's* version and does not move when FatLine's code changes: an
	// operator patching a FatLine bug and re-running would otherwise hit their
	// own stale image in the preflight and redeploy it, and be told it worked.
	// That is the one class of fix this path exists to ship.
	forceBuild := d.sourceDir != ""

	if !forceBuild {
		pinned, err := b.Resolve(ctx, ref, user, pass)
		switch {
		case err == nil:
			return pinned, nil
		case !errors.Is(err, image.ErrNotFound):
			// Only a literal "absent" counts as a miss. Building over a
			// permission failure would bury it under a long, doomed push.
			return "", fmt.Errorf("look up %s: %w", ref, err)
		}
	}

	source, err := d.findSource(d.sourceDir)
	if err != nil {
		return "", fmt.Errorf("%s is not in the instance's registry yet and there is no farcast checkout to build it from "+
			"(run the command from a farcast checkout, or pass --source <dir>): %w", ref, err)
	}
	ok, err := d.confirmBuild(env, ref, source)
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
func (d *fatlineDeployer) confirmBuild(env *Env, ref, source string) (bool, error) {
	if d.assumeYes {
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
func (d *fatlineDeployer) progressTo(env *Env) func(string) {
	if !isInteractive(env) && !env.Verbose {
		return nil
	}
	return func(line string) { fprintf(env.Err, "  %s\n", line) }
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

// deployCarrier maps the carrier recorded for an instance onto the workload
// shape that realizes it.
//
// A redeploy renders with the carrier the instance already has, never with a
// default: re-rendering a bound instance with a different Service type would
// tear down the point of presence the operator reaches it through, and — for the
// load balancer — replace a standing billable resource and its public IP as a
// side effect of a workload change nobody asked to be one.
func deployCarrier(c *config.Carrier) (deploy.Carrier, error) {
	switch c.Type {
	case "nlb":
		return deploy.CarrierLoadBalancer, nil
	default:
		return "", fmt.Errorf("instance is bound to carrier %q, which this build cannot render", c.Type)
	}
}

// renderWorkload renders FatLine's Kubernetes workload for one image and
// carrier. Both commands render through it, so a redeploy cannot produce a
// workload shaped differently from the one connect bootstrapped — and the CA
// *certificate* plus the server leaf go to the cluster while the CA key, which
// is not part of Config at all, stays on this machine.
func renderWorkload(img string, carrier deploy.Carrier, mtls config.MTLSMaterial) ([]byte, error) {
	return deploy.Render(deploy.Config{
		Image:         img,
		Carrier:       carrier,
		CACertPEM:     mtls.CACertPEM,
		ServerCertPEM: mtls.ServerCertPEM,
		ServerKeyPEM:  mtls.ServerKeyPEM,
	})
}
