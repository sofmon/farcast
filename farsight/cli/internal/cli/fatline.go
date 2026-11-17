package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"go/version"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/oci"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/planck"
	_ "github.com/sofmon/farcast/planck/providers" // register cloud adapters (gke)
)

// fatlineRolloutTimeout bounds the wait for FatLine's Pods to become ready.
// Both the first deploy and a redeploy use it, so an operator never has to
// learn two different patience budgets for the same workload.
const fatlineRolloutTimeout = 3 * time.Minute

// clusterApplier is the slice of the cluster client the deploying commands need
// (injectable). WaitExternalIP belongs to the first deploy only — a redeploy
// never re-provisions the carrier — but it stays on the one seam so tests can
// assert that it was *not* called.
type clusterApplier interface {
	Apply(ctx context.Context, manifests []byte) error
	RolloutStatus(ctx context.Context, namespace, name string, timeout time.Duration) error
	WaitExternalIP(ctx context.Context, namespace, name string, timeout time.Duration) (string, error)
	// Namespaces is here so a command can check what it is about to render
	// into before it builds anything (see kernel deploy).
	Namespaces(ctx context.Context) ([]string, error)
	preflighter
}

// preflighter is the one read a writing command makes as the writer before
// anything it does costs, is asked or is applied (ADR 0023 M2.5, A20-11).
type preflighter interface {
	NamespaceUID(ctx context.Context, name string) (string, error)
}

// preflightNamespace is that read: farcast-system's uid, discarded. It makes
// the first in-process call as the writer, the installer's key, before a
// command's first kubectl Apply could land, so an endpoint or a cluster that
// refuses the writer refuses it before anything was written, asked, minted
// or pushed. "" (no farcast-system yet, a first connect) is no failure.
func preflightNamespace(ctx context.Context, cl preflighter) error {
	if _, err := cl.NamespaceUID(ctx, deploy.DefaultNamespace); err != nil {
		return fmt.Errorf("before changing anything, read the instance's cluster as its installer service account: %w", err)
	}
	return nil
}

// openWriter is every writing seam's default: openCluster as the instance's
// writer, the installer's service-account key (ADR 0023 M2.5). Its reads,
// and the storage key pin's create and replace, run in-process as that key;
// until ADR 0023 M2.7 its Apply runs kubectl as the active gcloud
// configuration.
func openWriter(r clusterRef) (*cluster.Client, error) {
	r.Identity, r.Verifying = kube.Writer, false
	return openCluster(r)
}

// applyReadier is a writer that can say, running nothing and sending
// nothing, whether its Apply could start: cluster.Client.ApplyReady.
type applyReadier interface {
	ApplyReady() error
}

// The cluster client is what every writing seam opens by default, so the
// checks below that find a method by its interface never silently stop
// finding it.
var (
	_ applyReadier = (*cluster.Client)(nil)
	_ pinStore     = (*cluster.Client)(nil)
)

// applyReady is the local check every command that applies makes right after
// it opens its writer, before it reads, asks, mints, pushes, writes or
// records anything (ADR 0023 M2.5, S-F2). Until ADR 0023 M2.7 its Apply runs
// kubectl over the instance's kubeconfig; before M2.5 a missing kubectl or
// kubeconfig was found at the command's first read, which ran kubectl, and
// since M2.5 that read is in-process, so this finds them there instead. It
// cannot find a missing auth plugin or a signed-out gcloud: only kubectl's
// run does. A writer that cannot say (a test's fake) is taken as ready.
func applyReady(cl any) error {
	r, ok := cl.(applyReadier)
	if !ok {
		return nil
	}
	if err := r.ApplyReady(); err != nil {
		return fmt.Errorf("this machine cannot apply to the instance's cluster, so nothing was changed: %w", err)
	}
	return nil
}

// pinStoreFor is the pin a writing command reads and writes: its own seam
// when a test set one; otherwise the writer it already opened, when that
// writer reaches the pin too (the cluster client does), so one writer, one
// read of credentials.yaml and one token serve the whole command (A20-10);
// otherwise the default opener.
func pinStoreFor(seam pinStoreOpener, ref clusterRef, cl any) (pinStore, error) {
	if seam != nil {
		return seam(ref)
	}
	if ps, ok := cl.(pinStore); ok {
		return ps, nil
	}
	return defaultPinStore(ref)
}

// imageBuilder is the slice of *image.Builder these commands need (injectable):
// look a reference up, push the image this farcast carries, and — for --source
// or a source build — compile one and push it.
type imageBuilder interface {
	Resolve(ctx context.Context, ref, user, pass string) (string, error)
	BuildAndPush(ctx context.Context, opts image.Options, user, pass string) (image.Pushed, error)
	PushEmbedded(ctx context.Context, opts image.EmbeddedOptions, user, pass string) (image.Pushed, error)
}

// carriedComponents is what this farcast carries (ADR 0023 decision 4): the
// components package, behind a seam so every resolution rule is tested by an
// untagged test binary, which carries nothing.
type carriedComponents interface {
	Embedded() bool
	Lookup(string) (components.Artifact, bool)
	Layer(string) ([]byte, error)
	Base() string
	Revision() string
	Modified() bool
}

// packageCarried adapts the components package's functions.
type packageCarried struct{}

func (packageCarried) Embedded() bool                              { return components.Embedded() }
func (packageCarried) Lookup(n string) (components.Artifact, bool) { return components.Lookup(n) }
func (packageCarried) Layer(n string) ([]byte, error)              { return components.Layer(n) }
func (packageCarried) Base() string                                { return components.Base() }
func (packageCarried) Revision() string                            { return components.Revision() }
func (packageCarried) Modified() bool                              { return components.Modified() }

// providerOpener opens the cloud provider for an instance. It is a named type
// so the seam is the same one in every command that needs it.
type providerOpener func(meta *config.InstanceMetadata, creds *config.InstanceCredentials) (planck.Provider, error)

// defaultProviderOpener opens the real provider from the instance's recorded
// project, region and service-account key.
func defaultProviderOpener(meta *config.InstanceMetadata, creds *config.InstanceCredentials) (planck.Provider, error) {
	return planck.Open(meta.Provider, planck.Config{
		Project:     meta.Project,
		Location:    meta.Region,
		Credentials: []byte(creds.ServiceAccountKey),
	})
}

// The defaults of the provider and image-builder seams, as package variables
// (ADR 0023 M2.6, A23-49): a command whose seam is unset takes these, and the
// package's tests replace them with fakes that refuse, so no test reaches a
// real cloud provider or registry through these seams by leaving one unset.
// Other seams keep defaults that are real, but for connect's dial
// (connectDialDefault) and the two below.
//
// deployerNowDefault is the deployer's clock, a variable for the same
// reason: a test that runs a command through the router, where it cannot
// set the command's own clock, fixes it here, so a plan bound to the UTC
// day (kernel confirm's) is not made on one day and confirmed on the next.
//
// findSourceDefault and findToolchainDefault are the search for a farcast
// checkout and the question to its Go (`go env`, a process from PATH),
// which deciding a build makes in every mode since M2.6. They are variables
// so the package's tests refuse them too: no test runs this machine's Go,
// or binds the checkout it happens to run in, by leaving either unset.
var (
	openProviderDefault providerOpener = defaultProviderOpener
	newBuilderDefault                  = func(progress func(string)) imageBuilder {
		return &image.Builder{Progress: progress}
	}
	deployerNowDefault   = time.Now
	findSourceDefault    = image.FindSource
	findToolchainDefault = image.FindToolchain
)

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

// fatlineDeployer is what every command that deploys one of FarCast's own
// components has in common: the flags and the seams that decide *which* image
// a component runs and how it gets into the cluster. connect and redeploy
// embed it for FatLine and Shrike; kernel deploy and storage deploy hold one
// for TechnoCore and the keyholder.
//
// It is one shared type rather than four copies because those commands must
// never drift on image resolution. That path is the supply chain for the
// instance's network boundary and its key holder — which registry is
// consulted, what counts as a miss rather than a failure, what may be pushed or
// built, and the rule that a deploy is always pinned by digest (ADR 0007
// decision 4). A second, subtly different copy of those rules is exactly how a
// tag-pinned deploy or an unconfirmed build would eventually sneak in.
type fatlineDeployer struct {
	// component is which system workload this deployer resolves. Zero means
	// FatLine, so every existing caller is unchanged.
	component components.Component

	assumeYes bool
	// consent is --plan and --confirm <digest> (ADR 0023 M2.6), registered
	// by each command that has a plan, in its own SetFlags, and never by
	// setYesFlag: a command that registers them must also call consent.mode.
	consent consentFlags
	// fatlineImage is the command's own image flag (--fatline-image,
	// --technocore-image or --datasphered-image): an image deployed as given.
	fatlineImage string
	sourceDir    string
	// embedded is --embedded: deploy the image this farcast carries over an
	// operator-built one, or over one another farcast version deployed.
	embedded bool

	// Seams, overridable in tests; defaulted by ensureDefaults.
	newCluster   func(clusterRef) (clusterApplier, error)
	openProvider providerOpener
	newBuilder   func(progress func(string)) imageBuilder
	findSource   func(dir string) (string, error)
	// findToolchain is image.FindToolchain: the Go a source build compiles
	// with, found when the image is decided (decideBuild), so a build's
	// prompt and its plan name it without either reading the terminal.
	findToolchain func(ctx context.Context, parent []string, dir string) (image.Toolchain, error)
	carried       carriedComponents
	build         func() buildinfo.Info
	now           func() time.Time
}

func (d *fatlineDeployer) ensureDefaults() {
	if d.component.Name == "" {
		d.component = components.FatLine
	}
	if d.newCluster == nil {
		d.newCluster = func(r clusterRef) (clusterApplier, error) {
			// A refusal returns a nil applier, never a nil *cluster.Client
			// inside a non-nil one.
			cl, err := openWriter(r)
			if err != nil {
				return nil, err
			}
			return cl, nil
		}
	}
	if d.openProvider == nil {
		d.openProvider = openProviderDefault
	}
	if d.newBuilder == nil {
		d.newBuilder = newBuilderDefault
	}
	if d.findSource == nil {
		d.findSource = findSourceDefault
	}
	if d.findToolchain == nil {
		d.findToolchain = findToolchainDefault
	}
	if d.carried == nil {
		d.carried = packageCarried{}
	}
	if d.build == nil {
		d.build = buildinfo.Get
	}
	if d.now == nil {
		d.now = deployerNowDefault
	}
}

// The help strings of the image flags, shared so the four commands say the
// same thing.
const (
	embeddedUsage = "deploy the image this farcast carries, replacing an operator-built image or one another farcast version deployed (never implied by --yes)"
	// embeddedFatLineUsage is connect's and redeploy's: there --fatline-image
	// names FatLine's image alone, so --embedded beside it governs Shrike's.
	embeddedFatLineUsage = embeddedUsage + "; with --fatline-image, Shrike's image alone"
)

// imageFlagUsage is an image flag's help: who it names, that it must carry a
// digest, and what is deployed without it.
func imageFlagUsage(who string, c components.Component) string {
	return who + " image to deploy, digest-pinned (repository@sha256:…) (default: the image this farcast carries, pushed to the instance registry's " + c.ImagePath + ")"
}

// setImageFlags registers connect's and redeploy's image flags. They are
// declared once so their names, defaults and meaning cannot drift between the
// command that first deploys FatLine and the one that replaces it.
func (d *fatlineDeployer) setImageFlags(fs *flag.FlagSet) {
	// The default is empty rather than a ref: it depends on the instance, which
	// is not known until Run loads its metadata (see decideImage).
	fs.StringVar(&d.fatlineImage, "fatline-image", "", imageFlagUsage("FatLine", components.FatLine))
	fs.StringVar(&d.sourceDir, "source", "", "farcast checkout to build FatLine's and Shrike's images from with this machine's Go; recorded as operator-built")
	fs.BoolVar(&d.embedded, "embedded", false, embeddedFatLineUsage)
}

// setEmbeddedFlag registers --embedded on kernel deploy and storage deploy,
// whose image flag names their only component. Connect and redeploy register
// it in setImageFlags, with the help that says what it governs beside
// --fatline-image.
func (d *fatlineDeployer) setEmbeddedFlag(fs *flag.FlagSet) {
	fs.BoolVar(&d.embedded, "embedded", false, embeddedUsage)
}

// setYesFlag registers -y/--yes. The usage string is the caller's, because what
// the flag waives differs: connect's gate is about money, redeploy's is about
// changing what the boundary runs.
func (d *fatlineDeployer) setYesFlag(fs *flag.FlagSet, usage string) {
	fs.BoolVar(&d.assumeYes, "yes", false, usage)
	fs.BoolVar(&d.assumeYes, "y", false, usage)
}

// imageFlag is the name of the command's own image flag for this component.
func (d *fatlineDeployer) imageFlag() string {
	switch d.component.Name {
	case components.TechnoCore.Name:
		return "--technocore-image"
	case components.Datasphered.Name:
		return "--datasphered-image"
	default:
		return "--fatline-image"
	}
}

// checkImageFlags is every rule on the image flags, checked as usage before
// anything is loaded, asked or called.
func (d *fatlineDeployer) checkImageFlags() error {
	switch {
	case d.embedded && d.sourceDir != "":
		return usagef("--embedded deploys the image this farcast carries and --source builds a new one; pass one or the other")
	case d.embedded && d.fatlineImage != "" && d.imageFlagNamesAll():
		// Only where the image flag names everything the command deploys. On
		// connect and redeploy --fatline-image names FatLine's image alone,
		// and --embedded beside it governs Shrike's (ADR 0023 M1, review
		// finding SEC-2): refusing the pair would leave a Shrike record from
		// another farcast version blocking the break-glass redeploy with a
		// refusal whose remedy is itself refused.
		return usagef("--embedded deploys the image this farcast carries and %s deploys an image as given; pass one or the other", d.imageFlag())
	case d.fatlineImage != "" && d.sourceDir != "":
		// Opposed intents — "deploy exactly this" versus "build from here and
		// deploy that". Resolution answers the image flag before it ever
		// considers --source, so accepting both would silently honour one.
		return usagef("%s deploys an image as given and --source builds a new one; pass one or the other", d.imageFlag())
	case d.embedded && !d.carried.Embedded():
		return usagef("this farcast carries no components (a source build), so --embedded has nothing to deploy")
	case d.fatlineImage != "" && !isPinnedImageRef(d.fatlineImage):
		// Rule 1 (ADR 0023 M1). The builder's push grant covers the whole
		// instance repository, so a tag under system/ can be rewritten by an
		// application build; and nothing is looked up here, so the break-glass
		// path keeps working with no registry and never sends this instance's
		// credential to a host the operator typed.
		return usagef("%s must be digest-pinned (repository@sha256:<64 hex>): a tag can be moved by anything that may push to its repository, and %s is deployed exactly as named",
			d.imageFlag(), d.component.Name)
	}
	return nil
}

// registryHostPattern is a registry host as an image reference names it: DNS
// labels, optionally with a port.
var registryHostPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(?::[0-9]+)?$`)

// isPinnedImageRef reports whether ref is an image flag's value that may be
// deployed exactly as given: host/repository@sha256:<64 hex>, a tag before
// the digest allowed, in the canonical form oci.ParseReference reads it back
// to, and nothing else. A check of the text after '@' alone is not enough:
// the value is written into the workload's YAML as it stands
// (fatline/deploy renders it with text/template, and stays unchanged so no
// component's digest moves), so an empty repository, a host with a space or
// a newline in it, or anything a parser would trim must be refused here.
func isPinnedImageRef(ref string) bool {
	r, err := oci.ParseReference(ref)
	if err != nil || r.String() != ref {
		return false
	}
	return r.Repository != "" && isSHA256(r.Digest) && registryHostPattern.MatchString(r.Registry)
}

// imageFlagNamesAll reports whether the command's own image flag names every
// image the command deploys. It does on kernel deploy and storage deploy,
// which deploy one component each. It does not on connect and redeploy (this
// deployer's FatLine component): --fatline-image names FatLine's image alone,
// and Shrike's is still resolved by the rules, from the carried components
// unless a record keeps another.
func (d *fatlineDeployer) imageFlagNamesAll() bool {
	return d.component.Name != components.FatLine.Name
}

// prechecks reports whether this run may deploy an image this farcast carries
// unless a record keeps another: it carries components, --source was not
// given, and the command's own image flag does not name every image it
// deploys. On connect and redeploy --fatline-image therefore exempts nothing.
func (d *fatlineDeployer) prechecks() bool {
	if !d.carried.Embedded() || d.sourceDir != "" {
		return false
	}
	return d.fatlineImage == "" || !d.imageFlagNamesAll()
}

// precheck refuses a farcast whose carried components it must not push, before
// any prompt, any registry ensure and (outside connect) before the instance's
// record is read. It is a no-op where prechecks is false. On connect and
// redeploy it refuses under --fatline-image too, registry or none: such a
// farcast is not meant to touch an instance.
func (d *fatlineDeployer) precheck() error {
	if !d.prechecks() {
		return nil
	}
	return checkCarried(d.carried, d.build)
}

// notReleaseError is a refusal with its own text that wraps
// buildinfo.ErrNotRelease.
type notReleaseError struct{ msg string }

func (e *notReleaseError) Error() string { return e.msg }
func (e *notReleaseError) Unwrap() error { return buildinfo.ErrNotRelease }

// checkCarried refuses carried components that this farcast must not push
// (ADR 0023 decision 4): a version that is not a release, components assembled
// against another base, or components built at another revision than the
// farcast that carries them. Each refusal wraps buildinfo.ErrNotRelease.
func checkCarried(carried carriedComponents, build func() buildinfo.Info) error {
	info := build()
	// The raw version, never imageTag's fold of it: "+dirty" is a valid tag
	// once folded to "-dirty", and that is exactly what must be refused.
	if err := info.CheckRelease(); err != nil {
		reason := err.Error()
		var nr *buildinfo.NotReleaseError
		if errors.As(err, &nr) {
			reason = nr.Reason
		}
		return &notReleaseError{fmt.Sprintf("this farcast is version %s, which is not a release (%s): its components are only pushed under a release's tag. "+
			"Build farcast with farcast-release from a clean commit, or pass --source <dir> to build the components from a checkout", info.Version, reason)}
	}
	if base := carried.Base(); base != image.BaseImage {
		return &notReleaseError{fmt.Sprintf("this farcast's components were assembled against %s, but it pulls %s; it was not built by farcast-release", base, image.BaseImage)}
	}
	if rev := carried.Revision(); carried.Modified() || rev == "" || rev != info.Revision {
		built, carriedAt := info.Revision, rev
		if built == "" {
			built = "an unrecorded revision"
		}
		if carriedAt == "" {
			carriedAt = "an unrecorded revision"
		}
		if carried.Modified() {
			carriedAt += ", with uncommitted changes"
		}
		return &notReleaseError{fmt.Sprintf("this farcast was built at %s but carries components built at %s; it was not built by farcast-release, and its components are not pushed", built, carriedAt)}
	}
	return nil
}

// ensureRegistry ensures the instance's image registry and returns a handle able
// to mint a credential for it, recording the result locally.
//
// Every deploying command re-ensures on every run instead of trusting install
// to have done it (ADR 0007 decision 1): an instance installed before instances
// had registries converges here, rather than failing later as an unexplained
// ImagePullBackOff inside the cluster. The ensure is idempotent, and it is not
// cost-gated — the registry is cents at most (decision 8), unlike connect's load
// balancer.
func (d *fatlineDeployer) ensureRegistry(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata) (*registryAccess, error) {
	return ensureRegistry(ctx, env, name, meta, d.openProvider)
}

// registryRequired reports whether this deploy cannot go on without the
// instance's registry. Every rule but rule 1 needs it (rule 2). --fatline-image
// alone does not; --embedded beside it does, because it governs Shrike's image,
// which rules 4 and 5 take from the registry. Deploying FatLine alone instead
// would quietly drop the one thing the operator's --embedded asked for.
func (d *fatlineDeployer) registryRequired() bool {
	return d.fatlineImage == "" || d.embedded
}

// registryFailed is a failed ensure as the command reports it when
// registryRequired holds: beside --fatline-image it names --embedded as what
// needed the registry, and the way to deploy FatLine alone.
func (d *fatlineDeployer) registryFailed(err error) error {
	if d.fatlineImage != "" && d.embedded {
		return embeddedNeedsRegistry(err)
	}
	return err
}

// embeddedNeedsRegistry is the refusal when --embedded is given beside
// --fatline-image and there is no registry to take Shrike's image from.
func embeddedNeedsRegistry(err error) error {
	return fmt.Errorf("--embedded governs Shrike's image, which is pushed to the instance registry, and the registry could not be ensured; "+
		"drop --embedded to deploy FatLine alone: %w", err)
}

// ensureRegistry is the deployer's body, lifted out so a command that only
// needs to push into the instance's registry — mirroring a toolchain image,
// say — does not have to construct a FatLine deployer to get at it.
func ensureRegistry(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata, open providerOpener) (*registryAccess, error) {
	creds, err := env.ConfigDir.LoadInstanceCredentials(name)
	if err != nil {
		return nil, fmt.Errorf("load credentials for %q: %w", name, err)
	}
	p, err := open(meta, creds)
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

// The texts of the registry a plan reads (A23-5, A23-24).
const (
	// msgNoRegistryRecorded is planRegistry's refusal of a record that names
	// no registry: a plan reads the registry, and never creates one.
	msgNoRegistryRecorded = "instance %q has no image registry recorded; run 'farcast connect %s' interactively or with --yes, which ensures it"
	// msgPlanNeedsShrike is connect's and redeploy's refusal, under --plan
	// and --confirm, of a plan that would deploy FatLine without its Shrike
	// monitor (A23-5): with the instance, and the registry's failure.
	msgPlanNeedsShrike = "--plan and --confirm never deploy FatLine without its Shrike monitor, and instance %q's image registry could not be read (%w); " +
		"deploying FatLine alone is a break-glass step: run the command without --plan or --confirm, interactively or with --yes"
	// msgRegistryMoved is the ensure after consent answering with another
	// registry than the plan's: the instance, the registry now, and the
	// planned one.
	msgRegistryMoved = "instance %q's image registry is now %s, not the %s this command planned with; the registry was ensured, and nothing was pushed or deployed"
)

// planRegistry is the instance's registry as a plan reads it (ADR 0023 M2.6,
// A23-24): the one the record names, with the installer's key, read by
// loadInstallerKey, to mint the registry token its lookups use. It reads,
// and writes nothing: it never ensures the registry, records it or saves the
// record, and a record that names none is refused. Its steps, in order: the
// recorded prefix; the key, a blank one (Application Default Credentials)
// refused before the provider opens; then the provider, which must have a
// registry.
func (d *fatlineDeployer) planRegistry(_ context.Context, env *Env, name string, meta *config.InstanceMetadata) (*registryAccess, error) {
	prefix := registryPrefix(meta)
	if prefix == "" {
		return nil, fmt.Errorf(msgNoRegistryRecorded, name, name)
	}
	creds, err := loadInstallerKey(env.ConfigDir, name)
	if err != nil {
		return nil, err
	}
	p, err := d.openProvider(meta, creds)
	if err != nil {
		return nil, err
	}
	rp, ok := p.(planck.RegistryProvider)
	if !ok {
		return nil, fmt.Errorf("provider %q has no image registry: %w", meta.Provider, planck.ErrRegistryUnsupported)
	}
	return &registryAccess{provider: rp, registry: &planck.Registry{Ref: registryRefFor(meta), Prefix: prefix, Puller: meta.Registry.Puller}}, nil
}

// registryForPlan is the registry connect's and redeploy's plans read
// (A23-24), or nil when FatLine deploys alone. command names the command in
// the break-glass line.
//
// An interactive or --yes run on a record that names no registry first
// ensures one, as these commands always have, and then plans, so a first
// connect after a failed install ensure still works outside --plan; a plan
// never ensures (planRegistry). A registry that cannot be had refuses the
// command when it needs the registry (registryRequired); under --plan and
// --confirm it refuses it too when FatLine would deploy alone (A23-5), so no
// plan deploys the boundary without its monitor. Otherwise, in an
// interactive or --yes run, it says why and returns nil: the break-glass
// path, which deploys FatLine alone.
func (d *fatlineDeployer) registryForPlan(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata, m consentMode, command string) (*registryAccess, error) {
	if m == consentNone && registryPrefix(meta) == "" {
		if _, err := d.ensureRegistry(ctx, env, name, meta); err != nil {
			return nil, d.withoutRegistry(env, err, command)
		}
	}
	reg, err := d.planRegistry(ctx, env, name, meta)
	switch {
	case err == nil:
		return reg, nil
	case m != consentNone && !d.registryRequired():
		return nil, fmt.Errorf(msgPlanNeedsShrike, name, err)
	}
	return nil, d.withoutRegistry(env, err, command)
}

// withoutRegistry is a registry that could not be had, outside --plan and
// --confirm: the command's refusal when it needs the registry, and
// otherwise nil, once it has said so in the words connect and redeploy
// always used.
func (d *fatlineDeployer) withoutRegistry(env *Env, err error, command string) error {
	if d.registryRequired() {
		return d.registryFailed(err)
	}
	fprintf(env.Err, "Warning: %v\n", err)
	fprintf(env.Err, "Continuing: --fatline-image names an image this %s neither looks up nor pushes.\n", command)
	return nil
}

// realizeRegistry is the registry ensure as a realize step (ADR 0023 M2.6,
// A23-24): after consent, in every mode, given the registry the plan was
// made with. It ensures and records the registry, as ensureRegistry always
// has, and refuses before anything is pushed: an ensure that failed, with
// its own error and kind, and one that answered with another registry than
// the planned one (plan_changed under --confirm). It never drops an image
// the plan listed. With no planned registry, a break-glass plan that
// deploys FatLine alone, it ensures nothing.
func (d *fatlineDeployer) realizeRegistry(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata, planned *registryAccess, m consentMode) (*registryAccess, error) {
	if planned == nil {
		return nil, nil
	}
	reg, err := d.ensureRegistry(ctx, env, name, meta)
	if err != nil {
		return nil, fmt.Errorf("%w; nothing was pushed or deployed", err)
	}
	if now, want := reg.registry.Prefix, planned.registry.Prefix; now != want {
		return nil, changedAfterPlan(m, fmt.Sprintf(msgRegistryMoved, name, now, want))
	}
	return reg, nil
}

// readyWriter is openReady through the deployer's writing seam.
func (d *fatlineDeployer) readyWriter(ctx context.Context, env *Env, meta *config.InstanceMetadata) (clusterApplier, error) {
	return openReady(ctx, env, meta, d.newCluster)
}

// openReady opens the instance's writer through open, the command's writing
// seam, and reads once as it, before anything is minted, ensured, pushed,
// asked or applied (ADR 0023 M2.5, A20-10, A20-11): opening sends nothing,
// so an instance this machine cannot write as is refused first; applyReady
// finds a machine that cannot apply; and the read makes the writer's first
// in-process call before kubectl applies anything. The uid it reads is
// discarded: the plans of the commands that open it here bind none
// (cluster_identity none). An interactive or --yes run opens it before its
// plan, and --confirm right after the comparison (A23-23).
func openReady[W preflighter](ctx context.Context, env *Env, meta *config.InstanceMetadata, open func(clusterRef) (W, error)) (W, error) {
	var none W
	cl, err := open(clusterRef{Dir: env.ConfigDir, Meta: meta, Identity: kube.Writer, Warn: env.Err})
	if err != nil {
		return none, err
	}
	if err := applyReady(cl); err != nil {
		return none, err
	}
	if err := preflightNamespace(ctx, cl); err != nil {
		return none, err
	}
	return cl, nil
}

// registryTarget is the instance's registry as a plan's cloud facts name it:
// the recorded image-path prefix, which names its location, project and
// repository; or, for a record that names none (a reconnect's plan, which
// reads no registry), the repository the ensure would make, by location and
// name.
func registryTarget(meta *config.InstanceMetadata) string {
	if p := registryPrefix(meta); p != "" {
		return p
	}
	ref := registryRefFor(meta)
	return ref.Location + "/" + ref.Name
}

// registryFacts are a plan's cloud facts for the registry (A23-24): the
// ensure, unconditionally, as its two writes (the repository, then the
// cluster's pull grant on it, whose target is the repository until ADR 0023
// M2.8 reads the project number), then a push for each decision that puts an
// image in the registry, in the order given.
func registryFacts(meta *config.InstanceMetadata, decs ...imageDecision) []plan.Fact {
	target := registryTarget(meta)
	facts := []plan.Fact{
		plan.CloudFact{Type: plan.TypeCloud, Service: plan.CloudArtifactRegistry, Action: plan.CloudCreateRepository, Target: target},
		plan.CloudFact{Type: plan.TypeCloud, Service: plan.CloudArtifactRegistry, Action: plan.CloudSetPullGrant, Target: target},
	}
	for _, dec := range decs {
		if dec.pushes() {
			facts = append(facts, plan.CloudFact{Type: plan.TypeCloud, Service: plan.CloudArtifactRegistry, Action: plan.CloudPushImage, Target: dec.planTarget()})
		}
	}
	return facts
}

// imageOptions are the deployer's image flags as a plan binds them (A23-28):
// --embedded, the command's own image flag and --source, each its parsed
// value. The command adds its other flags and sorts them (sortedOptions).
func (d *fatlineDeployer) imageOptions() []plan.Option {
	return []plan.Option{
		{Flag: "embedded", Value: strconv.FormatBool(d.embedded)},
		{Flag: strings.TrimPrefix(d.imageFlag(), "--"), Value: d.fatlineImage},
		{Flag: "source", Value: d.sourceDir},
	}
}

// sortedOptions is opts in the order a plan binds them: ascending by flag.
func sortedOptions(opts []plan.Option) []plan.Option {
	slices.SortFunc(opts, func(a, b plan.Option) int { return strings.Compare(a.Flag, b.Flag) })
	return opts
}

// resolvedImage is what a resolution decided: the reference the cluster is
// told to run, and where it came from.
type resolvedImage struct {
	Ref    string             // what the cluster is told to run: always digest-pinned
	Record config.SystemImage // written by the caller exactly where it writes the deploy record
}

// imageDecision is what deciding a component's image found, before anything
// is pushed, built, asked or printed (ADR 0023 M2.6, A23-34): which of
// rules 1–6 applies, as a plan's image action, and everything realizing it
// needs. Deciding only reads — the registry token, Resolve, the carried
// components, the checkout and its Go — and realizing writes: a push or a
// build. A plan binds a decision; a command that does not plan decides and
// realizes at once (resolveImage).
type imageDecision struct {
	component components.Component
	// action is a plan.Image* constant. It is "" only in Shrike's decision
	// when FatLine deploys alone (decideSidecarImage's break-glass path),
	// which no plan holds.
	action string
	// repo is the component's repository in the instance's registry, "" for
	// a named image.
	repo string
	// target is the image the cluster is told to run: the flag's (named),
	// the kept one (keep_*), or repo@<the carried manifest> (reuse, push,
	// push_over_foreign). A build's is known once it is pushed, so it is "".
	target string
	// tagRef is the version tag the carried image is pushed under (rule 5).
	tagRef string
	// art is the carried artifact (rule 5).
	art components.Artifact
	// prov is the component's recorded provenance, valid when hasProv.
	prov    config.SystemImage
	hasProv bool
	// previous is the image rule 5 replaces, which its replacement note
	// names: the deploy record, or for Shrike its valid provenance.
	previous string
	// replacesOther is rule 5b: the carried image replaces one another
	// farcast version deployed. skew is the version_skew refusal that stands
	// for it while --embedded is not given (skewRefusal).
	replacesOther bool
	skew          error
	// source is a build's checkout and Go (build_source, build_development).
	source imageSource
	// record is the provenance recorded once the image is deployed. A
	// build's Image, Go and BuiltAt are filled in when it is pushed.
	record config.SystemImage
	// notices are the lines the resolution prints before it pushes or
	// builds, in their order; replacing is rule 5's replacement note, which
	// it prints once the image is in the registry (settleImage).
	notices   []string
	replacing string
}

// imageSource is a source build's checkout and the Go it compiles with.
type imageSource struct {
	dir       string
	goPath    string
	goVersion string
	// goErr is findToolchain's failure. It is no refusal: the build prompt
	// names it in place of the Go, as it did before the split.
	goErr error
}

// builds reports whether realizing the decision compiles the image (rules 3
// and 6), which confirmBuild asks about first.
func (dec imageDecision) builds() bool {
	return dec.action == plan.ImageBuildSource || dec.action == plan.ImageBuildDevelopment
}

// skewRefusal is the version-skew refusal when it stands: the decision
// replaces a component another farcast version deployed, and --embedded was
// not given (ADR 0021 decision 6, kept by ADR 0023 decision 4). Interactive
// and --yes runs return it before anything is asked or pushed; nil otherwise.
func (dec imageDecision) skewRefusal(embedded bool) error {
	if dec.replacesOther && !embedded {
		return dec.skew
	}
	return nil
}

// pushes reports whether realizing the decision puts an image in the
// registry: the carried image pushed (rule 5c), or a build (rules 3 and 6).
func (dec imageDecision) pushes() bool {
	return dec.action == plan.ImagePush || dec.action == plan.ImagePushOverForeign || dec.builds()
}

// planTarget is the image a plan names for the decision: its target, or for
// a build, whose digest exists only once it is built, the build placeholder
// (A23-30).
func (dec imageDecision) planTarget() string {
	if dec.builds() {
		return buildPlaceholder(dec.repo, dec.component.Name)
	}
	return dec.target
}

// buildPlaceholder is the image reference a plan renders for a component
// built from source (A23-30): the repository, @sha256:, and the hex SHA-256
// of farcast-placeholder:build:<component>. It is digest-shaped, so every
// renderer takes it, and it is the one part of a rendering that may differ
// from the real one by its digest alone (A23-31, item 4).
func buildPlaceholder(repo, component string) string {
	sum := sha256.Sum256([]byte("farcast-placeholder:build:" + component))
	return repo + "@sha256:" + hex.EncodeToString(sum[:])
}

// said is what resolving the decision says, in its order: its notices, then
// the replacement note. Outside a plan they print once each, before the
// command asks anything; in a plan they are notice facts (A23-26).
func (dec imageDecision) said() []string {
	lines := slices.Clone(dec.notices)
	if dec.replacing != "" {
		lines = append(lines, dec.replacing)
	}
	return lines
}

// msgSourceBuildNotice is a source build's plan notice (A23-13): the plan
// binds the checkout's directory and Go, not what the checkout holds.
const msgSourceBuildNotice = "the build compiles whatever %s holds when --confirm runs; this plan binds the directory, not its content"

// sourceNotices are a plan's notices for its source builds (A23-13): one
// per checkout the decisions build from, in their order.
func sourceNotices(decs ...imageDecision) []plan.Fact {
	var facts []plan.Fact
	var dirs []string
	for _, dec := range decs {
		if dec.builds() && !slices.Contains(dirs, dec.source.dir) {
			dirs = append(dirs, dec.source.dir)
			facts = append(facts, noticeFact(fmt.Sprintf(msgSourceBuildNotice, dec.source.dir)))
		}
	}
	return facts
}

// imageFact is the decision as a plan binds it (A23-33): the component, the
// action and the image it deploys (planTarget), that image's Go as recorded
// once deployed ("" for a named image and a build), the image the record
// says is deployed today, whether it replaces a component another farcast
// version deployed, and for a build the checkout and the Go it compiles
// with.
func (dec imageDecision) imageFact(meta *config.InstanceMetadata) plan.ImageFact {
	f := plan.ImageFact{
		Type: plan.TypeImage, Component: dec.component.Name, Action: dec.action, Target: dec.planTarget(),
		Go: dec.record.Go, Current: currentImage(meta, dec.component.Name), ReplacesOtherVersion: dec.replacesOther,
	}
	if dec.builds() {
		f.Source = &plan.ImageSource{Dir: dec.source.dir, GoPath: dec.source.goPath, GoVersion: dec.source.goVersion}
	}
	return f
}

// currentImage is the image the record says a component runs, with its
// recorded provenance when that names the same image, or nil when the
// record names none.
func currentImage(meta *config.InstanceMetadata, name string) *plan.ImageCurrent {
	img := deployRecordOf(meta, name)
	if img == "" {
		return nil
	}
	cur := &plan.ImageCurrent{Image: img}
	if rec, ok := meta.SystemImages[name]; ok && rec.Image == img {
		cur.Origin, cur.FarCast, cur.Go = rec.Origin, rec.Farcast, rec.Go
	}
	return cur
}

// decideImage decides what the cluster will be told to run for d.component,
// and where that image came from (ADR 0023 decision 4), without pushing,
// building, asking or printing anything (M2.6, A23-34). The rules, in order:
//
//  1. An explicit image flag is deployed exactly as given. It is digest-pinned
//     (checkImageFlags), and nothing is looked up or pushed. --embedded beside
//     --fatline-image does not change that: it governs Shrike's image alone.
//  2. Every other rule needs the instance's registry.
//  3. --source is an operator build: compiled with this machine's Go, pushed
//     under source-<digest>, and recorded with its source directory.
//  4. An operator build recorded for this instance is kept until --embedded
//     or --source; a development build is kept only by a farcast that carries
//     no components. Either is first checked to still be in the registry.
//  5. A farcast that carries components deploys the image it carries: reused
//     when the version tag already holds exactly it, pushed otherwise. One
//     another farcast version deployed is replaced only with --embedded.
//  6. A farcast that carries nothing (a source build) compiles the image from
//     the checkout it finds, and records it as a development build.
//
// It mints the registry token and makes the Resolve calls, finds a build's
// checkout and Go, and checks the carried components; realizeImage makes the
// push or the build. What the resolution says on the way is in the
// decision's notices, never printed here. On an error the decision holds
// what was decided before it, its notices and a skew refusal among them, so
// a caller that prints them first says what it always said.
//
// Every deploy is pinned by digest: a Deployment that names a tag can be
// redirected by whoever can write that tag (ADR 0007 decision 4).
func (d *fatlineDeployer) decideImage(ctx context.Context, env *Env, reg *registryAccess, meta *config.InstanceMetadata) (imageDecision, error) {
	c := d.component
	info := d.build()
	dec := imageDecision{component: c}

	// Rule 1: the operator named it; deploy exactly that.
	if d.fatlineImage != "" {
		if !isPinnedImageRef(d.fatlineImage) { // checked as usage already; belt and braces
			return dec, d.checkImageFlags()
		}
		dec.action, dec.target = plan.ImageNamed, d.fatlineImage
		dec.record = config.SystemImage{Image: d.fatlineImage, Origin: config.OriginNamed, Farcast: info.Version}
		return dec, nil
	}
	// Rule 2.
	if reg == nil { // guarded by each command's needs-the-registry rule; belt and braces
		return dec, fmt.Errorf("no image registry for this instance and no %s given", d.imageFlag())
	}
	dec.repo = reg.registry.Prefix + "/" + c.ImagePath
	user, pass, err := reg.credentials(ctx)
	if err != nil {
		return dec, err
	}
	// Lookups only: progress belongs to the push or the build.
	b := d.newBuilder(nil)

	// Rule 3: an explicit --source always builds. An operator build is its own
	// image, under its own tag and record, so there is nothing to look up first.
	if d.sourceDir != "" {
		return d.decideBuild(ctx, dec, config.OriginOperator)
	}

	prov, hasProv, ignored := d.provenance(meta, dec.repo)
	if ignored != "" {
		dec.notices = append(dec.notices, ignored)
	}

	// Rule 4: a kept build.
	if hasProv && ((prov.Origin == config.OriginOperator && !d.embedded) ||
		(prov.Origin == config.OriginDevelopment && !d.carried.Embedded())) {
		_, err := b.Resolve(ctx, prov.Image, user, pass)
		switch {
		case err == nil:
			dec.action = plan.ImageKeepOperator
			if prov.Origin == config.OriginDevelopment {
				dec.action = plan.ImageKeepDevelopment
			}
			dec.target, dec.record, dec.prov, dec.hasProv = prov.Image, prov, prov, true
			dec.notices = append(dec.notices, d.keepingNote(prov))
			return dec, nil
		case !errors.Is(err, image.ErrNotFound):
			return dec, fmt.Errorf("look up %s: %w", prov.Image, err)
		case prov.Origin == config.OriginOperator:
			// --embedded is named only where checkImageFlags accepts it, as in
			// keepingNote: a refusal must not offer a remedy that is itself
			// refused (review finding RCK2-2-2, the pattern SEC-2 removed).
			out := "pass --source <dir> to rebuild it; this farcast is a source build and carries no image to deploy instead"
			if d.carried.Embedded() {
				out = "pass --source <dir> to rebuild it, or --embedded to deploy the image this farcast carries"
			}
			return dec, fmt.Errorf("the operator-built %s image %s recorded for this instance is no longer in its registry; %s",
				c.Name, prov.Image, out)
		default:
			dec.notices = append(dec.notices, fmt.Sprintf("%s: the development image %s is no longer in the registry; building it again.", c.Name, prov.Image))
			hasProv = false
		}
	}
	dec.prov, dec.hasProv = prov, hasProv

	// Rule 5: the image this farcast carries.
	if d.carried.Embedded() {
		old := deployRecordOf(meta, c.Name)
		if c.Name == components.Shrike.Name {
			old = "" // its record is its provenance, which may have been ignored
			if hasProv {
				old = prov.Image
			}
		}
		return d.decideCarried(ctx, dec, b, user, pass, info, old)
	}

	// Rule 6: a source build of farcast, with nothing kept.
	return d.decideBuild(ctx, dec, config.OriginDevelopment)
}

// decideCarried is rule 5: deploy the image this farcast carries.
//
// old is the image the component is recorded as running, which a replacement
// note names: the deploy record, or for Shrike its valid provenance.
func (d *fatlineDeployer) decideCarried(ctx context.Context, dec imageDecision, b imageBuilder, user, pass string,
	info buildinfo.Info, old string) (imageDecision, error) {
	c := d.component

	// a. The precheck again. The commands run it before anything is asked or
	// called; this is the same check where the image is decided.
	if err := checkCarried(d.carried, d.build); err != nil {
		return dec, err
	}
	art, ok := d.carried.Lookup(c.Name)
	if !ok {
		return dec, fmt.Errorf("this farcast carries no %s component", c.Name)
	}
	want := dec.repo + "@" + art.Manifest
	dec.art, dec.target, dec.previous = art, want, old
	dec.record = config.SystemImage{Image: want, Origin: config.OriginEmbedded, Go: art.GoVersion, Farcast: info.Version}

	// b. The version-skew guard (ADR 0021 decision 6, kept by ADR 0023
	// decision 4): an image another farcast version deployed is replaced only
	// when the operator says so, because two farcasts of different versions
	// would otherwise keep redeploying each other's components, and an older
	// one would silently put back an older Go. The refusal is kept in the
	// decision: interactive and --yes runs return it (skewRefusal), and a
	// plan binds the replacement, which --confirm then executes.
	prov := dec.prov
	if dec.hasProv && (prov.Origin == config.OriginEmbedded || prov.Origin == config.OriginNamed) &&
		prov.Image != want && prov.Farcast != "" && prov.Farcast != info.Version {
		goOld := prov.Go
		if goOld == "" {
			goOld = "its Go is not recorded"
		}
		msg := fmt.Sprintf("%s runs %s, deployed by farcast %s (%s); this farcast is %s and carries %s (%s). Pass --embedded to replace it.",
			c.Name, prov.Image, prov.Farcast, goOld, info.Version, art.Manifest, art.GoVersion)
		if prov.Go != "" && goOlder(art.GoVersion, prov.Go) {
			msg += fmt.Sprintf(" That replaces %s with an older Go, %s.", prov.Go, art.GoVersion)
		}
		dec.replacesOther, dec.skew = true, withKind(kindVersionSkew, errors.New(msg))
	}

	// c. The version tag holds only the image this farcast carries.
	dec.tagRef = dec.repo + ":" + imageTag(info.Version)
	switch t, err := b.Resolve(ctx, dec.tagRef, user, pass); {
	case errors.Is(err, image.ErrNotFound):
		dec.action = plan.ImagePush
	case err != nil:
		return dec, fmt.Errorf("look up %s: %w", dec.tagRef, err)
	case t == want:
		dec.action = plan.ImageReuse
	default:
		// Never deployed, and said whatever the output mode: a tag that moved
		// under a release is something the operator has to hear about.
		_, found, _ := strings.Cut(t, "@")
		dec.action = plan.ImagePushOverForeign
		dec.notices = append(dec.notices, fmt.Sprintf("warning: %s points at %s, which is not the %s image this farcast carries (%s); it will not be deployed. Pushing the carried image over that tag.",
			dec.tagRef, found, c.Name, art.Manifest))
	}

	// e and f. A replacement is said, whatever replaced it.
	if old != "" && old != want {
		dec.replacing = d.replacingNote(old, prov, dec.hasProv, art)
	}
	return dec, nil
}

// decideBuild is rules 3 and 6: the checkout to compile the component from,
// and the Go this machine compiles it with.
func (d *fatlineDeployer) decideBuild(ctx context.Context, dec imageDecision, origin string) (imageDecision, error) {
	c := d.component
	source, err := d.findSource(d.sourceDir)
	if err != nil {
		if origin == config.OriginOperator {
			return dec, fmt.Errorf("--source %s is not a farcast checkout to build %s's image from: %w", d.sourceDir, c.Name, err)
		}
		return dec, fmt.Errorf("%s's image is not in the instance's registry %s yet and there is no farcast checkout to build it from "+
			"(run the command from a farcast checkout, or pass --source <dir>; a release farcast needs no checkout: it carries its components): %w", c.Name, dec.repo, err)
	}
	dec.action = plan.ImageBuildDevelopment
	if origin == config.OriginOperator {
		dec.action = plan.ImageBuildSource
	}
	dec.source.dir = source
	if tc, err := d.findToolchain(ctx, os.Environ(), source); err == nil {
		dec.source.goPath, dec.source.goVersion = tc.Go, tc.Version
	} else {
		dec.source.goErr = err
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		abs = source
	}
	dec.record = config.SystemImage{Origin: origin, Farcast: d.build().Version, Source: abs}
	return dec, nil
}

// realizeImage puts a decided image where the cluster can pull it (ADR 0023
// M2.6, A23-34): it pushes the image this farcast carries (push,
// push_over_foreign), or compiles and pushes a build (build_*), and returns
// what the caller deploys and records. A named, kept or reused image is
// already there, so for those it makes no registry call and looks nothing up
// again. It asks nothing: a build's consent (confirmBuild) is the caller's,
// given before this runs. Its progress lines, and their terminal check, are
// here and nowhere in decideImage.
func (d *fatlineDeployer) realizeImage(ctx context.Context, env *Env, reg *registryAccess, dec imageDecision) (resolvedImage, error) {
	c := dec.component
	say := d.progressTo(env)
	switch dec.action {
	case plan.ImageNamed, plan.ImageKeepOperator, plan.ImageKeepDevelopment:
		return resolvedImage{Ref: dec.target, Record: dec.record}, nil
	case plan.ImageReuse:
		if say != nil {
			say(fmt.Sprintf("%s: %s already holds the image this farcast carries", c.Name, dec.tagRef))
		}
		return resolvedImage{Ref: dec.target, Record: dec.record}, nil
	case plan.ImagePush, plan.ImagePushOverForeign, plan.ImageBuildSource, plan.ImageBuildDevelopment:
	default:
		return resolvedImage{}, fmt.Errorf("cli: no image was decided for %s", c.Name)
	}
	if reg == nil { // decided with a registry, so realized with one; belt and braces
		return resolvedImage{}, fmt.Errorf("no image registry for this instance to push %s's image to", c.Name)
	}
	// A credential of its own, minted where the push uses it (registryAccess)
	// rather than kept in the decision: a decision holds no secret, and one
	// made before a prompt may be answered after the token it read with has
	// expired.
	user, pass, err := reg.credentials(ctx)
	if err != nil {
		return resolvedImage{}, err
	}
	b := d.newBuilder(say)

	if dec.builds() {
		pushed, err := b.BuildAndPush(ctx, image.Options{
			SourceDir:  dec.source.dir,
			Package:    c.Package,
			Repository: dec.repo,
			BinaryPath: c.BinaryPath,
		}, user, pass)
		if err != nil {
			return resolvedImage{}, err
		}
		rec := dec.record
		rec.Image, rec.Go, rec.BuiltAt = pushed.Ref, pushed.GoVersion, d.now().UTC()
		return resolvedImage{Ref: pushed.Ref, Record: rec}, nil
	}

	// d. The push. No build confirmation: the image is part of the executable
	// the operator chose to run, and pushing it changes nothing that runs. The
	// command's own gate still applies to the deploy.
	art := dec.art
	layer, err := d.carried.Layer(c.Name)
	if err != nil {
		return resolvedImage{}, err
	}
	if say != nil {
		say(fmt.Sprintf("%s: pushing the image this farcast carries (%s, %s)", c.Name, art.GoVersion, art.Manifest))
	}
	pushed, err := b.PushEmbedded(ctx, image.EmbeddedOptions{
		Ref: dec.tagRef, Package: c.Package, BinaryPath: c.BinaryPath,
		Layer: layer, LayerDigest: art.Layer, LayerSize: art.LayerSize,
		DiffID: art.DiffID, Manifest: art.Manifest, GoVersion: art.GoVersion,
	}, user, pass)
	if err != nil {
		return resolvedImage{}, err
	}
	if pushed.Ref != dec.target {
		return resolvedImage{}, fmt.Errorf("pushed %s as %s, not the %s this farcast carries", dec.tagRef, pushed.Ref, dec.target)
	}
	return resolvedImage{Ref: dec.target, Record: dec.record}, nil
}

// resolveImage decides d.component's image and realizes it at once, saying
// what it always said, in the same order (settleImage). It is the path of the
// commands that have no plan yet, kernel deploy and storage deploy, and goes
// when they have one (ADR 0023 M2.6, A23-34). connect and redeploy decide
// before their consent and realize after it (workloadImages).
func (d *fatlineDeployer) resolveImage(ctx context.Context, env *Env, reg *registryAccess, meta *config.InstanceMetadata) (resolvedImage, error) {
	dec, err := d.decideImage(ctx, env, reg, meta)
	return d.settleImage(ctx, env, reg, dec, err)
}

// settleImage is a resolution after its decision, given decide's error: the
// version-skew refusal, before anything is said, asked or pushed; the
// decision's notices on stderr, whatever the output mode; decide's error;
// the build prompt; realize; and the replacement note once the image is in
// the registry. That is the order the lines came in before the decision was
// split from the push: the skew was refused before the version tag was
// looked up, so a skew decision's foreign-tag warning, which deciding now
// makes, is never said.
func (d *fatlineDeployer) settleImage(ctx context.Context, env *Env, reg *registryAccess, dec imageDecision, err error) (resolvedImage, error) {
	if skew := dec.skewRefusal(d.embedded); skew != nil {
		return resolvedImage{}, skew
	}
	for _, n := range dec.notices {
		fprintln(env.Err, n)
	}
	if err != nil {
		return resolvedImage{}, err
	}
	if err := d.buildConsent(env, dec); err != nil {
		return resolvedImage{}, err
	}
	resolved, err := d.realizeImage(ctx, env, reg, dec)
	if err != nil {
		return resolvedImage{}, err
	}
	if dec.replacing != "" {
		fprintln(env.Err, dec.replacing)
	}
	return resolved, nil
}

// provenance is this instance's recorded origin of the component's deployed
// image, when it still describes what is deployed.
//
// It is valid only while its Image equals the component's deploy record (for
// Shrike, which has none, it is used as is). An image FarCast pushed or built
// — embedded, operator or development — is valid only as repo@sha256:<64 hex>
// in this instance's registry: those are only ever pushed there, and rule 4
// hands the registry credential to whatever host a reference names, so a
// record naming another host must never reach it. A record that fails is
// ignored, and the command continues as if there were none; ignored is the
// line that says so, which the caller prints (a notice, never printed here).
func (d *fatlineDeployer) provenance(meta *config.InstanceMetadata, repo string) (rec config.SystemImage, ok bool, ignored string) {
	c := d.component
	rec, ok = meta.SystemImages[c.Name]
	if !ok || rec.Image == "" {
		return config.SystemImage{}, false, ""
	}
	if c.Name != components.Shrike.Name && rec.Image != deployRecordOf(meta, c.Name) {
		return config.SystemImage{}, false, ""
	}
	switch rec.Origin {
	case config.OriginEmbedded, config.OriginOperator, config.OriginDevelopment:
		digest, found := strings.CutPrefix(rec.Image, repo+"@")
		if !found || !isSHA256(digest) {
			return config.SystemImage{}, false, fmt.Sprintf("%s: ignoring the recorded origin of %s: it is not in this instance's registry %s", c.Name, rec.Image, repo)
		}
	case config.OriginNamed:
	default:
		// An origin this build does not know is no origin it can act on.
		return config.SystemImage{}, false, ""
	}
	return rec, true, ""
}

// deployRecordOf is the component's deploy record: the image the cluster was
// last told to run, as each command already records it. Shrike has none of its
// own; its SystemImages entry is its only record.
func deployRecordOf(meta *config.InstanceMetadata, name string) string {
	switch name {
	case components.FatLine.Name:
		return deployedImage(meta)
	case components.TechnoCore.Name:
		if meta.Kernel != nil {
			return meta.Kernel.Image
		}
	case components.Datasphered.Name:
		if meta.Keyholder != nil {
			return meta.Keyholder.Image
		}
	case components.Shrike.Name:
		return meta.SystemImages[name].Image
	}
	return ""
}

// keepingNote is rule 4's line when a kept build is reused.
func (d *fatlineDeployer) keepingNote(prov config.SystemImage) string {
	kind := "operator-built"
	if prov.Origin == config.OriginDevelopment {
		kind = "development"
	}
	goV := prov.Go
	if goV == "" {
		goV = "its Go is not recorded"
	}
	carries := "no components"
	if art, ok := d.carried.Lookup(d.component.Name); ok && d.carried.Embedded() {
		carries = art.GoVersion
	}
	next := "Pass --source to rebuild it."
	if prov.Origin == config.OriginOperator && d.carried.Embedded() {
		next = "Pass --embedded to replace it, or --source to rebuild it."
	}
	return fmt.Sprintf("%s: keeping the %s image %s (%s, built %s by farcast %s from %s). This farcast carries %s. %s",
		d.component.Name, kind, prov.Image, goV, prov.BuiltAt.UTC().Format(time.RFC3339), prov.Farcast, prov.Source, carries, next)
}

// replacingNote is rule 5's line when the image this farcast carries replaces
// another one.
func (d *fatlineDeployer) replacingNote(old string, prov config.SystemImage, hasProv bool, art components.Artifact) string {
	c := d.component.Name
	if !hasProv {
		return fmt.Sprintf("%s: replacing %s (its origin is not recorded on this machine).", c, old)
	}
	goOld := prov.Go
	if goOld == "" {
		goOld = "its Go is not recorded"
	}
	switch prov.Origin {
	case config.OriginOperator:
		return fmt.Sprintf("%s: replacing the operator-built image %s (%s) with the image this farcast carries (%s).", c, old, goOld, art.GoVersion)
	case config.OriginDevelopment:
		return fmt.Sprintf("%s: replacing the development image %s (built from %s) with the image this farcast carries (%s).", c, old, prov.Source, art.GoVersion)
	case config.OriginNamed:
		return fmt.Sprintf("%s: replacing the named image %s with the image this farcast carries.", c, old)
	default:
		return fmt.Sprintf("%s: replacing %s, deployed by farcast %s (%s), with the image this farcast carries (%s).", c, old, prov.Farcast, goOld, art.GoVersion)
	}
}

// goOlder reports whether Go release a is older than b ("go1.27.3" against
// "go1.27.4"). A name go/version does not accept is never called older.
func goOlder(a, b string) bool {
	if !version.IsValid(a) || !version.IsValid(b) {
		return false
	}
	return version.Compare(a, b) < 0
}

// recordSystemImage writes a component's provenance beside its deploy record,
// in the same save. An empty record removes it: Shrike's, when FatLine is
// deployed alone.
func recordSystemImage(meta *config.InstanceMetadata, name string, rec config.SystemImage) {
	if rec.Image == "" {
		delete(meta.SystemImages, name)
		return
	}
	if meta.SystemImages == nil {
		meta.SystemImages = map[string]config.SystemImage{}
	}
	meta.SystemImages[name] = rec
}

// sidecar is this deployer with Shrike's image in FatLine's place.
//
// It is this deployer with the component swapped, deliberately: the push, the
// consent gate, the provenance and the version-skew guard must behave
// identically for both images, and a second implementation is exactly how the
// two would drift. --fatline-image is cleared because it names FatLine's image
// and nothing else — an operator pinning the boundary's image is not pinning
// the monitor's. --embedded is kept, deliberately: beside --fatline-image it
// is the flag that governs Shrike (ADR 0023 M1, review finding SEC-2), so the
// monitor follows rules 4 and 5 with it given, past the version-skew guard and
// over an operator build.
func (d *fatlineDeployer) sidecar() *fatlineDeployer {
	s := *d
	s.component = components.Shrike
	s.fatlineImage = ""
	return &s
}

// decideSidecarImage decides Shrike's image in the same instance registry
// the FatLine image comes from, as decideImage does (sidecar), with one path
// of its own: the break-glass one, where there is no image to decide.
func (d *fatlineDeployer) decideSidecarImage(ctx context.Context, env *Env, reg *registryAccess, meta *config.InstanceMetadata) (imageDecision, error) {
	// --embedded asked for Shrike's carried image, which only the registry can
	// supply: refused rather than dropped. Each command refuses it at the
	// ensure, before anything is resolved; this is belt and braces.
	if d.fatlineImage != "" && reg == nil && d.embedded {
		return imageDecision{component: components.Shrike}, embeddedNeedsRegistry(errors.New("no image registry for this instance"))
	}
	// The break-glass path: --fatline-image names an image directly and needs
	// no registry at all, which is what makes it usable when the registry is
	// the thing that is broken. There is nowhere to get a monitor image from
	// in that case, so FatLine deploys alone — said out loud, because a
	// security component that quietly stops being deployed is worse than one
	// that was never there. The decision has no action, and its notices are
	// those two lines. No plan holds it: --plan and --confirm never deploy
	// FatLine without Shrike (A23-5).
	if d.fatlineImage != "" && reg == nil {
		return imageDecision{component: components.Shrike, notices: []string{
			"No image registry for this instance, so the Shrike monitor cannot be deployed: deploying FatLine alone.",
			"Egress is still enforced and every decision is still logged by FatLine. What is missing is alerting.",
		}}, nil
	}
	return d.sidecar().decideImage(ctx, env, reg, meta)
}

// realizeSidecarImage is realizeImage for Shrike's decision, where a
// decision with no action is FatLine deployed alone: no image, and an empty
// record, which removes Shrike's (recordSystemImage).
func (d *fatlineDeployer) realizeSidecarImage(ctx context.Context, env *Env, reg *registryAccess, dec imageDecision) (resolvedImage, error) {
	if dec.action == "" {
		return resolvedImage{}, nil
	}
	return d.sidecar().realizeImage(ctx, env, reg, dec)
}

// workloadImages are FatLine's and Shrike's images as connect's and
// redeploy's plans decide them (ADR 0023 M2.6, A23-34 to A23-36): the
// registry the plan read, nil for a break-glass plan that deploys FatLine
// alone; the two decisions; and what deciding them said, in today's words,
// which a plan carries as notices and every other run prints once, before
// anything is asked or, under --confirm, right after the comparison
// (A23-26). Both commands decide, consent to and realize them through the
// methods below, so they cannot drift on what FatLine's workload runs, and
// both realize them only after consent: nothing is ensured, pushed or built
// before the operator, or the plan, said so.
type workloadImages struct {
	reg             *registryAccess
	fatline, shrike imageDecision
	printed         []string
}

// decideWorkloadImages decides FatLine's image, then Shrike's, which ships
// with the boundary, not after it. On an error the images hold what was
// decided, and said, before it (refusal).
func (d *fatlineDeployer) decideWorkloadImages(ctx context.Context, env *Env, reg *registryAccess, meta *config.InstanceMetadata) (workloadImages, error) {
	im := workloadImages{reg: reg}
	var err error
	im.fatline, err = d.decideImage(ctx, env, reg, meta)
	im.printed = append(im.printed, im.fatline.said()...)
	if err != nil {
		return im, err
	}
	im.shrike, err = d.decideSidecarImage(ctx, env, reg, meta)
	im.printed = append(im.printed, im.shrike.said()...)
	return im, err
}

// writeFacts are FatLine's workload as a plan binds it: rendered for carrier
// over the images the plan names (a build's placeholder among them) and over
// mtls, placeholderMTLS's material, so no key is opened (A23-25, A23-30).
func (im workloadImages) writeFacts(carrier deploy.Carrier, mtls config.MTLSMaterial) ([]plan.Fact, error) {
	stream, err := renderWorkload(im.fatline.planTarget(), im.shrike.planTarget(), carrier, mtls)
	if err != nil {
		return nil, err
	}
	return applyFacts(stream)
}

// imageFacts are the two image facts: FatLine's, then Shrike's. A Shrike
// decision with no action, FatLine deployed alone, is in no plan that is
// printed (A23-5).
func (im workloadImages) imageFacts(meta *config.InstanceMetadata) []plan.Fact {
	facts := []plan.Fact{im.fatline.imageFact(meta)}
	if im.shrike.action != "" {
		facts = append(facts, im.shrike.imageFact(meta))
	}
	return facts
}

// cloudFacts are the registry's cloud facts when the plan read the registry
// (A23-24): the ensure, then a push for each image that goes into it.
func (im workloadImages) cloudFacts(meta *config.InstanceMetadata) []plan.Fact {
	if im.reg == nil {
		return nil
	}
	return registryFacts(meta, im.fatline, im.shrike)
}

// noticeFacts are what deciding the images said, then the source builds'
// notices, which only a plan carries (A23-13).
func (im workloadImages) noticeFacts() []plan.Fact {
	var facts []plan.Fact
	for _, line := range im.printed {
		facts = append(facts, noticeFact(line))
	}
	return append(facts, sourceNotices(im.fatline, im.shrike)...)
}

// skewRefusal is the version-skew refusal either image stands for while
// --embedded is not given, FatLine's first: an interactive or --yes run
// returns it before anything is asked (ADR 0023 decision 4; --yes never
// implies --embedded). Under --confirm the plan's replaces_other_version is
// the consent, and nothing refuses it (§9.5).
func (im workloadImages) skewRefusal(embedded bool) error {
	for _, dec := range []imageDecision{im.fatline, im.shrike} {
		if skew := dec.skewRefusal(embedded); skew != nil {
			return skew
		}
	}
	return nil
}

// say prints, outside a plan, what deciding the images said: FatLine's
// lines, then Shrike's, each through terminalText, since they carry values
// from the record and from argv (A23-26). A decision whose version-skew
// refusal stands ends it with that refusal, its own lines unsaid, as when
// resolving an image refused the skew before it looked the version tag up:
// an interactive or --yes run never announces a replacement, or a push over
// a foreign tag, that it then refuses (ADR 0023 decision 4; --yes never
// implies --embedded). embedded is --embedded, or true under --confirm,
// whose plan is the consent to the replacement (§9.5), so there every line
// prints, right after the comparison.
func (im workloadImages) say(env *Env, embedded bool) error {
	for _, dec := range []imageDecision{im.fatline, im.shrike} {
		if skew := dec.skewRefusal(embedded); skew != nil {
			return skew
		}
		for _, line := range dec.said() {
			fprintln(env.Err, terminalText(line))
		}
	}
	return nil
}

// refusal is how an interactive or --yes run refuses a plan it could not
// make, in the order it always has: what resolving the images said up to a
// version-skew refusal the decisions hold, which it returns (say); then the
// error.
func (im workloadImages) refusal(env *Env, embedded bool, err error) error {
	if skew := im.say(env, embedded); skew != nil {
		return skew
	}
	return err
}

// buildConsents asks, in an interactive or --yes run, for each image the
// plan builds, FatLine's first (confirmBuild). --confirm asks nothing.
func (d *fatlineDeployer) buildConsents(env *Env, im workloadImages) error {
	for _, dec := range []imageDecision{im.fatline, im.shrike} {
		if err := d.buildConsent(env, dec); err != nil {
			return err
		}
	}
	return nil
}

// realizeWorkloadImages makes the decisions real, after consent: the
// registry ensure the plan bound, refused before any push when it fails or
// answers with another registry (realizeRegistry); then FatLine's image,
// then Shrike's, pushed or built where the plan said so, and nothing looked
// up again. It returns what the cluster is told to run and records.
func (d *fatlineDeployer) realizeWorkloadImages(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata,
	im workloadImages, m consentMode) (fl, sh resolvedImage, err error) {
	reg, err := d.realizeRegistry(ctx, env, name, meta, im.reg, m)
	if err != nil {
		return resolvedImage{}, resolvedImage{}, err
	}
	if fl, err = d.realizeImage(ctx, env, reg, im.fatline); err != nil {
		return resolvedImage{}, resolvedImage{}, err
	}
	if sh, err = d.realizeSidecarImage(ctx, env, reg, im.shrike); err != nil {
		return resolvedImage{}, resolvedImage{}, err
	}
	return fl, sh, nil
}

// msgBuildYes is confirmBuild's refusal without a terminal and without
// --yes. A command that has a plan adds consentSuffix (consentFlags.suffix).
const msgBuildYes = "%s's image would be compiled from %s with this machine's Go and pushed to %s:source-…; pass --yes to build it"

// confirmBuild gates compiling a component's image from source. It is not a
// cost gate — registry storage is ~$0 (ADR 0007 decision 8) — it is a consent
// gate: the build compiles *this* checkout with this machine's Go and pushes
// the result into the one place the instance runs code from, so the operator
// should know it is happening, from where, with which Go, and how it is
// recorded.
//
// It is asked only for --source and a source build's fallback, from the
// decision's source: the checkout and the Go that decideBuild found. A
// release farcast pushing the image it carries asks nothing here: that image
// is part of the executable the operator chose to run.
func (d *fatlineDeployer) confirmBuild(env *Env, dec imageDecision) (bool, error) {
	if d.assumeYes {
		return true, nil
	}
	c, source := dec.component.Name, dec.source.dir
	if !isInteractive(env) {
		return false, usagef(msgBuildYes+d.consent.suffix(), c, source, dec.repo)
	}
	goLine := fmt.Sprintf("%s (%s)", dec.source.goPath, dec.source.goVersion)
	if dec.source.goErr != nil {
		goLine = fmt.Sprintf("the Go on PATH, which could not be asked (%v)", dec.source.goErr)
	}
	recorded := "recorded as operator-built: later commands keep it until --embedded or --source"
	if dec.record.Origin == config.OriginDevelopment {
		fprintf(env.Err, "This farcast carries no components (a source build), so %s's image is compiled here.\n", c)
		recorded = "recorded as a development build, which a release farcast replaces"
	}
	fprintf(env.Err, "%s's image would be compiled from %s by %s, with no container engine,\n", c, source, goLine)
	fprintf(env.Err, "pushed to the instance's registry as %s:source-…, and %s.\n", dec.repo, recorded)
	return newPrompter(env.In, env.Err).yesNo("Build and push it now?")
}

// buildConsent is confirmBuild for a decision that builds, and nil for one
// that does not: a declined build prints "Aborted." and is refused.
func (d *fatlineDeployer) buildConsent(env *Env, dec imageDecision) error {
	if !dec.builds() {
		return nil
	}
	ok, err := d.confirmBuild(env, dec)
	if err != nil {
		return err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return fmt.Errorf("building %s's image from %s was declined", dec.component.Name, dec.source.dir)
	}
	return nil
}

// progressTo returns the sink for build progress: stderr while the operator is
// watching, nothing otherwise — stdout carries only the command's result.
func (d *fatlineDeployer) progressTo(env *Env) func(string) {
	if !isInteractive(env) && !env.Verbose {
		return nil
	}
	return func(line string) { fprintf(env.Err, "  %s\n", line) }
}

// imageTag renders a build version as a valid OCI tag: the version tag a
// release pushes the images it carries under.
//
// A tag is [A-Za-z0-9_][A-Za-z0-9._-]{0,127}, which a Go build version does not
// always satisfy: "+dirty" carries a '+' no registry will accept. Folding the
// unrepresentable characters is safe because a version is checked raw before
// it ever reaches here — checkCarried refuses "dev", "+dirty" and a modified
// tree, and the fold would otherwise pass "+dirty" as "-dirty" — and because
// the tag is never trusted: what it holds is compared with the digest this
// farcast was released with, and the digest is what is deployed and recorded
// (ADR 0007 decision 4; ADR 0023 decision 4).
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

// renderWorkload renders FatLine's Kubernetes workload — the boundary and its
// co-scheduled monitor — for a carrier. Both commands render through it, so a redeploy cannot produce a
// workload shaped differently from the one connect bootstrapped — and the CA
// *certificate* plus the server leaf go to the cluster while the CA key, which
// is not part of Config at all, stays on this machine.
func renderWorkload(img, shrikeImg string, carrier deploy.Carrier, mtls config.MTLSMaterial) ([]byte, error) {
	return deploy.Render(deploy.Config{
		Image:        img,
		ShrikeImage:  shrikeImg,
		Carrier:      carrier,
		StreamRoutes: systemStreamRoutes(),
		// A keeper re-seeds a restarted keyholder replica and does nothing
		// else: Shrike's route, and any later one, is the operator's alone.
		KeeperRoutes:  []string{keyholder.StreamRoute},
		CACertPEM:     mtls.CACertPEM,
		ServerCertPEM: mtls.ServerCertPEM,
		ServerKeyPEM:  mtls.ServerKeyPEM,
	})
}

// systemStreamRoutes is the closed set of in-instance services the operator may
// reach through the tunnel.
//
// The keyholder's route is configured whether or not a keyholder is deployed
// yet: FatLine is deployed by `connect`, long before `storage deploy` runs, and
// a route to something absent fails as an honest "cannot reach the service"
// rather than as an unknown route — which would send an operator looking for a
// misconfiguration in the wrong component.
//
// Each replica is addressed through the headless Service, so an unseal reaches
// one specific pod rather than whichever the load balancer picks.
func systemStreamRoutes() []string {
	return []string{
		fmt.Sprintf("%s=%s-{ordinal}.%s-unseal.%s.svc.cluster.local:%d=%d",
			keyholder.StreamRoute,
			dsdeploy.DefaultName, dsdeploy.DefaultName, dsdeploy.DefaultNamespace,
			dsdeploy.DefaultUnsealPort, keyholderReplicas),
		// Shrike's status, on the Pod's own loopback. FatLine's relay runs in
		// that same Pod, so this reaches the monitor without the monitor ever
		// listening anywhere the cluster can dial — and like the keyholder's,
		// the route is configured whether or not a Shrike is deployed, so an
		// instance running FatLine alone fails as an honest "cannot reach the
		// service" rather than as an unknown route.
		fmt.Sprintf("%s=127.0.0.1:%d", deploy.ShrikeStreamRoute, deploy.ShrikeStatusPort),
	}
}
