package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"go/version"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/oci"
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
	// fatlineImage is the command's own image flag (--fatline-image,
	// --technocore-image or --datasphered-image): an image deployed as given.
	fatlineImage string
	sourceDir    string
	// embedded is --embedded: deploy the image this farcast carries over an
	// operator-built one, or over one another farcast version deployed.
	embedded bool

	// Seams, overridable in tests; defaulted by ensureDefaults.
	newCluster   func(kubeconfigPath string) clusterApplier
	openProvider providerOpener
	newBuilder   func(progress func(string)) imageBuilder
	findSource   func(dir string) (string, error)
	carried      carriedComponents
	build        func() buildinfo.Info
	now          func() time.Time
}

func (d *fatlineDeployer) ensureDefaults() {
	if d.component.Name == "" {
		d.component = components.FatLine
	}
	if d.newCluster == nil {
		d.newCluster = func(kc string) clusterApplier { return cluster.New(kc) }
	}
	if d.openProvider == nil {
		d.openProvider = defaultProviderOpener
	}
	if d.newBuilder == nil {
		d.newBuilder = func(progress func(string)) imageBuilder {
			return &image.Builder{Progress: progress}
		}
	}
	if d.findSource == nil {
		d.findSource = image.FindSource
	}
	if d.carried == nil {
		d.carried = packageCarried{}
	}
	if d.build == nil {
		d.build = buildinfo.Get
	}
	if d.now == nil {
		d.now = time.Now
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
	// is not known until Run loads its metadata (see resolveImage).
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

// resolvedImage is what a resolution decided: the reference the cluster is
// told to run, and where it came from.
type resolvedImage struct {
	Ref    string             // what the cluster is told to run: always digest-pinned
	Record config.SystemImage // written by the caller exactly where it writes the deploy record
}

// resolveImage decides what the cluster will be told to run for d.component,
// and where that image came from (ADR 0023 decision 4). The rules, in order:
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
// Every deploy is pinned by digest: a Deployment that names a tag can be
// redirected by whoever can write that tag (ADR 0007 decision 4).
func (d *fatlineDeployer) resolveImage(ctx context.Context, env *Env, reg *registryAccess, meta *config.InstanceMetadata) (resolvedImage, error) {
	c := d.component
	info := d.build()

	// Rule 1: the operator named it; deploy exactly that.
	if d.fatlineImage != "" {
		if !isPinnedImageRef(d.fatlineImage) { // checked as usage already; belt and braces
			return resolvedImage{}, d.checkImageFlags()
		}
		return resolvedImage{
			Ref:    d.fatlineImage,
			Record: config.SystemImage{Image: d.fatlineImage, Origin: config.OriginNamed, Farcast: info.Version},
		}, nil
	}
	// Rule 2.
	if reg == nil { // guarded by each command's needs-the-registry rule; belt and braces
		return resolvedImage{}, fmt.Errorf("no image registry for this instance and no %s given", d.imageFlag())
	}
	repo := reg.registry.Prefix + "/" + c.ImagePath
	user, pass, err := reg.credentials(ctx)
	if err != nil {
		return resolvedImage{}, err
	}
	b := d.newBuilder(d.progressTo(env))

	// Rule 3: an explicit --source always builds. An operator build is its own
	// image, under its own tag and record, so there is nothing to look up first.
	if d.sourceDir != "" {
		return d.buildFromSource(ctx, env, b, repo, user, pass, config.OriginOperator)
	}

	prov, hasProv := d.provenance(env, meta, repo)

	// Rule 4: a kept build.
	if hasProv && ((prov.Origin == config.OriginOperator && !d.embedded) ||
		(prov.Origin == config.OriginDevelopment && !d.carried.Embedded())) {
		_, err := b.Resolve(ctx, prov.Image, user, pass)
		switch {
		case err == nil:
			fprintln(env.Err, d.keepingNote(prov))
			return resolvedImage{Ref: prov.Image, Record: prov}, nil
		case !errors.Is(err, image.ErrNotFound):
			return resolvedImage{}, fmt.Errorf("look up %s: %w", prov.Image, err)
		case prov.Origin == config.OriginOperator:
			// --embedded is named only where checkImageFlags accepts it, as in
			// keepingNote: a refusal must not offer a remedy that is itself
			// refused (review finding RCK2-2-2, the pattern SEC-2 removed).
			out := "pass --source <dir> to rebuild it; this farcast is a source build and carries no image to deploy instead"
			if d.carried.Embedded() {
				out = "pass --source <dir> to rebuild it, or --embedded to deploy the image this farcast carries"
			}
			return resolvedImage{}, fmt.Errorf("the operator-built %s image %s recorded for this instance is no longer in its registry; %s",
				c.Name, prov.Image, out)
		default:
			fprintf(env.Err, "%s: the development image %s is no longer in the registry; building it again.\n", c.Name, prov.Image)
			hasProv = false
		}
	}

	// Rule 5: the image this farcast carries.
	if d.carried.Embedded() {
		old := deployRecordOf(meta, c.Name)
		if c.Name == components.Shrike.Name {
			old = "" // its record is its provenance, which may have been ignored
			if hasProv {
				old = prov.Image
			}
		}
		return d.carriedImage(ctx, env, b, repo, user, pass, info, prov, hasProv, old)
	}

	// Rule 6: a source build of farcast, with nothing kept.
	return d.buildFromSource(ctx, env, b, repo, user, pass, config.OriginDevelopment)
}

// carriedImage is rule 5: deploy the image this farcast carries.
//
// old is the image the component is recorded as running, which a replacement
// note names: the deploy record, or for Shrike its valid provenance.
func (d *fatlineDeployer) carriedImage(ctx context.Context, env *Env, b imageBuilder, repo, user, pass string,
	info buildinfo.Info, prov config.SystemImage, hasProv bool, old string) (resolvedImage, error) {
	c := d.component
	say := d.progressTo(env)

	// a. The precheck again. The commands run it before anything is asked or
	// called; this is the same check where the image is decided.
	if err := checkCarried(d.carried, d.build); err != nil {
		return resolvedImage{}, err
	}
	art, ok := d.carried.Lookup(c.Name)
	if !ok {
		return resolvedImage{}, fmt.Errorf("this farcast carries no %s component", c.Name)
	}
	want := repo + "@" + art.Manifest

	// b. The version-skew guard (ADR 0021 decision 6, kept by ADR 0023
	// decision 4): an image another farcast version deployed is replaced only
	// when the operator says so, because two farcasts of different versions
	// would otherwise keep redeploying each other's components, and an older
	// one would silently put back an older Go.
	if hasProv && (prov.Origin == config.OriginEmbedded || prov.Origin == config.OriginNamed) &&
		prov.Image != want && prov.Farcast != "" && prov.Farcast != info.Version && !d.embedded {
		goOld := prov.Go
		if goOld == "" {
			goOld = "its Go is not recorded"
		}
		msg := fmt.Sprintf("%s runs %s, deployed by farcast %s (%s); this farcast is %s and carries %s (%s). Pass --embedded to replace it.",
			c.Name, prov.Image, prov.Farcast, goOld, info.Version, art.Manifest, art.GoVersion)
		if prov.Go != "" && goOlder(art.GoVersion, prov.Go) {
			msg += fmt.Sprintf(" That replaces %s with an older Go, %s.", prov.Go, art.GoVersion)
		}
		return resolvedImage{}, withKind(kindVersionSkew, errors.New(msg))
	}

	// c. The version tag holds only the image this farcast carries.
	tagRef := repo + ":" + imageTag(info.Version)
	push := false
	switch t, err := b.Resolve(ctx, tagRef, user, pass); {
	case errors.Is(err, image.ErrNotFound):
		push = true
	case err != nil:
		return resolvedImage{}, fmt.Errorf("look up %s: %w", tagRef, err)
	case t == want:
		if say != nil {
			say(fmt.Sprintf("%s: %s already holds the image this farcast carries", c.Name, tagRef))
		}
	default:
		// Never deployed, and said whatever the output mode: a tag that moved
		// under a release is something the operator has to hear about.
		_, found, _ := strings.Cut(t, "@")
		fprintf(env.Err, "warning: %s points at %s, which is not the %s image this farcast carries (%s); it will not be deployed. Pushing the carried image over that tag.\n",
			tagRef, found, c.Name, art.Manifest)
		push = true
	}

	// d. The push. No build confirmation: the image is part of the executable
	// the operator chose to run, and pushing it changes nothing that runs. The
	// command's own gate still applies to the deploy.
	if push {
		layer, err := d.carried.Layer(c.Name)
		if err != nil {
			return resolvedImage{}, err
		}
		if say != nil {
			say(fmt.Sprintf("%s: pushing the image this farcast carries (%s, %s)", c.Name, art.GoVersion, art.Manifest))
		}
		pushed, err := b.PushEmbedded(ctx, image.EmbeddedOptions{
			Ref: tagRef, Package: c.Package, BinaryPath: c.BinaryPath,
			Layer: layer, LayerDigest: art.Layer, LayerSize: art.LayerSize,
			DiffID: art.DiffID, Manifest: art.Manifest, GoVersion: art.GoVersion,
		}, user, pass)
		if err != nil {
			return resolvedImage{}, err
		}
		if pushed.Ref != want {
			return resolvedImage{}, fmt.Errorf("pushed %s as %s, not the %s this farcast carries", tagRef, pushed.Ref, want)
		}
	}

	// e and f. A replacement is said, whatever replaced it.
	if old != "" && old != want {
		fprintln(env.Err, d.replacingNote(old, prov, hasProv, art))
	}

	// g.
	return resolvedImage{
		Ref:    want,
		Record: config.SystemImage{Image: want, Origin: config.OriginEmbedded, Go: art.GoVersion, Farcast: info.Version},
	}, nil
}

// buildFromSource is rules 3 and 6: compile the component from a checkout with
// this machine's Go, push it under its own source- tag, and record it.
func (d *fatlineDeployer) buildFromSource(ctx context.Context, env *Env, b imageBuilder, repo, user, pass, origin string) (resolvedImage, error) {
	c := d.component
	source, err := d.findSource(d.sourceDir)
	if err != nil {
		if origin == config.OriginOperator {
			return resolvedImage{}, fmt.Errorf("--source %s is not a farcast checkout to build %s's image from: %w", d.sourceDir, c.Name, err)
		}
		return resolvedImage{}, fmt.Errorf("%s's image is not in the instance's registry %s yet and there is no farcast checkout to build it from "+
			"(run the command from a farcast checkout, or pass --source <dir>; a release farcast needs no checkout: it carries its components): %w", c.Name, repo, err)
	}
	ok, err := d.confirmBuild(ctx, env, repo, source, origin)
	if err != nil {
		return resolvedImage{}, err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return resolvedImage{}, fmt.Errorf("building %s's image from %s was declined", c.Name, source)
	}
	pushed, err := b.BuildAndPush(ctx, image.Options{
		SourceDir:  source,
		Package:    c.Package,
		Repository: repo,
		BinaryPath: c.BinaryPath,
	}, user, pass)
	if err != nil {
		return resolvedImage{}, err
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		abs = source
	}
	return resolvedImage{
		Ref: pushed.Ref,
		Record: config.SystemImage{
			Image: pushed.Ref, Origin: origin, Go: pushed.GoVersion, Farcast: d.build().Version,
			BuiltAt: d.now().UTC(), Source: abs,
		},
	}, nil
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
// ignored, said, and the command continues as if there were none.
func (d *fatlineDeployer) provenance(env *Env, meta *config.InstanceMetadata, repo string) (config.SystemImage, bool) {
	c := d.component
	rec, ok := meta.SystemImages[c.Name]
	if !ok || rec.Image == "" {
		return config.SystemImage{}, false
	}
	if c.Name != components.Shrike.Name && rec.Image != deployRecordOf(meta, c.Name) {
		return config.SystemImage{}, false
	}
	switch rec.Origin {
	case config.OriginEmbedded, config.OriginOperator, config.OriginDevelopment:
		digest, found := strings.CutPrefix(rec.Image, repo+"@")
		if !found || !isSHA256(digest) {
			fprintf(env.Err, "%s: ignoring the recorded origin of %s: it is not in this instance's registry %s\n", c.Name, rec.Image, repo)
			return config.SystemImage{}, false
		}
	case config.OriginNamed:
	default:
		// An origin this build does not know is no origin it can act on.
		return config.SystemImage{}, false
	}
	return rec, true
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

// resolveSidecarImage settles Shrike's image in the same instance registry the
// FatLine image came from.
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
func (d *fatlineDeployer) resolveSidecarImage(ctx context.Context, env *Env, reg *registryAccess, meta *config.InstanceMetadata) (resolvedImage, error) {
	// --embedded asked for Shrike's carried image, which only the registry can
	// supply: refused rather than dropped. Each command refuses it at the
	// ensure, before anything is resolved; this is belt and braces.
	if d.fatlineImage != "" && reg == nil && d.embedded {
		return resolvedImage{}, embeddedNeedsRegistry(errors.New("no image registry for this instance"))
	}
	// The break-glass path: --fatline-image names an image directly and needs
	// no registry at all, which is what makes it usable when the registry is
	// the thing that is broken. There is nowhere to get a monitor image from
	// in that case, so FatLine deploys alone — said out loud, because a
	// security component that quietly stops being deployed is worse than one
	// that was never there.
	if d.fatlineImage != "" && reg == nil {
		fprintln(env.Err, "No image registry for this instance, so the Shrike monitor cannot be deployed: deploying FatLine alone.")
		fprintln(env.Err, "Egress is still enforced and every decision is still logged by FatLine. What is missing is alerting.")
		return resolvedImage{}, nil
	}
	sidecar := *d
	sidecar.component = components.Shrike
	sidecar.fatlineImage = ""
	return sidecar.resolveImage(ctx, env, reg, meta)
}

// confirmBuild gates compiling a component's image from source. It is not a
// cost gate — registry storage is ~$0 (ADR 0007 decision 8) — it is a consent
// gate: the build compiles *this* checkout with this machine's Go and pushes
// the result into the one place the instance runs code from, so the operator
// should know it is happening, from where, with which Go, and how it is
// recorded.
//
// It is asked only for --source and a source build's fallback. A release
// farcast pushing the image it carries asks nothing here: that image is part
// of the executable the operator chose to run.
func (d *fatlineDeployer) confirmBuild(ctx context.Context, env *Env, repo, source, origin string) (bool, error) {
	if d.assumeYes {
		return true, nil
	}
	c := d.component.Name
	if !isInteractive(env) {
		return false, usagef("%s's image would be compiled from %s with this machine's Go and pushed to %s:source-…; pass --yes to build it", c, source, repo)
	}
	var goLine string
	if tc, err := image.FindToolchain(ctx, os.Environ(), source); err == nil {
		goLine = fmt.Sprintf("%s (%s)", tc.Go, tc.Version)
	} else {
		goLine = fmt.Sprintf("the Go on PATH, which could not be asked (%v)", err)
	}
	recorded := "recorded as operator-built: later commands keep it until --embedded or --source"
	if origin == config.OriginDevelopment {
		fprintf(env.Err, "This farcast carries no components (a source build), so %s's image is compiled here.\n", c)
		recorded = "recorded as a development build, which a release farcast replaces"
	}
	fprintf(env.Err, "%s's image would be compiled from %s by %s, with no container engine,\n", c, source, goLine)
	fprintf(env.Err, "pushed to the instance's registry as %s:source-…, and %s.\n", repo, recorded)
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
