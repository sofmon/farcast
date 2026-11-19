package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/farsight/cli/internal/storage"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/technocore/pricing"
)

// keyholderMonthlyUSD is the standing Autopilot cost of ALL of the keyholder's
// replicas at the requests the workload declares, and keyholderMonthlyUSDMax
// is the same fleet on a cluster without bursting support, where Autopilot
// raises every small Pod to a five-times-higher per-Pod floor.
//
// Both are ESTIMATES and are printed as such — a model of a published rate
// card, not a bill. They are computed from datasphere/deploy's own exported
// requests so the figure quoted here cannot drift from the manifest applied.
//
// This used to be a hand-written 4, copied from ADR 0008 decision 6 — where
// "~$4/month" is the cost of the SECOND replica, not of the pair. The prompt
// therefore understated the standing cost by half. Deriving it removes the
// class of error rather than the instance.
var (
	keyholderMonthlyUSD    = pricing.WorkloadMonthlyUSD(keyholderReplicas, dsdeploy.RequestCPUMilli, dsdeploy.RequestMemMiB)
	keyholderMonthlyUSDMax = float64(keyholderReplicas) * pricing.PodMonthlyUSDNoBursting(dsdeploy.RequestCPUMilli, dsdeploy.RequestMemMiB)
)

// keyholderReplicas is what the workload deploys. Two survives the common
// events — a single-pod OOM, one node's repair, a rollout, an eviction — and
// does not survive a full pool walk. Both halves of that are true.
const keyholderReplicas = 2

type storageDeployCommand struct {
	deployer fatlineDeployer
	image    string

	// ensureStorage mints the bucket and keyring when the instance has none.
	// A seam, because whether this command mints at all is the fix for a real
	// defect and deserves a test that does not need a cloud;
	// ensureStorageDefault when unset.
	ensureStorage func(ctx context.Context, env *Env, instance string) error
	// newPinStore reaches the key pin; nil reaches the cluster.
	newPinStore pinStoreOpener
	// newPlanReader opens what the plan reads the pin and farcast-system's
	// uid through under --plan and --confirm: the instance's reader (ADR
	// 0023 M2.6, A23-20), openPinPlanReader when unset, and never the
	// writer. An interactive or --yes run reads through the pin store it
	// opened as the writer instead (design §7.3).
	newPlanReader func(clusterRef) (pinPlanReader, error)
}

// ensureStorageDefault is what storage deploy mints the instance's storage
// with when its seam is unset: mintStorage, which creates a bucket and a key
// ring in the cloud. A variable, so the package's tests refuse it, and no
// test reaches a cloud provider's storage by leaving the seam unset.
var ensureStorageDefault = mintStorage

// mintStorage mints the instance's bucket and, with none on this machine,
// its keyring, as the first storage command to need them does.
func mintStorage(ctx context.Context, env *Env, instance string) error {
	_, err := openSession(ctx, env, instance, true)
	return err
}

// ensureDefaults sets the command's own seams that a test left unset.
func (c *storageDeployCommand) ensureDefaults() {
	if c.ensureStorage == nil {
		c.ensureStorage = ensureStorageDefault
	}
	if c.newPlanReader == nil {
		c.newPlanReader = openPinPlanReader
	}
}

func (*storageDeployCommand) Name() string { return "deploy" }
func (*storageDeployCommand) Synopsis() string {
	return "Deploy the in-cluster keyholder that serves storage to applications"
}

func (*storageDeployCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage deploy <instance> [--datasphered-image REF@sha256:… | --source DIR | --embedded] [-y]
                               [--plan | --confirm <digest>]

Deploy the keyholder: the one in-cluster process that holds DataSphere key
material, and holds it only in memory.

Its image is the one this farcast carries, pushed into the instance's own
registry when the version tag does not already hold it. --datasphered-image
deploys a digest-pinned image as given; --source builds one from a farcast
checkout with this machine's Go and records it as operator-built, which later
deploys keep until --embedded or --source. A release farcast replaces an image
another farcast version deployed only with --embedded.

It comes up SEALED and stays sealed until you run 'farcast storage unseal'.
That is not a defect — key material never rests on cloud infrastructure, so it
has to arrive from this machine, and any restart returns the replica to the
same state. Applications receive ErrStorageSealed meanwhile.

Two replicas run behind a PodDisruptionBudget, spread across hosts. That
survives a single pod's OOM, one node's repair, a rollout and an eviction; it
does not survive every node being replaced at once.

It reads the key pin, decides the pin it writes and the image, and checks
the instance's mTLS material before it asks anything: it reads the
instance's recorded registry with the installer's key, and creates the
bucket and keyring, ensures the registry, pushes and builds only once the
deploy is confirmed. On an instance that records no registry, an
interactive or --yes run ensures it first.

--plan prints what the deploy would do, and changes nothing: its cost, the
image and where it comes from, the registry calls and the bucket it would
create, what it mints, the key pin it writes, each document it would apply,
and what it would print, with the plan's digest. It reads the pin and the
cluster as the instance's reader, which 'farcast reader grant' must have
verified read-only (there is no fallback to the installer's account), and
the registry with the installer's key; it opens no writer, and no private
key. A keyring behind the pin is a block: the plan says so, and its
--confirm refuses it.

--confirm <digest> does exactly the plan with that digest, asking nothing,
and refuses, having written nothing, if anything it binds has changed since.
It recomputes the plan as the reader, and opens the writer only after the
comparison, refusing if the writer reaches another cluster than the one the
plan read, or finds the pin moved; it writes the pin once, at the version
the plan read. Its plan is the consent to replacing an image another
farcast version deployed; --yes never is, and never implies --embedded.

This command changes the cluster. 'farcast storage unseal' deliberately does
not, so the command you reach for during an outage cannot make one worse.`)
}

func (c *storageDeployCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.image, "datasphered-image", "", imageFlagUsage("keyholder", components.Datasphered))
	fs.StringVar(&c.deployer.sourceDir, "source", "", "farcast checkout to build the keyholder's image from with this machine's Go; recorded as operator-built")
	c.deployer.setEmbeddedFlag(fs)
	c.deployer.setYesFlag(fs, "skip the cost confirmation and, for --source or a source build, the build confirmation; never implies --embedded")
	c.deployer.consent.register(fs)
}

// The texts of storage deploy's refusals (ADR 0023 M2.6, A23-43).
const (
	// msgKeyholderCostYes is the cost gate's refusal without a terminal:
	// the keyholder's monthly cost, and its replicas.
	msgKeyholderCostYes = "deploying the keyholder adds ~$%s/month of standing compute (%d replicas); pass --yes to confirm" + consentSuffix
	// msgDeployBehindPin is the block of a keyring behind the pin.
	msgDeployBehindPin = "%v. Deploying restarts every replica, and none of them could be unsealed from here afterwards, so nothing was deployed. " +
		"Bring this keyring up to date ('farcast storage key import'), or deploy from the machine that rotated"
	// msgDeployPinUnwritten is a pin the deploy could not write, or would
	// not: the cause, and the command that writes it.
	msgDeployPinUnwritten = "the key pin could not be written, so nothing was deployed: %w. %s re-arms it"
	// msgStorageRecordChanged is --confirm's refusal of a record that
	// changed while the deploy ran (A23-43): the instance, and what of it.
	msgStorageRecordChanged = "instance %q's record changed while the command ran (its %s is not what the plan read); " +
		"the bucket and the keyring were ensured, and nothing else was written"
)

func (c *storageDeployCommand) Run(ctx context.Context, env *Env, args []string) (err error) {
	// A 403 the writer met says whose it was, once (A20-9); one a plan's
	// reader met says so already (A23-22), and writerRefused leaves it.
	var meta *config.InstanceMetadata
	defer func() { err = writerRefused(err, meta) }()
	if len(args) != 1 {
		return usagef("storage deploy takes one instance argument")
	}
	mode, digest, err := c.deployer.consent.mode(c.deployer.assumeYes)
	if err != nil {
		return err
	}
	name := args[0]
	c.ensureDefaults()
	c.deployer.component = components.Datasphered
	c.deployer.fatlineImage = c.image
	c.deployer.ensureDefaults()
	if err := c.deployer.checkImageFlags(); err != nil {
		return err
	}
	// Before the record is read: a farcast whose carried components it must
	// not push is refused before anything is asked or called, in every mode,
	// --plan included, before any plan is computed (A23-10).
	if err := c.deployer.precheck(); err != nil {
		return err
	}

	meta, err = env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if err := recordNamed(meta, name); err != nil {
		return err
	}
	if err := refuseUnmigrated(name, meta); err != nil {
		return err
	}
	if !meta.FatLineDeployed {
		// The keyholder is only reachable through the tunnel, so deploying it
		// into an instance with no tunnel would produce something nobody can
		// ever unseal.
		return fmt.Errorf("instance %q is not connected; run 'farcast connect %s' first — "+
			"the keyholder is reachable only through the FatLine tunnel", name, name)
	}

	// The key pin is read before anything is spent: the plan's first read.
	// A deploy restarts every replica, and each one comes back enforcing the
	// pin: from a keyring the pin already refuses, nothing here could unseal
	// them afterwards.
	//
	// An interactive or --yes run reads it as the writer (ADR 0023 M2.5,
	// A20-10): one writer serves the pin and the apply, opened here, before
	// the cost is asked or anything is created or recorded, so an instance
	// this machine cannot write as is refused with nothing changed, and no
	// second open after the keyholder is recorded can fail. --plan and
	// --confirm read it as the instance's reader, which must be one 'reader
	// grant' has verified (A23-21): the writer is never opened for a plan,
	// and under --confirm only after the comparison (A23-23).
	ref := clusterRef{Dir: env.ConfigDir, Meta: meta, Warn: env.Err}
	var cl clusterApplier
	var ps pinStore
	var rd pinPlanReader
	if mode == consentNone {
		ref.Identity = kube.Writer
		if cl, err = c.deployer.newCluster(ref); err != nil {
			return fmt.Errorf("the key pin could not be reached, so nothing was deployed: %w", err)
		}
		defer afterWrites(env, name, cl)
		if ps, err = c.pinStoreOf(ref, cl); err != nil {
			return fmt.Errorf("the key pin could not be reached, so nothing was deployed: %w", err)
		}
		rd = ps
	} else {
		if err := requireGrantedReader(env.ConfigDir, meta, "storage deploy", mode); err != nil {
			return err
		}
		ref.Identity = kube.Reader
		if rd, err = c.newPlanReader(ref); err != nil {
			return err
		}
	}

	// Only a run that can pass the cost gate ensures a registry the record
	// does not name before its plan (A23-24's exception): one with no
	// terminal and no --yes is refused, and writes nothing.
	ensure := mode == consentNone && (c.deployer.assumeYes || isInteractive(env))
	p, b, err := c.plan(ctx, env, meta, rd, mode, ensure)
	if err != nil {
		if mode == consentNone {
			return p.refusal(env, c.deployer.embedded, err)
		}
		return err
	}
	switch mode {
	case consentPlan:
		return printPlan(env, b, c.deployer.now())
	case consentConfirm:
		if err := confirmPlan(b, digest); err != nil {
			return err
		}
	default:
		if len(b.Blocked) > 0 {
			return refuseBlocked(b)
		}
	}
	// What the plan says, once: before anything is asked or, under
	// --confirm, right after the comparison (A23-26). An interactive or
	// --yes run refuses a version skew there, before the image's own lines
	// (A25-23); under --confirm the plan is the consent to the replacement.
	if err := p.image.say(env, c.deployer.embedded || mode == consentConfirm); err != nil {
		return err
	}
	if mode == consentConfirm {
		// The writer, after the comparison and before anything irreversible
		// (A23-23): its preflight must read the cluster the plan read, and
		// its read of the pin must find it where the plan did. No bucket,
		// keyring, registry or image is touched before.
		if cl, err = openConfirmed(ctx, env, meta, b, c.deployer.newCluster); err != nil {
			return err
		}
		defer afterWrites(env, name, cl)
		ref.Identity = kube.Writer
		if ps, err = c.pinStoreOf(ref, cl); err != nil {
			return fmt.Errorf("the key pin could not be reached, so nothing was deployed: %w", err)
		}
		if err := checkPlannedPin(ctx, ps, p.pin); err != nil {
			return err
		}
	} else if proceed, err := c.consented(env, meta, p); err != nil || !proceed {
		return err
	}
	return c.deploy(ctx, env, meta, cl, ps, p, mode)
}

// deploy executes the plan's decisions, after consent or, under --confirm,
// after the comparison and the writer's checks (A23-43): the bucket and the
// keyring, minted and then read back; the registry ensure and the image the
// plan decided, pushed or built and never looked up again; the keyholder's
// server leaf, issued from the instance's CA; the pin, before the replicas
// exist; the record; the bucket grant; and the apply.
func (c *storageDeployCommand) deploy(ctx context.Context, env *Env, meta *config.InstanceMetadata, cl clusterApplier, ps pinStore,
	p preparedStorageDeploy, m consentMode) error {
	name := meta.Name
	// Mint the bucket and the keyring here rather than sending the operator
	// away to create them.
	//
	// This used to refuse, telling the operator to "run a 'farcast storage'
	// command first so the bucket is minted" — and the only such command that
	// mints is one that writes. The Phase 4.3 walk followed that instruction
	// literally, wrote to app/, and so put an object under the MASTER key
	// space at the one moment before the app scope exists. Unseal then minted
	// that scope over the prefix, and the object became unreachable by its own
	// name. A bring-up order whose documented happy path orphans data is a
	// trap in the order, not a mistake by whoever walked it.
	//
	// Minting the keyring here is deliberate too: it is needed by the unseal
	// that follows immediately, and the key-loss warning it prints belongs at
	// the moment storage is brought up rather than buried in the output of a
	// file copy.
	//
	// It comes after the cost is agreed, not before: the cost gate used to
	// sit below the bucket, so declining it — or running non-interactively
	// without --yes — exited non-zero having already created a real bucket
	// and keyring. The Phase 4.4 walk hit exactly that.
	if p.mintsStorage {
		if err := c.ensureStorage(ctx, env, name); err != nil {
			return fmt.Errorf("create storage for %q: %w", name, err)
		}
		fresh, err := env.ConfigDir.LoadInstanceMetadata(name)
		if err != nil {
			return fmt.Errorf("re-read instance %q after creating its storage: %w", name, err)
		}
		if m == consentConfirm {
			if err := p.sameRecord(name, fresh); err != nil {
				return err
			}
		}
		meta = fresh
	}

	// The registry ensure the plan bound, then the image the plan decided
	// (A23-34).
	reg, err := c.deployer.realizeRegistry(ctx, env, name, meta, p.reg, m)
	if err != nil {
		return err
	}
	resolved, err := c.deployer.realizeAndNote(ctx, env, reg, p.image)
	if err != nil {
		return err
	}
	img := resolved.Ref

	mtls, err := realizeIdentity(env, name, p.identity, m)
	if err != nil {
		return err
	}
	// The keyholder gets its OWN server leaf, distinct from FatLine's, so the
	// operator's session verifies that it is talking to the keyholder and not
	// to the tunnel that carried it. The CA private key never leaves here.
	certPEM, keyPEM, err := identity.IssueKeyholderServer(mtls.CACertPEM, mtls.CAKeyPEM, name)
	if err != nil {
		return fmt.Errorf("issue the keyholder's server identity: %w", err)
	}
	manifests, err := dsdeploy.Render(keyholderConfig(meta, img, meta.Storage.Bucket, meta.Storage.Provider, meta.Storage.Location,
		mtls.CACertPEM, certPEM, keyPEM))
	if err != nil {
		return err
	}

	// Before the replicas exist, and always: TechnoCore may create ConfigMaps
	// in this namespace, so the pin is this machine's only if this machine
	// created it. No apply touches it afterwards — an apply is
	// last-writer-wins, and could move it backwards. Under --confirm the
	// plan's pin is written once, at the version the plan read (A23-42).
	if m == consentConfirm {
		if _, err := pinOnce(ctx, ps, p.pin); err != nil {
			if kindOf(err) == kindPlanChanged {
				return err
			}
			return fmt.Errorf(msgDeployPinUnwritten, err, pinRemedy(name))
		}
	} else if _, err := pinOnDeploy(ctx, ps, env, name); err != nil {
		var behind *pinBehind
		if errors.As(err, &behind) {
			return fmt.Errorf("%v; nothing was deployed", behind)
		}
		return fmt.Errorf(msgDeployPinUnwritten, err, pinRemedy(name))
	}

	// Recorded BEFORE the apply, like every other billable thing this CLI
	// creates: a workload running in a cluster that local state does not know
	// about is one nobody will think to tear down.
	previous := meta.Keyholder
	meta.Keyholder = &config.Keyholder{
		Deployed: true, Image: img, Replicas: keyholderReplicas,
		RecordedAt: time.Now().UTC(),
	}
	if previous != nil {
		meta.Keyholder.Scope = previous.Scope
		meta.Keyholder.ScopePrefix = previous.ScopePrefix
		meta.Keyholder.Generation = previous.Generation
	}
	recordSystemImage(meta, components.Datasphered.Name, resolved.Record)
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return fmt.Errorf("record the keyholder before deploying it: %w", err)
	}

	// Before the workload exists, not after: a replica that starts without
	// this grant crash-loops, and an operator reading the fix underneath a
	// deploy that has already failed is the wrong order. On stderr so it
	// survives --output json, where the human result is never rendered. It
	// names the bucket as it exists now, a first deploy's included.
	writeBucketGrant(env.Err, meta.Project, meta.Storage.Bucket, dsdeploy.DefaultNamespace, dsdeploy.DefaultName)

	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Deploying the keyholder to %q…\n", name)
	}
	if err := cl.Apply(ctx, manifests); err != nil {
		return fmt.Errorf("deploy the keyholder: %w", err)
	}

	// Deliberately NO rollout wait. Every replica comes up sealed and a sealed
	// replica never becomes Ready, so waiting for readiness here would block
	// until it timed out — on the happy path — and teach the operator to
	// interrupt the tool. The next step is the unseal, and it is said plainly.
	return env.Printer.Print(deployResult{
		Instance: name, Image: img, Replicas: keyholderReplicas,
		Project: meta.Project, Bucket: meta.Storage.Bucket,
		Namespace: dsdeploy.DefaultNamespace, ServiceAccount: dsdeploy.DefaultName,
	})
}

// pinStoreOf is the pin storage deploy reads and writes: pinStoreFor, so the
// writer the deploy opened serves the pin and the apply (A20-10).
func (c *storageDeployCommand) pinStoreOf(ref clusterRef, cl clusterApplier) (pinStore, error) {
	return pinStoreFor(c.newPinStore, ref, cl)
}

// keyholderConfig is the keyholder's workload for meta's instance, rendered
// over img, the bucket it serves and where, and its CA and server leaf.
func keyholderConfig(meta *config.InstanceMetadata, img, bucket, provider, location string, caCertPEM, serverCertPEM, serverKeyPEM []byte) dsdeploy.Config {
	return dsdeploy.Config{
		Image:         img,
		Replicas:      keyholderReplicas,
		Instance:      meta.Name,
		Bucket:        bucket,
		Provider:      provider,
		Project:       meta.Project,
		Location:      location,
		CACertPEM:     caCertPEM,
		ServerCertPEM: serverCertPEM,
		ServerKeyPEM:  serverKeyPEM,
	}
}

// preparedStorageDeploy is every decision storage deploy executes, made once
// by its plan (ADR 0023 M2.6, A23-43): interactive runs, --yes and --confirm
// all execute from it.
type preparedStorageDeploy struct {
	// mintsStorage: the record names no bucket, so the deploy mints the
	// bucket and, with none on this machine, the keyring (ensureStorage).
	mintsStorage bool
	// keyholderDeployed and keyholderReplicas are the keyholder the record
	// named when the plan read it, which a --confirm reads again once the
	// storage is minted (sameRecord).
	keyholderDeployed bool
	keyholderReplicas int
	// bucket, provider and location are what the plan rendered the
	// keyholder with: the record's, or on a first deploy the placeholder
	// bucket and the provider and location the mint will record.
	bucket, provider, location string
	// identity is the instance's CA, read as its certificate alone.
	identity identityDecision
	// reg is the registry the plan read; image is the keyholder's image as
	// it decided it.
	reg   *registryAccess
	image imageDecision
	// pin is the key pin the deploy writes, or the one it keeps.
	pin pinDecision
	// cost is the plan's cost fact, which the question is asked from.
	cost plan.CostFact
}

// refusal is how an interactive or --yes run refuses a plan it could not
// make: a version skew the image decision stands for, before anything is
// said, or what it said up to the error, then the error.
func (p preparedStorageDeploy) refusal(env *Env, embedded bool, err error) error {
	if skew := p.image.say(env, embedded); skew != nil {
		return skew
	}
	return err
}

// sameRecord is --confirm's check of the record it read again after minting
// the storage (A23-43): it still names the instance, its keyholder is the one
// the plan read, its bucket is the one the plan rendered (or, for the bucket
// the plan said it would create, one), and its storage provider and location
// are the planned ones. Otherwise the command refuses, plan_changed, having
// written nothing but the bucket and the keyring.
func (p preparedStorageDeploy) sameRecord(name string, fresh *config.InstanceMetadata) error {
	if err := recordNamed(fresh, name); err != nil {
		return err
	}
	deployed, replicas := false, 0
	if fresh.Keyholder != nil {
		deployed, replicas = fresh.Keyholder.Deployed, fresh.Keyholder.Replicas
	}
	what := ""
	switch {
	case deployed != p.keyholderDeployed || replicas != p.keyholderReplicas:
		what = "keyholder"
	case fresh.Storage == nil || fresh.Storage.Bucket == "" || (!p.mintsStorage && fresh.Storage.Bucket != p.bucket):
		what = "storage bucket"
	case fresh.Storage.Provider != p.provider:
		what = "storage provider"
	case fresh.Storage.Location != p.location:
		what = "storage location"
	default:
		return nil
	}
	return changedAfterPlan(consentConfirm, fmt.Sprintf(msgStorageRecordChanged, name, what))
}

// placeholderBucket is the bucket a first deploy's plan renders and names
// (A23-12, A23-30): the mint draws the real name, at random, only once the
// deploy is confirmed.
func placeholderBucket(instance string) string {
	return "farcast-placeholder:bucket:" + instance
}

// keyholderLeafPlaceholder is the keyholder's server leaf or key as a plan
// renders it (A23-30): a plan issues no leaf and opens no CA key.
func keyholderLeafPlaceholder(instance, part string) []byte {
	return []byte("farcast-placeholder:keyholder_leaf:" + identity.KeyholderServerName(instance) + ":" + part)
}

// plan is storage deploy's plan (design §9.4, A23-43). It reads the key pin,
// then farcast-system's uid, which it binds as its target, through rd — the
// reader under --plan and --confirm, its errors the reader's (planRead), and
// in an interactive or --yes run the writer's pin store — and the keyring's
// key ids. It decides the pin the deploy writes (decidePin, or the empty pin
// with no keyring here): a keyring behind the pin blocks it, as does a pin
// that refuses the keyring itself or that no replica could read, and nothing
// more is read, Google included (A23-18). Otherwise it checks the instance's
// mTLS material, reading the CA certificate alone (decideIdentity), reads
// the registry the record names with the installer's key (deployRegistry),
// and decides the keyholder's image (decideImage). Its facts are the cost;
// the image; the registry's cloud facts, and the bucket a first deploy
// creates; the mints, the keyholder's leaf and a first keyring; a restart of
// the replicas a deployed keyholder runs; the pin and its write; each
// document of the workload it would apply, rendered over the image it names,
// the placeholder leaf and, on a first deploy, the placeholder bucket; and
// its notices, the bucket grant among them.
//
// With ensure (an interactive or --yes run, decided by the caller) a record
// that names no registry is first given one (A23-24's exception), after the
// pin, the uid, the blocks and the mTLS check. It reads no terminal and, but
// for that ensure, writes nothing.
func (c *storageDeployCommand) plan(ctx context.Context, env *Env, meta *config.InstanceMetadata, rd pinPlanReader, m consentMode, ensure bool) (preparedStorageDeploy, plan.Bound, error) {
	name := meta.Name
	var p preparedStorageDeploy
	if meta.Keyholder != nil {
		p.keyholderDeployed, p.keyholderReplicas = meta.Keyholder.Deployed, meta.Keyholder.Replicas
	}
	cur, present, rv, invalid, err := readPin(ctx, rd)
	if err != nil {
		return p, plan.Bound{}, planRead(m, fmt.Errorf("%w; nothing was deployed", err), name)
	}
	uid, err := rd.NamespaceUID(ctx, dsdeploy.DefaultNamespace)
	if err != nil {
		return p, plan.Bound{}, planRead(m, fmt.Errorf("read the uid of the instance's %s namespace: %w", dsdeploy.DefaultNamespace, err), name)
	}
	b := newBound("storage deploy", meta, "reader", uid)
	b.Options = sortedOptions(c.deployer.imageOptions())

	// The keyring the pin is decided from: the one the mint makes, with no
	// scopes, when the record names no bucket and this machine holds none;
	// otherwise this machine's, its key ids only (A23-25); and none at all
	// when it cannot be read, as pinOnDeploy has it.
	p.mintsStorage = meta.Storage == nil || meta.Storage.Bucket == ""
	mintsKeyring := false
	if p.mintsStorage {
		exists, err := env.ConfigDir.InstanceKeyringExists(name)
		if err != nil {
			return p, plan.Bound{}, err
		}
		mintsKeyring = !exists
	}
	var lists []scopeKEKs
	keyringHere := true
	if !mintsKeyring {
		if raw, lerr := env.ConfigDir.LoadInstanceKeyring(name); lerr != nil {
			keyringHere = false
		} else {
			k, err := datasphere.ParseKeyring(raw)
			if err != nil {
				return p, plan.Bound{}, fmt.Errorf(msgDeployPinUnwritten, err, pinRemedy(name))
			}
			lists = kekLists(k)
		}
	}
	if keyringHere {
		p.pin, err = decidePin(cur, present, rv, invalid, lists, true, false)
	} else {
		p.pin = emptyPinDecision(cur, present, rv, invalid)
	}
	var behind *pinBehind
	switch {
	case errors.As(err, &behind):
		b.Blocked = []plan.Block{blockOf(fmt.Errorf(msgDeployBehindPin, behind))}
		return p, b, nil
	case err != nil:
		b.Blocked = []plan.Block{blockOf(fmt.Errorf(msgDeployPinUnwritten, err, pinRemedy(name)))}
		return p, b, nil
	}

	// The keyholder's leaf is issued from the instance's CA, which must be
	// whole here (A26-2): connected, so never minted.
	if p.identity, err = decideIdentity(env, name, true); err != nil {
		return p, plan.Bound{}, err
	}
	if p.reg, err = c.deployer.deployRegistry(ctx, env, meta, ensure); err != nil {
		return p, plan.Bound{}, err
	}
	if p.image, err = c.deployer.decideImage(ctx, env, p.reg, meta); err != nil {
		return p, plan.Bound{}, err
	}

	// What the keyholder serves: the record's storage, or on a first deploy
	// what the mint will record — the provider for the instance's cloud, in
	// its region — and a placeholder for the bucket it names at random.
	if p.mintsStorage {
		if p.provider, err = storage.ProviderFor(meta); err != nil {
			return p, plan.Bound{}, err
		}
		p.bucket, p.location = placeholderBucket(name), meta.Region
	} else {
		p.bucket, p.provider, p.location = meta.Storage.Bucket, meta.Storage.Provider, meta.Storage.Location
	}
	manifests, err := dsdeploy.Render(keyholderConfig(meta, p.image.planTarget(), p.bucket, p.provider, p.location,
		p.identity.caCertPEM, keyholderLeafPlaceholder(name, "cert"), keyholderLeafPlaceholder(name, "key")))
	if err != nil {
		return p, plan.Bound{}, err
	}
	writes, err := applyFacts(manifests)
	if err != nil {
		return p, plan.Bound{}, err
	}
	pins, err := pinFacts(p.pin, nil)
	if err != nil {
		return p, plan.Bound{}, err
	}
	p.cost = keyholderCost(meta)

	facts := []plan.Fact{p.cost, p.image.imageFact(meta)}
	facts = append(facts, registryFacts(meta, p.image)...)
	if p.mintsStorage {
		facts = append(facts, plan.CloudFact{Type: plan.TypeCloud, Service: plan.CloudStorage, Action: plan.CloudCreateBucket, Target: p.bucket})
	}
	facts = append(facts, plan.MintFact{Type: plan.TypeMint, What: plan.MintKeyholderLeaf, Subject: identity.KeyholderServerName(name)})
	if mintsKeyring {
		facts = append(facts, plan.MintFact{Type: plan.TypeMint, What: plan.MintKeyring, Subject: name})
	}
	// A new leaf changes the pod template's mTLS hash, so the replicas of a
	// keyholder already deployed roll.
	if p.keyholderDeployed {
		facts = append(facts, plan.RestartFact{Type: plan.TypeRestart, Component: components.Datasphered.Name, Because: plan.RestartBecause})
	}
	facts = append(facts, pins...)
	facts = append(facts, writes...)
	if grant := bucketGrantText(meta.Project, p.bucket); grant != "" {
		facts = append(facts, noticeFact(grant))
	}
	for _, line := range p.image.said() {
		facts = append(facts, noticeFact(line))
	}
	b.Facts = append(facts, sourceNotices(p.image)...)
	return p, b, nil
}

// consented is an interactive or --yes run's consent to its plan: the cost,
// asked from the plan's cost fact, then the build question when the image is
// built from source. A version skew was refused before either
// (imageDecision.say). A declined cost is no error, as it never was; a
// declined build is.
func (c *storageDeployCommand) consented(env *Env, meta *config.InstanceMetadata, p preparedStorageDeploy) (bool, error) {
	ok, err := c.confirmCost(env, meta, p.cost)
	if err != nil {
		return false, err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return false, nil
	}
	return true, c.deployer.buildConsent(env, p.image)
}

// costWhatKeyholder is the keyholder's standing cost, as its cost fact names
// it.
const costWhatKeyholder = "the keyholder"

// keyholderCost is storage deploy's cost fact (A23-33): the keyholder's
// replicas, standing, with the same fleet's figure on a cluster without
// bursting support as its most, against the instance's cost limit and its
// floor fully provisioned (fullFloorCost). The question and the refusal are
// asked from it, so they say what the plan binds.
func keyholderCost(meta *config.InstanceMetadata) plan.CostFact {
	f := fullFloorCost(meta)
	f.Standing = []plan.StandingCost{{What: costWhatKeyholder, Replicas: keyholderReplicas,
		CPUMilli: dsdeploy.RequestCPUMilli, MemMiB: dsdeploy.RequestMemMiB,
		MonthCents: cents(keyholderMonthlyUSD), MaxMonthCents: ptr(cents(keyholderMonthlyUSDMax))}}
	return f
}

// keyholderCostQuestion is the cost gate's question, from the cost fact, in
// exact cents.
func keyholderCostQuestion(name string, f plan.CostFact) string {
	k := f.Standing[0]
	return fmt.Sprintf("Deploying the keyholder to %q runs %d replicas continuously (~$%s/month estimated, "+
		"against the cost limit %s/%s).\nThat figure models %s prices as of %s from the workload's declared requests. On a cluster "+
		"without bursting support Autopilot raises small Pods to a higher floor, which puts the same fleet "+
		"nearer $%s/month.",
		name, k.Replicas, amount(k.MonthCents), money(f.Currency, f.LimitCents), terminalText(f.Period),
		terminalText(f.Pricing.Region), terminalText(f.Pricing.AsOf), amount(*k.MaxMonthCents))
}

// confirmCost is storage deploy's cost gate, asked from the plan's cost fact
// f. --yes proceeds; a session with no terminal and no --yes is a usage
// error, which names the plan's route.
func (c *storageDeployCommand) confirmCost(env *Env, meta *config.InstanceMetadata, f plan.CostFact) (bool, error) {
	if c.deployer.assumeYes {
		return true, nil
	}
	if !isInteractive(env) {
		return false, usagef(msgKeyholderCostYes, amount(f.Standing[0].MonthCents), f.Standing[0].Replicas)
	}
	fprintln(env.Err, keyholderCostQuestion(meta.Name, f))
	return newPrompter(env.In, env.Err).yesNo("Deploy it?")
}

type deployResult struct {
	Instance       string `json:"instance"`
	Image          string `json:"image"`
	Replicas       int    `json:"replicas"`
	Project        string `json:"project,omitempty"`
	Bucket         string `json:"bucket,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
}

func (r deployResult) Human(w io.Writer) error {
	fprintf(w, "Keyholder deployed to %q (%d replicas)\n", r.Instance, r.Replicas)
	fprintf(w, "  image  %s\n", terminalText(r.Image))
	fprintf(w, "\nEvery replica is SEALED and will not become ready until you unseal it.\n")
	fprintf(w, "Run: farcast storage unseal %s\n", r.Instance)

	// The keyholder admits only callers that present a leaf (ADR 0018
	// decision 1), and a leaf is issued at 'farcast run'. An application
	// deployed before this keyholder holds none and is refused the moment
	// the new one starts — as ErrStorageUnavailable, which looks like an
	// outage to whoever did not read this line.
	fprintf(w, "\nApplications deployed before this keyholder hold no storage identity and will be\n")
	fprintf(w, "refused by it. Run 'farcast run' again for each of them to issue one.\n")

	// The grant itself was printed BEFORE the deploy — see writeBucketGrant.
	// All that belongs here is the reminder that it has to be in place before
	// the unseal above will work.
	if r.Project != "" && r.Bucket != "" {
		fprintf(w, "\nThe bucket grant printed above has to be in place first. Without it the\n")
		fprintf(w, "replicas crash-loop on a 403 at start-up and the unseal fails.\n")
	}
	return nil
}

// writeBucketGrant prints the IAM binding the keyholder needs before it runs.
//
// The keyholder reads and writes the bucket with a cloud-side identity (ADR
// 0008 decision 8). FarCast does not apply it: that needs permission to change
// a bucket's IAM, which the operator's credential is not required to carry and
// which this CLI deliberately never asks for.
//
// It is printed BEFORE the workload is applied. It used to be printed after,
// as part of the result — so the replicas were already crash-looping on a 403
// by the time the operator read how to prevent it, and the instance looked
// broken. That happened twice, on the Phase 3.2 and Phase 4.4 walks, and the
// second time cost a failed unseal as well (which is why unseal no longer
// consumes a generation when every push fails).
func writeBucketGrant(w io.Writer, project, bucket, namespace, serviceAccount string) {
	if project == "" || bucket == "" {
		return
	}
	// The project and the bucket are the record's, printed into commands to
	// paste, so a value that does not print as it is goes in Go-quoted
	// (ADR 0023 M2.6d, A28-3); one that does is unchanged.
	project, bucket = terminalText(project), terminalText(bucket)
	fprintf(w, "\nBefore this keyholder can start, it needs read/write access to the bucket\n")
	fprintf(w, "under its own identity. If you have not granted it for this instance yet, run:\n\n")
	fprintf(w, "  PROJNUM=$(gcloud projects describe %s --format='value(projectNumber)')\n", project)
	fprintf(w, "  PRINCIPAL=\"principal://iam.googleapis.com/projects/$PROJNUM/locations/global/workloadIdentityPools/%s.svc.id.goog/subject/ns/%s/sa/%s\"\n",
		project, namespace, serviceAccount)
	fprintf(w, "  gcloud storage buckets add-iam-policy-binding gs://%s \\\n", bucket)
	fprintf(w, "    --member \"$PRINCIPAL\" --role roles/storage.objectAdmin\n")
	fprintf(w, "  gcloud storage buckets add-iam-policy-binding gs://%s \\\n", bucket)
	fprintf(w, "    --member \"$PRINCIPAL\" --role roles/storage.legacyBucketReader\n")
	fprintf(w, "\nThe grant is on the BUCKET, not the project, and object access is\n")
	fprintf(w, "separated from bucket reads so the keyholder cannot delete its own bucket.\n\n")
}

// bucketGrantText is writeBucketGrant's lines as a plan's notice carries
// them, without the blank lines around them, or "" when it prints none.
func bucketGrantText(project, bucket string) string {
	var w strings.Builder
	writeBucketGrant(&w, project, bucket, dsdeploy.DefaultNamespace, dsdeploy.DefaultName)
	return strings.Trim(w.String(), "\n")
}
