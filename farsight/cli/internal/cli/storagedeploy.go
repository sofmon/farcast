package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
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
	"github.com/sofmon/farcast/planck"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
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
	// grantBucket is --grant-bucket: apply the keyholder's bucket grant, by
	// its ServiceAccount's uid, under --confirm or this terminal's question
	// (ADR 0023 M2.8, design §33, A33-24).
	grantBucket bool

	// ensureStorage mints the bucket and keyring when the instance has none.
	// A seam, because whether this command mints at all is the fix for a real
	// defect and deserves a test that does not need a cloud;
	// ensureStorageDefault when unset.
	ensureStorage func(ctx context.Context, env *Env, instance string) error
	// newPinStore reaches the key pin; nil reaches the cluster.
	newPinStore pinStoreOpener
	// newPlanReader opens what the plan reads the pin, farcast-system's uid
	// and the keyholder's ServiceAccount through under --plan and
	// --confirm: the instance's reader (ADR 0023 M2.6, A23-20; M2.8,
	// A33-18), openKeyholderPlanReader when unset, and never the writer. An
	// interactive or --yes run reads through the pin store and the writer
	// it opened instead (design §7.3).
	newPlanReader func(clusterRef) (keyholderPlanReader, error)
	// openBucketGrants opens the instance's bucket IAM with the installer's
	// key (A33-14): what the plan reads the keyholder's grant through, in
	// every mode, and what --grant-bucket applies it with.
	// openBucketGrantsDefault when unset.
	openBucketGrants func(ctx context.Context, env *Env, meta *config.InstanceMetadata) (bucketGrants, error)
	// interactive says whether the run can ask this terminal; isInteractive
	// when unset.
	interactive func(*Env) bool
}

// keyholderPlanReader is what storage deploy's plan reads the cluster
// through (A33-18): the key pin and farcast-system's uid, and the
// keyholder's ServiceAccount, whose uid the bucket grant names.
type keyholderPlanReader interface {
	pinPlanReader
	serviceAccountReader
}

// keyholderReader is an interactive or --yes run's plan reader: the pin
// store it opened as the writer, and the writer itself for the account.
type keyholderReader struct {
	pinPlanReader
	serviceAccountReader
}

// openKeyholderPlanReader is storage deploy's plan reader when its seam is
// unset (A23-20, A33-18): openReaderDefault, the instance's cluster as its
// reader, never the writer. A refusal returns a nil reader, never a nil
// *cluster.Client inside a non-nil one.
func openKeyholderPlanReader(r clusterRef) (keyholderPlanReader, error) {
	cl, err := openReaderDefault(r)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// bucketGrants is the instance's bucket IAM as storage deploy reads and
// changes it (A33-14): *storage.Grants, which proves the bucket's labels
// before each call.
type bucketGrants interface {
	State(ctx context.Context, bucket string, roles []string, member, shared string) (state, sharedState datasphere.GrantState, sharedRoles []string, err error)
	Ensure(ctx context.Context, bucket string, roles []string, member, shared string) (bool, error)
}

// ensureStorageDefault is what storage deploy mints the instance's storage
// with when its seam is unset: mintStorage, which creates a bucket and a key
// ring in the cloud. A variable, so the package's tests refuse it, and no
// test reaches a cloud provider's storage by leaving the seam unset.
var ensureStorageDefault = mintStorage

// openBucketGrantsDefault is what storage deploy opens the bucket's IAM with
// when its seam is unset: openInstanceBucketGrants, which reaches Google. A
// variable, so the package's tests refuse it (the tenth refusing seam), and
// no test reaches a bucket's policy by leaving the seam unset.
var openBucketGrantsDefault = openInstanceBucketGrants

// openInstanceBucketGrants opens the instance's bucket IAM with the
// installer's key (A33-14): loadInstallerKey, which refuses a blank key, so
// Application Default Credentials are never reached, then
// storage.OpenBucketGrants, which opens no keyring and mints nothing. It
// sends nothing: the adapter resolves its credential on its first call.
func openInstanceBucketGrants(_ context.Context, env *Env, meta *config.InstanceMetadata) (bucketGrants, error) {
	creds, err := loadInstallerKey(env.ConfigDir, meta.Name)
	if err != nil {
		return nil, err
	}
	g, err := storage.OpenBucketGrants(meta, creds.ServiceAccountKey)
	if err != nil {
		return nil, err
	}
	return g, nil
}

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
		c.newPlanReader = openKeyholderPlanReader
	}
	if c.openBucketGrants == nil {
		c.openBucketGrants = openBucketGrantsDefault
	}
	if c.interactive == nil {
		c.interactive = isInteractive
	}
}

// isInteractive is whether this run can ask its terminal: the command's
// seam, or isInteractive for a command whose defaults are not set.
func (c *storageDeployCommand) isInteractive(env *Env) bool {
	if c.interactive != nil {
		return c.interactive(env)
	}
	return isInteractive(env)
}

func (*storageDeployCommand) Name() string { return "deploy" }
func (*storageDeployCommand) Synopsis() string {
	return "Deploy the in-cluster keyholder that serves storage to applications"
}

func (*storageDeployCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage deploy <instance> [--datasphered-image REF@sha256:… | --source DIR | --embedded] [-y]
                               [--grant-bucket] [--plan | --confirm <digest>]

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
keyholder's ServiceAccount farcast-system/datasphered, and, with the
installer's key in every mode, the instance's recorded registry, the
project's number, and the bucket's labels and IAM policy. It creates the
bucket and keyring, ensures the registry, pushes and builds only once the
deploy is confirmed. On an instance that records no registry, an
interactive or --yes run ensures it first.

The keyholder reads and writes the bucket under its own cloud identity:
its ServiceAccount, named by the uid the API server gave it, since the
principal its name makes is shared by every FarCast instance in the
project. The deploy applies that ServiceAccount first, reads its uid, and
only then starts the replicas. Without --grant-bucket it prints the
commands that grant the ServiceAccount the bucket, and remove the binding
every instance in the project shares, just before it starts them; on a
first deploy the replicas restart on a 403 until that grant has
propagated, and an unseal fails meanwhile. --grant-bucket applies the
grant instead, in one change of the bucket's IAM policy, before any
replica exists: under --confirm of a plan made with it, or after its own
question in a terminal; never with --yes. The uid on a bucket's policy is
unverified until the M2 walk. One project per instance is still the full
separation: every cluster in a project can present any uid.

--plan prints what the deploy would do, and changes nothing: its cost, the
image and where it comes from, the registry calls and the bucket it would
create, what it mints, the keyholder's ServiceAccount, the bucket grant and
whether it is applied, the key pin it writes, each document it would apply,
and what it would print, with the plan's digest. It reads the pin, the
cluster and the keyholder's ServiceAccount as the instance's reader, which
'farcast reader grant' must have verified read-only (there is no fallback
to the installer's account), and the registry, the project's number and the
bucket's labels and IAM policy with the installer's key; it opens no
writer, and no private key. A keyring behind the pin is a block: the plan
says so, and its --confirm refuses it. So is --grant-bucket where the
stored credential may not read the bucket's IAM policy.

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
	fs.BoolVar(&c.grantBucket, "grant-bucket", false, "apply the keyholder's bucket grant, by its ServiceAccount's uid, under --confirm or this terminal's question (never with --yes)")
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

// The bucket grant's texts (ADR 0023 M2.8, design §33, A33-24 to A33-28).
const (
	// msgGrantBucketYes is --grant-bucket's refusal beside --yes: the
	// instance's name, twice ("<instance>" for one that is not valid).
	msgGrantBucketYes = "--grant-bucket cannot be run with --yes: it changes the IAM policy of instance %q's bucket; " +
		"confirm it in a terminal, or review 'farcast storage deploy %s --plan --grant-bucket' and pass --confirm <digest>"
	// msgGrantBucketTerminal is its refusal with no terminal and no answer.
	msgGrantBucketTerminal = "--grant-bucket needs a terminal to confirm" + consentSuffix
	// msgBucketGrantUnreadable is the block of --grant-bucket where the
	// stored credential may not read the bucket's policy: the bucket.
	msgBucketGrantUnreadable = "the stored credential may not read gs://%s's IAM policy, so --grant-bucket cannot apply the keyholder's grant; " +
		"plan without --grant-bucket and run the printed commands"
	// msgBucketGrantIncapable is its block where the providers cannot read
	// or change a bucket's IAM at all.
	msgBucketGrantIncapable = "the instance's storage provider cannot read or change a bucket's IAM, so --grant-bucket cannot apply the keyholder's grant; " +
		"plan without --grant-bucket and run the printed commands"
	// msgBucketGrantPending is the notice of a grant not applied whose
	// ServiceAccount does not exist yet: the bucket, as bucketShown names it.
	msgBucketGrantPending = "The keyholder's ServiceAccount farcast-system/datasphered does not exist yet: this deploy creates it before the keyholder, " +
		"and then prints the commands that grant it %s by its uid (and that remove the shared binding, when the bucket holds it). " +
		"Until they are run and IAM has propagated (typically 2 minutes, up to 7 or more), the replicas restart on a 403 and an unseal fails. " +
		"--grant-bucket applies the grant before the replicas start."
	// msgBucketGrantNewBucket is the notice of a grant not applied on a first
	// deploy whose ServiceAccount exists already: the bucket's name is drawn
	// only when it is created, so the commands print then.
	msgBucketGrantNewBucket = "The bucket this deploy creates does not exist yet: the deploy prints the commands that grant the keyholder's ServiceAccount " +
		"farcast-system/datasphered read/write access to it by its uid once it does. " +
		"Until they are run and IAM has propagated (typically 2 minutes, up to 7 or more), the replicas restart on a 403 and an unseal fails. " +
		"--grant-bucket applies the grant before the replicas start."
	// msgBucketGrantPresent is the notice of a grant in place: the bucket.
	msgBucketGrantPresent = "gs://%s grants the keyholder's ServiceAccount farcast-system/datasphered, by its uid, roles/storage.objectAdmin and " +
		"roles/storage.legacyBucketReader, and the principal every FarCast instance in the project shares holds neither"
	// msgServiceAccountReplaced begins the refusal of an account whose uid is
	// not the one the plan bound (A33-19): the namespace, the name, the uid
	// read and the one bound; the clause of what was written follows.
	msgServiceAccountReplaced = "the ServiceAccount %s/%s was replaced since the plan was made (its uid is %s, not %s); "
	// msgGrantQuestion is the terminal's question when the grant adds the
	// uid principal: the bucket, the principal, and msgGrantQuestionShared
	// or nothing.
	msgGrantQuestion       = "Grant roles/storage.objectAdmin and roles/storage.legacyBucketReader on %s to %s%s?"
	msgGrantQuestionShared = ", and remove them from %s, which every FarCast instance in project %q shares"
	// msgGrantQuestionRemove is its question when the grant only removes the
	// shared principal: the bucket, the shared principal, the project.
	msgGrantQuestionRemove = "Remove roles/storage.objectAdmin and roles/storage.legacyBucketReader on %s from %s, which every FarCast instance in project %q shares? " +
		"The keyholder's uid already holds both."
	// msgGrantPendingPrincipal names the uid principal in the question
	// before the ServiceAccount exists.
	msgGrantPendingPrincipal = "the keyholder's ServiceAccount farcast-system/datasphered, by the uid it has once this deploy creates it"
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
	// --grant-bucket changes a bucket's IAM policy, so --yes never covers it,
	// and it needs --plan, --confirm or this terminal's own question: refused
	// otherwise, before anything is read (A33-2, A33-24).
	if c.grantBucket {
		switch {
		case c.deployer.assumeYes:
			shown := name
			if validateInstanceName(name) != nil {
				shown = "<instance>"
			}
			return usagef(msgGrantBucketYes, shown, shown)
		case mode == consentNone && !c.isInteractive(env):
			return usagef(msgGrantBucketTerminal)
		}
	}
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
	var rd keyholderPlanReader
	if mode == consentNone {
		ref.Identity = kube.Writer
		if cl, err = c.deployer.newCluster(ref); err != nil {
			return fmt.Errorf("the key pin could not be reached, so nothing was deployed: %w", err)
		}
		defer afterWrites(env, name, cl)
		if ps, err = c.pinStoreOf(ref, cl); err != nil {
			return fmt.Errorf("the key pin could not be reached, so nothing was deployed: %w", err)
		}
		rd = keyholderReader{ps, cl}
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
	ensure := mode == consentNone && (c.deployer.assumeYes || c.isInteractive(env))
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
// after the comparison and the writer's checks (A23-43, A33-26), in this
// order in every mode:
//
//  1. the bucket and the keyring, minted and then read back;
//  2. the Namespace and the keyholder's ServiceAccount, applied (2a); the
//     account's uid, read as the writer (2b); and the bucket grant's
//     printed lines, rendered and checked with the real bucket and uid (2c);
//  3. under --grant-bucket, the one policy write that grants the uid
//     principal and removes the shared one (3b), before the image pushes,
//     so IAM propagates meanwhile, and before any replica exists;
//  4. the registry ensure and the image the plan decided, pushed or built
//     and never looked up again; the keyholder's server leaf, issued from
//     the instance's CA; the pin, before the replicas exist; the record;
//  5. the grant's lines, when it is not applied; and the rest of the
//     stream, each document applied once.
//
// Every refusal from 2a on says what was written before it (writtenSoFar).
func (c *storageDeployCommand) deploy(ctx context.Context, env *Env, meta *config.InstanceMetadata, cl clusterApplier, ps pinStore,
	p preparedStorageDeploy, m consentMode) error {
	name := meta.Name
	var written []string
	// refused is a refusal from 2a on, with the clause of what was written;
	// stopped is an apply's own failure, whose stream may be part-applied.
	refused := func(err error) error { return withWritten(err, writtenSoFar(written, false)) }
	stopped := func(err error) error { return withWritten(err, writtenSoFar(written, true)) }

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
		written = append(written, "the bucket and the keyring were ensured")
	}
	bucket := meta.Storage.Bucket

	// 2a. The Namespace and the keyholder's ServiceAccount, before anything
	// else of the keyholder: the grant names the account by its uid, which
	// exists only once the account does, and neither document creates a pod
	// (A33-26).
	account, err := dsdeploy.RenderAccount(keyholderConfig(meta, "", bucket, meta.Storage.Provider, meta.Storage.Location, nil, nil, nil))
	if err != nil {
		return refused(err)
	}
	if err := cl.Apply(ctx, account); err != nil {
		return stopped(fmt.Errorf("apply the keyholder's ServiceAccount: %w", err))
	}
	written = append(written, "the keyholder's ServiceAccount "+keyholderAccount+" was applied")

	// 2b. Its uid, as the writer: a plan that bound one requires it still,
	// and one that bound the placeholder adopts it (A33-19).
	uid, err := readServiceAccountUID(ctx, cl, consentNone, name, tcdeploy.DefaultNamespace, dsdeploy.DefaultName, plan.GrantBucket)
	switch {
	case err != nil:
		return refused(err)
	case uid == "":
		return refused(fmt.Errorf("the ServiceAccount %s was applied and then not found", keyholderAccount))
	case !p.grant.pending() && uid != p.grant.uid:
		return changedAfterPlan(m, fmt.Sprintf(msgServiceAccountReplaced, tcdeploy.DefaultNamespace, dsdeploy.DefaultName, uid, p.grant.uid)+
			writtenSoFar(written, false))
	}

	// 2c. What this deploy prints of the grant, rendered now, with the real
	// bucket and uid and every value checked (A33-15): the commands of a
	// grant not applied, or the line of one in place; and under
	// --grant-bucket the commands printed when the policy write is refused.
	// A refusal here comes before the policy write, the pin and the record.
	grantText, err := p.grant.printed(bucket, uid)
	if err != nil {
		return refused(err)
	}

	// 3b. The grant, under --grant-bucket's consent: one policy write that
	// adds the uid principal to both roles and removes the shared one, its
	// labels proved first. The replicas do not exist yet.
	result := bucketGrantPrinted
	if p.grant.fact.State == plan.GrantPresent && p.grant.fact.Shared == plan.GrantMissing {
		result = bucketGrantPresent
	}
	if p.grant.writes() {
		changed, err := c.applyBucketGrant(ctx, env, meta, p.grant, bucket, uid, grantText, written, m)
		if err != nil {
			return err
		}
		// changed is a write sent that may have made the change, so the
		// shared principal's removal is never left out of a later
		// refusal's clause (A33-26); unchanged is a grant found done before
		// any write.
		result = bucketGrantPresent
		if changed {
			result = bucketGrantApplied
			written = append(written, fmt.Sprintf("gs://%s's IAM policy now grants the keyholder's uid principal %s and %s and no longer grants the shared principal",
				bucket, bucketRoles[0], bucketRoles[1]))
		}
	}

	// The registry ensure the plan bound, then the image the plan decided
	// (A23-34).
	reg, err := c.deployer.realizeRegistry(ctx, env, name, meta, p.reg, m)
	if err != nil {
		return refused(err)
	}
	written = append(written, "the instance's registry was ensured and recorded")
	resolved, err := c.deployer.realizeAndNote(ctx, env, reg, p.image)
	if err != nil {
		return refused(err)
	}
	if p.image.pushes() {
		written = append(written, "the keyholder's image was pushed to the instance's registry")
	}
	img := resolved.Ref

	mtls, err := realizeIdentity(env, name, p.identity, m)
	if err != nil {
		return refused(err)
	}
	// The keyholder gets its OWN server leaf, distinct from FatLine's, so the
	// operator's session verifies that it is talking to the keyholder and not
	// to the tunnel that carried it. The CA private key never leaves here.
	certPEM, keyPEM, err := identity.IssueKeyholderServer(mtls.CACertPEM, mtls.CAKeyPEM, name)
	if err != nil {
		return refused(fmt.Errorf("issue the keyholder's server identity: %w", err))
	}
	workload, err := dsdeploy.RenderWorkload(keyholderConfig(meta, img, bucket, meta.Storage.Provider, meta.Storage.Location,
		mtls.CACertPEM, certPEM, keyPEM))
	if err != nil {
		return refused(err)
	}

	// Before the replicas exist, and always: TechnoCore may create ConfigMaps
	// in this namespace, so the pin is this machine's only if this machine
	// created it. No apply touches it afterwards — an apply is
	// last-writer-wins, and could move it backwards. Under --confirm the
	// plan's pin is written once, at the version the plan read (A23-42).
	var pinned pinWrite
	if m == consentConfirm {
		if pinned, err = pinOnce(ctx, ps, p.pin); err != nil {
			if kindOf(err) == kindPlanChanged {
				return refused(err)
			}
			return refused(fmt.Errorf(msgDeployPinUnwritten, err, pinRemedy(name)))
		}
	} else if pinned, err = pinOnDeploy(ctx, ps, env, name); err != nil {
		var behind *pinBehind
		if errors.As(err, &behind) {
			return refused(fmt.Errorf("%v; nothing was deployed", behind))
		}
		return refused(fmt.Errorf(msgDeployPinUnwritten, err, pinRemedy(name)))
	}
	if pinned.Changed {
		written = append(written, "the key pin was written")
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
		return refused(fmt.Errorf("record the keyholder before deploying it: %w", err))
	}
	written = append(written, "the keyholder was recorded as deployed")

	// Before the workload exists, not after: a replica that starts without
	// this grant crash-loops, and an operator reading the fix underneath a
	// deploy that has already failed is the wrong order. On stderr so it
	// survives --output json, where the human result is never rendered. It
	// names the bucket as it exists now, a first deploy's included, and the
	// ServiceAccount by the uid read at 2b. A grant applied prints nothing.
	if !p.grant.writes() {
		fprintf(env.Err, "%s", grantText)
	}

	if c.isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Deploying the keyholder to %q…\n", name)
	}
	if err := cl.Apply(ctx, workload); err != nil {
		return stopped(fmt.Errorf("deploy the keyholder: %w", err))
	}

	// Deliberately NO rollout wait. Every replica comes up sealed and a sealed
	// replica never becomes Ready, so waiting for readiness here would block
	// until it timed out — on the happy path — and teach the operator to
	// interrupt the tool. The next step is the unseal, and it is said plainly.
	return env.Printer.Print(deployResult{
		Instance: name, Image: img, Replicas: keyholderReplicas,
		Project: meta.Project, Bucket: bucket,
		Namespace: dsdeploy.DefaultNamespace, ServiceAccount: dsdeploy.DefaultName,
		BucketGrant: result, firstDeploy: p.mintsStorage,
	})
}

// applyBucketGrant is step 3b (A33-26, A33-27): the instance's bucket IAM,
// opened with the installer's key, and the one policy write that grants the
// keyholder's uid principal both roles and removes the shared principal from
// them, each proved against the bucket's labels first. It reports whether a
// write was sent and the policy then held the grant, which may be another
// writer's change after a stale refusal (A35-2;
// datasphere.BucketGrants.EnsureGrant). Its refusals say what was written
// before them, and every one after a policy read prints the commands (text)
// first but a policy that changed under both writes, plan_changed under
// --confirm: a write that may have landed unseen says so, and its clause
// names the write sent; a Google 403 names the bucket, never the cluster;
// any other refusal of the write leaves the policy unchanged; and a failure
// before any write was sent says that none was.
func (c *storageDeployCommand) applyBucketGrant(ctx context.Context, env *Env, meta *config.InstanceMetadata, g bucketGrant,
	bucket, uid, text string, written []string, m consentMode) (bool, error) {
	clause := writtenSoFar(written, false)
	member, err := workloadUIDPrincipal(g.number, g.project, uid)
	if err != nil {
		return false, withWritten(err, clause)
	}
	grants, err := c.openBucketGrants(ctx, env, meta)
	if err != nil {
		return false, withWritten(err, clause)
	}
	changed, err := grants.Ensure(ctx, bucket, bucketRoles, member, g.fact.SharedPrincipal)
	switch {
	case err == nil:
		return changed, nil
	case errors.Is(err, storage.ErrBucketUnproven):
		return false, withKind(kindInternal, fmt.Errorf("%w; %s", err, clause))
	case errors.Is(err, datasphere.ErrPolicyChanged):
		return false, changedAfterPlan(m, fmt.Sprintf("gs://%s's IAM policy changed while the grant was written; %s", bucket, clause))
	}
	fprintf(env.Err, "%s", text)
	switch {
	case errors.Is(err, datasphere.ErrPolicyUnconfirmed):
		// Sent, and no answer settles it, a refusal after an attempt that
		// failed in transport, failed reading its body, or got a 5xx
		// included, or followed by a read that failed, or by a read it
		// would write from that came without an etag or held a policy it
		// could not build: it may have landed, the shared principal's
		// removal included, so it is never said to be unchanged, and the
		// clause names the write sent. Checked first: what failed after it
		// may be a 403.
		sent := writtenSoFar(append(slices.Clone(written), "a write of gs://"+bucket+"'s IAM policy was sent"), false)
		return false, withKind(kindInternal, fmt.Errorf("whether gs://%s's new IAM policy took effect is not known (%w); "+
			"'farcast storage deploy %s --plan' reads it, and the printed commands finish the grant if it did not; %s", bucket, err, meta.Name, sent))
	case errors.Is(err, datasphere.ErrPermissionDenied):
		return false, withKind(kindForbidden, fmt.Errorf("the stored credential may not change gs://%s's IAM policy (%w); run the printed commands instead; %s",
			bucket, err, clause))
	case errors.Is(err, datasphere.ErrPolicyRejected):
		return false, withKind(kindInternal, fmt.Errorf("Google refused the new IAM policy of gs://%s (%w); its policy is unchanged; run the printed commands, or report it; %s",
			bucket, err, clause))
	}
	// No write was sent: the read failed, or farcast would not write what
	// it read.
	return false, withKind(kindInternal, fmt.Errorf("the grant on gs://%s was not written (%w); its policy is unchanged; run the printed commands, or report it; %s",
		bucket, err, clause))
}

// writtenSoFar is the clause a refusal of deploy from step 2a on ends with
// (A33-26): what was written, in the order it was, joined, then ", and
// nothing else was written", or, for an apply's own failure, whose stream may
// be part-applied (design D3), ", and the stream stopped at its first
// failing document".
func writtenSoFar(written []string, stopped bool) string {
	end := "nothing else was written"
	if stopped {
		end = "the stream stopped at its first failing document"
	}
	switch len(written) {
	case 0:
		if stopped {
			return end
		}
		return "nothing was written"
	case 1:
		return written[0] + ", and " + end
	}
	return strings.Join(written, ", ") + ", and " + end
}

// withWritten is err with clause, the one writtenSoFar made: before the
// closing "run the same command with --plan…" of a plan_changed refusal,
// and at its end otherwise. err's kind and chain are kept, so whose refusal
// it was is still found.
func withWritten(err error, clause string) error {
	msg := err.Error()
	if base, ok := strings.CutSuffix(msg, "; "+msgPlanAgain); ok {
		msg = base + "; " + clause + "; " + msgPlanAgain
	} else {
		msg += "; " + clause
	}
	return &writtenError{msg: msg, err: err}
}

// writtenError is an error with what was written before it.
type writtenError struct {
	msg string
	err error
}

func (e *writtenError) Error() string { return e.msg }
func (e *writtenError) Unwrap() error { return e.err }

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
	// grant is the keyholder's bucket grant as the plan read it (A33-25).
	grant bucketGrant
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

// plan is storage deploy's plan (design §9.4, A23-43, A33-25). It reads the
// key pin, then farcast-system's uid, which it binds as its target, through
// rd — the reader under --plan and --confirm, its errors the reader's
// (planRead), and in an interactive or --yes run the writer's pin store and
// the writer — and the keyring's key ids. It decides the pin the deploy
// writes (decidePin, or the empty pin with no keyring here): a keyring
// behind the pin blocks it, as does a pin that refuses the keyring itself or
// that no replica could read, and nothing more is read, Google included
// (A23-18). Otherwise it checks the record's project and bucket, reads the
// keyholder's ServiceAccount through rd (its uid, or the placeholder when it
// does not exist), checks the instance's mTLS material, reading the CA
// certificate alone (decideIdentity), reads the registry the record names
// with the installer's key (deployRegistry), decides the keyholder's image
// (decideImage), and reads the bucket grant with the installer's key
// (readBucketGrant): the project's number and, with a bucket recorded, the
// bucket's labels and IAM policy. --grant-bucket where that policy cannot be
// read, or where the providers cannot change it, is a block.
//
// Its facts are, in the order the command writes: the cost; the image; the
// registry's cloud facts, and the bucket a first deploy creates; the mints,
// the keyholder's leaf and a first keyring; a restart of the replicas a
// deployed keyholder runs; the Namespace's and the ServiceAccount's writes;
// the grant, and its policy write when --grant-bucket writes one; the pin
// and its write; each other document of the workload it would apply,
// rendered over the image it names, the placeholder leaf and, on a first
// deploy, the placeholder bucket; and its notices, the bucket grant's among
// them.
//
// With ensure (an interactive or --yes run, decided by the caller) a record
// that names no registry is first given one (A23-24's exception), after the
// pin, the uid, the blocks and the mTLS check. It reads no terminal and, but
// for that ensure, writes nothing.
func (c *storageDeployCommand) plan(ctx context.Context, env *Env, meta *config.InstanceMetadata, rd keyholderPlanReader, m consentMode, ensure bool) (preparedStorageDeploy, plan.Bound, error) {
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
	b.Options = sortedOptions(append(c.deployer.imageOptions(), plan.Option{Flag: "grant-bucket", Value: strconv.FormatBool(c.grantBucket)}))

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

	// The record's values the bucket grant's commands print, checked before
	// anything is read for them (A33-15): the project, and a recorded bucket.
	if !projectIDShape.MatchString(meta.Project) {
		return p, plan.Bound{}, withKind(kindInternal, fmt.Errorf(msgUnsafeRecord, name, "project ID", meta.Project))
	}
	if !p.mintsStorage && !bucketNameShape.MatchString(meta.Storage.Bucket) {
		return p, plan.Bound{}, withKind(kindInternal, fmt.Errorf(msgUnsafeRecord, name, "storage bucket", meta.Storage.Bucket))
	}
	// The keyholder's ServiceAccount, before any Google read (A33-25 step 1):
	// its uid, which the grant names, or "" when this deploy creates it.
	accountUID, err := readServiceAccountUID(ctx, rd, m, name, tcdeploy.DefaultNamespace, dsdeploy.DefaultName, plan.GrantBucket)
	if err != nil {
		return p, plan.Bound{}, err
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

	if p.grant, err = c.readBucketGrant(ctx, env, meta, p, accountUID); err != nil {
		return p, plan.Bound{}, err
	}
	if p.grant.fact.Apply {
		switch {
		case !p.grant.capable:
			b.Blocked = []plan.Block{blockOf(withKind(kindInternal, errors.New(msgBucketGrantIncapable)))}
			return p, b, nil
		case p.grant.fact.State == plan.GrantUnknown || p.grant.fact.Shared == plan.GrantUnknown:
			b.Blocked = []plan.Block{blockOf(withKind(kindForbidden, fmt.Errorf(msgBucketGrantUnreadable, p.bucket)))}
			return p, b, nil
		}
	}

	cfg := keyholderConfig(meta, p.image.planTarget(), p.bucket, p.provider, p.location,
		p.identity.caCertPEM, keyholderLeafPlaceholder(name, "cert"), keyholderLeafPlaceholder(name, "key"))
	account, err := dsdeploy.RenderAccount(cfg)
	if err != nil {
		return p, plan.Bound{}, err
	}
	workload, err := dsdeploy.RenderWorkload(cfg)
	if err != nil {
		return p, plan.Bound{}, err
	}
	accountWrites, err := applyFacts(account)
	if err != nil {
		return p, plan.Bound{}, err
	}
	workloadWrites, err := applyFacts(workload)
	if err != nil {
		return p, plan.Bound{}, err
	}
	pins, err := pinFacts(p.pin, nil)
	if err != nil {
		return p, plan.Bound{}, err
	}
	notice, err := p.grant.notice(p.bucket, p.mintsStorage)
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
	facts = append(facts, accountWrites...)
	facts = append(facts, p.grant.fact)
	if p.grant.writes() {
		facts = append(facts, plan.CloudFact{Type: plan.TypeCloud, Service: plan.CloudStorage, Action: plan.CloudSetBucketGrant, Target: p.grant.fact.Target})
	}
	facts = append(facts, pins...)
	facts = append(facts, workloadWrites...)
	if notice != "" {
		facts = append(facts, noticeFact(notice))
	}
	for _, line := range p.image.said() {
		facts = append(facts, noticeFact(line))
	}
	b.Facts = append(facts, sourceNotices(p.image)...)
	return p, b, nil
}

// readBucketGrant is the plan's read of the keyholder's bucket grant
// (A33-25 steps 3 to 5), as the installer's key, in every mode. uid is
// datasphered's as the plan read it, "" when the account does not exist and
// the grant names the uid placeholder (A33-19).
//
// Without planck.GrantReader the project's number is not known: both
// principals are "", both states unknown, and nothing is read (MS-6).
// Otherwise it reads the number, makes the two principals (A33-10), and:
//   - on a first deploy, reads no policy, the bucket not existing: both
//     states are missing; with --grant-bucket it opens the bucket IAM, which
//     sends nothing, only to know that it can be changed;
//   - with a bucket recorded, opens the bucket IAM and reads its policy
//     once, the bucket's labels proved first, whether or not the account
//     exists, so the shared principal is known. With the placeholder no
//     binding can hold the principal, and its state is missing: the match
//     is local, and nothing about the placeholder is sent. A provider
//     without bucket IAM is unknown for both, with no read; a 403 is
//     unknown for both.
func (c *storageDeployCommand) readBucketGrant(ctx context.Context, env *Env, meta *config.InstanceMetadata, p preparedStorageDeploy, uid string) (bucketGrant, error) {
	g := bucketGrant{
		instance: meta.Name, project: meta.Project, uid: uid,
		fact: plan.GrantFact{
			Type: plan.TypeGrant, Name: plan.GrantBucket, Target: "gs://" + p.bucket, ServiceAccount: keyholderAccount,
			Roles: slices.Clone(bucketRoles), State: plan.GrantUnknown, Shared: plan.GrantUnknown, Apply: c.grantBucket,
		},
	}
	reader, ok := p.reg.provider.(planck.GrantReader)
	if !ok {
		return g, nil
	}
	number, err := reader.ProjectNumber(ctx)
	if err != nil {
		return bucketGrant{}, fmt.Errorf("read the number of project %q with instance %q's installer key: %w", meta.Project, meta.Name, err)
	}
	g.number = number
	principalUID := uid
	if g.pending() {
		principalUID = saUIDPlaceholder(tcdeploy.DefaultNamespace, dsdeploy.DefaultName)
	}
	if g.fact.Principal, err = workloadUIDPrincipal(number, meta.Project, principalUID); err != nil {
		return bucketGrant{}, err
	}
	if g.fact.SharedPrincipal, err = workloadNamePrincipal(number, meta.Project, tcdeploy.DefaultNamespace, dsdeploy.DefaultName); err != nil {
		return bucketGrant{}, err
	}
	if p.mintsStorage {
		g.fact.State, g.fact.Shared, g.capable = plan.GrantMissing, plan.GrantMissing, true
		if !g.fact.Apply {
			return g, nil
		}
		if _, err := c.openBucketGrants(ctx, env, meta); err != nil {
			if errors.Is(err, storage.ErrNoBucketGrants) {
				g.capable = false
				return g, nil
			}
			return bucketGrant{}, err
		}
		return g, nil
	}
	grants, err := c.openBucketGrants(ctx, env, meta)
	switch {
	case errors.Is(err, storage.ErrNoBucketGrants):
		return g, nil
	case err != nil:
		return bucketGrant{}, err
	}
	g.capable = true
	state, shared, sharedRoles, err := grants.State(ctx, p.bucket, bucketRoles, g.fact.Principal, g.fact.SharedPrincipal)
	switch {
	case errors.Is(err, storage.ErrBucketUnproven):
		return bucketGrant{}, err
	case err != nil:
		return bucketGrant{}, fmt.Errorf("read the IAM policy of gs://%s with instance %q's installer key: %w", p.bucket, meta.Name, err)
	}
	g.fact.State, g.fact.Shared, g.sharedRoles = string(state), string(shared), sharedRoles
	if g.pending() && state != datasphere.GrantUnknown {
		// A principal no account holds yet: no binding can grant it.
		g.fact.State = plan.GrantMissing
	}
	return g, nil
}

// consented is an interactive or --yes run's consent to its plan: the cost,
// asked from the plan's cost fact, then the build question when the image is
// built from source, then, when --grant-bucket writes the bucket's policy,
// its own question (A33-24). A version skew was refused before any of them
// (imageDecision.say). A declined cost or grant is no error, as a declined
// cost never was; a declined build is.
func (c *storageDeployCommand) consented(env *Env, meta *config.InstanceMetadata, p preparedStorageDeploy) (bool, error) {
	ok, err := c.confirmCost(env, meta, p.cost)
	if err != nil {
		return false, err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return false, nil
	}
	if err := c.deployer.buildConsent(env, p.image); err != nil {
		return false, err
	}
	if !p.grant.writes() {
		return true, nil
	}
	ok, err = newPrompter(env.In, env.Err).yesNo(p.grant.question(p.mintsStorage))
	if err != nil {
		return false, err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
	}
	return ok, nil
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
	if !c.isInteractive(env) {
		return false, usagef(msgKeyholderCostYes, amount(f.Standing[0].MonthCents), f.Standing[0].Replicas)
	}
	fprintln(env.Err, keyholderCostQuestion(meta.Name, f))
	return newPrompter(env.In, env.Err).yesNo("Deploy it?")
}

// What a deploy reports of the bucket grant (A33-28).
const (
	// bucketGrantApplied: a policy write was sent and the policy holds the
	// grant: the write landed, or a read after one refused as stale found
	// it done, which may be that write's, landed with its answer lost
	// (datasphere.BucketGrants.EnsureGrant).
	bucketGrantApplied = "applied"
	// bucketGrantPresent: the grant was in place and the shared principal
	// gone, so nothing was written.
	bucketGrantPresent = "present"
	// bucketGrantPrinted: the commands were printed, for a human to run.
	bucketGrantPrinted = "printed"
)

type deployResult struct {
	Instance       string `json:"instance"`
	Image          string `json:"image"`
	Replicas       int    `json:"replicas"`
	Project        string `json:"project,omitempty"`
	Bucket         string `json:"bucket,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	// BucketGrant is bucketGrantApplied, bucketGrantPresent or
	// bucketGrantPrinted.
	BucketGrant string `json:"bucket_grant"`
	// firstDeploy says the deploy created the bucket.
	firstDeploy bool
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

	// The grant itself was printed BEFORE the replicas were started — see
	// writeBucketGrant — and only when it was not applied. All that belongs
	// here is the reminder that it has to be in place before the unseal
	// above will work, and on a first deploy what the replicas do until it
	// is (A33-28, OQ-D).
	if r.BucketGrant == bucketGrantPrinted {
		fprintf(w, "\nThe bucket grant printed above has to be in place first. Without it the\n")
		fprintf(w, "replicas crash-loop on a 403 at start-up and the unseal fails.\n")
		if r.firstDeploy {
			fprintf(w, "This first deploy's replicas restart until the grant has propagated (typically\n")
			fprintf(w, "2 minutes, up to 7 or more); --grant-bucket grants it before they start.\n")
		}
	}
	return nil
}

// The keyholder's bucket grant (ADR 0023 M2.8, design §33, A33-4, A33-15,
// A33-25): the two roles, on the bucket alone, for the keyholder's
// ServiceAccount, named by its uid.
var bucketRoles = []string{"roles/storage.objectAdmin", "roles/storage.legacyBucketReader"}

// keyholderAccount is the keyholder's ServiceAccount as a grant fact and the
// texts name it.
const keyholderAccount = tcdeploy.DefaultNamespace + "/" + dsdeploy.DefaultName

// bucketNameShape is the shape of the bucket names farcast mints
// (datasphere.MintBucketName), the only ones a printed command takes
// (A33-15).
var bucketNameShape = regexp.MustCompile(`^farcast-[a-z0-9-]{1,55}$`)

// bucketGrant is the keyholder's bucket grant as storage deploy's plan read
// it (A33-25): the fact the plan binds, and what its printed commands and
// its policy write are made from.
type bucketGrant struct {
	fact plan.GrantFact
	// instance and project are the record's, the project checked; number is
	// the project's, 0 when the provider states none.
	instance, project string
	number            int64
	// uid is datasphered's uid as the plan read it, "" when the account did
	// not exist and the plan bound the uid placeholder (A33-19).
	uid string
	// sharedRoles are the roles whose binding with no condition held the
	// shared principal when the plan read the policy: the printed remove
	// lines' roles (A33-11, A33-15).
	sharedRoles []string
	// capable says the providers can read and change a bucket's IAM: the
	// compute provider states the project's number, and the storage provider
	// has bucket IAM (or, on a first deploy without --grant-bucket, was not
	// asked).
	capable bool
}

// pending reports whether the plan bound the uid placeholder: the account
// did not exist when the plan read it.
func (g bucketGrant) pending() bool { return g.uid == "" }

// writes reports whether the deploy writes the bucket's policy: under
// --grant-bucket, when the uid principal lacks a role or the shared one
// still holds one (A33-25).
func (g bucketGrant) writes() bool {
	return g.fact.Apply && (g.fact.State != plan.GrantPresent || g.fact.Shared == plan.GrantPresent)
}

// done reports whether the grant is in place and the shared principal gone.
func (g bucketGrant) done() bool {
	return g.fact.State == plan.GrantPresent && g.fact.Shared == plan.GrantMissing
}

// bucketShown names the bucket in a question or a notice: gs://<bucket>, or,
// on a first deploy, the one the deploy creates.
func bucketShown(bucket string, first bool) string {
	if first {
		return "the bucket this deploy creates"
	}
	return "gs://" + bucket
}

// notice is the plan's notice of the grant (A23-26, A33-25), "" when none is
// due: none when --grant-bucket writes the policy, the cloud fact stating
// it; the present line when the grant is in place and the shared principal
// gone, applied or not; while the ServiceAccount does not exist, or on a
// first deploy, which names no bucket yet, that the commands print once
// they can be made; and otherwise the printed commands, then, unless the
// policy could not be read, that a plan made before the grant cannot be
// confirmed after it.
func (g bucketGrant) notice(bucket string, first bool) (string, error) {
	switch {
	case g.writes():
		return "", nil
	case g.done():
		return fmt.Sprintf(msgBucketGrantPresent, bucket), nil
	case g.pending():
		return fmt.Sprintf(msgBucketGrantPending, bucketShown(bucket, first)), nil
	case first:
		return msgBucketGrantNewBucket, nil
	}
	l, err := g.lines(bucket, g.uid)
	if err != nil {
		return "", err
	}
	text := bucketGrantText(l)
	if g.fact.State != plan.GrantUnknown {
		text += "\n" + msgPlanBeforeGrant
	}
	return text, nil
}

// printed is what a deploy prints of the grant (A33-26, step 2c), rendered
// before the policy write with the real bucket and the uid read at 2b,
// every value checked: the present line when the grant is in place and the
// shared principal gone; otherwise the commands, which a grant not applied
// prints before the replicas start and a refused policy write prints before
// its refusal.
func (g bucketGrant) printed(bucket, uid string) (string, error) {
	if g.done() {
		return fmt.Sprintf(msgBucketGrantPresent, bucket) + "\n", nil
	}
	l, err := g.lines(bucket, uid)
	if err != nil {
		return "", err
	}
	var w strings.Builder
	writeBucketGrant(&w, l)
	return w.String(), nil
}

// question is the terminal's question before --grant-bucket writes the
// policy (A33-24): the bucket, the uid principal (or the account, before it
// exists) and, when the bucket still grants it, the shared principal it
// removes; or, when the uid principal holds both roles already, the removal
// alone.
func (g bucketGrant) question(first bool) string {
	bucket := bucketShown(strings.TrimPrefix(g.fact.Target, "gs://"), first)
	if g.fact.State == plan.GrantPresent {
		return fmt.Sprintf(msgGrantQuestionRemove, bucket, g.fact.SharedPrincipal, g.project)
	}
	principal := g.fact.Principal
	if g.pending() {
		principal = msgGrantPendingPrincipal
	}
	shared := ""
	if g.fact.Shared == plan.GrantPresent {
		shared = fmt.Sprintf(msgGrantQuestionShared, g.fact.SharedPrincipal, g.project)
	}
	return fmt.Sprintf(msgGrantQuestion, bucket, principal, shared)
}

// lines are what writeBucketGrant prints for bucket and the account whose
// uid is uid, with the plan's states, every value checked (A33-15): the
// project and the bucket against their shapes, refused in msgUnsafeRecord's
// words, and the uid, which must be the API server's, A33-10's refusal
// otherwise; each kind internal, and nothing printed.
func (g bucketGrant) lines(bucket, uid string) (bucketGrantLines, error) {
	if !projectIDShape.MatchString(g.project) {
		return bucketGrantLines{}, withKind(kindInternal, fmt.Errorf(msgUnsafeRecord, g.instance, "project ID", g.project))
	}
	if !bucketNameShape.MatchString(bucket) {
		return bucketGrantLines{}, withKind(kindInternal, fmt.Errorf(msgUnsafeRecord, g.instance, "storage bucket", bucket))
	}
	if !serviceAccountUIDShape.MatchString(uid) {
		return bucketGrantLines{}, withKind(kindInternal, errors.New(msgUnsafeGrantUID))
	}
	number, quote := g.number, "'"
	if number == 0 {
		// No number is known: the commands read it into PROJNUM, and name
		// the principals with it, double-quoted.
		number, quote = 1, `"`
	}
	member, err := workloadUIDPrincipal(number, g.project, uid)
	if err != nil {
		return bucketGrantLines{}, err
	}
	shared, err := workloadNamePrincipal(number, g.project, tcdeploy.DefaultNamespace, dsdeploy.DefaultName)
	if err != nil {
		return bucketGrantLines{}, err
	}
	if g.number == 0 {
		member, shared = projnumPrincipal(member), projnumPrincipal(shared)
	}
	return bucketGrantLines{
		bucket: bucket, project: g.project, projnum: g.number == 0,
		member: quote + member + quote, sharedMember: quote + shared + quote,
		state: g.fact.State, shared: g.fact.Shared, sharedRoles: slices.Clone(g.sharedRoles),
	}, nil
}

// bucketGrantLines is what writeBucketGrant prints (A33-15), every value
// checked before it was made (bucketGrant.lines): the bucket and the
// project, single-quoted when printed; member and sharedMember, the uid
// principal and the shared one, already quoted; projnum when no project
// number is known; the plan's two states; and the roles that hold the shared
// principal.
type bucketGrantLines struct {
	bucket, project      string
	member, sharedMember string
	projnum              bool
	state, shared        string
	sharedRoles          []string
}

// writeBucketGrant prints the commands that grant the keyholder's
// ServiceAccount, by its uid, read/write access to its bucket, and that
// remove the binding every FarCast instance in the project shares, for a
// human to run in Cloud Shell before the keyholder runs.
//
// The keyholder reads and writes the bucket with a cloud-side identity (ADR
// 0008 decision 8). Since ADR 0023 M2.8 FarCast applies the grant itself
// under --grant-bucket's consent (a plan where a reader is granted, or a
// terminal's question), in one policy write; otherwise these commands are
// printed. Both name the ServiceAccount by its uid: the principal a name
// makes is shared by every instance in the project's Workload Identity pool.
// The uid principal on a bucket's policy is unverified until the M2 walk.
//
// It is printed BEFORE the workload is applied. It used to be printed after,
// as part of the result — so the replicas were already crash-looping on a 403
// by the time the operator read how to prevent it, and the instance looked
// broken. That happened twice, on the Phase 3.2 and Phase 4.4 walks, and the
// second time cost a failed unseal as well (which is why unseal no longer
// consumes a generation when every push fails).
//
// Each command is one line, with no backslash continuation, so a paste runs
// each alone, and every value in it is single-quoted, or, with no project
// number known, double-quoted around ${PROJNUM}, which the first command
// sets. The adds come before the removes, so a running keyholder is never
// cut off, and a remove names only a role that holds the shared principal,
// since gcloud fails one that does not. With the state unknown both blocks
// print, each introduced by its condition, the removes for both roles.
func writeBucketGrant(w io.Writer, g bucketGrantLines) {
	binding := func(verb, member, role string) string {
		return fmt.Sprintf("  gcloud storage buckets %s-iam-policy-binding 'gs://%s' --member %s --role '%s' --condition=None", verb, g.bucket, member, role)
	}
	unknown := g.state == plan.GrantUnknown
	adds := g.state != plan.GrantPresent
	fprintln(w)
	if adds {
		fprintln(w, "Before this keyholder can start, its ServiceAccount farcast-system/datasphered needs read/write access to the bucket, "+
			"granted to it by its uid. In Cloud Shell, run:")
	}
	if g.projnum {
		fprintf(w, "  PROJNUM=$(gcloud projects describe '%s' --format='value(projectNumber)')\n", g.project)
	}
	add := func() {
		for _, role := range bucketRoles {
			fprintln(w, binding("add", g.member, role))
		}
	}
	remove := func(roles []string) {
		for _, role := range roles {
			fprintln(w, binding("remove", g.sharedMember, role))
		}
	}
	switch {
	case unknown:
		fprintf(w, "If gs://%s does not grant it yet:\n", g.bucket)
		add()
		fprintf(w, "If it still grants the principal every FarCast instance in project '%s' shares, wait for IAM, then:\n", g.project)
		remove(bucketRoles)
	default:
		if adds {
			add()
		}
		if g.shared != plan.GrantPresent {
			break
		}
		if adds {
			fprintf(w, "Then wait for IAM (typically 2 minutes, up to 7 or more), and remove the binding every FarCast instance in project '%s' shares:\n", g.project)
		} else {
			fprintf(w, "Remove the binding every FarCast instance in project '%s' shares:\n", g.project)
		}
		remove(g.sharedRoles)
	}
	if adds {
		fprintln(w, "The grant is on the BUCKET, not the project, and object access is")
		fprintln(w, "separated from bucket reads so the keyholder cannot delete its own bucket.")
	}
	fprintln(w)
}

// bucketGrantText is writeBucketGrant's lines as a plan's notice carries
// them, without the blank lines around them (A27-10).
func bucketGrantText(g bucketGrantLines) string {
	var w strings.Builder
	writeBucketGrant(&w, g)
	return strings.Trim(w.String(), "\n")
}
