package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// readerVerifier is what 'reader grant' needs of a client opened as the
// reader: one read, and the reviews that prove it cannot write (design §0,
// M2.3's seams).
type readerVerifier interface {
	NamespacesLabelled(ctx context.Context, selector string) ([]string, error)
	CanI(ctx context.Context, a kube.ResourceAttributes) (bool, error)
}

// The verifying read's selector: the namespaces farcast manages, the same
// list world reads.
const readerGrantSelector = "app.kubernetes.io/managed-by=farcast"

// How long 'reader grant' waits for the reader's first read to be allowed.
// Google gives IAM changes "typically 2 minutes, potentially 7 minutes or
// longer"; the read is retried on a 401 or a 403 after 5, 10, 20 and 40
// seconds, then every 60, until 8 minutes have passed.
const (
	readerPropagation   = 8 * time.Minute
	readerSteadyBackoff = 60 * time.Second
)

var readerBackoff = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second}

// readerBackoffAt is the wait after the attempt numbered attempt, from 0.
func readerBackoffAt(attempt int) time.Duration {
	if attempt < len(readerBackoff) {
		return readerBackoff[attempt]
	}
	return readerSteadyBackoff
}

// The texts design §7.2 pins for 'reader grant'.
const (
	msgReaderGrantPrompt = "Grant %s, which the Cloud Shell script gave roles/container.clusterViewer, read access in %q's cluster: " +
		"namespaces (list); in farcast-system and every namespace the kernel meters, now and later (today %s): " +
		"deployments, statefulsets, jobs, pods and their logs, and the ConfigMaps %s?"
	// Until ADR 0023 M2.6 the --yes refusal ends at "in a terminal"; M2.6
	// adds the plan and confirm route.
	msgReaderGrantYes      = "reader grant cannot be run with --yes: it gives a Google identity read access to the cluster; confirm it in a terminal"
	msgReaderGrantTerminal = "reader grant needs a terminal to confirm"
	msgReaderPropagating   = "IAM changes typically take 2 minutes, and can take 7 minutes or longer; checking again until %s"
	// The second %s of these two is the review's why: "it is not read-only"
	// for the four write and Secret reviews, which are design §7.2's text.
	msgReaderNotReadOnly = "the reader %s may %s; %s, so nothing was recorded; " +
		"check the role the Cloud Shell script granted (roles/container.clusterViewer only)"
	msgReaderWithdrawn = "the reader %s may %s; %s, so its earlier verification was withdrawn and reads refuse until a clean grant; " +
		"check the role the Cloud Shell script granted (roles/container.clusterViewer only)"
)

// The two reasons a review that answers yes refuses the grant.
const (
	readerCanWrite      = "it is not read-only"
	readerReadsBeyondIt = "it reads beyond the RBAC farcast applied"
)

// readerReview is one thing the reader must not be allowed to do.
type readerReview struct {
	what  string // as the refusal names it, after "may"
	why   string // what a yes shows, readerCanWrite or readerReadsBeyondIt
	attrs kube.ResourceAttributes
}

// readerReviews are the five SelfSubjectAccessReviews 'reader grant' makes as
// the reader, each of which must answer allowed: false. GKE allows what
// either IAM or RBAC grants, so an IAM role stronger than clusterViewer,
// edited into the Cloud Shell paste, shows here if it can do one of these, and
// if GKE's reviews consult IAM as well as RBAC (not yet walked): write a
// Deployment or its scale, read a Secret, or read beyond the reader's RBAC,
// sampled by listing pods in kube-system, where no farcast RBAC ever binds the
// reader. They sample; a role whose only extra powers are others, such as
// pods/exec or serviceaccounts/token, does not show here.
var readerReviews = []readerReview{
	{"create deployments in " + tcdeploy.DefaultNamespace, readerCanWrite,
		kube.ResourceAttributes{Namespace: tcdeploy.DefaultNamespace, Verb: "create", Group: "apps", Resource: "deployments"}},
	{"get secrets in " + tcdeploy.DefaultNamespace, readerCanWrite,
		kube.ResourceAttributes{Namespace: tcdeploy.DefaultNamespace, Verb: "get", Resource: "secrets"}},
	{"patch deployments/scale in " + tcdeploy.DefaultNamespace, readerCanWrite,
		kube.ResourceAttributes{Namespace: tcdeploy.DefaultNamespace, Verb: "patch", Group: "apps", Resource: "deployments", Subresource: "scale"}},
	{"list secrets in every namespace", readerCanWrite,
		kube.ResourceAttributes{Verb: "list", Resource: "secrets"}},
	{"list pods in kube-system", readerReadsBeyondIt,
		kube.ResourceAttributes{Namespace: "kube-system", Verb: "list", Resource: "pods"}},
}

// readerGrantCommand grants the reader its Kubernetes RBAC and verifies, as
// the reader, that it can read and cannot write (design §7.2). It is newly
// automated: nothing else in FarCast grants a Google identity RBAC, so --yes
// never covers it.
//
// Until ADR 0023 M2.7 the RBAC is applied by kubectl, as the active gcloud
// configuration, through newApplier; the verifying read and reviews are the
// first in-process calls, as the reader, through newReader.
type readerGrantCommand struct {
	yes bool

	newApplier  func(kubeconfigPath string) clusterApplier
	newReader   func(clusterRef) (readerVerifier, error)
	interactive func(*Env) bool
	now         func() time.Time
	sleep       func(ctx context.Context, d time.Duration) error
}

func (*readerGrantCommand) Name() string { return "grant" }
func (*readerGrantCommand) Synopsis() string {
	return "Grant the reader read access in the cluster, and verify it read-only"
}

func (*readerGrantCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast reader grant <instance>

Grant the instance's reader service account read access in its cluster, then
check, as the reader, that it can read and cannot write. Run it once the
reader's key is recorded ('farcast reader record').

It applies the reader's Kubernetes RBAC:
  - namespaces (list), cluster-wide;
  - in farcast-system and in every namespace the kernel meters:
    deployments and statefulsets (get, list), pods (list), their logs (get),
    jobs (get), and the ConfigMaps technocore-namespaces, technocore-ledger,
    technocore-profiles, fatline-egress-policy and datasphered-pin (get).
It binds the reader only in farcast-system and the namespaces the kernel
meters, so never in a kube- namespace such as kube-system, which 'kernel
meter' refuses to meter. GKE's other managed namespaces, such as
gke-managed-system, are not refused: one the kernel meters is bound too. It
grants no Secret, Service, write verb or watch. Once granted, 'kernel meter',
'kernel deploy' and 'run' bind the reader in each namespace they start
metering, as this command's prompt says ("now and later"); 'kernel meter
--remove' leaves that binding in place.

Then, as the reader, it reads the namespaces farcast manages, retrying for up
to 8 minutes while IAM propagates, and asks the API server five questions,
each of which must be no: may it create deployments in farcast-system, get
secrets there, patch deployments/scale there, list secrets anywhere, or list
pods in kube-system, where its RBAC never binds it? A yes means the role the
Cloud Shell script granted is stronger than roles/container.clusterViewer,
and nothing is recorded; run again on a granted reader, it withdraws the
earlier verification, so reads refuse until a clean grant. The questions
sample; a role whose only extra powers are others does not show.

It asks in a terminal, and --yes is refused: it gives a Google identity read
access to the cluster.

Until ADR 0023 M2.7 the RBAC is applied with kubectl, as the active gcloud
configuration.`)
}

func (c *readerGrantCommand) SetFlags(fs *flag.FlagSet) {
	const usage = "refused: reader grant gives a Google identity read access to the cluster, so it asks in a terminal"
	fs.BoolVar(&c.yes, "yes", false, usage)
	fs.BoolVar(&c.yes, "y", false, usage)
}

func (c *readerGrantCommand) ensureDefaults() {
	if c.newApplier == nil {
		c.newApplier = func(kc string) clusterApplier { return cluster.New(kc) }
	}
	if c.newReader == nil {
		c.newReader = openReaderVerifier
	}
	if c.interactive == nil {
		c.interactive = isInteractive
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.sleep == nil {
		c.sleep = sleepContext
	}
}

// openReaderVerifier is newReader's default: openCluster as the reader, with
// Verifying set, so the reader opens whether or not it was verified before (a
// first grant, or a re-run). It is the only place Verifying is set.
func openReaderVerifier(r clusterRef) (readerVerifier, error) {
	r.Identity, r.Verifying = kube.Reader, true
	c, err := openCluster(r)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// sleepContext waits for d, or until ctx ends.
func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *readerGrantCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("reader grant takes one instance name")
	}
	name := args[0]
	if c.yes {
		return usagef(msgReaderGrantYes)
	}
	c.ensureDefaults()

	// 2. The reader must be recorded, uploaded and the one farcast derives,
	// before anything is rendered, asked or applied.
	meta, err := loadReaderRecord(env.ConfigDir, name)
	if err != nil {
		return err
	}
	email, err := grantableReader(env.ConfigDir, meta)
	if err != nil {
		return err
	}

	// 3. The RBAC, with farcast-system and every namespace the kernel meters.
	var metered []string
	if meta.Kernel != nil {
		metered = meta.Kernel.Namespaces
	}
	stream, err := renderReaderRBAC(email, metered)
	if err != nil {
		return err
	}
	bound, err := readerBoundNamespaces(metered)
	if err != nil {
		return err
	}

	// 4. Consent, in a terminal only.
	if !c.interactive(env) {
		return usagef(msgReaderGrantTerminal)
	}
	// The reader that step 6 verifies as is opened before anything is asked
	// or applied. Every refusal openCluster makes is local (the endpoint
	// rule, the cluster CA, reader.key) and it sends nothing (design §3.5),
	// so a reader that could never verify the grant is refused before a
	// Google identity is given RBAC.
	v, err := c.newReader(clusterRef{Dir: env.ConfigDir, Meta: meta, Identity: kube.Reader, Warn: env.Err})
	if err != nil {
		return err
	}
	ok, err := newPrompter(env.In, env.Err).yesNo(fmt.Sprintf(msgReaderGrantPrompt,
		email, name, strings.Join(bound, ", "), strings.Join(readerConfigMaps, ", ")))
	if err != nil {
		return err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return nil
	}

	// 5. The apply, through kubectl as the active gcloud configuration until
	// ADR 0023 M2.7.
	if err := c.newApplier(env.ConfigDir.InstanceKubeconfigPath(name)).Apply(ctx, stream); err != nil {
		return fmt.Errorf("apply instance %q's reader RBAC: %w; nothing was recorded", name, err)
	}

	// 6. The verification, as the reader opened above.
	if err := c.verifyRead(ctx, env, v, name, email); err != nil {
		return err
	}
	if err := c.verifyReadOnly(ctx, env, v, name, email, meta.Reader); err != nil {
		return err
	}

	// 7. Recorded only now.
	now := c.now().UTC()
	if _, err := env.ConfigDir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
		if m.Reader == nil || m.Reader.Email != email {
			return fmt.Errorf("instance %q's reader was changed by another command while this one ran; nothing was recorded; run 'farcast reader grant %s' again", name, name)
		}
		m.Reader.GrantedAt = now
		m.Reader.Scope = readerScopeMetered
		m.UpdatedAt = now
		return nil
	}); err != nil {
		return fmt.Errorf("record instance %q's reader as verified: %w", name, err)
	}
	return env.Printer.Print(readerGrantResult{
		Instance: name, Email: email, Scope: readerScopeMetered, Namespaces: bound, GrantedAt: now,
	})
}

// grantableReader is step 2 of 'reader grant': the record must hold a reader
// with an uploaded key, whose email is the one farcast derives for the
// instance. It returns the email the RBAC binds.
func grantableReader(dir config.Dir, meta *config.InstanceMetadata) (string, error) {
	name := meta.Name
	if meta.Reader == nil {
		return "", refuse(errCredentialMissing, "instance %q has no reader identity; run 'farcast reader init %s'", name, name)
	}
	if meta.Reader.KeyID == "" {
		return "", refuse(errCredentialMissing, "instance %q's reader key is not yet uploaded; run the printed Cloud Shell script, then 'farcast reader record %s --key-id <id>'", name, name)
	}
	return readerSubject(dir, meta)
}

// verifyRead is one read as the reader, retried on a 401 or a 403 while IAM
// propagates: after 5, 10, 20 and 40 seconds, then every 60, until 8 minutes
// have passed, the last wait cut short so the last attempt is at 8 minutes.
// The first retry says why it waits. Any other failure is not retried.
func (c *readerGrantCommand) verifyRead(ctx context.Context, env *Env, v readerVerifier, name, email string) error {
	deadline := c.now().Add(readerPropagation)
	for attempt := 0; ; attempt++ {
		_, err := v.NamespacesLabelled(ctx, readerGrantSelector)
		if err == nil {
			return nil
		}
		if !errors.Is(err, tkube.ErrUnauthorized) && !errors.Is(err, tkube.ErrForbidden) {
			return fmt.Errorf("read instance %q's cluster as the reader %s: %w; nothing was recorded", name, email, err)
		}
		now := c.now()
		left := deadline.Sub(now)
		if left <= 0 {
			return fmt.Errorf("the reader %s still cannot read instance %q's cluster after %s: %w; its RBAC is applied and nothing was recorded. "+
				"Check that the Cloud Shell script granted it roles/container.clusterViewer, then run 'farcast reader grant %s' again",
				email, name, readerPropagation, err, name)
		}
		if attempt == 0 {
			fprintf(env.Err, msgReaderPropagating+"\n", deadline.Format(time.TimeOnly))
		}
		if err := c.sleep(ctx, min(readerBackoffAt(attempt), left)); err != nil {
			return err
		}
	}
}

// verifyReadOnly makes the five reviews as the reader. The first that is
// allowed refuses the grant; on a reader verified before, it first withdraws
// that verification, so reads refuse until a clean grant. A review that fails,
// or whose "no" proves nothing (an evaluationError, kube.ErrUnreadable),
// records nothing and leaves an earlier verification as it was.
func (c *readerGrantCommand) verifyReadOnly(ctx context.Context, env *Env, v readerVerifier, name, email string, before *config.Reader) error {
	for _, r := range readerReviews {
		allowed, err := v.CanI(ctx, r.attrs)
		if err != nil {
			return fmt.Errorf("ask, as the reader %s, whether it may %s: %w; nothing was recorded", email, r.what, err)
		}
		if !allowed {
			continue
		}
		if before == nil || (before.GrantedAt.IsZero() && before.Scope == "") {
			return fmt.Errorf(msgReaderNotReadOnly, email, r.what, r.why)
		}
		if err := withdrawReaderGrant(env.ConfigDir, name); err != nil {
			return fmt.Errorf("the reader %s may %s; %s, and its earlier verification could not be withdrawn (%v), "+
				"so reads may still open it: run 'farcast reader grant %s' again", email, r.what, r.why, err, name)
		}
		return fmt.Errorf(msgReaderWithdrawn, email, r.what, r.why)
	}
	return nil
}

// withdrawReaderGrant clears the reader's GrantedAt and Scope, so openCluster
// refuses the reader and no later command binds it in a namespace it meters.
func withdrawReaderGrant(dir config.Dir, name string) error {
	_, err := dir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
		if m.Reader == nil {
			return nil
		}
		m.Reader.GrantedAt = time.Time{}
		m.Reader.Scope = ""
		m.UpdatedAt = time.Now().UTC()
		return nil
	})
	return err
}

// readerGrantResult is what 'reader grant' recorded.
type readerGrantResult struct {
	Instance   string    `json:"instance"`
	Email      string    `json:"email"`
	Scope      string    `json:"scope"`
	Namespaces []string  `json:"namespaces"`
	GrantedAt  time.Time `json:"granted_at"`
}

func (r readerGrantResult) Human(w io.Writer) error {
	fprintf(w, "✓ instance %q's reader %s reads the cluster, and was verified read-only\n", r.Instance, r.Email)
	for _, ns := range r.Namespaces {
		fprintf(w, "  "+msgReaderBinding+"\n", r.Email, ns)
	}
	fprintf(w, "Every namespace the kernel meters from now on is bound too, by 'kernel meter', 'kernel deploy' and 'run'.\n")
	return nil
}
