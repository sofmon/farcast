package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// msgNotMigrated is the refusal of a command that would write to the
// cluster of an instance whose record says its objects were last written
// with kubectl's client-side apply (ADR 0023 M2.7, design §6.5). Its three
// verbs are the instance's name.
const msgNotMigrated = "instance %q was last written by kubectl's client-side apply, and this farcast writes with server-side apply; " +
	"run 'farcast migrate %s --plan' to review the one-time rewrite, then 'farcast migrate %s --confirm <digest>'. Nothing was written."

// refuseUnmigrated refuses, kind not_migrated, a command that writes to the
// cluster of an instance meta does not record as written with server-side
// apply (meta.ServerSideApply nil), and is nil for one it does (design
// A30-20).
//
// Every command that writes to an instance's cluster calls it right after it
// has loaded the record and checked that the record names the instance
// (recordNamed), before any prompt, mint, provider open or cluster call. It
// is an error in every mode, --plan included, raised before any plan is
// computed, never a plan's block, and a plan binds nothing for it. A
// precheck that needs no record may come before it, as the carried-image
// precheck of redeploy, kernel deploy and storage deploy does. Where a
// command writes to the cluster only in some of its forms, only those
// refuse: connect on a first deploy or a resume, never on a reconnect or
// under --status; kernel meter once it has namespaces to change, never in its
// list-only form; and storage key rotate only with a keyholder deployed,
// whose pin it writes. migrate, which is how an instance comes to be
// recorded, never calls it.
func refuseUnmigrated(name string, meta *config.InstanceMetadata) error {
	if meta.ServerSideApply != nil {
		return nil
	}
	return withKind(kindNotMigrated, fmt.Errorf(msgNotMigrated, name, name, name))
}

// The safety net's texts (ADR 0023 M2.7, design §6.6, A30-28): an object an
// apply found still carrying kubectl's client-side apply, and the instance,
// once per object; and the record afterWrites could not clear: the instance,
// why, and the instance again.
const (
	msgTraceLeft       = "Warning: %s still carries kubectl's client-side apply (another farcast, or kubectl, wrote it since this instance was migrated); the next write will refuse until 'farcast migrate %s' runs again."
	msgTraceNotCleared = "Warning: could not clear instance %q's server_side_apply record (%s); run 'farcast migrate %s --plan' before its next write"
)

// tracer is a writer that can say which objects its applies answered with
// that still carry kubectl's client-side apply: cluster.Client.Traces.
type tracer interface {
	Traces() []string
}

// afterWrites is the safety net for writes after a migration (ADR 0023 M2.7,
// design §6.6, A30-28). A farcast older than M2.7, or kubectl, may still
// write a migrated instance with client-side apply from another machine, and
// every apply's answer shows it (cluster.Client.Traces). Each command that
// applies defers afterWrites(env, name, cl) right after every writer open
// that succeeds, so it runs on every return, a failed or partial apply's
// included.
//
// When w is a tracer whose Traces is not empty, it prints a Warning on
// stderr for each object, once, then clears the instance's server_side_apply
// record through UpdateInstanceMetadata, so every later write refuses until
// 'farcast migrate' runs again. Each line is made safe to print
// (output.ErrorText). Otherwise it does nothing and reads nothing:
// a test's fake, or a writer whose applies found nothing. It returns nothing
// and never replaces the command's error; a record it cannot clear is a
// Warning of its own.
func afterWrites(env *Env, name string, w any) {
	t, ok := w.(tracer)
	if !ok {
		return
	}
	traces := t.Traces()
	if len(traces) == 0 {
		return
	}
	for _, obj := range traces {
		fprintln(env.Err, output.ErrorText(fmt.Sprintf(msgTraceLeft, obj, name)))
	}
	if _, err := env.ConfigDir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
		m.ServerSideApply = nil
		return nil
	}); err != nil {
		fprintln(env.Err, output.ErrorText(fmt.Sprintf(msgTraceNotCleared, name, err, name)))
	}
}

// The texts of farcast migrate (ADR 0023 M2.7, design §6.1, A30-21 to A30-24).
// Every object is named by describeObject.
const (
	// msgMigrateYes names the instance, or <instance> for a name that is not
	// one (A23-41). It is a --yes refusal that names --plan in its own
	// words, as msgReaderGrantYes is.
	msgMigrateYes      = "migrate cannot be run with --yes: it rewrites live objects and cannot be undone; review 'farcast migrate %s --plan', then pass --confirm <digest>"
	msgMigrateTerminal = "migrate needs a terminal to confirm" + consentSuffix
	// msgMigratePrompt is the typed-name question; prompter.line adds ": ".
	msgMigratePrompt = "This cannot be undone. Type the instance name to migrate it"
	// msgMigrateNoInstallerKey is an open refused for want of the installer's
	// key (M9): the refusal, kept, then why migrate cannot do without it.
	msgMigrateNoInstallerKey = "%w; migrate runs as the installer service account whose key 'farcast install --credentials' stored, " +
		"so this machine cannot migrate instance %q; an instance installed without one (possible only before ADR 0023 M2.5) " +
		"cannot be migrated, only released"
	// msgMigrateBlocked is a selected object farcast never writes (A30-22):
	// the object, why it is not one farcast writes, and the instance.
	msgMigrateBlocked = "%s carries farcast's label and kubectl's client-side apply, but it is not an object farcast writes (%s); " +
		"migrate never rewrites it: remove its app.kubernetes.io/managed-by label, or delete it, from Cloud Shell, " +
		"then run 'farcast migrate %s --plan' again"
	// msgMigrateChanged is an object whose re-read is not what the plan
	// bound: the object, then how many of the plan's objects were verified
	// before it, of all of them.
	msgMigrateChanged = "%s changed since the plan was made (another writer applied or deleted it); %d of %d objects were migrated and the rest were not"
	// msgMigrateConflicts is the fifth 409 in a row for one object, the
	// cause before the consequence.
	msgMigrateConflicts = "%s kept changing while it was rewritten (%d attempts, each answered 409): %w; " + migrateSoFar
	// msgMigrateRewrite is any other failure to rewrite an object, and
	// msgMigrateReread and msgMigrateReadBack a failure to read it before
	// the rewrite or after it.
	msgMigrateRewrite  = "rewrite %s: %w; " + migrateSoFar
	msgMigrateReread   = "read %s again before rewriting it: %w; " + migrateSoFar
	msgMigrateReadBack = "read %s back after rewriting it: %w; " + migrateSoFar
	// migrateSoFar ends every failure of the loop that a second run finishes.
	migrateSoFar = "%d of %d objects were migrated and the rest were not, and running migrate again finishes them"
	// msgMigrateNoEntries is an object that carries the last-applied
	// annotation and no managed-fields entry, which no run of migrate
	// finishes: its rewrite would leave an empty list, which does not reset
	// the field (kube.MigrationPatch). The object, how many of the plan's
	// objects were migrated before it, of all, and the instance, with the
	// remedy, which is the operator's.
	msgMigrateNoEntries = "%s carries kubectl's last-applied annotation and no managed-fields entry, which migrate cannot rewrite " +
		"(an empty list does not reset the field); %d of %d objects were migrated and the rest were not, and running migrate again stops here: " +
		"remove its kubectl.kubernetes.io/last-applied-configuration annotation from Cloud Shell, then run 'farcast migrate %s --plan' again"
	// msgMigrateNotMigrated is an object the rewrite did not leave migrated
	// (§6.4): its parenthesis is kube.MigratedEndState's text, which names
	// managers, operations and the annotation's key, never a value.
	msgMigrateNotMigrated = "%s did not come back migrated (%w); nothing after it was touched"
	// msgMigrateTraceLeft is the discovery before recording finding a trace
	// (A30-24): how many objects were migrated, of all, and the first object
	// that still carries one.
	msgMigrateTraceLeft = "after %d of %d objects were migrated, %s still carries kubectl's client-side apply (written during the migration); nothing was recorded"
	// msgMigrateRediscover is that discovery failing.
	msgMigrateRediscover = "after %d of %d objects were migrated, %w; nothing was recorded, and running migrate again records it"
	// msgMigrateKeptFile is a legacy file the migration could not delete:
	// its config-relative path, and why.
	msgMigrateKeptFile = "Warning: could not delete %s (%s); nothing reads it"
)

// The loop's retry of a conflict (A30-23): only a 409 is tried again, after
// migrateRetryWait, and an object is tried migrateAttempts times in all.
const (
	migrateAttempts  = 5
	migrateRetryWait = 200 * time.Millisecond
)

// lastAppliedAnnotation is kubectl's client-side apply annotation
// (corev1.LastAppliedConfigAnnotation), as kube and cluster each name it for
// their own reads: migrate binds whether an object carries its key, and never
// its value, which on a Secret holds every key.
const lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// migrateCluster is what farcast migrate needs of the instance's writer
// (ADR 0023 M2.7, design §6.2 to §6.4): its discovery, its re-read and its one
// write, each metadata only, and the preflight read every writer makes.
type migrateCluster interface {
	ListMeta(ctx context.Context, k kube.Kind, namespace, selector string) ([]kube.Object, error)
	GetMeta(ctx context.Context, k kube.Kind, namespace, name string) (kube.Object, error)
	PatchManagedFields(ctx context.Context, k kube.Kind, namespace, name string, patch []byte) (kube.Object, error)
	preflighter
}

// The cluster client is migrate's writer by default.
var _ migrateCluster = (*cluster.Client)(nil)

// migrateWriterDefault is migrateCommand.newCluster's default: the instance's
// writer (openWriter), the installer's stored service-account key. A
// variable, so the package's tests reach no cluster through it but one they
// started (refusingdefaults_test.go).
var migrateWriterDefault = func(r clusterRef) (migrateCluster, error) {
	// A refusal returns a nil writer, never a nil *cluster.Client inside a
	// non-nil one.
	cl, err := openWriter(r)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// migrateCommand rewrites, once, the cluster objects an older farcast
// applied with kubectl's client-side apply, so this farcast can write them
// with server-side apply, and then records the instance as migrated (ADR
// 0023 M2.7, design §6). It is newly automated and cannot be undone, so
// --yes never covers it: it asks for the instance's name in a terminal, or
// takes --plan and then --confirm <digest>. Its plan is the one plan read as
// the writer, because it lists Secrets' metadata, which the reader is never
// granted (§7.3).
type migrateCommand struct {
	newCluster  func(clusterRef) (migrateCluster, error)   // default: openWriter
	interactive func(*Env) bool                            // default: isInteractive
	now         func() time.Time                           // default: time.Now
	sleep       func(context.Context, time.Duration) error // default: a ctx-aware sleep
	consent     consentFlags
	yes         bool
}

func (*migrateCommand) Name() string { return "migrate" }
func (*migrateCommand) Synopsis() string {
	return "Move an instance's cluster objects to server-side apply, once"
}

func (*migrateCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast migrate <instance> [--plan | --confirm <digest>]

Rewrite, once, the cluster objects an older farcast applied with kubectl's
client-side apply, so this farcast can manage them with server-side apply
(ADR 0023 decision 2). Each object's kubectl-client-side-apply entry is
renamed to farcast's, and kubectl's last-applied annotation, which holds a
copy of every applied field and of each Secret's keys, is removed. This
cannot be undone. Until an instance is migrated, every command that writes to
its cluster refuses.

In a terminal it prints its plan and migrates once the instance's name is
typed; --plan prints the plan and changes nothing, and --confirm <digest>
migrates exactly that plan. --yes is refused. Its plan is the one plan read
as the instance's writer, the installer service account, because it lists
Secrets' metadata, which the reader is never granted. An instance installed
without --credentials, possible only before ADR 0023 M2.5, cannot be
migrated, only released.`)
}

func (c *migrateCommand) SetFlags(fs *flag.FlagSet) {
	const usage = "refused: migrate cannot be undone, so it asks in a terminal, or takes --plan and then --confirm <digest>"
	fs.BoolVar(&c.yes, "yes", false, usage)
	fs.BoolVar(&c.yes, "y", false, usage)
	c.consent.register(fs)
}

func (c *migrateCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = migrateWriterDefault
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

// migrateResult is what a migration prints once it has recorded the
// instance, and what an interactive run on a migrated instance with nothing
// to do prints.
type migrateResult struct {
	Instance     string   `json:"instance"`
	Migrated     int      `json:"migrated"`      // objects this run rewrote
	Since        string   `json:"since"`         // server_side_apply.since, wireTime
	LocalDeleted []string `json:"local_deleted"` // config-relative, [] when none
}

func (r migrateResult) Human(w io.Writer) error {
	fprintf(w, "Migrated %d object(s) of instance %s to server-side apply; recorded since %s.\n", r.Migrated, terminalText(r.Instance), r.Since)
	for _, f := range r.LocalDeleted {
		fprintf(w, "Deleted %s.\n", terminalText(f))
	}
	return nil
}

func (c *migrateCommand) Run(ctx context.Context, env *Env, args []string) (err error) {
	if len(args) != 1 {
		return usagef("migrate takes one instance name")
	}
	name := args[0]
	// The answers are counted first, so --yes beside --plan or --confirm is
	// the three-way usage error, not the --yes refusal (A23-16).
	mode, digest, err := c.consent.mode(c.yes)
	if err != nil {
		return err
	}
	if c.yes {
		shown := name
		if validateInstanceName(name) != nil {
			shown = "<instance>"
		}
		return usagef(msgMigrateYes, shown)
	}
	c.ensureDefaults()
	if mode == consentNone && !c.interactive(env) {
		return usagef(msgMigrateTerminal)
	}

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("no such instance %q (run 'farcast install' first): %w", name, err)
	}
	if err := recordNamed(meta, name); err != nil {
		return err
	}
	if meta.Status == config.InstanceDeleting {
		return fmt.Errorf("instance %q is being released", name)
	}
	// A 403 the writer met says whose it was, once (A20-9).
	defer func() { err = writerRefused(err, meta) }()

	// The writer, in every mode: the plan reads the cluster as it (§6.1).
	// Its preflight reads farcast-system's uid, which the plan binds. An open
	// refused for want of the installer's key says why migrate needs it, and
	// keeps its kind (M9).
	open := func(r clusterRef) (migrateCluster, error) {
		cl, err := c.newCluster(r)
		if err != nil && kindOf(classified(err)) == kindCredentialMissing {
			return nil, fmt.Errorf(msgMigrateNoInstallerKey, err, name)
		}
		return cl, err
	}
	cl, uid, err := openReadyAt(ctx, env, meta, open)
	if err != nil {
		return err
	}
	p, b, err := c.plan(ctx, env, meta, cl, uid)
	if err != nil {
		return err
	}

	switch mode {
	case consentPlan:
		return printPlan(env, b, c.now())
	case consentConfirm:
		if err := confirmPlan(b, digest); err != nil {
			return err
		}
	default:
		// A block is refused outside --confirm too (A28-8): the plan is
		// shown, and nothing is asked.
		if p.refused != nil {
			if err := c.render(env, b); err != nil {
				return err
			}
			return p.refused
		}
		if meta.ServerSideApply != nil && len(p.fact.Objects) == 0 && len(p.fact.Local) == 0 {
			return env.Printer.Print(migrateResult{
				Instance: name, Since: plan.Time(meta.ServerSideApply.Since), LocalDeleted: []string{},
			})
		}
		if err := c.render(env, b); err != nil {
			return err
		}
		typed, err := newPrompter(env.In, env.Err).line(msgMigratePrompt)
		if err != nil {
			return err
		}
		if strings.TrimSpace(typed) != meta.Name {
			fprintln(env.Err, "Aborted.")
			return nil
		}
	}
	return c.migrate(ctx, env, meta, cl, p.fact, mode)
}

// render writes the plan b's human rendering on stderr, for the operator of
// an interactive run to read before the question.
func (c *migrateCommand) render(env *Env, b plan.Bound) error {
	r, err := newPlanResult(env, b, c.now())
	if err != nil {
		return err
	}
	return r.Human(env.Err)
}

// preparedMigrate is what migrate executes, decided once by its plan: an
// interactive run and --confirm both execute from it.
type preparedMigrate struct {
	fact plan.MigrateFact
	// refused is the first block's refusal, which an interactive run returns
	// as it is.
	refused error
}

// plan is migrate's plan (design §6.2, §6.4, A30-21, A30-22), read as the
// writer cl: farcast-system's uid as the writer's preflight read it, no
// option, and exactly one migrate fact, which cannot be undone. Its objects
// are those discovery selects, in its order, but for the ones farcast never
// writes, which are blocks; its local files are those LegacyKubectlFiles
// finds on this machine.
func (c *migrateCommand) plan(ctx context.Context, env *Env, meta *config.InstanceMetadata, cl migrateCluster, uid string) (preparedMigrate, plan.Bound, error) {
	b := newBound("migrate", meta, "writer", uid)
	var p preparedMigrate
	found, err := discoverClientSide(ctx, cl)
	if err != nil {
		return p, plan.Bound{}, err
	}
	fact := plan.MigrateFact{Type: plan.TypeMigrate, CannotBeUndone: true}
	for _, o := range found {
		if why := notWrittenByFarcast(o); why != "" {
			refused := refuse(kube.ErrRefusedDocument, msgMigrateBlocked, objectName(o), why, meta.Name)
			b.Blocked = append(b.Blocked, blockOf(refused))
			if p.refused == nil {
				p.refused = refused
			}
			continue
		}
		mo, err := migrateObjectOf(o)
		if err != nil {
			return p, plan.Bound{}, err
		}
		fact.Objects = append(fact.Objects, mo)
	}
	if fact.Local, err = env.ConfigDir.LegacyKubectlFiles(meta.Name); err != nil {
		return p, plan.Bound{}, fmt.Errorf("look for instance %q's kubectl files on this machine: %w", meta.Name, err)
	}
	b.Facts = []plan.Fact{fact}
	p.fact = fact
	return p, b, nil
}

// discoverClientSide is migrate's discovery (§6.2, A30-22): for each kind of
// kube.Kinds, in the table's order, one cluster-wide list of the objects that
// carry farcast's label, metadata only, keeping those kube.ClientSideTrace
// selects, in the server's order. The label alone selects nothing: the pin
// and the kernel's ConfigMaps carry it, and were never applied by kubectl.
// It lists every namespace, labelled or not: kernel meter binds the kernel in
// namespaces farcast did not create. Each object carries its kind's table
// entry.
func discoverClientSide(ctx context.Context, cl migrateCluster) ([]kube.Object, error) {
	var found []kube.Object
	for _, k := range kube.Kinds {
		objs, err := cl.ListMeta(ctx, k, "", managedSelector)
		if err != nil {
			return nil, fmt.Errorf("list the cluster's %s: %w", k.Resource, err)
		}
		for _, o := range objs {
			if kube.ClientSideTrace(o.Metadata) {
				o.Kind = k
				found = append(found, o)
			}
		}
	}
	return found, nil
}

// notWrittenByFarcast says why a selected object is not one farcast writes,
// so migrate never rewrites it (A30-22), or "" for one it writes: a kind
// whose names are restricted, by any other name (a ClusterRoleBinding not
// named farcast-reader-namespaces), or an object in a namespace that is the
// provider's (kube-system and every kube- namespace, validNamespace's rule,
// and GKE's gke- and gmp- namespaces), or such a namespace's own Namespace
// object, which is cluster-scoped and so named by its name. A deployment
// that a farcast older than M2.7 put in a gke- or gmp- Namespace, by its
// manifest's name or by run --namespace (planck's translate and
// validNamespace refuse only kube-), is blocked with that Namespace and
// every object in it. Removing the label does not settle it: the objects
// keep kubectl's entry, and the next farcast run of that deployment labels
// them again, which clears the migrated record. The remedy is to delete the
// deployment's objects, or its Namespace, from Cloud Shell, run migrate,
// then farcast run it again.
func notWrittenByFarcast(o kube.Object) string {
	if names := o.Kind.Names; names != nil && !slices.Contains(names, o.Metadata.Name) {
		return fmt.Sprintf("a %s farcast writes is named %s", o.Kind.Kind, strings.Join(names, " or "))
	}
	ns := o.Metadata.Namespace
	if o.Kind.Kind == "Namespace" {
		ns = o.Metadata.Name
	}
	for _, prefix := range []string{"kube-", "gke-", "gmp-"} {
		if strings.HasPrefix(ns, prefix) {
			return fmt.Sprintf("namespace %q is the provider's", ns)
		}
	}
	return ""
}

// objectName is o as migrate names it (describeObject).
func objectName(o kube.Object) string {
	return describeObject(o.Kind.Kind, o.Metadata.Namespace, o.Metadata.Name)
}

// migrateObjectOf is o as the migrate fact binds it (A30-12): what it is and
// where, its uid, the managers whose client-side entries the rewrite
// converts, the SHA-256 of those entries' fields, whether the last-applied
// annotation's key is there (never its value), and every other manager,
// which is kept.
func migrateObjectOf(o kube.Object) (plan.MigrateObject, error) {
	md := o.Metadata
	csa, err := kube.ClientSideManagers(md.ManagedFields)
	if err != nil {
		return plan.MigrateObject{}, fmt.Errorf("%s: %w", objectName(o), err)
	}
	_, annotated := md.Annotations[lastAppliedAnnotation]
	return plan.MigrateObject{
		API: o.Kind.APIVersion, Kind: o.Kind.Kind, Namespace: md.Namespace, Name: md.Name, UID: md.UID,
		CSAManagers: csa, CSAFieldsSHA256: csaFieldsSHA256(md.ManagedFields, csa),
		Annotation: annotated, OtherManagers: otherManagers(md.ManagedFields, csa),
	}, nil
}

// rewritten says whether the migration converts or removes e: an Update
// entry on the main resource of one of the managers in csa (kube's
// isCSAEntry, for the set).
func rewritten(e kube.ManagedFieldsEntry, csa []string) bool {
	return e.Operation == "Update" && e.Subresource == "" && slices.Contains(csa, e.Manager)
}

// csaFieldsSHA256 is the lowercase hex SHA-256 of the raw fieldsV1 bytes of
// every entry the migration converts or removes, concatenated in the list's
// order (A30-12). An object with the annotation alone hashes the empty
// input. fieldsV1 names fields, never their values.
func csaFieldsSHA256(entries []kube.ManagedFieldsEntry, csa []string) string {
	h := sha256.New()
	for _, e := range entries {
		if rewritten(e, csa) {
			h.Write(e.FieldsV1)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// otherManagers is every entry the migration keeps, as manager/operation,
// with /subresource when it is set, each once, in the list's order: farcast's
// own Apply entry and an operator's kubectl/Apply among them.
func otherManagers(entries []kube.ManagedFieldsEntry, csa []string) []string {
	var out []string
	for _, e := range entries {
		if rewritten(e, csa) {
			continue
		}
		m := e.Manager + "/" + e.Operation
		if e.Subresource != "" {
			m += "/" + e.Subresource
		}
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// migrate executes the plan's fact f as the writer cl, in mode m (A30-23,
// A30-24): each object in the plan's order, then a fresh discovery, then the
// record, and only then the local files. A failure stops it, and a second
// run finishes it.
func (c *migrateCommand) migrate(ctx context.Context, env *Env, meta *config.InstanceMetadata, cl migrateCluster, f plan.MigrateFact, m consentMode) error {
	name, total := meta.Name, len(f.Objects)
	for done, o := range f.Objects {
		if err := c.migrateOne(ctx, cl, name, o, done, total, m); err != nil {
			return err
		}
	}

	// Recorded only when a fresh discovery selects nothing: a trace written
	// during the migration, which the plan did not list, would otherwise be
	// recorded as migrated (A30-24). A farcast/Update entry, which the pin's
	// create and replace leave, is no trace.
	found, err := discoverClientSide(ctx, cl)
	if err != nil {
		return fmt.Errorf(msgMigrateRediscover, total, total, err)
	}
	if len(found) > 0 {
		return changedAfterPlan(m, fmt.Sprintf(msgMigrateTraceLeft, total, total, objectName(found[0])))
	}
	now := c.now().UTC()
	var since time.Time
	if _, err := env.ConfigDir.UpdateInstanceMetadata(name, func(rec *config.InstanceMetadata) error {
		since = now
		if rec.ServerSideApply != nil {
			since = rec.ServerSideApply.Since
		}
		rec.ServerSideApply = &config.ServerSideApply{Since: since, Farcast: buildinfo.Get().Version}
		rec.UpdatedAt = now
		return nil
	}); err != nil {
		return fmt.Errorf("record instance %q as migrated to server-side apply: %w; every object was migrated, and running migrate again records it", name, err)
	}

	// The files kubectl read and left beside the record, which nothing reads
	// once the instance is migrated. One that cannot be deleted is said, and
	// is no failure.
	removed, err := env.ConfigDir.RemoveLegacyKubectlFiles(name)
	if err != nil {
		path, cause := "", error(err)
		var pe *fs.PathError
		if errors.As(err, &pe) {
			path, cause = pe.Path, pe.Err
		}
		fprintln(env.Err, output.ErrorText(fmt.Sprintf(msgMigrateKeptFile, path, cause)))
	}
	if removed == nil {
		removed = []string{}
	}
	return env.Printer.Print(migrateResult{Instance: name, Migrated: total, Since: plan.Time(since), LocalDeleted: removed})
}

// migrateOne migrates the plan's object o of instance name, done objects of
// total having been verified before it (A30-23): it reads o again and
// checks it against the plan, rewrites its managed fields, and checks the
// end state on the rewrite's answer and on a fresh read. Only a 409 is tried
// again, after migrateRetryWait, from the re-read, migrateAttempts times in
// all; any other failure stops the run. An object that carries the
// last-applied annotation and no managed-fields entry is never sent: no run
// can rewrite it, and the error names the operator's remedy.
func (c *migrateCommand) migrateOne(ctx context.Context, cl migrateCluster, name string, o plan.MigrateObject, done, total int, m consentMode) error {
	k, ok := kube.KindOf(o.API, o.Kind)
	if !ok {
		return fmt.Errorf("cli: the migrate plan names %s %s, which is no kind farcast writes", o.API, o.Kind)
	}
	what := describeObject(o.Kind, o.Namespace, o.Name)
	for attempt := 1; ; attempt++ {
		read, err := cl.GetMeta(ctx, k, o.Namespace, o.Name)
		if errors.Is(err, tkube.ErrNotFound) {
			return changedAfterPlan(m, fmt.Sprintf(msgMigrateChanged, what, done, total))
		}
		if err != nil {
			return fmt.Errorf(msgMigrateReread, what, err, done, total)
		}
		csa, err := kube.ClientSideManagers(read.Metadata.ManagedFields)
		if err != nil || read.Metadata.UID != o.UID || !slices.Equal(csa, o.CSAManagers) ||
			csaFieldsSHA256(read.Metadata.ManagedFields, csa) != o.CSAFieldsSHA256 {
			return changedAfterPlan(m, fmt.Sprintf(msgMigrateChanged, what, done, total))
		}
		// The annotation with no entry at all: the rewrite would leave an
		// empty list, which kube.MigrationPatch refuses, on this run and on
		// every later one, so the error says what the operator does instead
		// of running migrate again.
		if _, annotated := read.Metadata.Annotations[lastAppliedAnnotation]; annotated && len(read.Metadata.ManagedFields) == 0 {
			return fmt.Errorf(msgMigrateNoEntries, what, done, total, name)
		}
		// Whether the object carried farcast's own Apply entry before the
		// rewrite, which the end state then requires (A30-8).
		hadApply := slices.ContainsFunc(read.Metadata.ManagedFields, kube.IsOwnApply)
		patch, err := kube.MigrationPatch(read, csa, kube.FieldManager)
		if err != nil {
			return fmt.Errorf(msgMigrateRewrite, what, err, done, total)
		}
		answer := read
		if patch != nil {
			answer, err = cl.PatchManagedFields(ctx, k, o.Namespace, o.Name, patch)
			if errors.Is(err, tkube.ErrConflict) {
				if attempt == migrateAttempts {
					return fmt.Errorf(msgMigrateConflicts, what, migrateAttempts, err, done, total)
				}
				if err := c.sleep(ctx, migrateRetryWait); err != nil {
					return fmt.Errorf(msgMigrateRewrite, what, err, done, total)
				}
				continue
			}
			if err != nil {
				return fmt.Errorf(msgMigrateRewrite, what, err, done, total)
			}
		}
		if err := kube.MigratedEndState(answer, csa, kube.FieldManager, hadApply); err != nil {
			return fmt.Errorf(msgMigrateNotMigrated, what, err)
		}
		// The answer may look migrated while the server kept the list it
		// had (§6.3): the end state is read back.
		back, err := cl.GetMeta(ctx, k, o.Namespace, o.Name)
		if err != nil {
			return fmt.Errorf(msgMigrateReadBack, what, err, done, total)
		}
		if err := kube.MigratedEndState(back, csa, kube.FieldManager, hadApply); err != nil {
			return fmt.Errorf(msgMigrateNotMigrated, what, err)
		}
		return nil
	}
}
