package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/planck/translate"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// What run reads of the instance before it deploys, and again after the
// builds: the kernel's ledger, and each application's live Deployment (ADR
// 0023 Choices 6, decided P1; design §5.4, A23-48, A28-1 to A28-6).
//
// A deploy renders replicas: 1 and translate's requests, so it restarts an
// application the cost guard stopped and resets one the kernel adapted. The
// review says so, one line per application, and while the instance's
// spending is at its limit run --yes deploys nothing: a script that loops
// on it would otherwise keep building (a build is a Job, which the kernel
// never stops) and keep restarting what the kernel stopped.

// appReplicas is the replica count translate renders for every application
// (planck/translate/workload.go): what a deploy sets a stopped one back to.
const appReplicas = 1

// Why run reads the instance's spending as at its limit (A28-1). They are
// the run fact's limit_reason words, never a level: the level is compared
// with cost.LevelReached.String() alone.
const (
	limitReasonReached    = "limit reached"
	limitReasonUnknown    = "level unknown"
	limitReasonUnreadable = "ledger unreadable"
	limitReasonStale      = "ledger stale"
)

// limitState is what the kernel's ledger says about the cost limit, as run's
// gate reads it (A28-1, A28-2, A28-4).
type limitState struct {
	// Reached is true when the gate reads the spending as at its limit: the
	// kernel's own level says so, or is one levelOf cannot place, or the
	// ledger cannot be read, or the kernel last looked too long ago. An
	// absent ledger, which a kernel that has never checkpointed leaves, is
	// not at the limit.
	Reached bool
	// Reason is "" unless Reached, and one of the limitReason words if so.
	Reason string
	// costStops is every <namespace>/<deployment> the ledger records the
	// cost guard stopping (costGuardStops). A ledger that cannot be read
	// names none.
	costStops map[string]bool
}

// readLimit reads the kernel's ledger, technocore-ledger's checkpoint, by
// the one rule the gate and its re-read both apply (A28-4). The ledger is
// absent only when the read says not found and no error. Anything else that
// is not a checkpoint this build decodes is unreadable, and reads as at the
// limit: a read error of any kind (a 403, a 404 that is not the API
// server's, a transport failure), the ConfigMap without its key, an empty
// value, and anything decodeCheckpoint refuses, a version or a ledger the
// kernel's own code would not restore included. now is run's clock, against
// which the checkpoint is stale (A28-2).
func readLimit(ctx context.Context, cl configMapReader, now time.Time) limitState {
	raw, found, err := cl.ConfigMapValue(ctx, deploy.DefaultNamespace, kernel.DefaultCheckpointName, kernel.CheckpointKey())
	if err == nil && !found {
		return limitState{}
	}
	if err != nil || strings.TrimSpace(raw) == "" {
		return limitState{Reached: true, Reason: limitReasonUnreadable}
	}
	cp, _, err := decodeCheckpoint(raw)
	if err != nil {
		return limitState{Reached: true, Reason: limitReasonUnreadable}
	}
	lim := limitState{costStops: costGuardStops(cp)}
	_, stale := checkpointFreshness(cp, now)
	switch level := cp.Observed.Level; {
	case level == cost.LevelReached.String():
		lim.Reached, lim.Reason = true, limitReasonReached
	case levelOf(level) == stateUnknown:
		lim.Reached, lim.Reason = true, limitReasonUnknown
	case stale:
		lim.Reached, lim.Reason = true, limitReasonStale
	}
	return lim
}

// checkpointFreshness is when the kernel last looked, as a checkpoint says
// it, and whether that is too long ago to trust: the observation's own time,
// or the last accrual's when it has none, stale when there is neither or it
// is older than checkpointStaleAfter at now. world marks a checkpoint stale
// by it, and run's gate reads a stale one as at the limit (A28-2): a kernel
// that stopped reporting no longer guards the spending.
func checkpointFreshness(cp kernel.Checkpoint, now time.Time) (observed time.Time, stale bool) {
	observed = cp.Observed.At
	if observed.IsZero() {
		observed = cp.Last
	}
	return observed, observed.IsZero() || observed.UTC().Truncate(time.Second).Before(now.Add(-checkpointStaleAfter))
}

// costGuardStops is every workload a checkpoint records the cost guard
// stopping, as <namespace>/<deployment> (tenantOf). A record is the
// kernel's, not a claim about now: a reader names a workload stopped by the
// cost guard only while it is still at zero (kernel.Stop).
func costGuardStops(cp kernel.Checkpoint) map[string]bool {
	stops := map[string]bool{}
	for _, st := range cp.Stops {
		if st.Reason == kernel.StopReasonCostGuard {
			stops[tenantOf(st.Namespace, st.Deployment)] = true
		}
	}
	return stops
}

// limitLine is the line the review prints, and a deploy plan renders, while
// the instance's spending reads as at its limit (A28-1).
func limitLine(reason string) string {
	return fmt.Sprintf("the instance's spending is at its limit (%s); this deploy adds to it until the kernel's next tick stops its applications", reason)
}

// appState is one application's live Deployment, as run reads it before it
// deploys (A28-5).
type appState struct {
	Namespace string
	App       string
	// Err is why the Deployment could not be read as one translate renders:
	// the read failed, or it has no container named after the application,
	// or no replica count. An application with an Err is unknown, and the
	// fields below are unset.
	Err error
	// Present is false for an application this deploy creates.
	Present bool
	// ReplicasLive and RequestsLive are what runs now: spec.replicas, and
	// the requests of the container named after the application.
	ReplicasLive *int32
	RequestsLive *plan.Requests
	// AdaptedAt is the kernel's stamp, and adapted whether it is later than
	// farcast's last apply: the kernel resized the application since.
	AdaptedAt time.Time
	adapted   bool
	// StoppedByCostGuard is true for an application at zero replicas that
	// the ledger records the cost guard stopping.
	StoppedByCostGuard bool
}

// stopped reports whether the application runs no replica now, whoever
// scaled it there, adapted or not.
func (a appState) stopped() bool {
	return a.Err == nil && a.ReplicasLive != nil && *a.ReplicasLive == 0
}

// restarts reports whether this deploy may restart something the kernel
// stopped: an application at zero replicas, or one that could not be read.
// The gate, the re-read and the at-the-limit lines key on this, never on the
// state word (A28-5).
func (a appState) restarts() bool { return a.Err != nil || a.stopped() }

// state is the application's reset, in precedence order (A28-5): unknown,
// then stopped, adapted or not, then adapted. "" is no reset.
func (a appState) state() string {
	switch {
	case a.Err != nil:
		return plan.ResetUnknown
	case a.stopped():
		return plan.ResetStopped
	case a.adapted:
		return plan.ResetAdapted
	}
	return ""
}

// kind is the error kind of an unknown application's read.
func (a appState) kind() string { return kindOf(classified(a.Err)) }

// who is who scaled a stopped application to zero, as the review and the
// gate say it (A23-48).
func (a appState) who() string {
	if a.StoppedByCostGuard {
		return "stopped by the cost guard"
	}
	return "scaled to 0 replicas"
}

// resetLine is the review's line for the application, or "" when this
// deploy resets nothing of it (A23-48, §5.4).
func (a appState) resetLine() string {
	app := terminalText(a.App)
	switch a.state() {
	case plan.ResetUnknown:
		return fmt.Sprintf("%s: its live state could not be read (%s); what this deploy changes there is not known", app, a.kind())
	case plan.ResetStopped:
		return fmt.Sprintf("%s: running 0 replicas (%s); this deploy sets %d", app, a.who(), appReplicas)
	case plan.ResetAdapted:
		return fmt.Sprintf("%s: requests %dm/%dMi (adapted by the kernel at %s); this deploy renders %dm/%dMi, "+
			"which Autopilot raises to its 250m/512Mi floor on a cluster without bursting, until the kernel adapts it again",
			app, a.RequestsLive.CPUMilli, a.RequestsLive.MemMiB, plan.Time(a.AdaptedAt), translate.RequestCPUMilli, translate.RequestMemMiB)
	}
	return ""
}

// atTheLimitLine is the line an interactive run prints, before it asks, for
// an application this deploy may restart while the spending is at its limit
// (A23-48).
func (a appState) atTheLimitLine() string {
	tenant := terminalText(tenantOf(a.Namespace, a.App))
	switch {
	case a.Err != nil:
		return fmt.Sprintf("%s could not be read while the instance's spending is at its limit; if the cost guard stopped it, deploying restarts it", tenant)
	case a.StoppedByCostGuard:
		return fmt.Sprintf("the cost guard stopped %s at the limit; deploying restarts it, and it bills until the kernel's next tick stops it again", tenant)
	}
	return fmt.Sprintf("%s is scaled to 0 replicas while the instance's spending is at its limit; deploying restarts it, "+
		"and the kernel may stop it again at its next tick", tenant)
}

// classifyApp is one application's state from its DeploymentState read
// (A28-5). A read error, a Deployment with no container named after the
// application, and one with no replica count are each unknown: what this
// deploy changes there is not known, and the gate fails closed on it.
func classifyApp(ns, app string, st cluster.DeploymentState, err error, lim limitState) appState {
	a := appState{Namespace: ns, App: app}
	if err == nil && !st.Present {
		return a
	}
	req, named := st.Requests[app]
	switch {
	case err != nil:
	case !named:
		err = withKind(kindDocumentUnreadable, fmt.Errorf("the Deployment %s/%s has no container named %q", ns, app, app))
	case st.Replicas == nil:
		err = withKind(kindDocumentUnreadable, fmt.Errorf("the Deployment %s/%s states no replica count", ns, app))
	}
	if err != nil {
		a.Err = err
		return a
	}
	replicas := *st.Replicas
	a.Present = true
	a.ReplicasLive = &replicas
	a.RequestsLive = &plan.Requests{CPUMilli: req.CPUMilli, MemMiB: req.MemMiB}
	a.AdaptedAt = st.AdaptedAt
	a.adapted = st.AdaptedAt.After(st.LastAppliedAt)
	a.StoppedByCostGuard = replicas == 0 && lim.costStops[tenantOf(ns, app)]
	return a
}

// liveReader is what run reads the instance's live state through: the
// kernel's ledger, the namespaces, and each application's Deployment.
type liveReader interface {
	configMapReader
	Namespaces(ctx context.Context) ([]string, error)
	DeploymentState(ctx context.Context, namespace, name string) (cluster.DeploymentState, error)
}

// readApps reads each of the manifest's applications in namespace ns, which
// exists, in manifest order (A28-5, A28-6). A failed read is that
// application unknown, with the failure's kind, so the gate fails closed on
// it; the exception is a reader's 403 under --plan or --confirm, which is
// the plan's read error (planRead) and refuses the plan.
func readApps(ctx context.Context, rd liveReader, ns string, m parser.Manifest, lim limitState, mode consentMode, name string) ([]appState, error) {
	apps := make([]appState, 0, len(m.Apps))
	for _, app := range m.Apps {
		st, err := rd.DeploymentState(ctx, ns, app.Name)
		if err != nil && mode != consentNone && errors.Is(err, tkube.ErrForbidden) {
			return nil, planRead(mode, err, name)
		}
		apps = append(apps, classifyApp(ns, app.Name, st, err, lim))
	}
	return apps, nil
}

// runLive is what run read of the instance before it deploys.
type runLive struct {
	Limit limitState
	// NamespaceExists is false for a namespace this deploy creates: nothing
	// was read in it, and every application is new.
	NamespaceExists bool
	// Apps are the manifest's applications, in manifest order.
	Apps []appState
}

// readLive reads the ledger, then the namespaces, then, when the target
// namespace exists, each application in it (A23-47's order). The deploy
// plan reads the same three, in the same order, with its block between the
// second and the third (A28-8).
func readLive(ctx context.Context, rd liveReader, ns string, m parser.Manifest, now time.Time, mode consentMode, name string) (runLive, error) {
	live := runLive{Limit: readLimit(ctx, rd, now)}
	var err error
	if live.NamespaceExists, err = namespaceExists(ctx, rd, ns, mode, name); err != nil {
		return runLive{}, err
	}
	if live.Apps, err = liveApps(ctx, rd, ns, m, live.Limit, live.NamespaceExists, mode, name); err != nil {
		return runLive{}, err
	}
	return live, nil
}

// namespaceExists reports whether the target namespace ns is in the
// cluster. A namespace list that fails is an error, never "the namespace is
// absent": that would read every application as new and open the gate
// (A28-6).
func namespaceExists(ctx context.Context, rd liveReader, ns string, mode consentMode, name string) (bool, error) {
	all, err := rd.Namespaces(ctx)
	if err != nil {
		return false, planRead(mode, fmt.Errorf("list the cluster's namespaces: %w", err), name)
	}
	return slices.Contains(all, ns), nil
}

// liveApps is each of the manifest's applications in namespace ns, in
// manifest order: read when ns exists (readApps), and each absent, read
// nowhere, when it does not (§5.4).
func liveApps(ctx context.Context, rd liveReader, ns string, m parser.Manifest, lim limitState, exists bool, mode consentMode, name string) ([]appState, error) {
	if exists {
		return readApps(ctx, rd, ns, m, lim, mode, name)
	}
	apps := make([]appState, 0, len(m.Apps))
	for _, app := range m.Apps {
		apps = append(apps, appState{Namespace: ns, App: app.Name})
	}
	return apps, nil
}

// unchangedAt reports whether now, the application as --confirm reads it
// again after the builds, is what a, as its plan read it, said (A23-6,
// A23-48, A28-10). A read that fails now is a change. An application the
// plan could not read is satisfied by one that shows no reset. Otherwise it
// must be there exactly when the plan found it there — so a Deployment
// found in a namespace the plan found absent is a change — with the replicas
// and requests the plan read.
func (a appState) unchangedAt(now appState) bool {
	switch {
	case now.Err != nil:
		return false
	case a.Err != nil:
		return now.state() == ""
	case a.Present != now.Present:
		return false
	case !a.Present:
		return true
	}
	return *a.ReplicasLive == *now.ReplicasLive && *a.RequestsLive == *now.RequestsLive
}

// resetFact is the application's application_reset fact under the limit
// read as lim, and false when the deploy resets nothing of it (A23-33).
func (a appState) resetFact(lim limitState) (plan.ApplicationResetFact, bool) {
	state := a.state()
	if state == "" {
		return plan.ApplicationResetFact{}, false
	}
	return plan.ApplicationResetFact{
		Type: plan.TypeApplicationReset, Namespace: a.Namespace, App: a.App, State: state,
		StoppedByCostGuard: a.StoppedByCostGuard, LimitReached: lim.Reached,
		ReplicasLive: a.ReplicasLive, ReplicasAfter: appReplicas, RequestsLive: a.RequestsLive,
		RequestsAfter: plan.Requests{CPUMilli: translate.RequestCPUMilli, MemMiB: translate.RequestMemMiB},
	}, true
}

// restartList is A23-48's list of what a deploy would restart, in manifest
// order: each as <ns>/<app> and who stopped it, or "(not read)".
func restartList(apps []appState) string {
	var out []string
	for _, a := range apps {
		if !a.restarts() {
			continue
		}
		why := "not read"
		if a.Err == nil {
			why = a.who()
		}
		out = append(out, fmt.Sprintf("%s (%s)", terminalText(tenantOf(a.Namespace, a.App)), why))
	}
	return strings.Join(out, ", ")
}

// The two endings of the gate's refusal: at the review, before anything is
// built, and at the re-read, after the builds and before anything else.
const (
	msgNothingBuilt  = "The manifest was read; nothing was built or deployed."
	msgBuildsWritten = "The builds were written, and nothing after them was."
)

// msgRunYesAtTheLimit is the gate's refusal (A28-1): run --yes deploys
// nothing while the spending is at its limit. The verbs are the namespace,
// the reason, restartClause's clause, and an ending.
const msgRunYesAtTheLimit = "run --yes would deploy %q while the instance's spending is at its limit (%s)%s; " +
	"confirm it interactively, or run the same command with --plan in place of --yes and confirm the plans it prints. %s"

// atTheLimit is the gate's refusal for a deploy into namespace ns, a usage
// error (exit 2, A28-12), ending as given.
func atTheLimit(ns string, live runLive, ending string) error {
	clause := ""
	if list := restartList(live.Apps); list != "" {
		clause = ", and would restart " + list
	}
	return usagef(msgRunYesAtTheLimit, ns, live.Limit.Reason, clause, ending)
}

// printAtTheLimit prints, for an interactive run while the spending is at
// its limit, the line for each application this deploy may restart.
func printAtTheLimit(w io.Writer, apps []appState) {
	for _, a := range apps {
		if a.restarts() {
			fprintln(w, a.atTheLimitLine())
		}
	}
}
