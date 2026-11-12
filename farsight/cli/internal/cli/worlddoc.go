package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/shrike"
	"github.com/sofmon/farcast/technocore/cost"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// The world document, schema 1: one instance, map-ready (farsight/cli/README.md,
// "farcast world"). Everything here is a pure function of what was gathered
// plus the clock — no I/O, no time.Now — so the golden vectors under
// testdata/world are byte-stable and the read route can later serve the very
// same document from inside the instance.

const worldSchema = 1

const (
	// checkpointStaleAfter is three default checkpoint intervals.
	checkpointStaleAfter = 15 * time.Minute
	// lineStaleAfter is how long since a line was last observed before it
	// is drawn as stale; it is also the window a refusal or a drift must
	// fall in to raise an alert.
	lineStaleAfter = time.Hour
	// keeperSeenWithin is how recently a keeper's tunnel row must have been
	// seen for the keeper to read as healthy.
	keeperSeenWithin = 24 * time.Hour
	// hostCap is how many hosts a document draws.
	hostCap = 200
	// managedSelector discovers the namespaces Planck created.
	managedSelector = "app.kubernetes.io/managed-by=farcast"
)

// Evidence, strongest first. "planned" is never emitted: nothing in a live
// world is decided and unbuilt.
const (
	evidenceObserved = "observed"
	evidenceDenied   = "denied"
	evidenceDeclared = "declared"
)

func evidenceRank(e string) int {
	switch e {
	case evidenceObserved:
		return 0
	case evidenceDenied:
		return 1
	default:
		return 2
	}
}

// Component and application states.
const (
	stateRunning     = "running"
	stateStarting    = "starting"
	stateStopped     = "stopped"
	stateNotDeployed = "not_deployed"
	stateUnknown     = "unknown"
)

// Component roles.
const (
	roleBoundary = "boundary"
	roleMonitor  = "monitor"
	roleKernel   = "kernel"
	roleStorage  = "storage"
)

// ------------------------------------------------------------ wire types

// buildStamp is the CLI that wrote a document: an input, like the clock, so a
// vector does not change with the build that checks it.
type buildStamp struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

func currentStamp() buildStamp {
	info := buildinfo.Get()
	return buildStamp{Version: info.Version, Commit: info.Commit}
}

// wireTime is a time on the wire: UTC, whole seconds, RFC 3339 — never Go's
// default RFC3339Nano, whose fractional seconds a strict ISO 8601 decoder
// refuses.
type wireTime time.Time

func (t wireTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).UTC().Truncate(time.Second).Format(time.RFC3339))
}

// UnmarshalJSON reads a time back, so a document round-trips in tests.
func (t *wireTime) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	*t = wireTime(v)
	return nil
}

// optTime is t on the wire, or null when it is the zero time.
func optTime(t time.Time) *wireTime {
	if t.IsZero() {
		return nil
	}
	w := wireTime(t)
	return &w
}

// cents is the one rounding rule for money on the wire.
func cents(usd float64) int64 { return int64(math.Round(usd * 100)) }

func ptr[T any](v T) *T { return &v }

// marshalJSON is json.Marshal without HTML escaping, for a MarshalJSON method:
// the printer writes documents unescaped, and a part encoded on its own must
// read the same as the whole.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// notRead is a part of the document that could not be read.
type notRead struct {
	Read bool `json:"read"`
}

// sectionProblem is why a section could not be read: a kind from the closed
// set and the message that explains it.
type sectionProblem struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// sectionStatus is one section's outcome: read, failed, or skipped because
// there is nothing to read (a seal with no keyholder recorded).
type sectionStatus struct {
	Read    bool            `json:"read"`
	Skipped string          `json:"skipped,omitempty"`
	Error   *sectionProblem `json:"error,omitempty"`
}

type worldSections struct {
	Spend   sectionStatus `json:"spend"`
	Apps    sectionStatus `json:"apps"`
	Policy  sectionStatus `json:"policy"`
	Network sectionStatus `json:"network"`
	Seal    sectionStatus `json:"seal"`
}

type worldDoc struct {
	Schema      int           `json:"schema"`
	GeneratedAt wireTime      `json:"generated_at"`
	FarCast     buildStamp    `json:"farcast"`
	Instance    worldInstance `json:"instance"`
	Groups      []worldGroup  `json:"groups"`
	Hosts       []worldHost   `json:"hosts"`
	Lines       []any         `json:"lines"`
	Devices     []worldDevice `json:"devices"`
	Alerts      []worldAlert  `json:"alerts"`
	Sections    worldSections `json:"sections"`
}

type worldInstance struct {
	Name         string           `json:"name"`
	Status       string           `json:"status"`
	CloudLogging string           `json:"cloud_logging"`
	Spend        any              `json:"spend"`   // notRead or worldSpend
	Network      any              `json:"network"` // notRead or worldNetwork
	Components   []worldComponent `json:"components"`
	HostsOmitted int              `json:"hosts_omitted"`
	Caveats      []string         `json:"caveats"`
}

type worldSpend struct {
	Read               bool      `json:"read"`
	Currency           string    `json:"currency"`
	Period             string    `json:"period"`
	PeriodStart        *wireTime `json:"period_start"`
	PeriodEnd          *wireTime `json:"period_end"`
	TotalCents         int64     `json:"total_cents"`
	ExpectedCents      int64     `json:"expected_cents"`
	ConfirmedCents     *int64    `json:"confirmed_cents"`
	HasConfirmation    bool      `json:"has_confirmation"`
	ConfirmedThrough   *wireTime `json:"confirmed_through"`
	LimitCents         *int64    `json:"limit_cents"`
	RecordedLimitCents *int64    `json:"recorded_limit_cents"`
	Level              string    `json:"level"`
	ObservedAt         *wireTime `json:"observed_at"`
	CheckpointStale    bool      `json:"checkpoint_stale"`
	NotMetered         []string  `json:"not_metered"`
	Caveats            []string  `json:"caveats"`
}

type worldNetwork struct {
	Read            bool      `json:"read"`
	Replica         *string   `json:"replica"`
	Since           *wireTime `json:"since"`
	FatLineReplicas *int      `json:"fatline_replicas"`
}

type worldComponent struct {
	Role    string  `json:"role"`
	Name    string  `json:"name"`
	State   string  `json:"state"`
	Ready   *int    `json:"ready"`
	Desired *int    `json:"desired"`
	Version *string `json:"version"`
}

type worldGroup struct {
	Namespace  string           `json:"namespace"`
	Metered    *bool            `json:"metered"`
	Provenance *worldProvenance `json:"provenance"`
	Apps       []worldApp       `json:"apps"`
}

type worldProvenance struct {
	Repository     string    `json:"repository"`
	Ref            string    `json:"ref"`
	Commit         string    `json:"commit"`
	ManifestDigest string    `json:"manifest_digest"`
	DeployedAt     *wireTime `json:"deployed_at"`
	StorageWired   bool      `json:"storage_wired"`
}

type worldApp struct {
	Name       string  `json:"name"`
	State      string  `json:"state"`
	Ready      *int    `json:"ready"`
	Desired    *int    `json:"desired"`
	StoppedBy  *string `json:"stopped_by"`
	MonthCents *int64  `json:"month_cents"`
}

type worldHost struct {
	Name   string   `json:"name"`
	SeenAs []string `json:"seen_as"`
}

type lineEnd struct {
	App       string `json:"app,omitempty"`
	Host      string `json:"host,omitempty"`
	Device    string `json:"device,omitempty"`
	Component string `json:"component,omitempty"`
}

type linePort struct {
	Port             *int      `json:"port"`
	Evidence         string    `json:"evidence"`
	Count            *int64    `json:"count"`
	Fails            *int64    `json:"fails"`
	Reason           *string   `json:"reason"`
	LastSeen         *wireTime `json:"last_seen"`
	NoLongerDeclared bool      `json:"no_longer_declared"`
}

type egressLine struct {
	Kind     string     `json:"kind"`
	From     lineEnd    `json:"from"`
	To       lineEnd    `json:"to"`
	Evidence string     `json:"evidence"`
	Ports    []linePort `json:"ports"`
	Stale    bool       `json:"stale"`
	Drift    *bool      `json:"drift"`
	LastSeen *wireTime  `json:"last_seen"`
	Since    *wireTime  `json:"since"`
}

type tunnelLine struct {
	Kind      string  `json:"kind"`
	From      lineEnd `json:"from"`
	To        lineEnd `json:"to"`
	Evidence  string  `json:"evidence"`
	LabelHint string  `json:"label_hint"`
}

type keeperLine struct {
	Kind     string    `json:"kind"`
	From     lineEnd   `json:"from"`
	To       lineEnd   `json:"to"`
	Evidence string    `json:"evidence"`
	LastSeen *wireTime `json:"last_seen"`
	Stale    bool      `json:"stale"`
}

type watchLine struct {
	Kind     string    `json:"kind"`
	From     lineEnd   `json:"from"`
	To       lineEnd   `json:"to"`
	Evidence string    `json:"evidence"`
	Since    *wireTime `json:"since"`
}

type storageLine struct {
	Kind      string  `json:"kind"`
	From      lineEnd `json:"from"`
	To        lineEnd `json:"to"`
	Evidence  string  `json:"evidence"`
	LabelHint string  `json:"label_hint"`
}

type worldDevice struct {
	ID     string `json:"id"`
	Role   string `json:"role"`
	Name   string `json:"name,omitempty"`
	Health string `json:"health,omitempty"`
}

type alertSubject struct {
	App       string `json:"app,omitempty"`
	Component string `json:"component,omitempty"`
	Device    string `json:"device,omitempty"`
	Instance  bool   `json:"instance,omitempty"`
}

func (s alertSubject) key() string {
	switch {
	case s.App != "":
		return "app:" + s.App
	case s.Component != "":
		return "component:" + s.Component
	case s.Device != "":
		return "device:" + s.Device
	default:
		return "instance"
	}
}

type worldAlert struct {
	ID       string       `json:"id"`
	Kind     string       `json:"kind"`
	Severity string       `json:"severity"`
	Subject  alertSubject `json:"subject"`
	Title    string       `json:"title"`
}

const (
	severityCritical = "critical"
	severityWarning  = "warning"
)

// ------------------------------------------------------------ inputs

// worldInputs is everything a world document is built from. The gather layer
// fills it by reading; a vector fills it with literals.
type worldInputs struct {
	Now   time.Time
	Stamp buildStamp
	Name  string
	Meta  *config.InstanceMetadata

	Apps    appsInput
	Spend   spendInput
	Policy  policyInput
	Network networkInput
	Seal    sealInput
}

// appsInput is the apps section: FarCast's own workloads, the namespaces the
// cluster lists as FarCast's, each one's workloads, and the kernel's metered
// list.
type appsInput struct {
	// Problem is a workload or namespace read that failed. Every workload
	// state is then unknown.
	Problem    *sectionProblem
	System     []cluster.Workload
	Namespaces []string
	Workloads  map[string][]cluster.Workload
	// Meter is the technocore-namespaces document.
	Meter meterInput
}

type meterInput struct {
	Problem    *sectionProblem
	Namespaces []string
}

// spendInput is the kernel's checkpoint, as the ConfigMap holds it.
type spendInput struct {
	Problem *sectionProblem
	Found   bool
	Raw     string
}

type policyInput struct {
	Problem *sectionProblem
	Doc     *policy.Document
}

type networkInput struct {
	Problem *sectionProblem
	// Tunnel is true when the tunnel opened: that read is the tunnel line's
	// evidence, whether or not the monitor then answered.
	Tunnel   bool
	Snapshot shrike.Snapshot
	// OperatorToken is this machine's own leaf's token, which tells the
	// operator's tunnel rows from another leaf's.
	OperatorToken string
}

type sealInput struct {
	Problem  *sectionProblem
	Skipped  bool
	Replicas []replicaRead
}

type replicaRead struct {
	Ordinal int
	State   *keyholder.State
	Problem *sectionProblem
}

// ------------------------------------------------------------ the builder

// worldBuilder holds the document while it is built.
type worldBuilder struct {
	in   worldInputs
	meta *config.InstanceMetadata
	now  time.Time
	doc  worldDoc

	spendRead bool
	spendBody *worldSpend
	byApp     map[string]float64

	groups map[string]*worldGroup
	// The kernel's metered list, whether it was read, and the namespaces
	// this machine's record says the kernel was deployed to meter: a group
	// is metered by the same rule whenever it is first named.
	meterRead     bool
	metered       map[string]bool
	recordMetered map[string]bool
	// undrawn counts, per namespace, the policy and monitor rows that name an
	// application no group can hold — farcast-system's — so they are said
	// rather than lost.
	undrawn map[string]int
	// declared is every (tenant, host key) the policy declares.
	declared map[string]bool
	// hostSeen is every raw spelling of each host key.
	hostSeen map[string]map[string]bool
	egress   map[string]*egressAcc

	lines  []lineEntry
	alerts []worldAlert

	caveats        []string
	spendCaveats   []string
	fatlineDesired *int
}

type egressAcc struct {
	tenant, host string
	ports        []linePort
	drift        bool
}

// buildWorld is the whole document from its inputs. Pure: the same inputs
// give the same bytes.
func buildWorld(in worldInputs) worldDoc {
	b := &worldBuilder{
		in:       in,
		meta:     in.Meta,
		now:      in.Now.UTC().Truncate(time.Second),
		groups:   map[string]*worldGroup{},
		undrawn:  map[string]int{},
		declared: map[string]bool{},
		hostSeen: map[string]map[string]bool{},
		egress:   map[string]*egressAcc{},
	}
	if b.meta == nil {
		b.meta = &config.InstanceMetadata{}
	}
	b.doc = worldDoc{
		Schema:      worldSchema,
		GeneratedAt: wireTime(b.now),
		FarCast:     in.Stamp,
		Instance: worldInstance{
			Name:         in.Name,
			Status:       b.meta.Status,
			CloudLogging: cloudLoggingOf(b.meta.CloudLogging),
			Spend:        notRead{},
			Network:      notRead{},
		},
	}
	b.components()
	b.spend()
	b.groupsAndApps()
	b.monthCents()
	b.policyLines()
	b.networkLines()
	b.storageLines()
	b.hostsAndEgress()
	b.devicesAndKeepers()
	b.raiseAlerts()
	b.sections()
	b.finish()
	return b.doc
}

// cloudLoggingOf maps the record's logging setting onto the wire: what the
// provider read back as system-only, never verified, or something else.
func cloudLoggingOf(v string) string {
	switch v {
	case config.CloudLoggingSystem:
		return "system_only"
	case "":
		return "unverified"
	default:
		return stateUnknown
	}
}

// problem is a section problem with every address, cloud name and account in
// its message replaced by what it is. A kubectl error can name the control
// plane, a tunnel error the carrier, and an API server's refusal or gcloud's
// credential error the account it ran as: the document never carries any of
// them.
func (b *worldBuilder) problem(p *sectionProblem) *sectionProblem {
	if p == nil {
		return nil
	}
	return &sectionProblem{Kind: p.Kind, Message: scrubMessage(p.Message, b.meta)}
}

// emailLike is anything shaped like an account: a person's, a service
// account's, or the work identity a token cached under this instance's own
// context was minted for.
var emailLike = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

func scrubMessage(msg string, meta *config.InstanceMetadata) string {
	// Accounts first, before a project inside a service account's address
	// is replaced and leaves the rest of the address behind. The pinned one
	// by name, whatever its case — GKE's refusals spell it as the token
	// does — and then anything else shaped like one.
	if a := strings.TrimSpace(meta.GCloudAccount); a != "" {
		msg = regexp.MustCompile("(?i)"+regexp.QuoteMeta(a)).ReplaceAllLiteralString(msg, "<account>")
	}
	msg = emailLike.ReplaceAllLiteralString(msg, "<account>")

	type sub struct{ from, to string }
	var subs []sub
	add := func(from, to string) {
		if strings.TrimSpace(from) != "" {
			subs = append(subs, sub{from, to})
		}
	}
	if meta.Carrier != nil {
		add(meta.Carrier.Endpoint, "<carrier>")
		if host, _, ok := strings.Cut(meta.Carrier.Endpoint, ":"); ok {
			add(host, "<carrier>")
		}
	}
	add(meta.Endpoint, "<control plane>")
	if meta.Storage != nil {
		add(meta.Storage.Bucket, "<bucket>")
	}
	add(meta.Cluster, "<cluster>")
	add(meta.Project, "<project>")
	// Longest first, so a host:port is replaced whole before its host is.
	sort.SliceStable(subs, func(i, j int) bool { return len(subs[i].from) > len(subs[j].from) })
	for _, s := range subs {
		msg = strings.ReplaceAll(msg, s.from, s.to)
	}
	return msg
}

func (b *worldBuilder) appsRead() bool { return b.in.Apps.Problem == nil }

func (b *worldBuilder) networkRead() bool { return b.in.Network.Problem == nil }

func (b *worldBuilder) policyRead() bool { return b.in.Policy.Problem == nil }

// workloadState is a workload's state from its counts.
func workloadState(ready, desired int) string {
	switch {
	case desired == 0:
		return stateStopped
	case ready < desired:
		return stateStarting
	default:
		return stateRunning
	}
}

// digestVersion is an image's digest, shortened: "sha256:" and its first 12
// hex characters. Empty when the reference is not digest-pinned.
func digestVersion(image string) string {
	_, digest, ok := strings.Cut(image, "@sha256:")
	if !ok || len(digest) < 12 {
		return ""
	}
	return "sha256:" + digest[:12]
}

// matchedVersion is the version of the image the record says was deployed,
// when the cluster runs exactly that image. A cluster running something else
// gets no version: it is reported, never guessed.
func matchedVersion(images []string, recorded string) *string {
	if recorded == "" || !slices.Contains(images, recorded) {
		return nil
	}
	if v := digestVersion(recorded); v != "" {
		return &v
	}
	return nil
}

func (b *worldBuilder) systemWorkload(name string) *cluster.Workload {
	for i := range b.in.Apps.System {
		if b.in.Apps.System[i].Name == name {
			return &b.in.Apps.System[i]
		}
	}
	return nil
}

// components are FarCast's own four, sorted by role.
func (b *worldBuilder) components() {
	meta := b.meta
	recorded := func(r *config.Registry) string {
		if r == nil {
			return ""
		}
		return r.FatLineDigest
	}
	kernelImage, keyholderImage := "", ""
	if meta.Kernel != nil {
		kernelImage = meta.Kernel.Image
	}
	if meta.Keyholder != nil {
		keyholderImage = meta.Keyholder.Image
	}
	component := func(role, name, image string) worldComponent {
		c := worldComponent{Role: role, Name: name, State: stateUnknown}
		if !b.appsRead() {
			return c
		}
		w := b.systemWorkload(name)
		if w == nil {
			c.State = stateNotDeployed
			return c
		}
		c.State = workloadState(w.Ready, w.Desired)
		c.Ready, c.Desired = ptr(w.Ready), ptr(w.Desired)
		c.Version = matchedVersion(w.Images, image)
		return c
	}
	boundary := component(roleBoundary, fldeploy.DefaultName, recorded(meta.Registry))
	if b.appsRead() {
		if w := b.systemWorkload(fldeploy.DefaultName); w != nil {
			b.fatlineDesired = ptr(w.Desired)
		}
	}

	// The monitor is a container in FatLine's Pod, not a workload of its
	// own: its counts are FatLine's, and whether it is running is what the
	// tunnel read says.
	monitor := worldComponent{Role: roleMonitor, Name: "shrike", State: stateUnknown}
	if b.appsRead() {
		w := b.systemWorkload(fldeploy.DefaultName)
		switch {
		case w == nil || len(w.Images) < 2:
			monitor.State = stateNotDeployed
		default:
			monitor.Ready, monitor.Desired = ptr(w.Ready), ptr(w.Desired)
			if v := digestVersion(w.Images[1]); v != "" {
				monitor.Version = &v
			}
			switch {
			case w.Desired == 0:
				monitor.State = stateStopped
			case b.networkRead():
				monitor.State = stateRunning
			default:
				monitor.State = stateUnknown
			}
		}
	}
	kernelC := component(roleKernel, tcdeploy.DefaultName, kernelImage)
	storage := component(roleStorage, dsdeploy.DefaultName, keyholderImage)
	b.doc.Instance.Components = []worldComponent{boundary, kernelC, monitor, storage}
	sort.Slice(b.doc.Instance.Components, func(i, j int) bool {
		return b.doc.Instance.Components[i].Role < b.doc.Instance.Components[j].Role
	})
}

func (b *worldBuilder) component(role string) *worldComponent {
	for i := range b.doc.Instance.Components {
		if b.doc.Instance.Components[i].Role == role {
			return &b.doc.Instance.Components[i]
		}
	}
	return nil
}

// notMeteredFacts are the charges the kernel cannot see from inside the
// cluster: 'costs' prints them, 'world' carries them as data, and both read
// this one list.
func notMeteredFacts() []string {
	return []string{
		"data through the carrier (egress and load-balancer processing)",
		"bucket storage and operations",
		"registry storage",
		fmt.Sprintf("the cluster's own managed workloads (modelled at about $%d/month in the floor, unverified)", emptyClusterMonthlyUSD),
		"the GKE cluster fee, if the free credit is spent on another cluster",
	}
}

// levelOf maps the kernel's own level onto the wire. The level comes from the
// checkpoint and only from there: it is never recomputed here, because the
// level an operator is shown must be the one enforcement acts on.
func levelOf(s string) string {
	switch s {
	case cost.LevelOK.String():
		return "ok"
	case cost.LevelWarn50.String():
		return "warn50"
	case cost.LevelWarn75.String():
		return "warn75"
	case cost.LevelWarn90.String():
		return "warn90"
	case cost.LevelReached.String():
		return "reached"
	default:
		return stateUnknown
	}
}

// spendProblem is the spend section's own failure, from what was gathered.
func (b *worldBuilder) spendProblem() (*sectionProblem, kernel.Checkpoint, *cost.Ledger) {
	in := b.in.Spend
	if in.Problem != nil {
		return in.Problem, kernel.Checkpoint{}, nil
	}
	if !in.Found || strings.TrimSpace(in.Raw) == "" {
		return &sectionProblem{Kind: kindNotCheckpointed, Message: fmt.Sprintf(
			"the kernel in %q has not checkpointed yet; it writes one within a few minutes of starting", b.in.Name)}, kernel.Checkpoint{}, nil
	}
	cp, ledger, err := decodeCheckpoint(in.Raw)
	if err != nil {
		return &sectionProblem{Kind: kindOf(err), Message: err.Error()}, cp, nil
	}
	return nil, cp, ledger
}

func (b *worldBuilder) spend() {
	p, cp, ledger := b.spendProblem()
	if p != nil {
		b.doc.Sections.Spend = sectionStatus{Error: b.problem(p)}
		return
	}
	b.doc.Sections.Spend = sectionStatus{Read: true}
	b.spendRead = true
	b.byApp = ledger.ByApp()

	accrual := ledger.Accrued()
	start, end := ledger.Period()
	obs := cp.Observed
	s := worldSpend{
		Read:            true,
		Currency:        currencyOf(b.meta),
		Period:          b.meta.CostLimit.Period,
		PeriodStart:     optTime(start),
		PeriodEnd:       optTime(end),
		TotalCents:      cents(accrual.Total),
		ExpectedCents:   cents(accrual.Expected),
		HasConfirmation: accrual.HasConfirmation,
		Level:           levelOf(obs.Level),
		NotMetered:      notMeteredFacts(),
	}
	if accrual.HasConfirmation {
		s.ConfirmedCents = ptr(cents(accrual.Confirmed))
		s.ConfirmedThrough = optTime(accrual.ConfirmedThrough)
	}
	var caveats []string
	if obs.Limit > 0 {
		s.LimitCents = ptr(cents(obs.Limit))
	} else {
		caveats = append(caveats, "the kernel published no limit")
	}
	if b.meta.CostLimit.Amount > 0 {
		s.RecordedLimitCents = ptr(cents(b.meta.CostLimit.Amount))
	}
	if s.LimitCents != nil && s.RecordedLimitCents != nil && *s.LimitCents != *s.RecordedLimitCents {
		caveats = append(caveats, fmt.Sprintf(
			"the kernel is enforcing %s %.2f and this machine has %s %.2f recorded; the cluster acts on its own until 'farcast kernel deploy %s' redeploys it",
			s.Currency, obs.Limit, s.Currency, b.meta.CostLimit.Amount, b.in.Name))
	}
	observed := obs.At
	if observed.IsZero() {
		observed = cp.Last
	}
	s.ObservedAt = optTime(observed)
	s.CheckpointStale = observed.IsZero() || observed.UTC().Truncate(time.Second).Before(b.now.Add(-checkpointStaleAfter))
	for _, d := range accrual.Discrepancies {
		caveats = append(caveats, "billing disagrees with the model beyond the clamp, and the estimate stands: "+d.String())
	}
	if obs.Incomplete {
		for _, u := range obs.Unreachable {
			caveats = append(caveats, "the kernel could not read a namespace it meters, so these figures are a floor: "+u)
		}
		if len(obs.Unreachable) == 0 {
			caveats = append(caveats, "the kernel could not read every namespace it meters, so these figures are a floor")
		}
	}
	if obs.Unclassified > 0 {
		caveats = append(caveats, fmt.Sprintf("%s carry no tier label and are protected from a cost shutdown as a result",
			plural(obs.Unclassified, "pod", "pods")))
	}
	if obs.Carrier == string(kernel.CarrierUnobserved) {
		caveats = append(caveats, "the kernel could not read the carrier's Service, so it is billing it as present")
	}
	b.spendCaveats = caveats
	b.spendBody = &s
}

// tenantOf is an application's id on the wire: namespace/app.
func tenantOf(ns, app string) string { return ns + "/" + app }

// group is the group for a namespace, created when it is first named —
// whoever names it, the cluster or the policy or the monitor — with its
// provenance and whether it is metered. The system namespace is never a
// group: its workloads are the components.
func (b *worldBuilder) group(ns string) *worldGroup {
	if ns == "" || ns == tcdeploy.DefaultNamespace {
		return nil
	}
	g := b.groups[ns]
	if g == nil {
		g = &worldGroup{Namespace: ns, Apps: []worldApp{}, Metered: b.meteredOf(ns)}
		if dep, ok := b.meta.Deployments[ns]; ok {
			g.Provenance = &worldProvenance{
				Repository: withoutUserinfo(dep.Repository), Ref: dep.Ref, Commit: dep.Commit,
				ManifestDigest: dep.ManifestDigest, DeployedAt: optTime(dep.DeployedAt),
				StorageWired: dep.StorageWired,
			}
		}
		b.groups[ns] = g
	}
	return g
}

// meteredOf is whether the kernel meters a namespace: true when its list or
// this machine's record names it, false when the list was read and neither
// does, and unknown when the list could not be read.
func (b *worldBuilder) meteredOf(ns string) *bool {
	switch {
	case b.metered[ns] || b.recordMetered[ns]:
		return ptr(true)
	case b.meterRead:
		return ptr(false)
	}
	return nil
}

func (b *worldBuilder) app(ns, name string) *worldApp {
	g := b.groups[ns]
	if g == nil {
		return nil
	}
	for i := range g.Apps {
		if g.Apps[i].Name == name {
			return &g.Apps[i]
		}
	}
	return nil
}

// ensureApp makes sure an application a line or an alert names is in its
// group. An application the policy or the monitor names that the cluster does
// not run is added as not deployed — or unknown, when the workloads could not
// be read — so nothing on the map points at nothing.
func (b *worldBuilder) ensureApp(ns, name, namedBy string) bool {
	g := b.group(ns)
	if g == nil || name == "" {
		b.undrawn[ns]++
		return false
	}
	if b.app(ns, name) != nil {
		return true
	}
	state := stateUnknown
	if b.appsRead() {
		state = stateNotDeployed
		b.caveats = append(b.caveats, fmt.Sprintf("%s is named by %s but not running in the cluster", tenantOf(ns, name), namedBy))
	}
	g.Apps = append(g.Apps, worldApp{Name: name, State: state})
	return true
}

func (b *worldBuilder) groupsAndApps() {
	meta := b.meta
	apps := b.in.Apps
	b.meterRead = apps.Meter.Problem == nil
	b.metered = map[string]bool{}
	if b.meterRead {
		for _, ns := range apps.Meter.Namespaces {
			b.metered[strings.TrimSpace(ns)] = true
		}
	}
	b.recordMetered = map[string]bool{}
	if meta.Kernel != nil {
		for _, ns := range meta.Kernel.Namespaces {
			b.recordMetered[ns] = true
		}
	}

	// Discovery: the cluster's own list, the kernel's metered list and this
	// machine's record. The policy and the monitor may name more, later.
	if b.appsRead() {
		for _, ns := range apps.Namespaces {
			b.group(ns)
		}
	}
	for ns := range b.metered {
		b.group(ns)
	}
	for ns := range b.recordMetered {
		b.group(ns)
	}
	for ns := range meta.Deployments {
		b.group(ns)
	}
	if b.appsRead() {
		for ns, ws := range apps.Workloads {
			g := b.group(ns)
			if g == nil {
				continue
			}
			for _, w := range ws {
				g.Apps = append(g.Apps, worldApp{
					Name: w.Name, State: workloadState(w.Ready, w.Desired),
					Ready: ptr(w.Ready), Desired: ptr(w.Desired),
				})
			}
		}
	}
}

// monthCents gives each application its accrual this period, where the
// kernel's ledger can tell it apart. The ledger keys spending by application
// name alone, so a name that runs in two namespaces — the system one included
// — is two applications the ledger has added together.
func (b *worldBuilder) monthCents() {
	if !b.spendRead {
		return
	}
	where := map[string][]string{}
	if b.appsRead() {
		for _, w := range b.in.Apps.System {
			where[w.Name] = append(where[w.Name], tcdeploy.DefaultNamespace)
		}
	}
	for ns, g := range b.groups {
		for _, a := range g.Apps {
			where[a.Name] = append(where[a.Name], ns)
		}
	}
	for name, nss := range where {
		if len(nss) < 2 {
			continue
		}
		sort.Strings(nss)
		b.spendCaveats = append(b.spendCaveats, fmt.Sprintf(
			"%s runs in more than one namespace (%s); the kernel's ledger keys spending by application name alone, so their shares cannot be told apart",
			name, strings.Join(nss, ", ")))
	}
	for _, g := range b.groups {
		if g.Metered == nil || !*g.Metered {
			// Not metered, or not known to be: the ledger holds nothing
			// for it, and nothing is not a zero.
			continue
		}
		for i := range g.Apps {
			a := &g.Apps[i]
			if len(where[a.Name]) > 1 {
				continue
			}
			a.MonthCents = ptr(cents(b.byApp[a.Name]))
		}
	}
}

// hostKey is how two spellings of a host are found to be one: lower case, no
// surrounding space, no trailing dot — the rule Shrike and FatLine compare by.
func hostKey(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

func (b *worldBuilder) seeHost(raw string) string {
	k := hostKey(raw)
	if k == "" {
		return ""
	}
	if b.hostSeen[k] == nil {
		b.hostSeen[k] = map[string]bool{}
	}
	b.hostSeen[k][raw] = true
	return k
}

func (b *worldBuilder) egressFor(tenant, host string) *egressAcc {
	key := tenant + "\x00" + host
	e := b.egress[key]
	if e == nil {
		e = &egressAcc{tenant: tenant, host: host}
		b.egress[key] = e
	}
	return e
}

// portOf reads a port as a number, or nothing.
func portOf(s string) *int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 || n > 65535 {
		return nil
	}
	return &n
}

// policyLines is the declared half: every host each application's policy
// entry names.
func (b *worldBuilder) policyLines() {
	if !b.policyRead() || b.in.Policy.Doc == nil {
		return
	}
	for _, app := range b.in.Policy.Doc.Apps {
		if !b.ensureApp(app.Namespace, app.Name, "the egress policy") {
			continue
		}
		tenant := tenantOf(app.Namespace, app.Name)
		for _, ext := range app.External {
			k := b.seeHost(ext.Host)
			if k == "" {
				continue
			}
			b.declared[tenant+"\x00"+k] = true
			e := b.egressFor(tenant, k)
			e.ports = append(e.ports, linePort{Evidence: evidenceDeclared, Reason: ptr(ext.Reason)})
		}
	}
}

// recent reports whether t falls within the stale window of now.
func (b *worldBuilder) recent(t time.Time) bool { return b.within(t, lineStaleAfter) }

// within reports whether t falls within d of now, to the second.
func (b *worldBuilder) within(t time.Time, d time.Duration) bool {
	return !t.IsZero() && !t.UTC().Truncate(time.Second).Before(b.now.Add(-d))
}

// networkLines is the counted half: what FatLine allowed and refused, as the
// monitor's picture holds it.
func (b *worldBuilder) networkLines() {
	if !b.networkRead() {
		return
	}
	snap := b.in.Network.Snapshot
	unattributed := 0
	for _, row := range snap.Allowed {
		if row.App == "" || row.Namespace == "" {
			unattributed++
			continue
		}
		if !b.ensureApp(row.Namespace, row.App, "the monitor") {
			continue
		}
		k := b.seeHost(row.Host)
		if k == "" {
			continue
		}
		tenant := tenantOf(row.Namespace, row.App)
		e := b.egressFor(tenant, k)
		port := linePort{
			Port: portOf(row.Port), Evidence: evidenceObserved,
			Count: ptr(row.Allows), Fails: ptr(row.Fails), LastSeen: optTime(row.LastSeen),
		}
		if b.policyRead() && !b.declared[tenant+"\x00"+k] {
			if b.isDrift(row.Namespace, row.LastSeen) {
				e.drift = true
			} else {
				port.NoLongerDeclared = true
			}
		}
		e.ports = append(e.ports, port)
	}
	if unattributed > 0 {
		b.caveats = append(b.caveats, fmt.Sprintf("%s allowed by FatLine name no application and are not drawn",
			plural(unattributed, "monitor row", "monitor rows")))
	}
	for _, v := range snap.Violations {
		if v.App == "" || v.Namespace == "" {
			continue // unattributed: an alert on the boundary, not a line
		}
		if !b.ensureApp(v.Namespace, v.App, "the monitor") {
			continue
		}
		k := b.seeHost(v.Host)
		if k == "" {
			continue
		}
		e := b.egressFor(tenantOf(v.Namespace, v.App), k)
		e.ports = append(e.ports, linePort{
			Port: portOf(v.Port), Evidence: evidenceDenied,
			Count: ptr(v.Count), Reason: ptr(v.Reason), LastSeen: optTime(v.LastSeen),
		})
	}
}

// isDrift is an allowed host the application's current policy does not
// declare, seen recently, and after this namespace was last deployed from
// here. Anything older is a host a redeploy removed: the monitor's tables
// live as long as its Pod, and a removed host is not drift.
func (b *worldBuilder) isDrift(ns string, lastSeen time.Time) bool {
	if !b.recent(lastSeen) {
		return false
	}
	if dep, ok := b.meta.Deployments[ns]; ok && !dep.DeployedAt.IsZero() {
		return lastSeen.After(dep.DeployedAt)
	}
	return true
}

// storageLines are declared lines from each application to storage, where
// this machine's record says its run wired storage and the keyholder is
// there. The keyholder keeps no per-application counters, so these are never
// observed.
func (b *worldBuilder) storageLines() {
	st := b.component(roleStorage)
	if st == nil || st.State == stateNotDeployed {
		return
	}
	for _, ns := range keysSorted(b.groups) {
		g := b.groups[ns]
		if g.Provenance == nil {
			b.caveats = append(b.caveats, "storage wiring unknown for "+ns)
			continue
		}
		if !g.Provenance.StorageWired {
			continue
		}
		for _, a := range g.Apps {
			if a.State == stateNotDeployed {
				continue
			}
			b.lines = append(b.lines, lineEntry{
				key: lineKey("storage", tenantOf(ns, a.Name), roleStorage),
				body: storageLine{Kind: "storage", From: lineEnd{App: tenantOf(ns, a.Name)},
					To: lineEnd{Component: roleStorage}, Evidence: evidenceDeclared, LabelHint: "wired_not_counted"},
			})
		}
	}
}

type lineEntry struct {
	key  string
	body any
}

func lineKey(kind, from, to string) string { return kind + "\x00" + from + "\x00" + to }

func keysSorted[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
