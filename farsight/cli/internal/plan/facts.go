package plan

// The fact types of ADR 0023 M2.6 (§9.4, as A23-33 amends it). Every one is a
// struct whose first field is Type, holding its FactType word; none has a map,
// a float or an omitempty field, so every field is always printed and always
// covered by the digest. An optional object is a pointer, printed as null.
// Money is integer cents, CPU integer millicores, memory integer MiB, and a
// time a string written by Time.
//
// M2.7 adds MigrateFact; M2.8 adds GrantFact and GitCredentialFact.

// The type words, one per fact type.
const (
	TypeCost             = "cost"
	TypeImage            = "image"
	TypeWrite            = "write"
	TypeMint             = "mint"
	TypeRestart          = "restart"
	TypeCloud            = "cloud"
	TypeKernelSettings   = "kernel_settings"
	TypeMeter            = "meter"
	TypeConfirmation     = "confirmation"
	TypePin              = "pin"
	TypeRotation         = "rotation"
	TypeFetch            = "fetch"
	TypeRun              = "run"
	TypeBuild            = "build"
	TypeApplicationReset = "application_reset"
	TypeReader           = "reader"
	TypeNotice           = "notice"
)

// ------------------------------------------------------------------ cost

// CostFact is what the command would cost against the instance's limit: the
// standing workloads it leaves running, its one-off Jobs, and the instance's
// floor.
type CostFact struct {
	Type       string `json:"type"`
	Currency   string `json:"currency"`
	Period     string `json:"period"`
	LimitCents int64  `json:"limit_cents"`
	// Standing and OneOff come in the order the command presents them.
	Standing []StandingCost `json:"standing"`
	OneOff   []OneOffCost   `json:"one_off"`
	// FloorMonthCents and BelowFloor come from the command's own floor.
	// BelowFloor is consented to by confirming the plan; it is never a block.
	FloorMonthCents int64   `json:"floor_month_cents"`
	BelowFloor      bool    `json:"below_floor"`
	Pricing         Pricing `json:"pricing"`
}

// StandingCost is one workload that keeps running, and bills, after the
// command.
type StandingCost struct {
	What       string `json:"what"`
	Replicas   int    `json:"replicas"`
	CPUMilli   int64  `json:"cpu_milli"`
	MemMiB     int64  `json:"mem_mib"`
	MonthCents int64  `json:"month_cents"`
	// MaxMonthCents is null except for the keyholder's figure.
	MaxMonthCents *int64 `json:"max_month_cents"`
}

// OneOffCost is a Job the command runs once.
type OneOffCost struct {
	What      string `json:"what"`
	Jobs      int    `json:"jobs"`
	CPUMilli  int64  `json:"cpu_milli"`
	MemMiB    int64  `json:"mem_mib"`
	DeadlineS int64  `json:"deadline_s"`
}

// Pricing dates the rate card a cost was computed from: the rate card's own
// region and date, not the instance's region.
type Pricing struct {
	Region string `json:"region"`
	AsOf   string `json:"as_of"`
}

func (CostFact) FactType() string { return TypeCost }

// ------------------------------------------------------------------ image

// ImageFact is how the command gets one component's image, by rules 1–6 of
// the image decision.
type ImageFact struct {
	Type      string `json:"type"`
	Component string `json:"component"`
	// Action is one of the Image* constants.
	Action string `json:"action"`
	// Target is the image the command deploys: the flag's or the recorded
	// reference (named, recorded, keep_*), <repo>@<compiled manifest digest>
	// (reuse, push, push_over_foreign), or a build placeholder (build_*).
	Target string `json:"target"`
	Go     string `json:"go"`
	// Current is the image deployed today, or null when none is recorded.
	Current *ImageCurrent `json:"current"`
	// ReplacesOtherVersion is true when the image replaces a component another
	// farcast version deployed. Under --confirm it is the consent to that.
	ReplacesOtherVersion bool `json:"replaces_other_version"`
	// Source is the checkout and Go a source build uses, or null. It binds
	// the directory, not its content.
	Source *ImageSource `json:"source"`
}

// ImageCurrent is the image a component runs today, as the record has it.
type ImageCurrent struct {
	Image   string `json:"image"`
	Origin  string `json:"origin"`
	FarCast string `json:"farcast"`
	Go      string `json:"go"`
}

// ImageSource is a source build's checkout directory and Go toolchain.
type ImageSource struct {
	Dir       string `json:"dir"`
	GoPath    string `json:"go_path"`
	GoVersion string `json:"go_version"`
}

// The image actions. There is no "omitted": no plan deploys FatLine without
// Shrike (A23-5).
const (
	ImageNamed            = "named"             // rule 1: the flag's image, or a toolchain image's flag
	ImageRecorded         = "recorded"          // a toolchain image from the record
	ImageBuildSource      = "build_source"      // rule 3: --source
	ImageKeepOperator     = "keep_operator"     // rule 4: an operator-built image, kept
	ImageKeepDevelopment  = "keep_development"  // rule 4: a development build, kept
	ImageReuse            = "reuse"             // rule 5c: the carried image's tag is already there
	ImagePush             = "push"              // rule 5c: the tag is absent
	ImagePushOverForeign  = "push_over_foreign" // rule 5c: the tag holds another image
	ImageBuildDevelopment = "build_development" // rule 6
)

func (ImageFact) FactType() string { return TypeImage }

// ------------------------------------------------------------------ write

// WriteFact is one document the command writes to the cluster.
type WriteFact struct {
	Type      string `json:"type"`
	API       string `json:"api"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Method is one of the Write* constants.
	Method string `json:"method"`
	// Force is false in M2.6: kubectl's client-side apply has no force, and
	// the pin's create and replace are not applies.
	Force bool `json:"force"`
	// ResourceVersion is "" except for a replace, and for the documents whose
	// content depends on what the cluster holds.
	ResourceVersion string `json:"resource_version"`
	// SHA256 is the lowercase hex SHA-256 of the document as the plan renders
	// it, placeholders included.
	SHA256 string `json:"sha256"`
}

// The write methods.
const (
	WriteApply   = "apply"
	WriteCreate  = "create"
	WriteReplace = "replace"
	WriteDelete  = "delete"
)

func (WriteFact) FactType() string { return TypeWrite }

// ------------------------------------------------------------------ mint

// MintFact is secret material, a key or a keyring the command would make.
// The plan names it; its bytes are never in a plan.
type MintFact struct {
	Type string `json:"type"`
	// What is one of the Mint* constants.
	What    string `json:"what"`
	Subject string `json:"subject"`
}

// What a command mints.
const (
	MintInstanceCA       = "instance_ca"
	MintFatLineLeaf      = "fatline_leaf"
	MintOperatorLeaf     = "operator_leaf" // the operator's client leaf, client.crt
	MintKeyholderLeaf    = "keyholder_leaf"
	MintKeyring          = "keyring"
	MintKey              = "key"
	MintAppLeaf          = "app_leaf"
	MintEgressCredential = "egress_credential"
	MintAppScope         = "app_scope"
)

func (MintFact) FactType() string { return TypeMint }

// ------------------------------------------------------------------ restart

// RestartFact is a component whose pods roll because the command re-mints
// their mTLS material.
type RestartFact struct {
	Type      string `json:"type"`
	Component string `json:"component"`
	// Because is RestartBecause.
	Because string `json:"because"`
}

// RestartBecause is why a re-mint restarts a component.
const RestartBecause = "new mTLS material: the pod template's farcast.sofmon.com/mtls-hash changes"

func (RestartFact) FactType() string { return TypeRestart }

// ------------------------------------------------------------------ cloud

// CloudFact is one thing the command does in the cloud provider, outside the
// cluster.
type CloudFact struct {
	Type string `json:"type"`
	// Service is one of the Cloud* service constants.
	Service string `json:"service"`
	// Action is one of the Cloud* action constants.
	Action string `json:"action"`
	Target string `json:"target"`
}

// The cloud services.
const (
	CloudArtifactRegistry = "artifactregistry"
	CloudStorage          = "storage"
)

// The cloud actions.
const (
	CloudCreateRepository = "create_repository"
	CloudSetPullGrant     = "set_pull_grant"
	CloudPushImage        = "push_image"
	CloudCreateBucket     = "create_bucket"
	CloudSetBucketGrant   = "set_bucket_grant"
)

func (CloudFact) FactType() string { return TypeCloud }

// ------------------------------------------------------------------ kernel_settings

// KernelSettingsFact is how kernel deploy configures the kernel.
type KernelSettingsFact struct {
	Type  string `json:"type"`
	Adapt bool   `json:"adapt"`
	// AdaptCooldownS and IntervalS are the knobs as the record stores them,
	// in seconds; 0 means the kernel's default.
	AdaptCooldownS int64 `json:"adapt_cooldown_s"`
	IntervalS      int64 `json:"interval_s"`
	// Namespaces come in the command's order.
	Namespaces []string `json:"namespaces"`
	// Reader is the reader whose bindings follow the metered namespaces, or "".
	Reader                string   `json:"reader"`
	ReaderBindingsCreated []string `json:"reader_bindings_created"`
}

func (KernelSettingsFact) FactType() string { return TypeKernelSettings }

// ------------------------------------------------------------------ meter

// MeterFact is the change kernel meter makes to what the kernel counts.
type MeterFact struct {
	Type string `json:"type"`
	// Add or Remove holds the arguments in argument order; the other is [].
	Add             []string `json:"add"`
	Remove          []string `json:"remove"`
	BindingsCreated []string `json:"bindings_created"`
	BindingsLeft    []string `json:"bindings_left"`
	// Reader is the reader whose bindings follow the metered namespaces, or "".
	Reader                string   `json:"reader"`
	ReaderBindingsCreated []string `json:"reader_bindings_created"`
	MeteredAfter          []string `json:"metered_after"`
}

func (MeterFact) FactType() string { return TypeMeter }

// ------------------------------------------------------------------ confirmation

// ConfirmationFact is the billed window kernel confirm records, and the
// windows the record holds after it.
type ConfirmationFact struct {
	Type        string `json:"type"`
	From        string `json:"from"`
	To          string `json:"to"`
	AmountCents int64  `json:"amount_cents"`
	// AsOfDay is the UTC day the confirmation is made.
	AsOfDay      string               `json:"as_of_day"`
	WindowsAfter []ConfirmationWindow `json:"windows_after"`
}

// ConfirmationWindow is one confirmed window.
type ConfirmationWindow struct {
	From        string `json:"from"`
	To          string `json:"to"`
	AmountCents int64  `json:"amount_cents"`
}

func (ConfirmationFact) FactType() string { return TypeConfirmation }

// ------------------------------------------------------------------ pin

// PinFact is the key pin the command would write. Key ids are 16 hex
// characters each.
type PinFact struct {
	Type    string   `json:"type"`
	Require []string `json:"require"`
	Retired []string `json:"retired"`
	// Lowering holds the ids the current pin requires or retires that this
	// one does not; [] when the pin only rises.
	Lowering []string `json:"lowering"`
	// Repairing is true when the pin replaces one that could not be read.
	Repairing bool `json:"repairing"`
}

func (PinFact) FactType() string { return TypePin }

// ------------------------------------------------------------------ rotation

// RotationFact is the size of storage key rotate: how many keys it mints, and
// how many keyholder replicas it hands them to.
type RotationFact struct {
	Type             string `json:"type"`
	NewKeys          int    `json:"new_keys"`
	HandoverReplicas int    `json:"handover_replicas"`
}

func (RotationFact) FactType() string { return TypeRotation }

// ------------------------------------------------------------------ fetch

// FetchFact is the in-instance read of a repository's manifest, run's fetch
// stage.
type FetchFact struct {
	Type       string `json:"type"`
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Manifest   string `json:"manifest"`
	Job        string `json:"job"`
	Fetcher    string `json:"fetcher"`
}

func (FetchFact) FactType() string { return TypeFetch }

// ------------------------------------------------------------------ run

// RunFact is what run's deploy stage deploys, from the manifest its fetch
// stage read.
type RunFact struct {
	Type string `json:"type"`
	// JobUID is the fetch Job's uid, and FetchPlanDigest the fetch stage's
	// digest: a Job made by another run changes the deploy plan.
	JobUID          string `json:"job_uid"`
	FetchPlanDigest string `json:"fetch_plan_digest"`
	Commit          string `json:"commit"`
	ManifestDigest  string `json:"manifest_digest"`
	Namespace       string `json:"namespace"`
	// ReplacesRepository is the repository the namespace was recorded under
	// that this run replaces, or "" when it replaces none.
	ReplacesRepository string `json:"replaces_repository"`
	// Apps come in manifest order.
	Apps                 []RunApp `json:"apps"`
	OtherDeploymentsKept []string `json:"other_deployments_kept"`
	// MeteringAdded is true when the run adds its namespace to what the
	// kernel counts.
	MeteringAdded bool `json:"metering_added"`
}

// RunApp is one application of a run's manifest.
type RunApp struct {
	Name          string `json:"name"`
	Containerfile string `json:"containerfile"`
	Context       string `json:"context"`
	// External comes in manifest order.
	External []RunHost `json:"external"`
}

// RunHost is one external host an application declares, with its reason.
type RunHost struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

func (RunFact) FactType() string { return TypeRun }

// ------------------------------------------------------------------ build

// BuildFact is the one-off image build farcast build runs in the instance.
type BuildFact struct {
	Type          string `json:"type"`
	Repository    string `json:"repository"`
	Ref           string `json:"ref"`
	App           string `json:"app"`
	Containerfile string `json:"containerfile"`
	Context       string `json:"context"`
	Tag           string `json:"tag"`
	Destination   string `json:"destination"`
}

func (BuildFact) FactType() string { return TypeBuild }

// ------------------------------------------------------------------ application_reset

// ApplicationResetFact is a live application a run deploy resets: one the
// cost guard or a scale stopped, one the kernel adapted, or one whose state
// could not be read.
type ApplicationResetFact struct {
	Type      string `json:"type"`
	Namespace string `json:"namespace"`
	App       string `json:"app"`
	// State is one of the Reset* constants.
	State string `json:"state"`
	// StoppedByCostGuard is true when the kernel's checkpoint names the app
	// among its stops.
	StoppedByCostGuard bool `json:"stopped_by_cost_guard"`
	// LimitReached is true when the kernel's ledger reads the limit reached,
	// reads a level it cannot place, or cannot be read.
	LimitReached bool `json:"limit_reached"`
	// ReplicasLive and RequestsLive are null when State is unknown.
	ReplicasLive  *int32    `json:"replicas_live"`
	ReplicasAfter int32     `json:"replicas_after"`
	RequestsLive  *Requests `json:"requests_live"`
	RequestsAfter Requests  `json:"requests_after"`
}

// Requests are an application's resource requests.
type Requests struct {
	CPUMilli int64 `json:"cpu_milli"`
	MemMiB   int64 `json:"mem_mib"`
}

// The states an application reset is found in.
const (
	ResetStopped = "stopped"
	ResetAdapted = "adapted"
	ResetUnknown = "unknown"
)

func (ApplicationResetFact) FactType() string { return TypeApplicationReset }

// ------------------------------------------------------------------ reader

// ReaderFact is the read access reader grant gives the instance's reader.
type ReaderFact struct {
	Type    string `json:"type"`
	Email   string `json:"email"`
	IAMRole string `json:"iam_role"`
	// Scope is where the reader reads: "metered" is farcast-system and every
	// namespace the kernel meters, now and later.
	Scope string `json:"scope"`
	// Namespaces are today's.
	Namespaces []string `json:"namespaces"`
	// Resources are the role's per-namespace grant, in its rule order.
	Resources  []string `json:"resources"`
	ConfigMaps []string `json:"configmaps"`
}

func (ReaderFact) FactType() string { return TypeReader }

// ------------------------------------------------------------------ notice

// NoticeFact is a line the command prints, in its exact words. Under --plan a
// notice is only a fact; elsewhere the command prints it once.
type NoticeFact struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (NoticeFact) FactType() string { return TypeNotice }
