package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// planNow is the clock the rendering tests print plans at.
var planNow = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

// sampleBound is a plan with header values of its own, holding facts.
func sampleBound(facts ...plan.Fact) plan.Bound {
	return plan.Bound{
		Protocol: plan.Protocol, FarCast: plan.Stamp{Version: "h-version", Commit: "h-commit"},
		Command: "h-command", Instance: "h-instance",
		Target: plan.Target{Provider: "h-provider", Project: "h-project", Region: "h-region", Cluster: "h-cluster",
			Endpoint: "h-endpoint", CreatedAt: "h-created", SystemNamespaceUID: "h-uid"},
		ClusterIdentity: "reader", Facts: facts,
	}
}

// renderPlan is b's human rendering, as --plan prints it, through the
// document (so b must encode).
func renderPlan(t *testing.T, b plan.Bound) string {
	t.Helper()
	r, err := newPlanResult(&Env{}, b, planNow)
	if err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if err := r.Human(&w); err != nil {
		t.Fatal(err)
	}
	return w.String()
}

// renderRow is one sample for TestEveryBoundFactIsRendered: a plan whose
// typ value carries a distinct printable sentinel per field, and the text
// each of typ's JSON paths must show.
type renderRow struct {
	name   string
	typ    reflect.Type
	bound  plan.Bound
	want   map[string][]string
	exempt []string
}

func factRow(name string, f plan.Fact, want map[string][]string, context ...plan.Fact) renderRow {
	return renderRow{name: name, typ: reflect.TypeOf(f), bound: sampleBound(append(context, f)...), want: want}
}

// The facts' samples. Each string is a sentinel, each number distinct, each
// amount of cents one %.0f would round; each boolean appears as true in one
// row and false in another.
func renderRows() []renderRow {
	i32 := func(v int32) *int32 { return &v }
	i64 := func(v int64) *int64 { return &v }
	api1, web1, api2 := placeholderKeyID("api", 1).String(), placeholderKeyID("web", 1).String(), placeholderKeyID("api", 2).String()

	bound := sampleBound()
	bound.Stage = "h-stage"
	bound.Options = []plan.Option{{Flag: "h-flag-a", Value: "h-value-a"}, {Flag: "h-flag-b", Value: ""}}
	bound.Blocked = []plan.Block{{Kind: "h-kind", Message: "h-block-message"}}
	unread := sampleBound()
	unread.ClusterIdentity, unread.Target.SystemNamespaceUID = "none", ""
	absent := sampleBound()
	absent.Target.SystemNamespaceUID = ""

	return []renderRow{
		{name: "bound", typ: reflect.TypeOf(plan.Bound{}), bound: bound, exempt: []string{"facts[]"}, want: map[string][]string{
			"protocol":                    {"plan protocol " + plan.Protocol},
			"farcast.version":             {"farcast h-version (commit"},
			"farcast.commit":              {"(commit h-commit)"},
			"command":                     {"farcast h-command h-instance, stage"},
			"instance":                    {"instance h-instance: provider"},
			"target.provider":             {"provider h-provider, project"},
			"target.project":              {"project h-project, region"},
			"target.region":               {"region h-region, cluster"},
			"target.cluster":              {"cluster h-cluster, endpoint"},
			"target.endpoint":             {"endpoint h-endpoint (recorded"},
			"target.created_at":           {"(recorded h-created); farcast-system"},
			"target.system_namespace_uid": {"; farcast-system h-uid\n"},
			"stage":                       {", stage h-stage, reading"},
			"options[].flag":              {"options: --h-flag-a=h-value-a, --h-flag-b (not given)\n"},
			"options[].value":             {"--h-flag-a=h-value-a,"},
			"cluster_identity":            {"reading the cluster as reader\n"},
			"blocked[].kind":              {"blocked (h-kind): ", "blocked: --confirm would refuse this plan (h-kind)\n"},
			"blocked[].message":           {"): h-block-message\n"},
		}},
		{name: "bound, reading no cluster", typ: reflect.TypeOf(plan.Bound{}), bound: unread, want: map[string][]string{
			"stage":                       {", stage -, reading"},
			"options[].flag":              {"options: none\n"},
			"target.system_namespace_uid": {"; farcast-system not read\n"},
			"cluster_identity":            {"reading the cluster as none\n"},
			"blocked[].kind":              {"To do exactly this: run the same command with --confirm sha256:"},
		}},
		{name: "bound, before farcast-system exists", typ: reflect.TypeOf(plan.Bound{}), bound: absent, want: map[string][]string{
			"target.system_namespace_uid": {"; farcast-system absent\n"},
		}},

		factRow("cost", plan.CostFact{Type: plan.TypeCost, Currency: "f-cur", Period: "f-period", LimitCents: 1234501,
			Standing:        []plan.StandingCost{{What: "f-standing", Replicas: 7, CPUMilli: 251, MemMiB: 513, MonthCents: 2001, MaxMonthCents: i64(3009)}},
			OneOff:          []plan.OneOffCost{{What: "f-oneoff", Jobs: 3, CPUMilli: 1501, MemMiB: 2049, DeadlineS: 901}},
			FloorMonthCents: 4507, BelowFloor: true, Pricing: plan.Pricing{Region: "f-region", AsOf: "f-asof"}},
			map[string][]string{
				"type":                       {"cost, against the cost limit"},
				"currency":                   {"f-cur 12345.01"},
				"period":                     {"/f-period:\n"},
				"limit_cents":                {"the cost limit f-cur 12345.01/f-period"},
				"standing[].what":            {"  standing: f-standing, "},
				"standing[].replicas":        {", 7 replica(s) at"},
				"standing[].cpu_milli":       {" at 251m CPU"},
				"standing[].mem_mib":         {" and 513 MiB, f-cur"},
				"standing[].month_cents":     {"f-cur 20.01 a month"},
				"standing[].max_month_cents": {"at most f-cur 30.09 a month"},
				"one_off[].what":             {"  one-off: f-oneoff, "},
				"one_off[].jobs":             {", 3 job(s) at"},
				"one_off[].cpu_milli":        {" at 1501m CPU"},
				"one_off[].mem_mib":          {" and 2049 MiB, each"},
				"one_off[].deadline_s":       {"each stopped after 901 s"},
				"floor_month_cents":          {"floor is f-cur 45.07 a month"},
				"below_floor":                {"; the cost limit is below it\n"},
				"pricing.region":             {"prices: f-region as of"},
				"pricing.as_of":              {" as of f-asof\n"},
			}),
		factRow("cost, not below the floor", plan.CostFact{Type: plan.TypeCost, Currency: "f-cur", Period: "f-period", LimitCents: 5},
			map[string][]string{
				"below_floor": {"; the cost limit is not below it\n"},
				"limit_cents": {"the cost limit f-cur 0.05/f-period"},
			}),

		factRow("image", plan.ImageFact{Type: plan.TypeImage, Component: "f-component", Action: "f-action", Target: "f-target", Go: "f-go",
			Current:              &plan.ImageCurrent{Image: "f-cur-image", Origin: "f-cur-origin", FarCast: "f-cur-farcast", Go: "f-cur-go"},
			ReplacesOtherVersion: true, Source: &plan.ImageSource{Dir: "f-dir", GoPath: "f-gopath", GoVersion: "f-goversion"}},
			map[string][]string{
				"type":                   {"image f-component: "},
				"component":              {"image f-component: f-action"},
				"action":                 {": f-action f-target"},
				"target":                 {"f-action f-target, go"},
				"go":                     {"f-target, go f-go\n"},
				"current.image":          {"today: f-cur-image (origin"},
				"current.origin":         {"(origin f-cur-origin, farcast"},
				"current.farcast":        {", farcast f-cur-farcast, go"},
				"current.go":             {", go f-cur-go)"},
				"replaces_other_version": {"  it replaces a component another farcast version deployed\n"},
				"source.dir":             {"a source build of f-dir, with"},
				"source.go_path":         {", with f-gopath ("},
				"source.go_version":      {"(f-goversion)\n"},
			}),
		factRow("image, nothing recorded", plan.ImageFact{Type: plan.TypeImage, Component: "f-component2", Action: "f-action2", Target: "f-target2"},
			map[string][]string{
				"current":                {"  today: nothing recorded\n"},
				"replaces_other_version": {"  it replaces no component another farcast version deployed\n"},
				"go":                     {"f-action2 f-target2\n"},
			}),

		factRow("write", plan.WriteFact{Type: plan.TypeWrite, API: "f-api", Kind: "f-kind", Namespace: "f-ns", Name: "f-name",
			Method: "f-method", Force: true, ResourceVersion: "f-rv", SHA256: "f-sha"},
			map[string][]string{
				"type":             {"write: f-method"},
				"api":              {"f-ns/f-name (f-api)"},
				"kind":             {"f-method f-kind f-ns"},
				"namespace":        {" f-ns/f-name "},
				"name":             {"/f-name (f-api)"},
				"method":           {"write: f-method f-kind"},
				"force":            {", force: yes, "},
				"resource_version": {", at resourceVersion f-rv, "},
				"sha256":           {", sha256 f-sha\n"},
			}),
		factRow("write, cluster-scoped, the hold-stage version", plan.WriteFact{Type: plan.TypeWrite, API: "f-api2", Kind: "f-kind2",
			Name: "f-name2", Method: plan.WriteReplace, SHA256: "f-sha2"},
			map[string][]string{
				"namespace":        {"write: replace f-kind2 f-name2 (f-api2)"},
				"resource_version": {", at the version the hold-stage write produced, "},
				"force":            {", force: no, "},
			}),

		factRow("mint", plan.MintFact{Type: plan.TypeMint, What: "f-what", Subject: "f-subject"},
			map[string][]string{"type": {"mint f-what"}, "what": {"mint f-what: f-subject\n"}, "subject": {": f-subject\n"}}),
		factRow("mint, the instance key space", plan.MintFact{Type: plan.TypeMint, What: plan.MintKey},
			map[string][]string{"subject": {"mint key: a new key for the instance key space\n"}}),
		factRow("mint, a scope's keys", plan.MintFact{Type: plan.TypeMint, What: plan.MintKey, Subject: "api"},
			map[string][]string{"subject": {"mint key: new key 1 of api\nmint key: new key 1 of web\nmint key: new key 2 of api\n"}},
			plan.MintFact{Type: plan.TypeMint, What: plan.MintKey, Subject: "api"},
			plan.MintFact{Type: plan.TypeMint, What: plan.MintKey, Subject: "web"}),

		factRow("restart", plan.RestartFact{Type: plan.TypeRestart, Component: "f-rcomp", Because: "f-because"},
			map[string][]string{"type": {"restart f-rcomp"}, "component": {"restart f-rcomp: "}, "because": {": f-because\n"}}),
		factRow("cloud", plan.CloudFact{Type: plan.TypeCloud, Service: "f-service", Action: "f-caction", Target: "f-ctarget"},
			map[string][]string{"type": {"cloud f-service"}, "service": {"cloud f-service: "}, "action": {": f-caction f-ctarget"}, "target": {" f-ctarget\n"}}),

		factRow("kernel_settings", plan.KernelSettingsFact{Type: plan.TypeKernelSettings, Adapt: true, AdaptCooldownS: 4321, IntervalS: 75,
			Namespaces: []string{"f-kns1", "f-kns2"}, Reader: "f-kreader", ReaderBindingsCreated: []string{"f-krb"}},
			map[string][]string{
				"type":                      {"kernel settings: "},
				"adapt":                     {", adapting on, "},
				"adapt_cooldown_s":          {"adapt cooldown 1h12m1s;"},
				"interval_s":                {"interval 1m15s,"},
				"namespaces[]":              {"; metering f-kns1, f-kns2\n"},
				"reader":                    {"the reader f-kreader is bound in"},
				"reader_bindings_created[]": {"is bound in: f-krb\n"},
			}),
		factRow("kernel_settings, the defaults", plan.KernelSettingsFact{Type: plan.TypeKernelSettings},
			map[string][]string{
				"adapt":            {", adapting off, "},
				"adapt_cooldown_s": {"adapt cooldown 6h0m0s (default);"},
				"interval_s":       {"interval 30s (default),"},
				"namespaces[]":     {"; metering none\n"},
				"reader":           {"  no reader binding is added\n"},
			}),

		factRow("meter", plan.MeterFact{Type: plan.TypeMeter, Add: []string{"f-add"}, Remove: []string{"f-remove"},
			BindingsCreated: []string{"f-bc"}, BindingsLeft: []string{"f-bl"}, Reader: "f-mreader",
			ReaderBindingsCreated: []string{"f-mrb"}, MeteredAfter: []string{"f-ma1", "f-ma2"}},
			map[string][]string{
				"type":                      {"meter: "},
				"add[]":                     {"meter: start metering f-add;"},
				"remove[]":                  {"; stop metering f-remove;"},
				"bindings_created[]":        {"RoleBinding is created in: f-bc;"},
				"bindings_left[]":           {"; left in place in: f-bl\n"},
				"reader":                    {"the reader f-mreader is bound in"},
				"reader_bindings_created[]": {"is bound in: f-mrb\n"},
				"metered_after[]":           {"metered afterwards: f-ma1, f-ma2\n"},
			}),

		factRow("confirmation", plan.ConfirmationFact{Type: plan.TypeConfirmation, From: "f-from", To: "f-to", AmountCents: 15003,
			AsOfDay: "f-asofday", WindowsAfter: []plan.ConfirmationWindow{{From: "f-wfrom", To: "f-wto", AmountCents: 207}}},
			map[string][]string{
				"type":                         {"confirmation: "},
				"from":                         {" for f-from..f-to,"},
				"to":                           {"..f-to, as of"},
				"amount_cents":                 {"the provider charged 150.03 for"},
				"as_of_day":                    {", as of f-asofday\n"},
				"windows_after[].from":         {"afterwards: f-wfrom..f-wto"},
				"windows_after[].to":           {"..f-wto 2.07"},
				"windows_after[].amount_cents": {"f-wto 2.07\n"},
			}),

		factRow("pin", plan.PinFact{Type: plan.TypePin, Require: []string{"f-req"}, Retired: []string{"f-ret"},
			Lowering: []string{"f-low"}, Repairing: true},
			map[string][]string{
				"type":       {"pin: "},
				"require[]":  {"pin: require f-req;"},
				"retired[]":  {"; retired f-ret\n"},
				"lowering[]": {"it lowers the pin, dropping f-low;"},
				"repairing":  {"; it replaces a pin that could not be read\n"},
			}),
		factRow("pin, raising, over a readable one", plan.PinFact{Type: plan.TypePin},
			map[string][]string{
				"require[]":  {"pin: require none; retired none\n"},
				"lowering[]": {"  it lowers nothing; "},
				"repairing":  {"; it repairs no unreadable pin\n"},
			}),
		factRow("pin, two scopes' new keys", plan.PinFact{Type: plan.TypePin, Require: []string{api1, "00112233aabbccdd", api2},
			Retired: []string{web1}, Lowering: []string{}},
			map[string][]string{
				"require[]": {"pin: require new key 1 of api, 00112233aabbccdd, new key 2 of api;"},
				"retired[]": {"; retired new key 1 of web\n"},
			},
			plan.MintFact{Type: plan.TypeMint, What: plan.MintKey, Subject: "api"},
			plan.MintFact{Type: plan.TypeMint, What: plan.MintKey, Subject: "web"},
			plan.MintFact{Type: plan.TypeMint, What: plan.MintKey, Subject: "api"}),

		factRow("rotation", plan.RotationFact{Type: plan.TypeRotation, NewKeys: 11, HandoverReplicas: 13},
			map[string][]string{"type": {"rotation: "}, "new_keys": {"rotation: 11 new key(s)"}, "handover_replicas": {"handed to 13 keyholder replica(s)"}}),
		factRow("fetch", plan.FetchFact{Type: plan.TypeFetch, Repository: "f-repo", Ref: "f-ref", Manifest: "f-manifest", Job: "f-job", Fetcher: "f-fetcher"},
			map[string][]string{
				"type": {"fetch: "}, "manifest": {"fetch: the manifest f-manifest from"}, "repository": {" from f-repo at"},
				"ref": {" at f-ref, read"}, "job": {"by the Job f-job with"}, "fetcher": {" with f-fetcher\n"},
			}),

		factRow("run", plan.RunFact{Type: plan.TypeRun, JobUID: "f-uid", FetchPlanDigest: "f-fpd", Commit: "f-commit", ManifestDigest: "f-md",
			Namespace: "f-rns", ReplacesRepository: "f-rr",
			Apps: []plan.RunApp{{Name: "f-app", Containerfile: "f-cf", Context: "f-ctx",
				External: []plan.RunHost{{Host: "f-host", Reason: "f-reason"}, {Host: "f-host2", Reason: "f-reason2"}}}},
			OtherDeploymentsKept: []string{"f-other"}, MeteringAdded: true},
			map[string][]string{
				"type":                     {"run: deploy "},
				"job_uid":                  {"(Job uid f-uid)\n"},
				"fetch_plan_digest":        {"fetched by the plan f-fpd (Job uid"},
				"commit":                   {"at commit f-commit, fetched"},
				"manifest_digest":          {"from the manifest f-md at"},
				"namespace":                {"run: deploy f-rns from"},
				"replaces_repository":      {"  it replaces the repository f-rr recorded for f-rns\n"},
				"apps[].name":              {"  app f-app: "},
				"apps[].containerfile":     {": f-cf in f-ctx;"},
				"apps[].context":           {" in f-ctx; reaches"},
				"apps[].external[].host":   {"reaches f-host (f-reason), f-host2 (f-reason2)\n"},
				"apps[].external[].reason": {"(f-reason)"},
				"other_deployments_kept[]": {"other deployments kept in f-rns: f-other;"},
				"metering_added":           {"; f-rns is added to what the kernel meters\n"},
			}),
		factRow("run, into a metered namespace, replacing nothing", plan.RunFact{Type: plan.TypeRun, Namespace: "f-rns2",
			Apps: []plan.RunApp{{Name: "f-app2"}}},
			map[string][]string{
				"replaces_repository":      {"  it replaces no other repository\n"},
				"apps[].external[].host":   {"; reaches nothing outside the instance\n"},
				"other_deployments_kept[]": {"other deployments kept in f-rns2: none;"},
				"metering_added":           {"; f-rns2 is already metered\n"},
			}),

		factRow("build", plan.BuildFact{Type: plan.TypeBuild, Repository: "f-brepo", Ref: "f-bref", App: "f-bapp",
			Containerfile: "f-bcf", Context: "f-bctx", Tag: "f-tag", Destination: "f-dest"},
			map[string][]string{
				"type": {"build: "}, "app": {"build: f-bapp from"}, "repository": {" from f-brepo at"}, "ref": {" at f-bref, "},
				"containerfile": {", f-bcf in f-bctx"}, "context": {" in f-bctx, tagged"}, "tag": {"tagged f-tag, pushed"},
				"destination": {"pushed to f-dest\n"},
			}),

		factRow("application_reset", plan.ApplicationResetFact{Type: plan.TypeApplicationReset, Namespace: "f-arns", App: "f-arapp",
			State: "f-state", StoppedByCostGuard: true, LimitReached: true, ReplicasLive: i32(17), ReplicasAfter: 19,
			RequestsLive: &plan.Requests{CPUMilli: 23, MemMiB: 29}, RequestsAfter: plan.Requests{CPUMilli: 31, MemMiB: 37}},
			map[string][]string{
				"type":                     {"reset f-arns/"},
				"namespace":                {"reset f-arns/f-arapp: "},
				"app":                      {"/f-arapp: f-state,"},
				"state":                    {": f-state, "},
				"stopped_by_cost_guard":    {", stopped by the cost guard; "},
				"limit_reached":            {"; the spending reads the limit reached, or cannot be read\n"},
				"replicas_live":            {"replicas: 17 now, "},
				"replicas_after":           {" now, 19 after;"},
				"requests_live.cpu_milli":  {"requests: 23m CPU and 29 MiB now"},
				"requests_live.mem_mib":    {" and 29 MiB now, "},
				"requests_after.cpu_milli": {"now, 31m CPU and"},
				"requests_after.mem_mib":   {" and 37 MiB after\n"},
			}),
		factRow("application_reset, unread", plan.ApplicationResetFact{Type: plan.TypeApplicationReset, Namespace: "f-arns2", App: "f-arapp2",
			State: plan.ResetUnknown},
			map[string][]string{
				"stopped_by_cost_guard": {", not stopped by the cost guard; "},
				"limit_reached":         {"; the spending does not read the limit reached\n"},
				"replicas_live":         {"replicas: not read now, 0 after;"},
				"requests_live":         {"requests: not read now, 0m CPU and 0 MiB after\n"},
			}),

		factRow("reader", plan.ReaderFact{Type: plan.TypeReader, Email: "f-email", IAMRole: "f-role", Scope: "f-scope",
			Namespaces: []string{"f-rns1", "f-rns2"}, Resources: []string{"f-res1", "f-res2"}, ConfigMaps: []string{"f-cm"}},
			map[string][]string{
				"type": {"reader: "}, "email": {"reader: f-email (f-role)"}, "iam_role": {" (f-role), scope"},
				"scope": {", scope f-scope: "}, "resources[]": {": f-res1, f-res2 in"}, "namespaces[]": {" in f-rns1, f-rns2;"},
				"configmaps[]": {"; the ConfigMaps f-cm\n"},
			}),

		factRow("notice", plan.NoticeFact{Type: plan.TypeNotice, Text: "f-notice <&> line\nand its second"},
			map[string][]string{"type": {"notice: "}, "text": {"notice: f-notice <&> line\n  and its second\n"}}),
	}
}

// jsonPaths is every JSON path below t: a.b for a field b of the object a,
// a[] for an element of the array a. A pointer to an object is also a path
// of its own (null), in pointers.
func jsonPaths(t reflect.Type, prefix string, leaves, pointers map[string]bool) {
	join := func(name string) string {
		if prefix == "" {
			return name
		}
		return prefix + "." + name
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if !f.IsExported() || name == "-" {
				continue
			}
			p := join(name)
			ft := f.Type
			if ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Struct {
				pointers[p] = true
				jsonPaths(ft.Elem(), p, leaves, pointers)
				continue
			}
			if ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct {
				jsonPaths(ft.Elem(), p+"[]", leaves, pointers)
				continue
			}
			if ft.Kind() == reflect.Slice {
				p += "[]"
			}
			if ft.Kind() == reflect.Struct {
				jsonPaths(ft, p, leaves, pointers)
				continue
			}
			leaves[p] = true
		}
	default:
		leaves[prefix] = true
	}
}

// factTypeNames is every type in the plan package with a FactType method,
// by its name, read from the package's source: a fact type added there
// without a row here fails TestEveryBoundFactIsRendered.
func factTypeNames(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join("..", "plan", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("the plan package's sources: %v (%d files)", err, len(files))
	}
	var names []string
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "FactType" || len(fn.Recv.List) != 1 {
				continue
			}
			rt := fn.Recv.List[0].Type
			if star, ok := rt.(*ast.StarExpr); ok {
				rt = star.X
			}
			if id, ok := rt.(*ast.Ident); ok {
				names = append(names, id.Name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// TestEveryBoundFactIsRendered: the operator consents by reading the
// rendering, so every value a plan binds appears in it: every field of every
// fact type, and every field of the plan outside its facts (design §9.6,
// A23-27). Cents print exactly, booleans as words both ways, and an empty
// stage as -. The digests a write binds are exempt from the table, not from
// the rendering; a placeholder key id renders as the key it stands for.
func TestEveryBoundFactIsRendered(t *testing.T) {
	rows := renderRows()

	byType := map[reflect.Type][]renderRow{}
	for _, r := range rows {
		byType[r.typ] = append(byType[r.typ], r)
	}
	planTypes := map[string]reflect.Type{}
	for typ := range byType {
		planTypes[typ.Name()] = typ
	}
	names := factTypeNames(t)
	if len(names) != 17 {
		t.Errorf("the plan package has %d fact types, %v; ADR 0023 M2.6 has 17", len(names), names)
	}
	for _, n := range names {
		if _, ok := planTypes[n]; !ok {
			t.Errorf("the fact type %s has no row", n)
		}
	}

	for typ, rs := range byType {
		leaves, pointers := map[string]bool{}, map[string]bool{}
		jsonPaths(typ, "", leaves, pointers)
		covered := map[string]bool{}
		bools := map[string]map[string]bool{}
		for _, r := range rs {
			for p := range r.want {
				if !leaves[p] && !pointers[p] {
					t.Errorf("%s: %q is not a path of %s", r.name, p, typ.Name())
				}
				covered[p] = true
				if f, ok := topField(typ, p); ok && f.Type.Kind() == reflect.Bool {
					if bools[p] == nil {
						bools[p] = map[string]bool{}
					}
					bools[p][strconv.FormatBool(boolAt(r, p))] = true
				}
			}
			for _, p := range r.exempt {
				covered[p] = true
			}
		}
		for p := range leaves {
			if !covered[p] {
				t.Errorf("%s: the path %q has no row and no exemption", typ.Name(), p)
			}
		}
		for p, seen := range bools {
			if !seen["true"] || !seen["false"] {
				t.Errorf("%s: the boolean %q is rendered by rows for %v only; both words are needed", typ.Name(), p, seen)
			}
		}
	}

	for _, r := range rows {
		text := renderPlan(t, r.bound)
		for p, wants := range r.want {
			for _, w := range wants {
				if !strings.Contains(text, w) {
					t.Errorf("%s: %q should show as %q in:\n%s", r.name, p, w, text)
				}
			}
		}
	}

	// Every plan a command prints (ADR 0023 M2.6b): each value its facts bind
	// shows in its rendering, so a renderer that drops one only a command's
	// own plan holds (connect's second standing cost, a source build's Go,
	// redeploy's replaced image, rotate's two pins) fails here, not only on
	// the samples above.
	t.Run("the commands' plans", func(t *testing.T) {
		for _, row := range planCommands() {
			t.Run(row.String(), func(t *testing.T) {
				_, dir := planFixture(t, row)
				doc, _ := runPlan(t, dir, row, output.ModeJSON)
				_, text := runPlan(t, dir, row, output.ModeHuman)
				b := decodedBound(t, doc)
				// A placeholder key id, rotate's, renders as the key it
				// stands for (A23-32).
				labels, _ := placeholderKeyLabels(b.Facts)
				for i, f := range b.Facts {
					for _, want := range renderedValues(reflect.ValueOf(f), "") {
						if label, ok := labels[want]; ok {
							want = label
						}
						if !strings.Contains(text, want) {
							t.Errorf("fact %d (%s) binds %q, which its rendering does not show:\n%s", i, f.FactType(), want, text)
						}
					}
				}
			})
		}
	})
}

// renderedValues is the text a plan's rendering must hold for each value v
// binds (name is v's JSON name): every string but a fact's type, line by
// line, through terminalText; an amount of cents as amount prints it; every
// other number in decimal. A boolean prints as words, which the sample rows
// check both ways.
func renderedValues(v reflect.Value, name string) []string {
	var out []string
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			out = renderedValues(v.Elem(), name)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() || f.Name == "Type" {
				continue
			}
			field, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			out = append(out, renderedValues(v.Field(i), field)...)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			out = append(out, renderedValues(v.Index(i), name)...)
		}
	case reflect.String:
		for _, line := range strings.Split(v.String(), "\n") {
			if line != "" {
				out = append(out, terminalText(line))
			}
		}
	case reflect.Int, reflect.Int32, reflect.Int64:
		if strings.HasSuffix(name, "_cents") {
			return []string{amount(v.Int())}
		}
		out = []string{strconv.FormatInt(v.Int(), 10)}
	}
	return out
}

// topField is the field of typ whose JSON name is the whole path p.
func topField(typ reflect.Type, p string) (reflect.StructField, bool) {
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name == p {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

// boolAt is the value of the top-level boolean p in r's sample: the last
// fact of r's type in its plan.
func boolAt(r renderRow, p string) bool {
	for i := len(r.bound.Facts) - 1; i >= 0; i-- {
		v := reflect.ValueOf(r.bound.Facts[i])
		if v.Type() != r.typ {
			continue
		}
		f, _ := topField(r.typ, p)
		return v.FieldByIndex(f.Index).Bool()
	}
	return false
}

// TestPlanRenderingQuotesHostileText: a value from a manifest, the cluster
// or the record that would act on the terminal (an escape sequence, a
// carriage return, a bidi override) prints Go-quoted, never raw.
func TestPlanRenderingQuotesHostileText(t *testing.T) {
	const esc, bidi, cr = "pay\x1b[2Kments", "evil\u202etxt.exe", "a\rb"
	b := sampleBound(
		plan.RunFact{Type: plan.TypeRun, Namespace: "web", Apps: []plan.RunApp{{Name: "api",
			External: []plan.RunHost{{Host: bidi, Reason: esc}}}}},
		plan.NoticeFact{Type: plan.TypeNotice, Text: "line one\n" + cr},
		plan.WriteFact{Type: plan.TypeWrite, Kind: "ConfigMap", Namespace: esc, Name: bidi, Method: plan.WriteApply},
	)
	b.Target.Project = esc
	b.Target.Endpoint = bidi
	b.Options = []plan.Option{{Flag: "source", Value: cr}}
	text := renderPlan(t, b)
	for _, raw := range []string{"\x1b", "\u202e", "\r"} {
		if strings.Contains(text, raw) {
			t.Errorf("the rendering holds %q raw:\n%s", raw, text)
		}
	}
	for _, want := range []string{
		"project " + strconv.QuoteToGraphic(esc) + ",",
		"endpoint " + strconv.QuoteToGraphic(bidi) + " (",
		"--source=" + strconv.QuoteToGraphic(cr),
		"reaches " + strconv.QuoteToGraphic(bidi) + " (" + strconv.QuoteToGraphic(esc) + ")",
		"  " + strconv.QuoteToGraphic(cr) + "\n",
		"ConfigMap " + strconv.QuoteToGraphic(esc) + "/" + strconv.QuoteToGraphic(bidi),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the rendering should hold %q:\n%s", want, text)
		}
	}

	// A block's message keeps its lines and escapes the rest, as an error does.
	blocked := sampleBound()
	blocked.Blocked = []plan.Block{{Kind: kindInternal, Message: "namespaces are missing:\n  " + esc}}
	text = renderPlan(t, blocked)
	if strings.Contains(text, "\x1b") {
		t.Errorf("a block's message prints an escape raw:\n%s", text)
	}
	if want := "blocked (internal): namespaces are missing:\n  " + output.ErrorText(esc) + "\n"; !strings.HasPrefix(text, want) {
		t.Errorf("the rendering begins %q, want %q", text, want)
	}

	// Every string of every fact type, and of the plan around it (row 81b,
	// M-M26A-MUT-04): a renderer that prints one field raw, a list among
	// them, fails here, whichever fact it is in.
	const hostile = "a\x1b[2Kb\u202ec"
	for _, r := range renderRows() {
		for i, f := range r.bound.Facts {
			v := reflect.New(reflect.TypeOf(f)).Elem()
			v.Set(reflect.ValueOf(f))
			setStrings(v, hostile)
			b := r.bound
			setStrings(reflect.ValueOf(&b).Elem(), hostile)
			b.Protocol = plan.Protocol
			b.Options = []plan.Option{{Flag: hostile, Value: hostile}}
			b.Facts = []plan.Fact{v.Interface().(plan.Fact)}
			text := renderPlan(t, b)
			if strings.Contains(text, "\x1b") || strings.Contains(text, "\u202e") {
				t.Errorf("%s, fact %d (%T): a value prints raw:\n%q", r.name, i, f, text)
			}
		}
	}
	// A fact this farcast has no words for prints its JSON, quoted too.
	text = renderPlan(t, sampleBound(irreversibleSample{Type: "irreversible_sample", What: hostile, once: true}))
	if strings.Contains(text, "\x1b") || strings.Contains(text, "\u202e") {
		t.Errorf("a fact with no words prints a value raw:\n%q", text)
	}

	t.Run("the commands", hostileTextOnTheCommands)
}

// hostileTextOnTheCommands is TestPlanRenderingQuotesHostileText's rows for
// connect, redeploy and build (ADR 0023 M2.6b): a value from the command
// line that would act on the terminal, valid UTF-8, never prints raw. A
// --source that holds one is bound by connect's and redeploy's plans as an
// option, as the image's source and in the source-build notice, and each
// prints Go-quoted; build refuses such a value where it renders its
// documents, before any plan, and its refusal does not hold it either. And
// for kernel deploy, storage deploy, storage key pin and storage key rotate
// (M2.6c): a value from the cluster or the record they read.
func hostileTextOnTheCommands(t *testing.T) {
	const hostileDir = "/work/far\x1b[2Kcast\u202etxt"
	raw := func(s string) bool { return strings.Contains(s, "\x1b") || strings.Contains(s, "\u202e") }
	for _, dr := range deployRigs() {
		t.Run(dr.name, func(t *testing.T) {
			r := dr.rig(t)
			r.configure = func(d *fatlineDeployer) { d.findSource = func(dir string) (string, error) { return dir, nil } }
			text, errb, err := r.run(t, output.ModeHuman, "--source", hostileDir, "--plan")
			if err != nil {
				t.Fatalf("%s --source <hostile> --plan: %v", dr.name, err)
			}
			if raw(text) || raw(errb) {
				t.Errorf("%s's plan prints the directory raw:\n%q\n%q", dr.name, text, errb)
			}
			quoted := strconv.QuoteToGraphic(hostileDir)
			for _, want := range []string{
				"--source=" + quoted,
				"  a source build of " + quoted + ", with ",
				"notice: " + strconv.QuoteToGraphic(fmt.Sprintf(msgSourceBuildNotice, hostileDir)) + "\n",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("%s's plan should hold %q:\n%s", dr.name, want, text)
				}
			}
		})
	}
	// What deciding the images said, outside the plan, under --confirm
	// (review S-CSEC-4): a kept operator build whose recorded checkout
	// holds an escape is said Go-quoted after the comparison, as the plan
	// showed it, never raw.
	const hostileSource = "/src\x1b[2Jevil"
	keptHostile := recorded(func(m *config.InstanceMetadata) {
		recordFatLine(m, imageIn("fatline", "a"), config.SystemImage{Origin: config.OriginOperator, Go: "go1.27.5",
			Farcast: testVersion, BuiltAt: testBuiltAt, Source: hostileSource})
	})
	for _, dr := range deployRigs() {
		t.Run(dr.name+" --confirm", func(t *testing.T) {
			r := dr.rig(t, keptHostile)
			r.fb.resolveFn = tagOrDigest
			doc := r.plan(t)
			_, errb, err := r.run(t, output.ModeHuman, "--confirm", doc.Digest)
			if err != nil {
				t.Fatalf("%s --confirm: %v\n%s", dr.name, err, errb)
			}
			if quoted := strconv.QuoteToGraphic(hostileSource); raw(errb) || !strings.Contains(errb, quoted[1:len(quoted)-1]) {
				t.Errorf("%s --confirm should say the kept build's checkout Go-quoted, never raw:\n%q", dr.name, errb)
			}
		})
	}
	// And redeploy's question names a recorded image as it is shown
	// everywhere else: a deploy record that holds an escape, with no
	// provenance, is said Go-quoted in the replacement note and in the
	// change the operator is asked about; and so is the image it deploys
	// when the recorded registry holds one.
	t.Run("redeploy's question", func(t *testing.T) {
		const hostileImage = "registry.example/fat\x1b[2Jline@sha256:0000000000000000000000000000000000000000000000000000000000000000"
		r := newRedeployRig(t, recorded(func(m *config.InstanceMetadata) { recordDeployedImage(m, hostileImage) }))
		r.fb.resolveFn = tagOrDigest
		r.in = devNullTerminal
		_, errb, _ := r.run(t, output.ModeHuman)
		quoted := strconv.QuoteToGraphic(hostileImage)
		if raw(errb) || !strings.Contains(errb, "this replaces the image \"prod\" runs: "+quoted+" → ") ||
			!strings.Contains(errb, strconv.QuoteToGraphic("fatline: replacing "+hostileImage+" (its origin is not recorded on this machine).")+"\n") {
			t.Errorf("redeploy should name the recorded image Go-quoted in its note and its question, never raw:\n%q", errb)
		}

		const hostilePrefix = "us-central1-docker.pkg.dev/proj-1/farcast-\x1b[2Jprod"
		r = newRedeployRig(t, recorded(func(m *config.InstanceMetadata) {
			m.Registry.Prefix = hostilePrefix
			recordDeployedImage(m, imageIn("fatline", "1"))
		}))
		r.fb.resolveFn = tagOrDigest
		r.in = devNullTerminal
		_, errb, _ = r.run(t, output.ModeHuman)
		target := strconv.QuoteToGraphic(hostilePrefix + "/system/fatline@" + sha(tagDigest))
		if raw(errb) || !strings.Contains(errb, "this replaces the image \"prod\" runs: "+imageIn("fatline", "1")+" → "+target+".\n") {
			t.Errorf("redeploy should name the image it deploys Go-quoted in its question, never raw:\n%q", errb)
		}
	})
	// What the plans of the commands that read the cluster bind from it, or
	// from the record (ADR 0023 M2.6c): farcast-system's uid, which the
	// cluster answers and the header names, and, for kernel deploy, a
	// namespace the record meters that the cluster no longer has, which the
	// plan names in a notice. Each prints Go-quoted in the rendering, never
	// raw.
	t.Run("the commands that read the cluster", func(t *testing.T) {
		const hostileUID = "uid\x1b[2Jevil\u202etxt"
		const hostileNamespace = "gone\x1b[2Kns\u202e"
		for _, row := range readerPlans(t) {
			t.Run(row.String(), func(t *testing.T) {
				row.seed = func(s *kubetest.Server) {
					s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{
						"name": tcdeploy.DefaultNamespace, "uid": hostileUID}})
				}
				if row.name == "kernel deploy" {
					row.edit = func(m *config.InstanceMetadata) { m.Kernel.Namespaces = append(m.Kernel.Namespaces, hostileNamespace) }
				}
				_, dir := planFixture(t, row)
				_, text := runPlan(t, dir, row, output.ModeHuman)
				if raw(text) {
					t.Errorf("%s's plan prints a value raw:\n%q", row, text)
				}
				wants := []string{strconv.QuoteToGraphic(hostileUID)}
				if row.name == "kernel deploy" {
					wants = append(wants, "notice: "+terminalText(fmt.Sprintf(msgNoLongerMetering, hostileNamespace))+"\n")
				}
				for _, want := range wants {
					if !strings.Contains(text, want) {
						t.Errorf("%s's plan should hold %q:\n%s", row, want, text)
					}
				}
			})
		}
	})
	t.Run("build", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		meteringInstance(t, dir, "p42")
		fj, opened := &fakeJobs{}, 0
		c := buildPlanCmd(t, fj, &fakeBuilder{}, &opened, "--repo", "https://github.com/example/repo.git",
			"--app", "api\x1b[2K\u202e", "--builder-image", builderDigest, "--plan")
		env, out, errb := testEnvBoth(dir, output.ModeHuman)
		err := c.Run(t.Context(), env, []string{"p42"})
		if err == nil || raw(err.Error()) || out.Len() != 0 || raw(errb.String()) {
			t.Errorf("build --app <hostile> --plan = %v, printing %q %q; want it refused, nothing raw", err, out, errb)
		}
		if opened+len(fj.applied) != 0 {
			t.Errorf("opened the writer %d times and applied %d streams", opened, len(fj.applied))
		}
	})
}

// setStrings sets every exported string below v, but a fact's Type, to s.
func setStrings(v reflect.Value, s string) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() && v.Kind() == reflect.Pointer {
			setStrings(v.Elem(), s)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if f := v.Type().Field(i); f.IsExported() && f.Name != "Type" {
				setStrings(v.Field(i), s)
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			setStrings(v.Index(i), s)
		}
	case reflect.String:
		v.SetString(s)
	}
}

// TestPlanDocumentCarriesTheBytesItsDigestCovers: a printed plan's bound
// member is exactly the canonical bytes, so hashing what was printed gives
// the printed digest (row 78). The plan holds <, > and &, which an encoder
// that escapes HTML would rewrite; and the document carries nothing else.
func TestPlanDocumentCarriesTheBytesItsDigestCovers(t *testing.T) {
	b := sampleBound(
		plan.ConfirmationFact{Type: plan.TypeConfirmation, From: "2026-11-01", To: "2026-11-02", AmountCents: 150, AsOfDay: "2026-11-16"},
		plan.NoticeFact{Type: plan.TypeNotice, Text: "Nothing to confirm: <b> & </b> > 0"},
	)
	env, out, _ := testEnvBoth("", output.ModeJSON)
	if err := printPlan(env, b, planNow); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema      int             `json:"schema"`
		Kind        string          `json:"kind"`
		GeneratedAt string          `json:"generated_at"`
		Digest      string          `json:"digest"`
		Bound       json.RawMessage `json:"bound"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("%v: %s", err, out.Bytes())
	}
	if got := plan.DigestOf(doc.Bound); got != doc.Digest {
		t.Errorf("the printed bound hashes to %s, the document says %s", got, doc.Digest)
	}
	if want := mustCanonical(t, b); string(doc.Bound) != want {
		t.Errorf("the printed bound is\n%s\nwant the canonical bytes\n%s", doc.Bound, want)
	}
	if !bytes.Contains(doc.Bound, []byte("<b> & </b> > 0")) {
		t.Errorf("the printed bound rewrote <, > or &: %s", doc.Bound)
	}
	if doc.Schema != plan.Schema || doc.Kind != plan.Kind || doc.GeneratedAt != plan.Time(planNow) {
		t.Errorf("the document opens %d %q %q", doc.Schema, doc.Kind, doc.GeneratedAt)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(members))
	for k := range members {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if want := []string{"bound", "digest", "generated_at", "kind", "schema"}; !slices.Equal(keys, want) {
		t.Errorf("the document's members are %v, want %v", keys, want)
	}

	// Every plan a command prints.
	for _, row := range planCommands() {
		_, dir := planFixture(t, row)
		doc, out := runPlan(t, dir, row, output.ModeJSON)
		if got := plan.DigestOf(doc.Bound); got != doc.Digest {
			t.Errorf("%s: the printed bound hashes to %s, the document says %s", row, got, doc.Digest)
		}
		if !strings.Contains(out, `"bound":`+string(doc.Bound)+"}") {
			t.Errorf("%s: the bound member is not printed as its bytes:\n%s", row, out)
		}
	}
}

// TestABlockedPlanIsRefusedWithItsKind: --plan prints a blocked plan and
// exits 0, its blocks first and, in place of the confirm line, the line
// saying --confirm would refuse it; its JSON carries the blocks. --confirm
// compares the digest first, then refuses with the first block's kind and
// message, exit 1 (A23-7). (ADR 0023 M2.6a: rows here print and confirm the
// plan; reader grant's blocked plan adds a row through the command.)
func TestABlockedPlanIsRefusedWithItsKind(t *testing.T) {
	msg := "instance \"atlas\" has no reader identity; run 'farcast reader init atlas'"
	b := sampleBound()
	b.ClusterIdentity, b.Target.SystemNamespaceUID = "none", ""
	b.Blocked = []plan.Block{
		blockOf(refuse(errCredentialMissing, "%s", msg)),
		{Kind: kindInternal, Message: "a second block"},
	}

	env, out, _ := testEnvBoth("", output.ModeHuman)
	err := printPlan(env, b, planNow)
	if exitCodeOf(err) != 0 {
		t.Fatalf("--plan of a blocked plan: %v (exit %d)", err, exitCodeOf(err))
	}
	text := out.String()
	digest := plan.DigestOf([]byte(mustCanonical(t, b)))
	if !strings.HasPrefix(text, "blocked (credential_missing): "+msg+"\nblocked (internal): a second block\n") {
		t.Errorf("the rendering does not begin with its blocks:\n%s", text)
	}
	if !strings.HasSuffix(text, "\ndigest: "+digest+"\nblocked: --confirm would refuse this plan (credential_missing)\n") {
		t.Errorf("the rendering does not end with its digest and the blocked line:\n%s", text)
	}
	if strings.Contains(text, "To do exactly this") {
		t.Errorf("a blocked plan offers a confirm line:\n%s", text)
	}

	env, out, _ = testEnvBoth("", output.ModeJSON)
	if err := printPlan(env, b, planNow); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Digest string `json:"digest"`
		Bound  struct {
			Facts   []json.RawMessage `json:"facts"`
			Blocked []plan.Block      `json:"blocked"`
		} `json:"bound"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Digest != digest || len(doc.Bound.Facts) != 0 || !slices.Equal(doc.Bound.Blocked, b.Blocked) {
		t.Errorf("the JSON plan is %s", out.Bytes())
	}

	err = confirmPlan(b, digest)
	if kindOf(classified(err)) != kindCredentialMissing || err.Error() != msg || exitCodeOf(err) != 1 {
		t.Errorf("--confirm of the blocked plan = %v (kind %s, exit %d), want its first block", err, kindOf(classified(err)), exitCodeOf(err))
	}
	err = confirmPlan(b, sampleDigest)
	if kindOf(classified(err)) != kindPlanChanged {
		t.Errorf("--confirm of a blocked plan whose digest changed = %v (kind %s), want plan_changed first", err, kindOf(classified(err)))
	}

	t.Run("reader grant", func(t *testing.T) {
		ran := strayKubectl(t)
		s, dir := planFixture(t, planCommandNamed(t, "reader grant", "no reader"))
		before := treeFiles(t, string(dir))
		stdout, stderr, code := farcastIn(t, dir, "reader", "grant", writeName, "--plan")
		if code != 0 || !strings.HasPrefix(stdout, "blocked (credential_missing): "+msg+"\n\n") ||
			!strings.HasSuffix(stdout, "\nblocked: --confirm would refuse this plan (credential_missing)\n") || strings.Contains(stdout, "To do exactly this") {
			t.Errorf("reader grant --plan of a blocked plan: exit %d, %q\n%s", code, stderr, stdout)
		}
		stdout, _, code = farcastIn(t, dir, "-o", "json", "reader", "grant", writeName, "--plan")
		doc := printedDocument(t, []byte(stdout))
		if got := decodedBound(t, doc); code != 0 || len(got.Facts) != 0 || !slices.Equal(got.Blocked, []plan.Block{{Kind: kindCredentialMissing, Message: msg}}) {
			t.Errorf("the JSON plan: exit %d, %s", code, stdout)
		}
		stdout, _, code = farcastIn(t, dir, "-o", "json", "reader", "grant", writeName, "--confirm", doc.Digest)
		var envelope struct {
			Error struct {
				Message string `json:"message"`
				Code    int    `json:"code"`
				Kind    string `json:"kind"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(stdout), &envelope); err != nil || code != 1 ||
			envelope.Error.Kind != kindCredentialMissing || envelope.Error.Message != msg || envelope.Error.Code != 1 {
			t.Errorf("reader grant --confirm of a blocked plan: exit %d, %s (%v)", code, stdout, err)
		}
		if len(s.Requests()) != 0 || ran() {
			t.Errorf("a blocked plan sent %d requests or ran kubectl (%v)", len(s.Requests()), ran())
		}
		sameFiles(t, "a blocked reader grant", before, treeFiles(t, string(dir)))
	})

	// The blocks of the commands that read the cluster (ADR 0023 M2.6c,
	// A23-18): kernel deploy's namespace the cluster lacks, and a keyring
	// behind the pin for storage deploy, storage key pin and storage key
	// rotate. Each plan begins with its one block, internal, and ends with
	// the blocked line and no confirm line; its --confirm recomputes it as
	// the reader and refuses with the block's kind and words, exit 1,
	// printing nothing, having opened no writer, provider, storage or
	// keyholder, sent nothing but the reader's reads, run no kubectl and
	// written nothing.
	t.Run("the commands that read the cluster", func(t *testing.T) {
		for _, row := range []planCommand{
			planCommandNamed(t, "kernel deploy", "a missing namespace"),
			planCommandNamed(t, "storage deploy", "behind the pin"),
			planCommandNamed(t, "storage key pin", "behind the pin"),
			planCommandNamed(t, "storage key rotate", "behind the pin"),
		} {
			t.Run(row.String(), func(t *testing.T) {
				ran := strayKubectl(t)
				s, dir := planFixture(t, row)
				before := treeFiles(t, string(dir))
				doc, _ := runPlan(t, dir, row, output.ModeJSON)
				b := decodedBound(t, doc)
				if len(b.Blocked) != 1 || b.Blocked[0].Kind != kindInternal || len(b.Facts) != 0 {
					t.Fatalf("%s's plan blocks %+v with %d facts; want one internal block and none", row, b.Blocked, len(b.Facts))
				}
				block := b.Blocked[0]
				_, text := runPlan(t, dir, row, output.ModeHuman)
				first, _, _ := strings.Cut(block.Message, "\n")
				if !strings.HasPrefix(text, "blocked (internal): "+output.ErrorText(first)) ||
					!strings.HasSuffix(text, "\ndigest: "+doc.Digest+"\nblocked: --confirm would refuse this plan (internal)\n") ||
					strings.Contains(text, "To do exactly this") {
					t.Errorf("%s --plan of a blocked plan:\n%s", row, text)
				}

				cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", doc.Digest)...)
				env, out, _ := testEnvBoth(dir, output.ModeJSON)
				err := cmd.Run(t.Context(), env, row.args)
				if err == nil || err.Error() != block.Message || kindOf(classified(err)) != kindInternal || exitCodeOf(err) != 1 {
					t.Errorf("%s --confirm of the blocked plan = %v (kind %s, exit %d); want its block", row, err, kindOf(classified(err)), exitCodeOf(err))
				}
				f := row.fakes
				if out.Len() != 0 || f.opened+f.writers+f.storages+f.keyholders != 0 {
					t.Errorf("%s --confirm of the blocked plan printed %q, and opened the provider %d times, the writer %d, storage %d and the keyholder %d",
						row, out, f.opened, f.writers, f.storages, f.keyholders)
				}
				if ran() {
					t.Errorf("%s ran kubectl for a blocked plan", row)
				}
				onlyThePlansReads(t, row, s)
				sameFiles(t, "a blocked "+row.name, before, treeFiles(t, string(dir)))
			})
		}
	})

	// connect, redeploy and build have no block (A23-35 to A23-37): what
	// would stop them refuses before any plan is computed, so every plan
	// they print is unblocked and ends with its confirm line.
	t.Run("connect, redeploy and build never block", func(t *testing.T) {
		for _, row := range planCommands() {
			if !slices.Contains([]string{"connect", "redeploy", "build"}, row.name) {
				continue
			}
			_, dir := planFixture(t, row)
			doc, _ := runPlan(t, dir, row, output.ModeJSON)
			_, text := runPlan(t, dir, row, output.ModeHuman)
			if b := decodedBound(t, doc); len(b.Blocked) != 0 || !strings.Contains(text, "\nTo do exactly this: ") || strings.Contains(text, "blocked") {
				t.Errorf("%s's plan is blocked (%+v), or offers no confirm line:\n%s", row, b.Blocked, text)
			}
		}
	})
}

// TestBlockKindsAreErrorKinds: a block's kind is the kind the router gives
// the refusal, so it is always one of the closed set; its message is the
// refusal's own text. (ADR 0023 M2.6a: rows for the refusals blockOf is
// given; each command that blocks adds its own.)
func TestBlockKindsAreErrorKinds(t *testing.T) {
	for _, tc := range []struct {
		err  error
		kind string
	}{
		{refuse(errCredentialMissing, "instance %q has no reader identity", "atlas"), kindCredentialMissing},
		{fmt.Errorf("instance %q: namespaces are missing:\n  web", "atlas"), kindInternal},
		{fmt.Errorf("load instance %q: %w", "atlas", config.ErrNoInstanceRecord), kindNotFound},
		{fmt.Errorf("read: %w", tkube.ErrForbidden), kindForbidden},
		{withKind(kindPlanChanged, errors.New("moved")), kindPlanChanged},
		{withKind("", errors.New("a kind left empty")), kindInternal},
	} {
		b := blockOf(tc.err)
		if b.Kind != tc.kind || b.Message != tc.err.Error() {
			t.Errorf("blockOf(%v) = %+v, want kind %s", tc.err, b, tc.kind)
		}
		if !slices.Contains(errorKinds, b.Kind) {
			t.Errorf("blockOf(%v) has the kind %q, which is not an error kind", tc.err, b.Kind)
		}
	}

	// storage deploy's, storage key pin's and storage key rotate's blocks, a
	// keyring behind the pin, as their plans raise them (A23-18): internal,
	// with nothing read after.
	// Each block is the command's own refusal, word for word as it says
	// what it did not do.
	for _, tc := range []struct {
		row     planCommand
		refusal string
	}{
		{planCommandNamed(t, "storage deploy", "behind the pin"), "so nothing was deployed"},
		{planCommandNamed(t, "storage key pin", "behind the pin"), "Nothing was written"},
		{planCommandNamed(t, "storage key rotate", "behind the pin"), "so nothing was rotated"},
	} {
		row, refusal := tc.row, tc.refusal
		_, dir := planFixture(t, row)
		doc, _ := runPlan(t, dir, row, output.ModeJSON)
		b := decodedBound(t, doc)
		if len(b.Blocked) != 1 || b.Blocked[0].Kind != kindInternal || !strings.HasPrefix(b.Blocked[0].Message, "this keyring is behind the instance's key pin") ||
			!strings.Contains(b.Blocked[0].Message, refusal) || len(b.Facts) != 0 {
			t.Errorf("%s blocks %+v with %d facts; want one internal block, the keyring behind the pin saying %q, and no facts", row, b.Blocked, len(b.Facts), refusal)
		}
	}

	// kernel deploy's block, a namespace --namespaces names that the cluster
	// lacks, as its plan raises it (A23-18): internal, in the refusal's own
	// words.
	{
		row := planCommandNamed(t, "kernel deploy", "a missing namespace")
		_, dir := planFixture(t, row)
		doc, _ := runPlan(t, dir, row, output.ModeJSON)
		want := plan.Block{Kind: kindInternal, Message: fmt.Sprintf(msgNoSuchNamespace, "web")}
		if blocked := decodedBound(t, doc).Blocked; !slices.Equal(blocked, []plan.Block{want}) || !slices.Contains(errorKinds, blocked[0].Kind) {
			t.Errorf("%s blocks %+v; want %+v, an error kind", row, blocked, want)
		}
	}

	// reader grant's blocks, as its plan raises them.
	for name, edit := range map[string]func(m *config.InstanceMetadata){
		"no reader":              func(m *config.InstanceMetadata) { m.Reader = nil },
		"no key id":              func(m *config.InstanceMetadata) { m.Reader.KeyID = "" },
		"not the derived reader": func(m *config.InstanceMetadata) { m.Reader.Email = "writer@kubetest.invalid" },
	} {
		row := planCommandNamed(t, "reader grant", "no reader")
		row.edit = edit
		_, dir := planFixture(t, row)
		doc, _ := runPlan(t, dir, row, output.ModeJSON)
		blocked := decodedBound(t, doc).Blocked
		if len(blocked) != 1 || blocked[0].Kind != kindCredentialMissing || !slices.Contains(errorKinds, blocked[0].Kind) {
			t.Errorf("reader grant with %s blocks %+v; want one credential_missing block", name, blocked)
		}
	}
}

// TestConfirmRefusesAChangedPlan: --confirm executes only the plan whose
// digest it was given; a plan that changed since is refused with
// plan_changed, exit 1, design §9.2's text naming both digests (row 74).
// (ADR 0023 M2.6a: rows here compare the plans; each command adds rows
// that change what its plan binds between --plan and --confirm.)
func TestConfirmRefusesAChangedPlan(t *testing.T) {
	meter := plan.MeterFact{Type: plan.TypeMeter, Add: []string{"extra"}, MeteredAfter: []string{"extra", "farcast-system"}}
	before := sampleBound(meter)
	given := plan.DigestOf([]byte(mustCanonical(t, before)))
	if err := confirmPlan(before, given); err != nil {
		t.Fatalf("--confirm of the same plan: %v", err)
	}

	for name, change := range map[string]func(*plan.Bound){
		"a fact": func(b *plan.Bound) {
			b.Facts = []plan.Fact{plan.MeterFact{Type: plan.TypeMeter, Add: []string{"other"}}}
		},
		"the target": func(b *plan.Bound) { b.Target.Project = "proj-other" },
		"an option":  func(b *plan.Bound) { b.Options = []plan.Option{{Flag: "remove", Value: "true"}} },
		"the stamp":  func(b *plan.Bound) { b.FarCast.Commit = "c-other" },
	} {
		after := sampleBound(meter)
		change(&after)
		now := plan.DigestOf([]byte(mustCanonical(t, after)))
		err := confirmPlan(after, given)
		want := "the plan for this command is now " + now + ", not the " + given + " given to --confirm: " +
			"something it binds has changed since the plan was made; run it with --plan to review the new one. Nothing was written."
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
			t.Errorf("%s changed: --confirm = %v (kind %s, exit %d), want %q", name, err, kindOf(classified(err)), exitCodeOf(err), want)
		}
	}

	// Each command's plan, changed between --plan and --confirm by its
	// record: refused plan_changed, exit 1, naming both digests, with
	// nothing sent but a plan's reads as the reader, run or written. Through
	// the router, connect, redeploy and kernel deploy carry no components (a
	// test binary is not a release), so they plan a build of this checkout;
	// what the registry answers is changed below, on a release.
	for _, tc := range []struct {
		row    planCommand
		change func(m *config.InstanceMetadata)
		// changeCluster, when set, changes what the plan read in the
		// cluster instead.
		changeCluster func(s *kubetest.Server)
	}{
		{row: planCommandNamed(t, "kernel meter", "add"), change: func(m *config.InstanceMetadata) {
			m.Kernel.Namespaces = append(m.Kernel.Namespaces, "other")
		}},
		{row: planCommandNamed(t, "kernel confirm", "a window"), change: func(m *config.InstanceMetadata) {
			m.Kernel.Confirmations = []config.KernelConfirmation{{Start: day(planMonth(3)), End: day(planMonth(4)), USD: 1}}
		}},
		{row: planCommandNamed(t, "reader grant", "a recorded reader"), change: func(m *config.InstanceMetadata) {
			m.Kernel.Namespaces = append(m.Kernel.Namespaces, "web")
		}},
		// Through the router, with the deployer's defaults faked: connect's
		// cost fact binds the limit.
		{row: planCommandNamed(t, "connect", "first deploy"), change: func(m *config.InstanceMetadata) {
			m.CostLimit.Amount = 75
		}},
		// redeploy's image fact binds the image the record says FatLine runs.
		{row: planCommandNamed(t, "redeploy", "the carried images"), change: func(m *config.InstanceMetadata) {
			recordDeployedImage(m, m.Registry.Prefix+"/system/fatline@"+sha("0"))
		}},
		// build's binds the builder the instance recorded, which runs today.
		{row: planCommandNamed(t, "build", "a named builder"), change: func(m *config.InstanceMetadata) {
			m.Toolchain = &config.Toolchain{Builder: builderDigest}
		}},
		// kernel deploy's cost fact binds the limit; it reads the cluster as
		// the reader, and the writer never opens.
		{row: planCommandNamed(t, "kernel deploy", "the carried image"), change: func(m *config.InstanceMetadata) {
			m.CostLimit.Amount = 75
		}},
		// storage deploy's cost fact binds the limit too; it reads the pin
		// and the cluster as the reader.
		{row: planCommandNamed(t, "storage deploy", "the recorded bucket"), change: func(m *config.InstanceMetadata) {
			m.CostLimit.Amount = 75
		}},
		// storage key pin's pin fact binds the pin it read: another writer
		// put one there since.
		{row: planCommandNamed(t, "storage key pin", "a pin to write"), changeCluster: pinSeeded(pinRetiringForeign)},
		// storage key rotate's pins bind the pin it read, too.
		{row: planCommandNamed(t, "storage key rotate", "with a keyholder"), changeCluster: pinSeeded(pinRetiringForeign)},
		// And its rotation fact binds the keyholder's replicas.
		{row: planCommandNamed(t, "storage key rotate", "with a keyholder"), change: func(m *config.InstanceMetadata) {
			m.Keyholder.Replicas = 3
		}},
	} {
		t.Run(tc.row.String(), func(t *testing.T) {
			ran := strayKubectl(t)
			pinPlanClock(t)
			fakeDeployDefaults(t)
			s, dir := planFixture(t, tc.row)
			wc := writeCommand{name: tc.row.name, args: tc.row.args, flags: tc.row.flags}
			planned := func() string {
				stdout, stderr, code := runLine(commandLine(dir, wc, "-o", "json", "--plan"))
				if code != 0 {
					t.Fatalf("--plan: exit %d, %s", code, stderr)
				}
				return printedDocument(t, []byte(stdout)).Digest
			}
			given := planned()
			if tc.changeCluster != nil {
				tc.changeCluster(s)
			} else if _, err := dir.UpdateInstanceMetadata(writeName, func(m *config.InstanceMetadata) error {
				tc.change(m)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			now := planned()
			before := treeFiles(t, string(dir))
			stdout, _, code := runLine(commandLine(dir, wc, "-o", "json", "--confirm", given))
			want := "the plan for this command is now " + now + ", not the " + given + " given to --confirm: " +
				"something it binds has changed since the plan was made; run it with --plan to review the new one. Nothing was written."
			var envelope struct {
				Error struct {
					Message string `json:"message"`
					Kind    string `json:"kind"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &envelope); err != nil || code != 1 || envelope.Error.Kind != kindPlanChanged || envelope.Error.Message != want {
				t.Errorf("--confirm of the old plan: exit %d, %s (%v); want plan_changed, %q", code, stdout, err, want)
			}
			if ran() {
				t.Error("a changed plan ran kubectl")
			}
			onlyThePlansReads(t, tc.row, s)
			sameFiles(t, "a changed plan", before, treeFiles(t, string(dir)))
		})
	}

	// connect's and redeploy's image facts bind what the registry's version
	// tag answered, as a release farcast that carries its components asks
	// it: holding the carried image when planned (a reuse), and gone when
	// confirmed (a push). Refused plan_changed before the writer opens, with
	// nothing minted, ensured, pushed or applied.
	for _, dr := range deployRigs() {
		t.Run(dr.name+"/the version tag gone", func(t *testing.T) {
			r := dr.rig(t)
			given := r.plan(t).Digest
			r.fb.resolveFn = notFoundForTags
			now := r.plan(t).Digest
			before := r.files(t)
			_, _, err := r.run(t, output.ModeJSON, "--confirm", given)
			want := "the plan for this command is now " + now + ", not the " + given + " given to --confirm: " +
				"something it binds has changed since the plan was made; run it with --plan to review the new one. Nothing was written."
			if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
				t.Errorf("%s --confirm after the tag moved = %v (kind %s); want plan_changed, %q", dr.name, err, kindOf(classified(err)), want)
			}
			if r.writers+r.dials+len(r.fp.ensured)+len(r.fb.embedded)+len(r.fb.built)+len(r.fc.applied) != 0 {
				t.Errorf("opened the writer %d times, dialled %d, ensured %d, pushed %d, built %d, applied %d",
					r.writers, r.dials, len(r.fp.ensured), len(r.fb.embedded), len(r.fb.built), len(r.fc.applied))
			}
			sameFiles(t, "a plan whose tag moved", before, r.files(t))
		})
	}
}

// copyConfigDir is a second config directory holding a copy of every file
// under src, at the same modes: the same instances, as another machine's
// directory, or a backup, would hold them.
func copyConfigDir(t *testing.T, src config.Dir) config.Dir {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "other")
	err := filepath.WalkDir(string(src), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(string(src), p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, info.Mode().Perm())
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(to, data, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
	return config.Dir(dst)
}

// confirmRefusedAsChanged runs row's --confirm of digest against dir, as
// the row's command with its own seams, and fails t unless it is refused
// plan_changed, exit 1, design §9.2's text naming the digest given, printing
// nothing, having opened no writer, storage or keyholder, ensured, built or
// pushed nothing, sent nothing to s but a plan's reads as the reader, and
// written nothing under dir.
func confirmRefusedAsChanged(t *testing.T, row planCommand, s *kubetest.Server, dir config.Dir, digest string) {
	t.Helper()
	before := treeFiles(t, string(dir))
	cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", digest)...)
	env, out, _ := testEnvBoth(dir, output.ModeJSON)
	err := cmd.Run(t.Context(), env, row.args)
	if err == nil || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 ||
		!strings.HasPrefix(err.Error(), "the plan for this command is now sha256:") || !strings.Contains(err.Error(), ", not the "+digest+" given to --confirm: ") {
		t.Errorf("%s --confirm of the plan = %v (kind %s, exit %d); want plan_changed, naming %s", row, err, kindOf(classified(err)), exitCodeOf(err), digest)
	}
	if out.Len() != 0 {
		t.Errorf("%s --confirm of a plan that changed printed %q", row, out)
	}
	if f := row.fakes; f != nil && (f.writers+f.storages+f.keyholders+f.dialled != 0 || len(f.provider.ensured)+len(f.builder.built)+len(f.builder.embedded) != 0) {
		t.Errorf("%s --confirm of a plan that changed opened the writer %d times, storage %d, the keyholder %d, dialled %d, "+
			"and ensured %d registries, built %d and pushed %d images", row, f.writers, f.storages, f.keyholders, f.dialled,
			len(f.provider.ensured), len(f.builder.built), len(f.builder.embedded))
	}
	onlyThePlansReads(t, row, s)
	sameFiles(t, row.String()+" --confirm of a plan that changed", before, treeFiles(t, string(dir)))
}

// ADR 0023 M2.6 (design §9.3, row 77): a plan binds the instance's target,
// and its project among it. A plan reviewed against one config directory is
// confirmed against a second that holds a copy of every file of the first,
// the record's project alone changed: the recomputed plan is another, so
// --confirm refuses it plan_changed and nothing is opened, sent or written.
// kernel meter reads no cluster; storage key pin and kernel deploy read it
// as the reader, both directories naming the same one.
func TestPlanFromAnotherConfigDirIsRefused(t *testing.T) {
	for _, row := range []planCommand{
		planCommandNamed(t, "kernel meter", "add"),
		planCommandNamed(t, "storage key pin", "a pin to write"),
		planCommandNamed(t, "kernel deploy", "the carried image"),
	} {
		t.Run(row.String(), func(t *testing.T) {
			ran := strayKubectl(t)
			s, dir := planFixture(t, row)
			doc, _ := runPlan(t, dir, row, output.ModeJSON)
			other := copyConfigDir(t, dir)
			if _, err := other.UpdateInstanceMetadata(writeName, func(m *config.InstanceMetadata) error {
				m.Project = "proj-test2"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			confirmRefusedAsChanged(t, row, s, other, doc.Digest)
			if ran() {
				t.Error("a plan confirmed against another directory ran kubectl")
			}
		})
	}
}

// ADR 0023 M2.6 (design §9.3): a plan binds the record's creation time. An
// instance released and installed again under the same name, project,
// region and cluster records a new one, so a plan made before is refused
// plan_changed by --confirm after, with nothing opened, sent or written.
func TestPlanAfterReinstallIsRefused(t *testing.T) {
	for _, row := range []planCommand{
		planCommandNamed(t, "kernel meter", "add"),
		planCommandNamed(t, "storage key pin", "a pin to write"),
	} {
		t.Run(row.String(), func(t *testing.T) {
			ran := strayKubectl(t)
			s, dir := planFixture(t, row)
			doc, _ := runPlan(t, dir, row, output.ModeJSON)
			if _, err := dir.UpdateInstanceMetadata(writeName, func(m *config.InstanceMetadata) error {
				m.CreatedAt = m.CreatedAt.Add(24 * time.Hour)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			confirmRefusedAsChanged(t, row, s, dir, doc.Digest)
			if ran() {
				t.Error("a plan confirmed after a reinstall ran kubectl")
			}
		})
	}
}

// ADR 0023 M2.6 (design §9.3, row 77): a plan that reads the cluster binds
// farcast-system's uid. The same record, its cluster's farcast-system
// replaced between --plan and --confirm — kubetest seeded again with
// another uid — is another cluster: --confirm, recomputing as the reader,
// refuses plan_changed before the writer opens, for every command whose plan
// reads it.
func TestPlanAgainstAReplacedSystemNamespaceIsRefused(t *testing.T) {
	for _, row := range readerPlans(t) {
		t.Run(row.String(), func(t *testing.T) {
			ran := strayKubectl(t)
			s, dir := planFixture(t, row)
			doc, _ := runPlan(t, dir, row, output.ModeJSON)
			if got := decodedBound(t, doc).Target.SystemNamespaceUID; got != planSystemUID {
				t.Fatalf("%s's plan binds farcast-system's uid %q; want %q", row, got, planSystemUID)
			}
			s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{
				"name": tcdeploy.DefaultNamespace, "uid": "00000000-0000-4000-8000-0000000000a2"}})
			confirmRefusedAsChanged(t, row, s, dir, doc.Digest)
			if ran() {
				t.Error("a plan confirmed against a replaced farcast-system ran kubectl")
			}
		})
	}
}

// irreversibleSample is a fact that cannot be undone; no fact of ADR 0023
// M2.6 is one, so the test makes its own.
type irreversibleSample struct {
	Type string `json:"type"`
	What string `json:"what"`
	once bool
}

func (irreversibleSample) FactType() string     { return "irreversible_sample" }
func (s irreversibleSample) Irreversible() bool { return !s.once }

// TestIrreversibleFactsComeFirst: a fact that says it cannot be undone is
// rendered before the others, and a fact type the rendering has no words for
// is still shown in full, as its JSON.
func TestIrreversibleFactsComeFirst(t *testing.T) {
	notice := plan.NoticeFact{Type: plan.TypeNotice, Text: "a notice"}
	r := planResult{typed: sampleBound(notice, irreversibleSample{Type: "irreversible_sample", What: "x <y>"}), confirm: "To do exactly this: …"}
	var w bytes.Buffer
	if err := r.Human(&w); err != nil {
		t.Fatal(err)
	}
	if want := "\n\nfact irreversible_sample: {\"type\":\"irreversible_sample\",\"what\":\"x <y>\"}\nnotice: a notice\n"; !strings.Contains(w.String(), want) {
		t.Errorf("the irreversible fact does not come first:\n%s", w.String())
	}

	r.typed = sampleBound(notice, &irreversibleSample{Type: "irreversible_sample", What: "z", once: true})
	w.Reset()
	if err := r.Human(&w); err != nil {
		t.Fatal(err)
	}
	if want := "notice: a notice\nfact irreversible_sample: {\"type\":\"irreversible_sample\",\"what\":\"z\"}\n"; !strings.Contains(w.String(), want) {
		t.Errorf("a fact that can be undone moved:\n%s", w.String())
	}
}
