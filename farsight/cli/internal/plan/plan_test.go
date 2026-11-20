package plan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// atlasBound is a plan for the atlas fixture instance, with every slice of its
// own given, so a test of something else never depends on nil normalization.
func atlasBound(facts ...Fact) Bound {
	if facts == nil {
		facts = []Fact{}
	}
	return Bound{
		Protocol: Protocol,
		FarCast:  Stamp{Version: "v0.0.0-test", Commit: "abc1234"},
		Command:  "kernel meter",
		Instance: "atlas",
		Target: Target{
			Provider:  "gke",
			Project:   "proj-atlas",
			Region:    "europe-west4",
			Cluster:   "farcast-atlas",
			Endpoint:  "gke-1a2b3c.europe-west4.gke.goog",
			CreatedAt: "2026-11-14T09:00:00Z",
		},
		Options:         []Option{{Flag: "remove", Value: "false"}},
		ClusterIdentity: "none",
		Facts:           facts,
		Blocked:         []Block{},
	}
}

// hostileNotice holds the three characters json.Marshal escapes, so any
// encoding but Canonical's gives other bytes.
var hostileNotice = NoticeFact{Type: TypeNotice, Text: `a <b> & "c"`}

func TestCanonicalIsCompactUnescapedAndOrdered(t *testing.T) {
	b := atlasBound(
		MeterFact{
			Type: TypeMeter, Add: []string{"apps", "web"}, Remove: []string{}, BindingsCreated: []string{"apps"},
			BindingsLeft: []string{}, ReaderBindingsCreated: []string{}, MeteredAfter: []string{"web", "apps"},
		},
		&hostileNotice,
	)
	got, err := Canonical(b)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	want := `{"protocol":"farcast-plan-1","farcast":{"version":"v0.0.0-test","commit":"abc1234"},` +
		`"command":"kernel meter","instance":"atlas",` +
		`"target":{"provider":"gke","project":"proj-atlas","region":"europe-west4","cluster":"farcast-atlas",` +
		`"endpoint":"gke-1a2b3c.europe-west4.gke.goog","created_at":"2026-11-14T09:00:00Z","system_namespace_uid":""},` +
		`"stage":"","options":[{"flag":"remove","value":"false"}],"cluster_identity":"none",` +
		`"facts":[{"type":"meter","add":["apps","web"],"remove":[],"bindings_created":["apps"],"bindings_left":[],` +
		`"reader":"","reader_bindings_created":[],"metered_after":["web","apps"]},` +
		`{"type":"notice","text":"a <b> & \"c\""}],` +
		`"blocked":[]}`
	if string(got) != want {
		t.Errorf("Canonical:\n got %s\nwant %s", got, want)
	}
	if bytes.HasSuffix(got, []byte("\n")) {
		t.Error("Canonical kept the encoder's trailing newline")
	}
	if !json.Valid(got) {
		t.Error("Canonical's bytes are not JSON")
	}
	again, err := Canonical(b)
	if err != nil || !bytes.Equal(again, got) {
		t.Errorf("a second Canonical of the same plan differs: %s (%v)", again, err)
	}
}

func TestCanonicalWritesEmptyArraysNotNull(t *testing.T) {
	run := &RunFact{Type: TypeRun, Apps: []RunApp{{Name: "web"}}}
	withNils := Bound{Protocol: Protocol, Facts: []Fact{
		CostFact{Type: TypeCost},
		ImageFact{Type: TypeImage},
		KernelSettingsFact{Type: TypeKernelSettings},
		MeterFact{Type: TypeMeter},
		ConfirmationFact{Type: TypeConfirmation},
		PinFact{Type: TypePin},
		run,
		ApplicationResetFact{Type: TypeApplicationReset},
		ReaderFact{Type: TypeReader},
		MigrateFact{Type: TypeMigrate, Objects: []MigrateObject{{Kind: "Deployment"}}},
		GrantFact{Type: TypeGrant},
	}}
	withEmpties := Bound{Protocol: Protocol, Options: []Option{}, Blocked: []Block{}, Facts: []Fact{
		CostFact{Type: TypeCost, Standing: []StandingCost{}, OneOff: []OneOffCost{}},
		ImageFact{Type: TypeImage},
		KernelSettingsFact{Type: TypeKernelSettings, Namespaces: []string{}, ReaderBindingsCreated: []string{}},
		MeterFact{
			Type: TypeMeter, Add: []string{}, Remove: []string{}, BindingsCreated: []string{}, BindingsLeft: []string{},
			ReaderBindingsCreated: []string{}, MeteredAfter: []string{},
		},
		ConfirmationFact{Type: TypeConfirmation, WindowsAfter: []ConfirmationWindow{}},
		PinFact{Type: TypePin, Require: []string{}, Retired: []string{}, Lowering: []string{}},
		RunFact{Type: TypeRun, Apps: []RunApp{{Name: "web", External: []RunHost{}}}, OtherDeploymentsKept: []string{}},
		ApplicationResetFact{Type: TypeApplicationReset},
		ReaderFact{Type: TypeReader, Namespaces: []string{}, Resources: []string{}, ConfigMaps: []string{}, ServiceAccounts: []string{}},
		MigrateFact{Type: TypeMigrate, Local: []string{},
			Objects: []MigrateObject{{Kind: "Deployment", CSAManagers: []string{}, OtherManagers: []string{}}}},
		GrantFact{Type: TypeGrant, Roles: []string{}},
	}}

	got, err := Canonical(withNils)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	want, err := Canonical(withEmpties)
	if err != nil {
		t.Fatalf("Canonical of the empty slices: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("nil slices and empty ones encode differently:\n  nil %s\nempty %s", got, want)
	}

	// Only the optional objects, which are pointers, may be null.
	optional := map[string]bool{"current": true, "source": true, "replicas_live": true, "requests_live": true}
	for _, m := range regexp.MustCompile(`"([a-z_]+)":null`).FindAllStringSubmatch(string(got), -1) {
		if !optional[m[1]] {
			t.Errorf("%q encodes as null, not []: %s", m[1], got)
		}
	}
	for _, member := range []string{
		`"options":[]`, `"blocked":[]`, `"standing":[]`, `"one_off":[]`, `"namespaces":[]`, `"add":[]`,
		`"metered_after":[]`, `"windows_after":[]`, `"lowering":[]`, `"external":[]`, `"other_deployments_kept":[]`,
		`"configmaps":[]`, `"local":[]`, `"csa_managers":[]`, `"other_managers":[]`, `"roles":[]`,
	} {
		if !bytes.Contains(got, []byte(member)) {
			t.Errorf("Canonical has no %s: %s", member, got)
		}
	}

	none, err := Canonical(Bound{Protocol: Protocol})
	if err != nil {
		t.Fatalf("Canonical of a plan with no facts: %v", err)
	}
	if !bytes.Contains(none, []byte(`"facts":[]`)) {
		t.Errorf("a plan with nil facts: %s", none)
	}

	// The copy is Canonical's own: the plan it was given is unchanged.
	if withNils.Options != nil || withNils.Blocked != nil {
		t.Error("Canonical changed the caller's options or blocks")
	}
	if run.Apps[0].External != nil || run.OtherDeploymentsKept != nil {
		t.Error("Canonical changed a fact the caller still holds")
	}
}

func TestCanonicalRefusesUnsortedOptionsAndAMistypedFact(t *testing.T) {
	if _, err := Canonical(atlasBound(MintFact{Type: TypeMint}, &hostileNotice)); err != nil {
		t.Fatalf("the well-formed plan the rows below break is refused: %v", err)
	}
	withOptions := func(o ...Option) Bound {
		b := atlasBound()
		b.Options = o
		return b
	}
	cases := map[string]Bound{
		"options out of order":    withOptions(Option{Flag: "to", Value: ""}, Option{Flag: "amount", Value: "1"}),
		"an option twice":         withOptions(Option{Flag: "amount", Value: "1"}, Option{Flag: "amount", Value: "2"}),
		"a mistyped fact":         atlasBound(MintFact{Type: TypeMint}, CostFact{Type: TypeImage}),
		"a mistyped pointer fact": atlasBound(&NoticeFact{Type: TypeCost, Text: "x"}),
		"an untyped fact":         atlasBound(NoticeFact{Text: "x"}),
		"a nil fact":              atlasBound(MintFact{Type: TypeMint}, nil),
		"a nil pointer fact":      atlasBound((*NoticeFact)(nil)),
		"another protocol": func() Bound {
			b := atlasBound()
			b.Protocol = "farcast-plan-2"
			return b
		}(),
		// encoding/json writes each invalid byte as U+FFFD, so two plans
		// that differ only in an invalid byte would have one digest.
		"a target value that is not UTF-8": func() Bound {
			b := atlasBound()
			b.Target.Project = "proj-\xff"
			return b
		}(),
		"a fact value that is not UTF-8": atlasBound(MeterFact{Type: TypeMeter, MeteredAfter: []string{"web", "a\xfeb"}}),
		"a block that is not UTF-8": func() Bound {
			b := atlasBound()
			b.Blocked = []Block{{Kind: "internal", Message: "\xc3"}}
			return b
		}(),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Canonical(b)
			if err == nil {
				t.Fatalf("Canonical accepted it: %s", got)
			}
			if got != nil {
				t.Errorf("Canonical refused and still returned bytes: %s", got)
			}
			if !strings.HasPrefix(err.Error(), "plan: ") {
				t.Errorf("error %q does not begin with plan: ", err)
			}
			if strings.Contains(name, "nil") && !strings.Contains(err.Error(), " nil") {
				t.Errorf("error %q does not say the fact is nil", err)
			}
			if strings.Contains(name, "UTF-8") && (!strings.Contains(err.Error(), "is not valid UTF-8") || !utf8.ValidString(err.Error())) {
				t.Errorf("error %q does not say where the plan is not UTF-8, in UTF-8", err)
			}
			if _, err := NewDocument(b, time.Unix(0, 0)); err == nil {
				t.Error("NewDocument accepted what Canonical refuses")
			}
		})
	}
}

// factSamples is one value of every fact type, by its Go name.
func factSamples() map[string]Fact {
	return map[string]Fact{
		"CostFact":             CostFact{},
		"ImageFact":            ImageFact{},
		"WriteFact":            WriteFact{},
		"MintFact":             MintFact{},
		"RestartFact":          RestartFact{},
		"CloudFact":            CloudFact{},
		"KernelSettingsFact":   KernelSettingsFact{},
		"MeterFact":            MeterFact{},
		"ConfirmationFact":     ConfirmationFact{},
		"PinFact":              PinFact{},
		"RotationFact":         RotationFact{},
		"FetchFact":            FetchFact{},
		"RunFact":              RunFact{},
		"BuildFact":            BuildFact{},
		"ApplicationResetFact": ApplicationResetFact{},
		"ReaderFact":           ReaderFact{},
		"NoticeFact":           NoticeFact{},
		"MigrateFact":          MigrateFact{},
		"GrantFact":            GrantFact{},
		"GitCredentialFact":    GitCredentialFact{},
	}
}

// factTypesDeclared lists the types this package gives a FactType method, read
// from its source, so a fact type added without a sample fails the walk.
func factTypesDeclared(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "FactType" || len(fn.Recv.List) != 1 {
				continue
			}
			recv := fn.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			if id, ok := recv.(*ast.Ident); ok {
				names = append(names, id.Name)
			}
		}
	}
	sort.Strings(names)
	return names
}

var factInterface = reflect.TypeFor[Fact]()

// checkCanonicalType walks typ: no map, no float, no omitempty or other json
// option, an explicit json name on every field, and no interface but Fact.
func checkCanonicalType(t *testing.T, path string, typ reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	switch typ.Kind() {
	case reflect.Map:
		t.Errorf("%s is a map", path)
	case reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		t.Errorf("%s is a float", path)
	case reflect.Interface:
		if typ != factInterface {
			t.Errorf("%s is an interface other than Fact", path)
		}
	case reflect.Pointer, reflect.Slice, reflect.Array:
		checkCanonicalType(t, path+"[]", typ.Elem(), seen)
	case reflect.Struct:
		if seen[typ] {
			return
		}
		seen[typ] = true
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag, ok := f.Tag.Lookup("json")
			name, opts, _ := strings.Cut(tag, ",")
			switch {
			case !f.IsExported():
				t.Errorf("%s.%s is unexported, so it is never encoded", path, f.Name)
			case !ok || name == "" || name == "-":
				t.Errorf("%s.%s has no json name", path, f.Name)
			case opts != "":
				t.Errorf("%s.%s has json options %q", path, f.Name, opts)
			}
			checkCanonicalType(t, path+"."+name, f.Type, seen)
		}
	}
}

func TestFactTypesAreCanonical(t *testing.T) {
	samples := factSamples()
	var sampled []string
	for name := range samples {
		sampled = append(sampled, name)
	}
	sort.Strings(sampled)
	if declared := factTypesDeclared(t); !reflect.DeepEqual(declared, sampled) {
		t.Fatalf("the fact types declared are\n  %v\nbut the samples are\n  %v", declared, sampled)
	}
	if len(sampled) != 20 {
		t.Errorf("ADR 0023 M2.8 has 20 fact types, not %d", len(sampled))
	}

	seen := map[reflect.Type]bool{}
	for _, typ := range []reflect.Type{reflect.TypeFor[Bound](), reflect.TypeFor[Document]()} {
		checkCanonicalType(t, typ.Name(), typ, seen)
	}
	words := map[string]string{}
	for _, name := range sampled {
		f := samples[name]
		typ := reflect.TypeOf(f)
		if typ.Kind() != reflect.Struct {
			t.Errorf("%s is a %s, not a struct", name, typ.Kind())
			continue
		}
		checkCanonicalType(t, name, typ, seen)
		first := typ.Field(0)
		if first.Name != "Type" || first.Type.Kind() != reflect.String || first.Tag.Get("json") != "type" {
			t.Errorf("%s's first field is %s %s `%s`, not Type string `json:\"type\"`", name, first.Name, first.Type, first.Tag)
		}
		word := f.FactType()
		if other, dup := words[word]; dup {
			t.Errorf("%s and %s share the type word %q", name, other, word)
		}
		words[word] = name
	}
}

// jsonPaths lists typ's JSON members in encoding order, a nested object's
// members after it as parent.member, and an array's elements' as parent[].member.
func jsonPaths(typ reflect.Type, prefix string) []string {
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		path := prefix + name
		out = append(out, path)
		elem, sep := f.Type, "."
		for elem.Kind() == reflect.Pointer || elem.Kind() == reflect.Slice {
			if elem.Kind() == reflect.Slice {
				sep = "[]."
			}
			elem = elem.Elem()
		}
		if elem.Kind() == reflect.Struct {
			out = append(out, jsonPaths(elem, path+sep)...)
		}
	}
	return out
}

func TestFactFieldsFollowTheFactTable(t *testing.T) {
	// §9.4's fact table as A23-33 amends it, with A30-12's migrate fact,
	// A33-11's grant fact, A33-16's service_accounts and A33-29's
	// git_credential fact, and §9.3's Bound and Document.
	want := map[string]string{
		TypeCost: "type currency period limit_cents " +
			"standing standing[].what standing[].replicas standing[].cpu_milli standing[].mem_mib standing[].month_cents standing[].max_month_cents " +
			"one_off one_off[].what one_off[].jobs one_off[].cpu_milli one_off[].mem_mib one_off[].deadline_s " +
			"floor_month_cents below_floor pricing pricing.region pricing.as_of",
		TypeImage: "type component action target go current current.image current.origin current.farcast current.go " +
			"replaces_other_version source source.dir source.go_path source.go_version",
		TypeWrite:          "type api kind namespace name method force resource_version sha256",
		TypeMint:           "type what subject",
		TypeRestart:        "type component because",
		TypeCloud:          "type service action target",
		TypeKernelSettings: "type adapt adapt_cooldown_s interval_s namespaces reader reader_bindings_created",
		TypeMeter:          "type add remove bindings_created bindings_left reader reader_bindings_created metered_after",
		TypeConfirmation: "type from to amount_cents as_of_day " +
			"windows_after windows_after[].from windows_after[].to windows_after[].amount_cents",
		TypePin:      "type require retired lowering repairing",
		TypeRotation: "type new_keys handover_replicas",
		TypeFetch:    "type repository ref manifest job fetcher",
		TypeRun: "type job_uid fetch_plan_digest commit manifest_digest namespace replaces_repository " +
			"apps apps[].name apps[].containerfile apps[].context apps[].external apps[].external[].host apps[].external[].reason " +
			"other_deployments_kept metering_added limit_reached limit_reason",
		TypeBuild: "type repository ref app containerfile context tag destination",
		TypeApplicationReset: "type namespace app state stopped_by_cost_guard limit_reached replicas_live replicas_after " +
			"requests_live requests_live.cpu_milli requests_live.mem_mib requests_after requests_after.cpu_milli requests_after.mem_mib",
		TypeReader: "type email iam_role scope namespaces resources configmaps service_accounts",
		TypeNotice: "type text",
		TypeMigrate: "type objects objects[].api objects[].kind objects[].namespace objects[].name objects[].uid " +
			"objects[].csa_managers objects[].csa_fields_sha256 objects[].annotation objects[].other_managers local irreversible",
		TypeGrant:         "type name target service_account principal roles state shared_principal shared apply",
		TypeGitCredential: "type action namespace name",
	}
	samples := factSamples()
	if len(samples) != len(want) {
		t.Fatalf("%d fact types, %d rows in the table", len(samples), len(want))
	}
	for name, f := range samples {
		row, ok := want[f.FactType()]
		if !ok {
			t.Errorf("%s's type word %q is not in the table", name, f.FactType())
			continue
		}
		if got := strings.Join(jsonPaths(reflect.TypeOf(f), ""), " "); got != row {
			t.Errorf("%s:\n got %s\nwant %s", name, got, row)
		}
	}

	shapes := map[reflect.Type]string{
		reflect.TypeFor[Bound](): "protocol farcast farcast.version farcast.commit command instance " +
			"target target.provider target.project target.region target.cluster target.endpoint target.created_at target.system_namespace_uid " +
			"stage options options[].flag options[].value cluster_identity facts blocked blocked[].kind blocked[].message",
		reflect.TypeFor[Document](): "schema kind generated_at digest bound",
	}
	for typ, row := range shapes {
		if got := strings.Join(jsonPaths(typ, ""), " "); got != row {
			t.Errorf("%s:\n got %s\nwant %s", typ.Name(), got, row)
		}
	}
	if Protocol != "farcast-plan-1" || Schema != 1 || Kind != "plan" {
		t.Errorf("Protocol, Schema, Kind = %q, %d, %q", Protocol, Schema, Kind)
	}
}

func TestDigestOfIsDomainSeparated(t *testing.T) {
	// sha256("farcast-plan-1\n{}"), computed outside Go.
	const pinned = "sha256:5c7e3d4adc05fbb8dc39b3b02fc2b945ff308ac2eb6a7dd8ed48bc7512e62359"
	if got := DigestOf([]byte("{}")); got != pinned {
		t.Errorf("DigestOf({}) = %s, want %s", got, pinned)
	}
	plain := sha256.Sum256([]byte("{}"))
	if DigestOf([]byte("{}")) == "sha256:"+hex.EncodeToString(plain[:]) {
		t.Error("DigestOf is a plain hash of the bytes, with no domain prefix")
	}

	c, err := Canonical(atlasBound(&hostileNotice))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte("farcast-plan-1\n"), c...))
	got := DigestOf(c)
	if want := "sha256:" + hex.EncodeToString(sum[:]); got != want {
		t.Errorf("DigestOf = %s, want %s", got, want)
	}
	if _, err := ParseDigest(got); err != nil {
		t.Errorf("ParseDigest refuses DigestOf's own digest %s: %v", got, err)
	}
}

func TestParseDigest(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	good := "sha256:" + hex64
	for _, s := range []string{good, "sha256:" + strings.Repeat("0", 64)} {
		got, err := ParseDigest(s)
		if err != nil || got != s {
			t.Errorf("ParseDigest(%q) = %q, %v; want it back", s, got, err)
		}
	}
	refused := map[string]string{
		"uppercase hex":      "sha256:" + strings.ToUpper(hex64),
		"one uppercase":      "sha256:A" + hex64[1:],
		"an uppercase name":  "SHA256:" + hex64,
		"63 hex":             "sha256:" + hex64[:63],
		"65 hex":             good + "0",
		"a leading space":    " " + good,
		"a trailing space":   good + " ",
		"an inner space":     "sha256: " + hex64[1:],
		"a trailing newline": good + "\n",
		"empty":              "",
		"the prefix alone":   "sha256:",
		"no prefix":          hex64,
		"another hash":       "sha512:" + hex64,
		"a non-hex letter":   "sha256:g" + hex64[1:],
	}
	// One text for every refusal: it never repeats what was pasted.
	_, errEmpty := ParseDigest("")
	if errEmpty == nil {
		t.Fatal("ParseDigest accepted the empty string")
	}
	for name, s := range refused {
		t.Run(name, func(t *testing.T) {
			got, err := ParseDigest(s)
			if err == nil {
				t.Fatalf("ParseDigest(%q) accepted it as %q", s, got)
			}
			if got != "" {
				t.Errorf("ParseDigest refused and still returned %q", got)
			}
			if !strings.HasPrefix(err.Error(), "plan: ") {
				t.Errorf("error %q does not begin with plan: ", err)
			}
			if err.Error() != errEmpty.Error() {
				t.Errorf("error %q depends on the input; the empty string's is %q", err, errEmpty)
			}
		})
	}
}

func TestNewDocumentStampsSchemaKindAndTime(t *testing.T) {
	cet := time.FixedZone("CET", 3600)
	now := time.Date(2026, 11, 14, 11, 0, 7, 999_999_999, cet)
	if got, want := Time(now), "2026-11-14T10:00:07Z"; got != want {
		t.Errorf("Time = %s, want %s: UTC, whole seconds, RFC 3339", got, want)
	}

	b := atlasBound(MintFact{Type: TypeMint, What: MintKey}, &hostileNotice)
	doc, err := NewDocument(b, now)
	if err != nil {
		t.Fatalf("NewDocument: %v", err)
	}
	c, err := Canonical(b)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || doc.Kind != "plan" || doc.GeneratedAt != "2026-11-14T10:00:07Z" {
		t.Errorf("schema, kind, generated_at = %d, %q, %q", doc.Schema, doc.Kind, doc.GeneratedAt)
	}
	if !bytes.Equal(doc.Bound, c) {
		t.Errorf("bound is not Canonical's bytes:\n got %s\nwant %s", doc.Bound, c)
	}
	if doc.Digest != DigestOf(c) {
		t.Errorf("digest %s is not DigestOf the bound's bytes, %s", doc.Digest, DigestOf(c))
	}

	// Printed as the CLI's printer prints, the document carries the bytes
	// its digest covers, byte for byte.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		t.Fatal(err)
	}
	want := `{"schema":1,"kind":"plan","generated_at":"2026-11-14T10:00:07Z","digest":"` + doc.Digest + `","bound":` + string(c) + "}\n"
	if buf.String() != want {
		t.Errorf("printed:\n got %s\nwant %s", buf.String(), want)
	}
	var back struct {
		Digest string          `json:"digest"`
		Bound  json.RawMessage `json:"bound"`
	}
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if DigestOf(back.Bound) != back.Digest {
		t.Errorf("the printed bound hashes to %s, not the printed digest %s", DigestOf(back.Bound), back.Digest)
	}

	b.Protocol = ""
	if doc, err := NewDocument(b, now); err == nil || !reflect.DeepEqual(doc, Document{}) {
		t.Errorf("NewDocument of a refused plan = %+v, %v", doc, err)
	}
}
