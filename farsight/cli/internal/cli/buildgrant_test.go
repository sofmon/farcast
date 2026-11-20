package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/planck"
)

// The exact string Artifact Registry returned on the 5.1b walk. Matching the
// permission rather than the prose is deliberate: the builder is a pinned
// third-party image whose wording FarCast does not control.
const arDenial = `error checking push permissions -- make sure you entered the correct tag name, ` +
	`and that you are authenticated correctly, and try again: checking push permission for ` +
	`"us-central1-docker.pkg.dev/proj/farcast-p51b/app/demo/reacher:abc": creating push check transport ` +
	`for us-central1-docker.pkg.dev failed: GET https://us-central1-docker.pkg.dev/v2/token?scope=... : ` +
	`DENIED: Permission 'artifactregistry.repositories.uploadArtifacts' denied on resource ` +
	`'//artifactregistry.googleapis.com/projects/proj/locations/us-central1/repositories/farcast-p51b'`

func TestARefusedPushIsRecognised(t *testing.T) {
	if !pushDenied(arDenial) {
		t.Error("the denial Artifact Registry actually returns was not recognised")
	}
	// A Containerfile that genuinely failed must not be mistaken for one.
	for _, notIt := range []string{
		"error building image: failed to execute command: exit status 1",
		"/bin/sh: apk: not found",
		"",
		"COPY failed: no source files were specified",
	} {
		if pushDenied(notIt) {
			t.Errorf("a real build failure was reported as a permission problem: %q", notIt)
		}
	}
}

// fixturePushGrant is the push grant a plan of the atlas fixture read:
// project proj-atlas at the fixture number, its repository farcast-atlas in
// europe-west4, farcast-builder at its fixture uid, with the states given.
func fixturePushGrant(state, shared string) pushGrant {
	return pushGrant{
		instance: "atlas", project: "proj-atlas", repository: "farcast-atlas", location: "europe-west4",
		number: fixtureProjectNumber, uid: fixtureBuilderUID,
		fact: plan.GrantFact{Type: plan.TypeGrant, Name: plan.GrantPush, ServiceAccount: builderAccount, Roles: []string{pushRole},
			State: state, Shared: shared},
	}
}

// The fixture's two principals, as the push grant's commands name them.
const (
	fixtureBuilderPrincipal = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/" +
		"kubernetes.serviceaccount.uid/" + fixtureBuilderUID
	fixtureBuilderSharedPrincipal = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/" +
		"subject/ns/farcast-system/sa/farcast-builder"
)

// The failure path is the only place this matters. Printing it after a build
// that already worked — which is what the code did — is printing it when it
// cannot be needed. Since ADR 0023 M2.8 (design §33, A33-15) the commands
// name the builder by its uid, take every value single-quoted, and need no
// gcloud configuration: the project, its number and the location are in
// them. The add always prints, under an introduction that agrees with the
// plan: a grant the plan read present and the push refused all the same is
// IAM still propagating, or a uid member Artifact Registry does not honour,
// which is unverified until the M2 walk, never "nothing grants it" over an
// empty block, nor a remove alone as the fix. A policy the plan could not
// read prints both conditional blocks, the remove included.
func TestAPushDenialExplainsItselfWithTheCommandThatFixesIt(t *testing.T) {
	add := "gcloud artifacts repositories add-iam-policy-binding 'farcast-atlas' --project 'proj-atlas' --location 'europe-west4' " +
		"--member '" + fixtureBuilderPrincipal + "' --role 'roles/artifactregistry.writer' --condition=None"
	remove := "gcloud artifacts repositories remove-iam-policy-binding 'farcast-atlas' --project 'proj-atlas' --location 'europe-west4' " +
		"--member '" + fixtureBuilderSharedPrincipal + "' --role 'roles/artifactregistry.writer' --condition=None"
	// Each phrase is on one line of the explanation.
	const (
		nothingGrants = "grants that identity write access"
		readPresent   = "the repository's own policy granted it write access"
		unverified    = "which is unverified until"
		// A policy the plan could not read keeps both conditional blocks,
		// the shared principal's removal included (A33-15).
		ifNotYet      = "If repository 'farcast-atlas' does not grant it yet:"
		ifStillShared = "If it still grants the principal every FarCast instance in project 'proj-atlas' shares, wait for IAM, then:"
	)
	for _, tc := range []struct {
		state, shared string
		want, not     []string
	}{
		{plan.GrantMissing, plan.GrantMissing, []string{add, nothingGrants}, []string{remove, readPresent}},
		{plan.GrantMissing, plan.GrantPresent, []string{add, remove, nothingGrants}, []string{readPresent}},
		{plan.GrantPresent, plan.GrantMissing, []string{add, readPresent, unverified}, []string{remove, nothingGrants}},
		{plan.GrantPresent, plan.GrantPresent, []string{add, remove, readPresent}, []string{nothingGrants}},
		{plan.GrantUnknown, plan.GrantUnknown, []string{add, remove, ifNotYet, ifStillShared}, []string{readPresent}},
	} {
		t.Run(tc.state+", the shared principal "+tc.shared, func(t *testing.T) {
			var buf bytes.Buffer
			g := fixturePushGrant(tc.state, tc.shared)
			uid := g.uid
			if !explainPushDenial(&buf, arDenial, g.fact.State, func() string { return grantText(t.Context(), nil, g.denied(), &uid) }) {
				t.Fatal("the denial was not explained")
			}
			out := buf.String()
			t.Log("\n" + out)
			for _, want := range append([]string{
				"not a problem with the Containerfile",
				"ONE repository, not the project",
				// The walk's own observation: the registry endpoint lagged the API.
				"few minutes",
			}, tc.want...) {
				if !strings.Contains(out, want) {
					t.Errorf("the explanation is missing %q", want)
				}
			}
			for _, not := range tc.not {
				if strings.Contains(out, not) {
					t.Errorf("the explanation says %q", not)
				}
			}
			if strings.Index(out, add) > strings.Index(out, "remove-iam-policy-binding") && strings.Contains(out, "remove-iam-policy-binding") {
				t.Error("the explanation removes before it adds")
			}
			if strings.Contains(out, "Cloud Shell:\n\n\n") {
				t.Error("the explanation prints an empty block of commands")
			}
			// No placeholder survives, and nothing asks gcloud for the number: the
			// command exists to be copied.
			for _, leftover := range []string{"<region>", "<project>", "PROJNUM", "projects describe", "\\\n"} {
				if strings.Contains(out, leftover) {
					t.Errorf("the copyable command still contains %q", leftover)
				}
			}
		})
	}
}

func TestAnOrdinaryBuildFailureIsNotExplainedAway(t *testing.T) {
	var buf bytes.Buffer
	asked := false
	if explainPushDenial(&buf, "error building image: exit status 1", plan.GrantMissing, func() string { asked = true; return "" }) {
		t.Error("a Containerfile failure was explained as a missing grant")
	}
	if buf.Len() != 0 || asked {
		t.Errorf("it wrote %q, or made the commands (%v), anyway", buf.String(), asked)
	}
}

// When the provider states no project number (a provider without the grant
// reader, MS-6), and only then, the number's placeholder survives: the
// commands read it into PROJNUM first, from the checked project, and name
// the principals double-quoted around it (A33-15), because a half-filled
// command is worse than one that shows its gaps.
func TestPlaceholdersSurviveWhenNothingIsKnown(t *testing.T) {
	g := fixturePushGrant(plan.GrantUnknown, plan.GrantUnknown)
	g.number = 0
	out, err := g.text(fixtureBuilderUID)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + out)
	lines := strings.Split(out, "\n")
	if lines[0] != "  PROJNUM=$(gcloud projects describe 'proj-atlas' --format='value(projectNumber)')" {
		t.Errorf("the first line is %q; want the project number read into PROJNUM", lines[0])
	}
	member := `"principal://iam.googleapis.com/projects/${PROJNUM}/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/kubernetes.serviceaccount.uid/` + fixtureBuilderUID + `"`
	shared := `"principal://iam.googleapis.com/projects/${PROJNUM}/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/subject/ns/farcast-system/sa/farcast-builder"`
	for _, want := range []string{"--member " + member + " ", "--member " + shared + " "} {
		if !strings.Contains(out, want) {
			t.Errorf("the commands do not name %s", want)
		}
	}
	if strings.Contains(out, "123456789012") {
		t.Error("a number the provider did not state was printed")
	}
}

// uidMember is the uid principal of the ServiceAccount whose uid is uid, in
// project's pool at number, written out here rather than by the code under
// test.
func uidMember(number int64, project, uid string) string {
	return fmt.Sprintf("principal://iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s.svc.id.goog/kubernetes.serviceaccount.uid/%s",
		number, project, uid)
}

// builderSharedMember is the principal every builder in project's pool
// shares, at number.
func builderSharedMember(number int64, project string) string {
	return fmt.Sprintf("principal://iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s.svc.id.goog/subject/ns/farcast-system/sa/farcast-builder",
		number, project)
}

// pushLines are the push grant's printed commands for proj-1's farcast-p42
// in us-central1 (buildableInstance), by the members given: the add, the
// wait, the remove, and the remove's introduction alone.
func pushLines(member, shared string) (add, wait, remove, removeAlone string) {
	return pushLinesFor("proj-1", "farcast-p42", member, shared)
}

// pushLinesFor is pushLines for project's repository, in us-central1.
func pushLinesFor(project, repository, member, shared string) (add, wait, remove, removeAlone string) {
	cmd := func(verb, m string) string {
		return "  gcloud artifacts repositories " + verb + "-iam-policy-binding '" + repository + "' --project '" + project + "' --location 'us-central1' --member " + m +
			" --role 'roles/artifactregistry.writer' --condition=None"
	}
	return cmd("add", "'"+member+"'"),
		"Then wait for IAM (typically 2 minutes, up to 7 or more), and remove the binding every FarCast instance in project '" + project + "' shares:",
		cmd("remove", "'"+shared+"'"),
		"Remove the binding every FarCast instance in project '" + project + "' shares:"
}

// TestPrintedGrantAddsBeforeItRemoves (design §33, A33-15, mutation 133):
// the push grant's commands add the builder's uid principal before they
// remove the shared one, so a running builder is never cut off; each is one
// line with no backslash continuation, every value single-quoted. A grant
// already present prints the remove alone, under its own introduction, and
// one whose state is unknown prints both, each under its condition.
func TestPrintedGrantAddsBeforeItRemoves(t *testing.T) {
	g := fixturePushGrant(plan.GrantMissing, plan.GrantPresent)
	g.instance, g.project, g.repository, g.location = "p42", "proj-1", "farcast-p42", "us-central1"
	member, shared := uidMember(fixtureProjectNumber, "proj-1", fixtureBuilderUID), builderSharedMember(fixtureProjectNumber, "proj-1")
	add, wait, remove, removeAlone := pushLines(member, shared)
	for _, tc := range []struct {
		name          string
		state, shared string
		want          []string
	}{
		{"missing, the shared principal held", plan.GrantMissing, plan.GrantPresent, []string{add, wait, remove}},
		{"missing, the shared principal gone", plan.GrantMissing, plan.GrantMissing, []string{add}},
		{"present, the shared principal held", plan.GrantPresent, plan.GrantPresent, []string{removeAlone, remove}},
		{"unknown", plan.GrantUnknown, plan.GrantUnknown, []string{"If repository 'farcast-p42' does not grant it yet:", add,
			"If it still grants the principal every FarCast instance in project 'proj-1' shares, wait for IAM, then:", remove}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g.fact.State, g.fact.Shared = tc.state, tc.shared
			text, err := g.text(fixtureBuilderUID)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Split(text, "\n"); !slices.Equal(got, tc.want) {
				t.Errorf("the commands are\n%s\nwant\n%s", text, strings.Join(tc.want, "\n"))
			}
			if strings.Contains(text, "\\") {
				t.Errorf("a command continues over a backslash:\n%s", text)
			}
		})
	}
	// The bucket grant's printer.
	t.Run("storage deploy", bucketPrinterAddsBeforeItRemoves)
}

// TestNoPrintedGrantDescribesTheProject (design §33, A33-15): with the
// project number known, no printed command asks gcloud for it, and none
// leans on gcloud's configured project; only a provider that states no
// number makes the commands read it into PROJNUM.
func TestNoPrintedGrantDescribesTheProject(t *testing.T) {
	for _, state := range []string{plan.GrantMissing, plan.GrantPresent, plan.GrantUnknown} {
		g := fixturePushGrant(state, plan.GrantPresent)
		if state == plan.GrantUnknown {
			g.fact.Shared = plan.GrantUnknown
		}
		text, err := g.text(fixtureBuilderUID)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "projects describe") || strings.Contains(line, "PROJNUM") {
				t.Errorf("%s: a command asks gcloud for the number it was given: %s", state, line)
			}
			if strings.Contains(line, "gcloud artifacts") && !strings.Contains(line, "--project 'proj-atlas'") {
				t.Errorf("%s: a command leans on gcloud's configured project: %s", state, line)
			}
		}
		g.number = 0
		if text, err := g.text(fixtureBuilderUID); err != nil || !strings.HasPrefix(text, "  PROJNUM=$(gcloud projects describe 'proj-atlas'") {
			t.Errorf("%s with no number known: %v\n%s\nwant PROJNUM read first", state, err, text)
		}
	}
	t.Run("storage deploy", bucketPrinterNeedsNoDescribe)
}

// buildPlanOf is build --plan, as JSON, on p42 (meteringInstance, with a
// granted reader), its reader holding accounts and its provider fp: the
// plan, and the provider's grant reads.
func buildPlanOf(t *testing.T, accounts map[string]string, fp planck.Provider, flags ...string) (plan.Document, plan.Bound) {
	t.Helper()
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	grantedReader(t, dir, "p42")
	opened := 0
	c := buildPlanCmd(t, &fakeJobs{accounts: accounts}, &fakeBuilder{}, &opened,
		append([]string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest, "--plan"}, flags...)...)
	c.openProvider = providerOf(fp)
	env, out, errb := testEnvBoth(dir, output.ModeJSON)
	if err := c.Run(t.Context(), env, []string{"p42"}); err != nil {
		t.Fatalf("build --plan: %v\n%s", err, errb)
	}
	if opened != 0 {
		t.Errorf("build --plan opened the writer %d times", opened)
	}
	doc := printedDocument(t, out.Bytes())
	return doc, decodedBound(t, doc)
}

// grantAfterImage is the plan's push grant fact, which must come right after
// the builder's image fact (design §33, A33-22), or a failure.
func grantAfterImage(t *testing.T, b plan.Bound) plan.GrantFact {
	t.Helper()
	for i, f := range b.Facts {
		if img, ok := f.(plan.ImageFact); ok && img.Component == "builder" {
			if i+1 < len(b.Facts) {
				if g, ok := b.Facts[i+1].(plan.GrantFact); ok {
					return g
				}
			}
			t.Fatalf("the fact after the builder's image is %T, not the push grant: %+v", b.Facts[min(i+1, len(b.Facts)-1)], b.Facts)
		}
	}
	t.Fatalf("the plan binds no builder image: %+v", b.Facts)
	return plan.GrantFact{}
}

// TestBuildPlanStatesThePushGrant (design §33, A33-22, A33-19, mutation
// 110c): build's plan binds the push grant right after the builder image,
// as the repository's own policy reads it with the installer's key: the
// builder's uid principal, the shared principal, both states, apply false.
// Its notice, the plan's last fact, is due when the grant is not present or
// the shared principal still holds it, and says so in A33-22's words: the
// commands, then that a plan made before the grant cannot be confirmed after
// it; or, for an account that does not exist yet, that this command creates
// it, with the uid placeholder bound and its state missing.
func TestBuildPlanStatesThePushGrant(t *testing.T) {
	member, shared := uidMember(fixtureProjectNumber, "proj-1", fixtureBuilderUID), builderSharedMember(fixtureProjectNumber, "proj-1")
	add, wait, remove, removeAlone := pushLines(member, shared)
	placeholder := uidMember(fixtureProjectNumber, "proj-1", "farcast-placeholder:sa-uid:farcast-system/farcast-builder")
	for _, tc := range []struct {
		name      string
		accounts  map[string]string
		states    map[string]planck.GrantState
		principal string
		state     string
		shared    string
		notice    string
	}{
		{"present, the shared principal gone", fixtureAccounts(), map[string]planck.GrantState{member: planck.GrantPresent},
			member, plan.GrantPresent, plan.GrantMissing, ""},
		{"missing, the shared principal held", fixtureAccounts(), map[string]planck.GrantState{shared: planck.GrantPresent},
			member, plan.GrantMissing, plan.GrantPresent, strings.Join([]string{msgPushGrantMissing, add, wait, remove, msgPlanBeforeGrant}, "\n")},
		{"present, the shared principal held", fixtureAccounts(), map[string]planck.GrantState{member: planck.GrantPresent, shared: planck.GrantPresent},
			member, plan.GrantPresent, plan.GrantPresent, strings.Join([]string{fmt.Sprintf(msgPushGrantShared, "proj-1"), removeAlone, remove}, "\n")},
		{"a policy the key may not read", fixtureAccounts(), map[string]planck.GrantState{member: planck.GrantUnknown, shared: planck.GrantUnknown},
			member, plan.GrantUnknown, plan.GrantUnknown, strings.Join([]string{msgPushGrantUnknown, "If repository 'farcast-p42' does not grant it yet:", add,
				"If it still grants the principal every FarCast instance in project 'proj-1' shares, wait for IAM, then:", remove}, "\n")},
		{"an account that does not exist yet", nil, map[string]planck.GrantState{shared: planck.GrantPresent},
			placeholder, plan.GrantMissing, plan.GrantPresent, msgPushGrantPending},
		// Whatever a policy says of the placeholder, no binding can grant
		// an account that does not exist.
		{"an account that does not exist yet, the placeholder read present", nil, map[string]planck.GrantState{placeholder: planck.GrantPresent},
			placeholder, plan.GrantMissing, plan.GrantMissing, msgPushGrantPending},
		// A policy the key may not read stays unknown for both, as the
		// bucket grant's does, so the commands printed once the account
		// exists carry the shared principal's removal too.
		{"an account that does not exist yet, a policy the key may not read", nil,
			map[string]planck.GrantState{placeholder: planck.GrantUnknown, shared: planck.GrantUnknown},
			placeholder, plan.GrantUnknown, plan.GrantUnknown, msgPushGrantPending},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp := &fakeProvider{grantStates: tc.states}
			_, b := buildPlanOf(t, tc.accounts, fp)
			want := plan.GrantFact{Type: plan.TypeGrant, Name: plan.GrantPush, Target: "us-central1-docker.pkg.dev/proj-1/farcast-p42",
				ServiceAccount: "farcast-system/farcast-builder", Principal: tc.principal, Roles: []string{"roles/artifactregistry.writer"},
				State: tc.state, SharedPrincipal: shared, Shared: tc.shared, Apply: false}
			if got := grantAfterImage(t, b); !reflect.DeepEqual(got, want) {
				t.Errorf("the push grant is\n%+v\nwant\n%+v", got, want)
			}
			notices := noticesOf(b)
			switch {
			case tc.notice == "" && len(notices) != 0:
				t.Errorf("a grant read present, the shared principal gone, has notices %q", notices)
			case tc.notice != "" && (len(notices) != 1 || notices[0] != tc.notice):
				t.Errorf("the notices are %q;\nwant\n%s", notices, tc.notice)
			}
			if tc.notice != "" {
				if _, ok := b.Facts[len(b.Facts)-1].(plan.NoticeFact); !ok {
					t.Errorf("the notice is not the plan's last fact: %+v", b.Facts)
				}
			}
			if !slices.Equal(fp.grantCalls, []string{"ProjectNumber", "RegistryGrant"}) || len(fp.grantReads) != 1 ||
				fp.grantReads[0] != (grantRead{Ref: planck.RegistryRef{Name: "farcast-p42", Location: "us-central1"}, Role: "roles/artifactregistry.writer", Member: tc.principal, Shared: shared}) {
				t.Errorf("the provider was asked %q, %+v; want the number, then one read of farcast-p42's policy for the two principals", fp.grantCalls, fp.grantReads)
			}
		})
	}
}

// TestPushGrantPrincipalCarriesTheProjectNumber (design §33, A33-10,
// mutation 110f): the principals carry the number the provider states, and
// the project's ID only as its pool's name; the policy is read for exactly
// the principal the plan binds, and the notice's commands name it.
func TestPushGrantPrincipalCarriesTheProjectNumber(t *testing.T) {
	const number = 987654321098
	fp := &fakeProvider{projectNumber: number}
	_, b := buildPlanOf(t, fixtureAccounts(), fp)
	g := grantAfterImage(t, b)
	member := uidMember(number, "proj-1", fixtureBuilderUID)
	if g.Principal != member || g.SharedPrincipal != builderSharedMember(number, "proj-1") {
		t.Errorf("the principals are %s and %s; want them at project number %d", g.Principal, g.SharedPrincipal, number)
	}
	if strings.Contains(g.Principal, "projects/proj-1/") || strings.Contains(g.SharedPrincipal, "projects/proj-1/") {
		t.Errorf("a principal names the project by its ID: %s", g.Principal)
	}
	if len(fp.grantReads) != 1 || fp.grantReads[0].Member != g.Principal || fp.grantReads[0].Shared != g.SharedPrincipal {
		t.Errorf("the policy was read for %+v; want the principals the plan binds", fp.grantReads)
	}
	if notices := noticesOf(b); len(notices) != 1 || !strings.Contains(notices[0], "--member '"+member+"'") {
		t.Errorf("the notice does not name %s:\n%q", member, notices)
	}
}

// TestPushGrantRefusesARegistryRecordedWithoutItsRepository (design §33,
// A33-15): a record that names an image registry by its prefix and not its
// repository, or not its location, which only a hand edit makes, is
// refused, kind internal, before anything is read or printed: build --plan
// and --yes, and run, whose deploy plan reads the repository's policy, before
// its fetch bills — --plan, --confirm and --yes alike. The provider is never
// opened, no reader or writer either, and nothing is applied.
func TestPushGrantRefusesARegistryRecordedWithoutItsRepository(t *testing.T) {
	for _, missing := range []string{"repository", "location"} {
		edit := func(t *testing.T, dir config.Dir, name string) {
			t.Helper()
			if _, err := dir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
				if missing == "repository" {
					m.Registry.Repository = ""
				} else {
					m.Registry.Location = ""
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		check := func(t *testing.T, what string, err error, name string, stdout, stderr string, opens int) {
			t.Helper()
			want := fmt.Sprintf("instance %q's record names an image registry but not its repository or its location; farcast reads and renders nothing from it", name)
			if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal {
				t.Errorf("%s = %v (kind %s);\nwant %q, internal", what, err, kindOf(classified(err)), want)
			}
			if stdout+stderr != "" || opens != 0 {
				t.Errorf("%s printed %q %q and opened %d seams before refusing", what, stdout, stderr, opens)
			}
		}
		for _, answer := range [][]string{{"--plan"}, {"--yes"}} {
			t.Run("build/"+missing+"/"+answer[0], func(t *testing.T) {
				dir := config.Dir(t.TempDir())
				meteringInstance(t, dir, "p42")
				grantedReader(t, dir, "p42")
				edit(t, dir, "p42")
				opens := 0
				c := withFlags(t, &buildCommand{}, append([]string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest}, answer...)...)
				c.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
				c.newCluster = func(clusterRef) (jobWaiter, error) { opens++; return &fakeJobs{}, nil }
				c.newPlanReader = func(clusterRef) (buildPlanReader, error) { opens++; return &fakeJobs{}, nil }
				c.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
					opens++
					return &fakeProvider{}, nil
				}
				env, out, errb := testEnvBoth(dir, output.ModeJSON)
				err := c.Run(t.Context(), env, []string{"p42"})
				check(t, "build "+answer[0], err, "p42", out.String(), errb.String(), opens)
			})
		}
		for _, answer := range [][]string{{"--plan"}, {"--confirm", zeroDigest}, {"--yes"}} {
			t.Run("run/"+missing+"/"+answer[0], func(t *testing.T) {
				r := newStageRig(t, func(m *config.InstanceMetadata) {
					if missing == "repository" {
						m.Registry.Repository = ""
					} else {
						m.Registry.Location = ""
					}
				})
				r.fp = &fakeProvider{}
				stdout, stderr, err := r.run(output.ModeJSON, answer...)
				check(t, "run "+answer[0], err, stageName, stdout, stderr, len(r.opened)+len(r.fp.grantCalls))
				if len(r.f.applied) != 0 {
					t.Errorf("run %s applied %d streams", answer[0], len(r.f.applied))
				}
			})
		}
	}
}

// TestPushGrantProjectNumberFailureRefusesThePlan (design §33, A33-22): a
// projects.get that fails refuses the plan, its error carried, with nothing
// applied and no plan printed: build's in every mode, and run's deploy plan.
// The policy is not read after it.
func TestPushGrantProjectNumberFailureRefusesThePlan(t *testing.T) {
	refused := errors.New("googleapi: Error 500: backend error")
	for _, answer := range [][]string{{"--plan"}, {"--yes"}} {
		t.Run("build/"+answer[0], func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			meteringInstance(t, dir, "p42")
			grantedReader(t, dir, "p42")
			fj, opened := &fakeJobs{accounts: fixtureAccounts()}, 0
			c := buildPlanCmd(t, fj, &fakeBuilder{}, &opened,
				append([]string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest}, answer...)...)
			fp := &fakeProvider{projectNumberErr: refused}
			c.openProvider = providerOf(fp)
			env, out, _ := testEnvBoth(dir, output.ModeJSON)
			err := c.Run(t.Context(), env, []string{"p42"})
			if !errors.Is(err, refused) || !strings.Contains(err.Error(), `read the number of project "proj-1" with instance "p42"'s installer key`) {
				t.Errorf("build %s = %v; want the projects.get failure", answer[0], err)
			}
			if out.Len() != 0 || len(fj.applied) != 0 || !slices.Equal(fp.grantCalls, []string{"ProjectNumber"}) {
				t.Errorf("build %s printed %q, applied %d streams and asked the provider %q", answer[0], out, len(fj.applied), fp.grantCalls)
			}
		})
	}
	t.Run("run <D>", func(t *testing.T) {
		r := newStageRig(t, nil)
		r.f.accounts = fixtureAccounts()
		d := r.deployPlan()
		r.fp = &fakeProvider{projectNumberErr: refused}
		stdout, _, err := r.confirm(d)
		if !errors.Is(err, refused) || kindOf(classified(err)) == kindPlanChanged {
			t.Errorf("run --confirm <D> = %v; want the projects.get failure, before any comparison", err)
		}
		if stdout != "" || len(r.f.applied) != 0 {
			t.Errorf("run --confirm <D> printed %q and applied %d streams", stdout, len(r.f.applied))
		}
	})
}

// TestRunDeployPlanStatesThePushGrant (design §33, A33-22, A33-19): run's
// deploy plan binds the push grant right after the builder image, read past
// every block, as build's plan does: the uid principal and its state, the
// shared principal and its, apply false; and its notice is the plan's last
// when it is due.
func TestRunDeployPlanStatesThePushGrant(t *testing.T) {
	member, shared := uidMember(fixtureProjectNumber, "proj-test1", fixtureBuilderUID), builderSharedMember(fixtureProjectNumber, "proj-test1")
	add, wait, remove, _ := pushLinesFor("proj-test1", "farcast-p43", member, shared)
	for _, tc := range []struct {
		name      string
		accounts  map[string]string
		states    map[string]planck.GrantState
		principal string
		state     string
		shared    string
		notice    string
	}{
		{"present, the shared principal gone", fixtureAccounts(), map[string]planck.GrantState{member: planck.GrantPresent},
			member, plan.GrantPresent, plan.GrantMissing, ""},
		{"missing, the shared principal held", fixtureAccounts(), map[string]planck.GrantState{shared: planck.GrantPresent},
			member, plan.GrantMissing, plan.GrantPresent, strings.Join([]string{msgPushGrantMissing, add, wait, remove, msgPlanBeforeGrant}, "\n")},
		{"an account that does not exist yet", nil, nil,
			uidMember(fixtureProjectNumber, "proj-test1", "farcast-placeholder:sa-uid:farcast-system/farcast-builder"), plan.GrantMissing, plan.GrantMissing, msgPushGrantPending},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStageRig(t, nil)
			r.f.accounts = tc.accounts
			r.fp = &fakeProvider{grantStates: tc.states}
			b := decodedBound(t, r.deployPlan())
			want := plan.GrantFact{Type: plan.TypeGrant, Name: plan.GrantPush, Target: "us-central1-docker.pkg.dev/proj-1/farcast-p43",
				ServiceAccount: "farcast-system/farcast-builder", Principal: tc.principal, Roles: []string{"roles/artifactregistry.writer"},
				State: tc.state, SharedPrincipal: shared, Shared: tc.shared}
			if got := grantAfterImage(t, b); !reflect.DeepEqual(got, want) {
				t.Errorf("the push grant is\n%+v\nwant\n%+v", got, want)
			}
			notices := noticesOf(b)
			if (tc.notice == "") != (len(notices) == 0) || (tc.notice != "" && notices[len(notices)-1] != tc.notice) {
				t.Errorf("the notices are %q;\nwant the push grant's last:\n%s", notices, tc.notice)
			}
			if !slices.Equal(r.fp.grantCalls, []string{"ProjectNumber", "RegistryGrant"}) {
				t.Errorf("the deploy plan asked the provider %q; want the number, then the repository's policy", r.fp.grantCalls)
			}
			if tc.notice == "" {
				return
			}
			// Outside a plan the review prints it, once (A23-26).
			if _, errb, err := r.run(output.ModeHuman, "--yes"); err != nil || strings.Count(errb, tc.notice+"\n") != 1 {
				t.Errorf("run --yes = %v, printing the notice %d times; want once:\n%s", err, strings.Count(errb, tc.notice+"\n"), errb)
			}
		})
	}
}

// TestPushGrantIsNeverApplied (design §33, A33-3, A33-22, mutations 110 and
// 110b): the push grant is read and never written. For build and for run's
// deploy plan, in every mode, with the grant missing, each computation of
// the plan asks the provider exactly for the project number and then the
// repository's policy, and nothing else of it: no registry ensured or
// deleted. Every grant fact binds apply false, and no command has a flag
// that would apply it.
func TestPushGrantIsNeverApplied(t *testing.T) {
	asked := func(t *testing.T, what string, fp *fakeProvider) {
		t.Helper()
		if !slices.Equal(fp.grantCalls, []string{"ProjectNumber", "RegistryGrant"}) || len(fp.ensured)+len(fp.regDeleted) != 0 {
			t.Errorf("%s asked the provider %q, ensured %d registries and deleted %d; want the number and one policy read alone",
				what, fp.grantCalls, len(fp.ensured), len(fp.regDeleted))
		}
	}
	notApplied := func(t *testing.T, what string, b plan.Bound) {
		t.Helper()
		grants := factsOf[plan.GrantFact](b)
		if len(grants) != 1 || grants[0].Apply || grants[0].State != plan.GrantMissing {
			t.Errorf("%s binds the grants %+v; want the push grant, missing, not applied", what, grants)
		}
	}
	build := func(t *testing.T, fj *fakeJobs, fp *fakeProvider, dir config.Dir, flags ...string) (*bytes.Buffer, error) {
		t.Helper()
		opened := 0
		c := buildPlanCmd(t, fj, &fakeBuilder{}, &opened,
			append([]string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest}, flags...)...)
		c.openProvider = providerOf(fp)
		env, out, _ := testEnvBoth(dir, output.ModeJSON)
		return out, c.Run(t.Context(), env, []string{"p42"})
	}
	t.Run("build", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		meteringInstance(t, dir, "p42")
		grantedReader(t, dir, "p42")
		fp := &fakeProvider{}
		out, err := build(t, &fakeJobs{accounts: fixtureAccounts()}, fp, dir, "--plan")
		if err != nil {
			t.Fatal(err)
		}
		doc := printedDocument(t, out.Bytes())
		asked(t, "build --plan", fp)
		notApplied(t, "build --plan", decodedBound(t, doc))
		for _, answer := range [][]string{{"--confirm", doc.Digest}, {"--yes"}} {
			fp := &fakeProvider{}
			fj := &fakeJobs{accounts: fixtureAccounts(), result: succeeded("sha256:" + strings.Repeat("c", 64))}
			if _, err := build(t, fj, fp, dir, answer...); err != nil {
				t.Fatalf("build %s: %v", answer[0], err)
			}
			asked(t, "build "+answer[0], fp)
			if len(fj.applied) != 1 {
				t.Errorf("build %s applied %d streams; want the build's", answer[0], len(fj.applied))
			}
		}
		// In a terminal, declined at the question.
		fp = &fakeProvider{}
		c := buildCmd(&fakeJobs{accounts: fixtureAccounts()})
		c.assumeYes = false
		c.openProvider = providerOf(fp)
		c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
		env, _, _ := testEnvBoth(dir, output.ModeHuman)
		env.In = devNullTerminal(t)
		fj := &fakeJobs{accounts: fixtureAccounts()}
		c.newCluster = func(clusterRef) (jobWaiter, error) { return fj, nil }
		// Its question reads a closed input: nothing is applied.
		if err := c.Run(t.Context(), env, []string{"p42"}); err == nil || len(fj.applied) != 0 {
			t.Fatalf("build in a terminal, its input closed = %v, applying %d streams", err, len(fj.applied))
		}
		asked(t, "build in a terminal", fp)
	})
	t.Run("run <D>", func(t *testing.T) {
		r := newStageRig(t, nil)
		r.f.accounts = fixtureAccounts()
		r.fp = &fakeProvider{}
		d := r.deployPlan()
		asked(t, "run --confirm <F>", r.fp)
		notApplied(t, "run's deploy plan", decodedBound(t, d))
		r.fp = &fakeProvider{}
		if _, errb, err := r.confirm(d); err != nil {
			t.Fatalf("run --confirm <D>: %v\n%s", err, errb)
		}
		asked(t, "run --confirm <D>", r.fp)
		r.fp = &fakeProvider{}
		if _, errb, err := r.run(output.ModeHuman, "--yes"); err != nil {
			t.Fatalf("run --yes: %v\n%s", err, errb)
		}
		asked(t, "run --yes", r.fp)
	})
	t.Run("no flag applies it", func(t *testing.T) {
		for _, line := range [][]string{
			{"build", writeName, "--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest, "--grant-push", "--plan"},
			{"run", writeName, "github.com/example/my-platform", "--grant-push", "--plan"},
		} {
			_, stderr, code := runLine(append([]string{"farcast", "--config", t.TempDir()}, line...))
			if code != 2 || !strings.Contains(stderr, "grant-push") {
				t.Errorf("farcast %s --grant-push: exit %d, %q; want an unknown flag, exit 2", line[0], code, stderr)
			}
		}
	})
}

// TestConfirmRefusesAPushGrantChangedSinceThePlan (design §33, A33-22,
// mutation 110e): the plan binds the grant's state, read before the
// comparison, so a plan made while the grant was missing cannot be
// confirmed once it is in place: build and run's deploy plan refuse,
// plan_changed, before the writer opens or anything is applied.
func TestConfirmRefusesAPushGrantChangedSinceThePlan(t *testing.T) {
	granted := func(project string) map[string]planck.GrantState {
		return map[string]planck.GrantState{uidMember(fixtureProjectNumber, project, fixtureBuilderUID): planck.GrantPresent}
	}
	t.Run("build", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		meteringInstance(t, dir, "p42")
		grantedReader(t, dir, "p42")
		flags := []string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest}
		opened := 0
		fj := &fakeJobs{accounts: fixtureAccounts()}
		c := buildPlanCmd(t, fj, &fakeBuilder{}, &opened, append(slices.Clone(flags), "--plan")...)
		env, out := testEnv(dir, output.ModeJSON)
		if err := c.Run(t.Context(), env, []string{"p42"}); err != nil {
			t.Fatal(err)
		}
		doc := printedDocument(t, out.Bytes())
		c = buildPlanCmd(t, fj, &fakeBuilder{}, &opened, append(slices.Clone(flags), "--confirm", doc.Digest)...)
		c.openProvider = providerOf(&fakeProvider{grantStates: granted("proj-1")})
		env, out = testEnv(dir, output.ModeJSON)
		err := c.Run(t.Context(), env, []string{"p42"})
		if kindOf(classified(err)) != kindPlanChanged {
			t.Fatalf("--confirm after the grant = %v; want plan_changed", err)
		}
		if opened+len(fj.applied) != 0 || out.Len() != 0 {
			t.Errorf("opened the writer %d times, applied %d streams and printed %q", opened, len(fj.applied), out)
		}
	})
	t.Run("run <D>", func(t *testing.T) {
		r := newStageRig(t, nil)
		r.f.accounts = fixtureAccounts()
		d := r.deployPlan()
		r.fp = &fakeProvider{grantStates: granted("proj-test1")}
		_, _, err := r.confirm(d)
		if kindOf(classified(err)) != kindPlanChanged {
			t.Fatalf("--confirm <D> after the grant = %v; want plan_changed", err)
		}
		if len(r.f.applied) != 0 || slices.Contains(r.opened, kube.Writer) {
			t.Errorf("applied %d streams and opened %v", len(r.f.applied), r.opened)
		}
	})
}

// TestPushCommandsPrintRightAfterTheBuildApply (design §33, A33-22,
// mutation 142): a plan that bound the uid placeholder reads the builder's
// ServiceAccount as the writer right after the build's apply, which created
// it, and prints the commands that grant it by its uid, before the wait: a
// grant that lands before the push lets the build succeed. The read is best
// effort: one that fails prints the one line that says so, and the build
// goes on to its wait and reports its digest. A plan that read the account
// makes no extra read. run reads and prints once, after its first build's
// apply.
func TestPushCommandsPrintRightAfterTheBuildApply(t *testing.T) {
	const digest = "sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	member := uidMember(fixtureProjectNumber, "proj-1", fixtureBuilderUID)
	add, _, _, _ := pushLines(member, builderSharedMember(fixtureProjectNumber, "proj-1"))
	const read = "meta farcast-system/farcast-builder"
	build := func(t *testing.T, fj *fakeJobs) (stdout string, errb *bytes.Buffer, atWait string) {
		t.Helper()
		dir := config.Dir(t.TempDir())
		meteringInstance(t, dir, "p42")
		fj.result = succeeded(digest)
		c := buildCmd(fj)
		c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
		env, out, e := testEnvBoth(dir, output.ModeHuman)
		fj.onWait = func() { atWait = e.String() }
		if err := c.Run(t.Context(), env, []string{"p42"}); err != nil {
			t.Fatalf("build: %v\n%s", err, e)
		}
		return out.String(), e, atWait
	}
	t.Run("the account created by the apply", func(t *testing.T) {
		fj := &fakeJobs{createAccount: fixtureBuilderUID}
		stdout, _, atWait := build(t, fj)
		if !strings.Contains(atWait, msgPushGrantNow+"\n"+add+"\n") {
			t.Errorf("at the wait, stderr was\n%s\nwant the commands for %s, under %q", atWait, fixtureBuilderUID, msgPushGrantNow)
		}
		if want := []string{read, "apply", read, "wait"}; !slices.Equal(fj.events, want) {
			t.Errorf("the writer saw %q; want %q", fj.events, want)
		}
		if !strings.Contains(stdout, "@"+digest) {
			t.Errorf("the build's digest was not reported:\n%s", stdout)
		}
	})
	t.Run("the read refused after the apply", func(t *testing.T) {
		fj := &fakeJobs{metaErrApplied: errors.New("kube: GET /api/v1/namespaces/farcast-system/serviceaccounts/farcast-builder: 500")}
		stdout, errb, atWait := build(t, fj)
		line := fmt.Sprintf(msgPushGrantUnread, "kube: GET /api/v1/namespaces/farcast-system/serviceaccounts/farcast-builder: 500", "p42")
		if !strings.Contains(atWait, line+"\n") || strings.Contains(errb.String(), msgPushGrantNow) {
			t.Errorf("stderr was\n%s\nwant %q in place of the commands, before the wait", errb, line)
		}
		if len(fj.waited) != 1 || !strings.Contains(stdout, "@"+digest) {
			t.Errorf("waited %d times and reported\n%s\nwant the build waited on and its digest reported", len(fj.waited), stdout)
		}
	})
	// The result names the uid principal of the account the apply created,
	// never the placeholder the plan bound (A33-22): read after the apply,
	// or, when that read failed, under the result.
	result := func(t *testing.T, cl jobWaiter, fj *fakeJobs) pushGrantResult {
		t.Helper()
		dir := config.Dir(t.TempDir())
		meteringInstance(t, dir, "p42")
		fj.result = succeeded(digest)
		c := buildCmd(fj)
		c.newCluster = func(clusterRef) (jobWaiter, error) { return cl, nil }
		c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
		env, out, e := testEnvBoth(dir, output.ModeJSON)
		if err := c.Run(t.Context(), env, []string{"p42"}); err != nil {
			t.Fatalf("build: %v\n%s", err, e)
		}
		var res struct {
			PushGrant pushGrantResult `json:"push_grant"`
		}
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return res.PushGrant
	}
	t.Run("the result, the account created by the apply", func(t *testing.T) {
		fj := &fakeJobs{createAccount: fixtureBuilderUID}
		if got, want := result(t, fj, fj), (pushGrantResult{Principal: member, State: plan.GrantMissing, Shared: plan.GrantMissing}); got != want {
			t.Errorf("the result's push_grant is %+v; want %+v", got, want)
		}
	})
	t.Run("the result, the read after the apply failed once", func(t *testing.T) {
		fj := &fakeJobs{createAccount: fixtureBuilderUID}
		if got := result(t, &failingAccountReads{fakeJobs: fj, fails: 1}, fj); got.Principal != member {
			t.Errorf("the result's push_grant names %s; want %s, read under the result", got.Principal, member)
		}
	})
	t.Run("the account created by the apply, a policy the key may not read", func(t *testing.T) {
		fj := &fakeJobs{createAccount: fixtureBuilderUID}
		placeholder := uidMember(fixtureProjectNumber, "proj-1", "farcast-placeholder:sa-uid:farcast-system/farcast-builder")
		dir := config.Dir(t.TempDir())
		meteringInstance(t, dir, "p42")
		fj.result = succeeded(digest)
		c := buildCmd(fj)
		c.openProvider = providerOf(&fakeProvider{grantStates: map[string]planck.GrantState{
			placeholder: planck.GrantUnknown, builderSharedMember(fixtureProjectNumber, "proj-1"): planck.GrantUnknown}})
		c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
		env, _, e := testEnvBoth(dir, output.ModeHuman)
		if err := c.Run(t.Context(), env, []string{"p42"}); err != nil {
			t.Fatalf("build: %v\n%s", err, e)
		}
		_, _, remove, _ := pushLines(member, builderSharedMember(fixtureProjectNumber, "proj-1"))
		want := strings.Join([]string{msgPushGrantNow, "If repository 'farcast-p42' does not grant it yet:", add,
			"If it still grants the principal every FarCast instance in project 'proj-1' shares, wait for IAM, then:", remove}, "\n")
		if !strings.Contains(e.String(), want) {
			t.Errorf("stderr was\n%s\nwant both conditional blocks under %q", e, msgPushGrantNow)
		}
	})
	t.Run("the account created by the apply, then a uid it would not take", func(t *testing.T) {
		fj := &fakeJobs{createAccount: "BAD"}
		_, errb, _ := build(t, fj)
		line := fmt.Sprintf(msgPushGrantUnread, `has the uid "BAD", which is not one the API server issues: `+kube.ErrUnreadable.Error(), "p42")
		if !strings.Contains(errb.String(), line+"\n") || strings.Count(line, builderAccount) != 1 {
			t.Errorf("stderr was\n%s\nwant %q, naming the account once", errb, line)
		}
	})
	t.Run("the account the plan read", func(t *testing.T) {
		fj := &fakeJobs{accounts: fixtureAccounts()}
		_, errb, _ := build(t, fj)
		if want := []string{read, "apply", "wait"}; !slices.Equal(fj.events, want) || strings.Contains(errb.String(), msgPushGrantNow) {
			t.Errorf("the writer saw %q and stderr was\n%s\nwant %q, and nothing printed after the apply", fj.events, errb, want)
		}
	})
	t.Run("run, two builds", func(t *testing.T) {
		r := newStageRig(t, nil)
		r.f.createAccount = fixtureBuilderUID
		_, errb, err := r.run(output.ModeHuman, "--yes")
		if err != nil {
			t.Fatalf("run --yes: %v\n%s", err, errb)
		}
		builds := 0
		for _, a := range r.f.applied {
			if strings.Contains(a, "kind: Job\n") && strings.Contains(a, "name: build-") {
				builds++
			}
		}
		if builds != 2 {
			t.Fatalf("guard: run built %d applications, want 2", builds)
		}
		if got := strings.Count(errb, msgPushGrantNow); got != 1 || len(r.f.metaReads) != 2 {
			t.Errorf("printed the commands %d times after %d account reads (%q); want once, the plan's read and one after the first build's apply\n%s",
				got, len(r.f.metaReads), r.f.metaReads, errb)
		}
		if member := uidMember(fixtureProjectNumber, "proj-test1", fixtureBuilderUID); !strings.Contains(errb, "--member '"+member+"'") {
			t.Errorf("the commands do not name %s:\n%s", member, errb)
		}
	})
}

// failingAccountReads is a writer whose first fails ServiceAccount reads
// after an apply fail, and whose later ones answer.
type failingAccountReads struct {
	*fakeJobs
	fails int
}

func (f *failingAccountReads) GetMeta(ctx context.Context, k kube.Kind, namespace, name string) (kube.Object, error) {
	if len(f.applied) > 0 && f.fails > 0 {
		f.fails--
		return kube.Object{}, errors.New("kube: GET /api/v1/namespaces/farcast-system/serviceaccounts/farcast-builder: 503")
	}
	return f.fakeJobs.GetMeta(ctx, k, namespace, name)
}

// TestGrantNamesTheServiceAccountUID's push rows (design §33, A33-4,
// mutation 126): the push grant names the builder's ServiceAccount by its
// uid, read from the cluster: the fact's principal, the policy read's
// member and the printed add carry the fixture's uid principal, and the
// principal every instance in the project shares appears only as the fact's
// shared principal and in the commands that remove it.
func TestGrantNamesTheServiceAccountUID(t *testing.T) {
	check := func(t *testing.T, b plan.Bound, text, project string, fp *fakeProvider) {
		t.Helper()
		member := uidMember(fixtureProjectNumber, project, fixtureBuilderUID)
		g := grantAfterImage(t, b)
		if g.Principal != member || len(fp.grantReads) != 1 || fp.grantReads[0].Member != member {
			t.Errorf("the grant names %s, and the policy was read for %+v; want %s", g.Principal, fp.grantReads, member)
		}
		notices := noticesOf(b)
		if len(notices) != 1 || !strings.Contains(notices[0], "add-iam-policy-binding") || !strings.Contains(notices[0], "--member '"+member+"'") {
			t.Errorf("the notice does not add %s:\n%q", member, notices)
		}
		for _, f := range b.Facts {
			if _, ok := f.(plan.GrantFact); ok {
				continue
			}
			lines := []string{}
			if n, ok := f.(plan.NoticeFact); ok {
				lines = strings.Split(n.Text, "\n")
			} else if raw, err := json.Marshal(f); err == nil {
				lines = []string{string(raw)}
			}
			for _, l := range lines {
				if strings.Contains(l, "subject/ns/") && !strings.Contains(l, "remove-iam-policy-binding") {
					t.Errorf("a %s names the shared principal outside a remove: %s", f.FactType(), l)
				}
			}
		}
		for _, l := range strings.Split(text, "\n") {
			if strings.Contains(l, "subject/ns/") && !strings.Contains(l, "remove-iam-policy-binding") && !strings.HasPrefix(l, "  the shared principal ") {
				t.Errorf("the rendering names the shared principal outside its line and the removes: %s", l)
			}
		}
	}
	t.Run("build", func(t *testing.T) {
		shared := builderSharedMember(fixtureProjectNumber, "proj-1")
		fp := &fakeProvider{grantStates: map[string]planck.GrantState{shared: planck.GrantPresent}}
		_, b := buildPlanOf(t, fixtureAccounts(), fp)
		check(t, b, renderPlan(t, b), "proj-1", fp)
	})
	t.Run("run <D>", func(t *testing.T) {
		r := newStageRig(t, nil)
		r.f.accounts = fixtureAccounts()
		r.fp = &fakeProvider{grantStates: map[string]planck.GrantState{builderSharedMember(fixtureProjectNumber, "proj-test1"): planck.GrantPresent}}
		b := decodedBound(t, r.deployPlan())
		check(t, b, renderPlan(t, b), "proj-test1", r.fp)
	})
	t.Run("storage deploy", bucketGrantNamesTheUID)
}

// TestGrantsWithoutTheCapabilityAreUnknown's push rows (design §33, MS-6):
// a provider without planck.GrantReader leaves both principals "" and both
// states unknown, reads nothing, and the notice's commands read the project
// number into PROJNUM, naming the principals double-quoted around it.
func TestGrantsWithoutTheCapabilityAreUnknown(t *testing.T) {
	check := func(t *testing.T, b plan.Bound, project string, fp *fakeProvider) {
		t.Helper()
		g := grantAfterImage(t, b)
		if g.Principal != "" || g.SharedPrincipal != "" || g.State != plan.GrantUnknown || g.Shared != plan.GrantUnknown || len(fp.grantCalls) != 0 {
			t.Errorf("the grant is %+v after the calls %q; want no principal, both unknown, nothing read", g, fp.grantCalls)
		}
		notices := noticesOf(b)
		want := []string{msgPushGrantUnknown,
			"  PROJNUM=$(gcloud projects describe '" + project + "' --format='value(projectNumber)')",
			`--member "principal://iam.googleapis.com/projects/${PROJNUM}/locations/global/workloadIdentityPools/` + project +
				`.svc.id.goog/kubernetes.serviceaccount.uid/` + fixtureBuilderUID + `"`,
			`--member "principal://iam.googleapis.com/projects/${PROJNUM}/locations/global/workloadIdentityPools/` + project +
				`.svc.id.goog/subject/ns/farcast-system/sa/farcast-builder"`,
		}
		for _, w := range want {
			if len(notices) != 1 || !strings.Contains(notices[0], w) {
				t.Errorf("the notice does not hold %q:\n%q", w, notices)
			}
		}
	}
	t.Run("build", func(t *testing.T) {
		fp := &fakeProvider{}
		_, b := buildPlanOf(t, fixtureAccounts(), clusterOnlyProvider{fp})
		check(t, b, "proj-1", fp)
	})
	t.Run("run <D>", func(t *testing.T) {
		r := newStageRig(t, nil)
		r.f.accounts = fixtureAccounts()
		r.fp, r.hideGrants = &fakeProvider{}, true
		check(t, decodedBound(t, r.deployPlan()), "proj-test1", r.fp)
	})
	t.Run("storage deploy", bucketGrantsWithoutTheCapability)
}
