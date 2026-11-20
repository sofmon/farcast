package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/planck"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// msgAtlasNotMigrated is refuseUnmigrated's text for writeName, written out
// (design §6.5).
const msgAtlasNotMigrated = `instance "atlas" was last written by kubectl's client-side apply, and this farcast writes with server-side apply; ` +
	`run 'farcast migrate atlas --plan' to review the one-time rewrite, then 'farcast migrate atlas --confirm <digest>'. Nothing was written.`

// unmigratedInstance is writeInstance's instance against s, with wc's edit,
// saved again as an instance whose objects were last written with kubectl's
// client-side apply (no server_side_apply), and then wc's prepare.
func unmigratedInstance(t *testing.T, s *kubetest.Server, wc writeCommand) config.Dir {
	t.Helper()
	dir, meta := writeInstance(t, s, true)
	if wc.edit != nil {
		wc.edit(meta)
	}
	meta.ServerSideApply = nil
	if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
		t.Fatal(err)
	}
	if wc.prepare != nil {
		wc.prepare(t, dir)
	}
	return dir
}

// consentForm is wc as it runs past every question: with --yes, or, for
// reader grant, which refuses --yes, through the interactive seam its row
// already sets; or, with planned, under --plan in place of --yes.
func consentForm(wc writeCommand, planned bool) writeCommand {
	flags := slices.DeleteFunc(slices.Clone(wc.flags), func(f string) bool { return f == "--yes" })
	switch {
	case planned:
		flags = append(flags, "--plan")
	case wc.name != "reader grant":
		flags = append(flags, "--yes")
	}
	wc.flags = flags
	return wc
}

// countDefaultProviderOpens makes the default provider opener count each open, and
// refuse it, for the rest of the test.
func countDefaultProviderOpens(t *testing.T) (opened func() int) {
	t.Helper()
	saved, n := openProviderDefault, 0
	openProviderDefault = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		n++
		return nil, errRefusingDefault
	}
	t.Cleanup(func() { openProviderDefault = saved })
	return func() int { return n }
}

// ADR 0023 M2.7 (design A30-20, §10.5 rows 92 and 92a): every command that
// writes to an instance's cluster refuses one whose objects were last written
// with kubectl's client-side apply before anything is asked, opened, minted
// or sent, with --yes (or reader grant's interactive seam) and under --plan
// alike: not_migrated, exit 1, nothing printed and no [y/N]; no request,
// /token included; credentials.yaml and the CA key never read; the provider
// never opened; and the config directory byte for byte what it was. Rotate's
// fixture has a keyholder, whose pin it would write. migrate, the one
// writeCommands row that never refuses an unmigrated instance, is how one
// comes to be recorded, and is left out.
func TestUnmigratedInstanceIsRefusedBeforeAnythingIsAsked(t *testing.T) {
	realPinOpener(t)
	opened := countDefaultProviderOpens(t)
	for _, wc := range writeCommands() {
		if wc.name == "migrate" {
			continue
		}
		for _, planned := range []bool{false, true} {
			form, how := consentForm(wc, planned), " --yes"
			switch {
			case planned:
				how = " --plan"
			case !slices.Contains(form.flags, "--yes"):
				how = ", interactive"
			}
			t.Run(wc.name+how, func(t *testing.T) {
				s := kubetest.New(t)
				dir := unmigratedInstance(t, s, wc)
				before, was := treeFiles(t, string(dir)), opened()
				reads := observeConfigReads(t)

				out, errb, err := runWrite(t, dir, form)
				if kindOf(classified(err)) != kindNotMigrated || exitCodeOf(err) != 1 {
					t.Fatalf("%s = %v (kind %s, exit %d); want not_migrated, exit 1", wc.name, err, kindOf(classified(err)), exitCodeOf(err))
				}
				if len(out)+len(errb) != 0 || bytes.Contains(errb, []byte("[y/N]")) {
					t.Errorf("%s printed %q and %q before it refused", wc.name, out, errb)
				}
				if got := s.Requests(); len(got) != 0 {
					t.Errorf("%s sent %d requests before it refused, the first %s %s", wc.name, len(got), got[0].Method, got[0].Path)
				}
				for _, p := range reads() {
					if base := filepath.Base(p); base == "credentials.yaml" || base == "ca.key" {
						t.Errorf("%s read %s before it refused", wc.name, base)
					}
				}
				if n := opened() - was; n != 0 {
					t.Errorf("%s opened the provider %d times before it refused", wc.name, n)
				}
				sameFiles(t, wc.name+" on an unmigrated instance", before, treeFiles(t, string(dir)))
			})
		}
	}
}

// clusterWriters is the commands that write to an instance's cluster, each
// of which refuses an instance not migrated to server-side apply, by the
// names a command line gives them, sorted: every command farcast's router
// reaches with a seam that writes (productionWriters, design A30-26) but
// migrate, which never refuses.
func clusterWriters(t *testing.T) []string {
	t.Helper()
	var names []string
	for name := range productionWriters(t) {
		if name != "migrate" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// ADR 0023 M2.7 (design §6.5, A30-20; §10.5 rows 93, 93a and 93b): every
// command that writes to an instance's cluster refuses one not migrated to
// server-side apply, with §6.5's text, kind not_migrated, and leaves it
// unmigrated: each of clusterWriters, derived from farcast's own commands,
// and connect's resume too. Each refuses
// before what A30-20 places after it: connect before its precheck (a farcast
// whose carried components it must not push), storage key pin before it
// reads the keyring, run before its fetch plan's blocks, interactively and
// under --plan, and build before its check of --repo and --app. The forms
// that write nothing to the cluster never refuse
// for it, and go on as on a migrated instance: connect's reconnect and
// --status, kernel meter's list of what it meters, and storage key rotate
// with no keyholder, interactively and under --plan.
func TestEveryClusterWriterRefusesAnUnmigratedInstance(t *testing.T) {
	realPinOpener(t)
	type row struct {
		name    string
		wc      writeCommand
		refuses bool
	}
	var rows []row
	for _, name := range clusterWriters(t) {
		rows = append(rows, row{name: name, wc: writeCommandNamed(t, name), refuses: true})
	}
	resume := writeCommandNamed(t, "connect")
	resume.edit = func(m *config.InstanceMetadata) { m.Carrier = nil }
	notRelease := writeCommandNamed(t, "connect")
	notRelease.cmd = func() Command {
		c := testConnect(&fakeProvider{}, &fakeBuilder{})
		c.build = devBuild
		return c
	}
	// A connect against a healthy boundary, its provider a fake, over the
	// material the fixture's connected instance holds.
	reconnect := func(flags ...string) writeCommand {
		return writeCommand{name: "connect", args: []string{writeName}, flags: flags, prepare: writeMaterial, cmd: func() Command {
			c := testConnect(&fakeProvider{}, &fakeBuilder{})
			c.dial = connectedDial()
			return c
		}}
	}
	// Refused before what the record alone decides next: storage key pin
	// before it reads the keyring, run before its fetch plan's blocks, build
	// before its usage check of --repo and --app.
	noKeys := writeCommandNamed(t, "storage key pin")
	noKeys.prepare = func(t *testing.T, dir config.Dir) {
		if err := os.Remove(dir.InstanceKeyringPath(writeName)); err != nil {
			t.Fatal(err)
		}
	}
	noKernel := writeCommandNamed(t, "run")
	noKernel.edit = func(m *config.InstanceMetadata) { m.Kernel = nil }
	noRepo := writeCommandNamed(t, "build")
	noRepo.flags = []string{"--builder-image", builderDigest, "--yes"}
	listOnly := writeCommandNamed(t, "kernel meter")
	listOnly.args = []string{writeName}
	alone := writeCommandNamed(t, "storage key rotate")
	alone.edit = func(m *config.InstanceMetadata) { m.Keyholder = nil }
	alonePlanned := consentForm(alone, true)
	rows = append(rows,
		row{name: "connect, resuming", wc: resume, refuses: true},
		row{name: "connect, from a farcast that is not a release", wc: notRelease, refuses: true},
		row{name: "storage key pin, its keyring missing", wc: noKeys, refuses: true},
		row{name: "run, no kernel", wc: noKernel, refuses: true},
		row{name: "run, no kernel, --plan", wc: consentForm(noKernel, true), refuses: true},
		row{name: "build, no --repo or --app", wc: noRepo, refuses: true},
		row{name: "connect, reconnecting", wc: reconnect()},
		row{name: "connect, reconnecting, --plan", wc: reconnect("--plan")},
		row{name: "connect --status", wc: reconnect("--status")},
		row{name: "kernel meter, listing", wc: listOnly},
		row{name: "storage key rotate, no keyholder", wc: alone},
		row{name: "storage key rotate, no keyholder, --plan", wc: alonePlanned},
	)
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s := kubetest.New(t)
			dir := unmigratedInstance(t, s, r.wc)
			out, errb, err := runWrite(t, dir, r.wc)
			if !r.refuses {
				if err != nil {
					t.Fatalf("%s on an unmigrated instance = %v (kind %s); it writes nothing to the cluster, and must go on\nstderr: %s",
						r.name, err, kindOf(classified(err)), errb)
				}
				if len(out) == 0 {
					t.Errorf("%s printed no result", r.name)
				}
				return
			}
			var k *kindError
			if !errors.As(err, &k) || k.kind != kindNotMigrated || err.Error() != msgAtlasNotMigrated {
				t.Fatalf("%s on an unmigrated instance = %v (kind %s); want not_migrated, %q", r.name, err, kindOf(classified(err)), msgAtlasNotMigrated)
			}
			meta, lerr := dir.LoadInstanceMetadata(writeName)
			if lerr != nil {
				t.Fatal(lerr)
			}
			if meta.ServerSideApply != nil {
				t.Errorf("%s recorded the instance as migrated: %+v", r.name, *meta.ServerSideApply)
			}
		})
	}
}

// ADR 0023 M2.7 (A30-20, A30-28): the refusal holds under --confirm, the
// one mode that runs with no question. A plan binds nothing for it, so a
// digest made while the instance was recorded as migrated still matches once
// the record no longer says so: a trace found since has cleared it
// (afterWrites), or the plan was made on another machine whose copy of the
// record is migrated. Every plan of every command that writes to the
// cluster, confirmed then, is refused not_migrated, exit 1, with nothing
// sent, printed on stdout or stderr, or written: each plan of
// applyingPlans, through its command's real writer, and each plan of
// storage key pin, and of storage key rotate with a keyholder, the two
// commands applyingPlans leaves out.
func TestConfirmRefusesAnInstanceUnmigratedSinceItsPlan(t *testing.T) {
	unmigrate := func(t *testing.T, dir config.Dir) {
		t.Helper()
		meta, err := dir.LoadInstanceMetadata(writeName)
		if err != nil {
			t.Fatal(err)
		}
		if meta.ServerSideApply == nil {
			t.Fatal("the fixture's record is not migrated: its plan was made unmigrated")
		}
		meta.ServerSideApply = nil
		if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(t *testing.T, what string, err error, sent int, stdout, stderr string) {
		t.Helper()
		if kindOf(classified(err)) != kindNotMigrated || exitCodeOf(err) != 1 || err.Error() != msgAtlasNotMigrated {
			t.Fatalf("%s --confirm on an instance unmigrated since its plan = %v (kind %s, exit %d); want not_migrated, exit 1",
				what, err, kindOf(classified(err)), exitCodeOf(err))
		}
		if sent != 0 || stdout != "" || stderr != "" {
			t.Errorf("%s --confirm sent %d requests, and printed %q on stdout and %q on stderr, before it refused", what, sent, stdout, stderr)
		}
	}
	for _, p := range applyingPlans(t) {
		t.Run(p.String(), func(t *testing.T) {
			var before map[string]string
			c := confirmApplying(t, p, func(_ *kubetest.Server, dir config.Dir, _ plan.Bound) {
				unmigrate(t, dir)
				before = treeFiles(t, string(dir))
			})
			refused(t, p.String(), c.err, len(c.sent), c.stdout, c.stderr)
			sameFiles(t, p.String()+" --confirm, unmigrated since its plan", before, treeFiles(t, string(c.dir)))
		})
	}
	var keyRows int
	for _, row := range planCommands() {
		if (row.name != "storage key pin" && row.name != "storage key rotate") || row.shape == "no keyholder" {
			continue
		}
		keyRows++
		t.Run(row.String(), func(t *testing.T) {
			s, dir := planFixture(t, row)
			digest := planDigest(t, dir, row)
			unmigrate(t, dir)
			before, seen := treeFiles(t, string(dir)), len(s.Requests())
			cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", digest)...)
			env, out, errb := testEnvBoth(dir, output.ModeJSON)
			err := cmd.Run(t.Context(), env, row.args)
			refused(t, row.String(), err, len(s.Requests())-seen, out.String(), errb.String())
			sameFiles(t, row.String()+" --confirm, unmigrated since its plan", before, treeFiles(t, string(dir)))
		})
	}
	if keyRows < 2 {
		t.Errorf("planCommands holds %d plans of storage key pin and storage key rotate with a keyholder; want each command's", keyRows)
	}
}

// migrateMarker is what a test puts in a Secret's data and in its
// last-applied annotation, raw and in base64: no plan, error or output may
// carry it.
const migrateMarker = "MIGRATE-SECRET-MARKER"

// The objects clientSideSeeded holds: a Deployment and a Secret in
// farcast-system, and a RoleBinding in a namespace nothing labels, as kernel
// meter binds the kernel there. The Secret's uid is fixed, so a test can
// answer for it.
const (
	seededDeployment  = "fatline"
	seededSecret      = "fatline-mtls"
	seededRoleBinding = "technocore"
	seededSecretUID   = "00000000-0000-4000-8000-0000000000b2"
)

// clientSideObject is an object as an older farcast left it, applied with
// kubectl's client-side apply: farcast's label, kubectl's last-applied
// annotation holding last, and kubectl-client-side-apply's one Update entry,
// which owns both. namespace is "" for a cluster-scoped kind.
func clientSideObject(apiVersion, kind, namespace, name, last string) map[string]any {
	md := map[string]any{
		"name":        name,
		"labels":      map[string]any{"app.kubernetes.io/managed-by": "farcast"},
		"annotations": map[string]any{lastAppliedAnnotation: last},
		"managedFields": []any{map[string]any{
			"manager": "kubectl-client-side-apply", "operation": "Update", "apiVersion": apiVersion,
			"time": "2026-11-01T09:00:00Z", "fieldsType": "FieldsV1",
			"fieldsV1": map[string]any{"f:metadata": map[string]any{
				"f:annotations": map[string]any{".": map[string]any{}, "f:" + lastAppliedAnnotation: map[string]any{}},
				"f:labels":      map[string]any{".": map[string]any{}, "f:app.kubernetes.io/managed-by": map[string]any{}},
			}},
		}},
	}
	if namespace != "" {
		md["namespace"] = namespace
	}
	return map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": md}
}

// clientSideSecret is the Secret clientSideSeeded holds: its data and its
// last-applied annotation, as kubectl wrote it, each carry migrateMarker.
func clientSideSecret() map[string]any {
	encoded := base64.StdEncoding.EncodeToString([]byte(migrateMarker))
	o := clientSideObject("v1", "Secret", tcdeploy.DefaultNamespace, seededSecret,
		`{"apiVersion":"v1","data":{"key":"`+encoded+`"},"kind":"Secret","stringData":{"raw":"`+migrateMarker+`"}}`+"\n")
	o["metadata"].(map[string]any)["uid"] = seededSecretUID
	o["data"] = map[string]any{"key": encoded}
	return o
}

// clientSideSeeded puts farcast-system (systemNamespace) and three objects
// an older farcast applied with kubectl's client-side apply in s: the
// Deployment, the Secret and the RoleBinding of seededDeployment,
// seededSecret and seededRoleBinding. Discovery lists them in the kinds'
// order: the Secret, the Deployment, then the RoleBinding.
func clientSideSeeded(s *kubetest.Server) {
	systemNamespace(s)
	s.Put(clientSideObject("apps/v1", "Deployment", tcdeploy.DefaultNamespace, seededDeployment, `{"kind":"Deployment"}`+"\n"))
	s.Put(clientSideSecret())
	s.Put(clientSideObject("rbac.authorization.k8s.io/v1", "RoleBinding", writeNewNamespace, seededRoleBinding, `{"kind":"RoleBinding"}`+"\n"))
}

// The paths of the seeded objects.
var (
	deploymentPath  = "/apis/apps/v1/namespaces/" + tcdeploy.DefaultNamespace + "/deployments/" + seededDeployment
	secretPath      = "/api/v1/namespaces/" + tcdeploy.DefaultNamespace + "/secrets/" + seededSecret
	roleBindingPath = "/apis/rbac.authorization.k8s.io/v1/namespaces/" + writeNewNamespace + "/rolebindings/" + seededRoleBinding
)

// migrateFixture is writeInstance against a fresh kubetest server started
// with opts and seeded by seed, its record saved again unmigrated, as an
// older farcast left it.
func migrateFixture(t *testing.T, seed func(*kubetest.Server), opts ...kubetest.Option) (*kubetest.Server, config.Dir) {
	t.Helper()
	s := kubetest.New(t, opts...)
	if seed != nil {
		seed(s)
	}
	dir, meta := writeInstance(t, s, true)
	meta.ServerSideApply = nil
	if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

// runMigrate runs migrate against dir, its flags parsed as the router
// parses them, in mode, interactive or not, with in on stdin, its writer the
// package's default (a loopback writer in tests), its clock planClock, and
// its sleep recorded and never slept. It returns what it printed, the sleeps
// it asked for, and its error.
func runMigrate(t *testing.T, dir config.Dir, mode output.Mode, interactive bool, in string, flags ...string) (stdout, stderr string, slept []time.Duration, err error) {
	t.Helper()
	c := withFlags(t, &migrateCommand{}, flags...)
	c.interactive = func(*Env) bool { return interactive }
	c.now = planClock
	c.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}
	env, out, errb := testEnvBoth(dir, mode)
	env.In = strings.NewReader(in)
	err = c.Run(t.Context(), env, []string{writeName})
	return out.String(), errb.String(), slept, err
}

// migratePlan is migrate --plan against dir, in JSON: the printed document,
// and the plan decoded.
func migratePlan(t *testing.T, dir config.Dir) (plan.Document, plan.Bound) {
	t.Helper()
	out, errb, _, err := runMigrate(t, dir, output.ModeJSON, false, "", "--plan")
	if err != nil {
		t.Fatalf("migrate --plan: %v\n%s", err, errb)
	}
	doc := printedDocument(t, []byte(out))
	return doc, decodedBound(t, doc)
}

// migrateFactOf is the plan's one migrate fact.
func migrateFactOf(t *testing.T, b plan.Bound) plan.MigrateFact {
	t.Helper()
	if len(b.Facts) != 1 {
		t.Fatalf("the plan binds %d facts; want the migrate fact alone", len(b.Facts))
	}
	f, ok := b.Facts[0].(plan.MigrateFact)
	if !ok {
		t.Fatalf("the plan's fact is a %T, not migrate's", b.Facts[0])
	}
	return f
}

// migrateConfirm is migrate --plan, then --confirm with its digest, in JSON:
// what the --confirm printed, the sleeps it asked for, and its error.
func migrateConfirm(t *testing.T, dir config.Dir) (stdout, stderr string, slept []time.Duration, err error) {
	t.Helper()
	doc, _ := migratePlan(t, dir)
	return runMigrate(t, dir, output.ModeJSON, false, "", "--confirm", doc.Digest)
}

// objectNames is each plan object as describeObject names it.
func objectNames(f plan.MigrateFact) []string {
	var out []string
	for _, o := range f.Objects {
		out = append(out, describeObject(o.Kind, o.Namespace, o.Name))
	}
	return out
}

// storedObject is the object at apiVersion and kind, namespace and name in
// the fixture's cluster, its metadata read as the writer.
func storedObject(t *testing.T, dir config.Dir, apiVersion, kind, namespace, name string) kube.Object {
	t.Helper()
	meta, err := dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := openWriter(clusterRef{Dir: dir, Meta: meta, Identity: kube.Writer, Warn: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	k, ok := kube.KindOf(apiVersion, kind)
	if !ok {
		t.Fatalf("no kind %s %s", apiVersion, kind)
	}
	o, err := cl.GetMeta(t.Context(), k, namespace, name)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// patchesTo counts the PATCHes s saw to path.
func patchesTo(s *kubetest.Server, path string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method == http.MethodPatch && r.Path == path {
			n++
		}
	}
	return n
}

// recordedMigration is the instance's server_side_apply record, nil for
// none.
func recordedMigration(t *testing.T, dir config.Dir) *config.ServerSideApply {
	t.Helper()
	meta, err := dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	return meta.ServerSideApply
}

// legacyFile is a legacy kubectl file of the fixture's instance, by its base
// name, and whether it is there.
func legacyFile(t *testing.T, dir config.Dir, base string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(dir.InstancePath(writeName), base))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// statusBody is a Kubernetes Status a handler answers with.
func statusBody(code int, reason string) []byte {
	b, err := json.Marshal(map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": reason, "code": code})
	if err != nil {
		panic(err)
	}
	return b
}

// objectBody is obj as JSON, for a handler's answer.
func objectBody(obj map[string]any) []byte {
	b, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	return b
}

// ADR 0023 M2.7 (design §6.1, A30-21; §10.5 row 99): --yes never migrates.
// --yes and -y are each a usage error, exit 2, naming the instance, or
// <instance> for a name that is not one, before anything is read, asked or
// sent; and --yes beside --plan is the three-way usage error, the answers
// counted first. Through the router the refusal is the same.
func TestMigrateRefusesYes(t *testing.T) {
	s := kubetest.New(t)
	dir, _ := writeInstance(t, s, true)
	for _, tc := range []struct {
		args  []string
		flags []string
		want  string
	}{
		{[]string{writeName}, []string{"--yes"}, fmt.Sprintf(msgMigrateYes, writeName)},
		{[]string{writeName}, []string{"-y"}, fmt.Sprintf(msgMigrateYes, writeName)},
		{[]string{"../other"}, []string{"--yes"}, fmt.Sprintf(msgMigrateYes, "<instance>")},
		{[]string{writeName}, []string{"--yes", "--plan"}, msgConsentExclusive},
		{[]string{writeName}, []string{"-y", "--confirm", sampleDigest}, msgConsentExclusive},
	} {
		reads := observeConfigReads(t)
		c := withFlags(t, &migrateCommand{interactive: func(*Env) bool { return true }}, tc.flags...)
		env, out, errb := testEnvBoth(dir, output.ModeJSON)
		env.In = strings.NewReader(writeName + "\n")
		err := c.Run(t.Context(), env, tc.args)
		var ue *usageError
		if !errors.As(err, &ue) || err.Error() != tc.want || exitCodeOf(err) != 2 {
			t.Errorf("migrate %q %q = %v; want the usage error %q", tc.args, tc.flags, err, tc.want)
		}
		if got := reads(); len(got) != 0 || out.Len()+errb.Len() != 0 {
			t.Errorf("migrate %q read %q and printed %q %q before refusing", tc.flags, got, out, errb)
		}
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("migrate --yes sent %d requests", len(got))
	}
	stdout, stderr, code := farcastIn(t, dir, "migrate", writeName, "--yes")
	if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "farcast migrate: "+fmt.Sprintf(msgMigrateYes, writeName)+"\n") {
		t.Errorf("farcast migrate --yes: exit %d, %q %q", code, stdout, stderr)
	}
	if recordedMigration(t, dir) == nil {
		t.Fatal("the fixture's record is not migrated")
	}
}

// ADR 0023 M2.7 (design §6.1, A30-21): migrate asks in a terminal or takes a
// plan. With neither a terminal nor an answer it is a usage error, exit 2,
// naming the plan's route, before it reads the record or sends anything; in
// JSON mode it is never interactive. With --plan it needs no terminal.
func TestMigrateNeedsATerminalOrAPlan(t *testing.T) {
	s, dir := migrateFixture(t, clientSideSeeded)
	before := treeFiles(t, string(dir))
	reads := observeConfigReads(t)
	_, _, _, err := runMigrate(t, dir, output.ModeJSON, false, writeName+"\n")
	var ue *usageError
	if !errors.As(err, &ue) || err.Error() != msgMigrateTerminal || exitCodeOf(err) != 2 {
		t.Fatalf("migrate with no terminal = %v; want the usage error %q", err, msgMigrateTerminal)
	}
	if got := reads(); len(got) != 0 {
		t.Errorf("migrate with no terminal read %q", got)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("migrate with no terminal sent %d requests", len(got))
	}
	c := &migrateCommand{}
	c.ensureDefaults()
	env, _, _ := testEnvBoth(dir, output.ModeJSON)
	if c.interactive(env) {
		t.Error("migrate in JSON mode takes itself for interactive")
	}
	sameFiles(t, "migrate with no terminal", before, treeFiles(t, string(dir)))

	if _, b := migratePlan(t, dir); len(migrateFactOf(t, b).Objects) != 3 {
		t.Errorf("migrate --plan with no terminal planned %d objects; want the 3 seeded", len(migrateFactOf(t, b).Objects))
	}
}

// ADR 0023 M2.7 (A30-21 step 5): migrate refuses an instance being
// released, in every mode, once it has read the record and before it opens
// its writer: no request, nothing printed, no file changed and nothing
// recorded.
func TestMigrateRefusesAnInstanceBeingReleased(t *testing.T) {
	for _, tc := range []struct {
		name        string
		interactive bool
		flags       []string
	}{
		{"--plan", false, []string{"--plan"}},
		{"--confirm", false, []string{"--confirm", sampleDigest}},
		{"interactive", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := migrateFixture(t, clientSideSeeded)
			meta, err := dir.LoadInstanceMetadata(writeName)
			if err != nil {
				t.Fatal(err)
			}
			meta.Status = config.InstanceDeleting
			if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
				t.Fatal(err)
			}
			before := treeFiles(t, string(dir))
			out, errb, _, err := runMigrate(t, dir, output.ModeJSON, tc.interactive, writeName+"\n", tc.flags...)
			if err == nil || err.Error() != `instance "atlas" is being released` || exitCodeOf(err) != 1 {
				t.Errorf("migrate %s on an instance being released = %v; want it refused", tc.name, err)
			}
			if got := s.Requests(); len(got) != 0 || out != "" || errb != "" {
				t.Errorf("migrate %s on an instance being released sent %d requests and printed %q %q", tc.name, len(got), out, errb)
			}
			sameFiles(t, "migrate on an instance being released", before, treeFiles(t, string(dir)))
		})
	}
}

// ADR 0023 M2.7 (design §6.1, A30-21): an interactive migrate prints its
// plan on stderr, then asks for the instance's name and compares what is
// typed, trimmed, with the name exactly. The name, with or without spaces
// around it, migrates; anything else, a longer name holding it, a shorter
// one, another case, or the "y" a yes-or-no question takes, aborts: Aborted.
// on stderr, exit 0, no PATCH, nothing recorded and no file changed.
func TestMigrateInteractiveComparesTheTypedName(t *testing.T) {
	for _, tc := range []struct {
		typed    string
		migrates bool
	}{
		{writeName + "\n", true},
		{"  " + writeName + " \t\n", true},
		{writeName + "-old\n", false},
		{"x" + writeName + "\n", false},
		{"atla\n", false},
		{strings.ToUpper(writeName) + "\n", false},
		{"y\n", false},
		{"\n", false},
	} {
		t.Run(strings.TrimSpace(tc.typed), func(t *testing.T) {
			s, dir := migrateFixture(t, clientSideSeeded)
			before := treeFiles(t, string(dir))
			out, errb, _, err := runMigrate(t, dir, output.ModeHuman, true, tc.typed)
			if err != nil {
				t.Fatalf("migrate, typing %q: %v\n%s", tc.typed, err, errb)
			}
			if !strings.Contains(errb, "\ndigest: sha256:") || !strings.Contains(errb, "farcast migrate "+writeName+", stage -, reading the cluster as writer") ||
				!strings.HasSuffix(strings.TrimSuffix(errb, "Aborted.\n"), "\n"+msgMigratePrompt+": ") {
				t.Errorf("migrate, typing %q, did not show its plan and ask for the name:\n%s", tc.typed, errb)
			}
			patched := 0
			for _, r := range s.Requests() {
				if r.Method == http.MethodPatch {
					patched++
				}
			}
			if !tc.migrates {
				if !strings.HasSuffix(errb, msgMigratePrompt+": Aborted.\n") || out != "" {
					t.Errorf("migrate, typing %q: stdout %q, stderr ends %q; want Aborted.", tc.typed, out, errb[max(0, len(errb)-80):])
				}
				if patched != 0 || recordedMigration(t, dir) != nil {
					t.Errorf("migrate, typing %q, sent %d PATCHes and recorded %+v", tc.typed, patched, recordedMigration(t, dir))
				}
				sameFiles(t, "migrate, aborted", before, treeFiles(t, string(dir)))
				return
			}
			if patched != 3 || recordedMigration(t, dir) == nil || !strings.HasPrefix(out, "Migrated 3 object(s) of instance atlas to server-side apply") {
				t.Errorf("migrate, typing %q: %d PATCHes, record %+v, printed %q; want the 3 objects migrated and recorded", tc.typed, patched, recordedMigration(t, dir), out)
			}
		})
	}
}

// ADR 0023 M2.7 (design §6.1, §7.3, A30-21): migrate's plan is the one plan
// read as the writer, because it lists Secrets' metadata, which the reader is
// never granted. Its cluster_identity is writer and it binds farcast-system's
// uid as the writer read it; every request is the writer's token or a GET
// as the writer; credentials.yaml is read; and no reader key is opened,
// whether the instance has a granted reader or none at all.
func TestMigratePlanReadsAsTheWriterAndNeedsNoReader(t *testing.T) {
	for _, reader := range []bool{true, false} {
		t.Run(fmt.Sprintf("a reader recorded: %v", reader), func(t *testing.T) {
			s, dir := migrateFixture(t, clientSideSeeded)
			if !reader {
				meta, err := dir.LoadInstanceMetadata(writeName)
				if err != nil {
					t.Fatal(err)
				}
				meta.Reader = nil
				if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
					t.Fatal(err)
				}
				for _, f := range []string{"reader.key", "reader.crt"} {
					if err := os.Remove(filepath.Join(dir.InstancePath(writeName), f)); err != nil {
						t.Fatal(err)
					}
				}
			}
			reads := observeConfigReads(t)
			_, b := migratePlan(t, dir)
			if b.ClusterIdentity != "writer" || b.Target.SystemNamespaceUID != planSystemUID || b.Command != "migrate" || len(b.Options) != 0 {
				t.Errorf("the plan reads as %q, binds farcast-system %q, is %q's, with options %+v; want the writer's, %q, migrate's, none",
					b.ClusterIdentity, b.Target.SystemNamespaceUID, b.Command, b.Options, planSystemUID)
			}
			if f := migrateFactOf(t, b); !f.CannotBeUndone || len(f.Objects) != 3 {
				t.Errorf("the fact is %+v; want the 3 seeded objects, irreversible", f)
			}
			var creds bool
			for _, p := range reads() {
				switch filepath.Base(p) {
				case "credentials.yaml":
					creds = true
				case "reader.key", "reader.crt":
					t.Errorf("migrate --plan read %s", p)
				}
			}
			if !creds {
				t.Error("migrate --plan did not read credentials.yaml, the writer's key")
			}
			reqs := s.Requests()
			if len(reqs) == 0 {
				t.Fatal("migrate --plan sent nothing")
			}
			for _, r := range reqs {
				if r.As != "writer" || (r.Path != "/token" && r.Method != http.MethodGet) {
					t.Errorf("migrate --plan sent %s %s as %q; want the writer's token and reads alone", r.Method, r.Path, r.As)
				}
			}
		})
	}
}

// ADR 0023 M2.7 (A30-21, M9): migrate runs as the installer service account
// whose key 'farcast install --credentials' stored. On an instance installed
// without one, the writer's open refuses, credential_missing, and migrate
// says, after openCluster's own words, why it cannot go on and that such an
// instance can only be released, in every mode, having sent nothing and
// changed no file. Another open refusal is not given that sentence.
func TestMigrateWithoutAnInstallerKeySaysSo(t *testing.T) {
	s := kubetest.New(t)
	clientSideSeeded(s)
	dir, meta := writeInstance(t, s, false)
	_, open := openWriter(clusterRef{Dir: dir, Meta: meta, Identity: kube.Writer, Warn: io.Discard})
	if open == nil || !strings.Contains(open.Error(), msgADCRefused) {
		t.Fatalf("the fixture's writer opens: %v", open)
	}
	want := open.Error() + `; migrate runs as the installer service account whose key 'farcast install --credentials' stored, ` +
		`so this machine cannot migrate instance "atlas"; an instance installed without one (possible only before ADR 0023 M2.5) ` +
		`cannot be migrated, only released`
	before := treeFiles(t, string(dir))
	for _, tc := range []struct {
		name        string
		interactive bool
		flags       []string
	}{
		{"--plan", false, []string{"--plan"}},
		{"--confirm", false, []string{"--confirm", sampleDigest}},
		{"interactive", true, nil},
	} {
		out, errb, _, err := runMigrate(t, dir, output.ModeJSON, tc.interactive, writeName+"\n", tc.flags...)
		if err == nil || err.Error() != want || !errors.Is(err, errCredentialMissing) || kindOf(classified(err)) != kindCredentialMissing || exitCodeOf(err) != 1 {
			t.Errorf("migrate %s on an install without a key = %v (kind %s); want %q, credential_missing", tc.name, err, kindOf(classified(err)), want)
		}
		if out != "" || errb != "" {
			t.Errorf("migrate %s printed %q %q", tc.name, out, errb)
		}
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("migrate sent %d requests on an install without a key", len(got))
	}
	sameFiles(t, "migrate on an install without a key", before, treeFiles(t, string(dir)))

	// A record with no endpoint is refused by openCluster too, endpoint_refused,
	// and is no matter of the installer's key.
	meta.Endpoint = ""
	meta.ServerSideApply = nil
	if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
		t.Fatal(err)
	}
	c := withFlags(t, &migrateCommand{}, "--plan")
	c.newCluster = func(r clusterRef) (migrateCluster, error) {
		// The writer farcast opens, which refuses a record with no endpoint
		// before it reads a key or sends anything.
		cl, err := openWriter(r)
		if err != nil {
			return nil, err
		}
		return cl, nil
	}
	env, _, _ := testEnvBoth(dir, output.ModeJSON)
	err := c.Run(t.Context(), env, []string{writeName})
	if err == nil || kindOf(classified(err)) != kindEndpointRefused || strings.Contains(err.Error(), "migrate runs as the installer service account") {
		t.Errorf("migrate --plan with no endpoint = %v; want openCluster's refusal alone, endpoint_refused", err)
	}
}

// ADR 0023 M2.7 (A30-21 step 6, A20-9): a 403 migrate's writer meets says
// whose it was, once, as it does for every command that writes: here the
// writer's preflight read of farcast-system, refused by RBAC, in every mode.
// Nothing is patched or recorded.
func TestMigrateSaysWhoseA403WasOnce(t *testing.T) {
	refused := kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.As != "writer" || r.Method != http.MethodGet || !strings.HasPrefix(r.Path, "/api/v1/namespaces") {
			return 0, nil, false
		}
		return http.StatusForbidden, statusBody(http.StatusForbidden, "Forbidden"), true
	})
	for _, tc := range []struct {
		name        string
		interactive bool
		flags       []string
	}{
		{"--plan", false, []string{"--plan"}},
		{"--confirm", false, []string{"--confirm", sampleDigest}},
		{"interactive", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := migrateFixture(t, clientSideSeeded, refused)
			_, _, _, err := runMigrate(t, dir, output.ModeJSON, tc.interactive, writeName+"\n", tc.flags...)
			if err == nil || strings.Count(err.Error(), msgWriterRBACRefused) != 1 || kindOf(classified(err)) != kindForbidden {
				t.Errorf("migrate %s, its writer refused by RBAC = %v (kind %s); want the writer's sentence once, forbidden", tc.name, err, kindOf(classified(err)))
			}
			if patchesTo(s, secretPath)+patchesTo(s, deploymentPath)+patchesTo(s, roleBindingPath) != 0 || recordedMigration(t, dir) != nil {
				t.Errorf("migrate %s, its writer refused, patched or recorded", tc.name)
			}
		})
	}
}

// providerSeeded is clientSideSeeded with the objects farcast never writes
// that carry its label and kubectl's client-side apply (A30-22): a
// ClusterRoleBinding not named farcast-reader-namespaces, and in each of
// kube-system, a gke- and a gmp- namespace a RoleBinding and the Namespace
// object itself, which is cluster-scoped. It also seeds, with the same
// trace, the Namespace of writeNewNamespace, which farcast writes (a
// farcast older than M2.7 kubectl-applied every Namespace it renders): that
// one is planned, not blocked.
func providerSeeded(s *kubetest.Server) {
	clientSideSeeded(s)
	const rbac = "rbac.authorization.k8s.io/v1"
	s.Put(clientSideObject(rbac, "ClusterRoleBinding", "", "someone-elses", "{}\n"))
	s.Put(clientSideObject("v1", "Namespace", "", writeNewNamespace, "{}\n"))
	for _, ns := range []string{"kube-system", "gke-managed-system", "gmp-public"} {
		s.Put(clientSideObject("v1", "Namespace", "", ns, "{}\n"))
		s.Put(clientSideObject(rbac, "RoleBinding", ns, seededRoleBinding, "{}\n"))
	}
}

// providerBlocks are providerSeeded's blocks, in discovery's order: the
// Namespaces, by name, the RoleBindings, by namespace, then the
// ClusterRoleBinding.
func providerBlocks() []plan.Block {
	block := func(object, why string) plan.Block {
		return plan.Block{Kind: kindInternal, Message: object + " carries farcast's label and kubectl's client-side apply, but it is not an object farcast writes (" +
			why + "); migrate never rewrites it: remove its app.kubernetes.io/managed-by label, or delete it, from Cloud Shell, then run 'farcast migrate atlas --plan' again"}
	}
	return []plan.Block{
		block("Namespace gke-managed-system", `namespace "gke-managed-system" is the provider's`),
		block("Namespace gmp-public", `namespace "gmp-public" is the provider's`),
		block("Namespace kube-system", `namespace "kube-system" is the provider's`),
		block("RoleBinding gke-managed-system/technocore", `namespace "gke-managed-system" is the provider's`),
		block("RoleBinding gmp-public/technocore", `namespace "gmp-public" is the provider's`),
		block("RoleBinding kube-system/technocore", `namespace "kube-system" is the provider's`),
		block("ClusterRoleBinding someone-elses", "a ClusterRoleBinding farcast writes is named farcast-reader-namespaces"),
	}
}

// ADR 0023 M2.7 (A30-22; §10.5 row 94b): an object that carries farcast's
// label and kubectl's client-side apply but that farcast never writes is a
// block, internal, one per object, named only in its block and never among
// the fact's objects: a ClusterRoleBinding by another name than
// farcast-reader-namespaces, an object in kube-system or a kube-, gke- or
// gmp- namespace, and such a namespace's Namespace object, which has no
// namespace of its own. A Namespace farcast writes, with the same trace, is
// one of the fact's objects and in no block. --plan prints the blocked plan,
// exit 0, its blocks first; --confirm refuses with the first block, exit 1;
// and an interactive run prints the plan and returns the first block's
// refusal before it asks. Neither patches anything or records the instance.
func TestMigratePlanBlocksObjectsFarcastNeverWrites(t *testing.T) {
	s, dir := migrateFixture(t, providerSeeded)
	doc, b := migratePlan(t, dir)
	if want := providerBlocks(); !slices.Equal(b.Blocked, want) {
		t.Errorf("the plan's blocks are\n%+v\nwant\n%+v", b.Blocked, want)
	}
	if got, want := objectNames(migrateFactOf(t, b)), []string{
		"Namespace extra", "Secret farcast-system/fatline-mtls", "Deployment farcast-system/fatline", "RoleBinding extra/technocore",
	}; !slices.Equal(got, want) {
		t.Errorf("the plan's objects are %q; want %q", got, want)
	}
	out, errb, _, err := runMigrate(t, dir, output.ModeHuman, false, "", "--plan")
	if err != nil || errb != "" || !strings.HasPrefix(out, "blocked (internal): Namespace gke-managed-system carries") ||
		!strings.HasSuffix(out, "\nblocked: --confirm would refuse this plan (internal)\n") {
		t.Errorf("migrate --plan of a blocked plan: %v, %q\n%s", err, errb, out)
	}

	first := providerBlocks()[0].Message
	out, errb, _, err = runMigrate(t, dir, output.ModeJSON, false, "", "--confirm", doc.Digest)
	if err == nil || err.Error() != first || kindOf(classified(err)) != kindInternal || exitCodeOf(err) != 1 || out != "" || errb != "" {
		t.Errorf("migrate --confirm of a blocked plan = %v (kind %s), printing %q %q; want its first block, internal", err, kindOf(classified(err)), out, errb)
	}
	out, errb, _, err = runMigrate(t, dir, output.ModeJSON, true, writeName+"\n")
	if err == nil || err.Error() != first || kindOf(classified(err)) != kindInternal || out != "" ||
		!strings.HasPrefix(errb, "blocked (internal): ") || strings.Contains(errb, msgMigratePrompt) {
		t.Errorf("an interactive migrate of a blocked plan = %v (kind %s), printing %q\n%s\nwant the plan shown and its first block, unasked", err, kindOf(classified(err)), out, errb)
	}
	for _, r := range s.Requests() {
		if r.Method != http.MethodGet && r.Path != "/token" {
			t.Errorf("a blocked migrate sent %s %s", r.Method, r.Path)
		}
	}
	if recordedMigration(t, dir) != nil {
		t.Error("a blocked migrate recorded the instance")
	}
}

// ADR 0023 M2.7 (A30-22; §10.5 row 94b): a provider's namespace is one whose
// name begins with kube-, gke- or gmp-. An application namespace that only
// contains them, which validNamespace and planck's translate allow, is
// farcast's: its Namespace object and a RoleBinding in it, each with
// kubectl's client-side trace, are the fact's objects and in no block.
func TestMigrateBlocksOnlyANamespaceThatStartsWithAProviderPrefix(t *testing.T) {
	const ns = "team-kube-gke-gmp-tools"
	_, dir := migrateFixture(t, func(s *kubetest.Server) {
		systemNamespace(s)
		s.Put(clientSideObject("v1", "Namespace", "", ns, "{}\n"))
		s.Put(clientSideObject("rbac.authorization.k8s.io/v1", "RoleBinding", ns, seededRoleBinding, "{}\n"))
	})
	_, b := migratePlan(t, dir)
	if len(b.Blocked) != 0 {
		t.Errorf("the plan's blocks are %+v; want none", b.Blocked)
	}
	if got, want := objectNames(migrateFactOf(t, b)), []string{"Namespace " + ns, "RoleBinding " + ns + "/" + seededRoleBinding}; !slices.Equal(got, want) {
		t.Errorf("the plan's objects are %q; want %q", got, want)
	}
}

// ADR 0023 M2.7 (A30-13, A30-22): a cluster-scoped object is named with no
// namespace and no slash: in the plan's rendering, in its block, and in the
// loop's errors. A ClusterRole to migrate that is deleted after the plan is
// named so in --confirm's plan_changed; and a ClusterRoleBinding farcast
// never writes, so in its block.
func TestMigrateNamesClusterScopedObjectsWithoutASlash(t *testing.T) {
	const rbac = "rbac.authorization.k8s.io/v1"
	rolePath := "/apis/" + rbac + "/clusterroles/farcast-reader"
	// The ClusterRole reads as deleted once a plan has listed it: a GET of it,
	// which only the loop's re-read makes, answers 404.
	s, dir := migrateFixture(t, func(s *kubetest.Server) {
		systemNamespace(s)
		s.Put(clientSideObject(rbac, "ClusterRole", "", "farcast-reader", "{}\n"))
	}, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.Method == http.MethodGet && r.Path == rolePath {
			return http.StatusNotFound, statusBody(http.StatusNotFound, "NotFound"), true
		}
		return 0, nil, false
	}))
	out, _, _, err := runMigrate(t, dir, output.ModeHuman, false, "", "--plan")
	if err != nil || !strings.Contains(out, "\n  ClusterRole farcast-reader ("+rbac+", uid ") {
		t.Errorf("migrate --plan: %v; the ClusterRole is not named alone:\n%s", err, out)
	}
	_, _, _, err = migrateConfirm(t, dir)
	want := "ClusterRole farcast-reader changed since the plan was made (another writer applied or deleted it); 0 of 1 objects were migrated and the rest were not; " + msgPlanAgain
	if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged {
		t.Errorf("migrate --confirm of a ClusterRole deleted after the plan = %v; want %q", err, want)
	}

	s.Put(clientSideObject(rbac, "ClusterRoleBinding", "", "someone-elses", "{}\n"))
	out, _, _, err = runMigrate(t, dir, output.ModeHuman, false, "", "--plan")
	if err != nil || !strings.HasPrefix(out, "blocked (internal): ClusterRoleBinding someone-elses carries farcast's label") {
		t.Errorf("migrate --plan: %v; the ClusterRoleBinding is not named alone:\n%s", err, out)
	}
}

// ADR 0023 M2.7 (design §6.2; §10.5 row 94): the label alone selects
// nothing. The key pin, which the pin's create left as farcast's Update,
// and the kernel's ledger and profiles, which its PUT and POST left as
// technocore's, carry farcast's label and no trace of kubectl's client-side
// apply: the plan lists only the ConfigMap kubectl applied, and the
// migration rewrites it alone, leaving the other three as they were.
func TestMigrationLeavesThePinAndTheKernelsConfigMaps(t *testing.T) {
	ns := tcdeploy.DefaultNamespace
	written := func(name, manager string) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{
			"name": name, "namespace": ns, "labels": map[string]any{"app.kubernetes.io/managed-by": "farcast"},
			"managedFields": []any{map[string]any{"manager": manager, "operation": "Update", "apiVersion": "v1", "time": "2026-11-01T09:00:00Z",
				"fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:data": map[string]any{".": map[string]any{}}}}},
		}, "data": map[string]any{"value": "kept"}}
	}
	kept := []string{"datasphered-pin", kernel.DefaultCheckpointName, kernel.DefaultProfilesName}
	s, dir := migrateFixture(t, func(s *kubetest.Server) {
		systemNamespace(s)
		s.Put(written("datasphered-pin", kube.FieldManager))
		s.Put(written(kernel.DefaultCheckpointName, "technocore"))
		s.Put(written(kernel.DefaultProfilesName, "technocore"))
		s.Put(clientSideObject("v1", "ConfigMap", ns, "fatline-egress-policy", "{}\n"))
	})
	rvs := map[string]string{}
	for _, name := range kept {
		rvs[name] = storedObject(t, dir, "v1", "ConfigMap", ns, name).Metadata.ResourceVersion
	}
	if _, b := migratePlan(t, dir); !slices.Equal(objectNames(migrateFactOf(t, b)), []string{"ConfigMap farcast-system/fatline-egress-policy"}) {
		t.Errorf("the plan's objects are %q; want the ConfigMap kubectl applied alone", objectNames(migrateFactOf(t, b)))
	}
	if _, errb, _, err := migrateConfirm(t, dir); err != nil {
		t.Fatalf("migrate --confirm: %v\n%s", err, errb)
	}
	for _, r := range s.Requests() {
		if r.Method == http.MethodPatch && r.Path != "/api/v1/namespaces/"+ns+"/configmaps/fatline-egress-policy" {
			t.Errorf("migrate patched %s", r.Path)
		}
	}
	for _, name := range kept {
		if got := storedObject(t, dir, "v1", "ConfigMap", ns, name).Metadata.ResourceVersion; got != rvs[name] {
			t.Errorf("ConfigMap %s moved from resourceVersion %s to %s", name, rvs[name], got)
		}
	}
	if recordedMigration(t, dir) == nil {
		t.Error("the migration was not recorded")
	}
}

// ADR 0023 M2.7 (design §6.2; §10.5 row 95): discovery is cluster-wide, so a
// RoleBinding kernel meter bound in a namespace farcast did not create, and
// nothing labels, is planned and migrated: each kind is listed across every
// namespace, by farcast's label, as the writer.
func TestMigrationFindsARoleBindingInAnUnlabelledNamespace(t *testing.T) {
	s, dir := migrateFixture(t, func(s *kubetest.Server) {
		systemNamespace(s)
		s.Put(clientSideObject("rbac.authorization.k8s.io/v1", "RoleBinding", writeNewNamespace, seededRoleBinding, "{}\n"))
	})
	if _, b := migratePlan(t, dir); !slices.Equal(objectNames(migrateFactOf(t, b)), []string{"RoleBinding extra/technocore"}) {
		t.Errorf("the plan's objects are %q; want the RoleBinding in extra", objectNames(migrateFactOf(t, b)))
	}
	var listed bool
	for _, r := range s.Requests() {
		if r.Method == http.MethodGet && r.Path == "/apis/rbac.authorization.k8s.io/v1/rolebindings" && strings.Contains(r.RawQuery, "labelSelector=app.kubernetes.io%2Fmanaged-by%3Dfarcast") {
			listed = r.As == "writer"
		}
		if strings.Contains(r.Path, "/namespaces/"+writeNewNamespace+"/") || r.Path == "/api/v1/namespaces/"+writeNewNamespace {
			t.Errorf("the plan read %s %s: discovery lists every namespace at once", r.Method, r.Path)
		}
	}
	if !listed {
		t.Error("the plan did not list RoleBindings across every namespace, by farcast's label, as the writer")
	}
	if _, errb, _, err := migrateConfirm(t, dir); err != nil {
		t.Fatalf("migrate --confirm: %v\n%s", err, errb)
	}
	if o := storedObject(t, dir, "rbac.authorization.k8s.io/v1", "RoleBinding", writeNewNamespace, seededRoleBinding); kube.ClientSideTrace(o.Metadata) {
		t.Errorf("the RoleBinding still carries kubectl's client-side apply: %+v", o.Metadata.ManagedFields)
	}
}

// changedSecret is the seeded Secret as it reads after the plan, changed by
// change, for a handler to answer its re-read with.
func changedSecret(change func(md map[string]any)) []byte {
	o := clientSideSecret()
	change(o["metadata"].(map[string]any))
	return objectBody(o)
}

// ADR 0023 M2.7 (A30-23; §10.5 row 99b): each object is read again before
// it is rewritten, and one whose uid, client-side managers or their fields'
// hash is not what the plan bound, the managers alone included (its entries
// all stripped, the annotation kept, among them), or which is gone, stops
// the run: under
// --confirm plan_changed, ending with the way to a new plan, and
// interactively internal; either way naming it, and how many of the plan's
// objects were migrated before it. Here the Secret, the first of three,
// changes, so none was; nothing is patched, and nothing is recorded. An
// entry of another manager, which the rewrite keeps, is not bound: one
// written after the plan changes nothing.
func TestMigrateConfirmRecomputesAndRefusesAChangedObject(t *testing.T) {
	ownsAnnotation := map[string]any{"f:metadata": map[string]any{"f:annotations": map[string]any{
		"f:" + lastAppliedAnnotation: map[string]any{}}}}
	for _, tc := range []struct {
		name   string
		status int
		body   []byte
	}{
		{"its uid", 0, changedSecret(func(md map[string]any) { md["uid"] = "00000000-0000-4000-8000-0000000000c3" })},
		{"its client-side managers", 0, changedSecret(func(md map[string]any) {
			md["managedFields"] = append(md["managedFields"].([]any), map[string]any{"manager": "kubectl-edit", "operation": "Update",
				"apiVersion": "v1", "time": "2026-11-02T09:00:00Z", "fieldsType": "FieldsV1", "fieldsV1": ownsAnnotation})
		})},
		{"their fields", 0, changedSecret(func(md map[string]any) {
			e := md["managedFields"].([]any)[0].(map[string]any)
			e["fieldsV1"].(map[string]any)["f:data"] = map[string]any{".": map[string]any{}, "f:key": map[string]any{}}
		})},
		// Planned with kubectl's entry, re-read with no entry and the
		// annotation: changed, never the remedy text of an object the plan
		// bound with the annotation alone, which is checked after this.
		{"its entries stripped, the annotation kept", 0, changedSecret(func(md map[string]any) { delete(md, "managedFields") })},
		{"gone", http.StatusNotFound, statusBody(http.StatusNotFound, "NotFound")},
	} {
		for _, interactive := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, interactive %v", tc.name, interactive), func(t *testing.T) {
				// The plan lists; only the loop reads the Secret by its path.
				s, dir := migrateFixture(t, clientSideSeeded, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
					if r.Method == http.MethodGet && r.Path == secretPath {
						return tc.status, tc.body, true
					}
					return 0, nil, false
				}))
				before := treeFiles(t, string(dir))
				var err error
				if interactive {
					_, _, _, err = runMigrate(t, dir, output.ModeJSON, true, writeName+"\n")
				} else {
					_, _, _, err = migrateConfirm(t, dir)
				}
				want := "Secret farcast-system/fatline-mtls changed since the plan was made (another writer applied or deleted it); 0 of 3 objects were migrated and the rest were not"
				kind := kindInternal
				if !interactive {
					want += "; " + msgPlanAgain
					kind = kindPlanChanged
				}
				if err == nil || err.Error() != want || kindOf(classified(err)) != kind {
					t.Errorf("migrate with the Secret changed (%s) = %v (kind %s); want %q, %s", tc.name, err, kindOf(classified(err)), want, kind)
				}
				for _, r := range s.Requests() {
					if r.Method == http.MethodPatch {
						t.Errorf("migrate patched %s after its plan changed", r.Path)
					}
				}
				sameFiles(t, "migrate whose plan changed", before, treeFiles(t, string(dir)))
			})
		}
	}

	// Another manager's entry, which the rewrite keeps and the plan binds no
	// hash of, written after the plan: the Secret's uid, client-side managers
	// and their fields are what the plan bound, so it is migrated.
	t.Run("another manager's entry", func(t *testing.T) {
		var srv atomic.Pointer[kubetest.Server]
		var labelled atomic.Bool
		s, dir := migrateFixture(t, clientSideSeeded, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
			if r.Method == http.MethodGet && r.Path == secretPath && !labelled.Swap(true) {
				o := clientSideSecret()
				md := o["metadata"].(map[string]any)
				md["labels"].(map[string]any)["team"] = "storage"
				md["managedFields"] = append(md["managedFields"].([]any), map[string]any{"manager": "kubectl-label", "operation": "Update",
					"apiVersion": "v1", "time": "2026-11-02T09:00:00Z", "fieldsType": "FieldsV1",
					"fieldsV1": map[string]any{"f:metadata": map[string]any{"f:labels": map[string]any{"f:team": map[string]any{}}}}})
				srv.Load().Put(o)
			}
			return 0, nil, false
		}))
		srv.Store(s)
		if out, errb, _, err := migrateConfirm(t, dir); err != nil || !labelled.Load() {
			t.Fatalf("migrate with another manager's entry written after the plan = %v (written %v), %q\n%s", err, labelled.Load(), out, errb)
		}
		o := storedObject(t, dir, "v1", "Secret", tcdeploy.DefaultNamespace, seededSecret)
		if kube.ClientSideTrace(o.Metadata) || !slices.ContainsFunc(o.Metadata.ManagedFields, func(e kube.ManagedFieldsEntry) bool { return e.Manager == "kubectl-label" }) {
			t.Errorf("the Secret's entries are %+v; want it migrated, kubectl-label's entry kept", o.Metadata.ManagedFields)
		}
	})

	// The second object changed: the first was migrated before it.
	t.Run("the second object, after the first", func(t *testing.T) {
		s, dir := migrateFixture(t, clientSideSeeded, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
			if r.Method == http.MethodGet && r.Path == deploymentPath {
				return http.StatusNotFound, statusBody(http.StatusNotFound, "NotFound"), true
			}
			return 0, nil, false
		}))
		_, _, _, err := migrateConfirm(t, dir)
		want := "Deployment farcast-system/fatline changed since the plan was made (another writer applied or deleted it); 1 of 3 objects were migrated and the rest were not; " + msgPlanAgain
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged {
			t.Errorf("migrate with the Deployment gone = %v; want %q", err, want)
		}
		if patchesTo(s, secretPath) != 1 || patchesTo(s, deploymentPath)+patchesTo(s, roleBindingPath) != 0 {
			t.Errorf("migrate patched the Secret %d times, and the rest %d; want the Secret once, and the rest never",
				patchesTo(s, secretPath), patchesTo(s, deploymentPath)+patchesTo(s, roleBindingPath))
		}
		if recordedMigration(t, dir) != nil {
			t.Error("a migration that stopped was recorded")
		}
	})

	// The client-side managers alone changed, their fields' hash the plan's:
	// an object planned with the annotation alone, re-read with
	// kubectl-client-side-apply's Update entry owning no field, which
	// ClientSideManagers names and which adds nothing to the hash. The set
	// refuses it, before any PATCH.
	t.Run("its client-side managers alone, the hash unchanged", func(t *testing.T) {
		const uid = "00000000-0000-4000-8000-0000000000d1"
		deployment := func(entry bool) map[string]any {
			o := clientSideObject("apps/v1", "Deployment", tcdeploy.DefaultNamespace, seededDeployment, `{"kind":"Deployment"}`+"\n")
			md := o["metadata"].(map[string]any)
			md["uid"] = uid
			delete(md, "managedFields")
			if entry {
				md["resourceVersion"] = "999"
				md["managedFields"] = []any{map[string]any{"manager": "kubectl-client-side-apply", "operation": "Update", "apiVersion": "apps/v1",
					"time": "2026-11-17T09:00:00Z"}}
			}
			return o
		}
		var reread atomic.Bool
		s, dir := migrateFixture(t, func(s *kubetest.Server) {
			systemNamespace(s)
			s.Put(deployment(false))
		}, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
			if !reread.Load() || r.Method != http.MethodGet || r.Path != deploymentPath {
				return 0, nil, false
			}
			return http.StatusOK, objectBody(deployment(true)), true
		}))
		doc, b := migratePlan(t, dir)
		if f := migrateFactOf(t, b); len(f.Objects) != 1 || len(f.Objects[0].CSAManagers) != 0 || !f.Objects[0].Annotation {
			t.Fatalf("the plan's objects are %+v; want the Deployment, its annotation alone", f.Objects)
		}
		reread.Store(true)
		_, errb, _, err := runMigrate(t, dir, output.ModeJSON, false, "", "--confirm", doc.Digest)
		want := "Deployment farcast-system/fatline changed since the plan was made (another writer applied or deleted it); 0 of 1 objects were migrated and the rest were not; " + msgPlanAgain
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged || patchesTo(s, deploymentPath) != 0 {
			t.Errorf("migrate --confirm over client-side managers changed under an unchanged hash = %v (kind %s), %d PATCHes\n%s; want %q, none",
				err, kindOf(classified(err)), patchesTo(s, deploymentPath), errb, want)
		}
		if recordedMigration(t, dir) != nil {
			t.Error("a migration whose plan changed was recorded")
		}
	})
}

// ADR 0023 M2.7 (A30-23; §10.5 row 99a): only a 409 is tried again, from the
// re-read, after 200 ms, five attempts in all. Four 409s then success
// migrate; five are cluster_rejected, naming the object and the 409, after
// exactly five PATCHes, each after a re-read; and a 503 stops the run after
// one PATCH, unretried. Nothing is recorded but by the run that finished.
func TestMigrateRetriesOnlyAConflictFiveTimes(t *testing.T) {
	deploymentOnly := func(s *kubetest.Server) {
		systemNamespace(s)
		s.Put(clientSideObject("apps/v1", "Deployment", tcdeploy.DefaultNamespace, seededDeployment, "{}\n"))
	}
	conflict := kube.Status{Status: tkube.Status{Reason: "Conflict"}}
	for _, tc := range []struct {
		name     string
		code     int
		times    int
		patches  int
		migrates bool
	}{
		{"four 409s, then success", http.StatusConflict, 4, 5, true},
		{"five 409s", http.StatusConflict, 5, 5, false},
		{"one 503", http.StatusServiceUnavailable, 1, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := migrateFixture(t, deploymentOnly)
			doc, _ := migratePlan(t, dir)
			for range tc.times {
				s.Fail(http.MethodPatch, deploymentPath, tc.code, conflict)
			}
			seen := len(s.Requests())
			_, errb, slept, err := runMigrate(t, dir, output.ModeJSON, false, "", "--confirm", doc.Digest)
			var patches, reads int
			for _, r := range s.Requests()[seen:] {
				switch {
				case r.Method == http.MethodPatch:
					patches++
					if reads != patches {
						t.Errorf("PATCH %d came after %d reads of the object; want each after its own re-read", patches, reads)
					}
				case r.Method == http.MethodGet && r.Path == deploymentPath && patches == reads:
					reads++
				}
			}
			if patches != tc.patches {
				t.Errorf("migrate sent %d PATCHes; want %d", patches, tc.patches)
			}
			wantSleeps := 0
			if tc.code == http.StatusConflict {
				wantSleeps = min(tc.times, migrateAttempts-1)
			}
			if len(slept) != wantSleeps || slices.ContainsFunc(slept, func(d time.Duration) bool { return d != 200*time.Millisecond }) {
				t.Errorf("migrate slept %v; want %d sleeps of 200ms", slept, wantSleeps)
			}
			if tc.migrates {
				if err != nil || recordedMigration(t, dir) == nil {
					t.Errorf("migrate after four 409s = %v, recorded %+v; want it migrated and recorded\n%s", err, recordedMigration(t, dir), errb)
				}
				return
			}
			prefix := "rewrite Deployment farcast-system/fatline: kube: PATCH " + deploymentPath + ": 503 "
			if tc.code == http.StatusConflict {
				prefix = "Deployment farcast-system/fatline kept changing while it was rewritten (5 attempts, each answered 409): kube: PATCH " + deploymentPath + ": 409 Conflict"
				if !errors.Is(err, tkube.ErrConflict) {
					t.Errorf("migrate after five 409s = %v; want the 409 wrapped", err)
				}
			}
			const suffix = "; 0 of 1 objects were migrated and the rest were not, and running migrate again finishes them"
			if err == nil || !strings.HasPrefix(err.Error(), prefix) || !strings.HasSuffix(err.Error(), suffix) || kindOf(classified(err)) != kindClusterRejected {
				t.Errorf("migrate = %v (kind %s); want %q…%q, cluster_rejected", err, kindOf(classified(err)), prefix, suffix)
			}
			if recordedMigration(t, dir) != nil {
				t.Error("a migration that stopped was recorded")
			}
		})
	}
}

// unchangedDeployment is the seeded Deployment as the server stored it,
// which a handler answers a PATCH with when the server kept the live list
// silently, and the annotation with it.
func unchangedDeployment() []byte {
	return objectBody(clientSideObject("apps/v1", "Deployment", tcdeploy.DefaultNamespace, seededDeployment, `{"kind":"Deployment"}`+"\n"))
}

// ADR 0023 M2.7 (design §6.3, §6.4; §10.5 row 96): the end state is checked
// on the rewrite's answer. A server that keeps the live list and the
// annotation, answering the PATCH with the object unchanged, is refused on
// that answer, cluster_rejected, naming the object and what is left of
// kubectl's client-side apply, before it is read back, and nothing after it
// is touched: the Secret before it was migrated, the RoleBinding after it
// never read or patched, and nothing recorded. And an object that had
// farcast's own Apply entry, and an annotation alone, must keep that entry:
// an answer without it is refused too (A30-8, hadApply read before the
// rewrite).
func TestMigrationRefusesASilentlyIgnoredRewrite(t *testing.T) {
	s, dir := migrateFixture(t, clientSideSeeded, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.Method == http.MethodPatch && r.Path == deploymentPath {
			return 0, unchangedDeployment(), true
		}
		return 0, nil, false
	}))
	doc, _ := migratePlan(t, dir)
	seen := len(s.Requests())
	_, _, _, err := runMigrate(t, dir, output.ModeJSON, false, "", "--confirm", doc.Digest)
	want := "Deployment farcast-system/fatline did not come back migrated (kubectl-client-side-apply/Update still present; " +
		"annotation kubectl.kubernetes.io/last-applied-configuration still present; farcast/Apply present 0 times, not once); nothing after it was touched"
	if err == nil || err.Error() != want || !errors.Is(err, kube.ErrNotMigrated) || kindOf(classified(err)) != kindClusterRejected {
		t.Errorf("migrate over a silently kept list = %v (kind %s); want %q, cluster_rejected", err, kindOf(classified(err)), want)
	}
	reqs := s.Requests()[seen:]
	last := slices.IndexFunc(reqs, func(r kubetest.Request) bool { return r.Method == http.MethodPatch && r.Path == deploymentPath })
	if last < 0 || last != len(reqs)-1 {
		t.Errorf("after the Deployment's PATCH (at %d of %d) migrate sent more; want it refused on the answer", last, len(reqs))
	}
	if patchesTo(s, secretPath) != 1 || slices.ContainsFunc(reqs, func(r kubetest.Request) bool { return r.Path == roleBindingPath }) {
		t.Errorf("migrate patched the Secret %d times, and touched the RoleBinding; want the Secret once, and the RoleBinding never", patchesTo(s, secretPath))
	}
	if recordedMigration(t, dir) != nil {
		t.Error("a migration that stopped was recorded")
	}

	t.Run("farcast's own Apply entry, dropped", func(t *testing.T) {
		const name = "annotated"
		path := "/apis/apps/v1/namespaces/" + tcdeploy.DefaultNamespace + "/deployments/" + name
		annotated := func(apply bool) map[string]any {
			o := clientSideObject("apps/v1", "Deployment", tcdeploy.DefaultNamespace, name, "{}\n")
			md := o["metadata"].(map[string]any)
			md["managedFields"] = []any{}
			if apply {
				md["managedFields"] = []any{map[string]any{"manager": kube.FieldManager, "operation": "Apply", "apiVersion": "apps/v1",
					"time": "2026-11-17T09:00:00Z", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}}}}
			} else {
				delete(md, "annotations")
			}
			return o
		}
		// The rewrite's answer, and every read of the object after it, show
		// neither the annotation nor farcast's Apply entry.
		var patched atomic.Bool
		_, dir := migrateFixture(t, func(s *kubetest.Server) {
			systemNamespace(s)
			s.Put(annotated(true))
		}, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
			if r.Path != path {
				return 0, nil, false
			}
			if r.Method == http.MethodPatch {
				patched.Store(true)
			}
			if patched.Load() {
				return 0, objectBody(annotated(false)), true
			}
			return 0, nil, false
		}))
		_, b := migratePlan(t, dir)
		if f := migrateFactOf(t, b); len(f.Objects) != 1 || len(f.Objects[0].CSAManagers) != 0 || !f.Objects[0].Annotation {
			t.Fatalf("the plan's fact is %+v; want the Deployment, its annotation alone", f)
		}
		_, _, _, err := migrateConfirm(t, dir)
		want := "Deployment farcast-system/annotated did not come back migrated (farcast/Apply present 0 times, not once); nothing after it was touched"
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindClusterRejected {
			t.Errorf("migrate over a dropped Apply entry = %v; want %q", err, want)
		}
		if recordedMigration(t, dir) != nil {
			t.Error("a migration that stopped was recorded")
		}
	})
}

// ADR 0023 M2.7 (A30-23, §6.3): an object that carries the last-applied
// annotation and no managed-fields entry, as one whose managedFields were
// reset by hand leaves it, cannot be rewritten: its rewrite would leave an
// empty list, which does not reset the field. It is planned, annotation
// alone, and never sent; every run stops at it, internal, naming it, how many
// objects were migrated before it, and the operator's remedy, never "running
// migrate again finishes them", with nothing recorded and no file deleted.
// Once the annotation is removed by hand, as the text says, nothing selects
// it, and migrate records the instance; removed between the plan and the
// loop's re-read, it is migrated with nothing sent.
func TestMigrateNamesTheRemedyForAnAnnotationWithNoEntries(t *testing.T) {
	const name = "stripped"
	path := "/api/v1/namespaces/" + tcdeploy.DefaultNamespace + "/configmaps/" + name
	stripped := func(annotated bool) map[string]any {
		o := clientSideObject("v1", "ConfigMap", tcdeploy.DefaultNamespace, name, "{}\n")
		md := o["metadata"].(map[string]any)
		md["managedFields"] = []any{}
		if !annotated {
			delete(md, "annotations")
		}
		return o
	}
	s, dir := migrateFixture(t, func(s *kubetest.Server) {
		systemNamespace(s)
		s.Put(stripped(true))
	})
	if _, b := migratePlan(t, dir); len(migrateFactOf(t, b).Objects) != 1 || len(migrateFactOf(t, b).Objects[0].CSAManagers) != 0 ||
		!migrateFactOf(t, b).Objects[0].Annotation {
		t.Fatalf("the plan's fact is %+v; want the ConfigMap, its annotation alone", migrateFactOf(t, b))
	}
	want := "ConfigMap farcast-system/stripped carries kubectl's last-applied annotation and no managed-fields entry, which migrate cannot rewrite " +
		"(an empty list does not reset the field); 0 of 1 objects were migrated and the rest were not, and running migrate again stops here: " +
		"remove its kubectl.kubernetes.io/last-applied-configuration annotation from Cloud Shell, then run 'farcast migrate atlas --plan' again"
	for run := 1; run <= 2; run++ {
		_, errb, _, err := migrateConfirm(t, dir)
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal {
			t.Fatalf("migrate --confirm, run %d, over an annotation with no entries = %v (kind %s)\n%s\nwant %q, internal", run, err, kindOf(classified(err)), errb, want)
		}
		if patchesTo(s, path) != 0 || recordedMigration(t, dir) != nil || !legacyFile(t, dir, "kubeconfig.yaml") {
			t.Errorf("run %d patched the ConfigMap %d times, recorded %+v, or deleted kubeconfig.yaml", run, patchesTo(s, path), recordedMigration(t, dir))
		}
	}
	if _, _, _, err := runMigrate(t, dir, output.ModeJSON, true, writeName+"\n"); err == nil || err.Error() != want {
		t.Errorf("an interactive migrate over an annotation with no entries = %v; want %q", err, want)
	}

	s.Put(stripped(false))
	if _, errb, _, err := migrateConfirm(t, dir); err != nil || recordedMigration(t, dir) == nil || patchesTo(s, path) != 0 {
		t.Errorf("migrate --confirm once the annotation is removed = %v, recorded %+v, %d PATCHes\n%s; want it recorded, nothing sent", err, recordedMigration(t, dir), patchesTo(s, path), errb)
	}

	// The annotation removed after --confirm's discovery and before the
	// loop reads the ConfigMap again, its uid kept: the re-read has neither
	// annotation nor entry, which is what the plan bound of its managers, so
	// nothing is left to rewrite. It is migrated with nothing sent and the
	// instance recorded, never refused with a text that says it still
	// carries the annotation. Only the loop reads it by its path, so the
	// handler removes it there, once.
	t.Run("the annotation removed before the re-read", func(t *testing.T) {
		const uid = "00000000-0000-4000-8000-0000000000e1"
		kept := func(annotated bool) map[string]any {
			o := stripped(annotated)
			o["metadata"].(map[string]any)["uid"] = uid
			return o
		}
		var srv atomic.Pointer[kubetest.Server]
		var removed atomic.Bool
		s, dir := migrateFixture(t, func(s *kubetest.Server) {
			systemNamespace(s)
			s.Put(kept(true))
		}, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
			if r.Method == http.MethodGet && r.Path == path && !removed.Swap(true) {
				srv.Load().Put(kept(false))
			}
			return 0, nil, false
		}))
		srv.Store(s)
		if _, b := migratePlan(t, dir); len(migrateFactOf(t, b).Objects) != 1 || !migrateFactOf(t, b).Objects[0].Annotation || removed.Load() {
			t.Fatalf("the plan's fact is %+v (read by its path: %v); want the ConfigMap, its annotation alone, listed only", migrateFactOf(t, b), removed.Load())
		}
		_, errb, _, err := migrateConfirm(t, dir)
		if err != nil || !removed.Load() || recordedMigration(t, dir) == nil || patchesTo(s, path) != 0 {
			t.Errorf("migrate --confirm, the annotation removed before the re-read = %v (removed %v), recorded %+v, %d PATCHes\n%s; want it recorded, nothing sent",
				err, removed.Load(), recordedMigration(t, dir), patchesTo(s, path), errb)
		}
	})
}

// migratedLooking is the seeded Deployment as a migration would leave it:
// farcast's Apply entry, owning the label, and no annotation. A handler
// answers a PATCH with it while the store keeps kubectl's.
func migratedLooking() []byte {
	return objectBody(map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": map[string]any{
		"name": seededDeployment, "namespace": tcdeploy.DefaultNamespace,
		"labels": map[string]any{"app.kubernetes.io/managed-by": "farcast"},
		"managedFields": []any{map[string]any{"manager": kube.FieldManager, "operation": "Apply", "apiVersion": "apps/v1",
			"time": "2026-11-01T09:00:00Z", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:metadata": map[string]any{
				"f:labels": map[string]any{".": map[string]any{}, "f:app.kubernetes.io/managed-by": map[string]any{}}}}}},
	}})
}

// ADR 0023 M2.7 (design §6.4; §10.5 row 96a): an answer that looks migrated
// is not taken on trust. The PATCH is answered with the object migrated,
// while the store keeps kubectl's entry and the annotation; only the fresh
// read after it refuses, cluster_rejected, naming what is left, and nothing
// is recorded.
func TestMigrationReadsBackAfterAnAnswerThatLooksMigrated(t *testing.T) {
	s, dir := migrateFixture(t, clientSideSeeded, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.Method == http.MethodPatch && r.Path == deploymentPath {
			return 0, migratedLooking(), true
		}
		return 0, nil, false
	}))
	doc, _ := migratePlan(t, dir)
	seen := len(s.Requests())
	_, _, _, err := runMigrate(t, dir, output.ModeJSON, false, "", "--confirm", doc.Digest)
	want := "Deployment farcast-system/fatline did not come back migrated (kubectl-client-side-apply/Update still present; " +
		"annotation kubectl.kubernetes.io/last-applied-configuration still present; farcast/Apply present 0 times, not once); nothing after it was touched"
	if err == nil || err.Error() != want || kindOf(classified(err)) != kindClusterRejected {
		t.Errorf("migrate over an answer that looks migrated = %v; want %q", err, want)
	}
	reqs := s.Requests()[seen:]
	at := slices.IndexFunc(reqs, func(r kubetest.Request) bool { return r.Method == http.MethodPatch && r.Path == deploymentPath })
	if at < 0 || at+1 >= len(reqs) || reqs[at+1].Method != http.MethodGet || reqs[at+1].Path != deploymentPath || at+2 != len(reqs) {
		t.Errorf("after the Deployment's PATCH migrate sent %d requests; want its read back alone", len(reqs)-at-1)
	}
	if recordedMigration(t, dir) != nil {
		t.Error("a migration whose read-back refused was recorded")
	}
}

// ADR 0023 M2.7 (design §6.4; §10.5 row 97): the instance is recorded only
// once every object is verified. The second of three PATCHes refused stops
// the run, naming how many were migrated: the first object is migrated, the
// others are not, nothing is recorded and no local file deleted. A second
// run plans the two left, and finishes, records and deletes.
func TestMigrationRecordsOnlyWhenEveryObjectIsDone(t *testing.T) {
	s, dir := migrateFixture(t, clientSideSeeded)
	doc, _ := migratePlan(t, dir)
	s.Fail(http.MethodPatch, deploymentPath, http.StatusInternalServerError, kube.Status{})
	_, _, _, err := runMigrate(t, dir, output.ModeJSON, false, "", "--confirm", doc.Digest)
	const suffix = "; 1 of 3 objects were migrated and the rest were not, and running migrate again finishes them"
	if err == nil || !strings.HasPrefix(err.Error(), "rewrite Deployment farcast-system/fatline: ") || !strings.HasSuffix(err.Error(), suffix) ||
		kindOf(classified(err)) != kindClusterRejected {
		t.Fatalf("migrate with its second PATCH refused = %v; want the rewrite's failure%s", err, suffix)
	}
	if recordedMigration(t, dir) != nil || !legacyFile(t, dir, "kubeconfig.yaml") {
		t.Errorf("a migration that stopped recorded %+v, or deleted kubeconfig.yaml", recordedMigration(t, dir))
	}
	for _, o := range []struct {
		api, kind, ns, name string
		migrated            bool
	}{
		{"v1", "Secret", tcdeploy.DefaultNamespace, seededSecret, true},
		{"apps/v1", "Deployment", tcdeploy.DefaultNamespace, seededDeployment, false},
		{"rbac.authorization.k8s.io/v1", "RoleBinding", writeNewNamespace, seededRoleBinding, false},
	} {
		if got := !kube.ClientSideTrace(storedObject(t, dir, o.api, o.kind, o.ns, o.name).Metadata); got != o.migrated {
			t.Errorf("%s %s/%s migrated: %v, want %v", o.kind, o.ns, o.name, got, o.migrated)
		}
	}

	_, b := migratePlan(t, dir)
	if got := objectNames(migrateFactOf(t, b)); !slices.Equal(got, []string{"Deployment farcast-system/fatline", "RoleBinding extra/technocore"}) {
		t.Errorf("the second plan's objects are %q; want the two left", got)
	}
	out, errb, _, err := migrateConfirm(t, dir)
	if err != nil {
		t.Fatalf("the second migrate: %v\n%s", err, errb)
	}
	var r migrateResult
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Migrated != 2 {
		t.Errorf("the second migrate printed %q; want 2 objects migrated", out)
	}
	if recordedMigration(t, dir) == nil || legacyFile(t, dir, "kubeconfig.yaml") {
		t.Errorf("the finished migration recorded %+v, kubeconfig.yaml there: %v", recordedMigration(t, dir), legacyFile(t, dir, "kubeconfig.yaml"))
	}
}

// fakeMigrateCluster is a writer that answers migrate's discovery from raw
// objects, as a server sends them, data and the last-applied annotation's
// value included, decoded into kube.Object as the cluster client decodes an
// answer; it reads nothing else and writes nothing. Unlike the cluster
// client, it does not empty the annotation's value: what migrate binds of an
// object must hold none of it whichever writer read it.
type fakeMigrateCluster struct {
	uid     string
	objects map[string][]map[string]any // by kind
}

func (f fakeMigrateCluster) NamespaceUID(context.Context, string) (string, error) { return f.uid, nil }

func (f fakeMigrateCluster) ListMeta(_ context.Context, k kube.Kind, namespace, selector string) ([]kube.Object, error) {
	if namespace != "" || selector != managedSelector {
		return nil, fmt.Errorf("test: migrate listed %s in %q by %q; want every namespace, by farcast's label", k.Resource, namespace, selector)
	}
	var out []kube.Object
	for _, obj := range f.objects[k.Kind] {
		var o kube.Object
		if err := json.Unmarshal(objectBody(obj), &o); err != nil {
			return nil, err
		}
		o.Kind = k
		out = append(out, o)
	}
	return out, nil
}

func (fakeMigrateCluster) GetMeta(context.Context, kube.Kind, string, string) (kube.Object, error) {
	return kube.Object{}, errors.New("test: a plan read an object again")
}

func (fakeMigrateCluster) PatchManagedFields(context.Context, kube.Kind, string, string, []byte) (kube.Object, error) {
	return kube.Object{}, errors.New("test: a plan rewrote an object")
}

// markerForms is migrateMarker as it could reach a text: raw, and in base64.
func markerForms() []string {
	return []string{migrateMarker, base64.StdEncoding.EncodeToString([]byte(migrateMarker)), base64.RawStdEncoding.EncodeToString([]byte(migrateMarker))}
}

// ADR 0023 M2.7 (design §6.4; §10.5 row 98): the annotation is a boolean.
// A Secret whose data and last-applied annotation hold a marker is planned
// with no byte of it, in the plan's JSON and in its rendering, whether the
// writer that read it is the cluster client, which empties the annotation's
// value, or one that hands it on as the server sent it. And when its
// rewrite's answer keeps the annotation, the marker in it, the refusal, the
// human output and the -o json envelope carry none of it either.
func TestMigratePlanCarriesNoSecretByte(t *testing.T) {
	noMarker := func(t *testing.T, what, text string) {
		t.Helper()
		for _, form := range markerForms() {
			if strings.Contains(text, form) {
				t.Errorf("%s carries the marker, as %q:\n%s", what, form, text)
			}
		}
	}
	plans := func(t *testing.T, dir config.Dir) {
		t.Helper()
		for _, mode := range []output.Mode{output.ModeJSON, output.ModeHuman} {
			c := withFlags(t, &migrateCommand{}, "--plan")
			c.newCluster = func(clusterRef) (migrateCluster, error) {
				return fakeMigrateCluster{uid: vectorSystemUID, objects: map[string][]map[string]any{"Secret": {clientSideSecret()}}}, nil
			}
			env, out, errb := testEnvBoth(dir, mode)
			if err := c.Run(t.Context(), env, []string{writeName}); err != nil {
				t.Fatalf("migrate --plan: %v", err)
			}
			if !strings.Contains(out.String(), seededSecret) {
				t.Fatalf("the plan does not name the Secret:\n%s", out)
			}
			noMarker(t, "the plan through a writer that hands the annotation on", out.String()+errb.String())
		}
	}

	s, dir := migrateFixture(t, clientSideSeeded, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.Method == http.MethodPatch && r.Path == secretPath {
			return 0, objectBody(clientSideSecret()), true
		}
		return 0, nil, false
	}))
	plans(t, dir)
	doc, _ := migratePlan(t, dir)
	noMarker(t, "the plan's JSON", string(doc.Bound))
	out, errb, _, err := runMigrate(t, dir, output.ModeHuman, false, "", "--plan")
	if err != nil || !strings.Contains(out, "Secret farcast-system/fatline-mtls (v1, uid "+seededSecretUID+")") {
		t.Fatalf("migrate --plan: %v\n%s", err, out)
	}
	noMarker(t, "the plan's rendering", out+errb)

	env, jsonOut, jsonErr := testEnvBoth(dir, output.ModeJSON)
	c := withFlags(t, &migrateCommand{}, "--confirm", doc.Digest)
	err = c.Run(t.Context(), env, []string{writeName})
	if !errors.Is(err, kube.ErrNotMigrated) || !strings.HasPrefix(err.Error(), "Secret farcast-system/fatline-mtls did not come back migrated (") {
		t.Fatalf("migrate --confirm over a kept annotation = %v; want the Secret not migrated", err)
	}
	env.Printer.PrintError(classified(err), exitCodeOf(err))
	noMarker(t, "the refusal", err.Error())
	noMarker(t, "the -o json envelope", jsonOut.String()+jsonErr.String())
	if !strings.Contains(jsonOut.String()+jsonErr.String(), `"cluster_rejected"`) {
		t.Errorf("the envelope does not carry the refusal's kind:\n%s%s", jsonOut, jsonErr)
	}
	_, errb, _, err = runMigrate(t, dir, output.ModeHuman, true, writeName+"\n")
	if !errors.Is(err, kube.ErrNotMigrated) {
		t.Fatalf("an interactive migrate over a kept annotation = %v", err)
	}
	noMarker(t, "the interactive run's output", errb+err.Error())
	if got := patchesTo(s, secretPath); got != 2 {
		t.Errorf("the Secret was patched %d times; want once a run", got)
	}

	// The plan vector, made over a Secret whose data and annotation hold the
	// marker (vectorMigrateCluster), holds none of it.
	vector, err := os.ReadFile(filepath.Join("testdata", "plan", "migrate.json"))
	if err != nil {
		t.Fatal(err)
	}
	noMarker(t, "testdata/plan/migrate.json", string(vector))
}

// ADR 0023 M2.7 (A30-12, A31-8): the plan binds each object as discovery
// read it. A Deployment with kubectl-client-side-apply's entry and no
// last-applied annotation, as an undecodable rewrite leaves one, is bound
// with its annotation absent; and an entry the rewrite keeps is bound with
// its subresource, so the status writer of a Deployment is
// kube-controller-manager/Update/status.
func TestMigratePlanBindsEachObjectAsDiscoveryReadIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(md map[string]any)
		check func(o plan.MigrateObject) bool
	}{
		{"no annotation", func(md map[string]any) { delete(md, "annotations") },
			func(o plan.MigrateObject) bool {
				return !o.Annotation && slices.Equal(o.CSAManagers, []string{"kubectl-client-side-apply"})
			}},
		{"a status writer", func(md map[string]any) {
			md["managedFields"] = append(md["managedFields"].([]any), map[string]any{
				"manager": "kube-controller-manager", "operation": "Update", "apiVersion": "apps/v1", "subresource": "status",
				"time": "2026-11-01T09:00:00Z", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:status": map[string]any{}},
			})
		}, func(o plan.MigrateObject) bool {
			return o.Annotation && slices.Equal(o.OtherManagers, []string{"kube-controller-manager/Update/status"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, dir := migrateFixture(t, func(s *kubetest.Server) {
				systemNamespace(s)
				o := clientSideObject("apps/v1", "Deployment", tcdeploy.DefaultNamespace, seededDeployment, `{"kind":"Deployment"}`+"\n")
				tc.edit(o["metadata"].(map[string]any))
				s.Put(o)
			})
			_, b := migratePlan(t, dir)
			if f := migrateFactOf(t, b); len(f.Objects) != 1 || !tc.check(f.Objects[0]) {
				t.Errorf("the plan's objects are %+v", f.Objects)
			}
		})
	}
}

// ADR 0023 M2.7 (A30-24; §10.5 row 97a): every object verified, discovery
// runs again, and the instance is recorded only when it selects nothing. A
// trace written during the migration, here put back on the migrated
// Deployment before the last lists, stops the run, naming it: under
// --confirm plan_changed, interactively internal. Nothing is recorded and
// no local file deleted.
func TestMigrateRecordsOnlyAfterAFreshDiscoverySelectsNothing(t *testing.T) {
	traced := objectBody(map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadataList",
		"metadata": map[string]any{"resourceVersion": "999"},
		"items": []any{map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": map[string]any{
			"name": seededDeployment, "namespace": tcdeploy.DefaultNamespace, "uid": "00000000-0000-4000-8000-0000000000d4",
			"labels":      map[string]any{"app.kubernetes.io/managed-by": "farcast"},
			"annotations": map[string]any{lastAppliedAnnotation: "{}\n"},
		}}}})
	for _, interactive := range []bool{false, true} {
		t.Run(fmt.Sprintf("interactive %v", interactive), func(t *testing.T) {
			var patched atomic.Bool
			_, dir := migrateFixture(t, func(s *kubetest.Server) {
				systemNamespace(s)
				s.Put(clientSideObject("apps/v1", "Deployment", tcdeploy.DefaultNamespace, seededDeployment, "{}\n"))
			}, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
				switch {
				case r.Method == http.MethodPatch:
					patched.Store(true)
				case r.Method == http.MethodGet && r.Path == "/apis/apps/v1/deployments" && patched.Load():
					return 0, traced, true
				}
				return 0, nil, false
			}))
			var err error
			if interactive {
				_, _, _, err = runMigrate(t, dir, output.ModeJSON, true, writeName+"\n")
			} else {
				_, _, _, err = migrateConfirm(t, dir)
			}
			want := "after 1 of 1 objects were migrated, Deployment farcast-system/fatline still carries kubectl's client-side apply (written during the migration); nothing was recorded"
			kind := kindInternal
			if !interactive {
				want += "; " + msgPlanAgain
				kind = kindPlanChanged
			}
			if !patched.Load() || err == nil || err.Error() != want || kindOf(classified(err)) != kind {
				t.Errorf("migrate with a trace put back = %v (kind %s, patched %v); want %q, %s", err, kindOf(classified(err)), patched.Load(), want, kind)
			}
			if recordedMigration(t, dir) != nil || !legacyFile(t, dir, "kubeconfig.yaml") {
				t.Errorf("migrate recorded %+v, or deleted kubeconfig.yaml, with a trace left", recordedMigration(t, dir))
			}
		})
	}
}

// ADR 0023 M2.7 (A30-24): the fresh discovery must run, and select
// nothing, before the record is written. One whose first list is answered
// 500, once every object is migrated, stops the run, saying so and that a
// second run records the instance: nothing is recorded and no local file
// deleted.
func TestMigrateRecordsNothingWhenItsFreshDiscoveryFails(t *testing.T) {
	var patched atomic.Bool
	_, dir := migrateFixture(t, clientSideSeeded, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		switch {
		case r.Method == http.MethodPatch:
			patched.Store(true)
		case patched.Load() && r.Method == http.MethodGet && r.Path == "/api/v1/namespaces":
			return http.StatusInternalServerError, statusBody(http.StatusInternalServerError, "InternalError"), true
		}
		return 0, nil, false
	}))
	_, errb, _, err := migrateConfirm(t, dir)
	if !patched.Load() || err == nil || !strings.HasPrefix(err.Error(), "after 3 of 3 objects were migrated, list the cluster's namespaces: ") ||
		!strings.HasSuffix(err.Error(), "; nothing was recorded, and running migrate again records it") {
		t.Errorf("migrate whose fresh discovery failed = %v (patched %v)\n%s; want the discovery's failure, nothing recorded", err, patched.Load(), errb)
	}
	if recordedMigration(t, dir) != nil || !legacyFile(t, dir, "kubeconfig.yaml") {
		t.Errorf("migrate whose fresh discovery failed recorded %+v, or deleted kubeconfig.yaml", recordedMigration(t, dir))
	}
}

// writePluginCache writes the GKE auth plugin's token cache beside the
// fixture's kubeconfig.yaml, as kubectl left it.
func writePluginCache(t *testing.T, dir config.Dir) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir.InstancePath(writeName), "gke_gcloud_auth_plugin_cache"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ADR 0023 M2.7 (design §6.4, A30-14, A30-24): once recorded, migrate deletes
// the files kubectl read and left beside the record, kubeconfig.yaml and the
// auth plugin's cache, and says so. The plan, read through migrate's plan
// row, lists them and touches nothing; --confirm, through the writer farcast
// opens (realWriter), records server_side_apply with since its clock's now,
// in UTC, and farcast this build's version, deletes both, and prints the
// result. A file it cannot delete is a warning on stderr, never a failure,
// and is not listed as deleted; and a record that cannot be written deletes
// nothing.
func TestMigrateRecordsAndDeletesTheLocalFiles(t *testing.T) {
	row := planCommandNamed(t, "migrate", "objects to migrate")
	_, dir := planFixture(t, row)
	writePluginCache(t, dir)
	before := treeFiles(t, string(dir))
	doc, _ := runPlan(t, dir, row, output.ModeJSON)
	runPlan(t, dir, row, output.ModeHuman)
	sameFiles(t, "migrate --plan", before, treeFiles(t, string(dir)))
	local := []string{"instances/atlas/kubeconfig.yaml", "instances/atlas/gke_gcloud_auth_plugin_cache"}
	if got := migrateFactOf(t, decodedBound(t, doc)).Local; !slices.Equal(got, local) {
		t.Errorf("the plan's local files are %q; want %q", got, local)
	}

	cmd := realWriter(t, withFlags(t, row.cmd(), "--confirm", doc.Digest)).(*migrateCommand)
	cmd.now = func() time.Time { return planNow.In(time.FixedZone("east", 5*3600)) }
	env, out, errb := testEnvBoth(dir, output.ModeJSON)
	if err := cmd.Run(t.Context(), env, row.args); err != nil {
		t.Fatalf("migrate --confirm: %v\n%s", err, errb)
	}
	got := recordedMigration(t, dir)
	if got == nil || !got.Since.Equal(planNow) || got.Since.Location() != time.UTC || got.Farcast != buildinfo.Get().Version {
		t.Errorf("recorded %+v; want since %s, in UTC, by %q", got, planNow, buildinfo.Get().Version)
	}
	for _, f := range []string{"kubeconfig.yaml", "gke_gcloud_auth_plugin_cache"} {
		if legacyFile(t, dir, f) {
			t.Errorf("%s is still there", f)
		}
	}
	var r migrateResult
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("the result does not decode: %v\n%s", err, out)
	}
	if want := (migrateResult{Instance: writeName, Migrated: 3, Since: "2026-11-16T10:00:00Z", LocalDeleted: local}); !sameResult(r, want) {
		t.Errorf("printed %+v; want %+v", r, want)
	}
	if errb.Len() != 0 {
		t.Errorf("migrate --confirm said %q", errb)
	}

	t.Run("its human form", func(t *testing.T) {
		var w bytes.Buffer
		if err := (migrateResult{Instance: writeName, Migrated: 3, Since: "2026-11-16T10:00:00Z", LocalDeleted: local}).Human(&w); err != nil {
			t.Fatal(err)
		}
		want := "Migrated 3 object(s) of instance atlas to server-side apply; recorded since 2026-11-16T10:00:00Z.\n" +
			"Deleted instances/atlas/kubeconfig.yaml.\nDeleted instances/atlas/gke_gcloud_auth_plugin_cache.\n"
		if w.String() != want {
			t.Errorf("the human form is\n%s\nwant\n%s", w.String(), want)
		}
	})

	t.Run("a file it cannot delete", func(t *testing.T) {
		_, dir := migrateFixture(t, clientSideSeeded)
		// A directory that is not empty, where the plugin's cache would be.
		cache := filepath.Join(dir.InstancePath(writeName), "gke_gcloud_auth_plugin_cache")
		if err := os.Mkdir(cache, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cache, "kept"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		out, errb, _, err := migrateConfirm(t, dir)
		if err != nil {
			t.Fatalf("migrate --confirm with a file it cannot delete: %v\n%s", err, errb)
		}
		var r migrateResult
		if err := json.Unmarshal([]byte(out), &r); err != nil || !slices.Equal(r.LocalDeleted, []string{"instances/atlas/kubeconfig.yaml"}) {
			t.Errorf("printed %q; want kubeconfig.yaml alone deleted", out)
		}
		if !strings.HasPrefix(errb, "Warning: could not delete instances/atlas/gke_gcloud_auth_plugin_cache (") ||
			!strings.HasSuffix(errb, "); nothing reads it\n") || strings.Contains(errb, string(dir)) {
			t.Errorf("migrate warned %q; want the file named relative to the config directory, and why", errb)
		}
		if recordedMigration(t, dir) == nil {
			t.Error("a file it could not delete stopped the record")
		}
	})

	t.Run("a record it cannot write", func(t *testing.T) {
		// Once the Deployment is rewritten, the last list of the fresh
		// discovery leaves metadata.yaml unreadable.
		var patched atomic.Bool
		var record atomic.Pointer[string]
		_, dir := migrateFixture(t, func(s *kubetest.Server) {
			systemNamespace(s)
			s.Put(clientSideObject("apps/v1", "Deployment", tcdeploy.DefaultNamespace, seededDeployment, "{}\n"))
		}, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
			switch {
			case r.Method == http.MethodPatch:
				patched.Store(true)
			case r.Path == "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" && patched.Load():
				if p := record.Load(); p != nil {
					if err := os.WriteFile(*p, []byte("not: [valid\n"), 0o600); err != nil {
						return http.StatusInternalServerError, statusBody(http.StatusInternalServerError, "InternalError"), true
					}
				}
			}
			return 0, nil, false
		}))
		path := filepath.Join(dir.InstancePath(writeName), "metadata.yaml")
		doc, _ := migratePlan(t, dir)
		record.Store(&path)
		_, _, _, err := runMigrate(t, dir, output.ModeJSON, false, "", "--confirm", doc.Digest)
		if err == nil || !strings.HasPrefix(err.Error(), `record instance "atlas" as migrated to server-side apply: `) {
			t.Errorf("migrate with its record unwritable = %v; want the record's failure", err)
		}
		if !legacyFile(t, dir, "kubeconfig.yaml") {
			t.Error("migrate deleted kubeconfig.yaml with nothing recorded")
		}
	})
}

// sameResult compares two results field by field.
func sameResult(a, b migrateResult) bool {
	return a.Instance == b.Instance && a.Migrated == b.Migrated && a.Since == b.Since && slices.Equal(a.LocalDeleted, b.LocalDeleted)
}

// ADR 0023 M2.7 (A30-21, A30-24; §10.5 row 97c): on an instance already
// recorded as migrated, since is kept. Migrating what another farcast or
// kubectl wrote since records this farcast's version and the first since;
// and an interactive run with nothing to migrate and no local file asks
// nothing, prints the record's since, and writes nothing.
func TestMigrateOnAMigratedRecordKeepsSince(t *testing.T) {
	since := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC) // recordMigrated's
	t.Run("objects to migrate", func(t *testing.T) {
		s := kubetest.New(t)
		clientSideSeeded(s)
		dir, _ := writeInstance(t, s, true)
		if got := recordedMigration(t, dir); got == nil || !got.Since.Equal(since) {
			t.Fatalf("the fixture records %+v; want since %s", got, since)
		}
		out, errb, _, err := migrateConfirm(t, dir)
		if err != nil {
			t.Fatalf("migrate --confirm: %v\n%s", err, errb)
		}
		got := recordedMigration(t, dir)
		if got == nil || !got.Since.Equal(since) || got.Farcast != buildinfo.Get().Version {
			t.Errorf("recorded %+v; want since %s kept, by %q", got, since, buildinfo.Get().Version)
		}
		var r migrateResult
		if err := json.Unmarshal([]byte(out), &r); err != nil || r.Since != "2026-11-18T09:00:00Z" || r.Migrated != 3 {
			t.Errorf("printed %q; want 3 objects migrated, since 2026-11-18T09:00:00Z", out)
		}
	})
	t.Run("nothing to do, interactively", func(t *testing.T) {
		s := kubetest.New(t)
		systemNamespace(s)
		dir, _ := writeInstance(t, s, true)
		if err := os.Remove(filepath.Join(dir.InstancePath(writeName), "kubeconfig.yaml")); err != nil {
			t.Fatal(err)
		}
		before := treeFiles(t, string(dir))
		c := &migrateCommand{interactive: func(*Env) bool { return true }}
		env, stdout, stderr := testEnvBoth(dir, output.ModeHuman)
		err := c.Run(t.Context(), env, []string{writeName})
		out, errb := stdout.String(), stderr.String()
		if err != nil || errb != "" || out != "Migrated 0 object(s) of instance atlas to server-side apply; recorded since 2026-11-18T09:00:00Z.\n" {
			t.Errorf("migrate with nothing to do = %v, %q %q; want the record's since, unasked", err, out, errb)
		}
		for _, r := range s.Requests() {
			if r.Method != http.MethodGet && r.Path != "/token" {
				t.Errorf("migrate with nothing to do sent %s %s", r.Method, r.Path)
			}
		}
		sameFiles(t, "migrate with nothing to do", before, treeFiles(t, string(dir)))
	})
	// A legacy file left beside a migrated record, as a run that could not
	// delete it leaves it, is no nothing-to-do: the plan lists it, the name
	// is asked for, and the file is deleted, since kept.
	t.Run("a legacy file left, interactively", func(t *testing.T) {
		s := kubetest.New(t)
		systemNamespace(s)
		dir, _ := writeInstance(t, s, true)
		if !legacyFile(t, dir, "kubeconfig.yaml") {
			t.Fatal("the fixture holds no kubeconfig.yaml")
		}
		out, errb, _, err := runMigrate(t, dir, output.ModeHuman, true, writeName+"\n")
		if err != nil || !strings.Contains(errb, msgMigratePrompt+": ") {
			t.Fatalf("migrate of a migrated record with kubeconfig.yaml left = %v\n%s; want it asked", err, errb)
		}
		if legacyFile(t, dir, "kubeconfig.yaml") || out != "Migrated 0 object(s) of instance atlas to server-side apply; recorded since 2026-11-18T09:00:00Z.\n"+
			"Deleted instances/atlas/kubeconfig.yaml.\n" {
			t.Errorf("migrate of a migrated record with kubeconfig.yaml left printed %q, the file there: %v; want it deleted, since kept", out, legacyFile(t, dir, "kubeconfig.yaml"))
		}
		if got := recordedMigration(t, dir); got == nil || !got.Since.Equal(since) {
			t.Errorf("recorded %+v; want since %s kept", got, since)
		}
	})
}

// ADR 0023 M2.7 (A30-21, A30-25): nothing to rewrite is nothing to do only
// for a record already migrated. An unmigrated instance whose cluster
// carries no trace of kubectl's client-side apply, as install leaves a
// cluster it adopted that no older farcast wrote, and no local file: an
// interactive run shows the plan, asks for the name, patches nothing, and
// records the instance since the migration's time.
func TestMigrateRecordsAnUnmigratedInstanceWithNothingToRewrite(t *testing.T) {
	s, dir := migrateFixture(t, systemNamespace)
	if err := os.Remove(filepath.Join(dir.InstancePath(writeName), "kubeconfig.yaml")); err != nil {
		t.Fatal(err)
	}
	out, errb, _, err := runMigrate(t, dir, output.ModeHuman, true, writeName+"\n")
	if err != nil || !strings.Contains(errb, msgMigratePrompt+": ") {
		t.Fatalf("migrate of an unmigrated instance with nothing to rewrite = %v\n%s; want it asked", err, errb)
	}
	if got := recordedMigration(t, dir); got == nil || !got.Since.Equal(planNow) ||
		out != "Migrated 0 object(s) of instance atlas to server-side apply; recorded since 2026-11-16T10:00:00Z.\n" {
		t.Errorf("migrate of an unmigrated instance with nothing to rewrite printed %q, recorded %+v; want it recorded since %s", out, got, planNow)
	}
	for _, r := range s.Requests() {
		if r.Method != http.MethodGet && r.Path != "/token" {
			t.Errorf("migrate with nothing to rewrite sent %s %s", r.Method, r.Path)
		}
	}
}

// msgTraceLeftOf is afterWrites' Warning for one object of writeName's
// instance, as it prints it (design §6.6).
func msgTraceLeftOf(object string) string {
	return "Warning: " + object + " still carries kubectl's client-side apply (another farcast, or kubectl, wrote it since this " +
		"instance was migrated); the next write will refuse until 'farcast migrate atlas' runs again.\n"
}

// firstTraceable is the first of b's apply write facts that is not a
// Namespace, and its index among them: an object a test can seed with a
// trace of kubectl's client-side apply without changing what a plan binds,
// as farcast-system's uid is.
func firstTraceable(t *testing.T, b plan.Bound) (int, plan.WriteFact) {
	t.Helper()
	for i, w := range applyWrites(b) {
		if w.Kind != "Namespace" {
			return i, w
		}
	}
	t.Fatal("the plan applies nothing but Namespaces")
	return 0, plan.WriteFact{}
}

// seedTrace stores the object w writes in s carrying kubectl's client-side
// apply's Update entry, as a farcast older than ADR 0023 M2.7 leaves an
// object it applied after the migration. kubetest's apply keeps that entry,
// another manager's, as the API server does (A30-28), so farcast's apply of
// w is answered with a trace. It returns the object's name as Traces names
// it.
//
// A ServiceAccount the fixture holds at a fixture uid keeps it: an object
// re-seeded without its uid would be another object, whose new uid the
// grant a plan bound would not name (design §33, A33-19).
func seedTrace(s *kubetest.Server, w plan.WriteFact) string {
	md := map[string]any{"name": w.Name, "managedFields": []any{map[string]any{
		"manager": "kubectl-client-side-apply", "operation": "Update", "apiVersion": w.API,
		"time": "2026-11-18T10:00:00Z", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:metadata": map[string]any{}},
	}}}
	name := w.Kind + " " + w.Name
	if w.Namespace != "" {
		md["namespace"] = w.Namespace
		name = w.Kind + " " + w.Namespace + "/" + w.Name
	}
	if uid, ok := fixtureAccounts()[w.Name]; ok && w.Kind == "ServiceAccount" && w.Namespace == tcdeploy.DefaultNamespace {
		md["uid"] = uid
	}
	s.Put(map[string]any{"apiVersion": w.API, "kind": w.Kind, "metadata": md})
	return name
}

// applyingForms are the ways the tests of afterWrites reach a command's
// applies: every plan of applyingPlans under --confirm, and each command of
// yesApplyingCommands with --yes, whose writer opens apart from
// --confirm's. Each form is one writer open, after which afterWrites is
// deferred.
func applyingForms(t *testing.T) (names []string, plans []applyingPlan, runs []func(*testing.T, applyingPlan, func(*kubetest.Server, config.Dir, plan.Bound), ...kubetest.Option) confirmation) {
	t.Helper()
	for _, p := range applyingPlans(t) {
		names, plans, runs = append(names, p.String()+"/--confirm"), append(plans, p), append(runs, confirmApplying)
		if slices.Contains(yesApplyingCommands, p.row.name) && !p.fetch {
			name := p.String()
			if p.row.name == "run" {
				name = "run"
			}
			names, plans, runs = append(names, name+"/--yes"), append(plans, p), append(runs, yesApplying)
		}
	}
	return names, plans, runs
}

// ADR 0023 M2.7 (A30-28, design §6.6, §10.5 row 101): a write after the
// migration that finds kubectl's client-side apply again clears the record.
// For every writer open of every command that applies, interactive or
// --yes and under --confirm, an object the command applies is stored as a
// farcast older than M2.7 leaves it: the command applies it, prints §6.6's
// Warning for it, once, clears the instance's server_side_apply record, and
// the next write to the instance refuses, not_migrated.
func TestAClientSideTraceAfterMigrationClearsTheRecord(t *testing.T) {
	names, plans, runs := applyingForms(t)
	for i, p := range plans {
		t.Run(names[i], func(t *testing.T) {
			var traced string
			c := runs[i](t, p, func(s *kubetest.Server, _ config.Dir, b plan.Bound) {
				_, w := firstTraceable(t, b)
				traced = seedTrace(s, w)
			})
			if got := strings.Count(c.stderr, msgTraceLeftOf(traced)); got != 1 || strings.Count(c.stderr, "still carries kubectl's") != 1 {
				t.Errorf("%s (%v) said %d times\n%s\nwant §6.6's Warning for %s alone, once", names[i], c.err, got, c.stderr, traced)
			}
			after, err := c.dir.LoadInstanceMetadata(writeName)
			if err != nil {
				t.Fatal(err)
			}
			if after.ServerSideApply != nil {
				t.Errorf("%s left the record migrated, %+v", names[i], *after.ServerSideApply)
			}
			next := withFlags(t, &kernelMeterCommand{}, "--plan")
			env, out, _ := testEnvBoth(c.dir, output.ModeJSON)
			err = next.Run(t.Context(), env, []string{writeName, "another"})
			if kindOf(classified(err)) != kindNotMigrated || err.Error() != msgAtlasNotMigrated || out.Len() != 0 {
				t.Errorf("the next write = %v (%q); want it refused, not_migrated", err, out)
			}
		})
	}
}

// ADR 0023 M2.7 (A30-28, §10.5 row 101a): afterWrites is deferred, so a
// command whose apply fails part-way still reports what it applied before.
// For every writer open of every command that applies a document after one
// it can find a trace on: that document is traced, the next apply is
// answered 500, and the command fails cluster_rejected, prints the Warning
// for the traced one, and clears the record.
func TestAPartialApplyStillReportsItsTraces(t *testing.T) {
	names, plans, runs := applyingForms(t)
	tried := 0
	for i, p := range plans {
		t.Run(names[i], func(t *testing.T) {
			var traced string
			c := runs[i](t, p, func(s *kubetest.Server, _ config.Dir, b plan.Bound) {
				k, w := firstTraceable(t, b)
				writes := applyWrites(b)
				if k+1 == len(writes) {
					t.Skipf("%s applies nothing after %s %s/%s", names[i], w.Kind, w.Namespace, w.Name)
				}
				traced = seedTrace(s, w)
				s.Fail(http.MethodPatch, factPath(t, writes[k+1]), http.StatusInternalServerError, kube.Status{})
			})
			tried++
			if kindOf(classified(c.err)) != kindClusterRejected || !strings.Contains(c.err.Error(), "documents were applied before") {
				t.Fatalf("%s = %v; want its apply refused part-way, cluster_rejected", names[i], c.err)
			}
			if got := strings.Count(c.stderr, msgTraceLeftOf(traced)); got != 1 {
				t.Errorf("%s said\n%s\nwant §6.6's Warning for %s once", names[i], c.stderr, traced)
			}
			after, err := c.dir.LoadInstanceMetadata(writeName)
			if err != nil {
				t.Fatal(err)
			}
			if after.ServerSideApply != nil {
				t.Errorf("%s left the record migrated after a partial apply that found a trace", names[i])
			}
		})
	}
	if tried < len(plans)-2 {
		t.Errorf("only %d of %d forms apply a document after a traced one", tried, len(plans))
	}
}

// ADR 0023 M2.7 (A30-28, M4, §10.5 row 98a): a trace is named by the
// document farcast applied, never by the server's answer, and nothing of the
// last-applied annotation is kept. connect's first deploy, through the
// router with -o json, its Secret fatline-mtls answered with
// kubectl-client-side-apply's entry and the annotation holding a marker, as
// a Secret kubectl applied holds its data, and its Deployment refused, so
// the command ends in an error envelope: the marker, raw or in base64, is in
// neither stderr nor the envelope, and the Warning names Secret
// farcast-system/fatline-mtls.
func TestTracesCarryNoSecretByte(t *testing.T) {
	const marker = "TRACE-SECRET-MARKER"
	encoded := base64.StdEncoding.EncodeToString([]byte(marker))
	fp, _ := fakeDeployDefaults(t)
	secretPath := "/api/v1/namespaces/farcast-system/secrets/fatline-mtls"
	s := kubetest.New(t, kubetest.WithSettledWorkloads(), kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.Method != http.MethodPatch || r.Path != secretPath {
			return 0, nil, false
		}
		body, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{
			"name": "fatline-mtls", "namespace": "farcast-system", "uid": "00000000-0000-4000-8000-0000000000c1",
			"annotations": map[string]any{lastAppliedAnnotation: `{"data":{"ca.crt":"` + encoded + `","note":"` + marker + `"}}`},
			"managedFields": []any{
				map[string]any{"manager": "farcast", "operation": "Apply", "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{}},
				map[string]any{"manager": "kubectl-client-side-apply", "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1",
					"fieldsV1": map[string]any{"f:metadata": map[string]any{}}},
			}}})
		if err != nil {
			return http.StatusInternalServerError, nil, true
		}
		return http.StatusOK, body, true
	}))
	s.Fail(http.MethodPatch, "/apis/apps/v1/namespaces/farcast-system/deployments/fatline", http.StatusInternalServerError, kube.Status{})
	wc := writeCommandNamed(t, "connect")
	dir, meta := writeInstance(t, s, true)
	wc.edit(meta)
	if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
		t.Fatal(err)
	}
	fp.registry = &planck.Registry{Ref: registryRefFor(meta), Prefix: meta.Registry.Prefix}
	stdout, stderr, code := runLine(commandLine(dir, wc, "-o", "json", "--yes"))
	if code != 1 || !strings.Contains(stdout, `"kind":"cluster_rejected"`) {
		t.Fatalf("connect: exit %d, %s\n%s", code, stdout, stderr)
	}
	if got := strings.Count(stderr, msgTraceLeftOf("Secret farcast-system/fatline-mtls")); got != 1 {
		t.Errorf("the Warning for the Secret appears %d times:\n%s", got, stderr)
	}
	for _, form := range []string{marker, encoded} {
		if strings.Contains(stdout, form) || strings.Contains(stderr, form) {
			t.Errorf("the annotation's value (%s) reached the output:\nstdout: %s\nstderr: %s", form, stdout, stderr)
		}
	}
	after, err := dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	if after.ServerSideApply != nil {
		t.Errorf("the trace left the record migrated")
	}
}

// tracesOf is a writer whose applies found traces: afterWrites' tracer.
type tracesOf []string

func (t tracesOf) Traces() []string { return t }

// ADR 0023 M2.7 (A30-28, design §6.6): afterWrites acts only on a tracer
// that found traces. A writer that is no tracer (a test's fake), and one
// whose applies found nothing, change nothing and read nothing. With
// traces, it says each one's Warning, once, in order, and clears the record,
// leaving the rest of it as it was. A record it cannot clear is a Warning of
// its own, in exactly its words and made safe to print, and nothing more:
// afterWrites returns nothing, so no command's error changes.
func TestAfterWritesClearsTheRecordOnlyForTraces(t *testing.T) {
	s := kubetest.New(t)
	dir, _ := writeInstance(t, s, true)
	record := filepath.Join(dir.InstancePath(writeName), "metadata.yaml")
	before, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []any{nil, &fakeCluster{}, tracesOf(nil), tracesOf{}} {
		reads := observeConfigReads(t)
		env, out, errb := testEnvBoth(dir, output.ModeJSON)
		afterWrites(env, writeName, w)
		if out.Len()+errb.Len() != 0 || len(reads()) != 0 {
			t.Errorf("afterWrites of %T with no trace printed %q %q and read %v", w, out, errb, reads())
		}
	}

	env, out, errb := testEnvBoth(dir, output.ModeJSON)
	afterWrites(env, writeName, tracesOf{"Secret farcast-system/fatline-mtls", "Namespace web"})
	if want := msgTraceLeftOf("Secret farcast-system/fatline-mtls") + msgTraceLeftOf("Namespace web"); errb.String() != want || out.Len() != 0 {
		t.Errorf("afterWrites said %q %q; want %q", out, errb, want)
	}
	after, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	migrated := "server_side_apply:\n  since: 2026-11-18T09:00:00Z\n  farcast: v0.0.0-test\n"
	if !bytes.Contains(before, []byte(migrated)) || !bytes.Equal(after, bytes.Replace(before, []byte(migrated), nil, 1)) {
		t.Errorf("afterWrites left the record\n%s\nwant it as it was\n%s\nwithout its server_side_apply", after, before)
	}

	// A record it cannot clear: an instance this directory holds no record
	// of, named with a control byte, as no command names one.
	const hostile = "gone\x1b[2J"
	env, out, errb = testEnvBoth(dir, output.ModeJSON)
	afterWrites(env, hostile, tracesOf{"Namespace web"})
	got := errb.String()
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "Warning: Namespace web still carries kubectl's client-side apply") ||
		!strings.HasPrefix(lines[1], "Warning: could not clear instance \"gone\\x1b[2J\"'s server_side_apply record (") ||
		!strings.HasSuffix(lines[1], "); run 'farcast migrate gone\\x1b[2J --plan' before its next write") || out.Len() != 0 {
		t.Errorf("afterWrites of a record it cannot clear said %q %q", out, got)
	}
	for _, r := range got {
		if r < 0x20 && r != '\n' {
			t.Fatalf("afterWrites printed the control byte %q raw: %q", r, got)
		}
	}
}
