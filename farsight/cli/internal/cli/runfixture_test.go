package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/manifest/parser"
	pbuild "github.com/sofmon/farcast/planck/build"
	pfetch "github.com/sofmon/farcast/planck/fetch"
	"github.com/sofmon/farcast/technocore/cost"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// ADR 0023 M2.6d (A23-49, A23-50, A28-11): the harness of run's rows in the
// cross-cutting tests. run's fetch plan is a planCommands row, stage fetch:
// --plan prints it, and it reads no cluster. Its deploy plan is printed only
// by --confirm with the fetch plan's digest, which opens the writer and
// applies the manifest read, so it is no planCommands row: runDeployRows are
// its shapes, each read through one of two helpers. runDeployDigest computes
// it as --confirm of a digest that is no plan's does — A23-47's "otherwise"
// path, which reads as the reader alone and writes nothing — and reads its
// digest from the refusal; runDeployPlan prints it, through --confirm with
// the fetch plan's digest under the succeeding stand-in kubectl. Both read
// runFixture's cluster, on kubetest.

// runTarget is the namespace the deploy plans of runDeployRows deploy into:
// twoAppManifest's name.
const runTarget = "my-platform"

// zeroDigest is a digest no plan has: run --confirm with it is A23-47's
// "otherwise" path, and is refused at the comparison (runDeployDigest).
var zeroDigest = sha("0")

// runFixtureArgs and runFixtureFlags are run's command line in these rows:
// stageRepo into writeName, at its default ref, both toolchain images named.
var (
	runFixtureArgs  = []string{writeName, "github.com/example/my-platform"}
	runFixtureFlags = []string{"--fetcher-image", fetcherDigest, "--builder-image", builderDigest}
)

// The uids of the build Jobs runSeed holds, and the digest each build
// reports.
var (
	runBuildUIDs    = map[string]string{"api": "00000000-0000-4000-8000-0000000000b1", "web": "00000000-0000-4000-8000-0000000000b2"}
	runBuildDigests = map[string]string{"api": sha("a"), "web": sha("b")}
)

// runOtherPolicy is the egress policy runSeed holds: another deployment's
// application, which a deploy into runTarget keeps.
func runOtherPolicy() *policy.Document {
	return &policy.Document{Version: policy.Version, Apps: []policy.App{{Name: "worker", Namespace: "jobs",
		CredentialSHA256: credentialOf("e"), External: []parser.External{{Host: "queue.example", Reason: "jobs"}}}}}
}

// runSeed is what runFixture's cluster holds (A28-11), each Job and pod at
// a fixed uid:
//   - farcast-system, at planSystemUID;
//   - the kernel's ledger, saved through its own ConfigMapStore, valid and
//     below the limit, observed at freshAt, which runClock reads as fresh;
//   - runOtherPolicy, the egress policy;
//   - the key pin, retiring a key no keyring here holds (pinRetiringForeign);
//   - the fetch Job of stageRepo at its default ref, finished at
//     stageJobUID, its pod's termination message the report of
//     twoAppManifest, and its log that manifest;
//   - each application's build Job, finished, its pod's message the digest
//     runBuildDigests gives it.
//
// With target, runTarget too, labelled as translate labels it, holding api
// and web rolled out, api adapted by the kernel after farcast last applied
// it and web not, and a StatefulSet, db, beside them. runFixture drops what
// the kernel's own Deployment and technocore-namespaces would add: a run
// reads neither.
func runSeed(t *testing.T, target bool) func(s *kubetest.Server) {
	t.Helper()
	ledger := savedCheckpoint(t, cost.LevelOK.String(), freshAt)
	body, err := runOtherPolicy().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return func(s *kubetest.Server) {
		systemNamespace(s)
		for _, cm := range []struct{ ns, name, key, value string }{
			{tcdeploy.DefaultNamespace, kernel.DefaultCheckpointName, kernel.CheckpointKey(), ledger},
			{fldeploy.DefaultNamespace, fldeploy.PolicyConfigMap, fldeploy.PolicyKey, string(body)},
			{dsdeploy.DefaultNamespace, dsdeploy.PinConfigMapName(""), dsdeploy.PinKey, pinRetiringForeign},
		} {
			s.Put(map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
				"metadata": map[string]any{"name": cm.name, "namespace": cm.ns}, "data": map[string]any{cm.key: cm.value}})
		}
		finishedJob(s, stageFetchJob(), stageJobUID, "fetch", reportFor(twoAppManifest), twoAppManifest)
		for _, app := range []string{"api", "web"} {
			finishedJob(s, pbuild.JobName(runTarget, app), runBuildUIDs[app], "kaniko", runBuildDigests[app], "")
		}
		if !target {
			return
		}
		s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": runTarget,
			"labels": map[string]any{"app.kubernetes.io/managed-by": "farcast", "app.kubernetes.io/part-of": runTarget,
				"farcast.sofmon.com/instance": writeName}}})
		applied := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
		s.Put(runDeployment("api", "250m", "512Mi", applied, applied.Add(44*time.Hour)))
		s.Put(runDeployment("web", "100m", "128Mi", applied, applied.Add(-24*time.Hour)))
		s.Put(map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet",
			"metadata": map[string]any{"name": "db", "namespace": runTarget},
			"spec": map[string]any{"replicas": 1, "selector": map[string]any{"matchLabels": map[string]any{"app": "db"}},
				"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "db", "image": "registry.example/db@" + sha("d")}}}}},
		})
	}
}

// finishedJob puts a Job in farcast-system that succeeded, at uid, with one
// container, and its one pod, whose termination message is message and
// whose log, when not "", is log.
func finishedJob(s *kubetest.Server, name, uid, container, message, log string) {
	s.Put(map[string]any{"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{"name": name, "namespace": tcdeploy.DefaultNamespace, "uid": uid},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{"job-name": name}},
			"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": container}}}},
		},
		"status": map[string]any{"succeeded": 1},
	})
	annotations := map[string]any{}
	if log != "" {
		annotations[kubetest.LogAnnotationPrefix+container] = log
	}
	s.Put(map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name + "-x7k2p", "namespace": tcdeploy.DefaultNamespace,
			"labels": map[string]any{"job-name": name}, "annotations": annotations},
		"spec": map[string]any{"containers": []any{map[string]any{"name": container}}},
		"status": map[string]any{"phase": "Succeeded", "containerStatuses": []any{map[string]any{"name": container,
			"state": map[string]any{"terminated": map[string]any{"message": message}}}}},
	})
}

// runDeployment is app's Deployment in runTarget as farcast last applied
// it, at applied, and rolled out: one replica, updated and available, its
// generation observed, the container named after app requesting cpu and
// mem, and the kernel's adapted-at stamp at adapted.
func runDeployment(app, cpu, mem string, applied, adapted time.Time) map[string]any {
	return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": app, "namespace": runTarget, "generation": 2,
			"annotations": map[string]any{kernel.AdaptedAtLabel: adapted.Format(time.RFC3339)},
			"managedFields": []any{map[string]any{"manager": kube.FieldManager, "operation": "Apply", "apiVersion": "apps/v1",
				"time": applied.Format(time.RFC3339), "fieldsType": "FieldsV1", "fieldsV1": map[string]any{}}}},
		"spec": map[string]any{"replicas": 1,
			"selector": map[string]any{"matchLabels": map[string]any{"app.kubernetes.io/name": app}},
			"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": app,
				"image":     "registry.example/" + app + "@" + sha("c"),
				"resources": map[string]any{"requests": map[string]any{"cpu": cpu, "memory": mem}}}}}}},
		"status": map[string]any{"replicas": 1, "updatedReplicas": 1, "availableReplicas": 1, "readyReplicas": 1, "observedGeneration": 2},
	}
}

// meterRunTarget is a record whose kernel meters runTarget.
func meterRunTarget(m *config.InstanceMetadata) {
	m.Kernel.Namespaces = append(m.Kernel.Namespaces, runTarget)
}

// noCAKeyMaterial is writeMaterial with ca.key gone: this machine is not the
// one that installed the instance.
func noCAKeyMaterial(t *testing.T, dir config.Dir) {
	t.Helper()
	writeMaterial(t, dir)
	if err := os.Remove(filepath.Join(dir.InstancePath(writeName), "fatline", "ca.key")); err != nil {
		t.Fatal(err)
	}
}

// runWithFakes is run as its plan rows run it (A23-49, A28-11): its builder
// f's; its plan's reader the instance's, through loopbackReader against the
// fixture's kubetest, each identity it was asked for recorded; its writer
// the instance's real one, each open counted, which --confirm with a fetch
// plan's digest needs for the manifest read; its keyholder refused and
// counted; and its clock runClock, at which runSeed's ledger is fresh.
func runWithFakes(f *planFakes) func() Command {
	return func() Command {
		c := &runCommand{}
		c.newPlanReader = func(r clusterRef) (runPlanReader, error) {
			f.readers = append(f.readers, r.Identity)
			cl, err := loopbackReader(r)
			if err != nil {
				return nil, err
			}
			return cl, nil
		}
		c.newCluster = func(r clusterRef) (runCluster, error) {
			f.writers++
			cl, err := openWriter(r)
			if err != nil {
				return nil, err
			}
			return cl, nil
		}
		c.newBuilder = func(func(string)) imageBuilder { return f.builder }
		c.newKeyholder = func(context.Context, *Env, string) (sealStateClient, func(), error) {
			f.keyholders++
			return nil, nil, errors.New("test: a plan opened the keyholder")
		}
		c.now = func() time.Time { return runClock }
		return c
	}
}

// pinRunClock fixes run's default clock at runClock, at which runSeed's
// ledger is fresh, for the rest of the test: for a test that runs run
// through the router, which sets no seam of its own, so its deploy plan
// binds the ledger as the direct rows bind it, whatever day the test runs.
func pinRunClock(t *testing.T) {
	t.Helper()
	saved := runNowDefault
	runNowDefault = func() time.Time { return runClock }
	t.Cleanup(func() { runNowDefault = saved })
}

// runDeployRows are run's deploy plans (ADR 0023 M2.6d, A28-11), each of
// stageRepo at its default ref into writeName, both toolchain images named,
// read from runSeed's cluster as the instance's reader:
//   - into runTarget, which the kernel meters, where api runs adapted and web
//     as farcast left it, beside a StatefulSet;
//   - into a namespace the cluster does not have yet, which the deploy
//     starts metering;
//   - into one that exists and the kernel does not meter, which blocks the
//     plan, forbidden;
//   - from a machine without the CA key, while storage is wired, which
//     blocks it, internal.
//
// None is a planCommands row: --plan prints run's fetch plan, never these.
func runDeployRows(t *testing.T) []planCommand {
	t.Helper()
	row := func(shape string, target, metered bool, prepare func(*testing.T, config.Dir)) planCommand {
		f := &planFakes{provider: &fakeProvider{}, builder: &fakeBuilder{}}
		r := planCommand{name: "run", shape: shape, stage: "deploy", args: runFixtureArgs, flags: runFixtureFlags,
			readsCluster: true, cmd: runWithFakes(f), seed: runSeed(t, target), prepare: prepare, fakes: f}
		if metered {
			r.edit = meterRunTarget
		}
		return r
	}
	return []planCommand{
		row("deploy into a metered namespace", true, true, writeMaterial),
		row("deploy into a new namespace", false, false, writeMaterial),
		row("deploy into an unmetered namespace", true, false, writeMaterial),
		row("deploy without the CA key", true, true, noCAKeyMaterial),
	}
}

// runDeployRowNamed is the runDeployRows row of shape.
func runDeployRowNamed(t *testing.T, shape string) planCommand {
	t.Helper()
	for _, r := range runDeployRows(t) {
		if r.shape == shape {
			return r
		}
	}
	t.Fatalf("no deploy plan %s", shape)
	return planCommand{}
}

// runFixture is run's deploy into a metered namespace (A23-49, A28-11): its
// row, and its fixture — writeInstance's record, metering runTarget, with
// the instance's mTLS material, and runSeed's cluster, on a kubetest server
// started with opts.
func runFixture(t *testing.T, opts ...kubetest.Option) (planCommand, *kubetest.Server, config.Dir) {
	t.Helper()
	row := runDeployRowNamed(t, "deploy into a metered namespace")
	s, dir := planFixtureWith(t, row, true, opts...)
	return row, s, dir
}

// planChangedNaming is §9.2's refusal of zeroDigest, naming the plan it is
// not.
var planChangedNaming = regexp.MustCompile(`^the plan for this command is now (sha256:[0-9a-f]{64}), not the ` + zeroDigest + ` given to --confirm: `)

// runDeployDigest is the digest of row's deploy plan, as run --confirm of a
// digest that is no plan's computes it (A28-11): A23-47's "otherwise" path,
// which reads the fetch Job and computes the deploy plan as the reader, and
// refuses at the comparison, plan_changed, naming it. It reads only as the
// reader, opens no writer, writes nothing and prints nothing. in, when not
// nil, is stdin.
func runDeployDigest(t *testing.T, dir config.Dir, row planCommand, in io.Reader) string {
	t.Helper()
	cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", zeroDigest)...)
	env, out, errb := testEnvBoth(dir, output.ModeHuman)
	if in != nil {
		env.In = in
	}
	err := cmd.Run(t.Context(), env, row.args)
	var m []string
	if err != nil {
		m = planChangedNaming.FindStringSubmatch(err.Error())
	}
	if m == nil || err.Error() != planChanged(m[1], zeroDigest).Error() || kindOf(classified(err)) != kindPlanChanged {
		t.Fatalf("%s --confirm %s = %v; want plan_changed, naming its deploy plan", row, zeroDigest, err)
	}
	if out.Len()+errb.Len() != 0 {
		t.Errorf("%s --confirm %s printed %q %q before refusing", row, zeroDigest, out, errb)
	}
	return m[1]
}

// runDeployPlan is row's deploy plan as run prints it (A28-11): --plan, then
// --confirm with the fetch plan's digest, which runs the manifest read — the
// fetch Job applied as the writer through the succeeding stand-in kubectl,
// for that one run, and read back as the reader from the Job the fixture
// holds — and prints the deploy plan in mode, nothing on stderr. It returns
// what runPlan returns, and puts PATH back as it was.
func runDeployPlan(t *testing.T, dir config.Dir, row planCommand, mode output.Mode) (plan.Document, string) {
	t.Helper()
	fetch, _ := runPlan(t, dir, row, output.ModeJSON)
	path := os.Getenv("PATH")
	succeedingKubectl(t)
	defer t.Setenv("PATH", path)
	cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", fetch.Digest)...)
	env, out, errb := testEnvBoth(dir, mode)
	if err := cmd.Run(t.Context(), env, row.args); err != nil {
		t.Fatalf("%s --confirm <fetch digest>: %v\n%s", row, err, errb)
	}
	if errb.Len() != 0 {
		t.Errorf("%s --confirm <fetch digest> wrote on stderr: %q", row, errb)
	}
	if mode == output.ModeJSON {
		return printedDocument(t, out.Bytes()), out.String()
	}
	return plan.Document{Digest: digestLine(t, out.String())}, out.String()
}

// planDigest is row's plan's digest: --plan's, or, for run's deploy plan,
// runDeployDigest's.
func planDigest(t *testing.T, dir config.Dir, row planCommand) string {
	t.Helper()
	if row.stage == "deploy" {
		return runDeployDigest(t, dir, row, nil)
	}
	doc, _ := runPlan(t, dir, row, output.ModeJSON)
	return doc.Digest
}

// runWithoutAReaderIsRefused is TestPlanWithoutAReaderIsRefused's run rows
// (A23-1, A23-21, rows 85 and 85b), against runFixture: --plan, which prints
// the fetch plan and reads no cluster, needs no reader; --confirm, with the
// fetch plan's digest or the deploy plan's, needs one 'reader grant'
// verified, and without it refuses with run's own words, credential_missing,
// before the reader or the writer opens — no fetch Job applied, the
// stand-in kubectl never run, no request sent, credentials.yaml never read
// and nothing printed. A granted reader that is not the derived one is
// refused by openCluster, in its words, before the writer opens.
func runWithoutAReaderIsRefused(t *testing.T) {
	for _, tc := range []struct {
		state  string
		edit   func(t *testing.T, dir config.Dir, meta *config.InstanceMetadata)
		remedy string
	}{
		{"none", func(_ *testing.T, _ config.Dir, m *config.InstanceMetadata) { m.Reader = nil },
			"run 'farcast reader init atlas', the printed Cloud Shell script, 'farcast reader record' and 'farcast reader grant'"},
		{"key missing", func(t *testing.T, dir config.Dir, _ *config.InstanceMetadata) {
			if err := os.Remove(filepath.Join(dir.InstancePath(writeName), "reader.key")); err != nil {
				t.Fatal(err)
			}
		}, "copy reader.key from the machine that made it, or run 'farcast reader init atlas --rotate'"},
		{"not uploaded", func(_ *testing.T, _ config.Dir, m *config.InstanceMetadata) { m.Reader.KeyID = "" },
			"run the printed Cloud Shell script, then 'farcast reader record atlas --key-id <id>' and 'farcast reader grant atlas'"},
		{"not granted", func(_ *testing.T, _ config.Dir, m *config.InstanceMetadata) { m.Reader.GrantedAt = time.Time{} },
			"run 'farcast reader grant atlas'"},
		{"granted, another reader", func(_ *testing.T, _ config.Dir, m *config.InstanceMetadata) {
			m.Reader.Email = "writer@kubetest.invalid"
		}, ""},
	} {
		for _, stage := range []string{"--plan", "<F>", "<D>"} {
			t.Run(tc.state+"/"+stage, func(t *testing.T) {
				ran := strayKubectl(t)
				row, s, dir := runFixture(t)
				answer := []string{"--plan"}
				switch stage {
				case "<F>":
					fetch, _ := runPlan(t, dir, row, output.ModeJSON)
					answer = []string{"--confirm", fetch.Digest}
				case "<D>":
					answer = []string{"--confirm", runDeployDigest(t, dir, row, nil)}
				}
				meta, err := dir.LoadInstanceMetadata(writeName)
				if err != nil {
					t.Fatal(err)
				}
				tc.edit(t, dir, meta)
				if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
					t.Fatal(err)
				}
				sent, readers := len(s.Requests()), len(row.fakes.readers)
				reads := observeConfigReads(t)
				cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), answer...)...)
				env, out, errb := testEnvBoth(dir, output.ModeJSON)
				err = cmd.Run(t.Context(), env, row.args)
				if stage == "--plan" {
					if err != nil {
						t.Fatalf("run --plan with a reader %s = %v; the fetch plan reads no cluster and needs no reader", tc.state, err)
					}
					if b := decodedBound(t, printedDocument(t, out.Bytes())); b.Stage != "fetch" || b.ClusterIdentity != "none" {
						t.Errorf("run --plan printed the plan of stage %q as %q; want the fetch plan, reading no cluster", b.Stage, b.ClusterIdentity)
					}
				} else {
					want := fmt.Sprintf("'farcast run --confirm' computes the deploy plan as instance %q's reader, whose state is %s; %s, "+
						"or run 'farcast run' in a terminal. Nothing was written.", writeName, tc.state, tc.remedy)
					opened := 0
					if tc.remedy == "" {
						// openCluster's own refusal of a reader that is not the
						// derived one.
						want = fmt.Sprintf("instance %q records the reader %q, which is not the reader farcast derives for it (%s); nothing was sent",
							writeName, "writer@kubetest.invalid", readerName(writeName)+"@<a name under .invalid>")
						opened = 1
					}
					if err == nil || err.Error() != want || !errors.Is(err, errCredentialMissing) || kindOf(classified(err)) != kindCredentialMissing {
						t.Fatalf("run --confirm %s with a reader %s = %v (kind %s);\nwant %q", stage, tc.state, err, kindOf(classified(err)), want)
					}
					if got := len(row.fakes.readers) - readers; got != opened || row.fakes.writers != 0 {
						t.Errorf("run --confirm %s opened its reader %d times and its writer %d times; want the reader %d times and the writer never",
							stage, got, row.fakes.writers, opened)
					}
					if out.Len()+errb.Len() != 0 {
						t.Errorf("run --confirm %s printed %q %q", stage, out, errb)
					}
				}
				if got := s.Requests()[sent:]; len(got) != 0 {
					t.Errorf("run %s with a reader %s sent %d requests (first %s %s as %q)", stage, tc.state, len(got), got[0].Method, got[0].Path, got[0].As)
				}
				for _, p := range reads() {
					if filepath.Base(p) == "credentials.yaml" {
						t.Errorf("run %s read %s", stage, p)
					}
				}
				if ran() {
					t.Errorf("run %s with a reader %s ran kubectl: the fetch Job was applied", stage, tc.state)
				}
			})
		}
	}
}

// runPlanReadErrorsNameTheReader is TestPlanReadErrorsNameTheReader's run
// row (A23-22, row 76e): under --confirm of a digest that is no plan's, the
// deploy plan's first read as the reader is the fetch Job's, and the 403 it
// meets there says what the reader needs, once, kind forbidden, never
// blaming the installer's account. sentence is the remedy status's shape
// calls for.
func runPlanReadErrorsNameTheReader(t *testing.T, status kube.Status, sentence string) {
	row, s, dir := runFixture(t)
	s.Fail(http.MethodGet, "/apis/batch/v1/namespaces/"+pfetch.Namespace+"/jobs/"+stageFetchJob(), http.StatusForbidden, status)
	cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", sampleDigest)...)
	env, out, _ := testEnvBoth(dir, output.ModeJSON)
	err := cmd.Run(t.Context(), env, row.args)
	if kind := kindOf(classified(err)); err == nil || kind != kindForbidden {
		t.Fatalf("run --confirm <D> = %v (kind %s); want forbidden", err, kind)
	}
	if msg := err.Error(); strings.Count(msg, sentence) != 1 || strings.Contains(msg, "installer service account") {
		t.Errorf("run --confirm <D> = %q;\nwant %q once and the installer's account never", msg, sentence)
	}
	if out.Len() != 0 || row.fakes.writers != 0 {
		t.Errorf("run --confirm <D> printed %q and opened the writer %d times", out, row.fakes.writers)
	}
	onlyThePlansReads(t, row, s, consentConfirm)
}

// runConfirmChecksTheWritersCluster is
// TestConfirmChecksTheWritersClusterIsThePlans's run rows (A23-23, A23-47,
// row 76c): the deploy plan reads farcast-system's uid as the reader, and
// the writer's list of the same namespace, answered here for the writer
// alone, names another, or none. --confirm with the deploy plan's digest
// compares, opens the writer, and refuses plan_changed, naming both uids,
// once the writer's preflight read it: no build applied, the stand-in
// kubectl never run, nothing written.
func runConfirmChecksTheWritersCluster(t *testing.T) {
	for _, tc := range []struct {
		name, writerUID, said string
	}{
		{"another farcast-system", "u2", "u2"},
		{"no farcast-system", "", "absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ran := strayKubectl(t)
			theWriters := kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
				if r.As != "writer" || r.Method != http.MethodGet || r.Path != "/api/v1/namespaces" {
					return 0, nil, false
				}
				items := []any{}
				if tc.writerUID != "" {
					items = append(items, map[string]any{"metadata": map[string]any{"name": tcdeploy.DefaultNamespace, "uid": tc.writerUID}})
				}
				body, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "NamespaceList", "metadata": map[string]any{}, "items": items})
				if err != nil {
					return http.StatusInternalServerError, nil, true
				}
				return http.StatusOK, body, true
			})
			row, s, dir := runFixture(t, theWriters)
			digest := runDeployDigest(t, dir, row, nil)
			before, sent := treeFiles(t, string(dir)), len(s.Requests())
			cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", digest)...)
			env, out, errb := testEnvBoth(dir, output.ModeJSON)
			err := cmd.Run(t.Context(), env, row.args)
			want := fmt.Sprintf("instance %q's cluster is not the one its plan read: farcast-system's uid is %s, not %s; nothing was written; %s",
				writeName, tc.said, planSystemUID, msgPlanAgain)
			if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
				t.Fatalf("run --confirm <D> against another cluster = %v (kind %s);\nwant %q, plan_changed\n%s", err, kindOf(classified(err)), want, errb)
			}
			if ran() || out.Len() != 0 {
				t.Errorf("ran kubectl %v and printed %q before refusing", ran(), out)
			}
			if !slices.Equal(row.fakes.readers, []kube.Identity{kube.Reader, kube.Reader}) || row.fakes.writers != 1 {
				t.Errorf("opened the plan's reader as %v and the writer %d times; want the reader twice, then the writer once", row.fakes.readers, row.fakes.writers)
			}
			// After the reader's recomputation, the writer read once: its
			// preflight, after its token.
			confirmed := s.Requests()[sent:]
			firstWriter := slices.IndexFunc(confirmed, func(r kubetest.Request) bool { return r.As == "writer" })
			var writerReads []string
			for i, r := range confirmed {
				switch {
				case firstWriter < 0 || i < firstWriter:
					if r.As != "reader" {
						t.Errorf("before the writer: %s %s as %q", r.Method, r.Path, r.As)
					}
				case r.As != "writer":
					t.Errorf("after the writer's token: %s %s as %q", r.Method, r.Path, r.As)
				case r.Path != "/token":
					writerReads = append(writerReads, r.Method+" "+r.Path)
				}
			}
			if !slices.Equal(writerReads, []string{"GET /api/v1/namespaces"}) {
				t.Errorf("the writer sent %q; want its preflight read alone", writerReads)
			}
			sameFiles(t, "run --confirm against another cluster", before, treeFiles(t, string(dir)))
		})
	}
}

// answeredRequest is one request kubetest answered, as
// TestConfirmRecomputesAsThePlansIdentity orders them: its identity, its
// method and path, and how many runs of the stand-in kubectl had begun.
type answeredRequest struct {
	as, method, path string
	applied          int
}

// answeredLog is a kubetest option that logs every request answered, with
// how many applies runs counts had begun, and the log.
func answeredLog(runs func() int) (kubetest.Option, func() []answeredRequest) {
	var mu sync.Mutex
	var seen []answeredRequest
	return kubetest.WithAnswered(func(r kubetest.Request, _ int) {
			n := runs()
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, answeredRequest{r.As, r.Method, r.Path, n})
		}), func() []answeredRequest {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(seen)
		}
}

// runConfirmRecomputesAsThePlansIdentity is
// TestConfirmRecomputesAsThePlansIdentity's run cases (A23-47, A23-50, rows
// 76 and 76a), against runFixture through run's real reader and writer, the
// stand-in kubectl the succeeding one.
//
// run <F>: --confirm with the fetch plan's digest applies the read as the
// writer — its token and its preflight first, before any apply — then the
// stand-in applies exactly the fetch plan's documents, and every request
// after is the reader's: the Job's wait, its pod list and its log, and the
// deploy plan's reads. It prints the deploy plan.
//
// run <D>: --confirm with the deploy plan's digest runs to the end. Every
// request before the writer's first token is the reader's, and none was
// answered after an apply: the deploy plan is computed again, and compared,
// as the reader, before anything is written. Every request after that token
// is the writer's, its preflight before any apply, and the stand-in applied
// the builds, then the egress policy, then the workloads.
func runConfirmRecomputesAsThePlansIdentity(t *testing.T) {
	t.Run("run <F>", func(t *testing.T) {
		calls, runs := succeedingKubectlRuns(t)
		opt, seen := answeredLog(runs)
		row, _, dir := runFixture(t, opt)
		fetch, _ := runPlan(t, dir, row, output.ModeJSON)
		planned := len(seen())
		cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", fetch.Digest)...)
		env, out, errb := testEnvBoth(dir, output.ModeJSON)
		if err := cmd.Run(t.Context(), env, row.args); err != nil {
			t.Fatalf("--confirm <F>: %v\n%s", err, errb)
		}
		if planned != 0 {
			t.Errorf("run --plan sent %d requests", planned)
		}
		confirmed := seen()[planned:]
		if len(confirmed) < 3 || confirmed[0] != (answeredRequest{"writer", http.MethodPost, "/token", 0}) ||
			confirmed[1] != (answeredRequest{"writer", http.MethodGet, "/api/v1/namespaces", 0}) {
			t.Fatalf("the confirm's requests begin %+v; want the writer's token, then its preflight, before any apply", confirmed)
		}
		for _, a := range confirmed[2:] {
			if a.as != "reader" || a.applied != 1 {
				t.Errorf("after the writer's preflight: %s %s as %q, after %d applies; want the reader's, after the read's one apply", a.method, a.path, a.as, a.applied)
			}
		}
		job := "/apis/batch/v1/namespaces/" + pfetch.Namespace + "/jobs/" + stageFetchJob()
		if !slices.ContainsFunc(confirmed, func(a answeredRequest) bool { return a.as == "reader" && a.path == job }) {
			t.Errorf("the reader never read the fetch Job %s: %+v", job, confirmed)
		}
		applied := appliedStreams(calls())
		if len(applied) != 1 {
			t.Fatalf("the stand-in applied %d streams; want the read's one", len(applied))
		}
		if got, want := wantWrites(t, applied[0]), planWrites(decodedBound(t, fetch)); !reflect.DeepEqual(got, want) {
			t.Errorf("applied\n%#v\nthe fetch plan bound\n%#v", got, want)
		}
		if b := decodedBound(t, printedDocument(t, out.Bytes())); b.Stage != "deploy" || b.ClusterIdentity != "reader" {
			t.Errorf("--confirm <F> printed the plan of stage %q as %q; want the deploy plan, as the reader", b.Stage, b.ClusterIdentity)
		}
		if !slices.Equal(row.fakes.readers, []kube.Identity{kube.Reader}) || row.fakes.writers != 1 {
			t.Errorf("opened the plan's reader as %v and the writer %d times; want the reader once and the writer once", row.fakes.readers, row.fakes.writers)
		}
	})

	t.Run("run <D>", func(t *testing.T) {
		calls, runs := succeedingKubectlRuns(t)
		opt, seen := answeredLog(runs)
		row, _, dir := runFixture(t, opt)
		digest := runDeployDigest(t, dir, row, nil)
		planned := len(seen())
		cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", digest)...).(*runCommand)
		cmd.newKeyholder = openerFor(&fakeStateKeyholder{phase: "unsealed"})
		env, _, errb := testEnvBoth(dir, output.ModeJSON)
		if err := cmd.Run(t.Context(), env, row.args); err != nil {
			t.Fatalf("--confirm <D>: %v\n%s", err, errb)
		}
		confirmed := seen()[planned:]
		firstWriter := slices.IndexFunc(confirmed, func(a answeredRequest) bool { return a.as == "writer" && a.path == "/token" })
		if firstWriter < 1 {
			t.Fatalf("the confirm's requests %+v; want the reader's recomputation, then the writer's token", confirmed)
		}
		for i, a := range confirmed {
			switch {
			case i < firstWriter && (a.as != "reader" || a.applied != 0):
				t.Errorf("before the writer's token: %s %s as %q, after %d applies; want the reader's, before any apply", a.method, a.path, a.as, a.applied)
			case i > firstWriter && a.as != "writer":
				t.Errorf("after the writer's token: %s %s as %q; want the writer's", a.method, a.path, a.as)
			}
		}
		if firstWriter+1 == len(confirmed) || confirmed[firstWriter+1] != (answeredRequest{"writer", http.MethodGet, "/api/v1/namespaces", 0}) {
			t.Errorf("the writer's reads are %+v; want its preflight first, before any apply", confirmed[firstWriter+1:])
		}
		var kinds []string
		for _, s := range appliedStreams(calls()) {
			docs := docsIn(t, string(s))
			switch {
			case len(docs) == 1 && docs["ConfigMap/"+fldeploy.PolicyConfigMap] != "":
				kinds = append(kinds, "policy")
			case docs["Job/"+pbuild.JobName(runTarget, "api")] != "":
				kinds = append(kinds, "build api")
			case docs["Job/"+pbuild.JobName(runTarget, "web")] != "":
				kinds = append(kinds, "build web")
			case docs["Deployment/api"] == runTarget && docs["Deployment/web"] == runTarget:
				kinds = append(kinds, "workloads")
			default:
				kinds = append(kinds, fmt.Sprint(docs))
			}
		}
		if want := []string{"build api", "build web", "policy", "workloads"}; !slices.Equal(kinds, want) {
			t.Errorf("the stand-in applied %q; want %q", kinds, want)
		}
		if !slices.Equal(row.fakes.readers, []kube.Identity{kube.Reader, kube.Reader}) || row.fakes.writers != 1 {
			t.Errorf("opened the plan's reader as %v and the writer %d times; want the reader for the plan and for the recomputation, then the writer once",
				row.fakes.readers, row.fakes.writers)
		}
	})
}

// runCredentialDigests are the credential_sha256 values of runTarget's
// applications in a rendered egress policy (A23-31 item 5), each held after
// the namespace line policy.Document.Marshal writes before it.
var runCredentialDigests = regexp.MustCompile(`("namespace": "` + runTarget + `",\n\s*"credential_sha256": ")[0-9a-f]{64}"`)

// runBuiltImages are the 64 hex after @sha256: of each image a run built
// into runTarget (A23-31 item 4).
var runBuiltImages = regexp.MustCompile(`(/app/` + runTarget + `/[a-z0-9-]+@sha256:)[0-9a-f]{64}`)

// runMasked is a document of run's deploy with A23-31's differences masked:
// masked's (a Secret's data and the mTLS hash), the build digests in image
// references, and this deployment's egress credentials' digests in the
// policy.
func runMasked(doc []byte) []byte {
	doc = runBuiltImages.ReplaceAll(masked(doc), []byte("${1}<masked>"))
	return runCredentialDigests.ReplaceAll(doc, []byte(`${1}<masked>"`))
}

// runPlannedDocuments is what the deploy plan into runTarget renders over
// its placeholders (A23-30), as the test computes it: each build, pinned to
// the commit read; the egress policy, runOtherPolicy merged with the
// manifest's, each of its credentials a placeholder; and the workloads,
// over placeholder images, credentials and leaves, and the instance's CA
// certificate.
func runPlannedDocuments(t *testing.T, dir config.Dir) (builds [][]byte, policyDoc, workloads []byte) {
	t.Helper()
	meta, err := dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	c, m := &runCommand{}, mustManifest(t, twoAppManifest)
	planned, err := c.planBuilds(meta, builderDigest, stageRepo, testCommit, m)
	if err != nil {
		t.Fatal(err)
	}
	doc, credentials, err := egressPolicy(runOtherPolicy(), runTarget, m, placeholderCredential)
	if err != nil {
		t.Fatal(err)
	}
	if policyDoc, err = fldeploy.RenderPolicyConfigMap(fldeploy.DefaultNamespace, doc); err != nil {
		t.Fatal(err)
	}
	images, scopes := map[string]string{}, map[string]datasphere.Scope{}
	for _, b := range planned {
		builds = append(builds, b.manifest)
		images[b.app] = buildPlaceholder(untagged(b.destination), runTarget+"/"+b.app)
		scope, err := datasphere.AppScopeName(runTarget, b.app)
		if err != nil {
			t.Fatal(err)
		}
		scopes[b.app] = datasphere.Scope{Name: scope}
	}
	ca, err := dir.LoadInstanceCACert(writeName)
	if err != nil {
		t.Fatal(err)
	}
	if workloads, err = c.translate(meta, runTarget, m, images, credentials, scopes, ca, placeholderAppLeaf); err != nil {
		t.Fatal(err)
	}
	return builds, policyDoc, workloads
}

// confirmWritesRunsDocumentsAsPlanned is
// TestConfirmWritesThePlannedDocumentsExceptTheirSecrets's row for run
// (A23-31, row 80): its deploy plan into runTarget, printed by --confirm
// with the fetch plan's digest, then confirmed through run's real writer
// against kubetest, its kubectl the succeeding stand-in, its keyholder one
// whose replicas serve, so the key pin is raised. The plan's write facts
// are the test's own rendering over the placeholders. The stand-in applied
// each build byte for byte as planned; the egress policy and the workloads
// equal the planned rendering once A23-31's differences are masked, and
// differ unmasked only in a Secret, a Deployment's image and the policy's
// credentials; and the pin, written in-process as the writer at the
// resourceVersion the plan read, is the planned document but for its key
// ids, whose count each array keeps.
func confirmWritesRunsDocumentsAsPlanned(t *testing.T) {
	calls := succeedingKubectl(t)
	row, s, dir := runFixture(t)
	doc, _ := runDeployPlan(t, dir, row, output.ModeJSON)
	b := decodedBound(t, doc)
	builds, policyDoc, workloads := runPlannedDocuments(t, dir)

	// The plan's write facts are this rendering: the builds, the policy at
	// the resourceVersion the plan read, the workloads, then the pin.
	pin := pinWriteFact(b)
	if pin == nil || pin.Method != plan.WriteReplace || pin.ResourceVersion == "" {
		t.Fatalf("the plan writes the pin %+v; want it replaced at the version it read", pin)
	}
	var want []plan.Fact
	for _, build := range builds {
		want = append(want, wantWrites(t, build)...)
	}
	policyWrite := wantWrites(t, policyDoc)
	writes := planWrites(b)
	if len(policyWrite) != 1 || len(writes) < len(want)+1 {
		t.Fatalf("the policy renders %d documents, and the plan binds %d writes", len(policyWrite), len(writes))
	}
	pw := policyWrite[0].(plan.WriteFact)
	pw.ResourceVersion = writes[len(want)].(plan.WriteFact).ResourceVersion
	if pw.ResourceVersion == "" {
		t.Errorf("the plan binds the policy, which the fixture holds, at no resourceVersion")
	}
	want = append(append(want, pw), wantWrites(t, workloads)...)
	if got := writes[:len(writes)-1]; !reflect.DeepEqual(got, want) || writes[len(writes)-1] != plan.Fact(*pin) {
		t.Fatalf("the plan's write facts are not the planned rendering, then the pin:\n%#v\n%#v", writes, want)
	}

	sent := len(s.Requests())
	cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", doc.Digest)...).(*runCommand)
	cmd.newKeyholder = openerFor(&fakeStateKeyholder{phase: "unsealed"})
	env, _, errb := testEnvBoth(dir, output.ModeJSON)
	if err := cmd.Run(t.Context(), env, row.args); err != nil {
		t.Fatalf("--confirm <D>: %v\n%s", err, errb)
	}
	applied := appliedStreams(calls())
	if len(applied) != len(builds)+2 {
		t.Fatalf("the stand-in applied %d streams; want the %d builds, the policy and the workloads", len(applied), len(builds))
	}
	for i, build := range builds {
		if !bytes.Equal(applied[i], build) {
			t.Errorf("build %d applied\n%s\nthe plan rendered\n%s", i, applied[i], build)
		}
	}
	if got, want := runMasked(applied[len(builds)]), runMasked(policyDoc); !bytes.Equal(got, want) || bytes.Equal(applied[len(builds)], policyDoc) {
		t.Errorf("the policy applied differs from the plan's beyond its credentials, or not there at all:\napplied:\n%s\nplanned:\n%s", applied[len(builds)], policyDoc)
	}
	appliedDocs, err := kube.SplitStream(applied[len(builds)+1])
	if err != nil {
		t.Fatal(err)
	}
	plannedDocs, err := kube.SplitStream(workloads)
	if err != nil {
		t.Fatal(err)
	}
	if len(appliedDocs) != len(plannedDocs) {
		t.Fatalf("applied %d workload documents; the plan bound %d", len(appliedDocs), len(plannedDocs))
	}
	differ := map[string]bool{}
	for i, p := range plannedDocs {
		a := appliedDocs[i]
		if !bytes.Equal(runMasked(a.Raw), runMasked(p.Raw)) {
			t.Errorf("document %d, %s %s/%s, differs from the plan beyond its secrets:\napplied:\n%s\nplanned:\n%s", i, p.Kind.Kind, p.Namespace, p.Name, a.Raw, p.Raw)
		}
		if !bytes.Equal(a.Raw, p.Raw) {
			differ[p.Kind.Kind] = true
		}
	}
	if !differ["Secret"] || !differ["Deployment"] || len(differ) != 2 {
		t.Errorf("the workloads differ unmasked in %v; want a Secret's data and a Deployment's image alone", differ)
	}

	body := pinWriteBody(t, s.Requests()[sent:])
	planned, err := pinDocument(pinOfFact(t, pinFactOf(t, b)), pin.ResourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	sameSHA256(t, "the plan's pin", planned, pin)
	if got, want := keyIDs.ReplaceAll(body, []byte("<id>")), keyIDs.ReplaceAll(planned, []byte("<id>")); !bytes.Equal(got, want) {
		t.Errorf("the pin sent\n%s\nthe plan's is\n%s", body, planned)
	}
	if bytes.Equal(body, planned) {
		t.Error("the pin sent is the planned document unmasked: the plan's placeholder ids are the real keys")
	}
}

// runDeployPlansCarryNoKeyMaterial is TestPlansCarryNoKeyMaterial's rows
// for run's deploy plans (A23-25, row 91g): each, printed in JSON and in
// text, holds no key of the instance's keyring, which it read for its ids
// and times, in base64 or hex; and the reads it took, the fetch plan and the
// manifest read before it among them, open no CA key, server key or client
// key. A plan into runTarget mints the applications' scopes (a guard: one
// that minted none would read no key id).
func runDeployPlansCarryNoKeyMaterial(t *testing.T) {
	for _, row := range runDeployRows(t) {
		t.Run(row.String(), func(t *testing.T) {
			_, dir := planFixture(t, row)
			encoded, raw := keyMaterialOf(t, dir, writeName)
			reads := observeConfigReads(t)
			_, js := runDeployPlan(t, dir, row, output.ModeJSON)
			_, text := runDeployPlan(t, dir, row, output.ModeHuman)
			if row.shape == "deploy into a metered namespace" && !strings.Contains(js, `"what":"app_scope"`) {
				t.Fatalf("guard: the deploy plan mints no scope: %s", js)
			}
			for i, key := range raw {
				for _, form := range []string{encoded[i], base64.StdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(key),
					base64.URLEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key), hex.EncodeToString(key)} {
					if strings.Contains(js, form) || strings.Contains(text, form) {
						t.Errorf("%s prints key %d of keys.yaml, as %s", row, i, form)
					}
				}
			}
			for _, p := range reads() {
				if base := filepath.Base(p); base == "ca.key" || base == "server.key" || base == "client.key" {
					t.Errorf("%s read %s", row, p)
				}
			}
		})
	}
}

// runDeployPlanChangedByThePolicy is TestConfirmRefusesAChangedPlan's row
// for run's deploy plan (row 74): the egress policy is written again
// between the plan and its --confirm, the same document, which the API
// server stores at a new resourceVersion. The deploy plan binds the policy
// at the version it read, so its digest moves, and --confirm of the old one
// refuses plan_changed, naming both, having read only as the reader and
// written nothing.
func runDeployPlanChangedByThePolicy(t *testing.T) {
	ran := strayKubectl(t)
	row, s, dir := runFixture(t)
	given := runDeployDigest(t, dir, row, nil)
	body, err := runOtherPolicy().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s.Put(map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": fldeploy.PolicyConfigMap, "namespace": fldeploy.DefaultNamespace},
		"data":     map[string]any{fldeploy.PolicyKey: string(body)}})
	if now := runDeployDigest(t, dir, row, nil); now == given {
		t.Fatalf("the deploy plan is %s before and after the policy's resourceVersion moved: it binds no version", now)
	}
	confirmRefusedAsChanged(t, row, s, dir, given)
	if ran() {
		t.Error("a changed deploy plan ran kubectl")
	}
}

// runDeployNoticesAreFacts is TestPlanPrintsNoticesOnlyAsFacts's row for
// run's deploy plan (A23-26, A28-8): with FatLine not deployed, the hosts
// the manifest declares are unreachable, which the review says. The deploy
// plan --confirm with the fetch plan's digest prints carries it as a notice
// fact, in JSON and in its rendering, with the hand-over's notice beside
// it, and prints neither on stderr. --confirm with the deploy plan's digest
// prints it once, right after the comparison, and stops here at applyReady,
// with no kubectl.
func runDeployNoticesAreFacts(t *testing.T) {
	row := runDeployRowNamed(t, "deploy into a metered namespace")
	row.edit = func(m *config.InstanceMetadata) {
		meterRunTarget(m)
		m.FatLineDeployed = false
	}
	_, dir := planFixture(t, row)
	notice := noWayOutWarning(writeName, mustManifest(t, twoAppManifest), false)
	if notice == "" {
		t.Fatal("guard: no notice to print")
	}
	for _, mode := range []output.Mode{output.ModeJSON, output.ModeHuman} {
		doc, text := runDeployPlan(t, dir, row, mode)
		if mode == output.ModeJSON {
			if got := noticesOf(decodedBound(t, doc)); !slices.Contains(got, notice) || !slices.Contains(got, msgRunHandOver) {
				t.Errorf("the deploy plan's notices are %q; want %q and the hand-over's among them", got, notice)
			}
		} else if want := strings.Join(noticeLines(noticeFact(notice)), "\n") + "\n"; !strings.Contains(text, want) {
			t.Errorf("the rendering does not show the notice %q:\n%s", want, text)
		}
	}
	doc, _ := runDeployPlan(t, dir, row, output.ModeJSON)
	noKubectl(t)
	cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", doc.Digest)...)
	env, _, errb := testEnvBoth(dir, output.ModeHuman)
	if err := cmd.Run(t.Context(), env, row.args); err == nil || !strings.Contains(err.Error(), msgCannotApply+msgKubectlMissing) {
		t.Fatalf("--confirm <D> = %v; want it past the comparison, at applyReady", err)
	}
	if got := strings.Count(errb.String(), notice+"\n"); got != 1 {
		t.Errorf("--confirm <D> printed the notice %d times; want once:\n%s", got, errb)
	}
}

// runBlock is one of run's blocks as its plans raise it (A23-18, A28-8):
// the row that raises it, its kind, and a phrase of the refusal it is, word
// for word.
type runBlock struct {
	row          planCommand
	kind, phrase string
}

// runBlocks are run's blocks: the fetch plan's, read from the record and
// keys.yaml, each internal — no kernel, a --namespace recorded under another
// repository, a keyring holding the shared application scope — and the
// deploy plan's, a namespace the kernel does not meter, forbidden, and no CA
// key, internal.
func runBlocks(t *testing.T) []runBlock {
	t.Helper()
	return []runBlock{
		{planCommandNamed(t, "run", "no kernel"), kindInternal, "has no kernel"},
		{planCommandNamed(t, "run", "a namespace recorded under another repository"), kindInternal,
			"Nothing was read, built or deployed. Pass --replace-repository to replace it"},
		{planCommandNamed(t, "run", "a keyring holding the shared application scope"), kindInternal,
			"shared before per-application scopes"},
		{runDeployRowNamed(t, "deploy into an unmetered namespace"), kindForbidden, fmt.Sprintf(msgUnmeteredNamespace, runTarget, writeName, runTarget)},
		{runDeployRowNamed(t, "deploy without the CA key"), kindInternal, noCAKey(writeName).Error()},
	}
}

// runPrintedPlan is row's plan as run prints it: --plan's, or, for its
// deploy plan, --confirm with the fetch plan's digest (runDeployPlan).
func runPrintedPlan(t *testing.T, dir config.Dir, row planCommand, mode output.Mode) (plan.Document, string) {
	t.Helper()
	if row.stage == "deploy" {
		return runDeployPlan(t, dir, row, mode)
	}
	return runPlan(t, dir, row, mode)
}

// runBlockedPlansAreRefusedWithTheirKind is
// TestABlockedPlanIsRefusedWithItsKind's rows for run (A23-7, A23-18,
// A28-8), each of runBlocks. Its plan — the fetch plan from --plan, the
// deploy plan from --confirm with the fetch plan's digest — prints its one
// block first, with no fact, and the blocked line in place of the confirm
// line. --confirm with its digest refuses with the block, exit 1, printing
// nothing, opening no writer and no keyholder, running no kubectl and
// writing nothing: the fetch plan's sends nothing, and the deploy plan's
// recomputes it as the reader, and sends nothing else.
func runBlockedPlansAreRefusedWithTheirKind(t *testing.T) {
	for _, tc := range runBlocks(t) {
		t.Run(tc.row.shape, func(t *testing.T) {
			ran := strayKubectl(t)
			row := tc.row
			s, dir := planFixture(t, row)
			doc, _ := runPrintedPlan(t, dir, row, output.ModeJSON)
			_, text := runPrintedPlan(t, dir, row, output.ModeHuman)
			b := decodedBound(t, doc)
			if len(b.Blocked) != 1 || b.Blocked[0].Kind != tc.kind || len(b.Facts) != 0 {
				t.Fatalf("%s's plan blocks %+v with %d facts; want one %s block and none", row, b.Blocked, len(b.Facts), tc.kind)
			}
			block := b.Blocked[0]
			first, _, _ := strings.Cut(block.Message, "\n")
			if !strings.HasPrefix(text, "blocked ("+tc.kind+"): "+output.ErrorText(first)) ||
				!strings.HasSuffix(text, "\ndigest: "+doc.Digest+"\nblocked: --confirm would refuse this plan ("+tc.kind+")\n") ||
				strings.Contains(text, "To do exactly this") {
				t.Errorf("%s's blocked plan prints:\n%s", row, text)
			}

			before, sent, writers := treeFiles(t, string(dir)), len(s.Requests()), row.fakes.writers
			cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", doc.Digest)...)
			env, out, _ := testEnvBoth(dir, output.ModeJSON)
			err := cmd.Run(t.Context(), env, row.args)
			if err == nil || err.Error() != block.Message || kindOf(classified(err)) != tc.kind || exitCodeOf(err) != 1 {
				t.Errorf("%s --confirm of the blocked plan = %v (kind %s, exit %d); want its block", row, err, kindOf(classified(err)), exitCodeOf(err))
			}
			if out.Len() != 0 || row.fakes.writers != writers || row.fakes.keyholders != 0 || ran() {
				t.Errorf("%s --confirm of the blocked plan printed %q, opened the writer %d times and the keyholder %d times, and ran kubectl %v",
					row, out, row.fakes.writers-writers, row.fakes.keyholders, ran())
			}
			onlyThePlansSent(t, row, s.Requests()[sent:], consentConfirm)
			sameFiles(t, "a blocked "+row.String(), before, treeFiles(t, string(dir)))
		})
	}
}

// runDeployHostileText is TestPlanRenderingQuotesHostileText's row for
// run's deploy plan (ADR 0023 M2.6d): farcast-system's uid and the fetch
// Job's, which the cluster answers, the header and the run fact bind, and
// each prints Go-quoted in the rendering, never raw.
func runDeployHostileText(t *testing.T) {
	const hostileUID = "uid\x1b[2Jevil\u202etxt"
	const hostileJobUID = "job\x1b]0;title\x07\u202euid"
	row := runDeployRowNamed(t, "deploy into a metered namespace")
	seed := row.seed
	row.seed = func(s *kubetest.Server) {
		seed(s)
		s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{
			"name": tcdeploy.DefaultNamespace, "uid": hostileUID}})
		finishedJob(s, stageFetchJob(), hostileJobUID, "fetch", reportFor(twoAppManifest), twoAppManifest)
	}
	_, dir := planFixture(t, row)
	_, text := runDeployPlan(t, dir, row, output.ModeHuman)
	for _, raw := range []string{"\x1b", "\x07", "\u202e"} {
		if strings.Contains(text, raw) {
			t.Errorf("the deploy plan prints %q raw:\n%q", raw, text)
		}
	}
	for _, want := range []string{"; farcast-system " + terminalText(hostileUID) + "\n", "(Job uid " + terminalText(hostileJobUID) + ")"} {
		if !strings.Contains(text, want) {
			t.Errorf("the deploy plan should hold %q:\n%s", want, text)
		}
	}
}

// runConfirmLinesRunTheSameCommand is TestTheConfirmLineRunsTheSameCommand's
// row for run's deploy plan through run() (A23-17): the fetch plan's line,
// run with the succeeding stand-in kubectl, runs the manifest read and
// prints the deploy plan, whose own line drops the fetch plan's --confirm
// and confirms the deploy plan's digest alone. That line, run with no
// kubectl, computes the same deploy plan as the reader and stops at
// applyReady, past the comparison, having sent only the reader's reads.
// run's clock is pinned at runClock (pinRunClock), so the deploy plan binds
// runSeed's ledger as fresh and below the limit, as the direct rows do.
func runConfirmLinesRunTheSameCommand(t *testing.T) {
	pinRunClock(t)
	row, s, dir := runFixture(t)
	wc := writeCommand{name: row.name, args: row.args, flags: row.flags}
	stdout, stderr, code := runLine(commandLine(dir, wc, "--plan"))
	if code != 0 {
		t.Fatalf("run --plan: exit %d, %s", code, stderr)
	}
	fetch := digestLine(t, stdout)
	words := shellWords(t, confirmLineOf(stdout))
	succeedingKubectl(t)
	stdout, stderr, code = runLine(words)
	if code != 0 {
		t.Fatalf("the fetch plan's confirm line %q: exit %d, %s", words, code, stderr)
	}
	if !strings.Contains(stdout, "\n  the instance's spending is not at its limit\n") {
		t.Fatalf("the deploy plan through the router does not bind the limit as not reached (run's clock unpinned?):\n%s", stdout)
	}
	deploy := digestLine(t, stdout)
	words = shellWords(t, confirmLineOf(stdout))
	if len(words) < 3 || words[0] != "farcast" || words[len(words)-2] != "--confirm" || words[len(words)-1] != deploy ||
		slices.Contains(words, fetch) || slices.Contains(words, "--plan") || deploy == fetch {
		t.Fatalf("the deploy plan's confirm line is %q; want the command again, confirming %s alone", words, deploy)
	}
	noKubectl(t)
	sent := len(s.Requests())
	_, stderr, code = runLine(words)
	if strings.Contains(stderr, "the plan for this command is now") {
		t.Fatalf("the deploy plan's confirm line computed another plan: %s", stderr)
	}
	if code != 1 || !strings.Contains(stderr, msgCannotApply+msgKubectlMissing) {
		t.Errorf("the deploy plan's confirm line: exit %d, %q; want it past the comparison, at applyReady", code, stderr)
	}
	onlyThePlansSent(t, row, s.Requests()[sent:], consentConfirm)
}
