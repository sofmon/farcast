package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/planck"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// ADR 0023 M2.5: the writing commands read the cluster, and write the
// storage key pin, in-process as the instance's writer, the installer's
// stored service-account key (design §7.3, A20-18). Until M2.7 their applies
// still run kubectl as the active gcloud configuration, so every test here
// that drives a command past its writer open pins PATH to a directory with
// no kubectl in it, or with a stand-in that must never run (A20-15): no
// test runs a real one.

// writeName is the instance the writing commands' fixtures record.
const writeName = "atlas"

// writeNewNamespace is a namespace the fixture's kernel does not meter yet,
// so kernel meter has one to add.
const writeNewNamespace = "extra"

// writeInstance is readerInstance (a loopback instance against s, its reader
// granted, its writer's credentials.yaml registered with s under id
// "writer") with everything each writing command checks before it opens the
// writer: a registry, a kernel and a cost limit, FatLine behind a carrier, a
// keyholder, storage and a keyring, and the kubeconfig.yaml install writes,
// which a writer's transitional kubectl Apply reads. keyed false rewrites
// credentials.yaml as an install with Application Default Credentials wrote
// it: a provider and no key.
func writeInstance(t *testing.T, s *kubetest.Server, keyed bool) (config.Dir, *config.InstanceMetadata) {
	t.Helper()
	dir, meta := readerInstance(t, s, writeName, true)
	meta.Registry = &config.Registry{Prefix: "us-central1-docker.pkg.dev/proj-test1/farcast-" + writeName}
	meta.Kernel = &config.Kernel{Deployed: true, Applied: true, Namespaces: []string{tcdeploy.DefaultNamespace}}
	meta.CostLimit = config.CostLimit{Amount: 100, Currency: "USD", Period: "monthly"}
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "9.9.9.9:8443", ServerName: identity.ServerName(writeName)}
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	meta.Storage = &config.Storage{Bucket: "b", Provider: "gcs", Location: "us-central1"}
	if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, dir, writeName, appsKeyring(t, "web"))
	if err := dir.SaveInstanceKubeconfig(writeName, []byte("apiVersion: v1\nkind: Config\n")); err != nil {
		t.Fatal(err)
	}
	if !keyed {
		if err := dir.SaveInstanceCredentials(writeName, &config.InstanceCredentials{Provider: "gke"}); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	return dir, loaded
}

// noKeyholder is a keyholder opener with no tunnel behind it.
func noKeyholder(context.Context, *Env, string) (sealStateClient, func(), error) {
	return nil, nil, errors.New("no tunnel in this test")
}

// writeCommand is one cluster-writing command as these tests run it: fresh
// each time, its flags parsed from flags, and every cluster seam left nil,
// so it opens the cluster through openCluster as the writer, exactly as
// farcast does. Only seams that would leave this machine otherwise (the
// keyholder's tunnel) or ask a terminal (reader grant's) are set.
type writeCommand struct {
	name  string
	args  []string
	flags []string
	cmd   func() Command
	// edit changes the fixture's record for a command that needs it
	// otherwise: connect deploys only into an instance not yet connected.
	edit func(meta *config.InstanceMetadata)
}

// writeCommands is the eleven commands that write to an instance's cluster.
func writeCommands() []writeCommand {
	return []writeCommand{
		{"connect", []string{writeName}, nil, func() Command { return newConnectCommand() },
			func(m *config.InstanceMetadata) { m.FatLineDeployed, m.Carrier = false, nil }},
		{"redeploy", []string{writeName}, nil, func() Command { return newRedeployCommand() }, nil},
		{"build", []string{writeName}, []string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest, "--yes"},
			func() Command { return &buildCommand{} }, nil},
		{"run", []string{writeName, "github.com/example/my-platform"}, []string{"--fetcher-image", fetcherDigest, "--builder-image", builderDigest, "--yes"},
			func() Command { return &runCommand{newKeyholder: noKeyholder} }, nil},
		{"kernel deploy", []string{writeName}, []string{"--yes"}, func() Command { return &kernelDeployCommand{} }, nil},
		{"kernel meter", []string{writeName, writeNewNamespace}, nil, func() Command { return &kernelMeterCommand{} }, nil},
		{"kernel confirm", []string{writeName}, []string{"--amount", "1", "--from", thisMonth(1), "--to", thisMonth(2)},
			func() Command { return &kernelConfirmCommand{} }, nil},
		{"storage deploy", []string{writeName}, []string{"--yes"}, func() Command { return &storageDeployCommand{} }, nil},
		{"storage key pin", []string{writeName}, nil, func() Command { return &keyPinCommand{newKeyholder: noKeyholder} }, nil},
		{"storage key rotate", []string{writeName}, []string{"--yes"}, func() Command { return &keyRotateCommand{newKeyholder: noKeyholder} }, nil},
		{"reader grant", []string{writeName}, nil, func() Command {
			return &readerGrantCommand{interactive: func(*Env) bool { return true }}
		}, nil},
	}
}

// writeCommandNamed is the one writeCommands row called name.
func writeCommandNamed(t *testing.T, name string) writeCommand {
	t.Helper()
	for _, wc := range writeCommands() {
		if wc.name == name {
			return wc
		}
	}
	t.Fatalf("no writing command %q", name)
	return writeCommand{}
}

// runWrite runs wc against dir in JSON mode, as the router would, and
// returns what it printed and its error. A prompt, if one were reached, is
// answered yes.
func runWrite(t *testing.T, dir config.Dir, wc writeCommand) (out, errb []byte, err error) {
	t.Helper()
	cmd := wc.cmd()
	fset := flag.NewFlagSet(wc.name, flag.ContinueOnError)
	cmd.SetFlags(fset)
	if err := fset.Parse(wc.flags); err != nil {
		t.Fatal(err)
	}
	env, o, e := testEnvBoth(dir, output.ModeJSON)
	env.In = strings.NewReader("y\n")
	err = cmd.Run(t.Context(), env, wc.args)
	return o.Bytes(), e.Bytes(), err
}

// noKubectl pins PATH to an empty directory for the rest of the test, so a
// writer's Apply finds no kubectl and none runs (A20-15).
func noKubectl(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

// strayKubectl pins PATH, for the rest of the test, to a directory holding a
// kubectl that must never run: it records that it ran and fails. It is for
// the tests that drive a command past its writer's local Apply check
// (applyReady) to an in-process failure, which no kubectl should follow.
// ran reports whether it ran.
func strayKubectl(t *testing.T) (ran func() bool) {
	t.Helper()
	bin, marker := t.TempDir(), filepath.Join(t.TempDir(), "ran")
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte("#!/bin/sh\n: > '"+marker+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}
}

// realPinOpener makes the commands without a pin seam of their own reach the
// pin through openPinStore, the writer, for the rest of the test, in place of
// the in-memory pins every other test gets, and restores those after.
func realPinOpener(t *testing.T) {
	t.Helper()
	saved := defaultPinStore
	defaultPinStore = openPinStore
	t.Cleanup(func() { defaultPinStore = saved })
}

// treeFiles is every file under root, by its path below root, with its bytes.
func treeFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// The pin's ConfigMap, as the API addresses it.
var (
	pinPath        = "/api/v1/namespaces/" + dsdeploy.DefaultNamespace + "/configmaps/" + dsdeploy.PinConfigMapName("")
	configMapsPath = "/api/v1/namespaces/" + dsdeploy.DefaultNamespace + "/configmaps"
)

// msgADCRefused is the start of openCluster's refusal of an instance
// installed with Application Default Credentials.
const msgADCRefused = `instance "atlas" was installed without a service-account key (Application Default Credentials)`

// The writer's sentence for a 403 (A20-9), by the 403's shape.
const (
	msgWriterRBACRefused = `; the cluster refused instance "atlas"'s installer service account (RBAC); check that it still holds roles/container.admin in project "proj-test1"`
	msgWriterIAMRefused  = `; the cluster's endpoint refused instance "atlas"'s installer service account (IAM); check that it still holds roles/container.admin in project "proj-test1"`
)

// kube-shaped failures, as the cluster client returns them.
var (
	errStalled = fmt.Errorf("deployment %q exceeded its progress deadline: %w", "fatline", kube.ErrRolloutStalled)
	errWaited  = fmt.Errorf("deployment farcast-system/fatline did not finish rolling out within 3m0s: %w", kube.ErrTimedOut)
	errServer  = &kube.APIError{Method: http.MethodGet, Path: "/apis/apps/v1/namespaces/farcast-system/deployments/fatline",
		Status: kube.Status{Status: tkube.Status{Code: http.StatusInternalServerError, Reason: "InternalError", Message: "etcd is unhappy"}}, KubernetesStatus: true}
	errRBAC = &kube.APIError{Method: http.MethodGet, Path: "/api/v1/namespaces",
		Status: kube.Status{Status: tkube.Status{Code: http.StatusForbidden, Reason: "Forbidden", Message: `namespaces is forbidden: User "writer@kubetest.invalid" cannot list resource "namespaces"`}}, KubernetesStatus: true}
)

// ADR 0023 M2.5 (§10.5 row 69, A20-16; mutations 69, 69a, 69b and 71f):
// every failure of a writing command's in-process cluster call reaches its
// envelope with the cluster's kind, and a 403 says, once, whose it was.
// Only failures that reach an envelope are claimed: run's and kernel
// deploy's rollout waits, build's JobLogs, run's pin raise and rotate's pin
// failure warn or are swallowed by design. kubectl is a stand-in that must
// never run: every in-process failure here comes before any apply.
func TestWritingCommandsCarryClusterKinds(t *testing.T) {
	ran := strayKubectl(t)
	realPinOpener(t)
	t.Cleanup(func() {
		if ran() {
			t.Error("a writing command ran kubectl after an in-process failure")
		}
	})

	// Every command, on an instance installed without a key: refused at the
	// writer's open, credential_missing, before anything is sent, run,
	// asked, minted, pushed or recorded. storage key rotate is the exception
	// by design (A20-10): it rotates without the pin, as its help says, and
	// its unfinished rotation is internal.
	t.Run("credential_missing", func(t *testing.T) {
		for _, wc := range writeCommands() {
			t.Run(wc.name, func(t *testing.T) {
				s := kubetest.New(t)
				dir, meta := writeInstance(t, s, false)
				if wc.edit != nil {
					wc.edit(meta)
					if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
						t.Fatal(err)
					}
				}
				before := treeFiles(t, string(dir))
				_, errb, err := runWrite(t, dir, wc)
				if got := len(s.Requests()); got != 0 {
					t.Errorf("%s sent %d requests for an instance with no installer key", wc.name, got)
				}
				if wc.name == "storage key rotate" {
					if err == nil || kindOf(classified(err)) != kindInternal || errors.Is(err, errCredentialMissing) {
						t.Errorf("rotate without a reachable pin = %v (kind %q); want its documented unfinished rotation, internal", err, kindOf(classified(err)))
					}
					return
				}
				if !errors.Is(err, errCredentialMissing) || !strings.Contains(err.Error(), msgADCRefused) {
					t.Fatalf("%s = %v; want openCluster's refusal of an ADC install", wc.name, err)
				}
				if kind := kindOf(classified(err)); kind != kindCredentialMissing {
					t.Errorf("%s's envelope says %q, want %q", wc.name, kind, kindCredentialMissing)
				}
				if bytes.Contains(errb, []byte("[y/N]")) {
					t.Errorf("%s asked before refusing: %s", wc.name, errb)
				}
				sameFiles(t, wc.name+" on an ADC instance", before, treeFiles(t, string(dir)))
			})
		}
	})

	// kernel deploy's first in-process call is its Namespaces read.
	kernelDeploy := writeCommandNamed(t, "kernel deploy")
	for _, row := range []struct {
		name     string
		opts     []kubetest.Option
		inject   func(s *kubetest.Server)
		kind     string
		sentence string // the writer's 403 sentence, which must appear once
	}{
		{"forbidden by RBAC", nil, func(s *kubetest.Server) {
			s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusForbidden, kube.Status{})
		}, kindForbidden, msgWriterRBACRefused},
		{"forbidden at the endpoint", nil, func(s *kubetest.Server) {
			s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusForbidden, kube.Status{Status: tkube.Status{Kind: "GoogleError", Message: "Permission denied"}})
		}, kindForbidden, msgWriterIAMRefused},
		{"two 401s", nil, func(s *kubetest.Server) {
			s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusUnauthorized, kube.Status{})
			s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusUnauthorized, kube.Status{})
		}, kindUnauthorized, ""},
		{"a refused mint", []kubetest.Option{kubetest.WithTokenAnswer(func(email string) (int, []byte, bool) {
			return http.StatusBadRequest, []byte(`{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`), true
		})}, nil, kindCredentialRefused, ""},
	} {
		t.Run("kernel deploy/"+row.name, func(t *testing.T) {
			s := kubetest.New(t, row.opts...)
			dir, _ := writeInstance(t, s, true)
			if row.inject != nil {
				row.inject(s)
			}
			_, _, err := runWrite(t, dir, kernelDeploy)
			if kind := kindOf(classified(err)); kind != row.kind {
				t.Fatalf("kernel deploy = %v; kind %q, want %q", err, kind, row.kind)
			}
			if !strings.Contains(err.Error(), "list the instance's namespaces: ") {
				t.Errorf("kernel deploy = %v; want its Namespaces read's failure", err)
			}
			msg := err.Error()
			for _, sentence := range []string{msgWriterRBACRefused, msgWriterIAMRefused} {
				want := 0
				if sentence == row.sentence {
					want = 1
				}
				if got := strings.Count(msg, sentence); got != want {
					t.Errorf("kernel deploy = %q;\nsays %q %d times, want %d", msg, sentence, got, want)
				}
			}
			for _, r := range s.Requests() {
				if r.As != "writer" && r.Path != "/token" {
					t.Errorf("%s %s as %q; want the writer", r.Method, r.Path, r.As)
				}
			}
		})
	}

	// The first pin read refused. A 500: storage deploy and storage key pin
	// say cluster_rejected; rotate goes on without the pin, by design. A 403
	// (C-F2, mutation 69b for these two): the pin read is their first
	// in-process call, so they say forbidden, with the writer's sentence once
	// by the 403's shape, and mint once.
	iamShaped := kube.Status{Status: tkube.Status{Kind: "GoogleError", Message: "Permission denied"}}
	for _, row := range []struct {
		name     string
		answer   string
		code     int
		status   kube.Status
		kind     string
		sentence string // the writer's 403 sentence, which must appear once
	}{
		{"storage deploy", "answering 500", http.StatusInternalServerError, kube.Status{}, kindClusterRejected, ""},
		{"storage key pin", "answering 500", http.StatusInternalServerError, kube.Status{}, kindClusterRejected, ""},
		{"storage key rotate", "answering 500", http.StatusInternalServerError, kube.Status{}, kindInternal, ""},
		{"storage deploy", "forbidden by RBAC", http.StatusForbidden, kube.Status{}, kindForbidden, msgWriterRBACRefused},
		{"storage deploy", "forbidden at the endpoint", http.StatusForbidden, iamShaped, kindForbidden, msgWriterIAMRefused},
		{"storage key pin", "forbidden by RBAC", http.StatusForbidden, kube.Status{}, kindForbidden, msgWriterRBACRefused},
		{"storage key pin", "forbidden at the endpoint", http.StatusForbidden, iamShaped, kindForbidden, msgWriterIAMRefused},
	} {
		t.Run(row.name+"/the pin read "+row.answer, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, true)
			s.Fail(http.MethodGet, pinPath, row.code, row.status)
			_, _, err := runWrite(t, dir, writeCommandNamed(t, row.name))
			if kind := kindOf(classified(err)); kind != row.kind {
				t.Fatalf("%s = %v; kind %q, want %q", row.name, err, kind, row.kind)
			}
			if row.kind != kindInternal && !strings.Contains(err.Error(), "read the key pin: ") {
				t.Errorf("%s = %v; want the pin read's failure", row.name, err)
			}
			if row.kind != kindInternal {
				msg := err.Error()
				for _, sentence := range []string{msgWriterRBACRefused, msgWriterIAMRefused} {
					want := 0
					if sentence == row.sentence {
						want = 1
					}
					if got := strings.Count(msg, sentence); got != want {
						t.Errorf("%s = %q;\nsays %q %d times, want %d", row.name, msg, sentence, got, want)
					}
				}
			}
			mints := 0
			for _, r := range s.Requests() {
				if r.Method != http.MethodGet && r.Method != http.MethodPost {
					t.Errorf("%s sent %s %s after the pin read failed", row.name, r.Method, r.Path)
				}
				if r.Path == "/token" {
					mints++
				} else if r.As != "writer" {
					t.Errorf("%s %s as %q; want the writer", r.Method, r.Path, r.As)
				}
			}
			if row.kind != kindInternal && mints != 1 {
				t.Errorf("%s minted %d tokens; one writer mints once", row.name, mints)
			}
		})
	}

	// writePin's three attempts, each answered 409: cluster_rejected.
	t.Run("storage key pin/three conflicts", func(t *testing.T) {
		s := kubetest.New(t)
		dir, _ := writeInstance(t, s, true)
		for range 3 {
			s.Fail(http.MethodPost, configMapsPath, http.StatusConflict, kube.Status{Status: tkube.Status{Reason: "AlreadyExists"}})
		}
		_, _, err := runWrite(t, dir, writeCommandNamed(t, "storage key pin"))
		if kind := kindOf(classified(err)); kind != kindClusterRejected || !strings.Contains(err.Error(), "the key pin changed while this command wrote it") {
			t.Fatalf("storage key pin = %v; kind %q, want %q after three conflicts", err, kind, kindClusterRejected)
		}
		var posts int
		for _, r := range s.Requests() {
			if r.Method == http.MethodPost && r.Path == configMapsPath {
				posts++
			}
			if r.Method == http.MethodPatch || r.Method == http.MethodPut {
				t.Errorf("storage key pin sent %s %s", r.Method, r.Path)
			}
		}
		if posts != 3 {
			t.Errorf("storage key pin created %d times; want writePin's 3 attempts", posts)
		}
	})

	// kubectl missing from the pinned PATH: the transitional Apply's own
	// refusal, found by applyReady before anything is recorded (S-F2),
	// internal until ADR 0023 M2.7. kernel confirm makes no in-process call,
	// so the cluster sees nothing.
	t.Run("kernel confirm/no kubectl", func(t *testing.T) {
		noKubectl(t)
		s := kubetest.New(t)
		dir, _ := writeInstance(t, s, true)
		_, _, err := runWrite(t, dir, writeCommandNamed(t, "kernel confirm"))
		if kind := kindOf(classified(err)); err == nil || kind != kindInternal || !strings.Contains(err.Error(), msgCannotApply+msgKubectlMissing) {
			t.Fatalf("kernel confirm with no kubectl = %v; kind %q, want %q", err, kind, kindInternal)
		}
		if got := len(s.Requests()); got != 0 {
			t.Errorf("kernel confirm sent %d requests; its writer makes no in-process call", got)
		}
		after, err := dir.LoadInstanceMetadata(writeName)
		if err != nil {
			t.Fatal(err)
		}
		if len(after.Kernel.Confirmations) != 0 {
			t.Errorf("a confirmation that was never pushed is recorded: %+v", after.Kernel.Confirmations)
		}
	})

	// connect, redeploy, build and run, with fakes: the preflight read
	// refused, before anything is applied; and kube-shaped failures after
	// the first Apply.
	for _, d := range deployingCommands() {
		t.Run(d.name+"/the preflight read refused", func(t *testing.T) {
			r := d.setup(t, nil, errRBAC)
			err := r.run()
			if kind := kindOf(classified(err)); kind != kindForbidden {
				t.Fatalf("%s = %v; kind %q, want %q", d.name, err, kind, kindForbidden)
			}
			if !strings.Contains(err.Error(), "before changing anything, read the instance's cluster as its installer service account: ") ||
				strings.Count(err.Error(), msgWriterProdRBACRefused) != 1 {
				t.Errorf("%s = %q; want the preflight's failure with the writer's sentence once", d.name, err)
			}
			if got := r.applied(); got != 0 || r.preflights() != 1 {
				t.Errorf("%s applied %d streams after %d preflight reads; want none after one", d.name, got, r.preflights())
			}
			if r.ensured() != 0 || r.pushed() != 0 {
				t.Errorf("%s ensured the registry %d times and pushed %d images before the preflight", d.name, r.ensured(), r.pushed())
			}
		})
		for _, after := range []struct {
			err  error
			kind string
		}{
			{errStalled, kindRolloutStalled},
			{errWaited, kindTimeout},
			{errServer, kindClusterRejected},
		} {
			t.Run(d.name+"/"+after.kind+" after the apply", func(t *testing.T) {
				r := d.setup(t, after.err, nil)
				err := r.run()
				if kind := kindOf(classified(err)); kind != after.kind {
					t.Fatalf("%s = %v; kind %q, want %q", d.name, err, kind, after.kind)
				}
				if r.applied() == 0 || r.preflights() != 1 {
					t.Errorf("%s failed before it applied (%d) or read %d times first", d.name, r.applied(), r.preflights())
				}
			})
		}
	}
}

// msgWriterProdRBACRefused is the writer's RBAC sentence for the deploying
// commands' fixtures, which record instance "prod" with no project.
const msgWriterProdRBACRefused = `; the cluster refused instance "prod"'s installer service account (RBAC); check that it still holds roles/container.admin in project ""`

// deploying is one deploying command set up with fakes for its cluster, its
// provider and its builder: what it did, as the fakes saw it.
type deploying struct {
	run        func() error
	applied    func() int
	preflights func() int
	ensured    func() int
	pushed     func() int
}

// deployingCommand is connect, redeploy, build or run, each set up so that
// failAfter (if not nil) is what its cluster answers after the first Apply,
// and failPreflight what its preflight read answers.
type deployingCommand struct {
	name  string
	setup func(t *testing.T, failAfter, failPreflight error) deploying
}

func deployingCommands() []deployingCommand {
	builderPushes := func(b *fakeBuilder) int { return len(b.built) + len(b.embedded) }
	return []deployingCommand{
		{"connect", func(t *testing.T, failAfter, failPreflight error) deploying {
			dir := config.Dir(t.TempDir())
			installedInstance(t, dir, "prod")
			fc := &fakeCluster{ip: "34.0.0.1", rolloutErr: failAfter, uidErr: failPreflight}
			fp, fb := &fakeProvider{}, &fakeBuilder{}
			c := testConnect(fp, fb)
			c.assumeYes = true
			c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
			c.dial = connectedDial()
			env, _ := testEnv(dir, output.ModeJSON)
			return deploying{
				run:        func() error { return c.Run(context.Background(), env, []string{"prod"}) },
				applied:    func() int { return len(fc.applied) },
				preflights: func() int { return fc.uidReads },
				ensured:    func() int { return len(fp.ensured) },
				pushed:     func() int { return builderPushes(fb) },
			}
		}},
		{"redeploy", func(t *testing.T, failAfter, failPreflight error) deploying {
			dir := config.Dir(t.TempDir())
			connectedInstance(t, dir, "prod")
			fc := &fakeCluster{rolloutErr: failAfter, uidErr: failPreflight}
			fp, fb := &fakeProvider{}, &fakeBuilder{}
			c := testRedeploy(fp, fb)
			c.assumeYes = true
			c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
			env, _ := testEnv(dir, output.ModeJSON)
			return deploying{
				run:        func() error { return c.Run(context.Background(), env, []string{"prod"}) },
				applied:    func() int { return len(fc.applied) },
				preflights: func() int { return fc.uidReads },
				ensured:    func() int { return len(fp.ensured) },
				pushed:     func() int { return builderPushes(fb) },
			}
		}},
		{"build", func(t *testing.T, failAfter, failPreflight error) deploying {
			dir := config.Dir(t.TempDir())
			meteringInstance(t, dir, "prod")
			fj := &fakeJobs{waitErr: failAfter, uidErr: failPreflight}
			fb := &fakeBuilder{}
			c := buildCmd(fj)
			c.newBuilder = func(func(string)) imageBuilder { return fb }
			c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
			env, _ := testEnv(dir, output.ModeJSON)
			return deploying{
				run:        func() error { return c.Run(context.Background(), env, []string{"prod"}) },
				applied:    func() int { return len(fj.applied) },
				preflights: func() int { return fj.uidReads },
				ensured:    func() int { return 0 },
				pushed:     func() int { return builderPushes(fb) + len(fb.resolved) },
			}
		}},
		{"run", func(t *testing.T, failAfter, failPreflight error) deploying {
			dir := config.Dir(t.TempDir())
			runnableInstance(t, dir, "prod")
			f := newFakeRun(twoAppManifest)
			f.waitErr, f.uidErr = failAfter, failPreflight
			fb := &fakeBuilder{}
			c := runCmd(f)
			c.newBuilder = func(func(string)) imageBuilder { return fb }
			env, _ := testEnv(dir, output.ModeJSON)
			return deploying{
				run: func() error {
					return c.Run(context.Background(), env, []string{"prod", "github.com/example/my-platform"})
				},
				applied:    func() int { return len(f.applied) },
				preflights: func() int { return f.uidReads },
				ensured:    func() int { return 0 },
				pushed:     func() int { return builderPushes(fb) + len(fb.resolved) },
			}
		}},
	}
}

// ADR 0023 M2.5 (A20-10), mutation 71a: kernel meter and kernel confirm
// open the writer before they change the record. On an instance installed
// without a key the open refuses, so metadata.yaml stays byte for byte what
// it was, and nothing is applied: a record that named namespaces, or held a
// confirmation, the cluster was never told of would be skipped by the next
// change for good.
func TestKernelMeterAndConfirmRefuseAnADCInstanceBeforeTheyRecord(t *testing.T) {
	noKubectl(t)
	for _, name := range []string{"kernel meter", "kernel confirm"} {
		t.Run(name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := writeInstance(t, s, false)
			record := filepath.Join(dir.InstancePath(writeName), "metadata.yaml")
			before, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = runWrite(t, dir, writeCommandNamed(t, name))
			if !errors.Is(err, errCredentialMissing) || !strings.Contains(err.Error(), msgADCRefused) {
				t.Fatalf("%s = %v; want the ADC install refused", name, err)
			}
			after, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Errorf("%s changed metadata.yaml before it refused:\nbefore:\n%s\nafter:\n%s", name, before, after)
			}
			if got := len(s.Requests()); got != 0 {
				t.Errorf("%s sent %d requests", name, got)
			}
		})
	}
}

// ADR 0023 M2.5 (A20-10), mutation 71b: connect, redeploy, build and run
// open the writer before anything costs, is asked or is minted. On an
// instance installed without a key each refuses credential_missing through
// its default cluster seam, and the fakes behind its other seams show what
// it never reached: connect minted no CA and asked no cost question (none
// is answered here, so asking would have been its refusal instead), none
// ensured the registry, resolved or pushed an image, and the cluster saw
// nothing.
func TestWritersRefuseAnADCInstanceBeforeAnythingCosts(t *testing.T) {
	noKubectl(t)
	for _, name := range []string{"connect", "redeploy", "build", "run"} {
		t.Run(name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, meta := writeInstance(t, s, false)
			fp, fb := &fakeProvider{}, &fakeBuilder{}
			opened := 0
			open := func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
				opened++
				return fp, nil
			}
			var cmd func(env *Env) error
			switch name {
			case "connect":
				meta.FatLineDeployed, meta.Carrier = false, nil
				if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
					t.Fatal(err)
				}
				c := testConnect(fp, fb)
				c.openProvider = open
				c.dial = connectedDial()
				cmd = func(env *Env) error { return c.Run(t.Context(), env, []string{writeName}) }
			case "redeploy":
				c := testRedeploy(fp, fb)
				c.openProvider = open
				cmd = func(env *Env) error { return c.Run(t.Context(), env, []string{writeName}) }
			case "build":
				c := &buildCommand{repo: "https://github.com/example/repo.git", app: "api", builderImage: "cgr.dev/chainguard/kaniko:latest"}
				c.newBuilder = func(func(string)) imageBuilder { return fb }
				cmd = func(env *Env) error { return c.Run(t.Context(), env, []string{writeName}) }
			case "run":
				c := &runCommand{newKeyholder: noKeyholder, fetcherImage: "alpine/git:latest", builderImage: "cgr.dev/chainguard/kaniko:latest"}
				c.newBuilder = func(func(string)) imageBuilder { return fb }
				cmd = func(env *Env) error {
					return c.Run(t.Context(), env, []string{writeName, "github.com/example/my-platform"})
				}
			}
			before := treeFiles(t, string(dir))
			env, _, errb := testEnvBoth(dir, output.ModeHuman)
			err := cmd(env)
			if !errors.Is(err, errCredentialMissing) || !strings.Contains(err.Error(), msgADCRefused) {
				t.Fatalf("%s = %v; want the ADC install refused at the writer's open", name, err)
			}
			if opened != 0 || len(fp.ensured) != 0 {
				t.Errorf("%s opened the provider %d times and ensured the registry %d times", name, opened, len(fp.ensured))
			}
			if len(fb.resolved)+len(fb.built)+len(fb.embedded) != 0 {
				t.Errorf("%s resolved %v, built %d and pushed %d images", name, fb.resolved, len(fb.built), len(fb.embedded))
			}
			if exists, _ := dir.InstanceMTLSExists(writeName); exists {
				t.Errorf("%s minted the instance's CA", name)
			}
			if errb.Len() != 0 {
				t.Errorf("%s wrote %q before it refused", name, errb)
			}
			if got := len(s.Requests()); got != 0 {
				t.Errorf("%s sent %d requests", name, got)
			}
			sameFiles(t, name+" on an ADC instance", before, treeFiles(t, string(dir)))
		})
	}
}

// ADR 0023 M2.5 (A20-12), mutation 71c: each writing command checks that the
// record it loaded names the instance it was given, before the writer opens:
// openCluster reads credentials.yaml, and hands kubectl kubeconfig.yaml,
// under the recorded name. A record naming another instance is refused as
// errCredentialMissing with recordNamed's words; credentials.yaml is never
// read and nothing is sent.
func TestWritingCommandsRefuseARecordNamingAnotherInstance(t *testing.T) {
	noKubectl(t)
	realPinOpener(t)
	for _, wc := range writeCommands() {
		t.Run(wc.name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, meta := writeInstance(t, s, true)
			if wc.edit != nil {
				wc.edit(meta)
			}
			meta.Name = "other"
			if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
				t.Fatal(err)
			}
			reads := observeConfigReads(t)
			_, _, err := runWrite(t, dir, wc)
			want := fmt.Sprintf("instance %q's record names the instance %q; farcast renders nothing from it", writeName, "other")
			if !errors.Is(err, errCredentialMissing) || err.Error() != want {
				t.Fatalf("%s = %v; want %q", wc.name, err, want)
			}
			for _, p := range reads() {
				if filepath.Base(p) == "credentials.yaml" {
					t.Errorf("%s read %s for a record naming another instance", wc.name, p)
				}
			}
			if got := len(s.Requests()); got != 0 {
				t.Errorf("%s sent %d requests", wc.name, got)
			}
		})
	}
}

// ADR 0023 M2.5 (A20-14): storage key pin through the real pin opener, as a
// loopback writer against kubetest. With a pin already there at a
// resourceVersion, the replace is a PUT whose body carries exactly that
// resourceVersion, every request is the writer's, and nothing is PATCHed:
// the pin is never applied.
func TestKeyPinWritesThroughTheRealPinOpener(t *testing.T) {
	noKubectl(t)
	realPinOpener(t)
	s := kubetest.New(t)
	dir, _ := writeInstance(t, s, true)
	// The pin requires the keys of the keyring's one application scope; the
	// keyring has gained a second scope since, so the command raises the pin.
	first, err := keyringOf(&Env{ConfigDir: dir}, writeName)
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.AddScope(mustAppScope(t, "api"))
	if err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, dir, writeName, second)
	partial := pinFor(first)
	s.Put(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": dsdeploy.PinConfigMapName(""), "namespace": dsdeploy.DefaultNamespace},
		"data":     map[string]any{dsdeploy.PinKey: string(partial.Marshal())},
	})
	// The resourceVersion the pin is at, read as the writer before the
	// command runs.
	c, err := openCluster(clusterRef{Dir: dir, Meta: &config.InstanceMetadata{Name: writeName, Provider: "gke", Project: "proj-test1", Region: "us-central1", Endpoint: s.Endpoint()},
		Identity: kube.Writer, Warn: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	_, rv, found, err := c.ConfigMapData(t.Context(), dsdeploy.DefaultNamespace, dsdeploy.PinConfigMapName(""))
	if err != nil || !found || rv == "" {
		t.Fatalf("the pin as stored: rv %q, found %v, %v", rv, found, err)
	}
	seen := len(s.Requests())

	_, errb, err := runWrite(t, dir, writeCommandNamed(t, "storage key pin"))
	if err != nil {
		t.Fatalf("storage key pin: %v\nstderr: %s", err, errb)
	}
	var puts int
	for _, r := range s.Requests()[seen:] {
		if r.As != "writer" {
			t.Errorf("%s %s as %q; want the writer", r.Method, r.Path, r.As)
		}
		switch {
		case r.Method == http.MethodPut && r.Path == pinPath:
			puts++
			if got := bodyResourceVersion(t, r.Body); got != rv {
				t.Errorf("the PUT carries resourceVersion %q; want %q, the one read", got, rv)
			}
			if !strings.Contains(r.RawQuery, "fieldManager=farcast") {
				t.Errorf("the PUT names no field manager: %q", r.RawQuery)
			}
		case r.Method == http.MethodPatch, r.Method == http.MethodPost && r.Path != "/token":
			t.Errorf("storage key pin sent %s %s", r.Method, r.Path)
		}
	}
	if puts != 1 {
		t.Errorf("storage key pin replaced the pin %d times; want once", puts)
	}
}

// ADR 0023 M2.5 (A20-13), mutation 71g: a writing command that warns with a
// cluster error it does not return passes the error through terminalText,
// so a hostile or broken API server cannot put escape sequences on the
// operator's terminal: run's and kernel deploy's rollout warnings, run's
// warning that the pin was not raised, and rotate's line that it was not
// written.
func TestWritingCommandsQuoteTheClusterOnTheirWarnings(t *testing.T) {
	hostile := &kube.APIError{Method: http.MethodGet, Path: "/apis/apps/v1/namespaces/my-platform/deployments/api",
		Status: kube.Status{Status: tkube.Status{Code: http.StatusInternalServerError, Reason: "InternalError", Message: "\x1b]0;owned\x07\x1b[2Jgone"}}, KubernetesStatus: true}
	quoted := strconv.QuoteToGraphic(hostile.Error())

	t.Run("run", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		runnableInstance(t, dir, "prod")
		f := newFakeRun(twoAppManifest)
		f.rolloutErr = hostile
		env, out, errb := testEnvBoth(dir, output.ModeHuman)
		if err := runCmd(f).Run(context.Background(), env, []string{"prod", "github.com/example/my-platform"}); err != nil {
			t.Fatal(err)
		}
		checkQuoted(t, "run", out.String()+errb.String(), quoted)
	})
	t.Run("kernel deploy", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		meteredInstance(t, dir, "prod", tcdeploy.DefaultNamespace)
		fc := &fakeCluster{rolloutErr: hostile, namespaces: []string{tcdeploy.DefaultNamespace}}
		c := testKernelDeploy(fc, &fakeBuilder{})
		env, out, errb := testEnvBoth(dir, output.ModeHuman)
		if err := c.Run(context.Background(), env, []string{"prod"}); err != nil {
			t.Fatal(err)
		}
		checkQuoted(t, "kernel deploy", out.String()+errb.String(), quoted)
	})
	t.Run("run's pin raise", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		meta := runnableInstance(t, dir, "prod")
		meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
		if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
			t.Fatal(err)
		}
		mintKeyring(t, dir, "prod")
		env, out, errb := testEnvBoth(dir, output.ModeHuman)
		c := runCmd(newFakeRun(twoAppManifest))
		c.newKeyholder = openerFor(&fakeStateKeyholder{phase: "unsealed"})
		c.newPinStore = func(clusterRef) (pinStore, error) { return &fakePinStore{failWrite: hostile}, nil }
		if err := c.Run(context.Background(), env, []string{"prod", "github.com/example/my-platform"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(errb.String(), "key pin was not raised") {
			t.Fatalf("run did not warn that the pin was not raised:\n%s", errb)
		}
		checkQuoted(t, "run's pin raise", out.String()+errb.String(), strconv.QuoteToGraphic("the key pin changed while this command wrote it, or could not be written: "+hostile.Error()))
	})
	t.Run("storage key rotate", func(t *testing.T) {
		dir, meta, env, out := handOverInstance(t, "prod")
		scopedKeyring(t, dir, "prod", "demo", "alpha")
		base := servingFleet(t, env, meta, dir)
		broken := &fakePinStore{failRead: hostile}
		err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(base),
			newPinStore: func(clusterRef) (pinStore, error) { return broken, nil }}).Run(context.Background(), env, []string{"prod"})
		if err == nil || !strings.Contains(out.String(), "NOT written") {
			t.Fatalf("rotate = %v, printing\n%s\nwant the pin NOT written", err, out)
		}
		checkQuoted(t, "storage key rotate", out.String(), strconv.QuoteToGraphic("read the key pin: "+hostile.Error()))
	})
}

// checkQuoted fails unless what holds the hostile text only quoted.
func checkQuoted(t *testing.T, cmd, what, quoted string) {
	t.Helper()
	if strings.ContainsAny(what, "\x1b\x07") {
		t.Errorf("%s put the cluster's control characters on the terminal: %q", cmd, what)
	}
	if !strings.Contains(what, quoted) {
		t.Errorf("%s's warning does not quote the cluster's error %s:\n%s", cmd, quoted, what)
	}
}

// bodyResourceVersion is the metadata.resourceVersion of a ConfigMap body.
func bodyResourceVersion(t *testing.T, body []byte) string {
	t.Helper()
	var cm struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &cm); err != nil {
		t.Fatalf("the body is not a ConfigMap (%v): %s", err, body)
	}
	return cm.Metadata.ResourceVersion
}

// ADR 0023 M2.5 (A20-17): storage key pin and storage key rotate reach the
// pin in-process with the instance's stored service-account key, so their
// help says the pin needs no kubectl, and no longer that it does.
func TestPinHelpSaysThePinNeedsNoKubectl(t *testing.T) {
	for _, row := range []struct {
		name string
		cmd  Command
		want string
	}{
		{"storage key pin", &keyPinCommand{}, "The pin is reached in-process, as the instance's installer service account, with the key 'farcast install --credentials' stored; it needs no kubectl."},
		{"storage key rotate", &keyRotateCommand{}, "The pin is written in-process, as the instance's installer service account, with the key 'farcast install --credentials' stored, and needs no kubectl;"},
	} {
		flat := strings.Join(strings.Fields(row.cmd.Usage()), " ")
		if !strings.Contains(flat, row.want) || strings.Contains(flat, "needs kubectl") {
			t.Errorf("%s's help does not say the pin needs no kubectl:\n%s", row.name, row.cmd.Usage())
		}
	}
}

// What applyReady says when this machine cannot run a writer's transitional
// kubectl Apply (S-F2): its lead, then the cluster client's own refusal.
const (
	msgCannotApply    = "this machine cannot apply to the instance's cluster, so nothing was changed: "
	msgKubectlMissing = "kubectl not found on PATH — deploying into an instance needs kubectl and the gke-gcloud-auth-plugin"
	msgNoKubeconfig   = "this machine has no kubeconfig for the instance, which kubectl applies through until ADR 0023 M2.7 ("
)

// offline wires the seams a writing command would reach Google or a registry
// through, once past its writer, to fakes that count what they were asked:
// a regression in the order these tests pin then fails them on this machine,
// never by leaving it.
type offline struct{ opened, built, storage int }

func (o *offline) wire(cmd Command) Command {
	provider := func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		o.opened++
		return &fakeProvider{}, nil
	}
	builder := func(func(string)) imageBuilder {
		o.built++
		return &fakeBuilder{}
	}
	switch c := cmd.(type) {
	case *connectCommand:
		c.openProvider, c.newBuilder = provider, builder
	case *redeployCommand:
		c.openProvider, c.newBuilder = provider, builder
	case *kernelDeployCommand:
		c.deployer.openProvider, c.deployer.newBuilder = provider, builder
	case *storageDeployCommand:
		c.deployer.openProvider, c.deployer.newBuilder = provider, builder
		c.ensureStorage = func(context.Context, *Env, string) error {
			o.storage++
			return errors.New("no storage in this test")
		}
	case *buildCommand:
		c.newBuilder = builder
	case *runCommand:
		c.newBuilder = builder
	}
	return cmd
}

// offlineCommand is wc with its Google- and registry-facing seams wired to o.
func offlineCommand(wc writeCommand, o *offline) writeCommand {
	inner := wc.cmd
	wc.cmd = func() Command { return o.wire(inner()) }
	return wc
}

// ADR 0023 M2.5 (S-F2): until M2.7 every command that applies runs kubectl,
// over the instance's kubeconfig, as its last step. Before M2.5 its first
// read ran kubectl too, so a machine with no kubectl, or no kubeconfig for
// the instance, was refused before anything else; since M2.5 those reads are
// in-process, and applyReady finds both right after the writer opens. Each of
// the nine commands that apply is then refused before it reads, asks, mints,
// pushes, writes the pin, opens a provider or records anything: no request
// reaches the cluster, no file under the config directory changes, nothing
// is asked, and no kubectl runs. storage key pin and rotate apply nothing,
// and need neither.
func TestCommandsThatApplyRefuseAMachineThatCannotApply(t *testing.T) {
	realPinOpener(t)
	for _, wc := range writeCommands() {
		if wc.name == "storage key pin" || wc.name == "storage key rotate" {
			continue
		}
		for _, lack := range []struct {
			name  string
			setup func(t *testing.T, dir config.Dir) (ran func() bool)
			cause string
		}{
			{"no kubectl", func(t *testing.T, _ config.Dir) func() bool {
				noKubectl(t)
				return func() bool { return false }
			}, msgKubectlMissing},
			{"no kubeconfig", func(t *testing.T, dir config.Dir) func() bool {
				ran := strayKubectl(t)
				if err := os.Remove(dir.InstanceKubeconfigPath(writeName)); err != nil {
					t.Fatal(err)
				}
				return ran
			}, msgNoKubeconfig},
		} {
			t.Run(wc.name+"/"+lack.name, func(t *testing.T) {
				s := kubetest.New(t)
				dir, meta := writeInstance(t, s, true)
				if wc.edit != nil {
					wc.edit(meta)
					if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
						t.Fatal(err)
					}
				}
				ran := lack.setup(t, dir)
				before := treeFiles(t, string(dir))
				var o offline
				_, errb, err := runWrite(t, dir, offlineCommand(wc, &o))
				if err == nil || !strings.Contains(err.Error(), msgCannotApply+lack.cause) {
					t.Fatalf("%s = %v; want applyReady's refusal, %q", wc.name, err, msgCannotApply+lack.cause)
				}
				if kind := kindOf(classified(err)); kind != kindInternal {
					t.Errorf("%s's envelope says %q, want %q until ADR 0023 M2.7", wc.name, kind, kindInternal)
				}
				if got := s.Requests(); len(got) != 0 {
					t.Errorf("%s sent %d requests (first %s %s) on a machine that cannot apply", wc.name, len(got), got[0].Method, got[0].Path)
				}
				if o.opened+o.built+o.storage != 0 {
					t.Errorf("%s opened a provider %d times, a builder %d times and storage %d times before refusing", wc.name, o.opened, o.built, o.storage)
				}
				if bytes.Contains(errb, []byte("[y/N]")) {
					t.Errorf("%s asked before refusing: %s", wc.name, errb)
				}
				if ran() {
					t.Errorf("%s ran kubectl", wc.name)
				}
				sameFiles(t, wc.name+" on a machine that cannot apply", before, treeFiles(t, string(dir)))
			})
		}
	}
}

// ADR 0023 M2.5 (A20-10, M-F10, mutation o16): storage deploy opens one
// writer, for its pin and its apply. It reads credentials.yaml, which holds
// the private key, once, and mints once. It stops at a refused pin read,
// before the cost is asked or a provider is opened.
func TestStorageDeployOpensOneWriter(t *testing.T) {
	ran := strayKubectl(t)
	realPinOpener(t)
	s := kubetest.New(t)
	dir, _ := writeInstance(t, s, true)
	s.Fail(http.MethodGet, pinPath, http.StatusInternalServerError, kube.Status{})
	reads := observeConfigReads(t)
	var o offline
	_, _, err := runWrite(t, dir, offlineCommand(writeCommandNamed(t, "storage deploy"), &o))
	if kind := kindOf(classified(err)); kind != kindClusterRejected {
		t.Fatalf("storage deploy = %v; kind %q, want the pin read's %q", err, kind, kindClusterRejected)
	}
	creds, mints := 0, 0
	for _, p := range reads() {
		if filepath.Base(p) == "credentials.yaml" {
			creds++
		}
	}
	for _, r := range s.Requests() {
		if r.Path == "/token" {
			mints++
		}
	}
	if creds != 1 || mints != 1 {
		t.Errorf("storage deploy read credentials.yaml %d times and minted %d tokens; one writer reads it once and mints once", creds, mints)
	}
	if o.opened+o.built+o.storage != 0 || ran() {
		t.Errorf("storage deploy went on past a refused pin read: provider %d, builder %d, storage %d, kubectl ran %v", o.opened, o.built, o.storage, ran())
	}
}

// ADR 0023 M2.5 (C-F1): when run hands new scopes to a serving keyholder, it
// raises the key pin through the writer it opened, not a second one: the
// installer's credentials.yaml is read once and its token minted once for
// the whole run, and the pin is created as the writer.
func TestRunRaisesThePinThroughItsOwnWriter(t *testing.T) {
	noKubectl(t)
	realPinOpener(t)
	s := kubetest.New(t)
	dir, meta := writeInstance(t, s, true)
	env, _, errb := testEnvBoth(dir, output.ModeJSON)
	kh := &fakeStateKeyholder{phase: "unsealed"}
	c := &runCommand{newKeyholder: func(context.Context, *Env, string) (sealStateClient, func(), error) { return kh, func() {}, nil }}
	c.ensureDefaults()
	reads := observeConfigReads(t)
	cl, err := c.newCluster(clusterRef{Dir: dir, Meta: meta, Identity: kube.Writer, Warn: env.Err})
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightNamespace(t.Context(), cl); err != nil {
		t.Fatal(err)
	}
	c.handScopesToTheKeyholder(t.Context(), env, meta, []string{"web"}, cl)

	creds, mints, created := 0, 0, 0
	for _, p := range reads() {
		if filepath.Base(p) == "credentials.yaml" {
			creds++
		}
	}
	for _, r := range s.Requests() {
		switch {
		case r.Path == "/token":
			mints++
		case r.As != "writer":
			t.Errorf("%s %s as %q; want the writer", r.Method, r.Path, r.As)
		case r.Method == http.MethodPost && r.Path == configMapsPath:
			created++
		}
	}
	if created != 1 {
		t.Fatalf("the pin was created %d times; want the hand-over's one raise (stderr: %s)", created, errb)
	}
	if creds != 1 || mints != 1 {
		t.Errorf("run read credentials.yaml %d times and minted %d tokens; its one writer reads it once and mints once", creds, mints)
	}
	if strings.Contains(errb.String(), "key pin was not raised") {
		t.Errorf("the pin raise warned: %s", errb)
	}
}
