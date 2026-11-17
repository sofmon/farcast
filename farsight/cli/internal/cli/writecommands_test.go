package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
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
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "192.0.2.10:8443", ServerName: identity.ServerName(writeName)}
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
	// prepare, when set, writes what the record alone cannot say, for a test
	// that takes the command as far as its plan: the instance's mTLS
	// material, which redeploy loads and the fixture does not hold.
	prepare func(t *testing.T, dir config.Dir)
}

// writeCommands is the eleven commands that write to an instance's cluster.
func writeCommands() []writeCommand {
	return []writeCommand{
		{name: "connect", args: []string{writeName}, cmd: func() Command { return newConnectCommand() },
			edit: func(m *config.InstanceMetadata) { m.FatLineDeployed, m.Carrier = false, nil }},
		{name: "redeploy", args: []string{writeName}, cmd: func() Command { return newRedeployCommand() }, prepare: writeMaterial},
		{name: "build", args: []string{writeName}, flags: []string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest, "--yes"},
			cmd: func() Command { return &buildCommand{} }},
		{name: "run", args: []string{writeName, "github.com/example/my-platform"}, flags: []string{"--fetcher-image", fetcherDigest, "--builder-image", builderDigest, "--yes"},
			cmd: func() Command { return &runCommand{newKeyholder: noKeyholder} }},
		{name: "kernel deploy", args: []string{writeName}, flags: []string{"--yes"}, cmd: func() Command { return &kernelDeployCommand{} }},
		{name: "kernel meter", args: []string{writeName, writeNewNamespace}, cmd: func() Command { return &kernelMeterCommand{} }},
		{name: "kernel confirm", args: []string{writeName}, flags: []string{"--amount", "1", "--from", thisMonth(1), "--to", thisMonth(2)},
			cmd: func() Command { return &kernelConfirmCommand{} }},
		{name: "storage deploy", args: []string{writeName}, flags: []string{"--yes"}, cmd: func() Command { return &storageDeployCommand{} }},
		{name: "storage key pin", args: []string{writeName}, cmd: func() Command { return &keyPinCommand{newKeyholder: noKeyholder} }},
		{name: "storage key rotate", args: []string{writeName}, flags: []string{"--yes"}, cmd: func() Command { return &keyRotateCommand{newKeyholder: noKeyholder} }},
		{name: "reader grant", args: []string{writeName}, cmd: func() Command {
			return &readerGrantCommand{interactive: func(*Env) bool { return true }}
		}},
	}
}

// writeMaterial saves writeInstance's mTLS material, as its first connect
// minted it.
func writeMaterial(t *testing.T, dir config.Dir) {
	t.Helper()
	mat, err := identity.Mint(writeName)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMTLS(writeName, toConfigMTLS(mat)); err != nil {
		t.Fatal(err)
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

	// Under --confirm (ADR 0023 M2.6, A23-23): connect and redeploy read
	// the registry to plan, so planRegistry refuses the record before any
	// plan is computed, its blank key read before the provider opens; build
	// plans with no key, so it compares and refuses at the writer's open.
	// Either way nothing is minted, ensured, looked up or pushed, nothing is
	// sent, and no file changes.
	for _, row := range confirmingPlans(t) {
		t.Run(row.String()+"/--confirm", func(t *testing.T) {
			s, dir := planFixtureKeyed(t, row, false)
			digest := sampleDigest
			if row.name == "build" {
				doc, _ := runPlan(t, dir, row, output.ModeJSON)
				digest = doc.Digest
			}
			before := treeFiles(t, string(dir))
			opened, resolved := row.fakes.opened, len(row.fakes.builder.resolved)
			cmd := realWriter(t, withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", digest)...))
			env, out, errb := testEnvBoth(dir, output.ModeJSON)
			err := cmd.Run(t.Context(), env, row.args)
			if !errors.Is(err, errCredentialMissing) || !strings.Contains(err.Error(), msgADCRefused) || kindOf(classified(err)) != kindCredentialMissing {
				t.Fatalf("%s --confirm on an ADC instance = %v; want the installer key refused, credential_missing", row, err)
			}
			if row.fakes.opened != opened || len(row.fakes.builder.resolved) != resolved {
				t.Errorf("%s --confirm opened the provider %d times and looked up %v before refusing", row, row.fakes.opened-opened, row.fakes.builder.resolved[resolved:])
			}
			if f := row.fakes; len(f.provider.ensured)+len(f.builder.built)+len(f.builder.embedded) != 0 {
				t.Errorf("%s --confirm ensured %d registries, built %d and pushed %d images", row, len(f.provider.ensured), len(f.builder.built), len(f.builder.embedded))
			}
			if out.Len()+errb.Len() != 0 || len(s.Requests()) != 0 {
				t.Errorf("%s --confirm printed %q %q and sent %d requests before refusing", row, out, errb, len(s.Requests()))
			}
			sameFiles(t, row.String()+" --confirm on an ADC instance", before, treeFiles(t, string(dir)))
		})
	}
}

// confirmingPlans are the planCommands rows of the commands ADR 0023 M2.6b
// wires that apply, one per state that confirms into a deploy: connect's
// first deploy and resume, redeploy, and build.
func confirmingPlans(t *testing.T) []planCommand {
	t.Helper()
	return []planCommand{
		planCommandNamed(t, "connect", "first deploy"),
		planCommandNamed(t, "connect", "resume"),
		planCommandNamed(t, "redeploy", "the carried images"),
		planCommandNamed(t, "build", "a named builder"),
	}
}

// realWriter clears cmd's writing seam, which its planCommands row sets to
// refuse, so --confirm opens the instance's writer as farcast does.
func realWriter(t *testing.T, cmd Command) Command {
	t.Helper()
	switch c := cmd.(type) {
	case *connectCommand:
		c.newCluster = nil
	case *redeployCommand:
		c.newCluster = nil
	case *buildCommand:
		c.newCluster = nil
	default:
		t.Fatalf("%T has no writing seam here", cmd)
	}
	return cmd
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

	// Under --confirm (ADR 0023 M2.6, A23-23): the plan needs no kubectl,
	// so the command plans and compares, and only then opens the writer,
	// whose applyReady refuses before anything is minted, ensured, pushed
	// or sent, and before any kubectl runs.
	for _, row := range confirmingPlans(t) {
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
			t.Run(row.String()+"/--confirm/"+lack.name, func(t *testing.T) {
				s, dir := planFixture(t, row)
				ran := lack.setup(t, dir)
				doc, _ := runPlan(t, dir, row, output.ModeJSON)
				before := treeFiles(t, string(dir))
				cmd := realWriter(t, withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", doc.Digest)...))
				env, _, errb := testEnvBoth(dir, output.ModeJSON)
				err := cmd.Run(t.Context(), env, row.args)
				if err == nil || !strings.Contains(err.Error(), msgCannotApply+lack.cause) || kindOf(classified(err)) != kindInternal {
					t.Fatalf("%s --confirm = %v; want applyReady's refusal after the comparison, %q", row, err, msgCannotApply+lack.cause)
				}
				if f := row.fakes; len(f.provider.ensured)+len(f.builder.built)+len(f.builder.embedded) != 0 {
					t.Errorf("%s --confirm ensured %d registries, built %d and pushed %d images before refusing", row, len(f.provider.ensured), len(f.builder.built), len(f.builder.embedded))
				}
				if got := s.Requests(); len(got) != 0 || ran() || errb.Len() != 0 {
					t.Errorf("%s --confirm sent %d requests, ran kubectl %v and said %q before refusing", row, len(got), ran(), errb)
				}
				sameFiles(t, row.String()+" --confirm on a machine that cannot apply", before, treeFiles(t, string(dir)))
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

// ADR 0023 M2.6: the plans. planCommand is one --plan shape of a command
// that has a plan, as these tests run it: fresh each time, its flags parsed
// from flags and --plan, against writeInstance's fixture changed by edit and
// prepare, on a kubetest server it must not reach unless it reads the
// cluster. Each part of M2.6 adds the rows of the commands it wires (A23-14,
// A23-49).
type planCommand struct {
	name  string // the command, as writeCommands names it
	shape string // which of its plans
	args  []string
	flags []string
	// readsCluster: the plan reads the cluster, as the instance's reader.
	readsCluster bool
	cmd          func() Command
	edit         func(meta *config.InstanceMetadata)
	// prepare, when set, writes what the record alone cannot say: the
	// instance's mTLS material, for connect's resume and reconnect.
	prepare func(t *testing.T, dir config.Dir)
	// fakes are what the row's command reaches the provider, the registry,
	// the writer and the carrier through, for a command that has those
	// seams (connect's, redeploy's, and build's builder and writer): a plan
	// may open the provider, mint the registry's token and look up, and
	// nothing more. nil for one with none of them.
	fakes *planFakes
}

func (p planCommand) String() string { return p.name + "/" + p.shape }

// planFakes are a plan row's fakes, and what its plans asked of them.
type planFakes struct {
	provider *fakeProvider
	builder  *fakeBuilder
	// opened counts the provider's opens, writers the writer's, and
	// dialled the carrier's dials.
	opened, writers, dialled int
}

// planClock is the clock planCommands' kernel confirm reads, planNow, and
// planMonth a day of its month: a plan bound to the UTC day must be made and
// confirmed on one day, and the real clock can cross midnight, or a month,
// between two readings.
func planClock() time.Time { return planNow }

func planMonth(day int) string {
	return time.Date(planNow.Year(), planNow.Month(), day, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)
}

// pinPlanClock fixes the deployer's default clock at planNow for the rest
// of the test: for a test that runs planCommands through the router, which
// builds its commands itself.
func pinPlanClock(t *testing.T) {
	t.Helper()
	saved := deployerNowDefault
	deployerNowDefault = planClock
	t.Cleanup(func() { deployerNowDefault = saved })
}

// routerCheckout is the farcast checkout fakeDeployDefaults finds when no
// --source names one: a test binary carries no components, so a command the
// router runs builds from it (rule 6), and its plan binds this directory,
// never the checkout the test happens to run in.
const routerCheckout = "/work/farcast"

// fakeDeployDefaults makes the deployer's provider, builder, checkout and Go
// defaults fakes for the rest of the test: for a test that runs connect
// through the router, which sets no seam of its own, and whose unset seams
// otherwise refuse (refusingdefaults_test.go). The provider answers as the
// GKE adapter does, the builder as fakeBuilder, the checkout is --source's
// directory or routerCheckout, and the Go is fakeToolchain's.
func fakeDeployDefaults(t *testing.T) (*fakeProvider, *fakeBuilder) {
	t.Helper()
	fp, fb := &fakeProvider{}, &fakeBuilder{}
	savedOpen, savedBuild := openProviderDefault, newBuilderDefault
	savedSource, savedToolchain := findSourceDefault, findToolchainDefault
	openProviderDefault = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) { return fp, nil }
	newBuilderDefault = func(func(string)) imageBuilder { return fb }
	findSourceDefault = func(dir string) (string, error) {
		if dir == "" {
			return routerCheckout, nil
		}
		return dir, nil
	}
	findToolchainDefault = fakeToolchain
	t.Cleanup(func() {
		openProviderDefault, newBuilderDefault = savedOpen, savedBuild
		findSourceDefault, findToolchainDefault = savedSource, savedToolchain
	})
	return fp, fb
}

// planCommands is every --plan shape of the commands wired so far: kernel
// meter, kernel confirm and reader grant (ADR 0023 M2.6a), none of which
// reads the cluster; connect and redeploy (M2.6b), which read none either
// and read the registry through their fakes; and build (M2.6b), which reads
// neither the cluster nor Google. kernel confirm reads planClock; through
// the router, pinPlanClock fixes the same clock.
func planCommands() []planCommand {
	meter := func() Command { return &kernelMeterCommand{} }
	confirm := func() Command {
		c := &kernelConfirmCommand{}
		c.deployer.now = planClock
		return c
	}
	grant := func() Command { return &readerGrantCommand{} }
	metering := func(m *config.InstanceMetadata) {
		m.Kernel.Namespaces = append(m.Kernel.Namespaces, writeNewNamespace)
	}

	// The deployer of connect and redeploy, a release farcast carrying the
	// fake components, its every seam a fake that counts.
	deployer := func(d *fatlineDeployer, f *planFakes) {
		asRelease(d, nil)
		d.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
			f.opened++
			return f.provider, nil
		}
		d.newBuilder = func(func(string)) imageBuilder { return f.builder }
		d.findSource = func(dir string) (string, error) {
			if dir == "" {
				return "", errors.New("no farcast checkout at or above the working directory")
			}
			return dir, nil
		}
		d.findToolchain = fakeToolchain
		d.newCluster = func(clusterRef) (clusterApplier, error) {
			f.writers++
			return nil, errors.New("test: a plan opened the writer")
		}
	}
	connect := func(f *planFakes) func() Command {
		return func() Command {
			c := newConnectCommand()
			deployer(&c.fatlineDeployer, f)
			c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
				f.dialled++
				return nil, errors.New("test: a plan dialled the carrier")
			}
			return c
		}
	}
	redeploy := func(f *planFakes) func() Command {
		return func() Command {
			c := newRedeployCommand()
			deployer(&c.fatlineDeployer, f)
			return c
		}
	}
	// build, its builder a fake that counts, and its writer refused.
	build := func(f *planFakes) func() Command {
		return func() Command {
			c := &buildCommand{}
			c.newBuilder = func(func(string)) imageBuilder { return f.builder }
			c.newCluster = func(clusterRef) (jobWaiter, error) {
				f.writers++
				return nil, errors.New("test: a plan opened the writer")
			}
			return c
		}
	}
	fakes := func(resolve func(string) (string, error)) *planFakes {
		return &planFakes{provider: &fakeProvider{}, builder: &fakeBuilder{resolveFn: resolve}}
	}
	firstDeploy := func(m *config.InstanceMetadata) { m.FatLineDeployed, m.Carrier = false, nil }
	resume := func(m *config.InstanceMetadata) { m.Carrier = nil }
	builderRecorded := func(m *config.InstanceMetadata) { m.Toolchain = &config.Toolchain{Builder: builderDigest} }
	buildFlags := []string{"--repo", "https://github.com/example/repo.git", "--app", "api"}
	first, resumed, lost, again, source := fakes(notFoundForTags), fakes(nil), fakes(nil), fakes(nil), fakes(nil)
	redeployed, rebuilt, named, recordedBuilder := fakes(notFoundForTags), fakes(nil), fakes(nil), fakes(nil)

	return []planCommand{
		{name: "kernel meter", shape: "add", args: []string{writeName, writeNewNamespace}, cmd: meter},
		{name: "kernel meter", shape: "remove", args: []string{writeName, writeNewNamespace}, flags: []string{"--remove"}, cmd: meter, edit: metering},
		{name: "kernel meter", shape: "already metered", args: []string{writeName, writeNewNamespace}, cmd: meter, edit: metering},
		{name: "kernel confirm", shape: "a window", args: []string{writeName}, flags: []string{"--amount", "1.25", "--from", planMonth(1), "--to", planMonth(2)}, cmd: confirm},
		{name: "kernel confirm", shape: "an empty window", args: []string{writeName}, flags: []string{"--amount", "0", "--from", planMonth(2), "--to", planMonth(2)}, cmd: confirm},
		{name: "reader grant", shape: "a recorded reader", args: []string{writeName}, cmd: grant},
		{name: "reader grant", shape: "no reader", args: []string{writeName}, cmd: grant, edit: func(m *config.InstanceMetadata) { m.Reader = nil }},
		// A first deploy mints the instance's material and pushes the
		// carried images, whose version tags the registry lacks.
		{name: "connect", shape: "first deploy", args: []string{writeName}, cmd: connect(first), edit: firstDeploy, fakes: first},
		{name: "connect", shape: "resume", args: []string{writeName}, cmd: connect(resumed), edit: resume, prepare: writeMaterial, fakes: resumed},
		{name: "connect", shape: "resume, its material lost", args: []string{writeName}, cmd: connect(lost), edit: resume, fakes: lost},
		{name: "connect", shape: "reconnect", args: []string{writeName}, cmd: connect(again), prepare: writeMaterial, fakes: again},
		{name: "connect", shape: "a source build", args: []string{writeName}, flags: []string{"--source", "/work/farcast"}, cmd: connect(source), edit: firstDeploy, fakes: source},
		// A redeploy pushes the carried images, whose version tags the
		// registry lacks, over the material the instance holds.
		{name: "redeploy", shape: "the carried images", args: []string{writeName}, cmd: redeploy(redeployed), prepare: writeMaterial, fakes: redeployed},
		{name: "redeploy", shape: "a source build", args: []string{writeName}, flags: []string{"--source", "/work/farcast"}, cmd: redeploy(rebuilt), prepare: writeMaterial, fakes: rebuilt},
		{name: "build", shape: "a named builder", args: []string{writeName}, flags: append(slices.Clone(buildFlags), "--builder-image", builderDigest), cmd: build(named), fakes: named},
		{name: "build", shape: "a recorded builder", args: []string{writeName}, flags: append(slices.Clone(buildFlags), "--ref", "refs/tags/v2", "--context", "svc", "--containerfile", "svc/Containerfile"),
			cmd: build(recordedBuilder), edit: builderRecorded, fakes: recordedBuilder},
	}
}

// planCommandNamed is the planCommands row of name and shape.
func planCommandNamed(t *testing.T, name, shape string) planCommand {
	t.Helper()
	for _, p := range planCommands() {
		if p.name == name && p.shape == shape {
			return p
		}
	}
	t.Fatalf("no plan %s/%s", name, shape)
	return planCommand{}
}

// planFixture is writeInstance, keyed, changed by row's edit and prepare.
func planFixture(t *testing.T, row planCommand) (*kubetest.Server, config.Dir) {
	t.Helper()
	return planFixtureKeyed(t, row, true)
}

// planFixtureKeyed is planFixture, its credentials.yaml holding the
// installer's key when keyed, and as an install with Application Default
// Credentials wrote it otherwise.
func planFixtureKeyed(t *testing.T, row planCommand, keyed bool) (*kubetest.Server, config.Dir) {
	t.Helper()
	s := kubetest.New(t)
	dir, meta := writeInstance(t, s, keyed)
	if row.edit != nil {
		row.edit(meta)
		if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
			t.Fatal(err)
		}
	}
	if row.prepare != nil {
		row.prepare(t, dir)
	}
	return s, dir
}

// withFlags parses flags into cmd as the router does, and returns cmd. A
// command's SetFlags resets what its flags hold, so a test sets its seams
// after, never its flags before.
func withFlags[C Command](t *testing.T, cmd C, flags ...string) C {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cmd.SetFlags(fs)
	if err := fs.Parse(flags); err != nil {
		t.Fatalf("parse %q: %v", flags, err)
	}
	return cmd
}

// runPlan runs row's --plan against dir in mode, with no terminal, and
// returns what it printed: the document (in JSON mode; its digest alone,
// from the digest line, in human mode) and the text. A plan prints nothing
// on stderr: its notices are facts (A23-26).
func runPlan(t *testing.T, dir config.Dir, row planCommand, mode output.Mode) (plan.Document, string) {
	t.Helper()
	return runPlanIn(t, dir, row, mode, strings.NewReader(""))
}

// runPlanIn is runPlan reading stdin from in.
func runPlanIn(t *testing.T, dir config.Dir, row planCommand, mode output.Mode, in io.Reader) (plan.Document, string) {
	t.Helper()
	cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--plan")...)
	env, out, errb := testEnvBoth(dir, mode)
	env.In = in
	if err := cmd.Run(t.Context(), env, row.args); err != nil {
		t.Fatalf("%s --plan: %v", row, err)
	}
	if errb.Len() != 0 {
		t.Errorf("%s --plan wrote on stderr: %q", row, errb)
	}
	if mode == output.ModeJSON {
		return printedDocument(t, out.Bytes()), out.String()
	}
	return plan.Document{Digest: digestLine(t, out.String())}, out.String()
}

// printedDocument decodes a printed plan.
func printedDocument(t *testing.T, out []byte) plan.Document {
	t.Helper()
	var doc plan.Document
	if err := json.Unmarshal(out, &doc); err != nil || doc.Kind != plan.Kind {
		t.Fatalf("not a plan (%v):\n%s", err, out)
	}
	return doc
}

// digestLine is the digest a plan's rendering prints.
func digestLine(t *testing.T, text string) string {
	t.Helper()
	for line := range strings.Lines(text) {
		if d, ok := strings.CutPrefix(line, "digest: "); ok {
			return strings.TrimSuffix(d, "\n")
		}
	}
	t.Fatalf("no digest line in:\n%s", text)
	return ""
}

// factTypes is each fact type by its type word, for decoding a printed plan.
var factTypes = map[string]reflect.Type{
	plan.TypeCost: reflect.TypeFor[plan.CostFact](), plan.TypeImage: reflect.TypeFor[plan.ImageFact](),
	plan.TypeWrite: reflect.TypeFor[plan.WriteFact](), plan.TypeMint: reflect.TypeFor[plan.MintFact](),
	plan.TypeRestart: reflect.TypeFor[plan.RestartFact](), plan.TypeCloud: reflect.TypeFor[plan.CloudFact](),
	plan.TypeKernelSettings: reflect.TypeFor[plan.KernelSettingsFact](), plan.TypeMeter: reflect.TypeFor[plan.MeterFact](),
	plan.TypeConfirmation: reflect.TypeFor[plan.ConfirmationFact](), plan.TypePin: reflect.TypeFor[plan.PinFact](),
	plan.TypeRotation: reflect.TypeFor[plan.RotationFact](), plan.TypeFetch: reflect.TypeFor[plan.FetchFact](),
	plan.TypeRun: reflect.TypeFor[plan.RunFact](), plan.TypeBuild: reflect.TypeFor[plan.BuildFact](),
	plan.TypeApplicationReset: reflect.TypeFor[plan.ApplicationResetFact](), plan.TypeReader: reflect.TypeFor[plan.ReaderFact](),
	plan.TypeNotice: reflect.TypeFor[plan.NoticeFact](),
}

// decodedBound decodes a printed plan's bound member, its facts typed.
func decodedBound(t *testing.T, doc plan.Document) plan.Bound {
	t.Helper()
	var raw struct {
		plan.Bound
		Facts []json.RawMessage `json:"facts"`
	}
	if err := json.Unmarshal(doc.Bound, &raw); err != nil {
		t.Fatalf("the bound member does not decode: %v\n%s", err, doc.Bound)
	}
	b := raw.Bound
	b.Facts = nil
	for _, f := range raw.Facts {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(f, &head); err != nil {
			t.Fatal(err)
		}
		typ, ok := factTypes[head.Type]
		if !ok {
			t.Fatalf("a fact of no known type: %s", f)
		}
		v := reflect.New(typ)
		if err := json.Unmarshal(f, v.Interface()); err != nil {
			t.Fatal(err)
		}
		b.Facts = append(b.Facts, v.Elem().Interface().(plan.Fact))
	}
	return b
}

// noticesOf is the text of every notice a plan carries.
func noticesOf(b plan.Bound) []string {
	var out []string
	for _, f := range b.Facts {
		if n, ok := f.(plan.NoticeFact); ok {
			out = append(out, n.Text)
		}
	}
	return out
}

// wantWrites is the write facts of an apply stream, as a plan binds them: a
// test's own reading of the stream, against which applyFacts is checked.
func wantWrites(t *testing.T, stream []byte) []plan.Fact {
	t.Helper()
	docs, err := kube.SplitStream(stream)
	if err != nil {
		t.Fatal(err)
	}
	var out []plan.Fact
	for _, d := range docs {
		out = append(out, plan.WriteFact{Type: plan.TypeWrite, API: d.Kind.APIVersion, Kind: d.Kind.Kind,
			Namespace: d.Namespace, Name: d.Name, Method: plan.WriteApply, SHA256: fmt.Sprintf("%x", sha256.Sum256(d.Raw))})
	}
	return out
}

// writeTargets is each write fact as kind namespace/name.
func writeTargets(b plan.Bound) []string {
	var out []string
	for _, f := range b.Facts {
		if w, ok := f.(plan.WriteFact); ok {
			out = append(out, w.Kind+" "+w.Namespace+"/"+w.Name)
		}
	}
	return out
}

// ADR 0023 M2.6 (rows 72, 73): --plan writes nothing. Every shape, in both
// modes, leaves the config directory byte for byte as it was, reaches the
// cluster only with GETs as its reader if it reads it at all (and not at all
// if not), and runs no kubectl. A command with a provider, a registry or a
// builder (connect's, redeploy's, build's) ensures and deletes no registry,
// builds and pushes no image (its token and lookups are reads), opens no
// writer and dials nothing.
func TestPlansWriteNothing(t *testing.T) {
	ran := strayKubectl(t)
	for _, row := range planCommands() {
		t.Run(row.String(), func(t *testing.T) {
			s, dir := planFixture(t, row)
			before := treeFiles(t, string(dir))
			reads := observeConfigReads(t)
			runPlan(t, dir, row, output.ModeJSON)
			runPlan(t, dir, row, output.ModeHuman)
			sameFiles(t, row.String()+" --plan", before, treeFiles(t, string(dir)))
			for _, p := range reads() {
				// A plan opens no private key (A23-25): the CA's, FatLine's
				// server key, or the operator's.
				if base := filepath.Base(p); base == "ca.key" || base == "server.key" || base == "client.key" {
					t.Errorf("%s --plan read %s", row, p)
				}
			}
			if f := row.fakes; f != nil {
				if len(f.provider.ensured)+len(f.provider.regDeleted) != 0 {
					t.Errorf("%s --plan ensured %d registries and deleted %d", row, len(f.provider.ensured), len(f.provider.regDeleted))
				}
				if len(f.builder.built)+len(f.builder.embedded) != 0 {
					t.Errorf("%s --plan built %d images and pushed %d", row, len(f.builder.built), len(f.builder.embedded))
				}
				if f.writers+f.dialled != 0 {
					t.Errorf("%s --plan opened the writer %d times and dialled %d", row, f.writers, f.dialled)
				}
			}
			reqs := s.Requests()
			if !row.readsCluster && len(reqs) != 0 {
				t.Errorf("%s --plan reads no cluster, and sent %d requests", row, len(reqs))
			}
			for _, r := range reqs {
				switch {
				case r.Path == "/token" && r.As != "reader":
					t.Errorf("%s --plan minted a token as %q", row, r.As)
				case r.Path != "/token" && r.Method != http.MethodGet:
					t.Errorf("%s --plan sent %s %s", row, r.Method, r.Path)
				}
			}
		})
	}
	if ran() {
		t.Error("a plan ran kubectl")
	}
}

// ADR 0023 M2.6 (row 91): a plan does not depend on the terminal. Each is
// printed in human mode with stdin a character device, which isTerminal
// takes for a terminal, and with stdin a pipe; the digests are equal, and so
// are the bound bytes of the two in JSON.
func TestPlanIgnoresTheTerminal(t *testing.T) {
	tty, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tty.Close() }()
	if !isTerminal(tty) {
		t.Fatalf("%s is not taken for a terminal here, so this test would prove nothing", os.DevNull)
	}
	for _, row := range planCommands() {
		t.Run(row.String(), func(t *testing.T) {
			_, dir := planFixture(t, row)
			inTTY, _ := runPlanIn(t, dir, row, output.ModeHuman, tty)
			inPipe, _ := runPlanIn(t, dir, row, output.ModeHuman, strings.NewReader(""))
			if inTTY.Digest != inPipe.Digest {
				t.Errorf("the plan in a terminal is %s, and in a pipe %s", inTTY.Digest, inPipe.Digest)
			}
			jsonTTY, _ := runPlanIn(t, dir, row, output.ModeJSON, tty)
			jsonPipe, _ := runPlanIn(t, dir, row, output.ModeJSON, strings.NewReader(""))
			if !bytes.Equal(jsonTTY.Bound, jsonPipe.Bound) || jsonTTY.Digest != inTTY.Digest {
				t.Errorf("the plan's bytes differ by stdin, or from its rendering:\n%s\n%s", jsonTTY.Bound, jsonPipe.Bound)
			}
		})
	}
}

// ADR 0023 M2.6 (row 79): a plan computed twice from the same state is the
// same bytes, and kernel confirm's two clock readings on one UTC day bind the
// same plan (design §9.4, the clock).
func TestPlanIsDeterministic(t *testing.T) {
	for _, row := range planCommands() {
		t.Run(row.String(), func(t *testing.T) {
			_, dir := planFixture(t, row)
			first, _ := runPlan(t, dir, row, output.ModeJSON)
			second, _ := runPlan(t, dir, row, output.ModeJSON)
			if !bytes.Equal(first.Bound, second.Bound) || first.Digest != second.Digest {
				t.Errorf("two plans from one state differ:\n%s\n%s", first.Bound, second.Bound)
			}
		})
	}
	t.Run("kernel confirm/two clock readings on one day", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		kernelInstance(t, dir, "p41")
		var docs []plan.Document
		for _, at := range []time.Time{
			time.Date(2026, 11, 16, 0, 0, 1, 0, time.UTC),
			// 23:59:59 UTC, read in a zone where it is already the 17th.
			time.Date(2026, 11, 17, 4, 59, 59, 999, time.FixedZone("east", 5*3600)),
		} {
			c := withFlags(t, confirmCmd(&fakeCluster{}), "--amount", "3.5", "--plan")
			c.deployer.now = func() time.Time { return at }
			env, out := testEnv(dir, output.ModeJSON)
			if err := c.Run(t.Context(), env, []string{"p41"}); err != nil {
				t.Fatal(err)
			}
			docs = append(docs, printedDocument(t, out.Bytes()))
		}
		if !bytes.Equal(docs[0].Bound, docs[1].Bound) {
			t.Errorf("two readings on 2026-11-16 bind different plans:\n%s\n%s", docs[0].Bound, docs[1].Bound)
		}
	})
}

// ADR 0023 M2.6 (A23-33, A23-35; review M-M26B-MUT-04 and -05): connect's
// facts follow its state. Only a first deploy binds the cost, which only it
// asks; mints come only when this machine holds no material; and a resume
// that mints over the FatLine deployed binds a restart of FatLine, right
// after the mints, the one fact of its plan that says FatLine's pods roll.
func TestConnectPlanFactsFollowItsState(t *testing.T) {
	for _, tc := range []struct {
		shape                  string
		cost, mints, restarted bool
	}{
		{"first deploy", true, true, false},
		{"resume", false, false, false},
		{"resume, its material lost", false, true, true},
	} {
		t.Run(tc.shape, func(t *testing.T) {
			row := planCommandNamed(t, "connect", tc.shape)
			_, dir := planFixture(t, row)
			doc, _ := runPlan(t, dir, row, output.ModeJSON)
			b := decodedBound(t, doc)
			costs := 0
			var mints []string
			restartAt, lastMint := -1, -1
			for i, f := range b.Facts {
				switch f := f.(type) {
				case plan.CostFact:
					costs++
				case plan.MintFact:
					mints = append(mints, f.What)
					lastMint = i
				case plan.RestartFact:
					if f.Component == components.FatLine.Name && f.Because == plan.RestartBecause {
						restartAt = i
					}
				}
			}
			var wantMints []string
			if tc.mints {
				wantMints = []string{plan.MintInstanceCA, plan.MintFatLineLeaf, plan.MintOperatorLeaf}
			}
			wantCosts := 0
			if tc.cost {
				wantCosts = 1
			}
			if costs != wantCosts || !slices.Equal(mints, wantMints) || (restartAt >= 0) != tc.restarted || (tc.restarted && restartAt != lastMint+1) {
				t.Errorf("connect %s binds %d costs, mints %q and a restart at %d (the last mint at %d); want %d costs, mints %q, a restart %v right after them",
					tc.shape, costs, mints, restartAt, lastMint, wantCosts, wantMints, tc.restarted)
			}
		})
	}
}

// ADR 0023 M2.6 (A23-24, §7.3), mutation 73a: which plans read the
// installer's key, the one credential that writes. In M2.6 a plan reads it
// only for the registry: connect's first deploy and resume, and redeploy,
// read it; connect's reconnect, build (which resolves a builder tag only
// anonymously, to refuse it, until M2.8's push grant), and kernel meter's,
// kernel confirm's and reader grant's plans, have no registry read, and
// none reads credentials.yaml. A plan of the read group on an instance
// installed without a key (Application Default Credentials) is refused
// credential_missing, before the provider opens.
func TestPlansStillReadTheInstallerKeyForGoogle(t *testing.T) {
	// By command, or by command/shape where its shapes differ.
	readsKey := map[string]bool{
		"kernel meter": false, "kernel confirm": false, "reader grant": false,
		"connect": true, "connect/reconnect": false, "redeploy": true, "build": false,
	}
	groupOf := func(row planCommand) (bool, bool) {
		if want, ok := readsKey[row.String()]; ok {
			return want, true
		}
		want, ok := readsKey[row.name]
		return want, ok
	}
	for _, row := range planCommands() {
		t.Run(row.String(), func(t *testing.T) {
			want, ok := groupOf(row)
			if !ok {
				t.Fatalf("%s is in no group: say whether its plan reads the installer's key", row.name)
			}
			_, dir := planFixture(t, row)
			reads := observeConfigReads(t)
			runPlan(t, dir, row, output.ModeJSON)
			got := slices.ContainsFunc(reads(), func(p string) bool { return filepath.Base(p) == "credentials.yaml" })
			if got != want {
				t.Errorf("%s --plan read credentials.yaml: %v, want %v (%q)", row, got, want, reads())
			}
			if !want {
				return
			}
			t.Run("an install without a key", func(t *testing.T) {
				_, dir := planFixtureKeyed(t, row, false)
				opened := row.fakes.opened
				cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--plan")...)
				env, out, _ := testEnvBoth(dir, output.ModeJSON)
				err := cmd.Run(t.Context(), env, row.args)
				if !errors.Is(err, errCredentialMissing) || !strings.Contains(err.Error(), msgADCRefused) || kindOf(classified(err)) != kindCredentialMissing {
					t.Errorf("%s --plan on an ADC install = %v; want the installer key refused, credential_missing", row, err)
				}
				if row.fakes.opened != opened || out.Len() != 0 {
					t.Errorf("%s --plan on an ADC install opened the provider %d times, and printed %q", row, row.fakes.opened-opened, out)
				}
			})
		})
	}
}

// ADR 0023 M2.6 (A23-26), mutation 91a: under --plan, a line a command
// prints while it works is a notice fact and is not printed; outside a plan
// it is printed once, in the same words. Rows for meteredReader's warning,
// kernel meter's no-op, kernel confirm's empty window, and connect's and
// redeploy's keepingNote. (M2.6c adds rotationScopeWarning.)
func TestPlanPrintsNoticesOnlyAsFacts(t *testing.T) {
	keeper := fatlineDeployer{component: components.FatLine, carried: newFakeCarried()}
	kept := config.SystemImage{Image: imageIn("fatline", "a"), Origin: config.OriginOperator, Go: "go1.27.5",
		Farcast: "v0.8.0", BuiltAt: testBuiltAt, Source: "/home/op/farcast"}
	for _, row := range []struct {
		name  string
		setup func(t *testing.T, dir config.Dir) (cmd func(flags ...string) Command, args []string)
		want  string
	}{
		{"meteredReader's warning", func(t *testing.T, dir config.Dir) (func(...string) Command, []string) {
			meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
			withReader(t, dir, "p42", "edited")
			return func(flags ...string) Command { return withFlags(t, meterCmd(&fakeCluster{}), flags...) }, []string{"p42", "demo"}
		}, "Warning: no reader binding is added: instance \"p42\" records the reader \"farcast-installer@proj-test1.iam.gserviceaccount.com\", " +
			"which is not the reader farcast derives for it (" + readerEmail("p42", "proj-test1") + "); no RBAC was rendered for it. " +
			"'farcast reader grant p42' binds the reader in every metered namespace once the record is fixed."},
		{"kernel meter's no-op", func(t *testing.T, dir config.Dir) (func(...string) Command, []string) {
			meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace, "demo")
			return func(flags ...string) Command { return withFlags(t, meterCmd(&fakeCluster{}), flags...) }, []string{"p42", "demo"}
		}, "Already metering demo."},
		{"kernel confirm's empty window", func(t *testing.T, dir config.Dir) (func(...string) Command, []string) {
			kernelInstance(t, dir, "p41")
			return func(flags ...string) Command {
				return withFlags(t, confirmCmd(&fakeCluster{}), append([]string{"--amount", "1", "--from", thisMonth(3), "--to", thisMonth(3)}, flags...)...)
			}, []string{"p41"}
		}, "Nothing to confirm: the window from " + thisMonth(3) + " to " + thisMonth(3) + " is empty."},
		// A resume asks no cost question, and a kept image no build
		// question: outside a plan it deploys, unasked.
		{"connect's keepingNote", func(t *testing.T, dir config.Dir) (func(...string) Command, []string) {
			meta := registeredInstance(t, dir, prodName)
			operatorRecorded(meta)
			meta.FatLineDeployed = true
			if err := dir.SaveInstanceMetadata(prodName, meta); err != nil {
				t.Fatal(err)
			}
			return func(flags ...string) Command {
				c := testConnect(&fakeProvider{}, &fakeBuilder{})
				c.newCluster = func(clusterRef) (clusterApplier, error) { return &fakeCluster{ip: "34.0.0.1"}, nil }
				c.dial = connectedDial()
				return withFlags(t, c, flags...)
			}, []string{prodName}
		}, keeper.keepingNote(kept)},
		// Outside a plan, redeploy asks about the change, so its run there
		// answers with --yes; it asks no build question for a kept image.
		{"redeploy's keepingNote", func(t *testing.T, dir config.Dir) (func(...string) Command, []string) {
			meta := registeredInstance(t, dir, prodName)
			operatorRecorded(meta)
			reconnected(t, dir, meta)
			if err := dir.SaveInstanceMetadata(prodName, meta); err != nil {
				t.Fatal(err)
			}
			return func(flags ...string) Command {
				if len(flags) == 0 {
					flags = []string{"--yes"}
				}
				c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
				c.newCluster = func(clusterRef) (clusterApplier, error) { return &fakeCluster{}, nil }
				return withFlags(t, c, flags...)
			}, []string{prodName}
		}, keeper.keepingNote(kept)},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			cmd, args := row.setup(t, dir)
			for _, mode := range []output.Mode{output.ModeJSON, output.ModeHuman} {
				env, out, errb := testEnvBoth(dir, mode)
				if err := cmd("--plan").Run(t.Context(), env, args); err != nil {
					t.Fatal(err)
				}
				if errb.Len() != 0 {
					t.Errorf("--plan printed %q on stderr", errb)
				}
				if mode == output.ModeJSON {
					if got := noticesOf(decodedBound(t, printedDocument(t, out.Bytes()))); !slices.Contains(got, row.want) {
						t.Errorf("the plan's notices are %q; want %q among them", got, row.want)
					}
				} else if !strings.Contains(out.String(), "notice: "+row.want+"\n") {
					t.Errorf("the rendering does not show the notice %q:\n%s", row.want, out)
				}
			}
			env, _, errb := testEnvBoth(dir, output.ModeHuman)
			if err := cmd().Run(t.Context(), env, args); err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(errb.String(), row.want+"\n"); got != 1 {
				t.Errorf("outside a plan the line is printed %d times; want once:\n%s", got, errb)
			}
		})
	}
}

// adcInstall is an instance installed with Application Default Credentials:
// a credentials.yaml with a provider and no key.
func adcInstall(t *testing.T, dir config.Dir, meta *config.InstanceMetadata) {
	t.Helper()
	if err := dir.SaveInstanceCredentials(meta.Name, &config.InstanceCredentials{Provider: "gke"}); err != nil {
		t.Fatal(err)
	}
}

// ADR 0023 M2.6 (A23-5, D1), mutation 91b: no plan deploys FatLine without
// its Shrike monitor. With --fatline-image and no --embedded, under --plan
// and --confirm, a registry that cannot be read refuses the command before
// any plan is computed, in each way it can fail, with A23-5's text and the
// failure's own kind: nothing is printed, read past the failure, written,
// ensured, looked up, opened or dialled. The break-glass path, FatLine
// alone, stays an interactive or --yes act
// (TestConnectExplicitImageSurvivesRegistryFailure).
func TestPlanNeverDeploysFatLineWithoutShrike(t *testing.T) {
	named := "registry.example/fatline@" + sha("c")
	for _, cause := range []struct {
		name      string
		edit      rigEdit
		configure func(d *fatlineDeployer)
		kind      string
	}{
		{"no registry recorded", recorded(func(m *config.InstanceMetadata) { m.Registry = nil }), nil, kindInternal},
		{"an install without a key", adcInstall, nil, kindCredentialMissing},
		{"the provider refused", nil, func(d *fatlineDeployer) {
			d.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
				return nil, errors.New("permission denied")
			}
		}, kindInternal},
		{"a provider with no registry", nil, func(d *fatlineDeployer) {
			d.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
				return clusterOnlyProvider{&fakeProvider{}}, nil
			}
		}, kindInternal},
	} {
		for _, dr := range deployRigs() {
			for _, answer := range [][]string{{"--plan"}, {"--confirm", sampleDigest}} {
				t.Run(dr.name+"/"+cause.name+"/"+answer[0], func(t *testing.T) {
					var edits []rigEdit
					if cause.edit != nil {
						edits = append(edits, cause.edit)
					}
					r := dr.rig(t, edits...)
					r.configure = cause.configure
					before := r.files(t)
					stdout, errb, err := r.run(t, output.ModeJSON, append([]string{"--fatline-image", named}, answer...)...)
					lead := fmt.Sprintf("--plan and --confirm never deploy FatLine without its Shrike monitor, and instance %q's image registry could not be read (", prodName)
					tail := "); deploying FatLine alone is a break-glass step: run the command without --plan or --confirm, interactively or with --yes"
					if err == nil || !strings.HasPrefix(err.Error(), lead) || !strings.HasSuffix(err.Error(), tail) {
						t.Fatalf("%s %s = %v; want A23-5's refusal", dr.name, answer[0], err)
					}
					if kind := kindOf(classified(err)); kind != cause.kind || exitCodeOf(err) != 1 {
						t.Errorf("the refusal's kind is %s (exit %d), want the registry failure's, %s", kind, exitCodeOf(err), cause.kind)
					}
					if stdout != "" || errb != "" {
						t.Errorf("printed %q and %q before refusing", stdout, errb)
					}
					if len(r.fp.ensured)+len(r.fb.resolved)+len(r.fb.embedded)+r.writers+r.dials+len(r.fc.applied) != 0 {
						t.Errorf("ensured %d, looked up %v, pushed %d, opened the writer %d times, dialled %d, applied %d",
							len(r.fp.ensured), r.fb.resolved, len(r.fb.embedded), r.writers, r.dials, len(r.fc.applied))
					}
					sameFiles(t, "a plan without Shrike", before, r.files(t))
				})
			}
		}
	}
}

// ADR 0023 M2.6 (A23-24), mutation 73b: a plan reads the instance's registry
// and never ensures one. On a record that names none, --plan and --confirm
// refuse with A23-24's text, kind internal, having ensured, written and
// looked up nothing. Outside them, a record that names no registry is
// ensured first, as before, and the command goes on: a first connect after
// a failed install ensure still works.
func TestPlanNeedsARecordedRegistry(t *testing.T) {
	unregistered := recorded(func(m *config.InstanceMetadata) { m.Registry = nil })
	for _, dr := range deployRigs() {
		for _, answer := range [][]string{{"--plan"}, {"--confirm", sampleDigest}} {
			t.Run(dr.name+"/"+answer[0], func(t *testing.T) {
				r := dr.rig(t, unregistered)
				before := r.files(t)
				stdout, _, err := r.run(t, output.ModeJSON, answer...)
				want := fmt.Sprintf(msgNoRegistryRecorded, prodName, prodName)
				if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal {
					t.Fatalf("%s %s with no registry recorded = %v; want %q", dr.name, answer[0], err, want)
				}
				if stdout != "" || len(r.fp.ensured)+len(r.fb.resolved)+r.writers != 0 {
					t.Errorf("printed %q, ensured %d registries, looked up %v and opened the writer %d times", stdout, len(r.fp.ensured), r.fb.resolved, r.writers)
				}
				sameFiles(t, "a plan with no registry recorded", before, r.files(t))
			})
		}
		t.Run(dr.name+"/--yes ensures it first", func(t *testing.T) {
			r := dr.rig(t, unregistered)
			if _, errb, err := r.run(t, output.ModeHuman, "--yes"); err != nil {
				t.Fatalf("%s --yes with no registry recorded: %v\n%s", dr.name, err, errb)
			}
			if len(r.fp.ensured) == 0 || registryPrefix(r.meta(t)) != repoPrefix(prodName) || len(r.fc.applied) != 1 {
				t.Errorf("ensured %d times, recorded %q, applied %d; want the registry ensured and recorded, then the deploy", len(r.fp.ensured), registryPrefix(r.meta(t)), len(r.fc.applied))
			}
		})
	}
}

// ADR 0023 M2.6 (A23-24), mutation 75b: the registry ensured after consent
// is the one the plan was made with. Answered with another, the command
// refuses before anything is pushed or applied: plan_changed under
// --confirm, ending with msgPlanAgain, and internal in a --yes run.
func TestConfirmRefusesAMovedRegistry(t *testing.T) {
	moved := &planck.Registry{
		Ref:    planck.RegistryRef{Name: "farcast-moved", Location: "us-central1"},
		Prefix: "us-central1-docker.pkg.dev/proj-1/farcast-moved",
		Puller: "serviceAccount:1234-compute@developer.gserviceaccount.com",
	}
	for _, dr := range deployRigs() {
		for _, answer := range []string{"--confirm", "--yes"} {
			t.Run(dr.name+"/"+answer, func(t *testing.T) {
				r := dr.rig(t)
				r.fb.resolveFn = notFoundForTags // the plan pushes both images
				flags := []string{answer}
				if answer == "--confirm" {
					flags = append(flags, r.plan(t).Digest)
				}
				r.fp.registry = moved
				_, errb, err := r.run(t, output.ModeJSON, flags...)
				want, kind := fmt.Sprintf(msgRegistryMoved, prodName, moved.Prefix, repoPrefix(prodName)), kindInternal
				if answer == "--confirm" {
					want, kind = want+"; "+msgPlanAgain, kindPlanChanged
				}
				if err == nil || err.Error() != want || kindOf(classified(err)) != kind {
					t.Fatalf("%s %s over a moved registry = %v (kind %s); want %q, %s\n%s", dr.name, answer, err, kindOf(classified(err)), want, kind, errb)
				}
				if len(r.fb.embedded)+len(r.fb.built)+len(r.fc.applied)+r.dials != 0 {
					t.Errorf("pushed %d, built %d, applied %d and dialled %d over a moved registry", len(r.fb.embedded), len(r.fb.built), len(r.fc.applied), r.dials)
				}
				if registryPrefix(r.meta(t)) != moved.Prefix {
					t.Errorf("the registry ensured was not recorded, as the refusal says it was: %q", registryPrefix(r.meta(t)))
				}
			})
		}
	}
}

// ADR 0023 M2.6 (A23-10): a farcast whose carried components it must not
// push is refused before any plan is computed, under --plan too, with
// today's refusal and its kind, internal: no plan is printed, and nothing is
// looked up or opened. (One --plan row per command that prechecks.)
func TestPlanOfANonReleaseIsRefusedBeforeAnyPlan(t *testing.T) {
	for _, dr := range deployRigs() {
		t.Run(dr.name, func(t *testing.T) {
			r := dr.rig(t)
			opened := 0
			r.configure = func(d *fatlineDeployer) {
				d.build = devBuild
				d.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
					opened++
					return r.fp, nil
				}
			}
			stdout, _, err := r.run(t, output.ModeJSON, "--plan")
			if !errors.Is(err, buildinfo.ErrNotRelease) || kindOf(classified(err)) != kindInternal {
				t.Fatalf("%s --plan from a farcast that is not a release = %v (kind %s); want the precheck's refusal, internal", dr.name, err, kindOf(classified(err)))
			}
			if stdout != "" || opened+len(r.fb.resolved)+r.writers != 0 {
				t.Errorf("printed %q, opened the provider %d times, looked up %v and opened the writer %d times before refusing", stdout, opened, r.fb.resolved, r.writers)
			}
		})
	}
}

// ADR 0023 M2.6 (A24-15): an option a plan binds from the command line must
// be valid UTF-8, or two plans that differ only there would share a digest.
// --plan and --confirm refuse such a value as an error the router prints,
// kind internal, exit 1, saying it is not UTF-8 and never quoting it; no
// plan is printed, and nothing is opened, pushed or applied. connect's and
// redeploy's --source reaches the plan's own check (a checkout this
// machine's file system names, faked here); build's values are refused
// first where its documents are rendered, which is the same refusal, sooner.
func TestPlanRefusesAnOptionThatIsNotUTF8(t *testing.T) {
	const hostileDir = "/work/far\xffcast"
	hostileBuilder := "cgr.dev/chainguard/kan\xffiko@sha256:" + strings.Repeat("b", 64)
	refused := func(t *testing.T, err error, stdout string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "not valid UTF-8") && !strings.Contains(err.Error(), "not UTF-8") ||
			strings.Contains(err.Error(), "\xff") || kindOf(classified(err)) != kindInternal || exitCodeOf(err) != 1 {
			t.Errorf("= %v (kind %s, exit %d); want it refused as not UTF-8, internal, exit 1, unquoted", err, kindOf(classified(err)), exitCodeOf(err))
		}
		if stdout != "" {
			t.Errorf("printed %q", stdout)
		}
	}
	for _, dr := range deployRigs() {
		for _, answer := range [][]string{{"--plan"}, {"--confirm", sampleDigest}} {
			t.Run(dr.name+"/"+answer[0], func(t *testing.T) {
				r := dr.rig(t)
				r.configure = func(d *fatlineDeployer) { d.findSource = func(dir string) (string, error) { return dir, nil } }
				stdout, _, err := r.run(t, output.ModeJSON, append([]string{"--source", hostileDir}, answer...)...)
				refused(t, err, stdout)
				if err != nil && (!strings.HasPrefix(err.Error(), "plan: bound.options[") || !strings.HasSuffix(err.Error(), "].value is not valid UTF-8")) {
					t.Errorf("%s's refusal is not the plan's own: %v", dr.name, err)
				}
				if r.writers+len(r.fb.built)+len(r.fb.embedded)+len(r.fp.ensured)+len(r.fc.applied) != 0 {
					t.Errorf("opened the writer %d times, built %d, pushed %d, ensured %d, applied %d",
						r.writers, len(r.fb.built), len(r.fb.embedded), len(r.fp.ensured), len(r.fc.applied))
				}
			})
		}
	}
	for _, answer := range [][]string{{"--plan"}, {"--confirm", sampleDigest}} {
		t.Run("build/"+answer[0], func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			meteringInstance(t, dir, "p42")
			fj, opened := &fakeJobs{}, 0
			c := buildPlanCmd(t, fj, &fakeBuilder{}, &opened,
				append([]string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", hostileBuilder}, answer...)...)
			env, out := testEnv(dir, output.ModeJSON)
			refused(t, c.Run(context.Background(), env, []string{"p42"}), out.String())
			if opened+len(fj.applied) != 0 {
				t.Errorf("opened the writer %d times and applied %d streams", opened, len(fj.applied))
			}
		})
	}
	// Through the router, whose envelope carries it.
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	stdout, stderr, code := runLine([]string{"farcast", "--config", string(dir), "-o", "json", "build", "p42",
		"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", hostileBuilder, "--plan"})
	if code != 1 || !strings.Contains(stdout, `"kind":"internal"`) || !strings.Contains(stdout, "not UTF-8") || strings.Contains(stdout, "\xff") {
		t.Errorf("farcast build --builder-image <not UTF-8> --plan: exit %d, %q %q", code, stdout, stderr)
	}
}

// kubectlCall is one run of the succeeding stand-in kubectl: its arguments
// and what it read on stdin.
type kubectlCall struct {
	Args  []string
	Stdin []byte
}

// succeedingKubectl pins PATH, for the rest of the test, to a directory
// holding a kubectl that succeeds (A23-49): a /bin/sh script that writes
// each run's arguments and stdin to numbered files and exits 0, as
// cluster/open_test.go's recording kubectl does for one run. With it a
// --confirm passes applyReady and reaches its apply, which runs nothing
// real. It runs with only the PATH the cluster client hands it, so it names
// cat by its path. calls reports every run, in order.
func succeedingKubectl(t *testing.T) (calls func() []kubectlCall) {
	t.Helper()
	bin, saw := t.TempDir(), t.TempDir()
	script := "#!/bin/sh\nn=0\nwhile [ -e '" + saw + "'/$n.argv ]; do n=$((n+1)); done\n" +
		"for a in \"$@\"; do printf '%s\\000' \"$a\"; done > '" + saw + "'/$n.argv\n" +
		"/bin/cat > '" + saw + "'/$n.stdin\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return func() []kubectlCall {
		var out []kubectlCall
		for n := 0; ; n++ {
			argv, err := os.ReadFile(filepath.Join(saw, strconv.Itoa(n)+".argv"))
			if errors.Is(err, os.ErrNotExist) {
				return out
			}
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := os.ReadFile(filepath.Join(saw, strconv.Itoa(n)+".stdin"))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, kubectlCall{Args: strings.Split(strings.TrimSuffix(string(argv), "\x00"), "\x00"), Stdin: stdin})
		}
	}
}

// appliedStreams is what the stand-in kubectl was given to apply, in order.
func appliedStreams(calls []kubectlCall) [][]byte {
	var out [][]byte
	for _, c := range calls {
		if slices.Contains(c.Args, "apply") {
			out = append(out, c.Stdin)
		}
	}
	return out
}

// planWrites is a plan's write facts, in its order.
func planWrites(b plan.Bound) []plan.Fact {
	var out []plan.Fact
	for _, f := range b.Facts {
		if w, ok := f.(plan.WriteFact); ok {
			out = append(out, w)
		}
	}
	return out
}

// masked is a document of FatLine's stream with exactly the differences
// A23-31 allows that stream masked: each value of a Secret's data (item 1)
// and the pod template's mTLS hash (item 2). The stream builds nothing, pins
// nothing and binds no bucket or egress credential, so items 3 to 6 have
// nothing to mask in it.
func masked(doc []byte) []byte {
	lines := strings.Split(string(doc), "\n")
	secret, inData := slices.Contains(lines, "kind: Secret"), false
	for i, l := range lines {
		switch {
		case secret && l == "data:":
			inData = true
			continue
		case inData && strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   "):
			if k, _, ok := strings.Cut(strings.TrimSpace(l), ": "); ok {
				lines[i] = "  " + k + ": <masked>"
			}
			continue
		}
		inData = false
		if lead, _, ok := strings.Cut(l, "farcast.sofmon.com/mtls-hash: "); ok {
			lines[i] = lead + "farcast.sofmon.com/mtls-hash: <masked>"
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// ADR 0023 M2.6 (A23-31, row 80): what --confirm applies is what its plan
// bound, but for the secrets the plan could only render as placeholders.
// Each command is planned, then confirmed through its real writer against
// kubetest, its kubectl the succeeding stand-in, which records the stream it
// is given; the command then fails at its first read after the apply (the
// rollout, or the build's Job, which kubetest does not hold), which this
// test does not need. FatLine's stream, from connect's first deploy (which
// mints the material) and from redeploy (which loads it): the plan's write
// facts are the planned rendering, over placeholder leaves and the plan's
// images, and the applied documents equal it document for document once a
// Secret's data and the mTLS hash are masked, and differ unmasked only
// there. build's three documents: byte for byte the plan's.
func TestConfirmWritesThePlannedDocumentsExceptTheirSecrets(t *testing.T) {
	for _, row := range []struct {
		name    string
		edit    func(m *config.InstanceMetadata)
		prepare func(t *testing.T, dir config.Dir)
		flags   []string
		cmd     func(fp *fakeProvider, fb *fakeBuilder) Command
		fatline bool // the stream is FatLine's, compared under A23-31's masks
	}{
		{"connect, a first deploy", func(m *config.InstanceMetadata) { m.FatLineDeployed, m.Carrier = false, nil }, nil, nil,
			func(fp *fakeProvider, fb *fakeBuilder) Command {
				c := testConnect(fp, fb)
				c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
					return nil, errors.New("test: the carrier is not dialled here")
				}
				return c
			}, true},
		{"redeploy", nil, writeMaterial, nil, func(fp *fakeProvider, fb *fakeBuilder) Command { return testRedeploy(fp, fb) }, true},
		{"build", nil, nil, []string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest},
			func(_ *fakeProvider, fb *fakeBuilder) Command {
				c := &buildCommand{}
				c.newBuilder = func(func(string)) imageBuilder { return fb }
				return c
			}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			calls := succeedingKubectl(t)
			s := kubetest.New(t)
			dir, meta := writeInstance(t, s, true)
			if row.edit != nil {
				row.edit(meta)
				if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
					t.Fatal(err)
				}
			}
			if row.prepare != nil {
				row.prepare(t, dir)
			}
			// The registry the ensure answers is the one the record names, and
			// the carried images' tags are missing, so both are pushed.
			fp := &fakeProvider{registry: &planck.Registry{Ref: registryRefFor(meta), Prefix: meta.Registry.Prefix}}
			fb := &fakeBuilder{resolveFn: notFoundForTags}
			run := func(flags ...string) (string, error) {
				cmd := withFlags(t, row.cmd(fp, fb), append(slices.Clone(row.flags), flags...)...)
				env, out, errb := testEnvBoth(dir, output.ModeJSON)
				err := cmd.Run(t.Context(), env, []string{writeName})
				return out.String() + errb.String(), err
			}
			printed, err := run("--plan")
			if err != nil {
				t.Fatalf("--plan: %v", err)
			}
			doc := printedDocument(t, []byte(printed))
			b := decodedBound(t, doc)
			// The planned identity is decided before the confirm mints any.
			var id identityDecision
			if exists, _ := dir.InstanceMTLSExists(writeName); exists {
				ca, err := dir.LoadInstanceCACert(writeName)
				if err != nil {
					t.Fatal(err)
				}
				id.caCertPEM = ca
			} else {
				id.mint = true
			}

			said, err := run("--confirm", doc.Digest)
			if err == nil || kindOf(classified(err)) == kindPlanChanged {
				t.Fatalf("--confirm = %v; want it past the comparison, to its first read after the apply\n%s", err, said)
			}
			t.Logf("--confirm stopped after its apply: %v", err)
			applied := appliedStreams(calls())
			if len(applied) != 1 {
				t.Fatalf("the stand-in kubectl applied %d streams; want the plan's one\n%s", len(applied), said)
			}
			if !row.fatline {
				if got, want := wantWrites(t, applied[0]), planWrites(b); !reflect.DeepEqual(got, want) {
					t.Errorf("applied\n%#v\nthe plan bound\n%#v", got, want)
				}
				return
			}

			// FatLine's stream as the plan rendered it: its images, over the
			// placeholder material.
			images := map[string]string{}
			for _, f := range b.Facts {
				if img, ok := f.(plan.ImageFact); ok {
					images[img.Component] = img.Target
				}
			}
			planned, err := renderWorkload(images["fatline"], images["shrike"], fldeploy.CarrierLoadBalancer, placeholderMTLS(writeName, id))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := wantWrites(t, planned), planWrites(b); !reflect.DeepEqual(got, want) {
				t.Fatalf("the plan's write facts are not the planned rendering:\n%#v\n%#v", want, got)
			}
			plannedDocs, err := kube.SplitStream(planned)
			if err != nil {
				t.Fatal(err)
			}
			appliedDocs, err := kube.SplitStream(applied[0])
			if err != nil {
				t.Fatal(err)
			}
			if len(appliedDocs) != len(plannedDocs) {
				t.Fatalf("applied %d documents; the plan bound %d", len(appliedDocs), len(plannedDocs))
			}
			differ := 0
			for i, p := range plannedDocs {
				a := appliedDocs[i]
				if !bytes.Equal(masked(a.Raw), masked(p.Raw)) {
					t.Errorf("document %d, %s %s/%s, differs from the plan beyond its secrets:\napplied:\n%s\nplanned:\n%s",
						i, p.Kind.Kind, p.Namespace, p.Name, a.Raw, p.Raw)
				}
				if !bytes.Equal(a.Raw, p.Raw) {
					differ++
					if p.Kind.Kind != "Secret" && p.Kind.Kind != "Deployment" {
						t.Errorf("document %d, a %s, differs unmasked", i, p.Kind.Kind)
					}
				}
			}
			if differ == 0 {
				t.Error("no document differs from the planned rendering: the plan's placeholders are the real material, or this test masks nothing")
			}
		})
	}
}
