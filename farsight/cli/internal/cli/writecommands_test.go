package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
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
	pbuild "github.com/sofmon/farcast/planck/build"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// ADR 0023 M2.5: the writing commands read the cluster, and write the
// storage key pin, in-process as the instance's writer, the installer's
// stored service-account key (design §7.3, A20-18). Since M2.7 they apply
// in-process as it too (A30-27), so no test here runs kubectl: a test that
// drives a command to its applies runs them against kubetest, settled
// (WithSettledWorkloads), and reads them back as requests
// (appliedRequests); one that must stop after the comparison has kubetest
// refuse its first apply (FailNextApply, A30-31).

// writeName is the instance the writing commands' fixtures record.
const writeName = "atlas"

// recordMigrated records m as an instance whose objects are written with
// server-side apply, at a fixed time and by a fixed farcast: the record ADR
// 0023 M2.7's writers check before they do anything (design A30-20). It is
// called wherever a record a writer runs on is built: in readerInstance and
// installedInstance, on which every other base fixture builds and saves the
// record again with it kept, and in the tests and helpers that build their
// own. Only a test of an unmigrated instance clears it.
func recordMigrated(m *config.InstanceMetadata) {
	m.ServerSideApply = &config.ServerSideApply{Since: time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC), Farcast: "v0.0.0-test"}
}

// writeNewNamespace is a namespace the fixture's kernel does not meter yet,
// so kernel meter has one to add.
const writeNewNamespace = "extra"

// writeInstance is readerInstance (a loopback instance against s, its reader
// granted, its writer's credentials.yaml registered with s under id
// "writer") with everything each writing command checks before it opens the
// writer: a registry, a kernel and a cost limit, FatLine behind a carrier, a
// keyholder, storage and a keyring, and the kubeconfig.yaml an install
// before ADR 0023 M2.7 wrote, which nothing reads or writes since M2.7 and
// migrate deletes: written here as a file, for migrate's local fact. keyed false rewrites credentials.yaml as an install with
// Application Default Credentials wrote it: a provider and no key.
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
	if err := os.WriteFile(filepath.Join(dir.InstancePath(writeName), "kubeconfig.yaml"), []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
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
	// material, which redeploy and storage deploy load and the fixture does
	// not hold.
	prepare func(t *testing.T, dir config.Dir)
}

// writeCommands is the twelve commands that write to an instance's cluster:
// ADR 0023 M2.7's migrate is the twelfth (A30-26). Its row answers its
// typed-name question as runWrite answers every prompt, "y", which is not
// the instance's name, so it aborts having written nothing.
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
		{name: "storage deploy", args: []string{writeName}, flags: []string{"--yes"}, cmd: func() Command { return &storageDeployCommand{} }, prepare: writeMaterial},
		{name: "storage key pin", args: []string{writeName}, cmd: func() Command { return &keyPinCommand{newKeyholder: noKeyholder} }},
		{name: "storage key rotate", args: []string{writeName}, flags: []string{"--yes"}, cmd: func() Command { return &keyRotateCommand{newKeyholder: noKeyholder} }},
		{name: "reader grant", args: []string{writeName}, cmd: func() Command {
			return &readerGrantCommand{interactive: func(*Env) bool { return true }}
		}},
		{name: "migrate", args: []string{writeName}, cmd: func() Command { return &migrateCommand{interactive: func(*Env) bool { return true }} }},
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

// applyQuery is the query of every apply (design §5.3, A30-27): farcast's
// field manager, strict field validation, and forced.
const applyQuery = "fieldManager=farcast&fieldValidation=Strict&force=true"

// appliedRequests is every server-side apply s saw, in order (A30-31): each
// PATCH whose Content-Type is application/apply-patch+yaml, one per
// document. A refused one is among them.
func appliedRequests(s *kubetest.Server) []kubetest.Request {
	return appliedOf(s.Requests())
}

// appliedBodies is the documents applies sent, one per request, in order,
// failing t unless each was sent as the writer with applyQuery.
func appliedBodies(t *testing.T, applies []kubetest.Request) [][]byte {
	t.Helper()
	var out [][]byte
	for _, r := range applies {
		if r.As != "writer" || r.RawQuery != applyQuery {
			t.Errorf("applied %s?%s as %q; want ?%s as the writer", r.Path, r.RawQuery, r.As, applyQuery)
		}
		out = append(out, r.Body)
	}
	return out
}

// stoppedAtTheFirstApply fails t unless reqs, what a command sent past its
// comparison with its first apply refused (FailNextApply, A30-31), are the
// plan's reader's requests, if any, then the writer's alone, ending in
// exactly one apply, the refused one: the command sent one refused apply,
// and stored nothing. It returns the reader's requests, and the writer's
// before that apply but its token's: its preflight, and any write the
// command makes before its first apply, for the caller to check against its
// plan.
func stoppedAtTheFirstApply(t *testing.T, what string, reqs []kubetest.Request) (readerReqs, writerReqs []kubetest.Request) {
	t.Helper()
	first := slices.IndexFunc(reqs, func(r kubetest.Request) bool { return r.As == "writer" })
	if first < 0 {
		t.Errorf("%s sent nothing as the writer; want it past the comparison, to its first apply", what)
		return reqs, nil
	}
	readerReqs = reqs[:first]
	for _, r := range readerReqs {
		if r.As != "reader" {
			t.Errorf("%s sent %s %s as %q before the writer's; want the reader's alone", what, r.Method, r.Path, r.As)
		}
	}
	for i, r := range reqs[first:] {
		apply := r.Method == http.MethodPatch && r.ContentType == "application/apply-patch+yaml"
		switch {
		case r.As != "writer":
			t.Errorf("%s sent %s %s as %q after the writer's first; want the writer's alone", what, r.Method, r.Path, r.As)
		case apply && first+i != len(reqs)-1:
			t.Errorf("%s sent more after its refused apply of %s: %d requests", what, r.Path, len(reqs)-1-first-i)
		case apply && r.RawQuery != applyQuery:
			t.Errorf("%s applied %s?%s; want ?%s", what, r.Path, r.RawQuery, applyQuery)
		case !apply && first+i == len(reqs)-1:
			t.Errorf("%s ended with %s %s; want its first apply, refused", what, r.Method, r.Path)
		case !apply && r.Path != "/token":
			writerReqs = append(writerReqs, r)
		}
	}
	return readerReqs, writerReqs
}

// streamOf is documents joined as one stream, each separated by ---, as a
// renderer writes them: what wantWrites and docsIn read.
func streamOf(documents [][]byte) []byte {
	var b bytes.Buffer
	for i, d := range documents {
		if i > 0 {
			b.WriteString("---\n")
		}
		b.Write(d)
	}
	return b.Bytes()
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
// failure warn or are swallowed by design. Since ADR 0023 M2.7 an apply is
// in-process too (A30-32): each command that applies carries its apply's
// kind, the writer's 403 sentence once, reader grant's included.
func TestWritingCommandsCarryClusterKinds(t *testing.T) {
	realPinOpener(t)

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

	// writePinLoop's three attempts, each answered 409: cluster_rejected.
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
			t.Errorf("storage key pin created %d times; want writePinLoop's 3 attempts", posts)
		}
	})

	// ADR 0023 M2.7 (A30-32, row 102a): each command that applies, planned
	// and confirmed through its real writer, its first apply refused. A 500
	// is cluster_rejected; a 403 is forbidden, with the writer's sentence
	// once by its shape, reader grant's included, which defers no
	// writerRefused and wraps its apply's error in it; a writer's mint
	// refused before the apply is credential_refused, and nothing is
	// applied. The record is as the command's rollback leaves it.
	for _, p := range applyingPlans(t) {
		for _, f := range []struct {
			name     string
			inject   func(s *kubetest.Server) // nil: the writer's mint is refused instead
			kind     string
			sentence string
		}{
			{"the apply answering 500", func(s *kubetest.Server) {
				s.FailNextApply(http.StatusInternalServerError, kube.Status{})
			}, kindClusterRejected, ""},
			{"the apply forbidden by RBAC", func(s *kubetest.Server) {
				s.FailNextApply(http.StatusForbidden, kube.Status{})
			}, kindForbidden, msgWriterRBACRefused},
			{"the apply forbidden at the endpoint", func(s *kubetest.Server) {
				s.FailNextApply(http.StatusForbidden, iamShaped)
			}, kindForbidden, msgWriterIAMRefused},
			{"the writer's token refused", nil, kindCredentialRefused, ""},
		} {
			t.Run(p.String()+"/"+f.name, func(t *testing.T) {
				// The writer's mint, refused from the confirm on: the plan's
				// own writer, run's manifest read's, mints as before.
				var refuseWriter atomic.Bool
				mints := kubetest.WithTokenAnswer(func(email string) (int, []byte, bool) {
					if email != "writer@kubetest.invalid" || !refuseWriter.Load() {
						return 0, nil, false
					}
					return http.StatusBadRequest, []byte(`{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`), true
				})
				var before *config.InstanceMetadata
				c := confirmApplying(t, p, func(s *kubetest.Server, dir config.Dir, _ plan.Bound) {
					var err error
					if before, err = dir.LoadInstanceMetadata(writeName); err != nil {
						t.Fatal(err)
					}
					if f.inject != nil {
						f.inject(s)
					} else {
						refuseWriter.Store(true)
					}
				}, mints)
				if kind := kindOf(classified(c.err)); kind != f.kind {
					t.Fatalf("%s = %v; kind %q, want %q\n%s", p, c.err, kind, f.kind, c.stderr)
				}
				msg := c.err.Error()
				for _, sentence := range []string{msgWriterRBACRefused, msgWriterIAMRefused} {
					want := 0
					if sentence == f.sentence {
						want = 1
					}
					if got := strings.Count(msg, sentence); got != want {
						t.Errorf("%s = %q;\nsays %q %d times, want %d", p, msg, sentence, got, want)
					}
				}
				applies := appliedOf(c.sent)
				if f.inject == nil && len(applies) != 0 {
					t.Errorf("%s applied %d documents with its writer's token refused", p, len(applies))
				}
				if f.inject != nil && len(applies) != 1 {
					t.Errorf("%s sent %d applies; want its first, refused, and nothing after it", p, len(applies))
				}
				after, err := c.dir.LoadInstanceMetadata(writeName)
				if err != nil {
					t.Fatal(err)
				}
				if why := p.rolledBack(before, after); why != "" {
					t.Errorf("%s left the record %s", p, why)
				}
			})
		}
	}

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

// iamShaped is a 403 as the DNS endpoint's IAM answers it, before
// Kubernetes sees the request: Google's JSON error, not a Status.
var iamShaped = kube.Status{Status: tkube.Status{Kind: "GoogleError", Message: "Permission denied"}}

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
			fc := &fakeCluster{ip: "203.0.113.1", rolloutErr: failAfter, uidErr: failPreflight}
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

	// Under --confirm (ADR 0023 M2.6, A23-23): connect, redeploy, kernel
	// deploy and storage deploy read the registry to plan, so planRegistry
	// refuses the record before any plan is computed, its blank key read
	// before the provider opens; kernel deploy and storage deploy have read
	// the cluster as the reader first, which is all they sent. build plans
	// with no key, so it compares and refuses at the writer's open; and so
	// does run (M2.6d), with its fetch plan's digest, reading nothing, and
	// with its deploy plan's, read as the reader alone (runDeployDigest
	// needs no installer key). Either way nothing is minted for the writer,
	// ensured, looked up or pushed, nothing is printed, and no file changes.
	for _, row := range confirmingPlans(t) {
		t.Run(row.String()+"/--confirm", func(t *testing.T) {
			s, dir := planFixtureKeyed(t, row, false)
			digest := sampleDigest
			if row.name == "build" || row.name == "run" {
				digest = planDigest(t, dir, row)
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
			if out.Len()+errb.Len() != 0 {
				t.Errorf("%s --confirm printed %q %q before refusing", row, out, errb)
			}
			onlyThePlansReads(t, row, s, consentConfirm)
			sameFiles(t, row.String()+" --confirm on an ADC instance", before, treeFiles(t, string(dir)))
		})
	}

	// storage key pin (ADR 0023 M2.6c, A23-23; C-C-R3 of the M2.6c review)
	// costs nothing, but writes: its plan reads as the reader and needs no
	// installer key, so an ADC install plans, and its --confirm compares and
	// is refused at the writer's open, credential_missing, having sent only
	// the reader's reads, written no pin and opened no keyholder.
	t.Run("storage key pin/a pin to write/--confirm", func(t *testing.T) {
		realPinOpener(t)
		row := planCommandNamed(t, "storage key pin", "a pin to write")
		s, dir := planFixtureKeyed(t, row, false)
		doc, _ := runPlan(t, dir, row, output.ModeJSON)
		before := treeFiles(t, string(dir))
		cmd := realWriter(t, withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", doc.Digest)...))
		env, out, errb := testEnvBoth(dir, output.ModeJSON)
		err := cmd.Run(t.Context(), env, row.args)
		if !errors.Is(err, errCredentialMissing) || !strings.Contains(err.Error(), msgADCRefused) || kindOf(classified(err)) != kindCredentialMissing {
			t.Fatalf("%s --confirm on an ADC instance = %v; want the installer key refused at the writer's open, credential_missing", row, err)
		}
		if out.Len()+errb.Len() != 0 || row.fakes.keyholders != 0 {
			t.Errorf("%s --confirm printed %q %q and opened the keyholder %d times before refusing", row, out, errb, row.fakes.keyholders)
		}
		onlyThePlansReads(t, row, s, consentConfirm)
		sameFiles(t, row.String()+" --confirm on an ADC instance", before, treeFiles(t, string(dir)))
	})
}

// confirmingPlans are the plan rows of the commands that apply, one per
// state that confirms into a deploy: connect's first deploy and resume,
// redeploy, build, kernel deploy and storage deploy (ADR 0023 M2.6b and
// M2.6c); and run's fetch plan, whose --confirm applies the manifest read,
// and its deploy plan into a metered namespace (M2.6d, A28-11).
func confirmingPlans(t *testing.T) []planCommand {
	t.Helper()
	return []planCommand{
		planCommandNamed(t, "connect", "first deploy"),
		planCommandNamed(t, "connect", "resume"),
		planCommandNamed(t, "redeploy", "the carried images"),
		planCommandNamed(t, "build", "a named builder"),
		planCommandNamed(t, "kernel deploy", "the carried image"),
		planCommandNamed(t, "storage deploy", "the recorded bucket"),
		planCommandNamed(t, "run", "the images named"),
		runDeployRowNamed(t, "deploy into a metered namespace"),
	}
}

// applyingPlan is one plan of a command that applies, as the tests of its
// applies confirm it against kubetest (ADR 0023 M2.7, A30-29, A30-31): its
// plan row; for a run row, which of run's two plans --confirm takes; and
// what the fixture needs so that the command runs past its applies, since
// kubetest finishes no Job.
type applyingPlan struct {
	row planCommand
	// fetch confirms run's fetch plan, whose --confirm applies the manifest
	// read; a run row without it confirms its deploy plan.
	fetch bool
	// seed adds to the row's fixture before the plan.
	seed func(s *kubetest.Server)
}

func (p applyingPlan) String() string {
	if p.row.stage == "deploy" {
		if p.fetch {
			return "run <F>"
		}
		return "run <D>"
	}
	return p.row.String()
}

// applyingPlans is a plan of each of the nine commands that apply, and both
// of run's (ADR 0023 M2.7): connect's first deploy, redeploy, build, kernel
// deploy, kernel meter, kernel confirm, storage deploy, reader grant, and
// run's fetch and deploy plans into runTarget. build's Job is seeded
// finished, so its apply keeps that status and its wait ends at once.
func applyingPlans(t *testing.T) []applyingPlan {
	t.Helper()
	return []applyingPlan{
		{row: planCommandNamed(t, "connect", "first deploy")},
		{row: planCommandNamed(t, "redeploy", "the carried images")},
		{row: planCommandNamed(t, "build", "a named builder"), seed: func(s *kubetest.Server) {
			finishedJob(s, pbuild.JobName(writeName, "api"), "00000000-0000-4000-8000-0000000000b3", "kaniko", sha("d"), "")
		}},
		{row: planCommandNamed(t, "kernel deploy", "the carried image")},
		{row: planCommandNamed(t, "kernel meter", "add")},
		{row: planCommandNamed(t, "kernel confirm", "a window")},
		{row: planCommandNamed(t, "storage deploy", "the recorded bucket")},
		{row: planCommandNamed(t, "reader grant", "a recorded reader")},
		{row: runDeployRowNamed(t, "deploy into a metered namespace"), fetch: true},
		{row: runDeployRowNamed(t, "deploy into a metered namespace")},
	}
}

// rolledBack is "" when after is the record a failure of p's command leaves
// from before, and otherwise what is wrong with it: no failure leaves the
// instance unmigrated; connect and redeploy record FatLine only once it is
// applied; kernel deploy and storage deploy record their workload before
// the apply and keep it, unapplied; kernel meter and kernel confirm put back
// what they recorded before the apply; and build, run and reader grant
// record nothing until they are done.
func (p applyingPlan) rolledBack(before, after *config.InstanceMetadata) string {
	if after.ServerSideApply == nil {
		return "unmigrated"
	}
	same := func(field string, a, b any) string {
		if !reflect.DeepEqual(a, b) {
			return fmt.Sprintf("with %s %+v, not %+v", field, b, a)
		}
		return ""
	}
	switch p.row.name {
	case "connect":
		if after.FatLineDeployed || after.Carrier != nil {
			return "naming FatLine deployed"
		}
	case "redeploy":
		if why := same("FatLine's image", before.Registry.FatLineDigest, after.Registry.FatLineDigest); why != "" {
			return why
		}
		return same("its system images", before.SystemImages, after.SystemImages)
	case "kernel deploy":
		if after.Kernel == nil || !after.Kernel.Deployed || (after.Kernel.Applied && !reflect.DeepEqual(before.Kernel, after.Kernel)) {
			return fmt.Sprintf("with the kernel %+v; want it as it was, or recorded and not applied", after.Kernel)
		}
	case "kernel meter":
		return same("the metered namespaces", before.Kernel.Namespaces, after.Kernel.Namespaces)
	case "kernel confirm":
		return same("the confirmations", before.Kernel.Confirmations, after.Kernel.Confirmations)
	case "storage deploy":
		if after.Keyholder == nil || !after.Keyholder.Deployed {
			return fmt.Sprintf("with the keyholder %+v; want it recorded", after.Keyholder)
		}
	case "reader grant":
		return same("the reader", before.Reader, after.Reader)
	case "build", "run":
		if why := same("the deployments", before.Deployments, after.Deployments); why != "" {
			return why
		}
		return same("the kernel", before.Kernel, after.Kernel)
	}
	return ""
}

// confirmation is what confirmApplying or yesApplying saw: the fixture, the
// plan, the requests the run after it sent, and its error, stdout and
// stderr.
type confirmation struct {
	s              *kubetest.Server
	dir            config.Dir
	b              plan.Bound
	sent           []kubetest.Request
	err            error
	stdout, stderr string
}

// confirmApplying plans p on its fixture, over a settled kubetest started
// with opts (A30-31), then confirms it through the command's real writer,
// with before run between the plan and the confirm. connect's carrier dials
// a connected tunnel, and run's keyholder serves, so a confirm that applies
// everything ends there; any other stop is the test's own.
func confirmApplying(t *testing.T, p applyingPlan, before func(s *kubetest.Server, dir config.Dir, b plan.Bound), opts ...kubetest.Option) confirmation {
	t.Helper()
	s, dir := planFixtureWith(t, p.row, true, opts...)
	if p.seed != nil {
		p.seed(s)
	}
	recordedRegistry(t, p.row, dir)
	var doc plan.Document
	if p.row.stage == "deploy" && !p.fetch {
		doc, _ = runDeployPlan(t, dir, p.row, output.ModeJSON)
	} else {
		doc, _ = runPlan(t, dir, p.row, output.ModeJSON)
	}
	c := confirmation{s: s, dir: dir, b: decodedBound(t, doc)}
	if before != nil {
		before(s, dir, c.b)
	}
	c.run(t, p, "--confirm", doc.Digest)
	return c
}

// yesApplyingCommands are the commands that apply whose interactive or
// --yes run opens its writer apart from the one --confirm opens: each takes
// --yes. kernel meter, kernel confirm and reader grant open one writer in
// every mode.
var yesApplyingCommands = []string{"connect", "redeploy", "build", "kernel deploy", "storage deploy", "run"}

// yesApplying is confirmApplying's --yes form, for a command of
// yesApplyingCommands: p's plan is printed with --plan (run's fetch plan, for
// a run row), and before run between it and the command run again with
// --yes, through its real writer, past every question.
func yesApplying(t *testing.T, p applyingPlan, before func(s *kubetest.Server, dir config.Dir, b plan.Bound), opts ...kubetest.Option) confirmation {
	t.Helper()
	s, dir := planFixtureWith(t, p.row, true, opts...)
	if p.seed != nil {
		p.seed(s)
	}
	recordedRegistry(t, p.row, dir)
	doc, _ := runPlan(t, dir, p.row, output.ModeJSON)
	c := confirmation{s: s, dir: dir, b: decodedBound(t, doc)}
	if before != nil {
		before(s, dir, c.b)
	}
	c.run(t, p, "--yes")
	return c
}

// run runs p's command once with answer, through its real writer, connect's
// carrier a connected tunnel and run's keyholder one whose replicas serve,
// and records what it sent and said.
func (c *confirmation) run(t *testing.T, p applyingPlan, answer ...string) {
	t.Helper()
	sent := len(c.s.Requests())
	cmd := realWriter(t, withFlags(t, p.row.cmd(), append(slices.Clone(p.row.flags), answer...)...))
	switch cmd := cmd.(type) {
	case *connectCommand:
		cmd.dial = connectedDial()
	case *runCommand:
		cmd.newKeyholder = openerFor(&fakeStateKeyholder{phase: "unsealed"})
	}
	env, out, errb := testEnvBoth(c.dir, output.ModeJSON)
	c.err = cmd.Run(t.Context(), env, p.row.args)
	c.sent, c.stdout, c.stderr = c.s.Requests()[sent:], out.String(), errb.String()
}

// recordedRegistry makes the fake provider of row, if it has one, ensure the
// registry its fixture's record names, as the real ensure finds it, so a
// command past its comparison realizes the registry its plan bound.
func recordedRegistry(t *testing.T, row planCommand, dir config.Dir) {
	t.Helper()
	if row.fakes == nil || row.fakes.provider == nil {
		return
	}
	meta, err := dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	row.fakes.provider.registry = &planck.Registry{Ref: registryRefFor(meta), Prefix: meta.Registry.Prefix}
}

// appliedOf is the applies among reqs, in order: appliedRequests over a
// slice of what a server saw.
func appliedOf(reqs []kubetest.Request) []kubetest.Request {
	var out []kubetest.Request
	for _, r := range reqs {
		if r.Method == http.MethodPatch && r.ContentType == "application/apply-patch+yaml" {
			out = append(out, r)
		}
	}
	return out
}

// factPath is the API path of the object a write fact writes.
func factPath(t *testing.T, w plan.WriteFact) string {
	t.Helper()
	k, ok := kube.KindOf(w.API, w.Kind)
	if !ok {
		t.Fatalf("the plan writes %s %s, which is no kind farcast applies", w.API, w.Kind)
	}
	return k.Path(w.Namespace, w.Name)
}

// applyWrites is a plan's apply write facts, in its order.
func applyWrites(b plan.Bound) []plan.WriteFact {
	var out []plan.WriteFact
	for _, f := range planWrites(b) {
		if w := f.(plan.WriteFact); w.Method == plan.WriteApply {
			out = append(out, w)
		}
	}
	return out
}

// realWriter clears cmd's writing seams, which its planCommands row sets to
// refuse, so --confirm opens the instance's writer as farcast does (and
// storage deploy reaches its pin through it).
func realWriter(t *testing.T, cmd Command) Command {
	t.Helper()
	switch c := cmd.(type) {
	case *connectCommand:
		c.newCluster = nil
	case *redeployCommand:
		c.newCluster = nil
	case *buildCommand:
		c.newCluster = nil
	case *kernelDeployCommand:
		c.deployer.newCluster = nil
	case *storageDeployCommand:
		c.deployer.newCluster, c.newPinStore = nil, nil
	case *keyPinCommand:
		c.newPinStore = nil
	case *runCommand:
		c.newCluster = nil
	case *migrateCommand:
		c.newCluster = nil
	case *kernelMeterCommand, *kernelConfirmCommand, *readerGrantCommand:
		// Their rows leave every writing seam to its default, the writer.
	default:
		t.Fatalf("%T has no writing seam here", cmd)
	}
	return cmd
}

// onlyThePlansReads fails t unless every request s saw is one row's plan
// may make under m (design §7.3, A23-20): none for a plan that reads no
// cluster, and for one that reads it, the reader's token and the reader's
// GETs, or for migrate's, read as the writer (identity "writer", A30-26),
// the writer's token and the writer's GETs. Under --confirm a row whose
// --confirm reads the cluster (confirmReadsCluster, run's fetch plan) may
// make the reader's too.
func onlyThePlansReads(t *testing.T, row planCommand, s *kubetest.Server, m consentMode) {
	t.Helper()
	onlyThePlansSent(t, row, s.Requests(), m)
}

// onlyThePlansSent is onlyThePlansReads over reqs: for a test whose server
// saw a writer's requests too, before the ones it checks.
func onlyThePlansSent(t *testing.T, row planCommand, reqs []kubetest.Request, m consentMode) {
	t.Helper()
	reads := row.readsCluster || row.identity == "writer" || (m == consentConfirm && row.confirmReadsCluster)
	as := "reader"
	if row.identity == "writer" {
		as = "writer"
	}
	for _, r := range reqs {
		switch {
		case !reads:
			t.Errorf("%s reads no cluster, and sent %s %s as %q", row, r.Method, r.Path, r.As)
		case r.As != as:
			t.Errorf("%s sent %s %s as %q; its plan reads as the %s alone", row, r.Method, r.Path, r.As, as)
		case r.Path != "/token" && r.Method != http.MethodGet:
			t.Errorf("%s sent %s %s; a plan only reads", row, r.Method, r.Path)
		}
	}
}

// ADR 0023 M2.5 (A20-12), mutation 71c: each writing command checks that the
// record it loaded names the instance it was given, before the writer opens:
// openCluster reads credentials.yaml under the recorded name. A record naming another instance is refused as
// errCredentialMissing with recordNamed's words; credentials.yaml is never
// read and nothing is sent.
func TestWritingCommandsRefuseARecordNamingAnotherInstance(t *testing.T) {
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

// ADR 0023 M2.7 (A30-35, §10.5 row 105a): farcast starts no kubectl, so no
// help or hint sends the operator to one. No Synopsis, Usage or flag usage of
// any command the router reaches, each group and its subcommands included,
// names kubectl, and neither do the five hint texts: build's, run's and the
// manifest read's failures, redeploy's rollout hint and kernel deploy's
// missing-namespace block. migrate's Usage names kubectl only as what it
// migrates from (design §6.1): its client-side apply, that apply's manager
// entry and its last-applied annotation.
func TestNoCommandHelpNamesKubectl(t *testing.T) {
	migratedFrom := []string{"kubectl's client-side apply", "kubectl-client-side-apply entry", "kubectl's last-applied annotation"}
	var seen []string
	var walk func(prefix string, reg *Registry)
	walk = func(prefix string, reg *Registry) {
		for _, c := range reg.Commands() {
			name := strings.TrimSpace(prefix + " " + c.Name())
			seen = append(seen, name)
			texts := map[string]string{"Synopsis": c.Synopsis(), "Usage": c.Usage()}
			commandFlags(c).VisitAll(func(f *flag.Flag) { texts["--"+f.Name] = f.Usage })
			for what, text := range texts {
				flat := strings.Join(strings.Fields(text), " ")
				if name == "migrate" && what == "Usage" {
					for _, phrase := range migratedFrom {
						if !strings.Contains(flat, phrase) {
							t.Errorf("migrate's Usage no longer says %q; this test's exemption is stale:\n%s", phrase, text)
						}
						flat = strings.ReplaceAll(flat, phrase, "")
					}
				}
				if strings.Contains(flat, "kubectl") {
					t.Errorf("%s's %s names kubectl:\n%s", name, what, text)
				}
			}
			if g, ok := c.(*group); ok {
				walk(name, g.subs)
			}
		}
	}
	walk("", defaultRegistry())
	for _, want := range []string{"migrate", "build", "run", "redeploy", "kernel meter", "reader grant", "usage", "storage key pin", "storage key rotate"} {
		if !slices.Contains(seen, want) {
			t.Errorf("the walk never reached %q; it reached %q", want, seen)
		}
	}
	for name, text := range map[string]string{
		"build's failure":                         msgBuildFailed,
		"run's build failure":                     msgRunBuildFailed,
		"the manifest read's failure":             msgFetchFailed,
		"redeploy's rollout hint":                 msgInspectFatline,
		"kernel deploy's missing-namespace block": msgNoSuchNamespace,
	} {
		if strings.Contains(text, "kubectl") {
			t.Errorf("%s names kubectl: %q", name, text)
		}
	}
}

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

// ADR 0023 M2.5 (A20-10, M-F10, mutation o16): storage deploy opens one
// writer, for its pin and its apply. It reads credentials.yaml, which holds
// the private key, once, and mints once. It stops at a refused pin read,
// before the cost is asked or a provider is opened.
func TestStorageDeployOpensOneWriter(t *testing.T) {
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
	if applied := len(appliedRequests(s)); o.opened+o.built+o.storage+applied != 0 {
		t.Errorf("storage deploy went on past a refused pin read: provider %d, builder %d, storage %d, applies %d", o.opened, o.built, o.storage, applied)
	}
}

// ADR 0023 M2.5 (C-F1): when run hands new scopes to a serving keyholder, it
// raises the key pin through the writer it opened, not a second one: the
// installer's credentials.yaml is read once and its token minted once for
// the whole run, and the pin is created as the writer.
func TestRunRaisesThePinThroughItsOwnWriter(t *testing.T) {
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
	if _, err := preflightUID(t.Context(), cl); err != nil {
		t.Fatal(err)
	}
	if err := c.handScopesToTheKeyholder(t.Context(), env, meta, []string{"web"}, cl, nil); err != nil {
		t.Fatal(err)
	}

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
	// identity is who the plan reads the cluster as, its cluster_identity:
	// "reader" for a row that readsCluster; "writer" for migrate's, the one
	// plan read as the writer, because it lists Secrets' metadata (ADR 0023
	// M2.7, design §6.1, A30-26); and "none" for a plan that reads no
	// cluster. TestEveryWritingCommandHasAPlanRow holds it to the plan's.
	identity string
	// confirmReadsCluster: its --confirm of a digest that is not its own
	// reads the cluster as the reader, where its --plan reads none: run's
	// fetch plan, whose --confirm of any other digest reads the fetch Job a
	// deploy plan would (A23-47, A28-11).
	confirmReadsCluster bool
	// stage is run's: "fetch" for its fetch plan, which --plan prints, and
	// "deploy" for its deploy plan (runDeployRows), which --confirm with the
	// fetch plan's digest prints; "" for every other command.
	stage string
	cmd   func() Command
	edit  func(meta *config.InstanceMetadata)
	// prepare, when set, writes what the record alone cannot say: the
	// instance's mTLS material, for connect's resume and reconnect.
	prepare func(t *testing.T, dir config.Dir)
	// seed, when set, puts what the plan reads in the fixture's cluster:
	// farcast-system, for a plan that reads the cluster.
	seed func(s *kubetest.Server)
	// fakes are what the row's command reaches the provider, the registry,
	// the writer, the carrier, the plan's reader, storage and the keyholder
	// through, for a command that has those seams (connect's, redeploy's,
	// kernel deploy's, storage deploy's, storage key pin's, storage key
	// rotate's, and build's builder and writer): a plan may open the
	// provider, mint the registry's token and look up, open its reader and
	// read as it, and nothing more. nil for one with none of them.
	fakes *planFakes
}

func (p planCommand) String() string { return p.name + "/" + p.shape }

// planFakes are a plan row's fakes, and what its plans asked of them.
type planFakes struct {
	provider *fakeProvider
	builder  *fakeBuilder
	// opened counts the provider's opens, writers the writer's (a pin
	// store's included), dialled the carrier's dials, storages storage
	// deploy's mints of the bucket and keyring, and keyholders the
	// keyholder's opens.
	opened, writers, dialled, storages, keyholders int
	// readers is the identity the plan's reader seam was asked to open, at
	// each open (A23-49).
	readers []kube.Identity
}

// planSystemUID is farcast-system's uid in the fixture's cluster, which a
// plan that reads the cluster binds as its target.
const planSystemUID = "00000000-0000-4000-8000-0000000000a1"

// systemNamespace puts farcast-system in s, at planSystemUID.
func systemNamespace(s *kubetest.Server) {
	s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{
		"name": tcdeploy.DefaultNamespace, "uid": planSystemUID}})
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
// defaults fakes for the rest of the test, and a plan's reader the loopback
// one: for a test that runs connect or kernel deploy through the router,
// which sets no seam of its own, and whose unset seams otherwise refuse
// (refusingdefaults_test.go). The provider answers as the GKE adapter does,
// the builder as fakeBuilder, the checkout is --source's directory or
// routerCheckout, the Go is fakeToolchain's, and the reader is
// loopbackReader.
func fakeDeployDefaults(t *testing.T) (*fakeProvider, *fakeBuilder) {
	t.Helper()
	fp, fb := &fakeProvider{}, &fakeBuilder{}
	savedOpen, savedBuild := openProviderDefault, newBuilderDefault
	savedSource, savedToolchain := findSourceDefault, findToolchainDefault
	savedReader := openReaderDefault
	openProviderDefault = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) { return fp, nil }
	newBuilderDefault = func(func(string)) imageBuilder { return fb }
	findSourceDefault = func(dir string) (string, error) {
		if dir == "" {
			return routerCheckout, nil
		}
		return dir, nil
	}
	findToolchainDefault = fakeToolchain
	openReaderDefault = loopbackReader
	t.Cleanup(func() {
		openProviderDefault, newBuilderDefault = savedOpen, savedBuild
		findSourceDefault, findToolchainDefault = savedSource, savedToolchain
		openReaderDefault = savedReader
	})
	return fp, fb
}

// loopbackReader is openReader for a record whose endpoint is a loopback
// address, a kubetest server's, and a refusal before anything is opened for
// any other: the reader a test's plan reads the cluster as, which can reach
// no cluster but one the test started.
func loopbackReader(r clusterRef) (*cluster.Client, error) {
	if r.Meta == nil {
		return nil, errors.New("test: a plan's reader needs the instance's record")
	}
	if !loopbackEndpoint(r.Meta.Endpoint) {
		return nil, fmt.Errorf("test: a plan's reader opens only a loopback test server, and the record names %q", r.Meta.Endpoint)
	}
	return openReader(r)
}

// loopbackEndpoint says whether a recorded endpoint is a loopback address
// and a port, as a kubetest server's is.
func loopbackEndpoint(endpoint string) bool {
	host, _, err := net.SplitHostPort(endpoint)
	ip := net.ParseIP(host)
	return err == nil && ip != nil && ip.IsLoopback()
}

// planCommands is every --plan shape of the commands wired so far: kernel
// meter, kernel confirm and reader grant (ADR 0023 M2.6a), none of which
// reads the cluster; connect and redeploy (M2.6b), which read none either
// and read the registry through their fakes; build (M2.6b), which reads
// neither the cluster nor Google; kernel deploy and storage deploy (M2.6c),
// which read the cluster as the instance's reader, through loopbackReader
// against the fixture's kubetest, and the registry through their fakes;
// storage key pin (M2.6c), which reads the cluster as the reader and no
// Google; and storage key rotate (M2.6c), which reads the cluster as the
// reader when a keyholder is deployed, and no cluster otherwise, and no
// Google; run (M2.6d), whose rows are below and in runDeployRows; and
// migrate (M2.7, A30-26), whose plan reads the cluster as the writer, the
// instance's own against the fixture's kubetest, and no Google. kernel
// confirm reads planClock; through the router, pinPlanClock fixes the same
// clock.
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
	// kernel deploy, its deployer as connect's, and its plan's reader the
	// instance's, against the fixture's kubetest, the identity it was asked
	// for recorded.
	kernelDeploy := func(f *planFakes) func() Command {
		return func() Command {
			c := &kernelDeployCommand{}
			deployer(&c.deployer, f)
			c.newPlanReader = func(r clusterRef) (kernelPlanReader, error) {
				f.readers = append(f.readers, r.Identity)
				cl, err := loopbackReader(r)
				if err != nil {
					return nil, err
				}
				return cl, nil
			}
			return c
		}
	}
	// A plan's reader seam of the storage commands: the instance's reader,
	// against the fixture's kubetest, the identity it was asked for
	// recorded.
	pinReader := func(f *planFakes) func(clusterRef) (pinPlanReader, error) {
		return func(r clusterRef) (pinPlanReader, error) {
			f.readers = append(f.readers, r.Identity)
			cl, err := loopbackReader(r)
			if err != nil {
				return nil, err
			}
			return cl, nil
		}
	}
	// The pin store as the writer, which no plan opens.
	pinWriter := func(f *planFakes) pinStoreOpener {
		return func(clusterRef) (pinStore, error) {
			f.writers++
			return nil, errors.New("test: a plan opened the pin as the writer")
		}
	}
	// storage deploy, its deployer as connect's, its storage mint counting,
	// its pin store as the writer refused, and its plan's reader the
	// instance's.
	storageDeploy := func(f *planFakes) func() Command {
		return func() Command {
			c := &storageDeployCommand{}
			deployer(&c.deployer, f)
			c.ensureStorage = func(context.Context, *Env, string) error {
				f.storages++
				return errors.New("test: a plan minted storage")
			}
			c.newPinStore = pinWriter(f)
			c.newPlanReader = pinReader(f)
			return c
		}
	}
	// storage key pin, its pin store as the writer refused, its keyholder
	// counting, and its plan's reader the instance's.
	keyPin := func(f *planFakes) func() Command {
		return func() Command {
			c := &keyPinCommand{}
			c.newPinStore = pinWriter(f)
			c.newKeyholder = func(context.Context, *Env, string) (sealStateClient, func(), error) {
				f.keyholders++
				return nil, nil, errors.New("test: a plan opened the keyholder")
			}
			c.newPlanReader = pinReader(f)
			return c
		}
	}
	// storage key rotate, its pin store as the writer refused, its keyholder
	// counting, and its plan's reader the instance's.
	keyRotate := func(f *planFakes) func() Command {
		return func() Command {
			c := &keyRotateCommand{}
			c.newPinStore = pinWriter(f)
			c.newKeyholder = func(context.Context, *Env, string) (sealStateClient, func(), error) {
				f.keyholders++
				return nil, nil, errors.New("test: a plan opened the keyholder")
			}
			c.newPlanReader = pinReader(f)
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
	kernelCarried, kernelBelow, kernelNamed, kernelMissing := fakes(notFoundForTags), fakes(nil), fakes(nil), fakes(nil)
	belowFloor := func(m *config.InstanceMetadata) { m.CostLimit.Amount = 50 }
	storageCarried, storageFirst, storageBehind, storageNamed := fakes(notFoundForTags), fakes(notFoundForTags), fakes(notFoundForTags), fakes(nil)
	pinNew, pinUnion, pinLowered, pinBelow := fakes(nil), fakes(nil), fakes(nil), fakes(nil)
	noStorage := func(m *config.InstanceMetadata) { m.Storage = nil }
	rotateHanded, rotateAlone, rotateBelow := fakes(nil), fakes(nil), fakes(nil)
	noKeyholderDeployed := func(m *config.InstanceMetadata) { m.Keyholder = nil }
	runNamed, runRecorded, runInto, runNoKernel, runOther, runShared := fakes(nil), fakes(nil), fakes(nil), fakes(nil), fakes(nil), fakes(nil)
	toolchainRecorded := func(m *config.InstanceMetadata) {
		m.Toolchain = &config.Toolchain{Fetcher: fetcherDigest, Builder: builderDigest}
	}
	intoShop := append(slices.Clone(runFixtureFlags), "--namespace", "shop")
	// migrate, its writer the instance's, against the fixture's kubetest
	// (migrateWriterDefault, loopback only here), counted as a writer open.
	migrate := func(f *planFakes) func() Command {
		return func() Command {
			return &migrateCommand{newCluster: func(r clusterRef) (migrateCluster, error) {
				f.writers++
				return migrateWriterDefault(r)
			}}
		}
	}
	migrating, nothingToMigrate := fakes(nil), fakes(nil)

	return []planCommand{
		{name: "kernel meter", shape: "add", identity: "none", args: []string{writeName, writeNewNamespace}, cmd: meter},
		{name: "kernel meter", shape: "remove", identity: "none", args: []string{writeName, writeNewNamespace}, flags: []string{"--remove"}, cmd: meter, edit: metering},
		{name: "kernel meter", shape: "already metered", identity: "none", args: []string{writeName, writeNewNamespace}, cmd: meter, edit: metering},
		{name: "kernel confirm", shape: "a window", identity: "none", args: []string{writeName}, flags: []string{"--amount", "1.25", "--from", planMonth(1), "--to", planMonth(2)}, cmd: confirm},
		{name: "kernel confirm", shape: "an empty window", identity: "none", args: []string{writeName}, flags: []string{"--amount", "0", "--from", planMonth(2), "--to", planMonth(2)}, cmd: confirm},
		{name: "reader grant", shape: "a recorded reader", identity: "none", args: []string{writeName}, cmd: grant},
		{name: "reader grant", shape: "no reader", identity: "none", args: []string{writeName}, cmd: grant, edit: func(m *config.InstanceMetadata) { m.Reader = nil }},
		// A first deploy mints the instance's material and pushes the
		// carried images, whose version tags the registry lacks.
		{name: "connect", shape: "first deploy", identity: "none", args: []string{writeName}, cmd: connect(first), edit: firstDeploy, fakes: first},
		{name: "connect", shape: "resume", identity: "none", args: []string{writeName}, cmd: connect(resumed), edit: resume, prepare: writeMaterial, fakes: resumed},
		{name: "connect", shape: "resume, its material lost", identity: "none", args: []string{writeName}, cmd: connect(lost), edit: resume, fakes: lost},
		{name: "connect", shape: "reconnect", identity: "none", args: []string{writeName}, cmd: connect(again), prepare: writeMaterial, fakes: again},
		{name: "connect", shape: "a source build", identity: "none", args: []string{writeName}, flags: []string{"--source", "/work/farcast"}, cmd: connect(source), edit: firstDeploy, fakes: source},
		// A redeploy pushes the carried images, whose version tags the
		// registry lacks, over the material the instance holds.
		{name: "redeploy", shape: "the carried images", identity: "none", args: []string{writeName}, cmd: redeploy(redeployed), prepare: writeMaterial, fakes: redeployed},
		{name: "redeploy", shape: "a source build", identity: "none", args: []string{writeName}, flags: []string{"--source", "/work/farcast"}, cmd: redeploy(rebuilt), prepare: writeMaterial, fakes: rebuilt},
		{name: "build", shape: "a named builder", identity: "none", args: []string{writeName}, flags: append(slices.Clone(buildFlags), "--builder-image", builderDigest), cmd: build(named), fakes: named},
		{name: "build", shape: "a recorded builder", identity: "none", args: []string{writeName}, flags: append(slices.Clone(buildFlags), "--ref", "refs/tags/v2", "--context", "svc", "--containerfile", "svc/Containerfile"),
			cmd: build(recordedBuilder), edit: builderRecorded, fakes: recordedBuilder},
		// A kernel deploy pushes the carried image, whose version tag the
		// registry lacks; below the floor, it binds that as a fact; with
		// --technocore-image it still reads the registry, which it ensures;
		// and a namespace the cluster lacks blocks it.
		{name: "kernel deploy", shape: "the carried image", identity: "reader", args: []string{writeName}, readsCluster: true, cmd: kernelDeploy(kernelCarried),
			seed: systemNamespace, fakes: kernelCarried},
		{name: "kernel deploy", shape: "below the floor", identity: "reader", args: []string{writeName}, readsCluster: true, cmd: kernelDeploy(kernelBelow),
			edit: belowFloor, seed: systemNamespace, fakes: kernelBelow},
		{name: "kernel deploy", shape: "a named image", identity: "reader", args: []string{writeName}, flags: []string{"--technocore-image", namedKernelImage},
			readsCluster: true, cmd: kernelDeploy(kernelNamed), seed: systemNamespace, fakes: kernelNamed},
		{name: "kernel deploy", shape: "a missing namespace", identity: "reader", args: []string{writeName}, flags: []string{"--namespaces", "web"},
			readsCluster: true, cmd: kernelDeploy(kernelMissing), seed: systemNamespace, fakes: kernelMissing},
		// A storage deploy over the recorded bucket pushes the carried
		// image, and creates the pin, which the cluster lacks; a first one
		// creates the bucket and mints the keyring too; with
		// --datasphered-image it still reads the registry, which it
		// ensures; and a keyring the pin is above blocks it.
		{name: "storage deploy", shape: "the recorded bucket", identity: "reader", args: []string{writeName}, readsCluster: true, cmd: storageDeploy(storageCarried),
			prepare: writeMaterial, seed: systemNamespace, fakes: storageCarried},
		{name: "storage deploy", shape: "a first deploy", identity: "reader", args: []string{writeName}, readsCluster: true, cmd: storageDeploy(storageFirst),
			edit: noStorage, prepare: noKeyring, seed: systemNamespace, fakes: storageFirst},
		{name: "storage deploy", shape: "a named image", identity: "reader", args: []string{writeName}, flags: []string{"--datasphered-image", namedKeyholderImage},
			readsCluster: true, cmd: storageDeploy(storageNamed), prepare: writeMaterial, seed: systemNamespace, fakes: storageNamed},
		{name: "storage deploy", shape: "behind the pin", identity: "reader", args: []string{writeName}, readsCluster: true, cmd: storageDeploy(storageBehind),
			prepare: writeMaterial, seed: pinSeeded(pinRequiringForeign), fakes: storageBehind},
		// A key pin creates the pin the cluster lacks; with --replace over
		// a pin it is not behind it raises it to the union, lowering
		// nothing; with --replace from behind the pin it lowers it; and
		// without --replace from behind the pin it is blocked.
		{name: "storage key pin", shape: "a pin to write", identity: "reader", args: []string{writeName}, readsCluster: true, cmd: keyPin(pinNew),
			seed: systemNamespace, fakes: pinNew},
		{name: "storage key pin", shape: "--replace over a pin it is not behind", identity: "reader", args: []string{writeName}, flags: []string{"--replace"},
			readsCluster: true, cmd: keyPin(pinUnion), seed: pinSeeded(pinRetiringForeign), fakes: pinUnion},
		{name: "storage key pin", shape: "--replace from behind the pin", identity: "reader", args: []string{writeName}, flags: []string{"--replace"},
			readsCluster: true, cmd: keyPin(pinLowered), seed: pinSeeded(pinRequiringForeign), fakes: pinLowered},
		{name: "storage key pin", shape: "behind the pin", identity: "reader", args: []string{writeName}, readsCluster: true, cmd: keyPin(pinBelow),
			seed: pinSeeded(pinRequiringForeign), fakes: pinBelow},
		// A rotate with a keyholder deployed reads the cluster and plans the
		// two pins the hand-over writes, the first a create of the pin the
		// cluster lacks; one with none deployed reads no cluster and writes
		// no pin; and a keyring the pin is above blocks it.
		{name: "storage key rotate", shape: "with a keyholder", identity: "reader", args: []string{writeName}, readsCluster: true, cmd: keyRotate(rotateHanded),
			seed: systemNamespace, fakes: rotateHanded},
		{name: "storage key rotate", shape: "no keyholder", identity: "none", args: []string{writeName}, cmd: keyRotate(rotateAlone),
			edit: noKeyholderDeployed, fakes: rotateAlone},
		{name: "storage key rotate", shape: "behind the pin", identity: "reader", args: []string{writeName}, readsCluster: true, cmd: keyRotate(rotateBelow),
			seed: pinSeeded(pinRequiringForeign), fakes: rotateBelow},
		// run's fetch plans (M2.6d): the manifest read, with both toolchain
		// images named, both recorded, or into a --namespace; and its blocks,
		// read from the record and keys.yaml alone: no kernel, a --namespace
		// recorded under another repository, and a keyring holding the scope
		// every application once shared. None reads the cluster; the
		// --confirm of a digest not its own reads the fetch Job a deploy plan
		// would, as the reader, but for a blocked one's, which reads nothing
		// (A28-8). Its deploy plans are runDeployRows.
		{name: "run", shape: "the images named", identity: "none", stage: "fetch", args: runFixtureArgs, flags: runFixtureFlags, confirmReadsCluster: true,
			cmd: runWithFakes(runNamed), fakes: runNamed},
		{name: "run", shape: "the images recorded", identity: "none", stage: "fetch", args: runFixtureArgs, confirmReadsCluster: true,
			cmd: runWithFakes(runRecorded), edit: toolchainRecorded, fakes: runRecorded},
		{name: "run", shape: "--namespace given", identity: "none", stage: "fetch", args: runFixtureArgs, flags: intoShop, confirmReadsCluster: true,
			cmd: runWithFakes(runInto), fakes: runInto},
		{name: "run", shape: "no kernel", identity: "none", stage: "fetch", args: runFixtureArgs, flags: runFixtureFlags,
			cmd: runWithFakes(runNoKernel), edit: func(m *config.InstanceMetadata) { m.Kernel = nil }, fakes: runNoKernel},
		{name: "run", shape: "a namespace recorded under another repository", identity: "none", stage: "fetch", args: runFixtureArgs, flags: intoShop,
			cmd: runWithFakes(runOther), edit: func(m *config.InstanceMetadata) {
				m.Deployments = map[string]config.Deployment{"shop": {Repository: "https://github.com/example/shop"}}
			}, fakes: runOther},
		{name: "run", shape: "a keyring holding the shared application scope", identity: "none", stage: "fetch", args: runFixtureArgs, flags: runFixtureFlags,
			cmd: runWithFakes(runShared), prepare: func(t *testing.T, dir config.Dir) { saveSharedScopeKeyring(t, dir, writeName) }, fakes: runShared},
		// migrate's plans (M2.7, A30-26), read as the writer: an instance an
		// older farcast applied with kubectl, its objects to migrate, and a
		// migrated one with nothing to migrate. Each finds the kubeconfig.yaml
		// the fixture holds, which a migration deletes.
		{name: "migrate", shape: "objects to migrate", identity: "writer", args: []string{writeName}, cmd: migrate(migrating),
			edit: func(m *config.InstanceMetadata) { m.ServerSideApply = nil }, seed: clientSideSeeded, fakes: migrating},
		{name: "migrate", shape: "nothing to migrate", identity: "writer", args: []string{writeName}, cmd: migrate(nothingToMigrate),
			seed: systemNamespace, fakes: nothingToMigrate},
	}
}

// foreignKeyID is a key id no fixture's keyring holds.
const foreignKeyID = "00112233aabbccdd"

// The pins the storage rows seed (pinSeeded): one that retires a key no
// keyring here holds, which a keyring is not behind and a raise unions in;
// and one that requires it, which every keyring here is behind.
var (
	pinRetiringForeign  = foreignPin(false)
	pinRequiringForeign = foreignPin(true)
)

// foreignPin is a pin of foreignKeyID alone, required or retired.
func foreignPin(require bool) string {
	id, err := datasphere.ParseKeyID(foreignKeyID)
	if err != nil {
		panic(err)
	}
	if require {
		return dskeyholder.Pin{Require: []datasphere.KeyID{id}}.Marshal()
	}
	return dskeyholder.Pin{Retired: []datasphere.KeyID{id}}.Marshal()
}

// pinSeeded puts farcast-system (systemNamespace) and the key pin, holding
// value, in s.
func pinSeeded(value string) func(s *kubetest.Server) {
	return func(s *kubetest.Server) {
		systemNamespace(s)
		s.Put(map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": dsdeploy.PinConfigMapName(""), "namespace": dsdeploy.DefaultNamespace},
			"data":     map[string]any{dsdeploy.PinKey: value},
		})
	}
}

// noKeyring is a first storage deploy's fixture: the instance's mTLS
// material (writeMaterial), and no keyring on this machine, which the
// deploy's storage mint makes.
func noKeyring(t *testing.T, dir config.Dir) {
	t.Helper()
	writeMaterial(t, dir)
	if err := os.Remove(dir.InstanceKeyringPath(writeName)); err != nil {
		t.Fatal(err)
	}
}

// namedKernelImage and namedKeyholderImage are operator-named TechnoCore and
// keyholder images: digest-pinned, as every image flag must be.
var (
	namedKernelImage    = "registry.example/technocore@" + sha("7")
	namedKeyholderImage = "registry.example/datasphered@" + sha("8")
)

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
	return planFixtureWith(t, row, keyed)
}

// planFixtureWith is planFixtureKeyed on a kubetest server started with
// opts. The server settles what a write leaves stored
// (WithSettledWorkloads, A30-31), so a --confirm that applies, which many
// rows' tests run, is answered as the API server and its controllers would,
// and a plan, which writes nothing, sees nothing of it.
func planFixtureWith(t *testing.T, row planCommand, keyed bool, opts ...kubetest.Option) (*kubetest.Server, config.Dir) {
	t.Helper()
	s := kubetest.New(t, append([]kubetest.Option{kubetest.WithSettledWorkloads()}, opts...)...)
	if row.seed != nil {
		row.seed(s)
	}
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
	plan.TypeNotice: reflect.TypeFor[plan.NoticeFact](), plan.TypeMigrate: reflect.TypeFor[plan.MigrateFact](),
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
// opts split it, as AllowResourceVersion splits the egress policy; each fact
// is at no resourceVersion, which the caller sets.
func wantWrites(t *testing.T, stream []byte, opts ...kube.SplitOption) []plan.Fact {
	t.Helper()
	docs, err := kube.SplitStream(stream, opts...)
	if err != nil {
		t.Fatal(err)
	}
	var out []plan.Fact
	for _, d := range docs {
		out = append(out, plan.WriteFact{Type: plan.TypeWrite, API: d.Kind.APIVersion, Kind: d.Kind.Kind,
			Namespace: d.Namespace, Name: d.Name, Method: plan.WriteApply, Force: true, SHA256: fmt.Sprintf("%x", sha256.Sum256(d.Raw))})
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

// ADR 0023 M2.6 (rows 72, 73, 72a): --plan writes nothing. Every shape, in
// both modes, leaves the config directory byte for byte as it was, reaches
// the cluster only with GETs as its reader if it reads it at all (and not at
// all if not), and applies nothing. A command with a provider, a registry or
// a builder (connect's, redeploy's, build's, kernel deploy's, storage
// deploy's) ensures and deletes no registry, builds and pushes no image (its
// token and lookups are reads), opens no writer and dials nothing; storage
// deploy mints no storage, and storage key pin opens no keyholder. migrate's
// plan (ADR 0023 M2.7, A30-26) is read as the writer: it opens the writer
// once for each plan it prints, and only reads as it. The
// shapes are every command's (everyPlanShape, design §28's step 9b), and
// run's deploy plans among them are computed as --confirm of a digest that
// is no plan's computes them (runDeployDigest): as the reader alone, with
// no writer opened and no fetch Job applied.
func TestPlansWriteNothing(t *testing.T) {
	for _, row := range everyPlanShape(t) {
		t.Run(row.String(), func(t *testing.T) {
			s, dir := planFixture(t, row)
			before := treeFiles(t, string(dir))
			reads := observeConfigReads(t)
			what := row.String() + " --plan"
			if row.stage == "deploy" {
				what = row.String() + "'s plan, computed by --confirm " + zeroDigest
				runDeployDigest(t, dir, row, nil)
			} else {
				runPlan(t, dir, row, output.ModeJSON)
				runPlan(t, dir, row, output.ModeHuman)
			}
			sameFiles(t, what, before, treeFiles(t, string(dir)))
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
				// One writer open for each of the two plans printed, for a
				// plan read as the writer, and none for any other.
				opens := 0
				if row.identity == "writer" {
					opens = 2
				}
				if f.writers != opens || f.dialled+f.storages+f.keyholders != 0 {
					t.Errorf("%s --plan opened the writer %d times (want %d), dialled %d, minted storage %d times and opened the keyholder %d times",
						row, f.writers, opens, f.dialled, f.storages, f.keyholders)
				}
			}
			onlyThePlansReads(t, row, s, consentPlan)
		})
	}
}

// ADR 0023 M2.6 (A23-25, A23-45, mutations 91e and 91g): a plan opens
// keys.yaml for its key ids and their times, and carries none of its key
// material. Every plan of the storage commands — storage deploy's, storage
// key pin's and storage key rotate's — and run's fetch plans, which read
// keys.yaml for the shared scope when a keyholder is deployed, whose fixture
// holds a keyring, printed in JSON and in text, holds no key of it in base64
// (padded or not, standard or URL) or in hex; and none opens the CA's key, a
// server's key or the operator's. run's deploy plans (M2.6d) are their own
// rows.
func TestPlansCarryNoKeyMaterial(t *testing.T) {
	rows := 0
	for _, row := range planCommands() {
		if !strings.HasPrefix(row.name, "storage ") && row.name != "run" {
			continue
		}
		t.Run(row.String(), func(t *testing.T) {
			_, dir := planFixture(t, row)
			if held, err := dir.InstanceKeyringExists(writeName); err != nil || !held {
				t.Skipf("no keyring to leak (%v)", err)
			}
			rows++
			encoded, raw := keyMaterialOf(t, dir, writeName)
			reads := observeConfigReads(t)
			_, js := runPlan(t, dir, row, output.ModeJSON)
			_, text := runPlan(t, dir, row, output.ModeHuman)
			for i, key := range raw {
				for _, form := range []string{encoded[i], base64.StdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(key),
					base64.URLEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key), hex.EncodeToString(key)} {
					if strings.Contains(js, form) || strings.Contains(text, form) {
						t.Errorf("%s --plan prints key %d of keys.yaml, as %s", row, i, form)
					}
				}
			}
			for _, p := range reads() {
				if base := filepath.Base(p); base == "ca.key" || base == "server.key" || base == "client.key" {
					t.Errorf("%s --plan read %s", row, p)
				}
			}
		})
	}
	if rows == 0 {
		t.Fatal("no plan of a storage command ran over a keyring")
	}
	t.Run("run's deploy plans", runDeployPlansCarryNoKeyMaterial)
}

// ADR 0023 M2.6 (row 91): a plan does not depend on the terminal. Each is
// printed in human mode with stdin a character device, which isTerminal
// takes for a terminal, and with stdin a pipe; the digests are equal, and so
// are the bound bytes of the two in JSON. The shapes are every command's
// (everyPlanShape, design §28's step 9b); run's deploy plans among them are
// computed in human mode as --confirm of a digest that is no plan's
// computes them (runDeployDigest), with each stdin, and their digests are
// equal.
func TestPlanIgnoresTheTerminal(t *testing.T) {
	tty, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tty.Close() }()
	if !isTerminal(tty) {
		t.Fatalf("%s is not taken for a terminal here, so this test would prove nothing", os.DevNull)
	}
	for _, row := range everyPlanShape(t) {
		t.Run(row.String(), func(t *testing.T) {
			_, dir := planFixture(t, row)
			if row.stage == "deploy" {
				if inTTY, inPipe := runDeployDigest(t, dir, row, tty), runDeployDigest(t, dir, row, strings.NewReader("")); inTTY != inPipe {
					t.Errorf("the deploy plan in a terminal is %s, and in a pipe %s", inTTY, inPipe)
				}
				return
			}
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
// same plan (design §9.4, the clock). run's deploy plans (M2.6d) are printed
// twice by --confirm with the fetch plan's digest, each running the manifest
// read again: one that mints a scope, an egress credential and a leaf for
// each application binds the same bytes both times.
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
	for _, row := range runDeployRows(t) {
		t.Run(row.String(), func(t *testing.T) {
			_, dir := planFixture(t, row)
			first, _ := runDeployPlan(t, dir, row, output.ModeJSON)
			second, _ := runDeployPlan(t, dir, row, output.ModeJSON)
			if !bytes.Equal(first.Bound, second.Bound) || first.Digest != second.Digest {
				t.Errorf("two deploy plans from one state differ:\n%s\n%s", first.Bound, second.Bound)
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
	// A23-44: storage key pin --replace over a pin this keyring is not
	// behind plans the union with that pin, lowering nothing, twice alike;
	// its --confirm writes exactly that pin, and an interactive --replace
	// (here --yes) from the same pin writes the same one.
	t.Run("storage key pin/--replace over a pin it is not behind", func(t *testing.T) {
		dir, keys, ps := keyPinFixture(t)
		seeded := dskeyholder.Pin{Retired: []datasphere.KeyID{foreignID(t)}}
		union := pinFor(keys).Union(seeded)
		ps.set(seeded.Marshal())
		first := runKeyPinPlan(t, dir, nil, "--replace")
		second := runKeyPinPlan(t, dir, nil, "--replace")
		if !bytes.Equal(first.Bound, second.Bound) {
			t.Errorf("two plans from one state differ:\n%s\n%s", first.Bound, second.Bound)
		}
		f := pinFactOf(t, decodedBound(t, first))
		if !pinOfFact(t, f).Equal(union) || len(f.Lowering) != 0 || f.Repairing {
			t.Fatalf("the plan's pin is %+v; want the union %s, lowering nothing", f, union.Marshal())
		}
		if _, stderr, err := runKeyPinConfirm(t, dir, nil, first, "--replace"); err != nil {
			t.Fatalf("--confirm: %v\n%s", err, stderr)
		}
		confirmed := ps.pin(t)
		ps.set(seeded.Marshal())
		c := withFlags(t, &keyPinCommand{}, "--replace", "--yes")
		c.newKeyholder = noKeyholder
		env, _, errb := testEnvBoth(dir, output.ModeJSON)
		if err := c.Run(t.Context(), env, []string{writeName}); err != nil {
			t.Fatalf("--replace --yes: %v\n%s", err, errb)
		}
		if !confirmed.Equal(union) || !ps.pin(t).Equal(union) {
			t.Errorf("--confirm wrote %s and --replace --yes %s; want both the planned union %s", confirmed.Marshal(), ps.value, union.Marshal())
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
// only for the registry: connect's first deploy and resume, redeploy,
// kernel deploy and storage deploy, each with its image named or not, read it;
// connect's reconnect, build (which resolves a builder tag only
// anonymously, to refuse it, until M2.8's push grant), and kernel meter's,
// kernel confirm's, reader grant's and storage key pin's plans, have no
// registry read, and none reads credentials.yaml, nor does a kernel deploy
// blocked by a missing namespace, or a storage deploy blocked by the pin,
// which read nothing after their block (A23-18). Neither do run's plans
// (M2.6d): its fetch plan reads the record and keys.yaml, and its deploy
// plan, computed as --confirm of a digest that is no plan's computes it
// (runDeployDigest), reads as the reader alone; --confirm with the fetch
// plan's digest reads the key, for the writer that applies the manifest
// read, before a deploy plan exists (A28-11). migrate's plan (M2.7, A30-26)
// reads it too, not for Google: it reads the cluster as the writer. A plan
// of the read group on an instance installed without a key (Application
// Default Credentials) is refused credential_missing, before the provider
// opens.
func TestPlansStillReadTheInstallerKeyForGoogle(t *testing.T) {
	// By command, or by command/shape where its shapes differ.
	readsKey := map[string]bool{
		"kernel meter": false, "kernel confirm": false, "reader grant": false,
		"connect": true, "connect/reconnect": false, "redeploy": true, "build": false,
		"kernel deploy": true, "kernel deploy/a missing namespace": false,
		"storage deploy": true, "storage deploy/behind the pin": false, "storage key pin": false,
		"storage key rotate": false, "run": false, "migrate": true,
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
	for _, row := range runDeployRows(t) {
		t.Run(row.String(), func(t *testing.T) {
			_, dir := planFixture(t, row)
			reads := observeConfigReads(t)
			runDeployDigest(t, dir, row, nil)
			if slices.ContainsFunc(reads(), func(p string) bool { return filepath.Base(p) == "credentials.yaml" }) {
				t.Errorf("%s read credentials.yaml computing the deploy plan (%q)", row, reads())
			}
		})
	}
}

// ADR 0023 M2.6 (A23-26), mutation 91a: under --plan, a line a command
// prints while it works is a notice fact and is not printed; outside a plan
// it is printed once, in the same words. Rows for meteredReader's warning,
// kernel meter's no-op, kernel confirm's empty window, connect's and
// redeploy's keepingNote, kernel deploy's dropped namespace, storage
// deploy's bucket grant, storage key pin --replace's lowering warning, and
// storage key rotate's rotationScopeWarning, the last three several lines;
// and run's deploy plan (M2.6d), which --confirm with the fetch plan's
// digest prints.
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
				c.newCluster = func(clusterRef) (clusterApplier, error) { return &fakeCluster{ip: "203.0.113.1"}, nil }
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
		// kernel deploy's plan reads the cluster as the reader, here a fake
		// that has farcast-system and not the namespace the record meters
		// too; outside a plan it asks the cost, so its run there answers
		// with --yes, reading the same fake as the writer.
		{"kernel deploy's dropped namespace", func(t *testing.T, dir config.Dir) (func(...string) Command, []string) {
			meta := planNoticeInstance(t, dir, "p44")
			meta.Kernel = &config.Kernel{Deployed: true, Applied: true, Namespaces: []string{tcdeploy.DefaultNamespace, "gone"}}
			if err := dir.SaveInstanceMetadata(meta.Name, meta); err != nil {
				t.Fatal(err)
			}
			fc := &fakeCluster{namespaces: []string{tcdeploy.DefaultNamespace}, uid: "u1"}
			return func(flags ...string) Command {
				if len(flags) == 0 {
					flags = []string{"--yes"}
				}
				c := withFlags(t, &kernelDeployCommand{}, flags...)
				noticeDeployer(&c.deployer, fc)
				c.newPlanReader = func(clusterRef) (kernelPlanReader, error) { return fc, nil }
				return c
			}, []string{meta.Name}
		}, fmt.Sprintf(msgNoLongerMetering, "gone")},
		// storage deploy's plan names the bucket grant its run prints
		// before the apply (A23-12); outside a plan it asks the cost, so its
		// run there answers with --yes. Its pin is the instance's in-memory
		// one, read as the reader in the plan and as the writer outside it.
		{"storage deploy's bucket grant", func(t *testing.T, dir config.Dir) (func(...string) Command, []string) {
			meta := planNoticeInstance(t, dir, "p45")
			meta.Storage = &config.Storage{Bucket: "farcast-p45-0a1b2c3d", Provider: "gcs", Location: meta.Region}
			if err := dir.SaveInstanceMetadata(meta.Name, meta); err != nil {
				t.Fatal(err)
			}
			pinStoreOf(dir, meta.Name).uid = "u1"
			fc := &fakeCluster{uid: "u1"}
			return func(flags ...string) Command {
				if len(flags) == 0 {
					flags = []string{"--yes"}
				}
				c := withFlags(t, &storageDeployCommand{}, flags...)
				noticeDeployer(&c.deployer, fc)
				c.newPinStore = testDefaultPinStore
				c.newPlanReader = testPinPlanReader
				c.ensureStorage = func(context.Context, *Env, string) error { return errors.New("test: the bucket is recorded") }
				return c
			}, []string{meta.Name}
		}, bucketGrantText("proj-test1", "farcast-p45-0a1b2c3d")},
		// storage key pin --replace from a keyring behind the pin: its plan
		// names what lowering it admits again; outside a plan it says so
		// before it asks, so its run there answers with --yes. The pin is
		// the instance's in-memory one, holding a key this keyring lacks.
		{"storage key pin --replace's lowering", func(t *testing.T, dir config.Dir) (func(...string) Command, []string) {
			meta := planNoticeInstance(t, dir, "p46")
			meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
			if err := dir.SaveInstanceMetadata(meta.Name, meta); err != nil {
				t.Fatal(err)
			}
			saveKeyring(t, dir, meta.Name, appsKeyring(t, "web"))
			ps := pinStoreOf(dir, meta.Name)
			ps.uid = "u1"
			ps.set(pinRequiringForeign)
			return func(flags ...string) Command {
				if len(flags) == 0 {
					flags = []string{"--yes"}
				}
				c := withFlags(t, &keyPinCommand{}, append([]string{"--replace"}, flags...)...)
				c.newPlanReader = testPinPlanReader
				c.newKeyholder = noKeyholder
				return c
			}, []string{meta.Name}
		}, keyPinLowerWarning(&pinBehind{Missing: []string{foreignKeyID}})},
		// Outside a plan, rotate asks, so its run there answers with --yes;
		// with no keyholder deployed it hands nothing over.
		{"rotate's rotationScopeWarning", func(t *testing.T, dir config.Dir) (func(...string) Command, []string) {
			kernelInstance(t, dir, "p43")
			saveKeyring(t, dir, "p43", appsKeyring(t, "web"))
			return func(flags ...string) Command {
				if len(flags) == 0 {
					flags = []string{"--yes"}
				}
				return withFlags(t, &keyRotateCommand{newKeyholder: noKeyholder}, flags...)
			}, []string{"p43"}
		}, rotationScopeWarning},
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
				} else if want := strings.Join(noticeLines(noticeFact(row.want)), "\n") + "\n"; !strings.Contains(out.String(), want) {
					t.Errorf("the rendering does not show the notice %q:\n%s", want, out)
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
	t.Run("run's deploy plan", runDeployNoticesAreFacts)
}

// planNoticeInstance is TestPlanPrintsNoticesOnlyAsFacts's instance for the
// commands whose plans read the cluster (ADR 0023 M2.6c): installed in
// project proj-test1 with the installer's stand-in key, its registry
// recorded, connected with its material minted, and its reader granted the
// metered scope, its key on this machine. The rows add what each command
// needs.
func planNoticeInstance(t *testing.T, dir config.Dir, name string) *config.InstanceMetadata {
	t.Helper()
	meta := connectedInstance(t, dir, name)
	meta.Project = "proj-test1"
	recordRegistry(meta, derivedRegistry(registrySpec(meta)))
	meta.Reader = &config.Reader{Email: readerEmail(name, "proj-test1"), KeyID: readerTestKeyID, GrantedAt: readerGrantedAt, Scope: readerScopeMetered}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveReaderKey(name, []byte("not read"), []byte("not read")); err != nil {
		t.Fatal(err)
	}
	return meta
}

// noticeDeployer is d as TestPlanPrintsNoticesOnlyAsFacts's rows run it: a
// release carrying the fake components, its provider and builder fakes, its
// checkout and Go fakes, and its writer fc.
func noticeDeployer(d *fatlineDeployer, fc *fakeCluster) {
	asRelease(d, nil)
	d.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return &fakeProvider{}, nil
	}
	d.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
	d.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
	d.findSource = func(string) (string, error) { return "/checkouts/farcast", nil }
	d.findToolchain = fakeToolchain
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
	// kernel deploy and storage deploy (ADR 0023 M2.6c; rows O52 and O53 of
	// the M2.6c review): the same refusal, the same kinds.
	for _, sc := range singleImageCommands() {
		for _, answer := range []string{"--confirm", "--yes"} {
			t.Run(sc.name+"/"+answer, func(t *testing.T) {
				r := sc.rig(t, nil)
				planned := registryPrefix(r.meta(t))
				flags := []string{answer}
				if answer == "--confirm" {
					flags = append(flags, r.plan(t).Digest)
				}
				r.fp.registry = moved
				_, errb, err := r.run(t, flags...)
				want, kind := fmt.Sprintf(msgRegistryMoved, writeName, moved.Prefix, planned), kindInternal
				if answer == "--confirm" {
					want, kind = want+"; "+msgPlanAgain, kindPlanChanged
				}
				if err == nil || err.Error() != want || kindOf(classified(err)) != kind {
					t.Fatalf("%s %s over a moved registry = %v (kind %s); want %q, %s\n%s", sc.name, answer, err, kindOf(classified(err)), want, kind, errb)
				}
				if len(r.fb.embedded)+len(r.fb.built)+len(r.fc.applied) != 0 {
					t.Errorf("pushed %d, built %d and applied %d over a moved registry", len(r.fb.embedded), len(r.fb.built), len(r.fc.applied))
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
// Each command is planned, then confirmed through its real writer against a
// settled kubetest, and runs to the end (connect's carrier a connected
// tunnel, build's Job already finished); since ADR 0023 M2.7 each document
// is its own apply, read back as the PATCH that sent it (A30-31), as the
// writer with farcast's forced query. storage deploy, storage key pin and
// storage key rotate have their own rows (ADR 0023 M2.6c): the keyholder's
// stream and the bucket, and the pins; and so does run (M2.6d), whose deploy
// runs to the end: its builds, egress policy, workloads and key pin.
// FatLine's stream, from connect's first deploy (which mints the material)
// and from redeploy (which loads it): the plan's write facts are the planned
// rendering, over placeholder leaves and the plan's images, and the applied
// documents equal it document for document once a Secret's data and the
// mTLS hash are masked, and differ unmasked only there. build's three
// documents: byte for byte the plan's.
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
				c.dial = connectedDial()
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
			s := kubetest.New(t, kubetest.WithSettledWorkloads())
			finishedJob(s, pbuild.JobName(writeName, "api"), "00000000-0000-4000-8000-0000000000b3", "kaniko", sha("d"), "")
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

			if said, err := run("--confirm", doc.Digest); err != nil {
				t.Fatalf("--confirm = %v; want it done\n%s", err, said)
			}
			applied := appliedBodies(t, appliedRequests(s))
			if !row.fatline {
				if got, want := wantWrites(t, streamOf(applied)), planWrites(b); !reflect.DeepEqual(got, want) {
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
			appliedDocs, err := kube.SplitStream(streamOf(applied))
			if err != nil {
				t.Fatal(err)
			}
			if len(appliedDocs) != len(plannedDocs) || len(applied) != len(plannedDocs) {
				t.Fatalf("applied %d documents in %d requests; the plan bound %d", len(appliedDocs), len(applied), len(plannedDocs))
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

	t.Run("storage deploy", confirmWritesTheKeyholderAsPlanned)
	t.Run("the key pin", confirmWritesThePinAsPlanned)
	t.Run("storage key rotate", confirmWritesRotatesPinsAsPlanned)
	t.Run("run", confirmWritesRunsDocumentsAsPlanned)
}

// bucketArgument is the keyholder's --bucket= argument, which A23-31 item 6
// lets a first storage deploy's confirm differ in from its plan.
var bucketArgument = regexp.MustCompile(`--bucket=\S+`)

// pinWriteBody is the body of the one write to the key pin among reqs, as
// the writer sent it: its create or its replace.
func pinWriteBody(t *testing.T, reqs []kubetest.Request) []byte {
	t.Helper()
	var bodies [][]byte
	for _, r := range reqs {
		if (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.Contains(r.Path, "/configmaps") {
			if r.As != "writer" {
				t.Errorf("the pin was written as %q", r.As)
			}
			bodies = append(bodies, r.Body)
		}
	}
	if len(bodies) != 1 {
		t.Fatalf("the pin was written %d times; want once", len(bodies))
	}
	return bodies[0]
}

// pinWriteFact is a plan's one write of the key pin, or nil.
func pinWriteFact(b plan.Bound) *plan.WriteFact {
	for _, f := range planWrites(b) {
		if w := f.(plan.WriteFact); w.Name == dsdeploy.PinConfigMapName("") {
			return &w
		}
	}
	return nil
}

// sameSHA256 fails t unless body is the document whose SHA-256 the write
// fact w binds.
func sameSHA256(t *testing.T, what string, body []byte, w *plan.WriteFact) {
	t.Helper()
	if sum := sha256.Sum256(body); w == nil || hex.EncodeToString(sum[:]) != w.SHA256 {
		t.Errorf("%s sent\n%s\nwhich is not the document the plan's write %+v binds", what, body, w)
	}
}

// confirmWritesTheKeyholderAsPlanned is
// TestConfirmWritesThePlannedDocumentsExceptTheirSecrets's rows for storage
// deploy (ADR 0023 M2.6c, A23-31): planned as the instance's reader, then
// confirmed through the instance's real writer against a settled kubetest,
// each document its own apply (ADR 0023 M2.7), over the recorded bucket and
// as a first deploy, whose storage mint records the bucket the real one
// would draw.
// The keyholder's stream the plan rendered — over the plan's image, the
// instance's CA certificate, the placeholder leaf and the plan's bucket, a
// placeholder on a first deploy — is the plan's write facts; the applied
// documents equal it once a Secret's data and the mTLS hash are masked, and
// on a first deploy the --bucket= argument too (items 1, 2 and 6), and
// differ unmasked only in the Secret and the StatefulSet. The pin is written
// in-process, as the writer: its body is the document whose SHA-256 the
// plan's pin write binds, byte for byte, its key ids this keyring's own.
func confirmWritesTheKeyholderAsPlanned(t *testing.T) {
	const minted = "farcast-atlas-0a1b2c3d"
	for _, first := range []bool{false, true} {
		name := "over the recorded bucket"
		if first {
			name = "a first deploy"
		}
		t.Run(name, func(t *testing.T) {
			realPinOpener(t)
			s := kubetest.New(t, kubetest.WithSettledWorkloads())
			systemNamespace(s)
			dir, meta := writeInstance(t, s, true)
			writeMaterial(t, dir)
			if first {
				meta.Storage = nil
				if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(dir.InstanceKeyringPath(writeName)); err != nil {
					t.Fatal(err)
				}
			}
			fp := &fakeProvider{registry: &planck.Registry{Ref: registryRefFor(meta), Prefix: meta.Registry.Prefix}}
			fb := &fakeBuilder{resolveFn: notFoundForTags}
			minting := 0
			run := func(flags ...string) (string, string, error) {
				c := withFlags(t, &storageDeployCommand{}, flags...)
				asRelease(&c.deployer, nil)
				c.deployer.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) { return fp, nil }
				c.deployer.newBuilder = func(func(string)) imageBuilder { return fb }
				c.newPlanReader = func(r clusterRef) (pinPlanReader, error) {
					cl, err := loopbackReader(r)
					if err != nil {
						return nil, err
					}
					return cl, nil
				}
				c.ensureStorage = func(_ context.Context, env *Env, name string) error {
					minting++
					_, err := env.ConfigDir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
						m.Storage = &config.Storage{Bucket: minted, Provider: "gcs", Location: m.Region}
						return nil
					})
					return err
				}
				env, out, errb := testEnvBoth(dir, output.ModeJSON)
				err := c.Run(t.Context(), env, []string{writeName})
				return out.String(), errb.String(), err
			}
			printed, _, err := run("--plan")
			if err != nil {
				t.Fatalf("--plan: %v", err)
			}
			doc := printedDocument(t, []byte(printed))
			b := decodedBound(t, doc)
			reads := len(s.Requests())
			if _, errb, err := run("--confirm", doc.Digest); err != nil {
				t.Fatalf("--confirm: %v\n%s", err, errb)
			}
			if wantMints := map[bool]int{false: 0, true: 1}[first]; minting != wantMints {
				t.Errorf("minted storage %d times; want %d", minting, wantMints)
			}
			applied := appliedBodies(t, appliedOf(s.Requests()[reads:]))

			// The keyholder's stream as the plan rendered it.
			var target string
			for _, f := range b.Facts {
				if img, ok := f.(plan.ImageFact); ok && img.Component == components.Datasphered.Name {
					target = img.Target
				}
			}
			ca, err := dir.LoadInstanceCACert(writeName)
			if err != nil {
				t.Fatal(err)
			}
			bucket, provider, location := placeholderBucket(writeName), "gcs", meta.Region
			if !first {
				bucket, provider, location = meta.Storage.Bucket, meta.Storage.Provider, meta.Storage.Location
			}
			planned, err := dsdeploy.Render(keyholderConfig(meta, target, bucket, provider, location, ca,
				keyholderLeafPlaceholder(writeName, "cert"), keyholderLeafPlaceholder(writeName, "key")))
			if err != nil {
				t.Fatal(err)
			}
			var workload []plan.Fact
			for _, f := range planWrites(b) {
				if f.(plan.WriteFact).Name != dsdeploy.PinConfigMapName("") {
					workload = append(workload, f)
				}
			}
			if got := wantWrites(t, planned); !reflect.DeepEqual(got, workload) {
				t.Fatalf("the plan's write facts are not the planned rendering:\n%#v\n%#v", workload, got)
			}
			plannedDocs, err := kube.SplitStream(planned)
			if err != nil {
				t.Fatal(err)
			}
			appliedDocs, err := kube.SplitStream(streamOf(applied))
			if err != nil {
				t.Fatal(err)
			}
			if len(appliedDocs) != len(plannedDocs) || len(applied) != len(plannedDocs) {
				t.Fatalf("applied %d documents in %d requests; the plan bound %d", len(appliedDocs), len(applied), len(plannedDocs))
			}
			mask := func(doc []byte) []byte {
				m := masked(doc)
				if first {
					m = bucketArgument.ReplaceAll(m, []byte("--bucket=<masked>"))
				}
				return m
			}
			differ := 0
			for i, p := range plannedDocs {
				a := appliedDocs[i]
				if !bytes.Equal(mask(a.Raw), mask(p.Raw)) {
					t.Errorf("document %d, %s %s/%s, differs from the plan beyond what may differ:\napplied:\n%s\nplanned:\n%s",
						i, p.Kind.Kind, p.Namespace, p.Name, a.Raw, p.Raw)
				}
				if !bytes.Equal(a.Raw, p.Raw) {
					differ++
					if p.Kind.Kind != "Secret" && p.Kind.Kind != "StatefulSet" {
						t.Errorf("document %d, a %s, differs unmasked", i, p.Kind.Kind)
					}
				}
			}
			if differ == 0 {
				t.Error("no document differs from the planned rendering: the plan's placeholders are the real material, or this test masks nothing")
			}

			sameSHA256(t, "the pin's write", pinWriteBody(t, s.Requests()[reads:]), pinWriteFact(b))
		})
	}
}

// confirmWritesThePinAsPlanned is
// TestConfirmWritesThePlannedDocumentsExceptTheirSecrets's rows for storage
// key pin (ADR 0023 M2.6c, A23-44): planned as the instance's reader, then
// confirmed through the instance's real writer against kubetest. Its pin,
// created or raised to the union at the version read, is sent as the
// document whose SHA-256 the plan's write binds, byte for byte: nothing in
// it may differ, its key ids being this keyring's and the pin's own.
func confirmWritesThePinAsPlanned(t *testing.T) {
	for _, shape := range []string{"a pin to write", "--replace over a pin it is not behind"} {
		t.Run(shape, func(t *testing.T) {
			realPinOpener(t)
			row := planCommandNamed(t, "storage key pin", shape)
			s, dir := planFixture(t, row)
			doc, _ := runPlan(t, dir, row, output.ModeJSON)
			b := decodedBound(t, doc)
			reads := len(s.Requests())
			c := withFlags(t, &keyPinCommand{}, append(slices.Clone(row.flags), "--confirm", doc.Digest)...)
			c.newPlanReader = func(r clusterRef) (pinPlanReader, error) {
				cl, err := loopbackReader(r)
				if err != nil {
					return nil, err
				}
				return cl, nil
			}
			c.newKeyholder = noKeyholder
			env, _, errb := testEnvBoth(dir, output.ModeJSON)
			if err := c.Run(t.Context(), env, row.args); err != nil {
				t.Fatalf("--confirm: %v\n%s", err, errb)
			}
			w := pinWriteFact(b)
			if w == nil {
				t.Fatalf("the plan writes no pin: %+v", b.Facts)
			}
			sameSHA256(t, "the pin's write", pinWriteBody(t, s.Requests()[reads:]), w)
		})
	}
}

// keyIDs are key ids as a pin's ConfigMap holds them: 16 hex each.
var keyIDs = regexp.MustCompile(`[0-9a-f]{16}`)

// confirmWritesRotatesPinsAsPlanned is
// TestConfirmWritesThePlannedDocumentsExceptTheirSecrets's row for storage
// key rotate (ADR 0023 M2.6c, A23-45): its plan binds two pin writes, the
// hold at the version it read and the final pin as a replace at the version
// the hold produces, both over the new keys' placeholder ids. Confirmed
// against a fleet that takes the keys, each body sent is the planned pin's
// document at the version it was sent at, but for the key ids in its data,
// which the arrays keep the count of (A23-31 item 3).
func confirmWritesRotatesPinsAsPlanned(t *testing.T) {
	r := newRotateRig(t, backdatedApps)
	doc := r.plan(t)
	pins, writes := rotatePins(t, decodedBound(t, doc))
	if len(pins) != 2 || len(writes) != 2 {
		t.Fatalf("the plan binds %d pins and %d pin writes; want the hold's and the final's", len(pins), len(writes))
	}
	if _, stderr, err := r.run(t, "--confirm", doc.Digest); err != nil {
		t.Fatalf("--confirm: %v\n%s", err, stderr)
	}
	if len(r.writes) != 2 {
		t.Fatalf("wrote the pin %d times; want the hold, then the final pin", len(r.writes))
	}
	for i, w := range r.writes {
		bound, err := pinDocument(pinOfFact(t, pins[i]), writes[i].ResourceVersion)
		if err != nil {
			t.Fatal(err)
		}
		sameSHA256(t, fmt.Sprintf("the plan's pin %d", i), bound, &writes[i])
		planned, err := pinDocument(pinOfFact(t, pins[i]), w.rv)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := keyIDs.ReplaceAll(w.body, []byte("<id>")), keyIDs.ReplaceAll(planned, []byte("<id>")); !bytes.Equal(got, want) {
			t.Errorf("pin write %d sent\n%s\nthe plan's, at the version it was sent at, is\n%s", i, w.body, planned)
		}
		if bytes.Equal(w.body, planned) {
			t.Errorf("pin write %d is the planned document unmasked: the plan's placeholder ids are the real keys", i)
		}
	}
}

// readerPlans are the planCommands rows that read the cluster as the
// instance's reader, the first shape of each command: kernel deploy, storage
// deploy, storage key pin and storage key rotate (ADR 0023 M2.6c). Each
// command that reads the cluster in a plan adds its rows to planCommands,
// and is then here.
func readerPlans(t *testing.T) []planCommand {
	t.Helper()
	var rows []planCommand
	seen := map[string]bool{}
	for _, row := range planCommands() {
		if row.readsCluster && !seen[row.name] {
			seen[row.name] = true
			rows = append(rows, row)
		}
	}
	if len(rows) == 0 {
		t.Fatal("no plan reads the cluster")
	}
	return rows
}

// ADR 0023 M2.6 (design §7.3, A23-50, row 84): a plan that reads the cluster
// reads it as the instance's reader, and only as it: it succeeds, the cluster
// sees at least one request, every one of them, every token among them, is
// the reader's, and its reader seam was asked for the reader. A plan that
// reads no cluster sends nothing. run's deploy plans (M2.6d) are computed
// as --confirm of a digest that is no plan's computes them
// (runDeployDigest): the reader alone, and no writer. migrate's plan (M2.7,
// A30-26) is the one read as the writer: every request is the writer's
// token or a GET as the writer.
func TestPlansPresentOnlyTheReaderToken(t *testing.T) {
	onlyTheReaders := func(t *testing.T, row planCommand, reqs []kubetest.Request) {
		t.Helper()
		if len(reqs) == 0 {
			t.Fatalf("%s reads the cluster, and sent nothing", row)
		}
		for _, r := range reqs {
			if r.As != "reader" {
				t.Errorf("%s: %s %s?%s as %q; want only the reader", row, r.Method, r.Path, r.RawQuery, r.As)
			}
		}
		if f := row.fakes; f == nil || len(f.readers) == 0 || slices.ContainsFunc(f.readers, func(id kube.Identity) bool { return id != kube.Reader }) {
			t.Errorf("%s opened its reader seam as %v; want the reader", row, row.fakes.readers)
		}
	}
	for _, row := range planCommands() {
		t.Run(row.String(), func(t *testing.T) {
			s, dir := planFixture(t, row)
			runPlan(t, dir, row, output.ModeJSON)
			reqs := s.Requests()
			if row.identity == "writer" {
				// migrate's plan is read as the writer (ADR 0023 M2.7,
				// A30-26): every request, every token among them, is the
				// writer's, and only reads.
				if len(reqs) == 0 {
					t.Fatalf("%s reads the cluster as the writer, and sent nothing", row)
				}
				for _, r := range reqs {
					if r.As != "writer" || (r.Path != "/token" && r.Method != http.MethodGet) {
						t.Errorf("%s: %s %s?%s as %q; want the writer's token and reads alone", row, r.Method, r.Path, r.RawQuery, r.As)
					}
				}
				return
			}
			if !row.readsCluster {
				if len(reqs) != 0 {
					t.Errorf("%s --plan reads no cluster, and sent %d requests", row, len(reqs))
				}
				return
			}
			onlyTheReaders(t, row, reqs)
		})
	}
	for _, row := range runDeployRows(t) {
		t.Run(row.String(), func(t *testing.T) {
			s, dir := planFixture(t, row)
			runDeployDigest(t, dir, row, nil)
			onlyTheReaders(t, row, s.Requests())
			if row.fakes.writers != 0 {
				t.Errorf("%s opened the writer %d times", row, row.fakes.writers)
			}
		})
	}
}

// answeredStatuses is a kubetest option that collects, for each request the
// server answered 403, its method, path and query.
func answeredStatuses() (kubetest.Option, func() []string) {
	var mu sync.Mutex
	var refused []string
	return kubetest.WithAnswered(func(r kubetest.Request, status int) {
			if status == http.StatusForbidden {
				mu.Lock()
				defer mu.Unlock()
				refused = append(refused, r.Method+" "+r.Path+"?"+r.RawQuery+" as "+r.As)
			}
		}), func() []string {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(refused)
		}
}

// ADR 0023 M2.6 (design §7.3, P3, A23-50, row 76b): every read the reader
// makes is one the RBAC 'reader grant' renders allows. kubetest authorizes
// the reader with exactly renderReaderRBAC's stream for the namespaces the
// fixture records as metered, and world, ps, costs, usage and logs, and
// every plan that reads the cluster, read with no 403 and succeed. run's
// deploy plans (M2.6d, A28-11) are computed through runDeployDigest, the
// reader's alone; runFixture's record meters the namespace they deploy
// into, and reading its fetch Job needs the jobs rule.
func TestEveryReaderReadIsAllowedByTheRenderedRBAC(t *testing.T) {
	t.Run("world", func(t *testing.T) {
		email := worldReaderEmail()
		stream, err := renderReaderRBAC(email, []string{tcdeploy.DefaultNamespace, "shop"})
		if err != nil {
			t.Fatal(err)
		}
		statuses, refused := answeredStatuses()
		f := newWorldReaderFixture(t, kubetest.WithRBAC(email, stream), statuses)
		if meta, err := f.dir.LoadInstanceMetadata("atlas"); err != nil || !slices.Equal(meta.Kernel.Namespaces, []string{tcdeploy.DefaultNamespace, "shop"}) {
			t.Fatalf("the fixture meters %v (%v); the RBAC is rendered for farcast-system and shop", meta.Kernel.Namespaces, err)
		}
		sections, _, _ := f.run(t)
		wantSections(t, sections, map[string]string{"spend": "read", "apps": "read", "policy": "read"})
		onlyTheReader(t, f.s)
		if got := refused(); len(got) != 0 {
			t.Errorf("world met 403s: %q", got)
		}
	})
	for _, rc := range readCommands() {
		t.Run(rc.name, func(t *testing.T) {
			email := readerName(readName) + "@kubetest.invalid"
			stream, err := renderReaderRBAC(email, []string{tcdeploy.DefaultNamespace, readNamespace})
			if err != nil {
				t.Fatal(err)
			}
			statuses, refused := answeredStatuses()
			s := kubetest.New(t, kubetest.WithRBAC(email, stream), statuses)
			dir, meta := readCommandsInstance(t, s, true)
			if !slices.Equal(meta.Kernel.Namespaces, []string{tcdeploy.DefaultNamespace, readNamespace}) {
				t.Fatalf("the fixture meters %v; the RBAC is rendered for farcast-system and %s", meta.Kernel.Namespaces, readNamespace)
			}
			out, errb, err := runRead(t, dir, rc)
			if err != nil {
				t.Fatalf("%s: %v\nstderr: %s", rc.name, err, errb)
			}
			rc.seeded(t, out)
			onlyTheReader(t, s)
			if got := refused(); len(got) != 0 {
				t.Errorf("%s met 403s: %q", rc.name, got)
			}
		})
	}
	var rows []planCommand
	for _, row := range planCommands() {
		if row.readsCluster {
			rows = append(rows, row)
		}
	}
	for _, row := range append(rows, runDeployRows(t)...) {
		t.Run(row.String(), func(t *testing.T) {
			email, stream := readerRBACFor(t, row)
			statuses, refused := answeredStatuses()
			s, dir := planFixtureWith(t, row, true, kubetest.WithRBAC(email, stream), statuses)
			if row.stage == "deploy" {
				runDeployDigest(t, dir, row, nil)
			} else {
				runPlan(t, dir, row, output.ModeJSON)
			}
			onlyTheReader(t, s)
			if got := refused(); len(got) != 0 {
				t.Errorf("%s met 403s: %q", row, got)
			}
		})
	}
}

// readerRBACFor is the RBAC 'reader grant' renders for row's fixture: the
// email of the reader its record names, bound in every namespace the record
// meters (A23-50, A28-11), read from a fixture of row's built for the
// purpose. A plan into a namespace the kernel meters, run's into runTarget,
// is read there with the binding its record gives it.
func readerRBACFor(t *testing.T, row planCommand) (string, []byte) {
	t.Helper()
	_, dir := planFixture(t, row)
	meta, err := dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	if row.String() == "run/deploy into a metered namespace" && !slices.Equal(meta.Kernel.Namespaces, []string{tcdeploy.DefaultNamespace, runTarget}) {
		t.Fatalf("the fixture meters %v; want farcast-system and %s", meta.Kernel.Namespaces, runTarget)
	}
	stream, err := renderReaderRBAC(meta.Reader.Email, meta.Kernel.Namespaces)
	if err != nil {
		t.Fatal(err)
	}
	return meta.Reader.Email, stream
}

// ADR 0023 M2.6 (A23-1, A23-21; rows 85 and 85a): a plan that reads the
// cluster needs a reader 'reader grant' has verified read-only, and has no
// fallback to the installer's account. For each such plan, under --plan and
// under --confirm, a reader in each of the four states short of granted is
// refused credential_missing, with the text naming the command, the answer,
// the state as 'instances' prints it, and what to do from that state, before
// the plan's reader seam opens, before credentials.yaml is read and before
// the provider opens: the cluster sees nothing, and nothing is printed. A
// granted reader whose recorded email is not the derived one passes that
// check, and openCluster refuses it, in its own words, sending nothing.
func TestPlanWithoutAReaderIsRefused(t *testing.T) {
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
		for _, plans := range readerPlans(t) {
			for _, answer := range [][]string{{"--plan"}, {"--confirm", sampleDigest}} {
				t.Run(plans.String()+"/"+tc.state+"/"+answer[0], func(t *testing.T) {
					row := planCommandNamed(t, plans.name, plans.shape) // its fakes fresh
					s, dir := planFixture(t, row)
					meta, err := dir.LoadInstanceMetadata(writeName)
					if err != nil {
						t.Fatal(err)
					}
					tc.edit(t, dir, meta)
					if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
						t.Fatal(err)
					}
					reads := observeConfigReads(t)
					cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), answer...)...)
					env, out, errb := testEnvBoth(dir, output.ModeJSON)
					err = cmd.Run(t.Context(), env, row.args)

					want := fmt.Sprintf("'farcast %s %s' reads the cluster as instance %q's reader, whose state is %s; %s, or run the command in a terminal",
						row.name, answer[0], writeName, tc.state, tc.remedy)
					readersOpened := 0
					if tc.remedy == "" {
						// openCluster's own refusal of a reader that is not the
						// derived one.
						want = fmt.Sprintf("instance %q records the reader %q, which is not the reader farcast derives for it (%s); nothing was sent",
							writeName, "writer@kubetest.invalid", readerName(writeName)+"@<a name under .invalid>")
						readersOpened = 1
					}
					if err == nil || err.Error() != want || !errors.Is(err, errCredentialMissing) || kindOf(classified(err)) != kindCredentialMissing {
						t.Fatalf("%s %s with a reader %s = %v (kind %s);\nwant %q", row, answer[0], tc.state, err, kindOf(classified(err)), want)
					}
					if got := len(s.Requests()); got != 0 {
						t.Errorf("%s sent %d requests", row, got)
					}
					for _, p := range reads() {
						if filepath.Base(p) == "credentials.yaml" {
							t.Errorf("%s read %s", row, p)
						}
					}
					if f := row.fakes; f.opened+f.writers != 0 || len(f.readers) != readersOpened {
						t.Errorf("%s opened the provider %d times, the writer %d times and its reader seam %d times; want the reader seam %d times",
							row, f.opened, f.writers, len(f.readers), readersOpened)
					}
					if out.Len()+errb.Len() != 0 {
						t.Errorf("%s printed %q %q", row, out, errb)
					}
				})
			}
		}
	}
	t.Run("run", runWithoutAReaderIsRefused)
}

// ADR 0023 M2.6 (A23-22, row 76e): an error a plan meets reading the
// cluster as the reader says what the reader needs, once, and never blames
// the installer's account, whose sentence writerRefused gives only the
// writer's errors. An RBAC 403 names 'farcast reader grant', and any other
// 403 the endpoint's IAM; either is kind forbidden, under --plan and in
// --confirm's recomputation. Each command that reads the cluster in its
// plan (readerPlans) meets it at its first read: kernel deploy's namespaces,
// and the storage commands' key pin (row S-C26-S5 of the M2.6c review); and
// run's deploy plan (M2.6d), under --confirm of a digest that is no plan's,
// its fetch Job.
func TestPlanReadErrorsNameTheReader(t *testing.T) {
	firstRead := map[string]string{
		"kernel deploy":      "/api/v1/namespaces",
		"storage deploy":     pinPath,
		"storage key pin":    pinPath,
		"storage key rotate": pinPath,
	}
	iam := kube.Status{}
	iam.Kind = "Error" // Google's JSON error, not a Kubernetes Status
	for _, tc := range []struct {
		name     string
		status   kube.Status
		sentence string
	}{
		{"forbidden by RBAC", kube.Status{}, "; run 'farcast reader grant atlas'"},
		{"forbidden at the endpoint", iam, "; " + msgReaderIAMRefused},
	} {
		for _, plans := range readerPlans(t) {
			path, ok := firstRead[plans.name]
			if !ok {
				t.Fatalf("%s reads the cluster in its plan: say which read it makes first", plans.name)
			}
			for _, answer := range [][]string{{"--plan"}, {"--confirm", sampleDigest}} {
				t.Run(plans.String()+"/"+tc.name+"/"+answer[0], func(t *testing.T) {
					row := planCommandNamed(t, plans.name, plans.shape) // its fakes fresh
					s, dir := planFixture(t, row)
					s.Fail(http.MethodGet, path, http.StatusForbidden, tc.status)
					cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), answer...)...)
					env, out, _ := testEnvBoth(dir, output.ModeJSON)
					err := cmd.Run(t.Context(), env, row.args)
					if kind := kindOf(classified(err)); err == nil || kind != kindForbidden {
						t.Fatalf("%s %s = %v (kind %s); want forbidden", row, answer[0], err, kind)
					}
					msg := err.Error()
					if strings.Count(msg, tc.sentence) != 1 || strings.Contains(msg, "installer service account") {
						t.Errorf("%s %s = %q;\nwant %q once and the installer's account never", row, answer[0], msg, tc.sentence)
					}
					if out.Len() != 0 || row.fakes.writers+row.fakes.opened != 0 {
						t.Errorf("%s %s printed %q, opened the writer %d times and the provider %d times", row, answer[0], out, row.fakes.writers, row.fakes.opened)
					}
					m := consentPlan
					if answer[0] == "--confirm" {
						m = consentConfirm
					}
					onlyThePlansReads(t, row, s, m)
				})
			}
		}
		t.Run("run <D>/"+tc.name, func(t *testing.T) { runPlanReadErrorsNameTheReader(t, tc.status, tc.sentence) })
	}
}

// ADR 0023 M2.6 (A23-23, row 76c): under --confirm, the writer opens only
// after the comparison, and the cluster it reaches must be the one the plan
// read as the reader. kernel deploy's plan reads farcast-system's uid u1
// through its reader, and the writer's cluster answers another, u2, or has
// no farcast-system at all: --confirm refuses, plan_changed, exit 1, naming
// both uids, once the writer's preflight read it, and before anything is
// ensured, pushed, recorded or applied.
// run's deploy plan (M2.6d) has the same rows, against runFixture
// (runConfirmChecksTheWritersCluster).
func TestConfirmChecksTheWritersClusterIsThePlans(t *testing.T) {
	for _, tc := range []struct {
		name, writerUID, said string
	}{
		{"another farcast-system", "u2", "u2"},
		{"no farcast-system", "", "absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := kubetest.New(t)
			if tc.writerUID != "" {
				s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{
					"name": tcdeploy.DefaultNamespace, "uid": tc.writerUID}})
			}
			dir, meta := writeInstance(t, s, true)
			fp := &fakeProvider{registry: &planck.Registry{Ref: registryRefFor(meta), Prefix: meta.Registry.Prefix}}
			fb := &fakeBuilder{resolveFn: notFoundForTags}
			reader := &fakeCluster{uid: "u1", namespaces: []string{tcdeploy.DefaultNamespace}}
			var opened []kube.Identity
			kernelDeploy := func(flags ...string) *kernelDeployCommand {
				c := withFlags(t, &kernelDeployCommand{}, flags...)
				asRelease(&c.deployer, nil)
				c.deployer.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) { return fp, nil }
				c.deployer.newBuilder = func(func(string)) imageBuilder { return fb }
				c.newPlanReader = func(r clusterRef) (kernelPlanReader, error) {
					opened = append(opened, r.Identity)
					return reader, nil
				}
				return c
			}
			env, out, _ := testEnvBoth(dir, output.ModeJSON)
			if err := kernelDeploy("--plan").Run(t.Context(), env, []string{writeName}); err != nil {
				t.Fatal(err)
			}
			doc := printedDocument(t, out.Bytes())
			if b := decodedBound(t, doc); b.ClusterIdentity != "reader" || b.Target.SystemNamespaceUID != "u1" {
				t.Fatalf("the plan reads as %q and binds the uid %q; want the reader's u1", b.ClusterIdentity, b.Target.SystemNamespaceUID)
			}
			before := treeFiles(t, string(dir))

			env, out, errb := testEnvBoth(dir, output.ModeJSON)
			err := kernelDeploy("--confirm", doc.Digest).Run(t.Context(), env, []string{writeName})
			want := fmt.Sprintf("instance %q's cluster is not the one its plan read: farcast-system's uid is %s, not u1; nothing was written; %s",
				writeName, tc.said, msgPlanAgain)
			if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
				t.Fatalf("--confirm against another cluster = %v (kind %s);\nwant %q, plan_changed\n%s", err, kindOf(classified(err)), want, errb)
			}
			if applied := len(appliedRequests(s)); applied+len(fp.ensured)+len(fb.embedded)+len(fb.built) != 0 || out.Len() != 0 {
				t.Errorf("applied %d documents, ensured %d, pushed %d, built %d and printed %q before refusing", applied, len(fp.ensured), len(fb.embedded), len(fb.built), out)
			}
			if !slices.Equal(opened, []kube.Identity{kube.Reader, kube.Reader}) {
				t.Errorf("the plan's reader seam was asked for %v; want the reader, once for the plan and once for the recomputation", opened)
			}
			// The writer read once: its preflight, after its token.
			var writerReads []string
			for _, r := range s.Requests() {
				if r.As != "writer" {
					t.Errorf("%s %s as %q; only the writer reaches this cluster", r.Method, r.Path, r.As)
				}
				if r.Path != "/token" {
					writerReads = append(writerReads, r.Method+" "+r.Path)
				}
			}
			if !slices.Equal(writerReads, []string{"GET /api/v1/namespaces"}) {
				t.Errorf("the writer sent %q; want its preflight read alone", writerReads)
			}
			sameFiles(t, "a confirm against another cluster", before, treeFiles(t, string(dir)))
		})
	}
	t.Run("run <D>", runConfirmChecksTheWritersCluster)
}

// The storage commands' rows of TestConfirmChecksTheWritersClusterIsThePlans
// (ADR 0023 M2.6c): storage deploy's, storage key pin's and storage key
// rotate's plans read farcast-system's uid u1 through the in-memory pin's
// reader view, and the writer answers u2. Each refuses plan_changed after
// the comparison, naming both, with the pin unwritten; storage deploy has
// minted, ensured, pushed and applied nothing, and rotate has minted
// nothing and opened no keyholder.
func TestConfirmChecksTheWritersClusterIsThePlansForTheStorageCommands(t *testing.T) {
	want := fmt.Sprintf(msgOtherCluster, writeName, "u2", "u1")
	t.Run("storage deploy", func(t *testing.T) {
		r := newStorageRig(t, nil)
		doc := r.plan(t)
		r.fc.uid = "u2"
		_, _, err := r.run(t, "--confirm", doc.Digest)
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged {
			t.Fatalf("--confirm against another cluster = %v (kind %s);\nwant %q", err, kindOf(classified(err)), want)
		}
		r.wroteNothing(t)
		if r.ps.exists {
			t.Errorf("wrote the pin %s", r.ps.value)
		}
	})
	t.Run("storage key pin", func(t *testing.T) {
		dir, _, ps := keyPinFixture(t)
		ps.uid = "u1"
		doc := runKeyPinPlan(t, dir, nil)
		c := keyPinPlanCmd(t, nil, "--confirm", doc.Digest)
		c.newPinStore = func(r clusterRef) (pinStore, error) {
			if r.Identity != kube.Writer {
				return nil, fmt.Errorf("test: the pin opened as %q", r.Identity)
			}
			return pinsAt{ps, "u2"}, nil
		}
		env, out, _ := testEnvBoth(dir, output.ModeJSON)
		err := c.Run(t.Context(), env, []string{writeName})
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged {
			t.Fatalf("--confirm against another cluster = %v (kind %s);\nwant %q", err, kindOf(classified(err)), want)
		}
		if ps.exists || out.Len() != 0 {
			t.Errorf("wrote the pin %s, and printed %q", ps.value, out)
		}
	})
	t.Run("storage key rotate", func(t *testing.T) {
		r := newRotateRig(t, backdatedApps)
		doc := r.plan(t)
		r.writerUID = "u2"
		before := keyringBytes(t, r.dir, writeName)
		stdout, _, err := r.run(t, "--confirm", doc.Digest)
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged {
			t.Fatalf("--confirm against another cluster = %v (kind %s);\nwant %q", err, kindOf(classified(err)), want)
		}
		if !bytes.Equal(before, keyringBytes(t, r.dir, writeName)) || len(r.writes) != 0 || r.keyholders != 0 || stdout != "" {
			t.Errorf("changed keys.yaml, wrote the pin %d times, opened the keyholder %d times, or printed %q", len(r.writes), r.keyholders, stdout)
		}
	})
}

// pinsAt is a pin store whose cluster answers farcast-system's uid as uid:
// the same pin, reached in another cluster.
type pinsAt struct {
	*fakePinStore
	uid string
}

func (p pinsAt) NamespaceUID(context.Context, string) (string, error) { return p.uid, nil }

// ADR 0023 M2.6 (design §7.3, A23-23, A23-50, rows 76 and 76a): --confirm
// recomputes the plan as the identity the plan read with, and writes as the
// writer only after the comparison. kernel deploy, planned and then
// confirmed against one settled kubetest server through its real reader and
// its real writer, runs to the end: every request the confirm sends as the
// reader comes before the writer's first token, every request after that
// token is the writer's, and nothing the reader read was answered after an
// apply. Since ADR 0023 M2.7 (A30-31) the applies are the writer's own
// requests: after its preflight and before its rollout read, one apply per
// document the plan bound, in the plan's order, each as the writer with
// farcast's forced query, and exactly the documents the plan bound. run's
// two plans (M2.6d) have their own cases
// (runConfirmRecomputesAsThePlansIdentity).
func TestConfirmRecomputesAsThePlansIdentity(t *testing.T) {
	t.Run("kernel deploy", func(t *testing.T) {
		answered, seen := answeredLog()
		s := kubetest.New(t, answered, kubetest.WithSettledWorkloads())
		systemNamespace(s)
		s.Put(map[string]any{
			"apiVersion": "apps/v1", "kind": "Deployment",
			"metadata": map[string]any{"name": tcdeploy.DefaultName, "namespace": tcdeploy.DefaultNamespace},
			"spec":     map[string]any{"replicas": 1},
			"status":   map[string]any{"replicas": 1, "updatedReplicas": 1, "availableReplicas": 1},
		})
		dir, meta := writeInstance(t, s, true)
		fp := &fakeProvider{registry: &planck.Registry{Ref: registryRefFor(meta), Prefix: meta.Registry.Prefix}}
		fb := &fakeBuilder{resolveFn: notFoundForTags}
		var readers []kube.Identity
		kernelDeploy := func(flags ...string) *kernelDeployCommand {
			c := withFlags(t, &kernelDeployCommand{}, flags...)
			asRelease(&c.deployer, nil)
			c.deployer.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) { return fp, nil }
			c.deployer.newBuilder = func(func(string)) imageBuilder { return fb }
			c.newPlanReader = func(r clusterRef) (kernelPlanReader, error) {
				readers = append(readers, r.Identity)
				cl, err := loopbackReader(r)
				if err != nil {
					return nil, err
				}
				return cl, nil
			}
			return c
		}
		env, out, errb := testEnvBoth(dir, output.ModeJSON)
		if err := kernelDeploy("--plan").Run(t.Context(), env, []string{writeName}); err != nil {
			t.Fatalf("--plan: %v\n%s", err, errb)
		}
		doc := printedDocument(t, out.Bytes())
		planned := len(seen())

		env, _, errb = testEnvBoth(dir, output.ModeJSON)
		if err := kernelDeploy("--confirm", doc.Digest).Run(t.Context(), env, []string{writeName}); err != nil {
			t.Fatalf("--confirm: %v\n%s", err, errb)
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
		var writerSent []answeredRequest
		for _, a := range confirmed[firstWriter+1:] {
			if a.path != "/token" {
				writerSent = append(writerSent, a)
			}
		}
		b := decodedBound(t, doc)
		rollout := "/apis/apps/v1/namespaces/" + tcdeploy.DefaultNamespace + "/deployments/" + tcdeploy.DefaultName
		want := []answeredRequest{{"writer", http.MethodGet, "/api/v1/namespaces", 0}}
		for i, w := range applyWrites(b) {
			want = append(want, answeredRequest{"writer", http.MethodPatch, factPath(t, w), i})
		}
		want = append(want, answeredRequest{"writer", http.MethodGet, rollout, len(want) - 1})
		if len(want) < 3 || !slices.Equal(writerSent, want) {
			t.Errorf("the writer sent\n%+v\nwant its preflight, one apply per planned document in order, then the rollout read\n%+v", writerSent, want)
		}
		applied := appliedBodies(t, appliedRequests(s))
		if got, want := wantWrites(t, streamOf(applied)), planWrites(b); !reflect.DeepEqual(got, want) {
			t.Errorf("applied\n%#v\nthe plan bound\n%#v", got, want)
		}
		if !slices.Equal(readers, []kube.Identity{kube.Reader, kube.Reader}) {
			t.Errorf("the plan's reader seam was asked for %v; want the reader for the plan and for the recomputation", readers)
		}
		after, err := dir.LoadInstanceMetadata(writeName)
		if err != nil {
			t.Fatal(err)
		}
		if after.Kernel == nil || !after.Kernel.Applied || after.Kernel.Image != carriedRegistryRef(meta, "technocore") {
			t.Errorf("recorded %+v; want the kernel applied with the carried image", after.Kernel)
		}
	})
	runConfirmRecomputesAsThePlansIdentity(t)
}

// ADR 0023 M2.7 (A30-29, §10.5 rows 100 and 100a): every apply is forced,
// and its plan says so. Every plan shape (everyPlanShape, run's deploy plans
// printed by runPrintedPlan) binds each of its apply write facts forced.
// For each plan of a command that applies (applyingPlans), --plan, then
// --confirm through the real writer against kubetest, run to the end: every
// apply the confirm sends is a server-side apply as the writer, with
// farcast's forced query; and the applies are the plan's apply write facts,
// one each, in order, each the document the fact names, carrying no
// resourceVersion but the one the fact binds, and the document whose SHA-256
// it binds, but for those A23-31 lets differ from the plan: a Secret, a
// workload (its mTLS hash, a built image, a bucket) and run's egress policy
// (its credentials).
func TestEveryApplyIsForced(t *testing.T) {
	t.Run("every plan", func(t *testing.T) {
		applies := 0
		for _, row := range everyPlanShape(t) {
			_, dir := planFixture(t, row)
			doc, _ := runPrintedPlan(t, dir, row, output.ModeJSON)
			for _, w := range applyWrites(decodedBound(t, doc)) {
				applies++
				if !w.Force {
					t.Errorf("%s's plan binds the apply of %s %s/%s unforced", row, w.Kind, w.Namespace, w.Name)
				}
			}
		}
		if applies == 0 {
			t.Error("no plan binds an apply")
		}
	})
	for _, p := range applyingPlans(t) {
		t.Run(p.String(), func(t *testing.T) {
			c := confirmApplying(t, p, nil)
			if c.err != nil {
				t.Fatalf("%s --confirm: %v\n%s", p, c.err, c.stderr)
			}
			writes := applyWrites(c.b)
			if len(writes) == 0 {
				t.Fatalf("%s's plan binds no apply", p)
			}
			bodies := appliedBodies(t, appliedOf(c.sent))
			if len(bodies) != len(writes) {
				t.Fatalf("%s --confirm applied %d documents; its plan binds %d", p, len(bodies), len(writes))
			}
			for i, w := range writes {
				// Split as ApplyAt splits it: only run's egress policy
				// carries the resourceVersion its fact binds (A30-40).
				docs, err := kube.SplitStream(bodies[i], kube.AllowResourceVersion(w.ResourceVersion))
				if err != nil || len(docs) != 1 {
					t.Fatalf("apply %d sent %d documents (%v); one each", i, len(docs), err)
				}
				d := docs[0]
				if d.Kind.APIVersion != w.API || d.Kind.Kind != w.Kind || d.Namespace != w.Namespace || d.Name != w.Name {
					t.Errorf("apply %d sent %s %s/%s; the plan's write %d is %s %s/%s", i, d.Kind.Kind, d.Namespace, d.Name, i, w.Kind, w.Namespace, w.Name)
				}
				switch w.Kind {
				case "Secret", "Deployment", "StatefulSet":
					continue
				case "ConfigMap":
					if w.Name == fldeploy.PolicyConfigMap {
						continue
					}
				}
				if sum := sha256.Sum256(d.Raw); hex.EncodeToString(sum[:]) != w.SHA256 {
					t.Errorf("apply %d sent %s %s/%s, which is not the document the plan binds:\n%s", i, w.Kind, w.Namespace, w.Name, d.Raw)
				}
			}
		})
	}
}

// carriedRegistryRef is a component's carried image in meta's recorded
// registry: what a release farcast carrying the fake components pushes and
// deploys there.
func carriedRegistryRef(meta *config.InstanceMetadata, component string) string {
	return meta.Registry.Prefix + "/system/" + component + "@" + sha(tagDigest)
}

// ADR 0023 M2.6 (A23-23, rows 76d): under --confirm, a writing command
// checks its writer before anything it cannot take back. storage deploy, on
// a first deploy over a pin its plan raises: a writer that will not open, a
// writer whose cluster refuses its preflight, which says whose the 403 was,
// once (A20-9), and a pin whose resourceVersion moved between the
// comparison and the writer's read of it each refuse the command with no
// bucket or keyring minted, no registry
// ensured, no image pushed or built, nothing applied, the pin and every file
// under the config directory as they were. The moved pin is plan_changed,
// in A23-42's words. storage key rotate, with a keyholder deployed, opens
// its writer after the comparison and before it mints: a writer that will
// not open, an install with no key behind the real pin opener, a writer
// whose cluster refuses its preflight, its 403 said to be the writer's
// once, and a pin moved after the comparison
// each refuse it with keys.yaml as it was, no pin written and the keyholder,
// and so the tunnel, never opened.
func TestConfirmChecksTheWriterBeforeAnythingIrreversible(t *testing.T) {
	refused := errors.New("test: the writer is refused")
	for _, tc := range []struct {
		name  string
		setup func(r *storageRig)
		want  func(err error) bool
	}{
		{"storage deploy/the writer refused", func(r *storageRig) { r.writerErr = refused },
			func(err error) bool { return errors.Is(err, refused) }},
		{"storage deploy/the writer's preflight refused", func(r *storageRig) { r.fc.uidErr = errRBAC },
			func(err error) bool {
				return kindOf(classified(err)) == kindForbidden && strings.Count(err.Error(), msgWriterRBACRefused) == 1
			}},
		{"storage deploy/the pin moved after the comparison", func(r *storageRig) {
			r.onWriter = func() { r.ps.set(r.ps.value) }
		}, func(err error) bool {
			return err.Error() == msgPinChanged && kindOf(classified(err)) == kindPlanChanged
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStorageRig(t, func(m *config.InstanceMetadata) { m.Storage = nil })
			r.mintsBucket(nil)
			r.ps.set(dskeyholder.Pin{}.Marshal())
			doc := r.plan(t)
			if w := planWrites(decodedBound(t, doc)); len(w) == 0 || w[0].(plan.WriteFact).Method != plan.WriteReplace || w[0].(plan.WriteFact).ResourceVersion != "1" {
				t.Fatalf("the plan's first write is %+v; want the pin's replace at the version read, 1", w)
			}
			tc.setup(r)
			before, pinBefore := treeFiles(t, string(r.dir)), r.ps.value
			stdout, _, err := r.run(t, "--confirm", doc.Digest)
			if err == nil || !tc.want(err) || exitCodeOf(err) != 1 {
				t.Fatalf("--confirm = %v (kind %s, exit %d)", err, kindOf(classified(err)), exitCodeOf(err))
			}
			if r.writers != 1 {
				t.Errorf("the writer opened %d times; want once, after the comparison", r.writers)
			}
			r.wroteNothing(t)
			if r.ps.value != pinBefore || stdout != "" {
				t.Errorf("the pin is %s (was %s), and the command printed %q", r.ps.value, pinBefore, stdout)
			}
			sameFiles(t, tc.name, before, treeFiles(t, string(r.dir)))
		})
	}

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, r *rotateRig)
		want  func(err error) bool
	}{
		{"storage key rotate/the writer refused", func(_ *testing.T, r *rotateRig) { r.writerErr = refused },
			func(err error) bool { return errors.Is(err, refused) }},
		{"storage key rotate/an install without a key", func(t *testing.T, r *rotateRig) {
			meta, err := r.dir.LoadInstanceMetadata(writeName)
			if err != nil {
				t.Fatal(err)
			}
			adcInstall(t, r.dir, meta)
			realPinOpener(t)
			r.realWriter = true
		}, func(err error) bool {
			return errors.Is(err, errCredentialMissing) && strings.Contains(err.Error(), msgADCRefused) && kindOf(classified(err)) == kindCredentialMissing
		}},
		{"storage key rotate/the writer's preflight refused", func(_ *testing.T, r *rotateRig) { r.writerUIDErr = errRBAC },
			func(err error) bool {
				return kindOf(classified(err)) == kindForbidden && strings.Count(err.Error(), msgWriterRBACRefused) == 1
			}},
		{"storage key rotate/the pin moved after the comparison", func(_ *testing.T, r *rotateRig) {
			r.onWriter = func() { r.ps.set(r.ps.value) }
		}, func(err error) bool {
			return err.Error() == msgPinChanged && kindOf(classified(err)) == kindPlanChanged
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRotateRig(t, backdatedApps)
			r.ps.set(pinFor(liveKeyring(t, r.dir, writeName)).Marshal())
			doc := r.plan(t)
			tc.setup(t, r)
			before, pinBefore := treeFiles(t, string(r.dir)), r.ps.value
			stdout, _, err := r.run(t, "--confirm", doc.Digest)
			if err == nil || !tc.want(err) || exitCodeOf(err) != 1 {
				t.Fatalf("--confirm = %v (kind %s, exit %d)", err, kindOf(classified(err)), exitCodeOf(err))
			}
			if r.keyholders != 0 || len(r.writes) != 0 || r.ps.value != pinBefore || stdout != "" {
				t.Errorf("opened the keyholder %d times, wrote the pin %d times (it is %s, was %s), and printed %q",
					r.keyholders, len(r.writes), r.ps.value, pinBefore, stdout)
			}
			sameFiles(t, tc.name, before, treeFiles(t, string(r.dir)))
		})
	}

	// A plan that writes no pin — the pin already this keyring's, as on
	// every routine storage deploy and repeated key pin — still holds the
	// writer to the pin it read (checkPlannedPin, A23-23 step 4; rows O09
	// and O32 of the M2.6c review): another writer that replaces it after
	// the comparison is plan_changed, before anything is ensured, pushed,
	// applied or handed over, and nothing is written over it.
	t.Run("storage deploy/a pin it does not write, moved after the comparison", func(t *testing.T) {
		r := newStorageRig(t, nil)
		keys := liveKeyring(t, r.dir, writeName)
		r.ps.set(pinFor(keys).Marshal())
		doc := r.plan(t)
		if w := planWrites(decodedBound(t, doc)); slices.ContainsFunc(w, func(f plan.Fact) bool { return f.(plan.WriteFact).Name == dsdeploy.PinConfigMapName("") }) {
			t.Fatalf("guard: the plan writes the pin: %+v", w)
		}
		other := pinFor(keys)
		other.Retired = append(other.Retired, foreignID(t))
		r.onWriter = func() { r.ps.set(other.Marshal()) }
		stdout, _, err := r.run(t, "--confirm", doc.Digest)
		if err == nil || err.Error() != msgPinChanged || kindOf(classified(err)) != kindPlanChanged {
			t.Fatalf("--confirm over a pin changed after the comparison = %v (kind %s); want plan_changed, %q", err, kindOf(classified(err)), msgPinChanged)
		}
		r.wroteNothing(t)
		if r.ps.value != other.Marshal() || stdout != "" {
			t.Errorf("the pin is %s, and the command printed %q; want the other writer's, and nothing", r.ps.value, stdout)
		}
	})
	t.Run("storage key pin/a pin it does not write, moved after the comparison", func(t *testing.T) {
		dir, keys, ps := keyPinFixture(t)
		ps.set(pinFor(keys).Marshal())
		kh := &fakeStateKeyholder{phase: "unsealed"}
		doc := runKeyPinPlan(t, dir, kh)
		if w := planWrites(decodedBound(t, doc)); len(w) != 0 {
			t.Fatalf("guard: the plan writes %+v", w)
		}
		other := pinFor(keys)
		other.Retired = append(other.Retired, foreignID(t))
		c := keyPinPlanCmd(t, kh, "--confirm", doc.Digest)
		c.newPinStore = func(ref clusterRef) (pinStore, error) {
			ps.set(other.Marshal())
			return testDefaultPinStore(ref)
		}
		env, out, _ := testEnvBoth(dir, output.ModeJSON)
		err := c.Run(t.Context(), env, []string{writeName})
		if err == nil || err.Error() != msgPinChanged || kindOf(classified(err)) != kindPlanChanged {
			t.Fatalf("--confirm over a pin changed after the comparison = %v (kind %s); want plan_changed, %q", err, kindOf(classified(err)), msgPinChanged)
		}
		if out.Len() != 0 || ps.value != other.Marshal() {
			t.Errorf("printed %q, and the pin is %s; want nothing, and the other writer's", out, ps.value)
		}
		for i := range 2 {
			if p := kh.replica(i).pin; p != nil {
				t.Errorf("replica %d was handed %s", i, p.Marshal())
			}
		}
	})
}

// ADR 0023 M2.6 (A23-43, mutation 91d): under --confirm, a first storage
// deploy reads its record again once the bucket and the keyring are minted,
// and refuses, plan_changed, if the keyholder, the bucket, the storage
// provider or the storage location is not what its plan read and rendered:
// nothing is ensured, pushed, built, written to the pin or applied, and the
// keyholder is not recorded. A record the mint left as the plan said goes on
// and deploys. storage key rotate reads its record again once its new keys
// are saved, and refuses, plan_changed, if the keyholder is not the one its
// plan read: no pin is written and nothing is handed over (A23-45).
func TestConfirmRefusesARecordChangedDuringTheCommand(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(m *config.InstanceMetadata)
		what   string
	}{
		{"the keyholder", func(m *config.InstanceMetadata) { m.Keyholder.Replicas = 3 }, "keyholder"},
		{"no bucket", func(m *config.InstanceMetadata) { m.Storage.Bucket = "" }, "storage bucket"},
		{"the provider", func(m *config.InstanceMetadata) { m.Storage.Provider = "s3" }, "storage provider"},
		{"the location", func(m *config.InstanceMetadata) { m.Storage.Location = "europe-west4" }, "storage location"},
		{"nothing", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStorageRig(t, func(m *config.InstanceMetadata) { m.Storage = nil })
			r.mintsBucket(tc.change)
			doc := r.plan(t)
			_, stderr, err := r.run(t, "--confirm", doc.Digest)
			if r.minted != 1 {
				t.Fatalf("minted storage %d times; want once, after the comparison", r.minted)
			}
			if tc.what == "" {
				if err != nil || len(r.fc.applied) != 1 {
					t.Fatalf("--confirm over the record the plan read = %v, applying %d streams\n%s", err, len(r.fc.applied), stderr)
				}
				return
			}
			want := fmt.Sprintf("instance %q's record changed while the command ran (its %s is not what the plan read); "+
				"the bucket and the keyring were ensured, and nothing else was written; %s", writeName, tc.what, msgPlanAgain)
			if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged {
				t.Fatalf("--confirm over a record that changed = %v (kind %s);\nwant %q", err, kindOf(classified(err)), want)
			}
			if len(r.fp.ensured)+len(r.fb.embedded)+len(r.fb.built)+len(r.fc.applied) != 0 || r.ps.exists {
				t.Errorf("ensured %d, pushed %d, built %d, applied %d, and wrote the pin %v after the record changed",
					len(r.fp.ensured), len(r.fb.embedded), len(r.fb.built), len(r.fc.applied), r.ps.exists)
			}
			if after, err := r.dir.LoadInstanceMetadata(writeName); err != nil || after.Keyholder.Image != "" {
				t.Errorf("recorded the keyholder %+v (%v)", after.Keyholder, err)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		change func(m *config.InstanceMetadata)
	}{
		{"storage key rotate/the keyholder's replicas", func(m *config.InstanceMetadata) { m.Keyholder.Replicas = 3 }},
		{"storage key rotate/no keyholder", func(m *config.InstanceMetadata) { m.Keyholder = nil }},
		{"storage key rotate/nothing", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRotateRig(t, backdatedApps)
			doc := r.plan(t)
			before := liveKeyring(t, r.dir, writeName)
			if tc.change != nil {
				// While the command runs: after the comparison, as the
				// writer opens.
				r.onWriter = func() {
					if _, err := r.dir.UpdateInstanceMetadata(writeName, func(m *config.InstanceMetadata) error {
						tc.change(m)
						return nil
					}); err != nil {
						t.Error(err)
					}
				}
			}
			stdout, stderr, err := r.run(t, "--confirm", doc.Digest)
			if tc.change == nil {
				if err != nil || len(r.writes) != 2 {
					t.Fatalf("--confirm over the record the plan read = %v, writing %d pins\n%s", err, len(r.writes), stderr)
				}
				return
			}
			want := fmt.Sprintf("instance %q's record changed while the command ran (its keyholder is not what the plan read); "+
				"the new keys were minted and saved in keys.yaml, and no pin was written; %s", writeName, msgPlanAgain)
			if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged {
				t.Fatalf("--confirm over a record that changed = %v (kind %s);\nwant %q", err, kindOf(classified(err)), want)
			}
			if r.keyholders != 0 || len(r.writes) != 0 || stdout != "" {
				t.Errorf("opened the keyholder %d times, wrote the pin %d times and printed %q after the record changed", r.keyholders, len(r.writes), stdout)
			}
			after := liveKeyring(t, r.dir, writeName)
			if len(after.Scopes()[0].Keyring().KEKs()) != len(before.Scopes()[0].Keyring().KEKs())+1 || scopeKEK(after) != scopeKEK(before) {
				t.Error("the refusal says the new keys were saved, held: keys.yaml does not hold them so")
			}
		})
	}
	// A record that cannot be read again once the new keys are saved — a
	// hand-edit as the command ran — is refused too (msgRotateRecordUnread,
	// internal; row O16 of the M2.6c review): no pin is written, nothing is
	// handed over, and keys.yaml holds the new keys, held.
	t.Run("storage key rotate/an unreadable record", func(t *testing.T) {
		r := newRotateRig(t, backdatedApps)
		doc := r.plan(t)
		before := liveKeyring(t, r.dir, writeName)
		path := filepath.Join(r.dir.InstancePath(writeName), "metadata.yaml")
		r.onWriter = func() {
			if err := os.WriteFile(path, []byte("{not: [yaml"), 0o600); err != nil {
				t.Error(err)
			}
		}
		stdout, _, err := r.run(t, "--confirm", doc.Digest)
		prefix := fmt.Sprintf("re-read instance %q after minting its new keys: ", writeName)
		if err == nil || !strings.HasPrefix(err.Error(), prefix) || !strings.HasSuffix(err.Error(), "; the new keys were saved in keys.yaml, and no pin was written") ||
			kindOf(classified(err)) != kindInternal {
			t.Fatalf("--confirm over an unreadable record = %v (kind %s); want msgRotateRecordUnread, internal", err, kindOf(classified(err)))
		}
		if r.keyholders != 0 || len(r.writes) != 0 || stdout != "" {
			t.Errorf("opened the keyholder %d times, wrote the pin %d times and printed %q", r.keyholders, len(r.writes), stdout)
		}
		after := liveKeyring(t, r.dir, writeName)
		if len(after.Scopes()[0].Keyring().KEKs()) != len(before.Scopes()[0].Keyring().KEKs())+1 || scopeKEK(after) != scopeKEK(before) {
			t.Error("the refusal says the new keys were saved, held: keys.yaml does not hold them so")
		}
	})
}
