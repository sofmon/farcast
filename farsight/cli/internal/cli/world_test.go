package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// The gather layer, tested with this package's own fakes. These assert which
// sections were read and with what kind — the bytes are the vectors' job.

// fakeWorldCluster answers the reads 'world' makes. A ConfigMap not in
// configMaps is absent; err fails every call.
type fakeWorldCluster struct {
	workloads  map[string][]cluster.Workload
	configMaps map[string]string
	labelled   []string
	err        error
	calls      []string
}

func (f *fakeWorldCluster) Workloads(_ context.Context, ns string) ([]cluster.Workload, error) {
	f.calls = append(f.calls, "workloads "+ns)
	if f.err != nil {
		return nil, f.err
	}
	return f.workloads[ns], nil
}

func (f *fakeWorldCluster) ConfigMapValue(_ context.Context, ns, name, key string) (string, bool, error) {
	f.calls = append(f.calls, "configmap "+ns+"/"+name)
	if f.err != nil {
		return "", false, f.err
	}
	v, ok := f.configMaps[ns+"/"+name+"/"+key]
	return v, ok, nil
}

func (f *fakeWorldCluster) NamespacesLabelled(_ context.Context, selector string) ([]string, error) {
	f.calls = append(f.calls, "namespaces "+selector)
	if f.err != nil {
		return nil, f.err
	}
	return f.labelled, nil
}

// fakeTunnel is fakeStreamDialer that can be closed.
type fakeTunnel struct {
	*fakeStreamDialer
	closed bool
}

func (f *fakeTunnel) Close() error { f.closed = true; return nil }

// fakeSeal answers each replica's state.
type fakeSeal struct {
	phases []string
	err    error
	asked  []int
}

func (f *fakeSeal) State(_ context.Context, i int) (keyholder.State, error) {
	f.asked = append(f.asked, i)
	if f.err != nil {
		return keyholder.State{}, f.err
	}
	return keyholder.State{Phase: f.phases[i], Generation: 3, Keys: map[string][]string{"app-shop-api": {"k1"}}}, nil
}

// worldFixture is a connected instance with a kernel, a keyholder and one
// deployed namespace, a cluster that answers for all of it, and a tunnel to a
// real monitor.
type worldFixture struct {
	dir      config.Dir
	cl       *fakeWorldCluster
	tun      *fakeTunnel
	seal     *fakeSeal
	cmd      *worldCommand
	connects int
	kenv     []string
}

func newWorldFixture(t *testing.T) *worldFixture {
	t.Helper()
	dir := config.Dir(t.TempDir())
	meta := connectedInstance(t, dir, "atlas")
	meta.Project, meta.GCloudAccount = "proj-atlas", "operator@example.org"
	meta.Kernel = &config.Kernel{Deployed: true, Applied: true, Namespaces: []string{"farcast-system", "shop"}}
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	meta.Deployments = map[string]config.Deployment{"shop": {Repository: "https://github.com/example/shop", StorageWired: true}}
	if err := dir.SaveInstanceMetadata("atlas", meta); err != nil {
		t.Fatal(err)
	}
	gdir := fakeGCloudDir(t, "work",
		gcloudConfig{Name: "work", Account: "someone@work.example", Project: "work-prod"},
		gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-atlas"})

	doc := policy.Document{Version: policy.Version, Apps: []policy.App{{Name: "api", Namespace: "shop",
		CredentialSHA256: credentialOf("a"), External: []parser.External{{Host: "api.example", Reason: "the api"}}}}}
	policyJSON, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	meterJSON, err := kernel.MarshalNamespaces([]string{"farcast-system", "shop"})
	if err != nil {
		t.Fatal(err)
	}
	f := &worldFixture{
		dir: dir,
		cl: &fakeWorldCluster{
			workloads: map[string][]cluster.Workload{
				tcdeploy.DefaultNamespace: {
					wl("Deployment", "farcast-system", "fatline", 2, 2, "reg/fatline@sha256:"+strings.Repeat("1", 64), "reg/shrike@sha256:"+strings.Repeat("2", 64)),
					wl("Deployment", "farcast-system", "technocore", 1, 1, "reg/technocore@sha256:"+strings.Repeat("3", 64)),
					wl("StatefulSet", "farcast-system", "datasphered", 2, 2, "reg/datasphered@sha256:"+strings.Repeat("4", 64)),
				},
				"shop": {wl("Deployment", "shop", "api", 1, 1, "reg/api@sha256:"+strings.Repeat("5", 64))},
			},
			configMaps: map[string]string{
				tcdeploy.DefaultNamespace + "/" + kernel.DefaultCheckpointName + "/" + kernel.CheckpointKey(): vectorCheckpoint(t, nil),
				fldeploy.DefaultNamespace + "/" + fldeploy.PolicyConfigMap + "/" + fldeploy.PolicyKey:         string(policyJSON),
				tcdeploy.DefaultNamespace + "/" + kernel.DefaultNamespacesName + "/" + kernel.NamespacesKey(): string(meterJSON),
			},
			labelled: []string{"shop"},
		},
		tun: &fakeTunnel{fakeStreamDialer: shrikeServing(t, func(m *shrike.Monitor) {
			m.Emit(event.Event{Kind: event.Allow, Tenant: "shop", App: "api", Host: "api.example", Port: "443"})
		})},
		seal: &fakeSeal{phases: []string{"unsealed", "unsealed"}},
	}
	f.cmd = &worldCommand{
		now:     func() time.Time { return vectorNow },
		stamp:   func() buildStamp { return vectorStamp },
		environ: func() []string { return []string{"HOME=/nonexistent", "CLOUDSDK_CONFIG=" + gdir, "PATH=/usr/bin"} },
		newCluster: func(_ string, env []string) worldCluster {
			f.kenv = env
			return f.cl
		},
		connect: func(context.Context, string, tunnel.ClientIdentity) (worldTunnel, error) {
			f.connects++
			return f.tun, nil
		},
		newSeal: func(keyholder.Dialer, string, config.DialIdentity) (sealReader, error) { return f.seal, nil },
	}
	return f
}

func (f *worldFixture) run(t *testing.T) (worldDoc, map[string]any) {
	t.Helper()
	env, out := testEnv(f.dir, output.ModeJSON)
	if err := f.cmd.Run(context.Background(), env, []string{"atlas"}); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.Bytes())
	}
	var doc worldDoc
	sections, _ := json.Marshal(raw["sections"])
	if err := json.Unmarshal(sections, &doc.Sections); err != nil {
		t.Fatal(err)
	}
	return doc, raw
}

func sectionKinds(s worldSections) map[string]string {
	out := map[string]string{}
	for name, st := range map[string]sectionStatus{"spend": s.Spend, "apps": s.Apps, "policy": s.Policy, "network": s.Network, "seal": s.Seal} {
		switch {
		case st.Error != nil:
			out[name] = st.Error.Kind
		case st.Skipped != "":
			out[name] = "skipped"
		case st.Read:
			out[name] = "read"
		}
	}
	return out
}

func wantSections(t *testing.T, s worldSections, want map[string]string) {
	t.Helper()
	got := sectionKinds(s)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("section %s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

// Everything readable is read: five sections, over one tunnel, and the seal
// read keeps phase and generation and drops the key ids it was sent.
func TestWorldReadsEverySectionOverOneTunnel(t *testing.T) {
	f := newWorldFixture(t)
	doc, raw := f.run(t)
	wantSections(t, doc.Sections, map[string]string{"spend": "read", "apps": "read", "policy": "read", "network": "read", "seal": "read"})
	if f.connects != 1 {
		t.Errorf("opened %d tunnels, want one for both tunnel reads", f.connects)
	}
	if !f.tun.closed {
		t.Error("the tunnel was not closed")
	}
	if f.tun.route != fldeploy.ShrikeStreamRoute {
		t.Errorf("the monitor was read over route %q", f.tun.route)
	}
	if !slices.Equal(f.seal.asked, []int{0, 1}) {
		t.Errorf("asked replicas %v, want [0 1]", f.seal.asked)
	}
	body, _ := json.Marshal(raw)
	for _, never := range []string{"app-shop-api", "credential_sha256", credentialOf("a"), "proj-atlas", "9.9.9.9", "operator@example.org"} {
		if strings.Contains(string(body), never) {
			t.Errorf("the document carries %q", never)
		}
	}
	// The observed line is there, from the real monitor.
	if !strings.Contains(string(body), `"evidence":"observed"`) {
		t.Errorf("no observed line:\n%s", body)
	}
}

// A kubectl that is not there is not asked for again: every cluster section
// says so with the one kind, and the tunnel reads still happen.
func TestWorldStopsAskingAKubectlThatIsMissing(t *testing.T) {
	f := newWorldFixture(t)
	f.cl.err = fmt.Errorf("kubectl not found: %w", cluster.ErrKubectlMissing)
	doc, _ := f.run(t)
	wantSections(t, doc.Sections, map[string]string{
		"spend": kindKubectlMissing, "apps": kindKubectlMissing, "policy": kindKubectlMissing,
		"network": "read", "seal": "read",
	})
	if len(f.cl.calls) != 1 {
		t.Errorf("kubectl was asked %d times after it was found missing: %v", len(f.cl.calls), f.cl.calls)
	}
}

func TestWorldMapsKubectlFailuresToKinds(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("refresh: %w", cluster.ErrSignedOut), kindGCloudSignedOut},
		{fmt.Errorf("plugin: %w", cluster.ErrAuthToolMissing), kindAuthToolMissing},
		{fmt.Errorf("kubectl get: %w", context.DeadlineExceeded), kindTimeout},
		{errors.New("Error from server (Forbidden)"), kindKubectlFailed},
	} {
		f := newWorldFixture(t)
		f.cl.err = tc.err
		doc, _ := f.run(t)
		wantSections(t, doc.Sections, map[string]string{"apps": tc.want, "spend": tc.want, "policy": tc.want})
	}
}

func TestWorldTunnelFailures(t *testing.T) {
	t.Run("unreachable", func(t *testing.T) {
		f := newWorldFixture(t)
		f.cmd.connect = func(context.Context, string, tunnel.ClientIdentity) (worldTunnel, error) {
			return nil, errors.New("fatline: connect https://9.9.9.9:8443: connection refused")
		}
		doc, raw := f.run(t)
		wantSections(t, doc.Sections, map[string]string{"network": kindTunnelUnreachable, "seal": kindTunnelUnreachable, "apps": "read"})
		if body, _ := json.Marshal(raw); strings.Contains(string(body), "9.9.9.9") {
			t.Errorf("the carrier's address reached the document:\n%s", body)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := newWorldFixture(t)
		f.cmd.connect = func(context.Context, string, tunnel.ClientIdentity) (worldTunnel, error) {
			return nil, fmt.Errorf("fatline: connect: %w", context.DeadlineExceeded)
		}
		doc, _ := f.run(t)
		wantSections(t, doc.Sections, map[string]string{"network": kindTimeout, "seal": kindTimeout})
	})
	t.Run("monitor answers wrong", func(t *testing.T) {
		f := newWorldFixture(t)
		f.tun.fakeStreamDialer = &fakeStreamDialer{err: errors.New("route refused")}
		doc, _ := f.run(t)
		wantSections(t, doc.Sections, map[string]string{"network": kindTunnelUnreachable, "seal": "read"})
	})
	t.Run("a replica does not answer", func(t *testing.T) {
		f := newWorldFixture(t)
		f.seal.err = errors.New("reaching replica 1: stream refused")
		doc, _ := f.run(t)
		wantSections(t, doc.Sections, map[string]string{"network": "read", "seal": kindTunnelUnreachable})
	})
}

// No carrier recorded is no tunnel, and no dial is attempted.
func TestWorldNeverConnectedDialsNothing(t *testing.T) {
	f := newWorldFixture(t)
	if _, err := f.dir.UpdateInstanceMetadata("atlas", func(m *config.InstanceMetadata) error {
		m.Carrier = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	doc, _ := f.run(t)
	wantSections(t, doc.Sections, map[string]string{"network": kindNotConnected, "seal": kindNotConnected, "apps": "read"})
	if f.connects != 0 {
		t.Errorf("dialled %d times with no carrier recorded", f.connects)
	}
}

// No kernel: the spend section says so without asking the cluster for a
// ledger nobody writes.
func TestWorldWithoutAKernel(t *testing.T) {
	f := newWorldFixture(t)
	if _, err := f.dir.UpdateInstanceMetadata("atlas", func(m *config.InstanceMetadata) error {
		m.Kernel = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	doc, _ := f.run(t)
	wantSections(t, doc.Sections, map[string]string{"spend": kindKernelAbsent, "apps": "read"})
	for _, c := range f.cl.calls {
		if strings.Contains(c, kernel.DefaultCheckpointName) {
			t.Errorf("read the ledger of an instance with no kernel: %v", f.cl.calls)
		}
	}
}

// A keyholder the record does not have is a seal section skipped, not failed.
func TestWorldSkipsTheSealWithNoKeyholder(t *testing.T) {
	f := newWorldFixture(t)
	if _, err := f.dir.UpdateInstanceMetadata("atlas", func(m *config.InstanceMetadata) error {
		m.Keyholder = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	doc, _ := f.run(t)
	wantSections(t, doc.Sections, map[string]string{"seal": "skipped", "network": "read"})
	if len(f.seal.asked) != 0 {
		t.Errorf("asked a keyholder the record does not have: %v", f.seal.asked)
	}
}

// Version skew is told apart from a broken document, for the policy and for
// the kernel's metered list; a metered list that cannot be read leaves the
// workloads read and only "metered" unknown.
func TestWorldVersionSkew(t *testing.T) {
	t.Run("policy", func(t *testing.T) {
		f := newWorldFixture(t)
		f.cl.configMaps[fldeploy.DefaultNamespace+"/"+fldeploy.PolicyConfigMap+"/"+fldeploy.PolicyKey] = `{"version":2,"apps":[]}`
		doc, _ := f.run(t)
		wantSections(t, doc.Sections, map[string]string{"policy": kindVersionSkew})
	})
	t.Run("policy broken", func(t *testing.T) {
		f := newWorldFixture(t)
		f.cl.configMaps[fldeploy.DefaultNamespace+"/"+fldeploy.PolicyConfigMap+"/"+fldeploy.PolicyKey] = `{"version":1,"apps":[{"name":"x"}]}`
		doc, _ := f.run(t)
		wantSections(t, doc.Sections, map[string]string{"policy": kindKubectlFailed})
	})
	t.Run("checkpoint", func(t *testing.T) {
		f := newWorldFixture(t)
		f.cl.configMaps[tcdeploy.DefaultNamespace+"/"+kernel.DefaultCheckpointName+"/"+kernel.CheckpointKey()] = `{"version":9}`
		doc, _ := f.run(t)
		wantSections(t, doc.Sections, map[string]string{"spend": kindVersionSkew})
	})
	t.Run("metered namespaces", func(t *testing.T) {
		f := newWorldFixture(t)
		f.cl.configMaps[tcdeploy.DefaultNamespace+"/"+kernel.DefaultNamespacesName+"/"+kernel.NamespacesKey()] = `{"version":7,"meter":[]}`
		f.cl.labelled = []string{"shop", "lab"}
		doc, raw := f.run(t)
		wantSections(t, doc.Sections, map[string]string{"apps": kindVersionSkew})
		groups := raw["groups"].([]any)
		var lab, shop map[string]any
		for _, g := range groups {
			m := g.(map[string]any)
			switch m["namespace"] {
			case "lab":
				lab = m
			case "shop":
				shop = m
			}
		}
		if lab == nil || lab["metered"] != nil {
			t.Errorf("lab's metering could not be read and must be null: %v", lab)
		}
		if shop == nil || shop["metered"] != true {
			t.Errorf("shop is metered by this machine's record: %v", shop)
		}
		if comps := raw["instance"].(map[string]any)["components"].([]any); comps[0].(map[string]any)["state"] != "running" {
			t.Errorf("the workloads were read and must stand: %v", comps)
		}
	})
	t.Run("checkpoint not written yet", func(t *testing.T) {
		f := newWorldFixture(t)
		delete(f.cl.configMaps, tcdeploy.DefaultNamespace+"/"+kernel.DefaultCheckpointName+"/"+kernel.CheckpointKey())
		doc, _ := f.run(t)
		wantSections(t, doc.Sections, map[string]string{"spend": kindNotCheckpointed})
	})
}

// The record's own failures are whole-command errors, with their kinds, and
// they name the record relative to the config directory.
func TestWorldRecordErrors(t *testing.T) {
	f := newWorldFixture(t)
	env, _ := testEnv(f.dir, output.ModeJSON)
	err := f.cmd.Run(context.Background(), env, []string{"nowhere"})
	if kindOf(err) != kindNotFound {
		t.Errorf("a missing instance: kind %q (%v)", kindOf(err), err)
	}
	for _, bad := range []string{"../atlas", "..", "a/b"} {
		if err := f.cmd.Run(context.Background(), env, []string{bad}); kindOf(err) != kindNotFound {
			t.Errorf("%q: kind %q (%v)", bad, kindOf(err), err)
		}
	}
	if err := f.cmd.Run(context.Background(), env, nil); exitCodeOf(err) != 2 {
		t.Errorf("no argument: exit %d, want 2", exitCodeOf(err))
	}
	if err := writeBrokenRecord(f.dir, "atlas"); err != nil {
		t.Fatal(err)
	}
	err = f.cmd.Run(context.Background(), env, []string{"atlas"})
	if kindOf(err) != kindRecordUnreadable || strings.Contains(err.Error(), f.dir.Path()) ||
		!strings.Contains(err.Error(), "instances/atlas/metadata.yaml") {
		t.Errorf("an unreadable record: kind %q, %v", kindOf(err), err)
	}
}

func writeBrokenRecord(dir config.Dir, name string) error {
	return os.WriteFile(filepath.Join(dir.InstancePath(name), "metadata.yaml"), []byte("cost_limit: [unclosed\n"), 0o600)
}

// The human reading says what was read and what was not, and quotes every
// name a monitor or a manifest chose.
func TestWorldHumanQuotesWhatTheInstanceChose(t *testing.T) {
	var in worldInputs
	for _, v := range worldVectors() {
		if v.name == "hostile_host_name" {
			in = v.inputs(t)
		}
	}
	in.Network.Snapshot.Replica = "fatline-\x1b[2Kforged"
	var b strings.Builder
	if err := buildWorld(in).Human(&b); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	t.Log("\n" + got)
	if !output.Printable(strings.ReplaceAll(got, "\n", "")) {
		t.Errorf("the human reading carries a character that acts on the terminal:\n%q", got)
	}
	for _, want := range []string{"expected", "confirmed", "counts are floors", `"fatline-\x1b[2Kforged"`, "refused"} {
		if !strings.Contains(got, want) {
			t.Errorf("the human reading is missing %q", want)
		}
	}

	in.Network = networkInput{Problem: &sectionProblem{Kind: kindTunnelUnreachable, Message: "no route\x1b]52;c;x\x07"}}
	b.Reset()
	if err := buildWorld(in).Human(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "network  tunnel_unreachable") || !output.Printable(strings.ReplaceAll(b.String(), "\n", "")) {
		t.Errorf("a section that was not read:\n%q", b.String())
	}
}

// blockingCluster is a control plane that never answers: every read waits
// until its context ends, and then fails the way the cluster package says a
// kubectl past its deadline failed.
type blockingCluster struct{ calls atomic.Int32 }

func (b *blockingCluster) wait(ctx context.Context) error {
	b.calls.Add(1)
	<-ctx.Done()
	return fmt.Errorf("kubectl get: %w", ctx.Err())
}

func (b *blockingCluster) Workloads(ctx context.Context, _ string) ([]cluster.Workload, error) {
	return nil, b.wait(ctx)
}

func (b *blockingCluster) ConfigMapValue(ctx context.Context, _, _, _ string) (string, bool, error) {
	return "", false, b.wait(ctx)
}

func (b *blockingCluster) NamespacesLabelled(ctx context.Context, _ string) ([]string, error) {
	return nil, b.wait(ctx)
}

func sectionMessage(t *testing.T, raw map[string]any, section string) string {
	t.Helper()
	s, _ := raw["sections"].(map[string]any)[section].(map[string]any)
	e, _ := s["error"].(map[string]any)
	msg, _ := e["message"].(string)
	return msg
}

// A control plane that does not answer costs one read's deadline, not the
// whole ceiling: it is not asked again, the later cluster sections say they
// were not asked, and the tunnel reads — made alongside — still come back.
func TestWorldASilentControlPlaneCostsOneReadNotTheCeiling(t *testing.T) {
	f := newWorldFixture(t)
	f.cmd.timeouts = worldTimeouts{ceiling: 20 * time.Second, kubectl: 100 * time.Millisecond, connect: 5 * time.Second, seal: 5 * time.Second}
	silent := &blockingCluster{}
	f.cmd.newCluster = func(string, []string) worldCluster { return silent }
	start := time.Now()
	doc, raw := f.run(t)
	elapsed := time.Since(start)
	wantSections(t, doc.Sections, map[string]string{
		"apps": kindTimeout, "spend": kindTimeout, "policy": kindTimeout, "network": "read", "seal": "read",
	})
	if n := silent.calls.Load(); n != 1 {
		t.Errorf("a control plane that did not answer was asked %d times", n)
	}
	if elapsed > 10*time.Second {
		t.Errorf("the read took %s; one silent read should cost about its own deadline", elapsed)
	}
	for _, section := range []string{"spend", "policy"} {
		if msg := sectionMessage(t, raw, section); !strings.Contains(msg, "not asked") {
			t.Errorf("%s: %q; a section that was never asked must say so", section, msg)
		}
	}
}

// A cluster read that runs to the ceiling does not starve the tunnel: the two
// are read side by side, so the network and seal sections are read, not
// reported as a tunnel that "did not open".
func TestWorldTheCeilingReachedByTheClusterDoesNotStarveTheTunnel(t *testing.T) {
	f := newWorldFixture(t)
	f.cmd.timeouts = worldTimeouts{ceiling: 2 * time.Second, kubectl: time.Hour, connect: 5 * time.Second, seal: 5 * time.Second}
	f.cmd.newCluster = func(string, []string) worldCluster { return &blockingCluster{} }
	doc, raw := f.run(t)
	wantSections(t, doc.Sections, map[string]string{
		"apps": kindTimeout, "spend": kindTimeout, "policy": kindTimeout, "network": "read", "seal": "read",
	})
	if f.connects != 1 {
		t.Errorf("dialled %d times", f.connects)
	}
	if msg := sectionMessage(t, raw, "policy"); !strings.Contains(msg, "ceiling") {
		t.Errorf("policy: %q; want the ceiling named", msg)
	}
}

// A tunnel the ceiling never let start says it was not attempted — which is
// not a carrier that did not answer — and dials nothing.
func TestWorldATunnelNeverTriedSaysSo(t *testing.T) {
	f := newWorldFixture(t)
	f.cmd.ensureDefaults()
	meta, err := f.dir.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	env, _ := testEnv(f.dir, output.ModeJSON)
	network, seal := f.cmd.throughTunnel(ctx, env, "atlas", meta)
	if network.Problem == nil || network.Problem.Kind != kindTimeout || !strings.Contains(network.Problem.Message, "not attempted") ||
		seal.Problem == nil || seal.Problem.Kind != kindTimeout {
		t.Errorf("network %+v, seal %+v", network.Problem, seal.Problem)
	}
	if f.connects != 0 || network.Tunnel {
		t.Errorf("dialled %d times past the ceiling", f.connects)
	}
}

// kubectl and its auth plugin name files in their errors — the instance's
// kubeconfig, gcloud's credential store, a cache under the home directory.
// A section message names none of this machine's paths.
func TestWorldSectionMessagesCarryNoLocalPath(t *testing.T) {
	f := newWorldFixture(t)
	gdir := envValueOf(f.cmd.environ(), "CLOUDSDK_CONFIG")
	kubeconfig := f.dir.InstanceKubeconfigPath("atlas")
	f.cl.err = fmt.Errorf("kubectl get: error loading config file %q: open %s: permission denied; "+
		"see %s and /nonexistent/.kube/cache/discovery", kubeconfig, kubeconfig, filepath.Join(gdir, "credentials.db"))
	doc, raw := f.run(t)
	wantSections(t, doc.Sections, map[string]string{"apps": kindKubectlFailed})
	msg := sectionMessage(t, raw, "apps")
	for _, never := range []string{f.dir.Path(), gdir, "/nonexistent"} {
		if strings.Contains(msg, never) {
			t.Errorf("the message carries %q: %s", never, msg)
		}
	}
	for _, want := range []string{"<config>/instances/atlas/kubeconfig.yaml", "$CLOUDSDK_CONFIG/credentials.db", "~/.kube/cache"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not say %q: %s", want, msg)
		}
	}
}

// A namespace the policy or the monitor names, and no other source does, is
// metered by the same rule as every other group: false when the kernel's list
// was read and neither it nor the record names it — which raises the alert —
// true when the record does, and unknown when the list could not be read.
func TestAGroupNamedOnlyByThePolicyIsMeteredByTheSameRule(t *testing.T) {
	groupOf := func(doc worldDoc, ns string) *worldGroup {
		for i := range doc.Groups {
			if doc.Groups[i].Namespace == ns {
				return &doc.Groups[i]
			}
		}
		return nil
	}
	alerted := func(doc worldDoc) bool {
		return slices.ContainsFunc(doc.Alerts, func(a worldAlert) bool { return a.ID == "unmetered_namespace:component:kernel:lab" })
	}
	base := func(t *testing.T) worldInputs {
		in := healthyInputs(t)
		in.Policy.Doc.Apps = append(in.Policy.Doc.Apps, policy.App{Name: "notebook", Namespace: "lab", CredentialSHA256: credentialOf("c")})
		return in
	}

	doc := buildWorld(base(t))
	if g := groupOf(doc, "lab"); g == nil || g.Metered == nil || *g.Metered || !alerted(doc) {
		t.Errorf("read and unlisted: group %+v, alerted %v; want metered false and the alert", g, alerted(doc))
	}

	in := base(t)
	in.Meta.Kernel.Namespaces = append(in.Meta.Kernel.Namespaces, "lab")
	doc = buildWorld(in)
	if g := groupOf(doc, "lab"); g == nil || g.Metered == nil || !*g.Metered || alerted(doc) {
		t.Errorf("listed by the record: group %+v, alerted %v; want metered true and no alert", g, alerted(doc))
	}

	in = base(t)
	in.Apps.Meter = meterInput{Problem: &sectionProblem{Kind: kindKubectlFailed, Message: "no list"}}
	doc = buildWorld(in)
	if g := groupOf(doc, "lab"); g == nil || g.Metered != nil || alerted(doc) {
		t.Errorf("list unread: group %+v, alerted %v; want metered null and no alert", g, alerted(doc))
	}
}

// A record written before credentials in repository URLs were refused may
// hold one; the document and its human reading never do.
func TestWorldNeverShowsACredentialInARepository(t *testing.T) {
	in := healthyInputs(t)
	dep := in.Meta.Deployments["shop"]
	dep.Repository = "https://x-access-token:ghp_planted@github.com/example/shop"
	in.Meta.Deployments["shop"] = dep
	doc := buildWorld(in)
	raw := vectorBytes(t, doc)
	var b strings.Builder
	if err := doc.Human(&b); err != nil {
		t.Fatal(err)
	}
	for what, got := range map[string]string{"document": string(raw), "human reading": b.String()} {
		if strings.Contains(got, "ghp_planted") || strings.Contains(got, "x-access-token") {
			t.Errorf("the %s carries the credential:\n%s", what, got)
		}
		if !strings.Contains(got, "https://github.com/example/shop") {
			t.Errorf("the %s lost the repository itself:\n%s", what, got)
		}
	}
}

// A record that does not parse is never quoted — not in the listing, not in
// its human reading, not in the error 'world' returns, nor a pin's — even when the
// fault sits right after the lines holding the project, the endpoints and the
// pinned account, which the YAML parser's own message would print.
func TestAnUnparseableRecordIsNeverQuoted(t *testing.T) {
	f := newWorldFixture(t)
	path := filepath.Join(f.dir.InstancePath("atlas"), "metadata.yaml")
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(good), "gcloud_account: operator@example.org\n") {
		t.Fatalf("guard: the record does not hold the account where this test breaks it:\n%s", good)
	}
	broken := strings.Replace(string(good), "gcloud_account: operator@example.org\n", "gcloud_account: operator@example.org\nbroken: [unclosed\n", 1)
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	// What the fixture's record holds, and where it lives.
	secrets := []string{"operator@example.org", "proj-atlas", "9.9.9.9", f.dir.Path()}

	outputs := map[string]string{}
	listing, code := runRouter(t, "--config", f.dir.Path(), "-o", "json", "instances")
	if code != 0 {
		t.Fatalf("instances: exit %d\n%s", code, listing)
	}
	outputs["instances -o json"] = string(listing)
	human, _ := runRouter(t, "--config", f.dir.Path(), "instances")
	outputs["instances"] = string(human)

	env, _ := testEnv(f.dir, output.ModeJSON)
	err = f.cmd.Run(context.Background(), env, []string{"atlas"})
	if kindOf(err) != kindRecordUnreadable {
		t.Fatalf("world: kind %q, %v", kindOf(err), err)
	}
	outputs["world"] = err.Error()

	pin := instancesVectorCommand()
	pin.account = "operator@example.org"
	err = pin.Run(context.Background(), env, []string{"pin-gcloud", "atlas"})
	if kindOf(err) != kindRecordUnreadable {
		t.Fatalf("pin-gcloud: kind %q, %v", kindOf(err), err)
	}
	outputs["pin-gcloud"] = err.Error()

	for what, got := range outputs {
		if !strings.Contains(got, "instances/atlas/metadata.yaml could not be parsed: a YAML syntax error at line ") {
			t.Errorf("%s does not say where the record broke:\n%s", what, got)
		}
		for _, s := range secrets {
			if strings.Contains(got, s) {
				t.Errorf("%s quotes the record (%q):\n%s", what, s, got)
			}
		}
	}
}

// A directory is replaced as a whole path component, longest first: a home
// of /Users/op is not the start of /Users/operator, and the config directory
// inside the home reads <config>, not ~/….
func TestLocalPathsAreReplacedAsWholeComponents(t *testing.T) {
	g := &gatherer{paths: localPaths(config.Dir("/Users/op/.config/farcast"),
		gcloudChoice{Dir: "/Volumes/keys/gcloud", Source: "$CLOUDSDK_CONFIG"}, []string{"HOME=/Users/op"})}
	got := g.scrub(`open "/Users/op/.config/farcast/instances/a/kubeconfig.yaml": denied; /Users/operator/x; /Users/op; ` +
		`/Volumes/keys/gcloud/credentials.db; /Volumes/keys/gcloud-old`)
	want := `open "<config>/instances/a/kubeconfig.yaml": denied; /Users/operator/x; ~; ` +
		`$CLOUDSDK_CONFIG/credentials.db; /Volumes/keys/gcloud-old`
	if got != want {
		t.Errorf("scrubbed\n got %s\nwant %s", got, want)
	}
}
