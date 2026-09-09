package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
	"github.com/sofmon/farcast/technocore/adapt"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
	"github.com/sofmon/farcast/technocore/usage"
)

// profilesFor builds a real kernel usage document through the real store, so
// this test cannot drift from what the kernel actually writes.
func profilesFor(t *testing.T, at time.Time, build func(*usage.Store), unavailable []string) string {
	t.Helper()
	store := usage.New(24)
	build(store)
	doc := kernel.Profiles{
		Version: kernel.ProfilesVersion, At: at, Store: store.Snapshot(), Unavailable: unavailable,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func usageReader(t *testing.T, body string) *fakeReader {
	t.Helper()
	return &fakeReader{configMaps: map[string]string{
		tcdeploy.DefaultNamespace + "/" + kernel.DefaultProfilesName + "/" + kernel.ProfilesKey(): body,
	}}
}

// fakeStreamDialer stands in for the FatLine tunnel: it dials a local server
// instead of relaying into a cluster, so the report exercises the real HTTP
// path over a fake transport rather than a faked response.
type fakeStreamDialer struct {
	addr  string
	err   error
	route string
	dials int
}

func (f *fakeStreamDialer) DialStream(ctx context.Context, route string, _ int) (net.Conn, error) {
	f.dials++
	f.route = route
	if f.err != nil {
		return nil, f.err
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", f.addr)
}

// shrikeServing runs a real Monitor behind a real handler, fed real events, so
// the report cannot drift from what Shrike actually serves.
func shrikeServing(t *testing.T, feed func(*shrike.Monitor)) *fakeStreamDialer {
	t.Helper()
	m := shrike.New(shrike.Config{Declared: []parser.External{{Host: "api.example"}}})
	feed(m)
	srv := httptest.NewServer(m.Handler())
	t.Cleanup(srv.Close)
	return &fakeStreamDialer{addr: strings.TrimPrefix(srv.URL, "http://")}
}

func runUsage(t *testing.T, dir config.Dir, body string, mode output.Mode) string {
	t.Helper()
	return runUsageWith(t, dir, body, mode, &fakeStreamDialer{err: errors.New("no tunnel in this test")})
}

func runUsageWith(t *testing.T, dir config.Dir, body string, mode output.Mode, d streamDialer) string {
	t.Helper()
	env, out := testEnv(dir, mode)
	c := &usageCommand{}
	f := usageReader(t, body)
	c.newCluster = func(string) usageReaderIface { return f }
	c.newDialer = func(context.Context, *Env, string) (streamDialer, func(), error) {
		if d == nil {
			return nil, nil, errors.New("no dialer")
		}
		return d, func() {}, nil
	}
	if err := c.Run(context.Background(), env, []string{"p51"}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestUsageReportsWhatOnePodUsedAgainstWhatItReserves(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	body := profilesFor(t, at, func(s *usage.Store) {
		for h := 0; h < 24; h++ {
			when := at.Add(-time.Duration(23-h) * time.Hour)
			for i := 0; i < 120; i++ {
				s.Record(when, "api", []usage.PodUsage{
					{Pod: "api-1", CPUMilli: 40, MemMiB: 110, RequestCPUMilli: 500, RequestMemMiB: 512},
					{Pod: "api-2", CPUMilli: 44, MemMiB: 118, RequestCPUMilli: 500, RequestMemMiB: 512},
				})
			}
		}
	}, nil)

	shown := runUsage(t, dir, body, output.ModeHuman)
	t.Log("\n" + shown)
	for _, want := range []string{"Observed usage", "24h window", "api", "500m", "512Mi", "ONE POD", "never sizes itself"} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing %q", want)
		}
	}
	// 500m reserved against a p95 of 44m is eleven times over, and 512Mi
	// against 118Mi is four. Both are what an operator would act on, so both
	// are asserted exactly rather than as "some ratio appeared".
	for _, want := range []string{"11.4x", "4.3x", "steady"} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing the %q ratio", want)
		}
	}
}

// The distinction the whole command turns on: two pods using 40m each are a
// pod that uses 40m, not one that uses 80m.
func TestUsageNeverSumsReplicasIntoOnePod(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	body := profilesFor(t, at, func(s *usage.Store) {
		for i := 0; i < 200; i++ {
			s.Record(at, "api", []usage.PodUsage{
				{Pod: "api-1", CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512},
				{Pod: "api-2", CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512},
				{Pod: "api-3", CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512},
			})
		}
	}, nil)

	var res usageResult
	if err := json.Unmarshal([]byte(runUsage(t, dir, body, output.ModeJSON)), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Apps) != 1 {
		t.Fatalf("reported %d applications", len(res.Apps))
	}
	got := res.Apps[0]
	if got.Pods != 3 {
		t.Errorf("pods is %d, want 3", got.Pods)
	}
	if got.CPU.Day.P95 > 45 {
		t.Errorf("p95 is %dm — three pods at 40m were summed into one", got.CPU.Day.P95)
	}
}

// "Not measured" and "measured as zero" are different states, and an operator
// acting on the second when the first is true would draw exactly the wrong
// conclusion about an application that looks idle.
func TestUsageSaysWhatItCouldNotMeasure(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	body := profilesFor(t, at, func(*usage.Store) {}, []string{"farcast-apps: kube: object not found"})
	shown := runUsage(t, dir, body, output.ModeHuman)
	t.Log("\n" + shown)
	for _, want := range []string{"Not measured", "not the same as zero", "farcast-apps", "Redeploying the kernel"} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

// Too few readings must read as "thin", never as a confident ratio built on
// three samples.
func TestUsageSaysThinRatherThanGuessing(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	body := profilesFor(t, at, func(s *usage.Store) {
		s.Record(at, "api", []usage.PodUsage{{Pod: "api-1", CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512}})
	}, nil)
	shown := runUsage(t, dir, body, output.ModeHuman)
	t.Log("\n" + shown)
	if !strings.Contains(shown, "thin") {
		t.Error("a single reading did not read as thin")
	}
	if !strings.Contains(shown, "collecting") {
		t.Error("the trend column claimed to know a direction from one reading")
	}
}

// A short window because the budget shortened it looks identical to an
// instance that just started, unless it says so.
func TestUsageSaysWhenTheBudgetShortenedTheWindow(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	store := usage.New(6)
	store.Record(at, "api", []usage.PodUsage{{CPUMilli: 40, RequestCPUMilli: 500}})
	doc := kernel.Profiles{
		Version: kernel.ProfilesVersion, At: at, Store: store.Snapshot(),
		TrimmedTo: 6, Dropped: []string{"batch"},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	shown := runUsage(t, dir, string(raw), output.ModeHuman)
	t.Log("\n" + shown)
	for _, want := range []string{"shortened to 6h", "size budget", "batch"} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

func TestUsageRefusesAnInstanceWithNoKernel(t *testing.T) {
	dir := config.Dir(t.TempDir())
	buildableInstance(t, dir, "bare")
	env, _ := testEnv(dir, output.ModeHuman)
	c := &usageCommand{}
	c.newCluster = func(string) usageReaderIface { return &fakeReader{} }
	err := c.Run(context.Background(), env, []string{"bare"})
	if err == nil || !strings.Contains(err.Error(), "kernel deploy") {
		t.Fatalf("error is %v, want one naming the command that fixes it", err)
	}
}

func TestUsageSaysWhenNothingHasBeenWrittenYet(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	env, _ := testEnv(dir, output.ModeHuman)
	c := &usageCommand{}
	c.newCluster = func(string) usageReaderIface { return &fakeReader{cmMissing: true} }
	err := c.Run(context.Background(), env, []string{"p51"})
	if err == nil || !strings.Contains(err.Error(), "has not written any usage profiles yet") {
		t.Fatalf("error is %v", err)
	}
}

// A document from another build is refused rather than half-read: these
// numbers exist to become a resource reservation.
func TestUsageRefusesAnUnknownDocumentVersion(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	env, _ := testEnv(dir, output.ModeHuman)
	c := &usageCommand{}
	f := usageReader(t, `{"version":99,"at":"2026-09-09T12:00:00Z","store":{"version":1,"hours":24}}`)
	c.newCluster = func(string) usageReaderIface { return f }
	err := c.Run(context.Background(), env, []string{"p51"})
	if err == nil || !strings.Contains(err.Error(), "older than the other") {
		t.Fatalf("error is %v", err)
	}
}

// The network half comes from the boundary, because the boundary is the only
// place an application's traffic is visible at all.
func TestUsageReportsWhatCrossedTheBoundaryPerApplication(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	body := profilesFor(t, at, func(*usage.Store) {}, nil)

	d := shrikeServing(t, func(m *shrike.Monitor) {
		m.Emit(event.Event{Kind: event.Allow, Tenant: "apps", App: "api", Host: "api.example", Port: "443"})
		m.Emit(event.Event{Kind: event.Close, Tenant: "apps", App: "api", Host: "api.example", Port: "443",
			BytesUp: 4096, BytesDown: 1 << 20, DialMillis: 40, DurationMillis: 900})
		m.Emit(event.Event{Kind: event.Fail, Tenant: "apps", App: "api", Host: "api.example", Port: "443",
			Reason: event.ReasonDialFailed, DialMillis: 3000})
		m.Emit(event.Event{Kind: event.Deny, Tenant: "apps", App: "web", Host: "nope.example",
			Reason: event.ReasonNotInAllowlist})
	})

	shown := runUsageWith(t, dir, body, output.ModeHuman, d)
	t.Log("\n" + shown)
	if d.route != "shrike" {
		t.Errorf("the monitor was reached by route %q, want the named %q route", d.route, "shrike")
	}
	for _, want := range []string{"Network", "api", "web", "4.0 KiB", "1.0 MiB", "never opens the tunnel it carries"} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing %q", want)
		}
	}
	// A failed connection and a denied one are different facts and get
	// different columns: one is the network, the other is the policy.
	if !strings.Contains(shown, ">2s") {
		t.Errorf("the three-second wait before failing is not shown")
	}
}

// An unidentified caller is the row an operator most needs to see, so it is
// named as what it is rather than rendered blank.
func TestUsageNamesAnUnidentifiedCaller(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	body := profilesFor(t, at, func(*usage.Store) {}, nil)

	d := shrikeServing(t, func(m *shrike.Monitor) {
		m.Emit(event.Event{Kind: event.Deny, Host: "x.example", Reason: event.ReasonUnknownApp})
	})
	shown := runUsageWith(t, dir, body, output.ModeHuman, d)
	if !strings.Contains(shown, "(unidentified)") {
		t.Errorf("output does not name the unidentified caller:\n%s", shown)
	}
}

// The two halves come from two places and either can be missing on its own. A
// tunnel that is down must not cost the operator the compute half as well.
func TestUsageStillReportsComputeWhenTheMonitorCannotBeReached(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	body := profilesFor(t, at, func(s *usage.Store) {
		for i := 0; i < usage.MinSamples; i++ {
			s.Record(at, "api", []usage.PodUsage{{CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512}})
		}
	}, nil)

	shown := runUsageWith(t, dir, body, output.ModeHuman, &fakeStreamDialer{err: errors.New("connection refused")})
	t.Log("\n" + shown)
	if !strings.Contains(shown, "api") || !strings.Contains(shown, "500m") {
		t.Error("the compute half was lost with the tunnel")
	}
	for _, want := range []string{"Network not measured", "not the same as zero", "connection refused", "farcast connect"} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

// An instance whose applications have made no outbound connection is a real
// answer, and a different one from a monitor that could not be read.
func TestUsageDistinguishesQuietFromUnreadable(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	body := profilesFor(t, at, func(*usage.Store) {}, nil)

	d := shrikeServing(t, func(*shrike.Monitor) {})
	shown := runUsageWith(t, dir, body, output.ModeHuman, d)
	if !strings.Contains(shown, "No application has made an outbound connection") {
		t.Errorf("a quiet instance did not read as quiet:\n%s", shown)
	}
	if strings.Contains(shown, "not measured") {
		t.Error("a quiet instance was reported as unmeasured")
	}
}

// The route has to be in what `connect` actually deploys, or the feature is
// dead in a cluster while every unit test above still passes — the failure
// mode this project has hit twice (Shrike deployed nowhere, `kernel meter`
// writing a list nothing read).
func TestTheDeployedRoutesReachTheMonitor(t *testing.T) {
	var found string
	for _, r := range systemStreamRoutes() {
		if strings.HasPrefix(r, fldeploy.ShrikeStreamRoute+"=") {
			found = r
		}
	}
	if found == "" {
		t.Fatalf("no %q route in what connect deploys: %v", fldeploy.ShrikeStreamRoute, systemStreamRoutes())
	}
	// Loopback, deliberately: the monitor listens where only its own Pod can
	// reach it, and FatLine's relay is in that Pod.
	want := fmt.Sprintf("%s=127.0.0.1:%d", fldeploy.ShrikeStreamRoute, fldeploy.ShrikeStatusPort)
	if found != want {
		t.Errorf("route is %q, want %q", found, want)
	}
	// And it must be the route the reader asks for.
	d := &fakeStreamDialer{err: errors.New("stop here")}
	_, _ = fetchNetwork(context.Background(), d)
	if d.route != fldeploy.ShrikeStreamRoute {
		t.Errorf("the reader asks for route %q, the deploy publishes %q", d.route, fldeploy.ShrikeStreamRoute)
	}
}

// The rendered workload must actually start the status listener, or the route
// reaches a port nothing is on.
func TestTheRenderedSidecarServesTheStatusPort(t *testing.T) {
	out, err := fldeploy.Render(fldeploy.Config{
		Image: "reg/fatline@sha256:aa", ShrikeImage: "reg/shrike@sha256:bb",
		CACertPEM: []byte("ca"), ServerCertPEM: []byte("crt"), ServerKeyPEM: []byte("key"),
		StreamRoutes: systemStreamRoutes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(out)
	if want := fmt.Sprintf("--status-listen=127.0.0.1:%d", fldeploy.ShrikeStatusPort); !strings.Contains(rendered, want) {
		t.Errorf("the sidecar does not serve %q", want)
	}
	if want := fmt.Sprintf("--stream-route=%s=127.0.0.1:%d", fldeploy.ShrikeStreamRoute, fldeploy.ShrikeStatusPort); !strings.Contains(rendered, want) {
		t.Errorf("the workload does not carry %q", want)
	}
}

// The tunnel failing to OPEN is a different path from a dial failing inside
// it, and the likelier of the two: an instance that has never been connected,
// or whose carrier is gone. It must read the same way — the compute half
// intact, the network half named as missing.
func TestUsageStillReportsComputeWhenThereIsNoTunnelAtAll(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	body := profilesFor(t, at, func(s *usage.Store) {
		for i := 0; i < usage.MinSamples; i++ {
			s.Record(at, "api", []usage.PodUsage{{CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512}})
		}
	}, nil)

	env, out := testEnv(dir, output.ModeHuman)
	c := &usageCommand{}
	c.newCluster = func(string) usageReaderIface { return usageReader(t, body) }
	c.newDialer = func(context.Context, *Env, string) (streamDialer, func(), error) {
		return nil, nil, errors.New("instance \"p51\" has no tunnel; run 'farcast connect p51' first")
	}
	if err := c.Run(context.Background(), env, []string{"p51"}); err != nil {
		t.Fatal(err)
	}
	shown := out.String()
	t.Log("\n" + shown)
	if !strings.Contains(shown, "500m") {
		t.Error("the compute half was lost with the tunnel")
	}
	if !strings.Contains(shown, "has no tunnel") {
		t.Errorf("the reason the network half is missing was not reported")
	}
}

// --no-network is a different empty from a monitor that could not be read.
func TestUsageSkipsTheNetworkWhenAsked(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	body := profilesFor(t, at, func(*usage.Store) {}, nil)

	env, out := testEnv(dir, output.ModeHuman)
	c := &usageCommand{noNetwork: true}
	c.newCluster = func(string) usageReaderIface { return usageReader(t, body) }
	called := false
	c.newDialer = func(context.Context, *Env, string) (streamDialer, func(), error) {
		called = true
		return nil, nil, errors.New("should not be reached")
	}
	if err := c.Run(context.Background(), env, []string{"p51"}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("--no-network opened the tunnel anyway")
	}
	if !strings.Contains(out.String(), "--no-network was given") {
		t.Errorf("the skipped section does not say why it is empty:\n%s", out.String())
	}
}

// Found live on the 5.1b walk: each FatLine replica keeps its own Shrike and
// its own picture, and a read lands on whichever pod terminated the tunnel —
// so two consecutive reports showed two different partial counts, each
// presented as the instance's traffic. Saying whose picture it is, and
// whether it is the whole one, is what makes the number usable.
func TestUsageSaysWhoseNetworkPictureItIs(t *testing.T) {
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	cases := []struct {
		name     string
		desired  int
		seedPods bool
		want     []string
		absent   []string
	}{
		{
			name: "several replicas", desired: 2, seedPods: true,
			want: []string{"of 2", "share of the instance's traffic, not the total"},
		},
		{
			name: "one replica", desired: 1, seedPods: true,
			want:   []string{"the only FatLine replica", "this is the whole picture"},
			absent: []string{"not the total"},
		},
		{
			name: "replica count unreadable", seedPods: false,
			want: []string{"could not be read", "whether this is the whole picture"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			meteringInstance(t, dir, "p51")
			body := profilesFor(t, at, func(*usage.Store) {}, nil)

			f := usageReader(t, body)
			if tc.seedPods {
				f.deployments = map[string][]cluster.Workload{
					tcdeploy.DefaultNamespace: {{Kind: "Deployment", Name: "fatline", Desired: tc.desired}},
				}
			}
			d := shrikeServing(t, func(m *shrike.Monitor) {
				m.Emit(event.Event{Kind: event.Allow, Tenant: "apps", App: "api", Host: "api.example"})
			})
			env, out := testEnv(dir, output.ModeHuman)
			c := &usageCommand{}
			c.newCluster = func(string) usageReaderIface { return f }
			c.newDialer = func(context.Context, *Env, string) (streamDialer, func(), error) {
				return d, func() {}, nil
			}
			if err := c.Run(context.Background(), env, []string{"p51"}); err != nil {
				t.Fatal(err)
			}
			shown := out.String()
			t.Log("\n" + shown)
			for _, w := range tc.want {
				if !strings.Contains(shown, w) {
					t.Errorf("output is missing %q", w)
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(shown, a) {
					t.Errorf("output wrongly contains %q", a)
				}
			}
		})
	}
}

// The monitor names its own pod, so a reader can tell two reads apart.
func TestTheMonitorNamesItsReplica(t *testing.T) {
	m := shrike.New(shrike.Config{})
	if m.Snapshot().Replica == "" {
		t.Error("the picture does not say which pod kept it")
	}
}

// A sidecar older than this build sends no replica name. The warning must
// still fire: the replica count comes from the cluster, and it is what decides
// whether the counts are a share.
func TestTheShareWarningDoesNotDependOnTheSidecarsVersion(t *testing.T) {
	r := usageResult{
		Network:  []shrike.AppStat{{App: "api", Allows: 1}},
		Replicas: 2,
		// NetworkReplica deliberately empty — an older monitor.
	}
	var buf bytes.Buffer
	if err := r.Human(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "not the total") {
		t.Errorf("no share warning without a replica name:\n%s", buf.String())
	}
}

// adviceFor builds a profile document carrying real kernel advice, so the
// report cannot drift from what the kernel actually publishes.
func adviceFor(t *testing.T, at time.Time, adapting bool, advice ...kernel.Adaptation) string {
	t.Helper()
	store := usage.New(24)
	doc := kernel.Profiles{
		Version: kernel.ProfilesVersion, At: at, Store: store.Snapshot(),
		Advice: advice, Adapting: adapting,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestUsageShowsWhatWouldBeResizedAndWhatItIsWaitingFor(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	body := adviceFor(t, at, false,
		kernel.Adaptation{
			Namespace: "apps", Deployment: "api", Container: "api", Replicas: 1,
			Advice: adapt.Advice{App: "api", CurrentCPUMilli: 500, CurrentMemMiB: 512,
				CPUMilli: 130, MemMiB: 128, Act: true},
		},
		kernel.Adaptation{
			Namespace: "apps", Deployment: "batch", Replicas: 1,
			Advice: adapt.Advice{App: "batch", CurrentCPUMilli: 100, CurrentMemMiB: 128,
				CPUMilli: 100, MemMiB: 128, Hold: "only 14 readings so far"},
		},
	)
	shown := runUsage(t, dir, body, output.ModeHuman)
	t.Log("\n" + shown)
	for _, want := range []string{
		"Right-sizing", "api", "500m/512Mi", "130m/128Mi",
		"batch", "holding: only 14 readings so far",
		"Adapting is OFF", "--adapt",
	} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing %q", want)
		}
	}
	// A saving must read as a saving.
	if !strings.Contains(shown, "-") {
		t.Error("no signed monthly delta")
	}
}

// A report that cannot tell a kernel holding back from one merely thinking
// out loud leaves an operator unable to know whether their instance is being
// changed underneath them.
func TestUsageSaysWhetherTheKernelIsActingOnItsAdvice(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	a := kernel.Adaptation{
		Namespace: "apps", Deployment: "api", Container: "api", Replicas: 1,
		Advice: adapt.Advice{App: "api", CurrentCPUMilli: 500, CurrentMemMiB: 512, CPUMilli: 130, MemMiB: 128, Act: true},
	}
	on := runUsage(t, dir, adviceFor(t, at, true, a), output.ModeHuman)
	if !strings.Contains(on, "Adapting is ON") || !strings.Contains(on, "every resize is a rollout") &&
		!strings.Contains(on, "Every resize is a rollout") {
		t.Errorf("an adapting kernel does not say so:\n%s", on)
	}
	off := runUsage(t, dir, adviceFor(t, at, false, a), output.ModeHuman)
	if !strings.Contains(off, "Adapting is OFF") {
		t.Errorf("a non-adapting kernel does not say so:\n%s", off)
	}
}

// A clamped step read as the system's final opinion would look like a wrong
// answer rather than a first move.
func TestUsageSaysWhenAStepWasBounded(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	body := adviceFor(t, at, false, kernel.Adaptation{
		Namespace: "apps", Deployment: "api", Container: "api", Replicas: 1,
		Advice: adapt.Advice{App: "api", CurrentCPUMilli: 4000, CurrentMemMiB: 4096,
			CPUMilli: 2000, MemMiB: 2048, Act: true, Stepped: true},
	})
	shown := runUsage(t, dir, body, output.ModeHuman)
	if !strings.Contains(shown, "move further next time") {
		t.Errorf("a bounded step is presented as final:\n%s", shown)
	}
}

// Nothing to advise means no section at all, rather than an empty heading.
func TestUsageOmitsRightSizingWhenThereIsNone(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	shown := runUsage(t, dir, profilesFor(t, at, func(*usage.Store) {}, nil), output.ModeHuman)
	if strings.Contains(shown, "Right-sizing") {
		t.Errorf("an empty right-sizing section was printed:\n%s", shown)
	}
}
