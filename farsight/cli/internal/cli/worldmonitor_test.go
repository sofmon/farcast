package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
)

// The monitor's state is first what the tunnel read says: a Shrike that
// answered is running, whatever else could not be read. Only when it did not
// answer does FatLine's workload say what it can, and unknown is left for a
// monitor neither read can speak for.
func TestTheMonitorIsRunningWhenItAnswered(t *testing.T) {
	appsFailed := &sectionProblem{Kind: kindGCloudSignedOut, Message: "signed out"}
	networkFailed := &sectionProblem{Kind: kindTunnelUnreachable, Message: "the FatLine tunnel did not open"}
	cases := []struct {
		name           string
		mutate         func(*worldInputs)
		state          string
		ready, desired *int
	}{
		{"every section read", func(*worldInputs) {}, stateRunning, ptr(2), ptr(2)},
		{"the apps section failed, the network section read", func(in *worldInputs) {
			in.Apps = appsInput{Problem: appsFailed, Meter: meterInput{Problem: appsFailed}}
		}, stateRunning, nil, nil},
		{"the network section failed, FatLine running both containers", func(in *worldInputs) {
			in.Network = networkInput{Problem: networkFailed}
		}, stateUnknown, ptr(2), ptr(2)},
		{"both failed", func(in *worldInputs) {
			in.Apps = appsInput{Problem: appsFailed, Meter: meterInput{Problem: appsFailed}}
			in.Network = networkInput{Problem: networkFailed}
		}, stateUnknown, nil, nil},
		{"the network section failed, FatLine's Pod has no second container", func(in *worldInputs) {
			in.Apps.System[0] = wl("Deployment", "farcast-system", "fatline", 2, 2, vecFatLineImage)
			in.Network = networkInput{Problem: networkFailed}
		}, stateNotDeployed, nil, nil},
		{"the network section failed, FatLine scaled to zero", func(in *worldInputs) {
			in.Apps.System[0] = wl("Deployment", "farcast-system", "fatline", 0, 0, vecFatLineImage, vecShrikeImage)
			in.Network = networkInput{Problem: networkFailed}
		}, stateStopped, ptr(0), ptr(0)},
		{"the network section failed, no FatLine at all", func(in *worldInputs) {
			in.Apps.System = []cluster.Workload{in.Apps.System[1], in.Apps.System[2]}
			in.Network = networkInput{Problem: networkFailed}
		}, stateNotDeployed, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := healthyInputs(t)
			c.mutate(&in)
			doc := buildWorld(in)
			var monitor *worldComponent
			for i := range doc.Instance.Components {
				if doc.Instance.Components[i].Role == roleMonitor {
					monitor = &doc.Instance.Components[i]
				}
			}
			if monitor == nil {
				t.Fatal("no monitor component")
			}
			if monitor.State != c.state {
				t.Errorf("state %q, want %q", monitor.State, c.state)
			}
			if !sameInt(monitor.Ready, c.ready) || !sameInt(monitor.Desired, c.desired) {
				t.Errorf("ready %v desired %v, want %v %v", deref(monitor.Ready), deref(monitor.Desired), deref(c.ready), deref(c.desired))
			}
		})
	}
}

// Across every vector, the watch line and a running monitor are the same
// fact: both say Shrike answered through the tunnel. A vector whose apps
// section failed while its network section read must be among them, or this
// proves nothing about the case the rehearsal found (phase 7, F1).
func TestTheWatchLineAndARunningMonitorAgree(t *testing.T) {
	sawAppsFailedNetworkRead := false
	for _, v := range worldVectors() {
		t.Run(v.name, func(t *testing.T) {
			in := v.inputs(t)
			doc := buildWorld(in)
			watched := false
			for _, l := range doc.Lines {
				if _, ok := l.(watchLine); ok {
					watched = true
				}
			}
			running := false
			for _, c := range doc.Instance.Components {
				if c.Role == roleMonitor {
					running = c.State == stateRunning
				}
			}
			if watched != running {
				t.Errorf("watch line drawn %v, monitor running %v", watched, running)
			}
			if in.Apps.Problem != nil && in.Network.Problem == nil {
				sawAppsFailedNetworkRead = true
				if !running {
					t.Error("the monitor answered through the tunnel, and is not running")
				}
			}
		})
	}
	if !sawAppsFailedNetworkRead {
		t.Fatal("guard: no vector reads the network with the apps section failed")
	}
}

// The terminal reading says the applications were not read where the
// workloads were not, and never counts what an answer from Shrike named: a
// monitor running because it answered is not a workloads read. A kernel
// metered list that could not be read fails the apps section with every
// workload read, and the count stands.
func TestTheHumanAppsLineSaysWhetherTheWorkloadsWereRead(t *testing.T) {
	vectors := map[string]worldVector{}
	for _, v := range worldVectors() {
		vectors[v.name] = v
	}
	unread := "  apps       not read, in 1 namespace known from elsewhere\n"
	for name, want := range map[string]string{
		"account_in_message": unread,
		"nothing_read":       unread,
		"healthy":            "  apps       2 applications in 1 namespace\n",
		"tunnel_down":        "  apps       2 applications in 1 namespace\n",
	} {
		t.Run(name, func(t *testing.T) {
			v, ok := vectors[name]
			if !ok {
				t.Fatalf("no vector %q", name)
			}
			var b strings.Builder
			if err := buildWorld(v.inputs(t)).Human(&b); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(b.String(), want) {
				t.Errorf("want the line %q in:\n%s", want, b.String())
			}
		})
	}

	in := healthyInputs(t)
	in.Apps.Meter = meterInput{Problem: &sectionProblem{Kind: kindKubectlFailed, Message: "no list"}}
	doc := buildWorld(in)
	if doc.Sections.Apps.Read {
		t.Fatal("guard: the apps section reads as read with its metered list failed")
	}
	var b strings.Builder
	if err := doc.Human(&b); err != nil {
		t.Fatal(err)
	}
	if want := "  apps       2 applications in 1 namespace\n"; !strings.Contains(b.String(), want) {
		t.Errorf("the metered list unread, the workloads read: want %q in:\n%s", want, b.String())
	}
}

// A count of replicas is said in the singular for one, as every count is.
func TestAReplicaCountOfOneIsSingular(t *testing.T) {
	in := healthyInputs(t)
	in.Apps.Workloads["shop"][0] = wl("Deployment", "shop", "web", 0, 1, vecRegistry+"/app/shop/web"+digestOf("5"))
	in.Seal.Replicas = in.Seal.Replicas[:1]
	in.Seal.Replicas[0].State = &keyholder.State{Phase: "restart-sealed", Since: vectorNow.Add(-20 * time.Minute)}
	titles := map[string]string{}
	for _, a := range buildWorld(in).Alerts {
		titles[a.Kind] = a.Title
	}
	if got, want := titles["not_ready"], "shop/web has 0 of 1 replica ready"; got != want {
		t.Errorf("not ready: %q, want %q", got, want)
	}
	if got, want := titles["sealed"], "Storage is sealed on 1 of 1 replica"; got != want {
		t.Errorf("sealed: %q, want %q", got, want)
	}

	in = healthyInputs(t)
	in.Apps.Workloads["shop"][1] = wl("Deployment", "shop", "api", 1, 2, vecRegistry+"/app/shop/api"+digestOf("6"))
	for _, a := range buildWorld(in).Alerts {
		if a.Kind == "not_ready" && a.Title != "shop/api has 1 of 2 replicas ready" {
			t.Errorf("not ready: %q", a.Title)
		}
	}
}

func sameInt(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func deref(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}
