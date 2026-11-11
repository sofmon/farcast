package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/keeper"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
)

// terminalText leaves text that only prints alone and quotes anything that
// would act on the terminal instead — including the bidi format characters,
// which are not ASCII controls, and bytes that are not UTF-8 at all.
func TestTerminalText(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"payment processing", "payment processing"},
		{"paiement à l'étranger — ça marche", "paiement à l'étranger — ça marche"},
		{"支払い処理", "支払い処理"},
		{"a\x1b[2Kb", `"a\x1b[2Kb"`},
		{"a\rb", `"a\rb"`},
		{"a\nb", `"a\nb"`},
		{"a\x00b", `"a\x00b"`},
		{"a\tb", `"a\tb"`},
		{"a\u202eb", `"a\u202eb"`},
		{"a\u200fb", `"a\u200fb"`},
		{"a\u009bb", `"a\u009bb"`},
		{"a\x9bb", `"a\x9bb"`},
		{"", ""},
	} {
		if got := terminalText(tc.in); got != tc.want {
			t.Errorf("terminalText(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// hostileText is what a component outside this machine could hand a renderer:
// an OSC 52 clipboard write, an erase-line, a carriage return, a raw C1 CSI
// and a bidi override.
const hostileText = "x\x1b]52;c;ZXZpbA==\x07\x1b[2K\r\x9b\u202e"

// Review finding PRIV-1, the audit. Every human renderer this change added
// that prints a string from outside this machine — the monitor's picture,
// the keyholder's state, FatLine's status, the keyholder's refusals as a
// keeper reports them — puts it through terminalText. --json carries each
// as it came.
func TestRemoteTextIsQuotedInHumanReports(t *testing.T) {
	render := func(r interface{ Human(io.Writer) error }) string {
		t.Helper()
		var b bytes.Buffer
		if err := r.Human(&b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	t.Run("usage: application, monitor replica", func(t *testing.T) {
		out := render(usageResult{Instance: "p", Hours: 1, Network: []shrike.AppStat{{App: hostileText, Denies: 1}},
			NetworkReplica: hostileText, Replicas: 2, TunnelSeparated: true})
		onlyPrintable(t, "usage", out)
		if !strings.Contains(out, `\x1b]52`) {
			t.Errorf("the application's name is not shown, quoted:\n%s", out)
		}
	})
	t.Run("usage: why the network was not read", func(t *testing.T) {
		onlyPrintable(t, "usage", render(usageResult{Instance: "p", Hours: 1, NetworkError: "the monitor answered " + hostileText}))
	})
	t.Run("storage state: scopes and a shared node", func(t *testing.T) {
		states := []replicaState{
			{Ordinal: 0, Phase: "unsealed", Generation: 1, Scopes: []string{hostileText}, Node: hostileText},
			{Ordinal: 1, Phase: "unsealed", Generation: 1, Scopes: []string{"app-demo-alpha"}, Node: hostileText},
		}
		r := stateResult{Instance: "p", Replicas: states, RelayNode: hostileText}
		r.Colocated, r.PlacementUnknown = sharedNodes(states)
		if len(r.Colocated) != 1 {
			t.Fatalf("guard: %d colocation group(s); want one", len(r.Colocated))
		}
		out := render(r)
		onlyPrintable(t, "storage state", out)
		if !strings.Contains(out, "run on one node (\"x") || !strings.Contains(out, "drops the tunnel") {
			t.Errorf("the shared node is not named, quoted, or the relay on it is not said:\n%s", out)
		}
	})
	t.Run("connect: the relaying node and the allowlist", func(t *testing.T) {
		onlyPrintable(t, "connect", render(connectResult{Name: "p", Connected: true, Node: hostileText, Allowlist: []string{hostileText}}))
	})
	t.Run("run: the deployed applications", func(t *testing.T) {
		onlyPrintable(t, "run", render(runResult{Instance: "p", Deployment: "demo", Namespace: "demo", Metered: true,
			Apps: []runApp{{Name: hostileText, Image: "img", External: []parser.External{{Host: hostileText, Reason: hostileText}}}}}))
	})
	t.Run("keeper: what each replica got", func(t *testing.T) {
		var b bytes.Buffer
		env := &Env{Err: &b, Verbose: true}
		cfg := keeper.Config{Instance: "prod", Generation: 1}
		keeperReport(env, cfg, keeper.Decision{Action: keeper.ActionStale, FleetWide: true}, keyholder.State{Phase: hostileText})
		keeperReport(env, cfg, keeper.Decision{Action: keeper.ActionHold, Reason: "sealed by the operator: " + hostileText}, keyholder.State{})
		keeperReport(env, cfg, keeper.Decision{Action: keeper.ActionNone, Reason: hostileText}, keyholder.State{})
		keeperReport(env, cfg, keeper.Decision{Action: keeper.ActionReseed}, keyholder.State{Boot: "\x1b[2K\x9b"})
		if n := strings.Count(b.String(), "\n"); n != 4 {
			t.Errorf("guard: %d line(s) reported; want 4:\n%s", n, b.String())
		}
		onlyPrintable(t, "keeper run", b.String())
	})
	t.Run("keeper: the fleet's verdict on this device", func(t *testing.T) {
		env, dir, store, cfg := installedKeeper(t)
		var b bytes.Buffer
		env.Err = &b
		fleet := &fakeStateKeyholder{phase: "restart-sealed"}
		served := heldKeys(liveKeyring(t, dir, "prod"))
		served[hostileText] = []string{"00000000000000aa"}
		fleet.replica(1).phase, fleet.replica(1).generation, fleet.replica(1).keys = "unsealed", 3, served
		if _, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store)); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), "this device: stale-bundle") || !strings.Contains(b.String(), `\x1b]52`) {
			t.Fatalf("guard: the fleet's verdict naming the replica's scope was not reported:\n%s", b.String())
		}
		onlyPrintable(t, "keeper run", b.String())
	})
}
