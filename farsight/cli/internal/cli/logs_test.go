package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

func TestLogsFindsTheAppWithoutBeingToldTheNamespace(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43", "my-platform")
	env, out := testEnv(dir, output.ModeHuman)

	f := &fakeReader{
		deployments: map[string][]cluster.Workload{"my-platform": {appDeployment("my-platform", "api", 1, 1, "app")}},
		logsBody:    "hello from the app\n",
	}
	c := &logsCommand{lines: 200}
	c.newCluster = func(string) logReader { return f }
	if err := c.Run(context.Background(), env, []string{"p43", "api"}); err != nil {
		t.Fatal(err)
	}
	if f.logged != "my-platform deployment/api" {
		t.Errorf("read %q, want the deployment in the namespace it was found in", f.logged)
	}
	// The application's own bytes, not wrapped in this CLI's envelope.
	if out.String() != "hello from the app\n" {
		t.Errorf("logs were reformatted: %q", out.String())
	}
}

func TestLogsRefusesToGuessBetweenTwoAppsWithTheSameName(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43", "one", "two")
	env, _ := testEnv(dir, output.ModeHuman)

	f := &fakeReader{deployments: map[string][]cluster.Workload{
		"one": {appDeployment("one", "api", 1, 1, "app")},
		"two": {appDeployment("two", "api", 1, 1, "app")},
	}}
	c := &logsCommand{lines: 200}
	c.newCluster = func(string) logReader { return f }
	err := c.Run(context.Background(), env, []string{"p43", "api"})
	if err == nil {
		t.Fatal("logs picked one of two identically named applications")
	}
	if !strings.Contains(err.Error(), "--namespace") {
		t.Errorf("the error does not say how to disambiguate: %v", err)
	}
	if f.logged != "" {
		t.Errorf("it read %q anyway", f.logged)
	}
}

func TestLogsPassesTailFollowAndPrevious(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43", "my-platform")
	env, _ := testEnv(dir, output.ModeHuman)

	f := &fakeReader{deployments: map[string][]cluster.Workload{
		"my-platform": {appDeployment("my-platform", "api", 1, 1, "app")},
	}}
	c := &logsCommand{lines: 25, follow: true, previous: true}
	c.newCluster = func(string) logReader { return f }
	if err := c.Run(context.Background(), env, []string{"p43", "api"}); err != nil {
		t.Fatal(err)
	}
	want := []any{25, true, true}
	for i := range want {
		if f.logArgs[i] != want[i] {
			t.Errorf("log args = %v, want %v", f.logArgs, want)
			break
		}
	}
}

// "deployment/datasphered" names nothing: the key holder is a StatefulSet, so
// the log target has to be built from the kind that was actually found.
func TestLogsTargetsTheKindItFound(t *testing.T) {
	for kind, want := range map[string]string{
		"Deployment":  "deployment/thing",
		"StatefulSet": "statefulset/thing",
	} {
		t.Run(kind, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			meteringInstance(t, dir, "p43", "apps")
			env, _ := testEnv(dir, output.ModeHuman)

			f := &fakeReader{deployments: map[string][]cluster.Workload{
				"apps": {workloadOf(kind, "apps", "thing", 1, 1, "app")},
			}}
			c := &logsCommand{lines: 10}
			c.newCluster = func(string) logReader { return f }
			if err := c.Run(context.Background(), env, []string{"p43", "thing"}); err != nil {
				t.Fatal(err)
			}
			if f.logged != "apps "+want {
				t.Errorf("read %q, want %q", f.logged, "apps "+want)
			}
		})
	}
}

// Review finding R-3. The usage text says the cluster is CONFIGURED not to
// send logs to the provider's logging, which is the provider's read-back, and
// that the next walk checks it — never that the provider does not receive
// them, which nothing has observed yet (ADR 0019).
func TestLogsUsageDoesNotPresentTheReadBackAsObserved(t *testing.T) {
	u := strings.Join(strings.Fields((&logsCommand{}).Usage()), " ")
	if strings.Contains(u, "does not send them") {
		t.Errorf("usage states the provider's read-back as observed behaviour:\n%s", u)
	}
	for _, want := range []string{"configured not to send them to the provider's logging", "the next walk checks"} {
		if !strings.Contains(u, want) {
			t.Errorf("usage omits %q:\n%s", want, u)
		}
	}
}
