package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
)

type fakeReader struct {
	deployments map[string][]cluster.Workload
	errs        map[string]error

	configMaps map[string]string
	cmMissing  bool

	logged   string
	logArgs  []any
	logsBody string
}

func (f *fakeReader) Workloads(_ context.Context, ns string) ([]cluster.Workload, error) {
	if err := f.errs[ns]; err != nil {
		return nil, err
	}
	return f.deployments[ns], nil
}

func (f *fakeReader) ConfigMapValue(_ context.Context, ns, name, key string) (string, bool, error) {
	if f.cmMissing {
		return "", false, nil
	}
	v, ok := f.configMaps[ns+"/"+name+"/"+key]
	if !ok {
		return "", true, errors.New("no such key")
	}
	return v, true, nil
}

func (f *fakeReader) Logs(_ context.Context, out io.Writer, ns, target string, lines int, follow, previous bool) error {
	f.logged = ns + " " + target
	f.logArgs = []any{lines, follow, previous}
	_, err := io.WriteString(out, f.logsBody)
	return err
}

func appDeployment(ns, name string, desired, ready int, tier string) cluster.Workload {
	return workloadOf("Deployment", ns, name, desired, ready, tier)
}

func workloadOf(kind, ns, name string, desired, ready int, tier string) cluster.Workload {
	return cluster.Workload{
		Kind: kind, Namespace: ns, Name: name, Desired: desired, Ready: ready,
		Images:    []string{"reg.example/app/" + name + "@sha256:" + strings.Repeat("a", 64)},
		Labels:    map[string]string{"farcast.sofmon.com/tier": tier},
		CreatedAt: time.Now().Add(-3 * time.Hour),
	}
}

func meteringInstance(t *testing.T, dir config.Dir, name string, namespaces ...string) *config.InstanceMetadata {
	t.Helper()
	meta := buildableInstance(t, dir, name)
	meta.Kernel = &config.Kernel{Deployed: true, Namespaces: append([]string{tcdeploy.DefaultNamespace}, namespaces...)}
	meta.CostLimit = config.CostLimit{Amount: 100, Currency: "USD", Period: "monthly"}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

func TestPsListsApplicationsAndHidesTheInstanceMachinery(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43", "my-platform")
	env, out := testEnv(dir, output.ModeHuman)

	f := &fakeReader{deployments: map[string][]cluster.Workload{
		"my-platform":             {appDeployment("my-platform", "api", 1, 1, "app"), appDeployment("my-platform", "web", 2, 2, "app")},
		tcdeploy.DefaultNamespace: {appDeployment(tcdeploy.DefaultNamespace, "fatline", 2, 2, "system")},
	}}
	c := &psCommand{}
	c.newCluster = func(string) lister { return f }
	if err := c.Run(context.Background(), env, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	shown := out.String()
	for _, want := range []string{"api", "web", "1/1", "2/2"} {
		if !strings.Contains(shown, want) {
			t.Errorf("ps does not show %q:\n%s", want, shown)
		}
	}
	if strings.Contains(shown, "fatline") {
		t.Errorf("ps shows instance machinery without --all:\n%s", shown)
	}

	// --all includes it.
	env2, out2 := testEnv(dir, output.ModeHuman)
	c2 := &psCommand{all: true}
	c2.newCluster = func(string) lister { return f }
	if err := c2.Run(context.Background(), env2, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2.String(), "fatline") {
		t.Errorf("--all does not show instance machinery:\n%s", out2.String())
	}
}

// A stopped application is what a protective shutdown leaves behind, and it
// looks exactly like a broken one unless the listing says which it is.
func TestPsExplainsZeroReplicas(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43", "my-platform")
	env, out := testEnv(dir, output.ModeHuman)

	f := &fakeReader{deployments: map[string][]cluster.Workload{
		"my-platform": {appDeployment("my-platform", "api", 0, 0, "app")},
	}}
	c := &psCommand{}
	c.newCluster = func(string) lister { return f }
	if err := c.Run(context.Background(), env, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "0/0") {
		t.Errorf("a stopped application is not shown as stopped:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "protective shutdown") {
		t.Errorf("nothing explains why an application is at zero:\n%s", out.String())
	}
}

// One namespace refusing must not hide the rest — and the listing must say it
// is partial, because the namespace it could not read may hold the answer.
func TestPsSaysWhenItCouldNotSeeEverything(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43", "my-platform", "other")
	env, out := testEnv(dir, output.ModeHuman)

	f := &fakeReader{
		deployments: map[string][]cluster.Workload{"my-platform": {appDeployment("my-platform", "api", 1, 1, "app")}},
		errs:        map[string]error{"other": errors.New("forbidden")},
	}
	c := &psCommand{}
	c.newCluster = func(string) lister { return f }
	if err := c.Run(context.Background(), env, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	shown := out.String()
	if !strings.Contains(shown, "api") {
		t.Errorf("one unreadable namespace hid the readable ones:\n%s", shown)
	}
	if !strings.Contains(shown, "partial") {
		t.Errorf("a partial listing does not say so:\n%s", shown)
	}
	// And names which namespace, with the cluster's own reason — "partial"
	// alone tells the operator nothing they can act on.
	for _, want := range []string{"other", "forbidden"} {
		if !strings.Contains(shown, want) {
			t.Errorf("the listing does not say %q could not be read:\n%s", want, shown)
		}
	}
}

// FarCast runs both kinds, and the key holder is a StatefulSet. A listing that
// asked only for Deployments showed an instance with no storage in it at all.
//
// Found on the Phase 4.3 walk: `farcast ps --all` said it shows FarCast's own
// components and silently omitted one of them.
func TestPsShowsStatefulSetsAsWellAsDeployments(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43")
	env, out := testEnv(dir, output.ModeHuman)

	f := &fakeReader{deployments: map[string][]cluster.Workload{
		tcdeploy.DefaultNamespace: {
			workloadOf("Deployment", tcdeploy.DefaultNamespace, "fatline", 2, 2, "system"),
			workloadOf("StatefulSet", tcdeploy.DefaultNamespace, "datasphered", 2, 2, "system"),
		},
	}}
	c := &psCommand{all: true}
	c.newCluster = func(string) lister { return f }
	if err := c.Run(context.Background(), env, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "datasphered") {
		t.Errorf("the key holder is a StatefulSet and does not appear:\n%s", out.String())
	}
}
