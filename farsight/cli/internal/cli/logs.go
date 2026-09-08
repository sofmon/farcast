package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
)

// logReader is the slice of the cluster client following logs needs.
type logReader interface {
	lister
	Logs(ctx context.Context, out io.Writer, namespace, target string, lines int, follow, previous bool) error
}

type logsCommand struct {
	namespace string
	lines     int
	follow    bool
	previous  bool

	newCluster func(kubeconfigPath string) logReader
}

func (*logsCommand) Name() string     { return "logs" }
func (*logsCommand) Synopsis() string { return "Stream an application's logs" }

func (*logsCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast logs <instance> <app> [--follow] [--tail <n>] [--previous]
                    [--namespace <name>]

Read an application's logs. The app is found by name across every namespace the
instance's kernel meters, so the namespace only has to be given when two
deployments share a name.

--previous reads the container that died rather than the one running now, which
is the one worth reading after a crash loop.

Logs are the application's own output. FarCast does not collect, forward or
store them anywhere — this reads them from the cluster on demand and prints
them here.`)
}

func (c *logsCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.namespace, "namespace", "", "the namespace the app is in")
	fs.IntVar(&c.lines, "tail", 200, "how many lines of history to show")
	fs.BoolVar(&c.follow, "follow", false, "keep streaming until interrupted")
	fs.BoolVar(&c.follow, "f", false, "keep streaming until interrupted")
	fs.BoolVar(&c.previous, "previous", false, "read the previous container, after a crash")
	fs.BoolVar(&c.previous, "p", false, "read the previous container, after a crash")
}

func (c *logsCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = func(kc string) logReader { return cluster.New(kc) }
	}
}

func (c *logsCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 2 {
		return usagef("logs takes an instance and an application, e.g. 'farcast logs prod api'")
	}
	name, app := args[0], args[1]
	c.ensureDefaults()

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	cl := c.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))

	// The kind matters as much as the namespace: the key holder is a
	// StatefulSet, and "deployment/datasphered" names nothing.
	found, err := findApp(ctx, cl, (&psCommand{all: true}).namespacesOf(meta), app, c.namespace)
	if err != nil {
		return err
	}
	namespace, kind := found.Namespace, found.Kind

	// Logs go to stdout unformatted, whatever --output says: they are the
	// application's bytes, and wrapping them in this CLI's envelope would make
	// them something else.
	return cl.Logs(ctx, env.Out, namespace, strings.ToLower(kind)+"/"+app, c.lines, c.follow, c.previous)
}

// findApp locates a workload by name across the namespaces an instance meters,
// and refuses to guess when two of them match.
//
// It returns the workload rather than its namespace because the caller needs
// the kind too: FarCast runs Deployments and StatefulSets, and a log target
// built from the wrong one names nothing.
func findApp(ctx context.Context, cl lister, namespaces []string, app, only string) (cluster.Workload, error) {
	if only != "" {
		namespaces = []string{only}
	}
	var found []cluster.Workload
	var unreadable []string
	for _, ns := range namespaces {
		workloads, err := cl.Workloads(ctx, ns)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", ns, err))
			continue
		}
		for _, w := range workloads {
			if w.Name == app {
				found = append(found, w)
			}
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		if len(unreadable) > 0 {
			return cluster.Workload{}, fmt.Errorf("no application %q in %s, and %s could not be read (%s)",
				app, strings.Join(namespaces, ", "),
				plural(len(unreadable), "namespace", "namespaces"), strings.Join(unreadable, "; "))
		}
		return cluster.Workload{}, fmt.Errorf("no application %q in %s", app, strings.Join(namespaces, ", "))
	default:
		var where []string
		for _, w := range found {
			where = append(where, w.Namespace)
		}
		return cluster.Workload{}, fmt.Errorf("%q exists in %s; name one with --namespace", app, strings.Join(where, " and "))
	}
}
