package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/planck/translate"
	"github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/pricing"
	"github.com/sofmon/farcast/technocore/tier"
)

// lister is the slice of the cluster client a listing needs.
type lister interface {
	Deployments(ctx context.Context, namespace string) ([]cluster.Workload, error)
}

type psCommand struct {
	all       bool
	namespace string

	newCluster func(kubeconfigPath string) lister
}

func (*psCommand) Name() string     { return "ps" }
func (*psCommand) Synopsis() string { return "List running applications" }

func (*psCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast ps <instance> [--namespace <name>] [--all]

List what is running in an instance, across every namespace its kernel meters.

By default this shows applications. --all adds FarCast's own components, which
are the instance machinery a cost shutdown never stops.

Replicas at 0/n are stopped rather than broken: that is what a protective
shutdown leaves behind, and it is deliberate.`)
}

func (c *psCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.all, "all", false, "include FarCast's own components")
	fs.BoolVar(&c.all, "a", false, "include FarCast's own components")
	fs.StringVar(&c.namespace, "namespace", "", "list only this namespace")
}

func (c *psCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = func(kc string) lister { return cluster.New(kc) }
	}
}

func (c *psCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("ps takes one instance argument")
	}
	name := args[0]
	c.ensureDefaults()

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	namespaces := c.namespacesOf(meta)
	if len(namespaces) == 0 {
		return fmt.Errorf("instance %q meters no namespaces; 'farcast run %s <repo>' deploys one", name, name)
	}

	cl := c.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
	res := psResult{Instance: name, Currency: currencyOf(meta)}
	for _, ns := range namespaces {
		workloads, err := cl.Deployments(ctx, ns)
		if err != nil {
			// One namespace refusing must not hide the rest, for the same
			// reason the kernel's own meter tolerates it — but the report has
			// to say the picture is partial, because the namespace it could
			// not read may hold the thing the operator is looking for.
			res.Unreadable = append(res.Unreadable, fmt.Sprintf("%s: %v", ns, err))
			continue
		}
		for _, w := range workloads {
			t := tier.Of(w.Labels)
			if !c.all && ns == deploy.DefaultNamespace {
				continue
			}
			res.Apps = append(res.Apps, psApp{
				Namespace: w.Namespace, Name: w.Name,
				Ready: w.Ready, Desired: w.Desired,
				Tier: string(t), Image: strings.Join(w.Images, ", "),
				Age: since(w.CreatedAt),
			})
		}
	}
	sort.Slice(res.Apps, func(i, j int) bool {
		if res.Apps[i].Namespace != res.Apps[j].Namespace {
			return res.Apps[i].Namespace < res.Apps[j].Namespace
		}
		return res.Apps[i].Name < res.Apps[j].Name
	})
	res.MonthlyUSD = pricing.WorkloadMonthlyUSD(res.replicas(), translate.RequestCPUMilli, translate.RequestMemMiB)
	return env.Printer.Print(res)
}

// namespacesOf is what to look in: the kernel's metered list, which is exactly
// what a deployment adds itself to.
func (c *psCommand) namespacesOf(meta *config.InstanceMetadata) []string {
	if c.namespace != "" {
		return []string{c.namespace}
	}
	var out []string
	if meta.Kernel != nil {
		out = append(out, meta.Kernel.Namespaces...)
	}
	if !containsString(out, deploy.DefaultNamespace) {
		out = append(out, deploy.DefaultNamespace)
	}
	return out
}

func currencyOf(meta *config.InstanceMetadata) string {
	if meta.CostLimit.Currency != "" {
		return meta.CostLimit.Currency
	}
	return "USD"
}

// since is a compact age, for a listing where a column is worth more than a
// timestamp.
func since(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

type psApp struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Ready     int    `json:"ready"`
	Desired   int    `json:"desired"`
	Tier      string `json:"tier"`
	Image     string `json:"image"`
	Age       string `json:"age,omitempty"`
}

type psResult struct {
	Instance   string   `json:"instance"`
	Apps       []psApp  `json:"apps"`
	Unreadable []string `json:"unreadable,omitempty"`
	MonthlyUSD float64  `json:"monthly_usd"`
	Currency   string   `json:"currency"`
}

func (r psResult) replicas() int {
	var n int
	for _, a := range r.Apps {
		n += a.Desired
	}
	return n
}

func (r psResult) Human(w io.Writer) error {
	if len(r.Apps) == 0 {
		fmt.Fprintf(w, "Nothing is running in %q.\n", r.Instance)
	} else {
		fmt.Fprintf(w, "%-22s %-18s %-7s %-8s %s\n", "NAMESPACE", "NAME", "READY", "TIER", "AGE")
		for _, a := range r.Apps {
			ready := fmt.Sprintf("%d/%d", a.Ready, a.Desired)
			fmt.Fprintf(w, "%-22s %-18s %-7s %-8s %s\n", a.Namespace, a.Name, ready, a.Tier, a.Age)
		}
		var stopped int
		for _, a := range r.Apps {
			if a.Desired == 0 {
				stopped++
			}
		}
		if stopped > 0 {
			fmt.Fprintf(w, "\n%s at 0 replicas. A protective shutdown scales to zero and never back:\n",
				plural(stopped, "application is", "applications are"))
			fmt.Fprintf(w, "bringing an application back up is not the kernel's decision to make.\n")
		}
	}
	for _, u := range r.Unreadable {
		fmt.Fprintf(w, "\nCould not read %s\n", u)
	}
	if len(r.Unreadable) > 0 {
		fmt.Fprintf(w, "This listing is partial.\n")
	}
	return nil
}
