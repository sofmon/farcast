package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// kernelMeterCommand adds a namespace to what the kernel meters.
//
// Two things have to happen for a namespace to be counted, and doing only one
// is worse than doing neither: the kernel needs a RoleBinding to list pods
// there, and it needs to be told the namespace exists. A namespace with a
// binding and no listing is invisible; one listed without a binding makes
// every tick report an unreachable namespace. This command does both, in one
// apply, so they cannot come apart.
type kernelMeterCommand struct {
	deployer fatlineDeployer
	remove   bool
}

func (*kernelMeterCommand) Name() string { return "meter" }
func (*kernelMeterCommand) Synopsis() string {
	return "Report or change the namespaces the kernel meters"
}

func (*kernelMeterCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast kernel meter <instance> [namespace...] [--remove]

With no namespace, report what the kernel is metering.

With namespaces, start metering them: each gets a RoleBinding letting the
kernel list pods and deployments there, and all of them are written to the
list the kernel re-reads on every reconcile. The kernel is NOT restarted —
it is a single replica with a Recreate strategy, so restarting it would stop
the cost meter at exactly the moment new spending starts.

Metering a namespace is what makes the applications in it count against the
instance's cost limit. A namespace nobody meters holds workloads that run,
bill, and are attributed to nothing.

--remove stops metering a namespace. The RoleBinding is left in place: this
command does not delete cluster objects, and the grant is harmless without
the listing. Removing the namespace removes it too.`)
}

func (c *kernelMeterCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.remove, "remove", false, "stop metering the named namespaces")
	c.deployer.setYesFlag(fs, "unused; accepted so scripts can pass it uniformly")
}

func (c *kernelMeterCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) == 0 {
		return usagef("kernel meter takes an instance, then any namespaces to add or remove")
	}
	name := args[0]
	c.deployer.ensureDefaults()

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if meta.Kernel == nil || !meta.Kernel.Deployed {
		return fmt.Errorf("instance %q has no kernel; run 'farcast kernel deploy %s' first", name, name)
	}

	requested := args[1:]
	if len(requested) == 0 {
		return env.Printer.Print(meterResult{
			Instance: name, Metered: append([]string(nil), meta.Kernel.Namespaces...),
		})
	}
	for _, ns := range requested {
		if err := validNamespace(ns); err != nil {
			return usagef("namespace %q: %v", ns, err)
		}
		if !c.remove && ns == tcdeploy.DefaultNamespace {
			// It is already in the workload's own bindings, and adding it
			// here would suggest it is optional.
			return usagef("%q is metered by the kernel's own deployment and does not need adding", ns)
		}
		if c.remove && ns == tcdeploy.DefaultNamespace {
			return usagef("refusing to stop metering %q; the instance's own components live there and would stop being counted",
				tcdeploy.DefaultNamespace)
		}
	}

	previous := append([]string(nil), meta.Kernel.Namespaces...)
	next, added := applyMeterChange(previous, requested, c.remove)
	if len(added) == 0 && !c.remove && sameSet(previous, next) {
		fprintf(env.Err, "Already metering %s.\n", strings.Join(requested, ", "))
		return env.Printer.Print(meterResult{Instance: name, Metered: next})
	}

	manifest, err := meterManifest(next, added)
	if err != nil {
		return err
	}

	// Recorded before the apply, like every other thing this CLI changes in a
	// cluster: a namespace the cluster meters and local state does not know
	// about is one the next change would silently drop.
	meta.Kernel.Namespaces = next
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return fmt.Errorf("record the metered namespaces before applying them: %w", err)
	}

	cl := c.deployer.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
	if err := cl.Apply(ctx, manifest); err != nil {
		meta.Kernel.Namespaces = previous
		if saveErr := env.ConfigDir.SaveInstanceMetadata(name, meta); saveErr != nil {
			return fmt.Errorf("apply the metered namespaces: %w (and local state could not be rolled back: %v)", err, saveErr)
		}
		return fmt.Errorf("apply the metered namespaces: %w", err)
	}

	return env.Printer.Print(meterResult{
		Instance: name, Metered: next, Added: added, Removed: removedFrom(previous, next),
		BindingsLeft: c.remove,
	})
}

// meterManifest is one apply stream: a RoleBinding for each newly metered
// namespace, then the list the kernel reads. They go together on purpose —
// applied separately, a failure between them leaves the kernel told to meter a
// namespace it has no permission to read.
func meterManifest(all, added []string) ([]byte, error) {
	var buf bytes.Buffer
	for _, ns := range added {
		b, err := tcdeploy.RenderNamespaceBinding(ns, "", "")
		if err != nil {
			return nil, err
		}
		buf.Write(b)
		buf.WriteString("---\n")
	}
	cm, err := kernel.RenderNamespacesConfigMap(tcdeploy.DefaultNamespace, kernel.DefaultNamespacesName, all)
	if err != nil {
		return nil, err
	}
	buf.Write(cm)
	return buf.Bytes(), nil
}

// applyMeterChange returns the new metered set and the namespaces that are
// newly added (and therefore need a binding).
func applyMeterChange(current, requested []string, remove bool) (next, added []string) {
	set := map[string]bool{}
	for _, ns := range current {
		set[ns] = true
	}
	for _, ns := range requested {
		if remove {
			delete(set, ns)
			continue
		}
		if !set[ns] {
			added = append(added, ns)
		}
		set[ns] = true
	}
	for ns := range set {
		next = append(next, ns)
	}
	sort.Strings(next)
	sort.Strings(added)
	return next, added
}

func removedFrom(before, after []string) []string {
	keep := map[string]bool{}
	for _, ns := range after {
		keep[ns] = true
	}
	var out []string
	for _, ns := range before {
		if !keep[ns] {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			return false
		}
	}
	return true
}

// validNamespace enforces the DNS-label shape Kubernetes requires, so a typo
// fails here rather than as a rejected apply.
func validNamespace(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	if len(s) > 63 {
		return fmt.Errorf("must be at most 63 characters")
	}
	if strings.HasPrefix(s, "kube-") {
		return fmt.Errorf("the managed namespaces are out of bounds (ADR 0003)")
	}
	for i := range len(s) {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
		case ch == '-' && i != 0 && i != len(s)-1:
		default:
			return fmt.Errorf("must be a DNS label: lowercase letters, digits and interior hyphens")
		}
	}
	return nil
}

type meterResult struct {
	Instance     string   `json:"instance"`
	Metered      []string `json:"metered"`
	Added        []string `json:"added,omitempty"`
	Removed      []string `json:"removed,omitempty"`
	BindingsLeft bool     `json:"-"`
}

func (r meterResult) Human(w io.Writer) error {
	if len(r.Metered) == 0 {
		fmt.Fprintf(w, "%q meters nothing, which means nothing is counted against its cost limit.\n", r.Instance)
		return nil
	}
	fmt.Fprintf(w, "%q meters:\n", r.Instance)
	for _, ns := range r.Metered {
		switch {
		case meteredContains(r.Added, ns):
			fmt.Fprintf(w, "  %-24s (added)\n", ns)
		default:
			fmt.Fprintf(w, "  %s\n", ns)
		}
	}
	for _, ns := range r.Removed {
		fmt.Fprintf(w, "  %-24s (no longer metered)\n", ns)
	}
	if len(r.Removed) > 0 && r.BindingsLeft {
		fmt.Fprintf(w, "\nThe kernel's RoleBinding is still present in %s. It grants nothing that is\n",
			strings.Join(r.Removed, ", "))
		fmt.Fprintf(w, "read any more, and deleting the namespace removes it.\n")
	}
	if len(r.Added) > 0 {
		fmt.Fprintf(w, "\nThe kernel picks these up on its next reconcile. It was not restarted.\n")
	}
	return nil
}

func meteredContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
