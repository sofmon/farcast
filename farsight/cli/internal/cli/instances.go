package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// instancesCommand lists the instances this machine holds, from their local
// records alone, and pins the gcloud account each is read as.
type instancesCommand struct {
	account string

	// Seams: the clock, the build stamp and the environment gcloud's
	// configuration directory is resolved from.
	now     func() time.Time
	stamp   func() buildStamp
	environ func() []string
}

func newInstancesCommand() *instancesCommand { return &instancesCommand{} }

func (*instancesCommand) Name() string     { return "instances" }
func (*instancesCommand) Synopsis() string { return "List the instances this machine holds" }

func (*instancesCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast instances
       farcast instances pin-gcloud <instance> --account <email>

List every instance this machine holds, from each one's local record alone:
its status, region, cost limit, which of FarCast's components the record says
were deployed, how many keepers are enrolled, and whether a gcloud account is
pinned. It opens no credential, no kubeconfig, no CA key and no keyring, and
touches no network.

pin-gcloud records the gcloud account an instance's cluster is read as. 'farcast
world' then reads only under a gcloud configuration whose account is that one
and whose project is the instance's, and refuses otherwise — so a read never
runs as whichever configuration happens to be active. The pin is refused unless
such a configuration exists in gcloud's configuration directory
($CLOUDSDK_CONFIG, or ~/.config/gcloud). It is run from a terminal; the FarCast
app shows the pin for the operator to confirm and never writes it.`)
}

func (c *instancesCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.account, "account", "", "pin-gcloud: the gcloud account to read this instance as")
}

func (c *instancesCommand) ensureDefaults() {
	if c.now == nil {
		c.now = time.Now
	}
	if c.stamp == nil {
		c.stamp = currentStamp
	}
	if c.environ == nil {
		c.environ = os.Environ
	}
}

func (c *instancesCommand) Run(_ context.Context, env *Env, args []string) error {
	c.ensureDefaults()
	if len(args) > 0 && args[0] == "pin-gcloud" {
		return c.pin(env, args[1:])
	}
	if len(args) > 0 {
		return usagef("instances takes no arguments, or 'pin-gcloud <instance> --account <email>'; got %q", args[0])
	}
	if c.account != "" {
		return usagef("--account belongs to 'farcast instances pin-gcloud <instance> --account <email>'")
	}
	names, err := env.ConfigDir.ListInstances()
	if err != nil {
		return fmt.Errorf("list the instances on this machine: %w", err)
	}
	res := instancesResult{Schema: worldSchema, GeneratedAt: wireTime(c.now().UTC().Truncate(time.Second)), FarCast: c.stamp(),
		Instances: make([]instanceEntry, 0, len(names))}
	for _, name := range names {
		res.Instances = append(res.Instances, instanceEntryOf(env.ConfigDir, name))
	}
	return env.Printer.Print(res)
}

// instanceEntryOf is one instance as its record states it, or why the
// record could not be read.
func instanceEntryOf(dir config.Dir, name string) instanceEntry {
	meta, err := dir.LoadInstanceMetadata(name)
	if err != nil {
		return instanceEntry{Name: name, Error: &sectionProblem{Kind: kindRecordUnreadable, Message: recordError(name, err).Error()}}
	}
	e := instanceEntry{
		Name: name, Provider: meta.Provider, Region: meta.Region, Status: meta.Status,
		CostLimit: &costLimitEntry{
			Cents: cents(meta.CostLimit.Amount), Currency: meta.CostLimit.Currency, Period: meta.CostLimit.Period,
		},
		CloudLogging: cloudLoggingOf(meta.CloudLogging),
		Components: &componentsEntry{
			FatLine:   meta.FatLineDeployed,
			Kernel:    meta.Kernel != nil && meta.Kernel.Deployed,
			Keyholder: meta.Keyholder != nil && meta.Keyholder.Deployed,
		},
		GCloudPinned: strings.TrimSpace(meta.GCloudAccount) != "",
	}
	for _, k := range meta.Keepers {
		if !k.Revoked {
			e.Keepers++
		}
	}
	return e
}

// instancesResult is 'farcast instances -o json', schema 1. Project ids,
// cluster names, endpoints, addresses and the pinned account itself are never
// in it.
type instancesResult struct {
	Schema      int             `json:"schema"`
	GeneratedAt wireTime        `json:"generated_at"`
	FarCast     buildStamp      `json:"farcast"`
	Instances   []instanceEntry `json:"instances"`
}

type instanceEntry struct {
	Name         string           `json:"name"`
	Provider     string           `json:"provider,omitempty"`
	Region       string           `json:"region,omitempty"`
	Status       string           `json:"status,omitempty"`
	CostLimit    *costLimitEntry  `json:"cost_limit,omitempty"`
	CloudLogging string           `json:"cloud_logging,omitempty"`
	Components   *componentsEntry `json:"components,omitempty"`
	Keepers      int              `json:"keepers"`
	GCloudPinned bool             `json:"gcloud_pinned"`
	Error        *sectionProblem  `json:"error,omitempty"`
}

// MarshalJSON keeps an unreadable entry to its name and its error: the
// listing says nothing it did not read, and a zero is not a reading.
func (e instanceEntry) MarshalJSON() ([]byte, error) {
	type plain instanceEntry
	if e.Error != nil {
		return marshalJSON(struct {
			Name  string          `json:"name"`
			Error *sectionProblem `json:"error"`
		}{e.Name, e.Error})
	}
	return marshalJSON(plain(e))
}

type costLimitEntry struct {
	Cents    int64  `json:"cents"`
	Currency string `json:"currency"`
	Period   string `json:"period"`
}

// componentsEntry is what the local record says was deployed, not what is
// running: 'world' reads that.
type componentsEntry struct {
	FatLine   bool `json:"fatline"`
	Kernel    bool `json:"kernel"`
	Keyholder bool `json:"keyholder"`
}

func (r instancesResult) Human(w io.Writer) error {
	if len(r.Instances) == 0 {
		fprintln(w, "No instances on this machine. 'farcast install' provisions one.")
		return nil
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	fprintf(w, "%-18s %-12s %-16s %-18s %-8s %-8s %-8s %-8s %s\n",
		"NAME", "STATUS", "REGION", "LIMIT", "FATLINE", "KERNEL", "STORAGE", "KEEPERS", "GCLOUD")
	for _, e := range r.Instances {
		if e.Error != nil {
			fprintf(w, "%-18s %s: %s\n", terminalText(e.Name), e.Error.Kind, terminalText(e.Error.Message))
			continue
		}
		limit := fmt.Sprintf("%s %.0f/%s", e.CostLimit.Currency, float64(e.CostLimit.Cents)/100, e.CostLimit.Period)
		gcloud := "not pinned"
		if e.GCloudPinned {
			gcloud = "pinned"
		}
		fprintf(w, "%-18s %-12s %-16s %-18s %-8s %-8s %-8s %-8d %s\n",
			terminalText(e.Name), terminalText(e.Status), terminalText(e.Region), terminalText(limit),
			yes(e.Components.FatLine), yes(e.Components.Kernel), yes(e.Components.Keyholder), e.Keepers, gcloud)
	}
	return nil
}

// pin records the gcloud account an instance is read as.
//
// It refuses an account that no configuration in gcloud's directory has
// together with the instance's project: a pin must never name an identity
// that cannot read the instance, or 'world' would refuse every read and the
// operator would not know why.
func (c *instancesCommand) pin(env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("pin-gcloud takes one instance argument: farcast instances pin-gcloud <instance> --account <email>")
	}
	name := args[0]
	account := strings.TrimSpace(c.account)
	if account == "" || strings.ContainsAny(account, " \t\n") {
		return usagef("pin-gcloud needs --account <email>, the gcloud account to read %q as", name)
	}
	meta, err := loadRecord(env.ConfigDir, name)
	if err != nil {
		return err
	}
	if meta.Project == "" {
		return withKind(kindGCloudMismatch, fmt.Errorf(
			"instance %q records no cloud project, so no gcloud configuration can be checked against it; nothing was pinned", name))
	}
	dir, source, err := gcloudDirFrom(c.environ())
	if err != nil {
		return err
	}
	configs, err := readGCloudConfigs(dir, source)
	if err != nil {
		return err
	}
	match := matchingConfigs(configs, account, meta.Project)
	if len(match) == 0 {
		return withKind(kindGCloudMismatch, fmt.Errorf(
			"no gcloud configuration in %s has that account together with %q's project %q (%s); nothing was pinned. "+
				"Create one first: gcloud config configurations create <name>, then set its account and project",
			source, name, meta.Project, consideredText(configs, account)))
	}
	if _, err := env.ConfigDir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
		m.GCloudAccount = account
		m.UpdatedAt = time.Now().UTC()
		return nil
	}); err != nil {
		return fmt.Errorf("record the pinned gcloud account for %q: %w", name, err)
	}
	return env.Printer.Print(pinResult{Instance: name, GCloudPinned: true, Configuration: match[0].Name})
}

// pinResult says the pin landed and which configuration a read will use. It
// does not repeat the account: the operator typed it, and a result that
// travels further than the terminal has no need of it.
type pinResult struct {
	Instance      string `json:"instance"`
	GCloudPinned  bool   `json:"gcloud_pinned"`
	Configuration string `json:"configuration"`
}

func (r pinResult) Human(w io.Writer) error {
	fprintf(w, "Pinned %q to the account you gave. 'farcast world %s' reads through gcloud configuration %q.\n",
		r.Instance, r.Instance, r.Configuration)
	return nil
}
