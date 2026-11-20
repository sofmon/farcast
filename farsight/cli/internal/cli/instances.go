package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// instancesCommand lists the instances this machine holds, from their local
// records alone.
type instancesCommand struct {
	// Seams: the clock and the build stamp.
	now   func() time.Time
	stamp func() buildStamp
}

func newInstancesCommand() *instancesCommand { return &instancesCommand{} }

func (*instancesCommand) Name() string     { return "instances" }
func (*instancesCommand) Synopsis() string { return "List the instances this machine holds" }

func (*instancesCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast instances

List every instance this machine holds, from each one's local record alone:
its status, region, cost limit, which of FarCast's components the record says
were deployed, how many keepers are enrolled, whether a reader identity is
recorded and how far it is set up ('farcast reader'). It opens no credential,
no kubeconfig, no CA key, no reader key and no keyring, and touches no network:
whether the reader's key is on this machine is told from the file's presence
alone.`)
}

// msgPinGCloudRetired is what 'instances pin-gcloud' says since ADR 0023 M2
// (design §7.4): a usage error, exit 2. Its --account flag went at M2.9a
// (design A37-11), so the flag parser refuses that form before Run.
const msgPinGCloudRetired = "pin-gcloud was retired by ADR 0023 M2: farcast reads each instance's cluster as its own read-only service account ('farcast reader init'), so there is no gcloud account to pin."

func (c *instancesCommand) SetFlags(*flag.FlagSet) {}

func (c *instancesCommand) ensureDefaults() {
	if c.now == nil {
		c.now = time.Now
	}
	if c.stamp == nil {
		c.stamp = currentStamp
	}
}

func (c *instancesCommand) Run(_ context.Context, env *Env, args []string) error {
	c.ensureDefaults()
	// The retired pin, with or without an instance, writes nothing and says
	// why.
	if len(args) > 0 && args[0] == "pin-gcloud" {
		return usagef("%s", msgPinGCloudRetired)
	}
	if len(args) > 0 {
		return usagef("instances takes no arguments; got %q", args[0])
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
	reader, err := readerStateOf(dir, name, meta)
	if err != nil {
		return instanceEntry{Name: name, Error: &sectionProblem{Kind: kindRecordUnreadable, Message: err.Error()}}
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
		Reader: reader,
	}
	for _, k := range meta.Keepers {
		if !k.Revoked {
			e.Keepers++
		}
	}
	return e
}

// The reader states 'instances' reports (design §8.2): how far an instance's
// read-only identity is set up, each step 'farcast reader' takes.
const (
	readerNone        = "none"         // no reader recorded: 'reader init'
	readerKeyMissing  = "key_missing"  // recorded, and reader.key is not on this machine
	readerNotUploaded = "not_uploaded" // no key id recorded: the Cloud Shell script, then 'reader record'
	readerNotGranted  = "not_granted"  // not verified read-only: 'reader grant'
	readerGranted     = "granted"      // the read commands read as it
)

// readerStateOf is how far an instance's reader is set up, from its record
// and whether reader.key exists, which is told by a stat and never by opening
// the file. A key file whose presence cannot be told is an error naming it
// relative to the config directory, as an unreadable record is.
func readerStateOf(dir config.Dir, name string, meta *config.InstanceMetadata) (string, error) {
	if meta.Reader == nil {
		return readerNone, nil
	}
	exists, err := dir.ReaderKeyExists(name)
	if err != nil {
		// The stat's own words, without the absolute path they carry.
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return "", fmt.Errorf("%s could not be checked: %v", filepath.Join("instances", name, "reader.key"), err)
	}
	switch {
	case !exists:
		return readerKeyMissing, nil
	case meta.Reader.KeyID == "":
		return readerNotUploaded, nil
	case meta.Reader.GrantedAt.IsZero():
		return readerNotGranted, nil
	}
	return readerGranted, nil
}

// instancesResult is 'farcast instances -o json', schema 2. Project ids,
// cluster names, endpoints, addresses and the reader's account itself are
// never in it.
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
	Reader       string           `json:"reader"`
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
		"NAME", "STATUS", "REGION", "LIMIT", "FATLINE", "KERNEL", "STORAGE", "KEEPERS", "READER")
	for _, e := range r.Instances {
		if e.Error != nil {
			fprintf(w, "%-18s %s: %s\n", terminalText(e.Name), e.Error.Kind, terminalText(e.Error.Message))
			continue
		}
		limit := fmt.Sprintf("%s %.0f/%s", e.CostLimit.Currency, float64(e.CostLimit.Cents)/100, e.CostLimit.Period)
		fprintf(w, "%-18s %-12s %-16s %-18s %-8s %-8s %-8s %-8d %s\n",
			terminalText(e.Name), terminalText(e.Status), terminalText(e.Region), terminalText(limit),
			yes(e.Components.FatLine), yes(e.Components.Kernel), yes(e.Components.Keyholder), e.Keepers,
			strings.ReplaceAll(e.Reader, "_", " "))
	}
	return nil
}
