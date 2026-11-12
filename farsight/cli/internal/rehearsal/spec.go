package rehearsal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The scenarios: what the instance shows on the next Refresh (D8). The fake
// tools, Shrike's status handler and the keyholders read the scenario from
// rehearsal.json on every call, so a switch needs no restart.
const (
	ScenarioHealthy          = "healthy"
	ScenarioSealed           = "sealed"
	ScenarioStaleCheckpoint  = "stale-checkpoint"
	ScenarioCostReached      = "cost-reached"
	ScenarioDenied           = "denied"
	ScenarioSignedOut        = "signed-out"
	ScenarioIdentityMismatch = "identity-mismatch"
	ScenarioSlowCluster      = "slow-cluster"
)

var scenarios = []string{
	ScenarioHealthy, ScenarioSealed, ScenarioStaleCheckpoint, ScenarioCostReached,
	ScenarioDenied, ScenarioSignedOut, ScenarioIdentityMismatch, ScenarioSlowCluster,
}

// Scenarios is every scenario name, in the order the runbook walks them.
func Scenarios() []string { return slices.Clone(scenarios) }

// ValidScenario reports whether name is one of Scenarios.
func ValidScenario(name string) bool { return slices.Contains(scenarios, name) }

// specFile is the rehearsal's own record, at the top of its directory.
const specFile = "rehearsal.json"

// defaultSlowSeconds is how long the fake kubectl sleeps in slow-cluster:
// longer than world's 20-second kubectl read deadline.
const defaultSlowSeconds = 25

// period is how long a rehearsal's ledger runs. Its period starts five days
// before the rehearsal did, so a rehearsal lives for 25 days.
const (
	periodLead   = 5 * 24 * time.Hour
	periodLength = 30 * 24 * time.Hour
)

// errExpired is what every read says once the ledger's period has ended.
const errExpired = "this rehearsal is older than its 30-day period; start a new one"

// Spec is rehearsal.json: everything the fake tools, the keyholders and
// Shrike's status handler need, read again on every call.
type Spec struct {
	Instance string    `json:"instance"`
	Account  string    `json:"account"`
	Project  string    `json:"project"`
	Scenario string    `json:"scenario"`
	Started  time.Time `json:"started"`
	// Dirs are the rehearsal's own directories, every one resolved through
	// its symlinks when it was made.
	Dirs Dirs `json:"dirs"`
	// Images are FarCast's own components' digest-pinned references, the
	// ones metadata.yaml records and the cluster answers run.
	Images map[string]string `json:"images"`
	// SlowSeconds is how long kubectl sleeps in slow-cluster.
	SlowSeconds float64 `json:"slow_seconds"`
}

// Dirs are the directories a rehearsal is made of.
type Dirs struct {
	Root    string `json:"root"`
	Config  string `json:"config"`
	GCloud  string `json:"gcloud"`
	KubeBin string `json:"kube_bin"`
	SDKBin  string `json:"sdk_bin"`
}

// dirsUnder is the layout D3 fixes, under an already resolved root.
func dirsUnder(root string) Dirs {
	return Dirs{
		Root:    root,
		Config:  filepath.Join(root, "config"),
		GCloud:  filepath.Join(root, "gcloud"),
		KubeBin: filepath.Join(root, "kube", "bin"),
		SDKBin:  filepath.Join(root, "sdk", "bin"),
	}
}

// LoadSpec reads dir's rehearsal.json and checks it is one this build wrote.
func LoadSpec(dir string) (Spec, error) {
	data, err := os.ReadFile(filepath.Join(dir, specFile))
	if err != nil {
		return Spec{}, err
	}
	var s Spec
	if err := json.Unmarshal(data, &s); err != nil {
		return Spec{}, fmt.Errorf("%s could not be read: %w", specFile, err)
	}
	if err := s.validate(); err != nil {
		return Spec{}, fmt.Errorf("%s: %w", specFile, err)
	}
	return s, nil
}

func (s Spec) validate() error {
	if err := validInstance(s.Instance); err != nil {
		return err
	}
	if !ValidScenario(s.Scenario) {
		return fmt.Errorf("unknown scenario %q", s.Scenario)
	}
	if err := validINIValue("account", s.Account); err != nil {
		return err
	}
	if err := validINIValue("project", s.Project); err != nil {
		return err
	}
	if s.Started.IsZero() {
		return errors.New("no start time")
	}
	if s.Dirs != dirsUnder(s.Dirs.Root) || !filepath.IsAbs(s.Dirs.Root) {
		return errors.New("its directories are not the rehearsal's own layout")
	}
	if s.SlowSeconds < 0 || s.SlowSeconds > 600 {
		return fmt.Errorf("slow_seconds %v is out of range", s.SlowSeconds)
	}
	return nil
}

// periodStart is UTC midnight five days before the rehearsal started: the
// ledger is anchored to the rehearsal, never to the calendar, so a window it
// confirms is always closed, inside the period and before the start.
func (s Spec) periodStart() time.Time {
	t := s.Started.UTC().Add(-periodLead)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func (s Spec) periodEnd() time.Time { return s.periodStart().Add(periodLength) }

// expired reports whether now is past the ledger's period.
func (s Spec) expired(now time.Time) bool { return !now.Before(s.periodEnd()) }

// writeSpec replaces dir's rehearsal.json through a temporary file and a
// rename, so a fake tool reading it mid-switch sees the old or the new one.
func writeSpec(dir string, s Spec) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, specFile), append(data, '\n'))
}

// writeAtomic writes data to path (0600) through a temporary file in the same
// directory and a rename.
func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op once the rename succeeds
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SetScenario switches what a rehearsal's instance shows, from its next read.
// identity-mismatch also moves the rehearsal's gcloud configuration to
// another project, and every other scenario moves it back.
func SetScenario(dir, name string) error {
	if !ValidScenario(name) {
		return fmt.Errorf("unknown scenario %q; the scenarios are %s", name, strings.Join(scenarios, ", "))
	}
	root, err := resolvePath(dir)
	if err != nil {
		return err
	}
	if err := guard(root, ""); err != nil {
		return err
	}
	s, err := LoadSpec(root)
	if err != nil {
		return fmt.Errorf("%s holds no rehearsal: %w", dir, err)
	}
	if s.Dirs.Root != root {
		return fmt.Errorf("%s was made at %s; a rehearsal does not move", dir, s.Dirs.Root)
	}
	if err := writeGCloudConfig(s, name); err != nil {
		return fmt.Errorf("write the rehearsal's gcloud configuration: %w", err)
	}
	s.Scenario = name
	return writeSpec(root, s)
}

// The instance name rule 'farcast install' applies (validateInstanceName).
func validInstance(name string) error {
	if name == "" || len(name) > 32 || name[0] < 'a' || name[0] > 'z' || name[len(name)-1] == '-' {
		return fmt.Errorf("instance name %q is not one 'farcast install' would create", name)
	}
	for i := range len(name) {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return fmt.Errorf("instance name %q is not one 'farcast install' would create", name)
		}
	}
	return nil
}

// validINIValue refuses a value that would add a line or a section to the
// gcloud configuration file it is written into.
func validINIValue(what, v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("no %s", what)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f || r == '[' || r == ']' || r == '=' {
			return fmt.Errorf("the %s %q holds a character a gcloud configuration cannot carry", what, v)
		}
	}
	return nil
}
