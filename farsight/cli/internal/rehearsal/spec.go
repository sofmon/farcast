package rehearsal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The scenarios: what the instance shows on the next Refresh (D8). The
// cluster's handler, its token endpoint, its delay, Shrike's status handler,
// the keyholders and the tunnel's watcher read the scenario from
// rehearsal.json on every call, so a switch needs no restart.
const (
	ScenarioHealthy         = "healthy"
	ScenarioSealed          = "sealed"
	ScenarioStaleCheckpoint = "stale-checkpoint"
	ScenarioCostReached     = "cost-reached"
	ScenarioAtFloor         = "at-floor"
	ScenarioDenied          = "denied"
	ScenarioSlowCluster     = "slow-cluster"
	// ScenarioTokenRefused: the token endpoint refuses every assertion with
	// invalid_grant, so 'world' shows credential_refused.
	ScenarioTokenRefused = "token-refused"
	// ScenarioUnauthorized: every read answers 401, the retry after the
	// re-mint too.
	ScenarioUnauthorized = "unauthorized"
	// ScenarioForbidden: the kernel's checkpoint and the egress policy answer
	// 403, so spend and policy show forbidden and apps still read.
	ScenarioForbidden = "forbidden"
	// ScenarioReaderMissing: reader.key is moved aside to reader.key.away,
	// and back on any other scenario.
	ScenarioReaderMissing = "reader-missing"
	// ScenarioTunnelDown: FatLine's tunnel stops listening while the cluster
	// stays up, and listens again on any other scenario.
	ScenarioTunnelDown = "tunnel-down"
)

var scenarios = []string{
	ScenarioHealthy, ScenarioSealed, ScenarioStaleCheckpoint, ScenarioCostReached, ScenarioAtFloor,
	ScenarioDenied, ScenarioSlowCluster, ScenarioTokenRefused, ScenarioUnauthorized, ScenarioForbidden,
	ScenarioReaderMissing, ScenarioTunnelDown,
}

// retiredScenarios were the gcloud identity's scenarios, retired with the
// fake tools when the cluster moved into the harness (ADR 0023 M2.4).
var retiredScenarios = []string{"signed-out", "identity-mismatch"}

// Scenarios is every scenario name, in the order the runbook walks them.
func Scenarios() []string { return slices.Clone(scenarios) }

// RetiredScenarios are the scenario names that are no longer scenarios.
func RetiredScenarios() []string { return slices.Clone(retiredScenarios) }

// CheckScenario reports why name is not a scenario, nil when it is one. A
// retired name says what replaced it; any other says what the scenarios are.
// Every place that takes a scenario name asks it.
func CheckScenario(name string) error {
	switch {
	case slices.Contains(scenarios, name):
		return nil
	case slices.Contains(retiredScenarios, name):
		return fmt.Errorf("scenario %q was retired with ADR 0023 M2; use token-refused or forbidden", name)
	}
	return fmt.Errorf("unknown scenario %q; the scenarios are %s", name, strings.Join(scenarios, ", "))
}

// specFile is the rehearsal's own record, at the top of its directory.
const specFile = "rehearsal.json"

// defaultSlowSeconds is how long the cluster holds every answer in
// slow-cluster, a /token's included: longer than world's 20-second deadline
// for each cluster read.
const defaultSlowSeconds = 25

// period is how long a rehearsal's ledger runs. Its period starts five days
// before the rehearsal did, so a rehearsal lives for 25 days.
const (
	periodLead   = 5 * 24 * time.Hour
	periodLength = 30 * 24 * time.Hour
)

// errExpired is what every read says once the ledger's period has ended.
const errExpired = "this rehearsal is older than its 30-day period; start a new one"

// Spec is rehearsal.json: everything the cluster, the keyholders, Shrike's
// status handler and the tunnel's watcher need, read again on every call.
type Spec struct {
	Instance string    `json:"instance"`
	Project  string    `json:"project"`
	Scenario string    `json:"scenario"`
	Started  time.Time `json:"started"`
	// Dirs are the rehearsal's own directories, every one resolved through
	// its symlinks when it was made.
	Dirs Dirs `json:"dirs"`
	// Images are FarCast's own components' digest-pinned references, the
	// ones metadata.yaml records and the cluster answers run.
	Images map[string]string `json:"images"`
	// SlowSeconds is how long the cluster holds every answer in slow-cluster.
	SlowSeconds float64 `json:"slow_seconds"`
}

// Dirs are the directories a rehearsal is made of.
type Dirs struct {
	Root   string `json:"root"`
	Config string `json:"config"`
}

// dirsUnder is the layout D3 fixes, under an already resolved root.
func dirsUnder(root string) Dirs {
	return Dirs{Root: root, Config: filepath.Join(root, "config")}
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
	if err := CheckScenario(s.Scenario); err != nil {
		return err
	}
	if err := validProject(s.Project); err != nil {
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
// rename, so a handler reading it mid-switch sees the old or the new one.
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
// reader-missing also moves the instance's reader.key aside, and every other
// scenario moves it back; tunnel-down takes effect within a moment, when the
// harness's watcher next reads the scenario.
//
// A directory made before ADR 0023 M2.4 is refused, as Start refuses it: its
// harness, if one runs, reads a rehearsal.json this build no longer writes.
func SetScenario(dir, name string) error {
	if err := CheckScenario(name); err != nil {
		return err
	}
	root, err := resolvePath(dir)
	if err != nil {
		return err
	}
	if err := guard(root, ""); err != nil {
		return err
	}
	if madeBeforeM24(root) {
		return errors.New(errMadeBeforeM24)
	}
	s, err := LoadSpec(root)
	if err != nil {
		return fmt.Errorf("%s holds no rehearsal: %w", dir, err)
	}
	if s.Dirs.Root != root {
		return fmt.Errorf("%s was made at %s; a rehearsal does not move", dir, s.Dirs.Root)
	}
	if err := placeReaderKey(s, name); err != nil {
		return fmt.Errorf("move the rehearsal instance's reader key: %w", err)
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

// projectIDShape is Google's project-ID shape, the one farcast's reader
// checks (checkedReader): 6 to 30 characters, lowercase letters, digits and
// hyphens, starting with a letter and not ending with a hyphen. A rehearsal
// whose project failed it would show credential_missing on every read.
var projectIDShape = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

// validProject refuses a project farcast's reader would refuse.
func validProject(project string) error {
	if !projectIDShape.MatchString(project) {
		return fmt.Errorf("the project %q is not one Google issues (6 to 30 of a-z, 0-9 and -, starting with a letter)", project)
	}
	return nil
}
