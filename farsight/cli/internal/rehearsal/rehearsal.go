// Package rehearsal is the Connected view's no-cost rehearsal (ADR 0021
// decision 9, amended 2026-11-12; Verification 5): an instance that lives on
// this machine and listens only on 127.0.0.1, for the FarCast app to read
// from Finder before it reads a live one.
//
// Start writes a state directory holding an instance record, a gcloud
// configuration directory and three fake tools — kubectl,
// gke-gcloud-auth-plugin and gcloud, each a link to the harness binary — and
// runs a real FatLine, a real Shrike and two keyholder replicas behind it. The
// operator's own farcast then reads it exactly as it reads a cluster: kubectl
// by bare name through the auth plugin, the network and seal through the
// FatLine tunnel.
//
// The rig never touches the operator's real gcloud, kube or farcast
// directories: Start refuses a directory that overlaps one, and the fake
// plugin and gcloud refuse to run unless CLOUDSDK_CONFIG names the
// rehearsal's own. The fake kubectl answers only the reads 'farcast world'
// sends, and refuses every variable that should never reach it.
//
// It is never part of farcast: a fake kubectl must never be in the product
// binary. It is built as ./bin/farcast-rehearsal.
package rehearsal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sofmon/farcast/shrike"
)

// Options configure a rehearsal.
type Options struct {
	// Dir is the state directory: new, empty, or one a stopped harness left
	// (a restart). Empty makes a temporary one.
	Dir string
	// Instance is the instance's name; "" is "rehearsal".
	Instance string
	// Account is the pinned gcloud account; "" is operator@rehearsal.invalid.
	Account string
	// Project is the instance's project; "" is rehearsal-project.
	Project string
	// Scenario is what the instance shows: "" is healthy on a new directory,
	// and the rehearsal's own on a restart.
	Scenario string
	// Tools is the binary linked as kubectl, gke-gcloud-auth-plugin and
	// gcloud; "" is this process's own executable.
	Tools string
	// Farcast is the operator's farcast, shown in the settings text when
	// SettingsText is given none. It is never run by the library.
	Farcast string
	// Home is the home directory whose gcloud and kube directories the guard
	// protects; "" is the user's own. A test seam.
	Home string
	// Now is the clock for what a new rehearsal records; nil is time.Now.
	Now func() time.Time
	// Log receives the harness's own diagnostics; nil discards them.
	Log io.Writer
}

// Default names. Every one is a placeholder, so nothing a rehearsal shows
// names anything real.
const (
	DefaultInstance = "rehearsal"
	DefaultAccount  = "operator@rehearsal.invalid"
	DefaultProject  = "rehearsal-project"
)

// Rig is a running rehearsal.
type Rig struct {
	// Dir and the four below are resolved through their symlinks.
	Dir, ConfigDir, GCloudDir, KubeBin, SDKBin string
	// TunnelAddr is FatLine's tunnel, 127.0.0.1:<port>.
	TunnelAddr string

	spec     Spec
	farcast  string
	m        material
	log      io.Writer
	mon      *shrike.Monitor
	keeperID string // the keeper leaf's token

	shrikeAddr     string
	keyholderAddrs []string
	servers        []io.Closer

	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

// Start makes or restarts a rehearsal and runs it. It returns once every
// listener answers and the monitor holds the start-up traffic: an allowed
// egress row and the keeper's stream into storage.
func Start(ctx context.Context, o Options) (*Rig, error) {
	if o.Instance == "" {
		o.Instance = DefaultInstance
	}
	if err := validInstance(o.Instance); err != nil {
		return nil, err
	}
	if o.Scenario != "" && !ValidScenario(o.Scenario) {
		return nil, fmt.Errorf("unknown scenario %q; the scenarios are %s", o.Scenario, strings.Join(scenarios, ", "))
	}
	for what, v := range map[string]string{"account": o.Account, "project": o.Project} {
		if v != "" {
			if err := validINIValue(what, v); err != nil {
				return nil, err
			}
		}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	tools, err := resolveTools(o.Tools)
	if err != nil {
		return nil, err
	}
	farcast := ""
	if o.Farcast != "" {
		if farcast, err = resolvePath(o.Farcast); err != nil {
			return nil, err
		}
	}

	// The guard runs before anything is written, a temporary directory
	// included: its parent is checked first, then the directory made in it.
	dir, made := o.Dir, false
	if dir == "" {
		if err := guard(filepath.Join(os.TempDir(), "farcast-rehearsal-new"), o.Home); err != nil {
			return nil, err
		}
		if dir, err = os.MkdirTemp("", "farcast-rehearsal-"); err != nil {
			return nil, err
		}
		made = true
	}
	root, err := resolvePath(dir)
	if err == nil {
		err = guard(root, o.Home)
	}
	if err != nil {
		if made {
			_ = os.Remove(dir)
		}
		return nil, err
	}

	var spec Spec
	var m material
	var tunnelAddr string
	restart := false
	switch state, err := inspectDir(root, o.Instance); {
	case err != nil:
		return nil, err
	case state == dirRehearsal:
		restart = true
		if spec, m, tunnelAddr, err = prepareRestart(root, o, tools); err != nil {
			return nil, err
		}
	case state == dirOther:
		return nil, fmt.Errorf("%s is not empty and holds no rehearsal of instance %q; give a new or empty directory, or one a stopped harness left", dir, o.Instance)
	default:
		if state == dirMissing {
			if err := os.MkdirAll(root, 0o700); err != nil {
				return nil, err
			}
			made = true
		} else if err := os.Chmod(root, 0o700); err != nil {
			return nil, err
		}
		if spec, m, tunnelAddr, err = prepareNew(root, o, tools); err != nil {
			clearNew(root, made)
			return nil, err
		}
	}

	r := &Rig{
		Dir: root, ConfigDir: spec.Dirs.Config, GCloudDir: spec.Dirs.GCloud, KubeBin: spec.Dirs.KubeBin, SDKBin: spec.Dirs.SDKBin,
		TunnelAddr: tunnelAddr, spec: spec, farcast: farcast, m: m, log: o.Log,
	}
	if err := r.serve(ctx); err != nil {
		_ = r.Close()
		if !restart {
			clearNew(root, made)
		}
		return nil, err
	}
	return r, nil
}

// resolveTools is the binary the tool links point at, resolved, and checked
// to be an executable file.
func resolveTools(tools string) (string, error) {
	if tools == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("cannot find this program's own executable to link the fake tools to: %w", err)
		}
		tools = exe
	}
	abs, err := filepath.Abs(tools)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("the tools binary %s: %w", tools, err)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("the tools binary %s is not an executable file", tools)
	}
	return real, nil
}

type dirState int

const (
	dirMissing dirState = iota
	dirEmpty
	dirRehearsal
	dirOther
)

// inspectDir is what a directory holds: nothing, a rehearsal of this
// instance, or something else.
func inspectDir(root, instance string) (dirState, error) {
	info, err := os.Lstat(root)
	if isMissing(err) {
		return dirMissing, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("%s is not a directory", root)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return dirEmpty, nil
	}
	if s, err := LoadSpec(root); err == nil && s.Instance == instance {
		return dirRehearsal, nil
	}
	return dirOther, nil
}

// prepareNew writes a new rehearsal into an empty root.
func prepareNew(root string, o Options, tools string) (Spec, material, string, error) {
	now := o.Now().UTC().Truncate(time.Second)
	s := Spec{
		Instance: o.Instance, Account: o.Account, Project: o.Project, Scenario: o.Scenario,
		Started: now, Dirs: dirsUnder(root), SlowSeconds: defaultSlowSeconds,
		Images: map[string]string{},
	}
	if s.Account == "" {
		s.Account = DefaultAccount
	}
	if s.Project == "" {
		s.Project = DefaultProject
	}
	if s.Scenario == "" {
		s.Scenario = ScenarioHealthy
	}
	for _, name := range []string{nameFatLine, nameShrike, nameKernel, nameKeyholder} {
		s.Images[name] = imageRef(name)
	}
	tunnelAddr, err := freeLoopback()
	if err != nil {
		return Spec{}, material{}, "", err
	}
	m, err := makeLayout(root, s, tools, tunnelAddr, now)
	if err != nil {
		return Spec{}, material{}, "", fmt.Errorf("write the rehearsal into %s: %w", root, err)
	}
	return s, m, tunnelAddr, nil
}

// prepareRestart checks a rehearsal a stopped harness left and reads what it
// needs to run again, refusing before it listens on anything.
func prepareRestart(root string, o Options, tools string) (Spec, material, string, error) {
	s, err := LoadSpec(root)
	if err != nil {
		return Spec{}, material{}, "", err
	}
	if s.Dirs != dirsUnder(root) {
		return Spec{}, material{}, "", fmt.Errorf("this rehearsal was made at %s; a rehearsal does not move, so start a new one in a new directory", s.Dirs.Root)
	}
	if o.Scenario != "" && o.Scenario != s.Scenario {
		return Spec{}, material{}, "", fmt.Errorf("this rehearsal shows %s, not %s; change the scenario with 'farcast-rehearsal scenario'", s.Scenario, o.Scenario)
	}
	if o.Account != "" && !strings.EqualFold(o.Account, s.Account) {
		return Spec{}, material{}, "", errors.New("this rehearsal pins another account; a restart keeps the one it was made with")
	}
	if o.Project != "" && o.Project != s.Project {
		return Spec{}, material{}, "", errors.New("this rehearsal records another project; a restart keeps the one it was made with")
	}
	if s.expired(o.Now()) {
		return Spec{}, material{}, "", errors.New(errExpired)
	}
	m, tunnelAddr, err := loadLayout(s, tools)
	if err != nil {
		return Spec{}, material{}, "", err
	}
	// Exactly the recorded port, so nothing the operator entered in
	// Settings changes, or refuse.
	l, err := net.Listen("tcp", tunnelAddr)
	if err != nil {
		return Spec{}, material{}, "", fmt.Errorf("%s is in use: another harness may be running on this directory; stop it, or start a new rehearsal in a new directory", tunnelAddr)
	}
	_ = l.Close()
	return s, m, tunnelAddr, nil
}

// clearNew removes what a failed first Start wrote: root was empty or did not
// exist when it began.
func clearNew(root string, made bool) {
	if made {
		_ = os.RemoveAll(root)
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(root, e.Name()))
	}
}

// freeLoopback is a 127.0.0.1 address with a port nothing holds right now.
func freeLoopback() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := l.Addr().String()
	return addr, l.Close()
}

// Close stops every listener and the traffic. It is idempotent, and it leaves
// the state directory on disk: a later Start on it restarts the rehearsal.
func (r *Rig) Close() error {
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		var errs []error
		for _, s := range r.servers {
			if err := s.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		r.wg.Wait()
		r.closeErr = errors.Join(errs...)
	})
	return r.closeErr
}

// Path is the PATH the FarCast app builds for these settings: the tools'
// directories, kubectl's first, then the system's own.
func (r *Rig) Path() string {
	return strings.Join([]string{r.KubeBin, r.SDKBin, "/usr/bin", "/bin", "/usr/sbin", "/sbin"}, string(os.PathListSeparator))
}

// Listeners are every address the rig listens on: the tunnel, Shrike's status
// route and the two keyholder replicas. All are on 127.0.0.1.
func (r *Rig) Listeners() []string {
	return append([]string{r.TunnelAddr, r.shrikeAddr}, r.keyholderAddrs...)
}

// SettingsText is what the operator enters in FarCast › Settings, and how to
// drive and stop the rehearsal. farcast is the text for the farcast row; ""
// is Options.Farcast, or a reminder to use one built from this commit.
func (r *Rig) SettingsText(farcast string) string {
	if farcast == "" {
		farcast = r.farcast
	}
	if farcast == "" {
		farcast = "your ./bin/farcast, built from this harness's commit"
	}
	links := toolLinks(r.spec.Dirs)
	var b strings.Builder
	row := func(name, value string) { fmt.Fprintf(&b, "  %-32s%s\n", name, value) }
	b.WriteString("Enter these in FarCast › Settings (⌘,), press Check, then Confirm:\n")
	row("farcast", farcast)
	row("kubectl", links[toolKubectl])
	row("gke-gcloud-auth-plugin", links[toolPlugin])
	row("gcloud", links[toolGCloud])
	row("farcast configuration directory", r.ConfigDir)
	row("gcloud configuration directory", r.GCloudDir)
	b.WriteString("\n")
	fmt.Fprintf(&b, "Instance: %s · gcloud account pinned · scenario %s\n", r.spec.Instance, r.spec.Scenario)
	fmt.Fprintf(&b, "Every call the fake tools answer is logged to %s\n", filepath.Join(r.Dir, callsLog))
	fmt.Fprintf(&b, "Change what the instance shows:  farcast-rehearsal scenario --dir %s <%s>\n", ShellQuote(r.Dir), strings.Join(scenarios, "|"))
	fmt.Fprintf(&b, "Stop with Ctrl-C. Start again on this directory with --dir %s; remove it when done:  rm -rf %s\n",
		ShellQuote(r.Dir), ShellQuote(r.Dir))
	return b.String()
}

// ShellQuote is s as one shell word: as it is when it needs no quoting, and
// single-quoted otherwise.
func ShellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (r *Rig) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(r.log, "farcast-rehearsal: "+format+"\n", args...)
}
