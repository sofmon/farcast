// Package rehearsal is the Connected view's no-cost rehearsal (ADR 0021
// decision 9, amended 2026-11-12; Verification 5): an instance that lives on
// this machine and listens only on 127.0.0.1, for the FarCast app to read
// from Finder before it reads a live one.
//
// Start writes a state directory holding an instance record — a cluster
// endpoint on 127.0.0.1 and the CA it is trusted on, a reader whose key
// 'farcast reader grant' would have verified read-only, and a writer key no
// read may use — and runs a fake Kubernetes API server and token endpoint
// (kube/kubetest), a real FatLine, a real Shrike and two keyholder replicas
// behind it. The operator's own farcast then reads it exactly as it reads a
// cluster since ADR 0023 M2.4: the cluster in-process as the instance's
// reader, with a token minted at the rehearsal's token endpoint, and the
// network and seal through the FatLine tunnel.
//
// The rig never touches the operator's real gcloud, kube or farcast
// directories: Start refuses a directory that overlaps one. Its cluster
// answers only the reads 'farcast world' sends, and only to the reader: a
// writer's token is refused on every read, and every request, the token
// endpoint's included, is a line in calls.log.
//
// It is never part of farcast: a fake API server must never be in the
// product binary. It is built as ./bin/farcast-rehearsal.
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

	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/fatline"
	"github.com/sofmon/farcast/shrike"
)

// Options configure a rehearsal.
type Options struct {
	// Dir is the state directory: new, empty, or one a stopped harness left
	// (a restart). Empty makes a temporary one.
	Dir string
	// Instance is the instance's name; "" is "rehearsal".
	Instance string
	// Project is the instance's project, of Google's project-ID shape; "" is
	// rehearsal-project.
	Project string
	// Scenario is what the instance shows: "" is healthy on a new directory,
	// and the rehearsal's own on a restart.
	Scenario string
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
	DefaultProject  = "rehearsal-project"
)

// systemPath is the PATH the FarCast app gives farcast: the system's own
// directories, and nothing else (FarSightKit's ChildEnvironment).
const systemPath = "/usr/bin:/bin:/usr/sbin:/sbin"

// Rig is a running rehearsal.
type Rig struct {
	// Dir and ConfigDir are resolved through their symlinks.
	Dir, ConfigDir string
	// TunnelAddr is FatLine's tunnel, and ClusterAddr the cluster's API
	// server and token endpoint, each 127.0.0.1:<port>.
	TunnelAddr, ClusterAddr string

	spec     Spec
	farcast  string
	m        material
	log      io.Writer
	mon      *shrike.Monitor
	keeperID string // the keeper leaf's token

	shrikeAddr     string
	keyholderAddrs []string
	servers        []io.Closer
	// cluster is the rig's API server and token endpoint, held so a test can
	// see that it keeps no request log (A18-7).
	cluster *kubetest.Server

	// The tunnel runs under its own stop, so tunnel-down can stop it while
	// everything else serves, and start a new FatLine of this configuration
	// when it ends.
	fatlineConfig fatline.Config
	tunnelMu      sync.Mutex
	tunnelStop    func()        // stops the FatLine running now, and waits; nil when none was started
	tunnelDone    chan struct{} // closed once that FatLine's Serve returned
	tunnelClosed  bool          // set by Close: no FatLine starts again

	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

// prepared is what a rig needs to serve, from a new directory or a restart.
type prepared struct {
	spec                    Spec
	m                       material
	tunnelAddr, clusterAddr string
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
	if o.Scenario != "" {
		if err := CheckScenario(o.Scenario); err != nil {
			return nil, err
		}
	}
	if o.Project != "" {
		if err := validProject(o.Project); err != nil {
			return nil, err
		}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	farcast := ""
	if o.Farcast != "" {
		var err error
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
		var err error
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

	var p prepared
	restart := false
	switch state, err := inspectDir(root, o.Instance); {
	case err != nil:
		return nil, err
	case state == dirRehearsal:
		restart = true
		if p, err = prepareRestart(root, o); err != nil {
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
		if p, err = prepareNew(root, o); err != nil {
			clearNew(root, made)
			return nil, err
		}
	}

	r := &Rig{
		Dir: root, ConfigDir: p.spec.Dirs.Config, TunnelAddr: p.tunnelAddr, ClusterAddr: p.clusterAddr,
		spec: p.spec, farcast: farcast, m: p.m, log: o.Log,
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

type dirState int

const (
	dirMissing dirState = iota
	dirEmpty
	dirRehearsal
	dirOther
)

// inspectDir is what a directory holds: nothing, a rehearsal of this
// instance, or something else. A rehearsal made before ADR 0023 M2.4 is
// refused here, whatever its scenario: its cluster was fake tools, which this
// build no longer has.
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
	if madeBeforeM24(root) {
		return 0, errors.New(errMadeBeforeM24)
	}
	if s, err := LoadSpec(root); err == nil && s.Instance == instance {
		return dirRehearsal, nil
	}
	return dirOther, nil
}

// prepareNew writes a new rehearsal into an empty root.
func prepareNew(root string, o Options) (prepared, error) {
	now := o.Now().UTC().Truncate(time.Second)
	s := Spec{
		Instance: o.Instance, Project: o.Project, Scenario: o.Scenario,
		Started: now, Dirs: dirsUnder(root), SlowSeconds: defaultSlowSeconds,
		Images: map[string]string{},
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
		return prepared{}, err
	}
	clusterAddr, err := freeLoopback()
	if err != nil {
		return prepared{}, err
	}
	m, err := makeLayout(root, s, tunnelAddr, clusterAddr, now)
	if err != nil {
		return prepared{}, fmt.Errorf("write the rehearsal into %s: %w", root, err)
	}
	return prepared{spec: s, m: m, tunnelAddr: tunnelAddr, clusterAddr: clusterAddr}, nil
}

// prepareRestart checks a rehearsal a stopped harness left and reads what it
// needs to run again, refusing before it listens on anything.
func prepareRestart(root string, o Options) (prepared, error) {
	s, err := LoadSpec(root)
	if err != nil {
		return prepared{}, err
	}
	if s.Dirs != dirsUnder(root) {
		return prepared{}, fmt.Errorf("this rehearsal was made at %s; a rehearsal does not move, so start a new one in a new directory", s.Dirs.Root)
	}
	if o.Scenario != "" && o.Scenario != s.Scenario {
		return prepared{}, fmt.Errorf("this rehearsal shows %s, not %s; change the scenario with 'farcast-rehearsal scenario'", s.Scenario, o.Scenario)
	}
	if o.Project != "" && o.Project != s.Project {
		return prepared{}, errors.New("this rehearsal records another project; a restart keeps the one it was made with")
	}
	if s.expired(o.Now()) {
		return prepared{}, errors.New(errExpired)
	}
	m, tunnelAddr, clusterAddr, err := loadLayout(s)
	if err != nil {
		return prepared{}, err
	}
	// Exactly the recorded ports, so nothing the operator entered in
	// Settings, and no endpoint the record holds, changes; or refuse.
	for _, addr := range []string{tunnelAddr, clusterAddr} {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return prepared{}, fmt.Errorf("%s is in use: another harness may be running on this directory; stop it, or start a new rehearsal in a new directory", addr)
		}
		_ = l.Close()
	}
	return prepared{spec: s, m: m, tunnelAddr: tunnelAddr, clusterAddr: clusterAddr}, nil
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

// Close stops every listener, the traffic and the tunnel's watcher. It is
// idempotent, and it leaves the state directory on disk: a later Start on it
// restarts the rehearsal.
func (r *Rig) Close() error {
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		r.stopTunnel(true)
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

// Path is the PATH the FarCast app gives farcast: the system's directories
// alone. Nothing the rehearsal runs is found on it: farcast reads the cluster
// in-process.
func (r *Rig) Path() string { return systemPath }

// Listeners are every address the rig listens on: the tunnel's address
// (listed even while tunnel-down has it stopped), the cluster, Shrike's
// status route and the two keyholder replicas. All are on 127.0.0.1.
func (r *Rig) Listeners() []string {
	return append([]string{r.TunnelAddr, r.ClusterAddr, r.shrikeAddr}, r.keyholderAddrs...)
}

// readerWords is the instance's reader as the FarCast app's Settings Check
// says it: granted, unless reader-missing has moved its key aside.
func readerWords(scenario string) string {
	if scenario == ScenarioReaderMissing {
		return "reader key missing"
	}
	return "reader granted"
}

// SettingsText is what the operator enters in FarCast › Settings, and how to
// drive and stop the rehearsal. farcast is the text for the farcast row; ""
// is Options.Farcast, or a reminder to use one built from this commit. The
// rows are titled as the app titles its fields.
func (r *Rig) SettingsText(farcast string) string {
	if farcast == "" {
		farcast = r.farcast
	}
	if farcast == "" {
		farcast = "your ./bin/farcast, built from this harness's commit"
	}
	var b strings.Builder
	row := func(name, value string) { fmt.Fprintf(&b, "  %-32s%s\n", name, value) }
	b.WriteString("Enter these in FarCast › Settings (⌘,), press Check, then Confirm:\n")
	row("farcast", farcast)
	row("farcast configuration directory", r.ConfigDir)
	b.WriteString("\n")
	fmt.Fprintf(&b, "Instance: %s · %s · scenario %s\n", r.spec.Instance, readerWords(r.spec.Scenario), r.spec.Scenario)
	fmt.Fprintf(&b, "Every request the cluster and its token endpoint see, and every one a keyholder refuses, is logged to %s\n", filepath.Join(r.Dir, callsLog))
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
