package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// Every remote read 'world' makes has its own deadline, and the whole command
// has a ceiling: a Refresh in the app must come back, whatever answered.
const (
	worldCeiling         = 60 * time.Second
	clusterReadTimeout   = 20 * time.Second
	tunnelConnectTimeout = 15 * time.Second
	sealReadTimeout      = 10 * time.Second
)

// worldTimeouts are the deadlines one read runs under. They are fields rather
// than the constants alone so a test can make a silent control plane cost
// milliseconds instead of the seconds it costs an operator.
type worldTimeouts struct {
	ceiling, cluster, connect, seal time.Duration
}

var defaultWorldTimeouts = worldTimeouts{
	ceiling: worldCeiling, cluster: clusterReadTimeout, connect: tunnelConnectTimeout, seal: sealReadTimeout,
}

// worldCluster is the slice of the cluster client the read needs: workloads,
// ConfigMaps, and the namespaces Planck labelled.
type worldCluster interface {
	Workloads(ctx context.Context, namespace string) ([]cluster.Workload, error)
	ConfigMapValue(ctx context.Context, namespace, name, key string) (string, bool, error)
	NamespacesLabelled(ctx context.Context, selector string) ([]string, error)
}

// worldTunnel is the one tunnel both tunnel reads ride: the monitor's picture
// and the keyholder's seal state. Two tunnels would double what the provider
// sees of a Refresh.
type worldTunnel interface {
	DialStream(ctx context.Context, route string, ordinal int) (net.Conn, error)
	Close() error
}

// sealReader asks one keyholder replica what it holds.
type sealReader interface {
	State(ctx context.Context, ordinal int) (keyholder.State, error)
}

type worldCommand struct {
	// Seams. The clock and the build stamp are inputs so a document is a
	// function of what was read; the environment says where home is, so a
	// message never names it; the rest reach the cluster and the tunnel.
	now     func() time.Time
	stamp   func() buildStamp
	environ func() []string
	// newCluster opens the cluster as the instance's reader (ADR 0023 M2.4).
	newCluster func(clusterRef) (worldCluster, error)
	// connect is the final dial, and only that: the identity it is handed
	// was loaded by the narrow loader, which never opens ca.key.
	connect func(ctx context.Context, endpoint string, id tunnel.ClientIdentity) (worldTunnel, error)
	newSeal func(d keyholder.Dialer, instance string, id config.DialIdentity) (sealReader, error)
	// timeouts are defaultWorldTimeouts unless a test sets them.
	timeouts worldTimeouts
}

func newWorldCommand() *worldCommand { return &worldCommand{} }

func (*worldCommand) Name() string { return "world" }
func (*worldCommand) Synopsis() string {
	return "Read one instance, as the map draws it"
}

func (*worldCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast world <instance>

Read one instance and report it as a single document: its components, its
applications grouped by namespace and labelled with the repository this
machine deployed there, every host they reach or declare, the operator's and
keepers' devices, its spending as the kernel reports it, and what needs
attention. It is the document the FarCast app's map draws, and it changes
nothing.

It reads in five sections — spend, apps, policy, network, seal — each on its
own. A section that cannot be read says why, with a kind, and the rest still
come back; what it would have told is marked unknown, never left out.

The cluster reads run in-process as the instance's own read-only service
account ('farcast reader'), and never without a reader that 'farcast reader
grant' has verified read-only: without one, the cluster sections say why and
nothing is sent. Each run mints a token for that account at
oauth2.googleapis.com, which tells Google the account and the time. Each read
then reaches the provider's API server, which may log who, when and from
where (ADR 0019).

The network and seal reads ride one FatLine tunnel. The provider sees its
source address, timing, sizes and the server name that names the instance —
and none of its content. Without a tunnel they are reported as not read; this
never runs 'connect'.

It never opens the CA key or the storage keyring.`)
}

func (c *worldCommand) SetFlags(*flag.FlagSet) {}

func (c *worldCommand) ensureDefaults() {
	if c.now == nil {
		c.now = time.Now
	}
	if c.stamp == nil {
		c.stamp = currentStamp
	}
	if c.environ == nil {
		c.environ = os.Environ
	}
	if c.newCluster == nil {
		c.newCluster = func(r clusterRef) (worldCluster, error) {
			// A refusal returns a nil cluster, never a nil *cluster.Client
			// inside a non-nil one.
			cl, err := openCluster(r)
			if err != nil {
				return nil, err
			}
			return cl, nil
		}
	}
	if c.connect == nil {
		c.connect = func(ctx context.Context, endpoint string, id tunnel.ClientIdentity) (worldTunnel, error) {
			return tunnel.Connect(ctx, endpoint, id)
		}
	}
	if c.newSeal == nil {
		c.newSeal = func(d keyholder.Dialer, instance string, id config.DialIdentity) (sealReader, error) {
			return keyholder.New(d, instance, id.CACertPEM, id.ClientCertPEM, id.ClientKeyPEM)
		}
	}
	if c.timeouts == (worldTimeouts{}) {
		c.timeouts = defaultWorldTimeouts
	}
}

func (c *worldCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("world takes one instance argument")
	}
	name := args[0]
	c.ensureDefaults()
	ctx, cancel := context.WithTimeout(ctx, c.timeouts.ceiling)
	defer cancel()

	meta, err := loadRecord(env.ConfigDir, name)
	if err != nil {
		return err
	}
	g := &gatherer{name: name, timeouts: c.timeouts, paths: localPaths(env.ConfigDir, c.environ())}
	// The cluster is read as the instance's reader, and only as it (ADR 0023
	// M2.4). A record that names another instance, or a reader that cannot
	// read, is no refusal of the whole command: the cluster sections carry
	// it, and the tunnel sections read on their own. openCluster builds
	// paths from the recorded name, so it must be the name given first.
	if err := recordNamed(meta, name); err != nil {
		g.refused(err)
	} else if cl, err := c.newCluster(clusterRef{Dir: env.ConfigDir, Meta: meta, Identity: kube.Reader, Warn: env.Err}); err != nil {
		g.refused(err)
	} else {
		g.cl = cl
	}

	// The cluster and the tunnel are read side by side. Neither waits on the
	// other, so a control plane that does not answer cannot spend the
	// tunnel's share of the ceiling, nor a carrier that does not answer the
	// cluster's: each section is read on its own.
	var (
		network networkInput
		seal    sealInput
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		network, seal = c.throughTunnel(ctx, env, name, meta)
	}()
	in := worldInputs{Stamp: c.stamp(), Name: name, Meta: meta}
	in.Apps = g.apps(ctx, meta)
	in.Spend = g.spend(ctx, name, meta)
	in.Policy = g.policy(ctx)
	wg.Wait()
	in.Network, in.Seal = network, seal
	in.Now = c.now()
	return env.Printer.Print(buildWorld(in))
}

// localPath is one of this machine's directories, matched only as a whole
// path component, and what a message says in its place.
type localPath struct {
	dir *regexp.Regexp
	say string
}

// localPaths are this machine's own directories: the config directory and
// the home directory. A failure to open the cluster can name a file under
// them — a key or a CA file that will not load — and a section message never
// carries a home directory's path.
func localPaths(dir config.Dir, environ []string) []localPath {
	type sub struct{ path, say string }
	var subs []sub
	add := func(path, say string) {
		if filepath.IsAbs(path) && len(filepath.Clean(path)) > 1 {
			subs = append(subs, sub{filepath.Clean(path), say})
		}
	}
	add(dir.Path(), "<config>")
	home := envValueOf(environ, "HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	add(home, "~")
	// Longest first, so a directory inside another is replaced whole.
	sort.SliceStable(subs, func(i, j int) bool { return len(subs[i].path) > len(subs[j].path) })
	out := make([]localPath, 0, len(subs))
	for _, s := range subs {
		// A whole component only: a home of /Users/op is not the start of
		// /Users/operator.
		out = append(out, localPath{dir: regexp.MustCompile(regexp.QuoteMeta(s.path) + `($|[^A-Za-z0-9._-])`), say: s.say})
	}
	return out
}

// envValueOf is the last value environ gives key, the one a process sees.
func envValueOf(environ []string, key string) string {
	v := ""
	for _, kv := range environ {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			v = val
		}
	}
	return v
}

// validInstanceName refuses a name that is not one directory under the
// instances directory: 'world' reads a record by name, and a name that walks
// out of it reads somebody else's file.
func validInstanceName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`) && filepath.Base(name) == name
}

// loadRecord reads an instance's record for a read command: not_found when
// this machine holds no such instance, record_unreadable when it holds one it
// cannot read. The message names the record relative to the config directory,
// so it is the same on every machine and leaks no home directory.
func loadRecord(dir config.Dir, name string) (*config.InstanceMetadata, error) {
	if !validInstanceName(name) {
		return nil, withKind(kindNotFound, fmt.Errorf("no instance named %q on this machine", name))
	}
	meta, err := dir.LoadInstanceMetadata(name)
	switch {
	case errors.Is(err, config.ErrNoInstanceRecord):
		return nil, withKind(kindNotFound, fmt.Errorf("no instance named %q on this machine; 'farcast instances' lists them", name))
	case err != nil:
		return nil, withKind(kindRecordUnreadable, recordError(name, err))
	}
	return meta, nil
}

// recordError is why an instance's record could not be read, naming the file
// relative to the config directory.
//
// A record that does not parse is told by the kind of fault and its line,
// never in the parser's words: those quote the lines around the fault, and a
// record holds the project, the endpoints and the reader's account. This
// message reaches the app and every document a read prints; the operator
// opens the file to see the rest.
func recordError(name string, err error) error {
	rel := filepath.Join("instances", name, "metadata.yaml")
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s could not be read: %v", rel, pe.Err)
	}
	if fault, ok := config.ParseFault(err); ok {
		return fmt.Errorf("%s could not be parsed: %s", rel, fault)
	}
	// Nothing else comes out of a record read today. Whatever does is not
	// quoted either: a message of unknown shape may carry the record.
	return fmt.Errorf("%s could not be parsed", rel)
}

// gatherer makes the cluster reads, each with its own deadline. A failure
// that every later read would meet the same way — no usable reader, its key
// refused, its token refused, a control plane that could not be reached or did
// not answer, the ceiling reached — is remembered, and the later reads report
// it without asking again.
type gatherer struct {
	// name is the instance's, for the sentence a refused read appends.
	name     string
	cl       worldCluster
	timeouts worldTimeouts
	// paths are this machine's directories and what a message says instead.
	paths []localPath
	fatal *sectionProblem
}

// worldFatal are the kinds every later cluster read would meet the same way
// (design §8.1, A18-9): the reader cannot be opened or authenticated, or the
// cluster cannot be reached. forbidden is not among them: RBAC is per object,
// so one refusal says nothing of the next read.
var worldFatal = map[string]bool{
	kindCredentialMissing: true, kindCredentialRefused: true, kindUnsafeEnvironment: true,
	kindEndpointRefused: true, kindUnauthorized: true, kindClusterUnreachable: true,
}

// refused is the cluster not opened at all: every cluster section carries
// why, and nothing is sent.
func (g *gatherer) refused(err error) {
	g.fatal = &sectionProblem{Kind: kindOfCluster(err), Message: g.scrub(err.Error())}
}

// kindOfCluster is clusterKind, or internal for a failure it does not know:
// a section error always names a kind.
func kindOfCluster(err error) string {
	if k := clusterKind(err); k != "" {
		return k
	}
	return kindInternal
}

// scrub is a cluster message with this machine's paths replaced.
func (g *gatherer) scrub(msg string) string {
	for _, p := range g.paths {
		msg = p.dir.ReplaceAllString(msg, strings.ReplaceAll(p.say, "$", "$$")+"${1}")
	}
	return msg
}

func (g *gatherer) problemOf(ctx context.Context, err error) *sectionProblem {
	// A 403 says what the reader needs (A18-10); every other failure reads
	// as it came.
	err = readerRefused(err, g.name)
	p := &sectionProblem{Kind: kindOfCluster(err), Message: g.scrub(err.Error())}
	switch {
	case worldFatal[p.Kind]:
		g.fatal = p
	case ctx.Err() != nil:
		g.fatal = &sectionProblem{Kind: kindTimeout, Message: "not asked: the read reached its ceiling of " + g.timeouts.ceiling.String()}
	case p.Kind == kindTimeout:
		// A control plane that let one read run out its deadline is not asked
		// again: every later read would wait out its own, and three of them
		// are the whole ceiling.
		g.fatal = &sectionProblem{Kind: kindTimeout, Message: fmt.Sprintf(
			"not asked: the cluster did not answer an earlier read within %s", g.timeouts.cluster)}
	}
	return p
}

func (g *gatherer) call(ctx context.Context, read func(context.Context) error) *sectionProblem {
	if g.fatal != nil {
		return g.fatal
	}
	rctx, cancel := context.WithTimeout(ctx, g.timeouts.cluster)
	defer cancel()
	if err := read(rctx); err != nil {
		return g.problemOf(ctx, err)
	}
	return nil
}

// apps is the apps section: FarCast's own workloads, the namespaces Planck
// labelled, the kernel's metered list, and each namespace's workloads.
//
// The reader is bound in farcast-system and the metered namespaces only (ADR
// 0023 M2.3, P3), so a namespace outside them answers forbidden. That
// namespace is marked, its workloads unknown, and the rest are still read
// (P5, A18-1): it is still grouped, so the alert that it is not metered is
// still raised. A forbidden farcast-system, a failed namespace list, and
// every other failure fail the section as a whole.
func (g *gatherer) apps(ctx context.Context, meta *config.InstanceMetadata) appsInput {
	var in appsInput
	if p := g.call(ctx, func(ctx context.Context) (err error) {
		in.System, err = g.cl.Workloads(ctx, tcdeploy.DefaultNamespace)
		return err
	}); p != nil {
		in.Problem = p
		in.Meter.Problem = p
		return in
	}
	if p := g.call(ctx, func(ctx context.Context) (err error) {
		in.Namespaces, err = g.cl.NamespacesLabelled(ctx, managedSelector)
		return err
	}); p != nil {
		in.Problem = p
		in.Meter.Problem = p
		return in
	}
	in.Meter = g.meter(ctx)

	// Every namespace any source names, read once each.
	set := map[string]bool{}
	for _, ns := range in.Namespaces {
		set[ns] = true
	}
	for _, ns := range in.Meter.Namespaces {
		set[ns] = true
	}
	if meta.Kernel != nil {
		for _, ns := range meta.Kernel.Namespaces {
			set[ns] = true
		}
	}
	for ns := range meta.Deployments {
		set[ns] = true
	}
	delete(set, tcdeploy.DefaultNamespace)
	delete(set, "")
	in.Workloads = map[string][]cluster.Workload{}
	for _, ns := range keysSorted(set) {
		var ws []cluster.Workload
		var werr error
		if p := g.call(ctx, func(ctx context.Context) (err error) {
			ws, err = g.cl.Workloads(ctx, ns)
			werr = err
			return err
		}); p != nil {
			if werr != nil && errors.Is(werr, tkube.ErrForbidden) {
				if in.Unread == nil {
					in.Unread = map[string]*sectionProblem{}
				}
				// The mark says the remedy for this namespace, once: not
				// p's, whose 'reader grant' cannot bind a namespace this
				// machine does not record as metered.
				in.Unread[ns] = &sectionProblem{Kind: kindForbidden, Message: fmt.Sprintf("the workloads in %s: %s",
					ns, g.scrub(namespaceRefused(werr, g.name, ns, meta).Error()))}
				continue
			}
			in.Problem = &sectionProblem{Kind: p.Kind, Message: fmt.Sprintf("the workloads in %s: %s", ns, p.Message)}
			in.Workloads, in.Unread = nil, nil
			return in
		}
		in.Workloads[ns] = ws
	}
	return in
}

// meter reads the kernel's metered-namespace document the way the kernel
// does: absent, or present with no entry, is an empty list.
func (g *gatherer) meter(ctx context.Context) meterInput {
	var m meterInput
	var raw string
	var found bool
	if p := g.call(ctx, func(ctx context.Context) (err error) {
		raw, found, err = g.cl.ConfigMapValue(ctx, tcdeploy.DefaultNamespace, kernel.DefaultNamespacesName, kernel.NamespacesKey())
		if err != nil && found {
			// Present with no entry: the kernel reads that as nothing asked
			// for, and so does this.
			raw, err = "", nil
		}
		return err
	}); p != nil {
		m.Problem = p
		return m
	}
	m.Namespaces = []string{}
	if !found || strings.TrimSpace(raw) == "" {
		return m
	}
	var doc kernel.Namespaces
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		m.Problem = &sectionProblem{Kind: kindDocumentUnreadable, Message: "decode the kernel's metered namespaces: " + err.Error()}
		return m
	}
	if doc.Version != kernel.NamespacesVersion {
		m.Problem = &sectionProblem{Kind: kindVersionSkew, Message: fmt.Sprintf(
			"the kernel's metered-namespace list is version %d and this build reads %d; one of them is older than the other",
			doc.Version, kernel.NamespacesVersion)}
		return m
	}
	m.Namespaces = append(m.Namespaces, doc.Meter...)
	return m
}

// spend is the kernel's checkpoint, as 'costs' reads it.
func (g *gatherer) spend(ctx context.Context, name string, meta *config.InstanceMetadata) spendInput {
	if meta.Kernel == nil || !meta.Kernel.Deployed {
		return spendInput{Problem: &sectionProblem{Kind: kindKernelAbsent, Message: fmt.Sprintf(
			"instance %q has no kernel, so nothing is metering it; run 'farcast kernel deploy %s'", name, name)}}
	}
	var in spendInput
	if p := g.call(ctx, func(ctx context.Context) (err error) {
		in.Raw, in.Found, err = g.cl.ConfigMapValue(ctx, tcdeploy.DefaultNamespace, kernel.DefaultCheckpointName, kernel.CheckpointKey())
		if err != nil && in.Found {
			// The ConfigMap is there and holds no checkpoint yet.
			in.Raw, err = "", nil
		}
		return err
	}); p != nil {
		return spendInput{Problem: p}
	}
	return in
}

// policy is the instance's egress policy, read by the same reader 'run' uses.
func (g *gatherer) policy(ctx context.Context) policyInput {
	var in policyInput
	if p := g.call(ctx, func(ctx context.Context) (err error) {
		in.Doc, err = readEgressPolicy(ctx, g.cl)
		return err
	}); p != nil {
		return policyInput{Problem: p}
	}
	return in
}

// throughTunnel makes the two tunnel reads over one tunnel: the monitor's
// picture, and each keyholder replica's seal state.
//
// The tunnel is opened with the narrow identity — the CA certificate and the
// operator's leaf — so the CA key is never read, and the seal read asks for
// phase, generation and hold only, so the keyring is never read either.
func (c *worldCommand) throughTunnel(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata) (networkInput, sealInput) {
	sealSkipped := meta.Keyholder == nil || !meta.Keyholder.Deployed
	fail := func(p *sectionProblem) (networkInput, sealInput) {
		if sealSkipped {
			return networkInput{Problem: p}, sealInput{Skipped: true}
		}
		return networkInput{Problem: p}, sealInput{Problem: p}
	}
	if meta.Carrier == nil || meta.Carrier.Endpoint == "" {
		return fail(&sectionProblem{Kind: kindNotConnected, Message: fmt.Sprintf(
			"instance %q has no tunnel recorded, so its traffic and seal state cannot be read; 'farcast connect %s' opens one", name, name)})
	}
	if ctx.Err() != nil {
		// Said as it is: the tunnel was never tried, which is not the same
		// as a carrier that did not answer.
		return fail(&sectionProblem{Kind: kindTimeout, Message: fmt.Sprintf(
			"the FatLine tunnel was not attempted: the read reached its ceiling of %s first", c.timeouts.ceiling)})
	}
	id, err := env.ConfigDir.LoadDialIdentity(name)
	if err != nil {
		return fail(&sectionProblem{Kind: kindRecordUnreadable, Message: fmt.Sprintf(
			"the operator identity in %s could not be read: %v", filepath.Join("instances", name, "fatline"), unwrapPath(err))})
	}
	dialID, err := clientIdentity(config.MTLSMaterial{
		CACertPEM: id.CACertPEM, ClientCertPEM: id.ClientCertPEM, ClientKeyPEM: id.ClientKeyPEM,
	}, name)
	if err != nil {
		return fail(&sectionProblem{Kind: kindRecordUnreadable, Message: "the operator identity is not usable: " + err.Error()})
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeouts.connect)
	conn, err := c.connect(cctx, "https://"+meta.Carrier.Endpoint, dialID)
	cancel()
	if err != nil {
		return fail(&sectionProblem{Kind: tunnelKind(err), Message: "the FatLine tunnel did not open: " + err.Error()})
	}
	defer func() { _ = conn.Close() }()

	network := networkInput{Tunnel: true}
	if token, err := identity.LeafTokenPEM(id.ClientCertPEM); err == nil {
		network.OperatorToken = token
	}
	if snap, err := fetchNetwork(ctx, conn); err != nil {
		network.Problem = &sectionProblem{Kind: tunnelKind(err), Message: err.Error()}
	} else {
		network.Snapshot = snap
	}

	if sealSkipped {
		return network, sealInput{Skipped: true}
	}
	reader, err := c.newSeal(conn, name, id)
	if err != nil {
		return network, sealInput{Problem: &sectionProblem{Kind: kindRecordUnreadable, Message: err.Error()}}
	}
	seal := sealInput{}
	for i := range replicaCount(meta) {
		sctx, cancel := context.WithTimeout(ctx, c.timeouts.seal)
		st, err := reader.State(sctx, i)
		cancel()
		r := replicaRead{Ordinal: i}
		if err != nil {
			r.Problem = &sectionProblem{Kind: tunnelKind(err), Message: err.Error()}
		} else {
			// Phase, generation and hold: what the map shows. Key ids and
			// the pin are dropped here, so nothing downstream can be built
			// on them.
			r.State = &keyholder.State{Phase: st.Phase, Since: st.Since, Generation: st.Generation, HoldReason: st.HoldReason}
		}
		seal.Replicas = append(seal.Replicas, r)
	}
	return network, seal
}

// unwrapPath is a file error without its absolute path.
func unwrapPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %w", filepath.Base(pe.Path), pe.Err)
	}
	return err
}
