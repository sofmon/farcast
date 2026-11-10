//go:build walk

// The walk probe: the client a live walk needs and the CLI will not be.
//
// Several Phase 5 criteria are about what the keyholder and FatLine refuse
// from a DISHONEST client — a keeper that claims to be the operator, a lost
// device pushing its old bundle, an application leaf at the public tunnel. The
// CLI refuses all of those before it sends anything, which is right and makes
// it useless for showing the cluster refuses them too. macOS curl cannot load
// an Ed25519 leaf, and a new tool on the operator's machine is a dependency
// this project does not take. So the probe is Go, in this package, behind a
// build tag, and never part of any ordinary test run:
//
//	FARCAST_WALK=1 FARCAST_WALK_PROBE=<probe> FARCAST_WALK_INSTANCE=<name> … \
//	  go test -mod=vendor -tags walk -run TestWalkProbe -v ./farsight/cli/internal/cli/
//
// A live walk builds it once instead, with go test -mod=vendor -tags walk -c
// -o <scratch>/walkprobe.test, and runs that binary with -test.run
// '^TestWalkProbe$' -test.v. A go test run links a fresh binary at a new
// temporary path every time, and an outbound firewall that rules per binary
// holds each one's connections until the probe's own deadline: the
// 2026-11-10 walk lost every probe that dialled the tunnel to that, until it
// moved to a fixed path.
//
// It skips unless FARCAST_WALK=1, takes no default instance, and never prints
// key material — key IDs only. It reads the operator's config directory the
// way the CLI does ($FARCAST_CONFIG_HOME, then the user config directory).
//
// go test runs the probe in the package's directory, not the caller's, so a
// relative path is resolved against FARCAST_WALK_CWD, and refused without it
// rather than looked for in the wrong place. The Session A runbook sets it to
// a scratch directory outside the checkout: the files a walk passes here are
// keyring copies, packets and a passphrase, and none of them belongs where a
// commit could pick it up.
//
// Probes (FARCAST_WALK_PROBE):
//
//	packet        decode a keeper packet: leaf URIs, EKU, expiry, the bundle's
//	              scopes and key IDs, whether the leaf binds the bundle; FAIL if
//	              it carries a master key ID or any private key but the leaf's
//	state         every replica's state as the given leaf sees it
//	push          push a bundle with a leaf, intent and generation of your choosing
//	seal          seal (FARCAST_WALK_HOLD=1 for a hold) with the given leaf
//	release-hold  release a hold with the given leaf
//	tunnel        present any certificate at the public carrier and report what
//	              the handshake, Status and each stream route do
//	open          read a stored object with a packet's scope keys
//
// Inputs:
//
//	FARCAST_WALK_CWD      the directory relative paths are resolved against
//	FARCAST_WALK_LEAF     operator | store:<dir> | packet:<file>   (default operator)
//	FARCAST_WALK_BUNDLE   store:<dir> | packet:<file> | keys:<keys.yaml> | keys:@live (this machine's keyring)
//	FARCAST_WALK_PACKET   the packet for 'packet' and 'open'
//	FARCAST_WALK_PASSPHRASE_FILE   a packet's passphrase
//	FARCAST_WALK_ORDINAL  replica (default 0)
//	FARCAST_WALK_INTENT   operator-unseal | restart-reseed | hand-over | operator-unseal+below-pin
//	FARCAST_WALK_GENERATION   default: what the replica reports, plus one
//	FARCAST_WALK_CERT, FARCAST_WALK_KEY   PEM files for 'tunnel'; without them,
//	                      'tunnel' presents FARCAST_WALK_LEAF
//	FARCAST_WALK_OBJECT   the logical key for 'open'
package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keeper"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/storage"
	"github.com/sofmon/farcast/fatline/identity"
)

func TestWalkProbe(t *testing.T) {
	if os.Getenv("FARCAST_WALK") != "1" {
		t.Skip("the walk probe talks to a live instance; set FARCAST_WALK=1")
	}
	instance := os.Getenv("FARCAST_WALK_INSTANCE")
	if instance == "" {
		t.Fatal("FARCAST_WALK_INSTANCE is required; the probe has no default instance")
	}
	dir, err := config.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	env := &Env{Out: os.Stdout, Err: os.Stderr, In: os.Stdin, Printer: &output.Printer{Mode: output.ModeHuman, Out: os.Stdout, Err: os.Stderr}, ConfigDir: dir}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	w := &walk{t: t, ctx: ctx, env: env, instance: instance}
	switch probe := os.Getenv("FARCAST_WALK_PROBE"); probe {
	case "packet":
		w.packet()
	case "state":
		w.state()
	case "push":
		w.push()
	case "seal":
		w.seal(os.Getenv("FARCAST_WALK_HOLD") == "1")
	case "release-hold":
		w.releaseHold()
	case "tunnel":
		w.tunnel()
	case "open":
		w.open()
	default:
		t.Fatalf("FARCAST_WALK_PROBE=%q: want packet, state, push, seal, release-hold, tunnel or open", probe)
	}
}

type walk struct {
	t        *testing.T
	ctx      context.Context
	env      *Env
	instance string
}

func (w *walk) say(format string, args ...any) { fmt.Printf(format+"\n", args...) }

// path resolves a file argument against the caller's directory.
func (w *walk) path(p string) string {
	w.t.Helper()
	if filepath.IsAbs(p) {
		return p
	}
	cwd := os.Getenv("FARCAST_WALK_CWD")
	if cwd == "" {
		w.t.Fatalf("%q is relative, and go test runs in the package directory: set FARCAST_WALK_CWD to the directory you run from, or pass an absolute path", p)
	}
	return filepath.Join(cwd, p)
}

// material is a leaf and the CA, and where they came from.
type material struct {
	from                string
	ca, cert, key       []byte
	carrier, serverName string
}

// openPacket opens a sealed keeper packet with the passphrase file.
func (w *walk) openPacket(path string) *keeper.Packet {
	w.t.Helper()
	sealed, err := os.ReadFile(w.path(path))
	if err != nil {
		w.t.Fatal(err)
	}
	passPath := os.Getenv("FARCAST_WALK_PASSPHRASE_FILE")
	if passPath == "" {
		w.t.Fatal("FARCAST_WALK_PASSPHRASE_FILE is required to open a packet")
	}
	pass, err := os.ReadFile(w.path(passPath))
	if err != nil {
		w.t.Fatal(err)
	}
	p, err := keeper.Open(sealed, strings.TrimRight(string(pass), "\r\n"))
	if err != nil {
		w.t.Fatalf("open the packet: %v", err)
	}
	return p
}

// leaf resolves FARCAST_WALK_LEAF.
func (w *walk) leaf() material {
	w.t.Helper()
	spec := os.Getenv("FARCAST_WALK_LEAF")
	switch {
	case spec == "" || spec == "operator":
		mtls, err := w.env.ConfigDir.LoadInstanceMTLS(w.instance)
		if err != nil {
			w.t.Fatal(err)
		}
		meta, err := w.env.ConfigDir.LoadInstanceMetadata(w.instance)
		if err != nil {
			w.t.Fatal(err)
		}
		return material{from: "the operator's leaf", ca: mtls.CACertPEM, cert: mtls.ClientCertPEM, key: mtls.ClientKeyPEM,
			carrier: meta.Carrier.Endpoint, serverName: identity.ServerName(w.instance)}
	case strings.HasPrefix(spec, "store:"):
		store, err := keeper.OpenStore(w.path(strings.TrimPrefix(spec, "store:")))
		if err != nil {
			w.t.Fatal(err)
		}
		cfg, err := store.Config()
		if err != nil {
			w.t.Fatal(err)
		}
		ca, cert, key, bundle, err := store.Material()
		if err != nil {
			w.t.Fatal(err)
		}
		clear(bundle)
		return material{from: "keeper store " + cfg.Device, ca: ca, cert: cert, key: key, carrier: cfg.Carrier, serverName: cfg.ServerName}
	case strings.HasPrefix(spec, "packet:"):
		p := w.openPacket(strings.TrimPrefix(spec, "packet:"))
		defer p.Zero()
		return material{from: "packet " + p.Device, ca: p.CACertPEM, cert: slices.Clone(p.LeafCertPEM), key: slices.Clone(p.LeafKeyPEM),
			carrier: p.Carrier, serverName: p.ServerName}
	}
	w.t.Fatalf("FARCAST_WALK_LEAF=%q: want operator, store:<dir> or packet:<file>", spec)
	return material{}
}

// bundle resolves FARCAST_WALK_BUNDLE to a marshalled bundle. A keyring
// becomes a bundle of every scope it holds, at the generation given.
func (w *walk) bundle(generation uint64) []byte {
	w.t.Helper()
	spec := os.Getenv("FARCAST_WALK_BUNDLE")
	switch {
	case strings.HasPrefix(spec, "store:"):
		store, err := keeper.OpenStore(w.path(strings.TrimPrefix(spec, "store:")))
		if err != nil {
			w.t.Fatal(err)
		}
		_, _, key, bundle, err := store.Material()
		if err != nil {
			w.t.Fatal(err)
		}
		clear(key)
		return bundle
	case strings.HasPrefix(spec, "packet:"):
		p := w.openPacket(strings.TrimPrefix(spec, "packet:"))
		defer p.Zero()
		return slices.Clone(p.Bundle)
	case strings.HasPrefix(spec, "keys:"):
		file := strings.TrimPrefix(spec, "keys:")
		if file == "@live" {
			file = w.env.ConfigDir.InstanceKeyringPath(w.instance)
		} else {
			file = w.path(file)
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			w.t.Fatal(err)
		}
		k, err := datasphere.ParseKeyring(raw)
		clear(raw)
		if err != nil {
			w.t.Fatal(err)
		}
		b, err := datasphere.NewBundle(w.instance, generation, k.Scopes())
		if err != nil {
			w.t.Fatal(err)
		}
		defer b.Zero()
		out, err := b.Marshal()
		if err != nil {
			w.t.Fatal(err)
		}
		return out
	}
	w.t.Fatalf("FARCAST_WALK_BUNDLE=%q: want store:<dir>, packet:<file> or keys:<keys.yaml>", spec)
	return nil
}

// client reaches the keyholder through the tunnel as the given leaf.
func (w *walk) client(m material) (*keyholder.Client, func()) {
	w.t.Helper()
	conn, err := keeperTunnel(w.ctx, keeper.Config{Instance: w.instance, Carrier: m.carrier, ServerName: m.serverName}, m.ca, m.cert, m.key)
	if err != nil {
		w.t.Fatalf("the tunnel refused %s: %v", m.from, err)
	}
	c, err := keyholder.New(keyholder.Conn(conn), w.instance, m.ca, m.cert, m.key)
	if err != nil {
		_ = conn.Close()
		w.t.Fatal(err)
	}
	return c, func() { _ = conn.Close() }
}

func ordinal() int {
	n, _ := strconv.Atoi(os.Getenv("FARCAST_WALK_ORDINAL"))
	return n
}

func (w *walk) report(i int, st keyholder.State, err error) {
	var r *keyholder.Refusal
	switch {
	case errors.As(err, &r):
		w.say("replica %d REFUSED: status %d, code %q — %s", i, r.Status, r.Code, r.Reason)
	case err != nil:
		w.say("replica %d ERROR: %v", i, err)
	default:
		w.say("replica %d %s, generation %d, boot %s, scopes %v", i, st.Phase, st.Generation, shortBoot(st.Boot), st.Scopes)
		for _, s := range sortedKeys(st.Keys) {
			w.say("    %s: %v", s, st.Keys[s])
		}
		if st.Pin != nil {
			w.say("    key pin: %s, requires %d, retires %d, serving below %v %s",
				st.Pin.Status, len(st.Pin.Require), len(st.Pin.Retired), st.Pin.ServingBelow, st.Pin.Error)
		} else {
			w.say("    key pin: not reported (an image from before the pin)")
		}
	}
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (w *walk) state() {
	m := w.leaf()
	c, done := w.client(m)
	defer done()
	w.say("as %s:", m.from)
	for i := range 2 {
		st, err := c.State(w.ctx, i)
		w.report(i, st, err)
	}
}

func (w *walk) push() {
	m := w.leaf()
	c, done := w.client(m)
	defer done()
	i := ordinal()
	intent := os.Getenv("FARCAST_WALK_INTENT")
	if intent == "" {
		w.t.Fatal("FARCAST_WALK_INTENT is required for push")
	}
	gen := uint64(0)
	if g := os.Getenv("FARCAST_WALK_GENERATION"); g != "" {
		v, err := strconv.ParseUint(g, 10, 64)
		if err != nil {
			w.t.Fatal(err)
		}
		gen = v
	} else if st, err := c.State(w.ctx, i); err == nil {
		gen = st.Generation + 1
	}
	payload := w.bundle(gen)
	defer clear(payload)
	w.say("pushing to replica %d as %s, intent %s, bundle generation from %s", i, m.from, intent, os.Getenv("FARCAST_WALK_BUNDLE"))
	st, err := c.Unseal(w.ctx, i, payload, intent)
	w.report(i, st, err)
}

func (w *walk) seal(hold bool) {
	m := w.leaf()
	c, done := w.client(m)
	defer done()
	i := ordinal()
	st, err := c.Seal(w.ctx, i, hold, "walk probe")
	w.say("seal (hold=%v) replica %d as %s:", hold, i, m.from)
	w.report(i, st, err)
}

func (w *walk) releaseHold() {
	m := w.leaf()
	c, done := w.client(m)
	defer done()
	i := ordinal()
	st, err := c.ReleaseHold(w.ctx, i)
	w.say("release-hold replica %d as %s:", i, m.from)
	w.report(i, st, err)
}

// tunnel presents an arbitrary certificate at the carrier. Each step reports
// what happened rather than failing, because a refusal is the expected answer
// for most leaves.
func (w *walk) tunnel() {
	certPath, keyPath := os.Getenv("FARCAST_WALK_CERT"), os.Getenv("FARCAST_WALK_KEY")
	var cert, key []byte
	if certPath == "" && keyPath == "" {
		m := w.leaf()
		certPath, cert, key = m.from, m.cert, m.key
	} else {
		var err error
		if cert, err = os.ReadFile(w.path(certPath)); err != nil {
			w.t.Fatal(err)
		}
		if key, err = os.ReadFile(w.path(keyPath)); err != nil {
			w.t.Fatal(err)
		}
	}
	defer clear(key)
	mtls, err := w.env.ConfigDir.LoadInstanceMTLS(w.instance)
	if err != nil {
		w.t.Fatal(err)
	}
	meta, err := w.env.ConfigDir.LoadInstanceMetadata(w.instance)
	if err != nil {
		w.t.Fatal(err)
	}
	w.say("presenting %s, leaf URIs %v", certPath, leafURIs(cert))
	conn, err := keeperTunnel(w.ctx, keeper.Config{Instance: w.instance, Carrier: meta.Carrier.Endpoint, ServerName: identity.ServerName(w.instance)},
		mtls.CACertPEM, cert, key)
	if err != nil {
		w.say("tunnel: REFUSED at connect: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	if st, err := conn.Status(w.ctx); err != nil {
		w.say("tunnel: Status REFUSED: %v", err)
	} else {
		w.say("tunnel: Status answered: %+v", st)
	}
	for _, route := range []string{keyholder.StreamRoute, "shrike"} {
		s, err := conn.DialStream(w.ctx, route, 0)
		if err != nil {
			w.say("route %s: REFUSED: %v", route, err)
			continue
		}
		_ = s.Close()
		w.say("route %s: opened", route)
	}
}

func leafURIs(certPEM []byte) []string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	var out []string
	for _, u := range cert.URIs {
		out = append(out, u.String())
	}
	return out
}

// packet decodes a packet and checks it carries only what a keeper should.
func (w *walk) packet() {
	path := os.Getenv("FARCAST_WALK_PACKET")
	if path == "" {
		w.t.Fatal("FARCAST_WALK_PACKET is required")
	}
	p := w.openPacket(path)
	defer p.Zero()
	block, _ := pem.Decode(p.LeafCertPEM)
	if block == nil {
		w.t.Fatal("the packet's leaf is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		w.t.Fatal(err)
	}
	w.say("device %s of %s, carrier %s, server name %s", p.Device, p.Instance, p.Carrier, p.ServerName)
	w.say("leaf URIs %v, extended key usage %v, expires %s", leafURIs(p.LeafCertPEM), cert.ExtKeyUsage, cert.NotAfter.UTC().Format(time.RFC3339))
	if err := leafBindsBundle(p.LeafCertPEM, p.Bundle); err != nil {
		w.say("FAIL: %v", err)
		w.t.Fail()
	} else {
		w.say("the leaf binds the bundle it carries")
	}
	b, err := datasphere.ParseBundle(p.Bundle)
	if err != nil {
		w.t.Fatal(err)
	}
	defer b.Zero()
	bundleIDs := map[string]bool{}
	for _, s := range b.Scopes() {
		var ids []string
		for _, e := range s.Keyring().KEKs() {
			ids = append(ids, e.ID.String())
			bundleIDs[e.ID.String()] = true
		}
		for _, e := range s.Keyring().NameKeys() {
			bundleIDs[e.ID.String()] = true
		}
		w.say("  scope %s: KEKs %v", s.Name, ids)
	}
	// The master key space never travels to a keeper (ADR 0008 finding 2).
	if keys, err := keyringOf(w.env, w.instance); err == nil {
		for _, e := range append(keys.KEKs(), keys.NameKeys()...) {
			if bundleIDs[e.ID.String()] {
				w.say("FAIL: the bundle carries master key %s", e.ID)
				w.t.Fail()
			}
		}
		w.say("checked against this machine's keyring: no master key in the bundle")
	} else {
		w.say("no keyring on this machine to check the master keys against (%v)", err)
	}
	if n := strings.Count(string(p.LeafKeyPEM), "PRIVATE KEY-----") / 2; n != 1 {
		w.say("FAIL: the leaf key file holds %d private keys", n)
		w.t.Fail()
	}
	if strings.Contains(string(p.CACertPEM), "PRIVATE KEY") || strings.Contains(string(p.LeafCertPEM), "PRIVATE KEY") {
		w.say("FAIL: a private key rides outside the leaf key")
		w.t.Fail()
	}
}

// open reads one stored object with a packet's scope keys and nothing else.
// After a rotation and rekey, a revoked device's keys should open nothing.
func (w *walk) open() {
	path, object := os.Getenv("FARCAST_WALK_PACKET"), os.Getenv("FARCAST_WALK_OBJECT")
	if path == "" || object == "" {
		w.t.Fatal("FARCAST_WALK_PACKET and FARCAST_WALK_OBJECT are required for open")
	}
	p := w.openPacket(path)
	defer p.Zero()
	b, err := datasphere.ParseBundle(p.Bundle)
	if err != nil {
		w.t.Fatal(err)
	}
	defer b.Zero()
	session, err := storage.Open(w.ctx, storage.Options{Dir: w.env.ConfigDir, Instance: w.instance})
	if err != nil {
		w.t.Fatal(err)
	}
	for _, s := range b.Scopes() {
		if !s.Owns(object) {
			continue
		}
		store, err := datasphere.NewStore(session.Provider, session.Bucket, s.Keyring())
		if err != nil {
			w.t.Fatal(err)
		}
		data, err := store.Read(w.ctx, object)
		clear(data)
		switch {
		case errors.Is(err, datasphere.ErrUnknownKey):
			w.say("%s with %s's keys: ErrUnknownKey — the object is under a key this device never held", object, p.Device)
		case err != nil:
			w.say("%s with %s's keys: %v", object, p.Device, err)
		default:
			w.say("%s with %s's keys: READ %d bytes — this device's keys still open it", object, p.Device, len(data))
		}
		return
	}
	w.say("no scope in %s's bundle owns %s", p.Device, object)
}
