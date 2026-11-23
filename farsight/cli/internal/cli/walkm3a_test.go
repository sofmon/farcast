//go:build walk

// The M3a probe: whether Google's certificate route exists (ADR 0024 M3a;
// design §6; docs/runbooks/adr-0024-m3a-probe.md).
//
// ADR 0024 proposes that the operator's cloud identity is a certificate the
// device makes and a human pastes into the provider. On Google that is X.509
// Workload Identity Federation, which no page read settles end to end for
// D2's profile: a self-signed anchor per role whose only subject field is a
// random role ID, and a leaf whose DN equals its issuer's. This probe walks
// it. It calls kube.Federation and devicekey, the code M3b ships, so what it
// walks is what M3b ships; only I1, I6, V5's exchange, T4's read-back and
// T2's token info take probe-only paths.
//
// It is built once, to a fixed path, and never by an ordinary test run:
//
//	env GOWORK=off GOTOOLCHAIN=go1.27.4 GOPROXY=off GOFLAGS=-mod=vendor \
//	  go test -tags walk -c -o <scratch>/walkprobe.test ./farsight/cli/internal/cli/
//
// and run one step per process, from the runbook's walk shell:
//
//	FARCAST_WALK=1 FARCAST_WALK_M3A_STEP=<step> … <scratch>/walkprobe.test \
//	  -test.run '^TestWalkM3a$' -test.v -test.count=1 -test.timeout 0
//
// It skips unless FARCAST_WALK=1. Before any step it refuses an environment
// that sets GODEBUG, SSL_CERT_FILE, SSL_CERT_DIR, KUBECONFIG, a GOOGLE_
// variable or a proxy variable in any case (m3aEnvironmentFaults), and asks
// kube.UnsafeEnvironment first: the cli test binary never runs
// hardenEnvironment, and the probe-only clients send a bearer over HTTP/2.
//
// What it prints: statuses, OAuth error codes, Google error statuses, TLS
// alert words and TLS versions, issued_token_type, lifetimes, settle times as
// deltas in whole seconds, scope sets, counts, and yes/no. Never a token, a
// key, an assertion, an email, a project number or any ID. Remote text goes
// through walkScrubber, with every ID of the run added as a literal
// (m3aLiterals). Blocks go to files under <dir>/blocks and are never printed:
// a write prints the block's name and the first 12 hex of its SHA-256.
//
// Hosts it dials (the runbook's P0.4 gives each its firewall rule), each a
// constant here or in kube:
//
//	sts.mtls.googleapis.com:443            product (kube.STSMTLSHost): every X.509 exchange
//	iamcredentials.googleapis.com:443      product (kube.IAMCredentialsHost): every impersonation
//	sts.googleapis.com:443                 probe-only: V5's JWT, I6
//	iamcredentials.mtls.googleapis.com:443 probe-only: I1 [inf, unverified: no page read names it]
//	iam.googleapis.com:443                 probe-only: T4's read-back of V1's two providers
//	oauth2.googleapis.com:443              probe-only: T2's token info, by POST
//	the cluster's DNS endpoint (*.gke.goog:443), from the instance record: W-FED only
//
// Steps (FARCAST_WALK_M3A_STEP; design §6's items in brackets):
//
//	init               [P0] draw the IDs; enrol V1, V1b, V1c, V8; make V1x, V1y, V2–V7, N1's and I7's anchors
//	blocks             [P0] write every block that needs no later state (again after coordinates, for console-v1c.txt)
//	coordinates        [P1] record the project number from the setup's last line
//	mark               after every IAM change: record FARCAST_WALK_M3A_MARK's time
//	console            [P2] V1c's two leaves, S1–S4 each; each accepted one impersonates the reader SA
//	t1                 [P3] T1 for V1's two roles and V1b's T1, with each one's first impersonation (V1b's T2),
//	                   in one round-robin from the setup mark
//	t2, t3, t4         [P3] impersonation and token info, silent renewal, the read-back polled from the mark
//	v1b                [P3] V1b's T1 and T2 alone, for a rerun
//	negatives          [P4] N1–N10, each beside its positive control, checked twice
//	variants           [P5] V2–V8
//	contingent-blocks  [P5] contingent.sh, only if T1 refused every shape for a role
//	contingent         [P5] V1x and V1y
//	i1 … i6            [P5] I1 to I6; I6 gates as N6, beside V5 at the plain endpoint as its control
//	i7-added, i7-removed  [P5] I7, after i7-add.sh and i7-remove.sh
//	renew, renew-console  [P6] stage a writer anchor renewal; write renew-paste.sh or console-renew.txt
//	renewal            [P6] the staged leaf and the old leaf from the mark, the reader; then commit
//	renew-discard      [P6.4] discard a staged renewal Google did not take, while the current writer leaf still exchanges
//	hold-binding       [P7 (a)] held: a writer token, after revoke-binding
//	writer-back        [P7] after readd-binding.sh or enable-writer.sh
//	hold-disable       [P7 (b)] held: after disable-writer (gating)
//	hold-delete        [P7 (c), P10 (a)] held: after teardown-v1 (gating)
//	audit-block        [P8] write audit.sh
//	wfed-init, wfed-blocks, wfed, wfed-gone   W-FED, in the M2 walk (its W-FED section)
//
// Inputs:
//
//	FARCAST_WALK=1             the gate
//	FARCAST_WALK_M3A_STEP      the step; no default, and an unknown one fails listing every step
//	FARCAST_WALK_M3A_DIR       the probe's directory: absolute or relative to FARCAST_WALK_CWD; a
//	                           real directory, 0700; empty for init and wfed-init
//	FARCAST_WALK_CWD           as the walk probe takes it
//	FARCAST_WALK_PROJECT       init and wfed-init: the project ID, stored in the state
//	FARCAST_WALK_M3A_LINE      coordinates: the file holding the setup's last line
//	FARCAST_WALK_M3A_MARK      mark: the mark's name, one of m3aMarkNames
//	FARCAST_WALK_M3A_SINCE     renewal: renew-paste or renew-console; writer-back: readd-binding or enable-writer
//	FARCAST_WALK_INSTANCE      wfed: the M2 walk's instance, its record from config.Resolve("")
//	FARCAST_WALK_M3A_SHAPE     wfed, wfed-gone: S1 to S4, M3a's simplest passing shape
//
// Keys. V1, V1b, V1c and V8 are devicekey stores under <dir>/device-a,
// device-b, device-c and device-v8. Every other key that outlives its step is
// PKCS#8 PEM, 0600, created O_EXCL under <dir>/variants/<name>/ (0700); the
// negatives', I3's and I4's leaf keys live in memory for their one step. For
// the leaves the negatives, I3 and I4 need, the probe reads V1's reader
// anchor key itself, once per step, from its own literal path
// <dir>/device-a/reader/anchor.key, after a mode check. No product code does
// this, and devicekey exports no such path. Where the probe needs the writer
// keys it calls devicekey.GiveConsent(devicekey.ConsentConfirmed) in this test
// file: devicekey's call-site scan (custody_scan_test.go) reads no test file.
package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/auth"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/devicekey"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// The probe-only hosts. The product's are kube.STSMTLSHost and
// kube.IAMCredentialsHost.
const (
	m3aSTSPlainHost     = "sts.googleapis.com"                 // [STS]
	m3aIAMCredsMTLSHost = "iamcredentials.mtls.googleapis.com" // [inf, unverified]: the *.mtls.googleapis.com convention
	m3aIAMHost          = "iam.googleapis.com"                 // [PROV-GET]
	m3aTokenInfoHost    = "oauth2.googleapis.com"              // [TT]
)

// V5's subject token types: the vendored library's jwt (sts_exchange.go:39),
// then id_token [STS].
const (
	m3aTokenTypeJWT     = "urn:ietf:params:oauth:token-type:jwt"
	m3aTokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
)

// m3aHeldWait is how long a held step waits for its mark.
const m3aHeldWait = 30 * time.Minute

// The probe's device directories.
const (
	m3aDeviceA  = "device-a"
	m3aDeviceB  = "device-b"
	m3aDeviceC  = "device-c"
	m3aDeviceV8 = "device-v8"
	m3aDeviceW  = "device"
)

// m3aStepDef is a step and its context bound.
type m3aStepDef struct {
	run   func(*m3aWalk)
	bound time.Duration
}

// m3aStepTable is every step, with its context bound.
func m3aStepTable() map[string]m3aStepDef {
	return map[string]m3aStepDef{
		"init":              {(*m3aWalk).stepInit, 2 * time.Minute},
		"blocks":            {(*m3aWalk).stepBlocks, time.Minute},
		"coordinates":       {(*m3aWalk).stepCoordinates, 10 * time.Second},
		"mark":              {(*m3aWalk).stepMark, 10 * time.Second},
		"console":           {(*m3aWalk).stepConsole, 15 * time.Minute},
		"t1":                {(*m3aWalk).stepT1, 15 * time.Minute},
		"t2":                {(*m3aWalk).stepT2, 15 * time.Minute},
		"t3":                {(*m3aWalk).stepT3, 15 * time.Minute},
		"t4":                {(*m3aWalk).stepT4, 15 * time.Minute},
		"v1b":               {(*m3aWalk).stepV1b, 15 * time.Minute},
		"negatives":         {(*m3aWalk).stepNegatives, 30 * time.Minute},
		"variants":          {(*m3aWalk).stepVariants, 15 * time.Minute},
		"contingent-blocks": {(*m3aWalk).stepContingentBlocks, time.Minute},
		"contingent":        {(*m3aWalk).stepContingent, 15 * time.Minute},
		"i1":                {(*m3aWalk).stepI1, 5 * time.Minute},
		"i2":                {(*m3aWalk).stepI2, 5 * time.Minute},
		"i3":                {(*m3aWalk).stepI3, 5 * time.Minute},
		"i4":                {(*m3aWalk).stepI4, 5 * time.Minute},
		"i5":                {(*m3aWalk).stepI5, 5 * time.Minute},
		"i6":                {(*m3aWalk).stepI6, 15 * time.Minute},
		"i7-added":          {(*m3aWalk).stepI7Added, 15 * time.Minute},
		"i7-removed":        {(*m3aWalk).stepI7Removed, 15 * time.Minute},
		"renew":             {(*m3aWalk).stepRenew, time.Minute},
		"renew-console":     {(*m3aWalk).stepRenewConsole, time.Minute},
		"renewal":           {(*m3aWalk).stepRenewal, 15 * time.Minute},
		"renew-discard":     {(*m3aWalk).stepRenewDiscard, 2 * time.Minute},
		"hold-binding":      {(*m3aWalk).stepHoldBinding, 100 * time.Minute},
		"writer-back":       {(*m3aWalk).stepWriterBack, 15 * time.Minute},
		"hold-disable":      {(*m3aWalk).stepHoldDisable, 100 * time.Minute},
		"hold-delete":       {(*m3aWalk).stepHoldDelete, 100 * time.Minute},
		"audit-block":       {(*m3aWalk).stepAuditBlock, time.Minute},
		"wfed-init":         {(*m3aWalk).stepWFEDInit, time.Minute},
		"wfed-blocks":       {(*m3aWalk).stepWFEDBlocks, time.Minute},
		"wfed":              {(*m3aWalk).stepWFED, 20 * time.Minute},
		"wfed-gone":         {(*m3aWalk).stepWFEDGone, 15 * time.Minute},
	}
}

func TestWalkM3a(t *testing.T) {
	if os.Getenv("FARCAST_WALK") != "1" {
		t.Skip("the M3a probe talks to Google; set FARCAST_WALK=1")
	}
	if err := kube.UnsafeEnvironment(); err != nil {
		t.Fatal(err)
	}
	if faults := m3aEnvironmentFaults(os.Environ()); len(faults) > 0 {
		t.Fatalf("the environment sets %s; the probe refuses each (it names the variable, never its value): unset them and run it again",
			terminalText(strings.Join(faults, ", ")))
	}
	table := m3aStepTable()
	step := os.Getenv("FARCAST_WALK_M3A_STEP")
	def, ok := table[step]
	if !ok {
		names := slices.Sorted(maps.Keys(table))
		t.Fatalf("FARCAST_WALK_M3A_STEP=%q: want one of %s; there is no default", terminalText(step), strings.Join(names, ", "))
	}
	ctx, cancel := context.WithTimeout(context.Background(), def.bound)
	defer cancel()
	w := &m3aWalk{walk: &walk{t: t, ctx: ctx}, step: step, clock: m3aWallClock(), sc: newWalkScrubber(nil)}
	w.start = w.clock.now()
	w.dir = w.probeDir(step == "init" || step == "wfed-init")
	def.run(w)
}

// m3aWalk is one step's run.
type m3aWalk struct {
	*walk
	step  string
	dir   string
	st    *m3aState
	sc    walkScrubber
	clock m3aClock
	start time.Time
	fed   *kube.Federation
}

// ---- The directory, the state and the files ----

// probeDir resolves FARCAST_WALK_M3A_DIR: a real directory, 0700, and empty
// when the step starts a state. Like devicekey's, its checks read mode bits
// only: an access control list on the directory, which on macOS its files
// inherit, is not seen. The runbook's P0.2 checks for one with ls -led.
func (w *m3aWalk) probeDir(empty bool) string {
	w.t.Helper()
	raw := os.Getenv("FARCAST_WALK_M3A_DIR")
	if raw == "" {
		w.t.Fatal("FARCAST_WALK_M3A_DIR is required: the probe's own directory, 0700")
	}
	dir := w.path(raw)
	fi, err := os.Lstat(dir)
	switch {
	case err != nil:
		w.stop(w.sc, "the probe's directory: %v", err)
	case !fi.IsDir():
		w.stop(w.sc, "the probe's directory is not a directory (a link is refused)")
	case fi.Mode().Perm()&0o077 != 0:
		w.stop(w.sc, "the probe's directory is open to other accounts; make it 0700")
	}
	if empty {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) > 0 {
			w.stop(w.sc, "%s starts a state, and the probe's directory is not empty", w.step)
		}
	}
	return dir
}

// load reads the state and extends the scrubber with the run's literals.
func (w *m3aWalk) load() {
	w.t.Helper()
	st, err := m3aLoadState(w.dir)
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	wfedStep := strings.HasPrefix(w.step, "wfed")
	shared := w.step == "mark" || w.step == "coordinates" // both walks use them
	if !shared && st.WFED != wfedStep {
		w.t.Fatalf("%s needs %s state, and this directory holds the other", w.step, map[bool]string{true: "W-FED's", false: "M3a's"}[wfedStep])
	}
	w.st = st
	w.addLiterals()
}

// addLiterals adds the run's values to the scrubber, longest first.
func (w *m3aWalk) addLiterals() {
	w.sc.literals = append(w.sc.literals, m3aLiterals(w.st)...)
	slices.SortStableFunc(w.sc.literals, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
}

func (w *m3aWalk) save() {
	w.t.Helper()
	if err := m3aSaveState(w.dir, w.st); err != nil {
		w.stop(w.sc, "write the state: %v", err)
	}
}

// mkdir makes rel under the probe's directory, 0700.
func (w *m3aWalk) mkdir(rel string) string {
	w.t.Helper()
	dir := filepath.Join(w.dir, rel)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		w.stop(w.sc, "make %s: %v", rel, err)
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		w.stop(w.sc, "%s is not a private directory", rel)
	}
	return dir
}

// writeNew writes a new 0600 file, O_CREATE|O_EXCL.
func (w *m3aWalk) writeNew(rel string, data []byte) {
	w.t.Helper()
	w.mkdir(filepath.Dir(rel))
	f, err := os.OpenFile(filepath.Join(w.dir, rel), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		w.stop(w.sc, "create %s: %v", rel, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		w.stop(w.sc, "write %s: %v", rel, err)
	}
	if err := f.Close(); err != nil {
		w.stop(w.sc, "write %s: %v", rel, err)
	}
}

// readPrivate reads a file the probe wrote, after checking it is a plain
// 0600 file.
func (w *m3aWalk) readPrivate(rel string) []byte {
	w.t.Helper()
	path := filepath.Join(w.dir, rel)
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		w.stop(w.sc, "%s is missing, or not a private plain file", rel)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		w.stop(w.sc, "read %s: %v", rel, err)
	}
	return b
}

// writeKey writes key as PKCS#8 PEM.
func (w *m3aWalk) writeKey(rel string, key crypto.Signer) {
	w.t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		w.stop(w.sc, "encode %s: %v", rel, err)
	}
	w.writeNew(rel, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	clear(der)
}

// readKey reads a PKCS#8 PEM key the probe wrote.
func (w *m3aWalk) readKey(rel string) crypto.Signer {
	w.t.Helper()
	raw := w.readPrivate(rel)
	defer clear(raw)
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		w.stop(w.sc, "%s is not a PKCS#8 PEM key", rel)
	}
	defer clear(block.Bytes)
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		w.stop(w.sc, "%s does not parse as a key", rel)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		w.stop(w.sc, "%s is not a signing key", rel)
	}
	return s
}

// writeCert writes a certificate's PEM.
func (w *m3aWalk) writeCert(rel string, der []byte) {
	w.t.Helper()
	w.writeNew(rel, []byte(m3aPEM(der)))
}

// readCert reads a certificate the probe wrote, and, when it holds one, its
// key: <base>.crt and <base>.key.
func (w *m3aWalk) readCert(base string, withKey bool) m3aCert {
	w.t.Helper()
	block, _ := pem.Decode(w.readPrivate(base + ".crt"))
	if block == nil || block.Type != "CERTIFICATE" {
		w.stop(w.sc, "%s.crt is not a PEM certificate", base)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		w.stop(w.sc, "%s.crt does not parse", base)
	}
	out := m3aCert{der: block.Bytes, cert: c}
	if withKey {
		out.key = w.readKey(base + ".key")
	}
	return out
}

// writePair writes a variant's anchor and leaf, with their keys, under
// variants/<name>/. V3's one certificate is its anchor alone.
func (w *m3aWalk) writePair(name string, p m3aPair) int {
	w.t.Helper()
	base := filepath.Join("variants", name)
	w.writeCert(filepath.Join(base, "anchor.crt"), p.anchor.der)
	w.writeKey(filepath.Join(base, "anchor.key"), p.anchor.key)
	if bytes.Equal(p.anchor.der, p.leaf.der) {
		return 1
	}
	w.writeCert(filepath.Join(base, "leaf.crt"), p.leaf.der)
	w.writeKey(filepath.Join(base, "leaf.key"), p.leaf.key)
	if p.leaf.key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(p.anchor.key.Public()) {
		return 1 // V2: one key, in two files
	}
	return 2
}

// readPair reads what writePair wrote.
func (w *m3aWalk) readPair(name string) m3aPair {
	w.t.Helper()
	base := filepath.Join("variants", name)
	anchor := w.readCert(filepath.Join(base, "anchor"), true)
	if _, err := os.Lstat(filepath.Join(w.dir, base, "leaf.crt")); errors.Is(err, os.ErrNotExist) {
		return m3aPair{anchor: anchor, leaf: anchor}
	}
	return m3aPair{anchor: anchor, leaf: w.readCert(filepath.Join(base, "leaf"), true)}
}

// writeBlock writes a block, 0600 in the 0700 blocks directory, atomically,
// and prints its name and digest, never its content.
func (w *m3aWalk) writeBlock(name string, b []byte) {
	w.t.Helper()
	dir := w.mkdir("blocks")
	f, err := os.CreateTemp(dir, ".block-*")
	if err != nil {
		w.stop(w.sc, "write blocks/%s: %v", name, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, name))
	}
	if err != nil {
		w.stop(w.sc, "write blocks/%s: %v", name, err)
	}
	w.say("wrote blocks/%s (sha256 %s)", name, m3aDigest(b))
}

// recordLeaf adds a leaf the run made to the state's list, for audit.sh. The
// caller saves.
func (w *m3aWalk) recordLeaf(der ...[]byte) {
	for _, d := range der {
		if len(d) > 0 {
			w.st.Leaves = append(w.st.Leaves, slices.Clone(d))
		}
	}
}

// recordCA adds a CA certificate the run made outside a variant's anchors and
// I7's to the state's list, for audit.sh: Google's X.509 keyInfo carries a
// trust anchor's or an intermediate CA's fingerprint.
func (w *m3aWalk) recordCA(der ...[]byte) {
	for _, d := range der {
		if len(d) > 0 {
			w.st.CAs = append(w.st.CAs, slices.Clone(d))
		}
	}
}

// ---- Devices and identities ----

func (w *m3aWalk) store(device string) *devicekey.Store {
	w.t.Helper()
	s, err := devicekey.Open(filepath.Join(w.dir, device))
	if err != nil {
		w.stop(w.sc, "open %s's keys: %v", device, err)
	}
	return s
}

// reader is a device's reader identity (purpose: read).
func (w *m3aWalk) reader(device string) devicekey.Identity {
	w.t.Helper()
	id, err := w.store(device).OpenForRead(rand.Reader, w.clock.now())
	if err != nil {
		w.stop(w.sc, "open %s's reader: %v", device, err)
	}
	return id
}

// writer is a device's writer identity. The consent is given here, in a test
// file, which devicekey's call-site scan does not read.
func (w *m3aWalk) writer(device string) devicekey.Identity {
	w.t.Helper()
	id, err := w.store(device).OpenForWrite(devicekey.GiveConsent(devicekey.ConsentConfirmed), rand.Reader, w.clock.now())
	if err != nil {
		w.stop(w.sc, "open %s's writer: %v", device, err)
	}
	return id
}

// roleIDOf is the role ID a device's certificates carry, opening no key.
func (w *m3aWalk) roleIDOf(device string, r devicekey.Role) devicekey.RoleID {
	w.t.Helper()
	_, _, id, err := w.store(device).Certificates(r)
	if err != nil {
		w.stop(w.sc, "read %s's %s certificates: %v", device, r, err)
	}
	return id
}

// v1ReaderAnchor is V1's reader anchor with its key: the probe's one read of
// a device's anchor key outside custody, by its own literal path, after a
// mode check. No product code does this.
func (w *m3aWalk) v1ReaderAnchor() (m3aCert, devicekey.RoleID) {
	w.t.Helper()
	anchorDER, _, id, err := w.store(m3aDeviceA).Certificates(devicekey.Reader)
	if err != nil {
		w.stop(w.sc, "read V1's reader certificates: %v", err)
	}
	c, err := x509.ParseCertificate(anchorDER)
	if err != nil {
		w.stop(w.sc, "V1's reader anchor does not parse")
	}
	key := w.readKey(filepath.Join(m3aDeviceA, "reader", "anchor.key"))
	return m3aCert{der: anchorDER, cert: c, key: key}, id
}

func (w *m3aWalk) newRoleID() devicekey.RoleID {
	w.t.Helper()
	id, err := devicekey.NewRoleID(rand.Reader)
	if err != nil {
		w.stop(w.sc, "draw a role ID: %v", err)
	}
	return id
}

func (w *m3aWalk) newObjectID(kind devicekey.ObjectKind) string {
	w.t.Helper()
	id, err := devicekey.NewObjectID(kind, rand.Reader)
	if err != nil {
		w.stop(w.sc, "draw an object ID: %v", err)
	}
	return id
}

// ---- Exchanges ----

func (w *m3aWalk) federation() *kube.Federation {
	w.t.Helper()
	if w.fed == nil {
		f, err := kube.NewFederation()
		if err != nil {
			w.stop(w.sc, "%v", err)
		}
		w.fed = f
	}
	return w.fed
}

// aud is a variant's provider's audience.
func (w *m3aWalk) aud(variant, role string) string {
	w.t.Helper()
	if w.st.ProjectNumber == "" {
		w.t.Fatal("the project number is not recorded; run coordinates first")
	}
	a, err := kube.Audience(w.st.ProjectNumber, w.st.Pool, w.st.provider(variant, role))
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	return a
}

// email is an SA's email: "reader" or "writer".
func (w *m3aWalk) email(role string) string {
	if role == m3aWriter {
		return m3aEmail(w.st.WriterSA, w.st.Project)
	}
	return m3aEmail(w.st.ReaderSA, w.st.Project)
}

// m3aPresent is what a handshake presents: a leaf, any intermediates, the
// chain's anchor (nil when the leaf is its own), and the leaf's key.
type m3aPresent struct {
	leaf   []byte
	mid    [][]byte
	anchor []byte
	signer crypto.Signer
}

func m3aPresentOf(id devicekey.Identity) m3aPresent {
	return m3aPresent{leaf: id.LeafDER(), anchor: id.AnchorDER(), signer: id.Signer()}
}

func m3aPresentCert(leaf m3aCert, anchor []byte, mid ...m3aCert) m3aPresent {
	p := m3aPresent{leaf: leaf.der, anchor: anchor, signer: leaf.key}
	for _, m := range mid {
		p.mid = append(p.mid, m.der)
	}
	return p
}

// exchange sends p in shape to aud, through the step's one Federation. This
// is the seam between devicekey's and kube's types, which lives only here.
func (w *m3aWalk) exchange(aud string, p m3aPresent, shape m3aShape, scopes []string) (*kube.ExchangeAnswer, error) {
	tlsChain, subject := shape.chains(p.leaf, p.mid, p.anchor)
	return w.federation().Exchange(w.ctx, kube.NewExchangeRequest(aud, kube.NewClientIdentity(tlsChain, p.signer), subject, scopes))
}

// notSent stops the step when kube refused a request before sending it: the
// probe built it wrong, and polling it would measure nothing.
func (w *m3aWalk) notSent(label string, err error) {
	w.t.Helper()
	if errors.Is(err, kube.ErrCredentialInvalid) || errors.Is(err, kube.ErrEndpointRefused) {
		w.stop(w.sc, "%s: %s", label, w.refusal(err))
	}
}

// refusal describes a failed exchange or impersonation: kube's fixed text,
// which holds only a status, a shape-checked code or alert, or a field,
// scrubbed all the same.
func (w *m3aWalk) refusal(err error) string {
	var fe *kube.FederationError
	switch {
	case errors.As(err, &fe) && fe.Status == http.StatusOK:
		return "ANSWERED 200 without a usable token: " + w.sc.text(err.Error())
	case errors.Is(err, kube.ErrTokenRefused):
		out := "REFUSED: " + w.sc.text(err.Error())
		if fe != nil && fe.TLSVersion != 0 {
			out += " [" + tls.VersionName(fe.TLSVersion) + "]"
		}
		if _, decided := m3aAnswered(err); !decided {
			out += " (no decision: this answer tests nothing)"
		}
		return out
	case errors.Is(err, kube.ErrCredentialInvalid), errors.Is(err, kube.ErrEndpointRefused):
		return "NOT SENT (refused before sending): " + w.sc.text(err.Error())
	}
	return "NOT ANSWERED: " + w.sc.text(err.Error())
}

// accepted describes an exchange's answer: never its token.
func m3aAccepted(a *kube.ExchangeAnswer) string {
	return fmt.Sprintf("issued_token_type access_token, lifetime %s, TLS 1.3: %s",
		m3aSeconds(a.ExpiresIn()), m3aYesNo(a.TLSVersion() == tls.VersionTLS13))
}

// since is the step's own mark.
func (w *m3aWalk) since() time.Time {
	w.t.Helper()
	t, err := m3aStepSince(w.st.Marks, w.step, os.Getenv("FARCAST_WALK_M3A_SINCE"))
	if err != nil {
		w.t.Fatal(err)
	}
	return t
}

// acceptedLine is a positive's ACCEPTED line, with both deltas, how far its
// delta is a settle time (m3aTimingNote), and what came.
func (w *m3aWalk) acceptedLine(since time.Time, o m3aOutcome, detail string) string {
	notes := []string{}
	if n := m3aLatestNote(since.Add(o.delta), since, w.st.Marks); n != "" {
		notes = append(notes, n)
	}
	if n := m3aTimingNote(o); n != "" {
		notes = append(notes, n)
	}
	notes = append(notes, detail)
	return "ACCEPTED after " + m3aSeconds(o.delta) + " (" + strings.Join(notes, "; ") + ")"
}

// boundNote is a line's timing note at the bound, in parentheses, or "".
func m3aBoundNote(o m3aOutcome) string {
	if n := m3aTimingNote(o); n != "" {
		return " (" + n + ")"
	}
	return ""
}

// positive tries an exchange under the settle rule from since, and prints
// its line. It returns the answer, or nil.
func (w *m3aWalk) positive(label string, since time.Time, try func() (*kube.ExchangeAnswer, error)) *kube.ExchangeAnswer {
	a, _ := w.positiveVerdict(label, since, try)
	return a
}

// positiveVerdict is positive with its gating verdict (m3aPositiveVerdict):
// holds, FAILS on a decision against it, or INCONCLUSIVE when its last
// answer was no decision, so the step is run again.
func (w *m3aWalk) positiveVerdict(label string, since time.Time, try func() (*kube.ExchangeAnswer, error)) (*kube.ExchangeAnswer, string) {
	var ans *kube.ExchangeAnswer
	var last error
	o := m3aPositiveOutcome(w.ctx, w.clock, since, func() bool {
		a, err := try()
		if err == nil {
			ans = a
			return true
		}
		w.notSent(label, err)
		last = err
		return false
	})
	w.positiveLine(label, since, o, ans, last)
	if o.ok {
		return ans, m3aHolds
	}
	return nil, m3aPositiveVerdict(false, last)
}

// positiveLine prints a positive's line: its acceptance, with both deltas and
// what came, or its last refusal at the bound.
func (w *m3aWalk) positiveLine(label string, since time.Time, o m3aOutcome, ans *kube.ExchangeAnswer, last error) {
	if o.ok && ans != nil {
		w.say("%s: %s", label, w.acceptedLine(since, o, m3aAccepted(ans)))
		return
	}
	if last == nil {
		last = errors.New("not tried")
	}
	w.say("%s: %s at the bound (%s from the mark)%s: %s", label, m3aBoundWords(last), m3aSeconds(m3aSettleBound), m3aBoundNote(o), w.refusal(last))
}

// m3aBoundWords is how a positive's line names its end at the bound: "still
// refused" after a decision against it, else "no decision".
func m3aBoundWords(last error) string {
	if m3aPositiveVerdict(false, last) == m3aInconclusive {
		return "no decision"
	}
	return "still refused"
}

// impersonate calls generateAccessToken for an SA under the settle rule from
// since, and prints its line. It returns the SA token, which is never
// printed.
func (w *m3aWalk) impersonate(label string, since time.Time, fed *auth.Token, role string) *auth.Token {
	tok, _ := w.impersonateVerdict(label, since, fed, role)
	return tok
}

// impersonateVerdict is impersonate with its gating verdict. Not tried, with
// no federated token, it is INCONCLUSIVE: the exchange that made no token
// carries the verdict, FAILS or INCONCLUSIVE.
func (w *m3aWalk) impersonateVerdict(label string, since time.Time, fed *auth.Token, role string) (*auth.Token, string) {
	if fed == nil {
		w.say("%s: not tried (no federated token)", label)
		return nil, m3aInconclusive
	}
	var tok *auth.Token
	var last error
	o := m3aPositiveOutcome(w.ctx, w.clock, since, func() bool {
		t, err := w.federation().Impersonate(w.ctx, fed, w.email(role))
		if err == nil && t != nil && t.Value != "" {
			tok = t
			return true
		}
		w.notSent(label, err)
		last = err
		return false
	})
	return tok, w.impersonationLine(label, since, o, tok, last)
}

// impersonationLine prints an impersonation's line and returns its gating
// verdict: its acceptance, with both deltas, its timing note and when the SA
// token expires; or its last refusal at the bound.
func (w *m3aWalk) impersonationLine(label string, since time.Time, o m3aOutcome, tok *auth.Token, last error) string {
	if o.ok && tok != nil {
		mins := int(time.Until(tok.Expiry).Round(time.Minute) / time.Minute)
		w.say("%s: %s", label, w.acceptedLine(since, o, fmt.Sprintf("a token came: yes; expires in about %d min", mins)))
		return m3aHolds
	}
	if last == nil {
		w.say("%s: still refused at the bound (%s from the mark)%s: answered without a token", label, m3aSeconds(m3aSettleBound), m3aBoundNote(o))
		return m3aFails
	}
	w.say("%s: %s at the bound (%s from the mark)%s: %s", label, m3aBoundWords(last), m3aSeconds(m3aSettleBound), m3aBoundNote(o), w.refusal(last))
	return m3aPositiveVerdict(false, last)
}

// m3aRoundTarget is one provider a round-robin sends to: its label, its
// audience, what the handshake presents, and the shapes it tries.
type m3aRoundTarget struct {
	label  string
	aud    string
	p      m3aPresent
	shapes []m3aShape
}

// m3aFollow is an impersonation a round-robin polls once a target has an
// accepted shape (m3aRoundsReady): with the token of the target's first
// accepted answer (shape 0), or of one shape's, at role's SA. So a binding's
// first settle time is measured from the same mark, at the same times, as the
// exchanges are, not after their round-robin has run to its bound.
type m3aFollow struct {
	label  string
	target int
	shape  m3aShape
	role   string
}

// m3aRoundsResult is a round-robin's result: per target, which shapes passed,
// their answers and its verdict as a gating positive (m3aAnyShapeVerdict);
// per follow, its verdict (INCONCLUSIVE when never tried: the exchange that
// made no token carries the verdict) and its SA token, or nil.
type m3aRoundsResult struct {
	passed   [][4]bool
	answers  [][4]*kube.ExchangeAnswer
	verdicts []string
	follows  []string
	tokens   []*auth.Token
}

// rounds sends every target's shapes, and each follow once it is ready, in
// one round-robin from since (m3aRoundsReady), so each entry's settle time is
// measured from the mark, not from the end of another entry's tries. It prints
// one line per target and shape, then one per follow.
func (w *m3aWalk) rounds(since time.Time, targets []m3aRoundTarget, follows []m3aFollow) m3aRoundsResult {
	type entry struct{ target, i int }
	var entries []entry
	for t, tg := range targets {
		for i := range tg.shapes {
			entries = append(entries, entry{t, i})
		}
	}
	n := len(entries)
	r := m3aRoundsResult{
		passed:   make([][4]bool, len(targets)),
		answers:  make([][4]*kube.ExchangeAnswer, len(targets)),
		verdicts: make([]string, len(targets)),
		follows:  make([]string, len(follows)),
		tokens:   make([]*auth.Token, len(follows)),
	}
	lasts := make([][]error, len(targets))
	for t, tg := range targets {
		lasts[t] = make([]error, len(tg.shapes))
	}
	first := make([]*kube.ExchangeAnswer, len(targets))
	followLast := make([]error, len(follows))
	source := func(f m3aFollow) *kube.ExchangeAnswer {
		if f.shape == 0 {
			return first[f.target]
		}
		return r.answers[f.target][f.shape-1]
	}
	out := m3aRoundsReady(w.ctx, w.clock, since, n+len(follows), func(k int) bool {
		return k < n || source(follows[k-n]) != nil
	}, func(k int) bool {
		if k < n {
			e := entries[k]
			tg := targets[e.target]
			a, err := w.exchange(tg.aud, tg.p, tg.shapes[e.i], nil)
			if err != nil {
				w.notSent(tg.label, err)
				lasts[e.target][e.i] = err
				return false
			}
			r.answers[e.target][tg.shapes[e.i]-1] = a
			if first[e.target] == nil {
				first[e.target] = a
			}
			return true
		}
		j := k - n
		f := follows[j]
		tok, err := w.federation().Impersonate(w.ctx, source(f).Token(), w.email(f.role))
		if err == nil && tok != nil && tok.Value != "" {
			r.tokens[j] = tok
			return true
		}
		w.notSent(f.label, err)
		followLast[j] = err
		return false
	})
	for k, e := range entries {
		tg, o := targets[e.target], out[k]
		s := tg.shapes[e.i]
		if o.ok {
			r.passed[e.target][s-1] = true
			w.say("%s %s: %s", tg.label, s, w.acceptedLine(since, o, m3aAccepted(r.answers[e.target][s-1])))
		} else {
			w.say("%s %s: %s at the bound%s: %s", tg.label, s, m3aBoundWords(lasts[e.target][e.i]), m3aBoundNote(o), w.refusal(lasts[e.target][e.i]))
		}
	}
	for t := range targets {
		r.verdicts[t] = m3aAnyShapeVerdict(r.passed[t] != [4]bool{}, lasts[t])
	}
	for j, f := range follows {
		o := out[n+j]
		if o.tries == 0 {
			w.say("%s: not tried (no shape of its own was accepted)", f.label)
			r.follows[j] = m3aInconclusive
			continue
		}
		r.follows[j] = w.impersonationLine(f.label, since, o, r.tokens[j], followLast[j])
	}
	return r
}

// shapesFor is what this step sends to a provider whose role's shape is
// recorded under key.
func (w *m3aWalk) shapesFor(key string) []m3aShape {
	w.t.Helper()
	s, err := m3aStepShapes(w.st, w.step, key)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

// shapeFor is this step's one shape for key: T1's simplest.
func (w *m3aWalk) shapeFor(key string) m3aShape { return w.shapesFor(key)[0] }

// m3aPassedList is "S1, S3".
func m3aPassedList(passed [4]bool) string {
	var out []string
	for i, ok := range passed {
		if ok {
			out = append(out, m3aShapes[i].String())
		}
	}
	return strings.Join(out, ", ")
}

// verdictT1 prints a T1-shaped verdict and fails the step when no shape
// passed: FAILS when each shape was refused with a decision, INCONCLUSIVE
// when a shape's last answer was no decision, so the step is run again.
func (w *m3aWalk) verdictT1(name string, passed [4]bool, verdict string) {
	if s, ok := m3aSimplest(passed); ok {
		w.say("%s: holds (%s pass; the simplest is %s)", name, m3aPassedList(passed), s)
		return
	}
	if verdict == m3aInconclusive {
		w.say("%s: INCONCLUSIVE (no shape passed, and a shape's last answer was no decision: run the step again)", name)
		w.t.Errorf("a gating positive was not decided; run the step again")
		return
	}
	w.say("%s: FAILS (every shape refused)", name)
	w.t.Errorf("a gating positive failed; see its lines")
}

// gate prints a gating positive's verdict line, and fails the step unless it
// holds.
func (w *m3aWalk) gate(name, verdict string) {
	switch verdict {
	case m3aHolds:
		w.say("%s: holds", name)
	case m3aInconclusive:
		w.say("%s: INCONCLUSIVE (an answer was no decision: run the step again)", name)
		w.t.Errorf("a gating positive was not decided; run the step again")
	default:
		w.say("%s: FAILS", name)
		w.t.Errorf("a gating positive failed; see its lines")
	}
}

// ---- Probe-only clients ----

// probeSend makes one request through a probe-only client (m3aHTTPClient, in
// walkm3ablocks_test.go, with its host guard). A transport
// failure is its inner error, never the *url.Error, which names the URL.
func (w *m3aWalk) probeSend(host string, cert *tls.Certificate, method, path string, header http.Header, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(w.ctx, method, "https://"+host+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("the request could not be built")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := m3aHTTPClient(host, cert).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := m3aReadLimited(resp.Body, walkMaxBody)
	return resp.StatusCode, b, err
}

// m3aGoogleStatus is a Google JSON error's status, shape-checked, or "none".
func m3aGoogleStatus(body []byte) string {
	var g struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &g) != nil {
		return "none"
	}
	var e struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(g.Error, &e) != nil || len(e.Status) < 1 || len(e.Status) > 64 {
		return "none"
	}
	for _, c := range e.Status {
		if (c < 'A' || c > 'Z') && c != '_' {
			return "none"
		}
	}
	return e.Status
}

// m3aSTSAnswer is a plain STS answer, read for V5 and I6.
type m3aSTSAnswer struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

// plainExchange posts a form to STS's plain endpoint, with no client
// certificate. It returns the status, with sent false when no answer came
// (m3aPlainAnswered reads the two); what came, never the token: on
// acceptance the issued type and lifetime, else the refusal; and the token
// when a usable one came. Any 200 is an acceptance, usable or not.
func (w *m3aWalk) plainExchange(form string) (code int, sent bool, line string, tok *auth.Token) {
	code, body, err := w.probeSend(m3aSTSPlainHost, nil, http.MethodPost, kube.STSTokenPath,
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}}, []byte(form))
	defer clear(body)
	if err != nil {
		return 0, false, "NOT ANSWERED: " + w.sc.text(err.Error()), nil
	}
	if code != http.StatusOK {
		line := fmt.Sprintf("REFUSED: status %d %s, OAuth error %s, Google status %s", code, http.StatusText(code), oauthErrorCode(body), m3aGoogleStatus(body))
		if _, decided := m3aPlainAnswered(code, true); !decided {
			line += " (no decision: this status tests nothing)"
		}
		return code, true, line, nil
	}
	var a m3aSTSAnswer
	if json.Unmarshal(body, &a) != nil || a.AccessToken == "" {
		return code, true, "ANSWERED 200 without a usable token", nil
	}
	itt := "another type"
	if a.IssuedTokenType == kube.TokenTypeAccessToken {
		itt = "access_token"
	}
	tok = &auth.Token{Value: a.AccessToken, Type: "Bearer", Expiry: time.Now().Add(time.Duration(a.ExpiresIn) * time.Second)}
	return code, true, fmt.Sprintf("issued_token_type %s, lifetime %d s", itt, a.ExpiresIn), tok
}

// ---- Steps: P0 and P1 ----

// stepInit draws the run's IDs, enrols the four devices, and makes every
// other variant's keys and certificates (P0).
func (w *m3aWalk) stepInit() {
	project := os.Getenv("FARCAST_WALK_PROJECT")
	if !m3aProjectIDShape(project) {
		w.t.Fatal("FARCAST_WALK_PROJECT must be a project ID (6 to 30 of [a-z0-9-], a letter first); its value is not printed")
	}
	now := w.clock.now()
	st := &m3aState{Project: project, Variants: map[string]*m3aVariant{}, Marks: m3aMarks{}}
	st.Pool = w.newObjectID(devicekey.PoolID)
	st.ReaderSA = w.newObjectID(devicekey.ServiceAccountID)
	st.WriterSA = w.newObjectID(devicekey.ServiceAccountID)
	st.APIRecord = w.newObjectID(devicekey.PoolID)
	w.st = st
	devices, keys := 0, 0
	for _, d := range []struct {
		name, dir string
		roles     []devicekey.Role
	}{
		{m3aV1, m3aDeviceA, []devicekey.Role{devicekey.Reader, devicekey.Writer}},
		{m3aV1b, m3aDeviceB, []devicekey.Role{devicekey.Reader}},
		{m3aV1c, m3aDeviceC, []devicekey.Role{devicekey.Reader, devicekey.Writer}},
		{m3aV8, m3aDeviceV8, []devicekey.Role{devicekey.Reader}},
	} {
		_, ids, err := devicekey.Enrol(rand.Reader, filepath.Join(w.dir, d.dir), d.roles, now)
		if err != nil {
			w.stop(w.sc, "enrol %s: %v", d.dir, err)
		}
		v := &m3aVariant{Providers: map[string]string{}, RoleIDs: map[string]string{}, Anchors: map[string][]byte{}}
		for _, id := range ids {
			role := id.Role().String()
			v.Providers[role] = w.newObjectID(devicekey.ProviderID)
			v.RoleIDs[role] = id.ID().Hex()
			v.Anchors[role] = id.AnchorDER()
			w.recordLeaf(id.LeafDER())
			keys += 2
		}
		st.Variants[d.name] = v
		devices++
	}
	st.Variants[m3aV8].Subject = w.newRoleID().Hex() // V8's constant, not its role ID

	variants := 0
	for _, mk := range []struct {
		name string
		make func(io.Reader, time.Time, devicekey.RoleID) (m3aPair, error)
	}{
		{m3aV1x, m3aVariantV1x}, {m3aV1y, m3aVariantV1y}, {m3aV2, m3aVariantV2}, {m3aV3, m3aVariantV3},
		{m3aV4, m3aVariantV4}, {m3aV6, m3aVariantV6}, {m3aV7, m3aVariantV7},
	} {
		id := w.newRoleID()
		pair, err := mk.make(rand.Reader, now, id)
		if err != nil {
			w.stop(w.sc, "make %s: %v", mk.name, err)
		}
		keys += w.writePair(mk.name, pair)
		st.Variants[mk.name] = &m3aVariant{
			Providers: map[string]string{m3aReader: w.newObjectID(devicekey.ProviderID)},
			RoleIDs:   map[string]string{m3aReader: id.Hex()},
			Anchors:   map[string][]byte{m3aReader: pair.anchor.der},
		}
		w.recordLeaf(pair.leaf.der)
		variants++
	}

	v5, err := m3aNewKey(rand.Reader)
	if err != nil {
		w.stop(w.sc, "make V5's key: %v", err)
	}
	w.writeKey(filepath.Join("variants", m3aV5, "signing.key"), v5)
	point, err := v5.PublicKey.Bytes()
	if err != nil {
		w.stop(w.sc, "encode V5's key: %v", err)
	}
	st.Variants[m3aV5] = &m3aVariant{
		Providers: map[string]string{m3aReader: w.newObjectID(devicekey.ProviderID)},
		Subject:   w.newRoleID().Hex(),
		Issuer:    "https://" + w.newObjectID(devicekey.PoolID) + ".invalid",
		KID:       w.newObjectID(devicekey.ProviderID),
		PublicKey: point,
	}
	keys++
	variants++

	readerID, err := devicekey.ParseRoleID(st.roleID(m3aV1, m3aReader))
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	n1, err := m3aAnchor(rand.Reader, readerID, now) // N1's foreign anchor, CN V1's reader ID
	if err != nil {
		w.stop(w.sc, "make N1's anchor: %v", err)
	}
	w.writeCert(filepath.Join("variants", "n1", "anchor.crt"), n1.der)
	w.writeKey(filepath.Join("variants", "n1", "anchor.key"), n1.key)
	w.recordCA(n1.der)
	i7a, err := m3aAnchor(rand.Reader, readerID, now) // I7's second anchor, CN V1's reader ID
	if err != nil {
		w.stop(w.sc, "make I7's anchor: %v", err)
	}
	i7l, err := m3aLeaf(rand.Reader, now, m3aLeafSpec{id: readerID}, i7a)
	if err != nil {
		w.stop(w.sc, "make I7's leaf: %v", err)
	}
	keys += w.writePair("i7", m3aPair{anchor: i7a, leaf: i7l}) + 1
	st.I7Anchor = i7a.der
	w.recordLeaf(i7l.der)
	w.save()
	w.addLiterals()

	fi, err := os.Lstat(w.dir)
	w.say("devices enrolled: %d; variants made: %d, and N1's and I7's anchors; keys made: %d", devices, variants, keys)
	w.say("directory mode 0700: %s", m3aYesNo(err == nil && fi.Mode().Perm() == 0o700))
}

// stepBlocks writes every block that needs no later state. Run again after
// coordinates, it gives console-v1c.txt its principals and leaves every other
// block byte-identical.
func (w *m3aWalk) stepBlocks() {
	w.load()
	blocks, err := m3aStaticBlocks(w.st)
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	for _, name := range m3aStaticBlockNames {
		w.writeBlock(name, blocks[name])
	}
	if w.st.ProjectNumber == "" {
		w.say("console-v1c.txt has no principals yet: they name the project number; run blocks again after coordinates")
	}
}

// stepCoordinates records the project's number from the setup's last line
// (P1). The line is read from a file, never printed, and checked whole.
func (w *m3aWalk) stepCoordinates() {
	w.load()
	path := os.Getenv("FARCAST_WALK_M3A_LINE")
	if path == "" {
		w.t.Fatal("FARCAST_WALK_M3A_LINE is required: the file holding the line setup.sh printed last")
	}
	f, err := os.Open(w.path(path))
	if err != nil {
		w.stop(w.sc, "read the coordinates line: %v", err)
	}
	line, err := m3aReadLimited(f, 256)
	_ = f.Close()
	if err != nil {
		w.t.Fatal("the coordinates file is not one line")
	}
	n, err := m3aParseCoordinates(line, w.st.Project)
	if err != nil {
		w.t.Fatal(err)
	}
	w.st.ProjectNumber = n
	w.save()
	w.say("coordinates recorded: yes; the project matches: yes")
}

// stepMark records now under FARCAST_WALK_M3A_MARK.
func (w *m3aWalk) stepMark() {
	name := os.Getenv("FARCAST_WALK_M3A_MARK")
	if err := m3aCheckMarkName(name); err != nil {
		w.t.Fatal(err)
	}
	w.load()
	if w.st.Marks == nil {
		w.st.Marks = m3aMarks{}
	}
	w.st.Marks.add(name, w.clock.now())
	w.save()
	w.say("marked %s", name)
}

// ---- Steps: P2 and P3 ----

// stepConsole is P2: V1c's two leaves at the providers the console made,
// S1–S4 each, and each accepted one impersonating the reader SA, every entry
// in one round-robin from the console mark: an impersonation is polled from
// the round its shape is accepted in, so each role's settle times, the
// binding's included, are its own.
func (w *m3aWalk) stepConsole() {
	w.load()
	since := w.since()
	roles := []struct{ role, key string }{{m3aReader, m3aShapeV1cReader}, {m3aWriter, m3aShapeV1cWriter}}
	targets := make([]m3aRoundTarget, len(roles))
	var follows []m3aFollow
	for i, r := range roles {
		id := w.reader(m3aDeviceC)
		if r.role == m3aWriter {
			id = w.writer(m3aDeviceC)
		}
		targets[i] = m3aRoundTarget{label: "V1c " + r.role, aud: w.aud(m3aV1c, r.role), p: m3aPresentOf(id), shapes: w.shapesFor(r.key)}
		for _, s := range targets[i].shapes {
			follows = append(follows, m3aFollow{label: "V1c " + r.role + " " + s.String() + " impersonating the reader SA", target: i, shape: s, role: m3aReader})
		}
	}
	res := w.rounds(since, targets, follows)
	if w.st.Shapes == nil {
		w.st.Shapes = map[string][4]bool{}
	}
	for i, r := range roles {
		w.st.Shapes[r.key] = res.passed[i]
		w.say("%s: %s (information)", targets[i].label, map[bool]string{true: "accepted in " + m3aPassedList(res.passed[i]), false: "every shape refused"}[res.passed[i] != [4]bool{}])
	}
	w.save()
}

// stepT1 is P3's T1 and V1b: V1's reader leaf at its reader provider, its
// writer leaf at its writer provider and V1b's reader leaf at V1b's provider,
// each in all four shapes, and, once a role has an accepted shape, its first
// impersonation (V1's reader at the reader SA, V1's writer at the writer SA,
// V1b at the reader SA), every entry in one round-robin from the setup mark
// (m3aRoundsReady). So each exchange's settle time and each binding's first
// settle time is measured from the mark, under the settle rule, and none waits
// for another entry's tries to reach the bound. V1's two impersonations are
// information here (T2 gates in t2); V1b's is V1b's T2, and gates.
func (w *m3aWalk) stepT1() {
	w.load()
	w.v1Rounds(true)
}

// stepV1b is a rerun of V1b alone: its reader as T1, and its impersonation of
// the reader SA, in one round-robin from the setup mark. t1 runs V1b with V1;
// this step is for when V1b alone needs running again.
func (w *m3aWalk) stepV1b() {
	w.load()
	w.v1Rounds(false)
}

// v1Rounds is t1 (withV1) or v1b's rerun: the round-robin, the shapes
// recorded, and the verdicts.
func (w *m3aWalk) v1Rounds(withV1 bool) {
	since := w.since()
	if w.st.Shapes == nil {
		w.st.Shapes = map[string][4]bool{}
	}
	plan, planFollows := m3aT1Plan(withV1)
	devices := map[string]string{m3aV1: m3aDeviceA, m3aV1b: m3aDeviceB}
	targets := make([]m3aRoundTarget, len(plan))
	for i, pt := range plan {
		id := w.reader(devices[pt.variant])
		if pt.role == m3aWriter {
			id = w.writer(devices[pt.variant])
		}
		targets[i] = m3aRoundTarget{label: pt.label, aud: w.aud(pt.variant, pt.role), p: m3aPresentOf(id), shapes: w.shapesFor(pt.key)}
	}
	follows := make([]m3aFollow, len(planFollows))
	for j, f := range planFollows {
		follows[j] = m3aFollow{label: f.label, target: f.target, role: f.role}
	}
	r := w.rounds(since, targets, follows)
	for i, pt := range plan {
		w.st.Shapes[pt.key] = r.passed[i]
	}
	w.save()
	for i, pt := range plan {
		w.verdictT1(pt.verdict, r.passed[i], r.verdicts[i])
	}
	for j, f := range planFollows {
		if _, ok := m3aSimplest(r.passed[f.target]); f.gating && ok {
			w.gate("V1b T2", r.follows[j])
		}
	}
}

// tokenInfo asks token info about an SA token, by POST with the token in the
// body, never in a query, prints the reduced facts, and returns its part in
// T2's verdict (m3aT2TokenInfo): a 200 must list both scopes; a status other
// than 200 is "not answered by POST", and T2 then holds on the impersonation
// alone; no answer, or one not readable, is INCONCLUSIVE.
func (w *m3aWalk) tokenInfo(tok *auth.Token, role string) string {
	if tok == nil {
		w.say("token info: not asked (no SA token)")
		return m3aInconclusive // the impersonation's own verdict decides
	}
	code, body, err := w.probeSend(m3aTokenInfoHost, nil, http.MethodPost, "/tokeninfo",
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(url.Values{"access_token": {tok.Value}}.Encode()))
	defer clear(body)
	var f m3aTokenInfoFacts
	var readErr error
	switch {
	case err != nil:
		w.say("token info (POST): NOT ANSWERED: %s", w.sc.text(err.Error()))
	case code != http.StatusOK:
		w.say("token info (POST): status %d %s; token info not answered by POST", code, http.StatusText(code))
	default:
		f, readErr = m3aTokenInfo(body, w.email(role))
		if readErr != nil {
			w.say("token info (POST): status 200; %v", readErr)
			break
		}
		scopes := strings.Join(f.scopes, ", ")
		if scopes == "" {
			scopes = "none"
		}
		expires := "expires_in " + f.expiresIn
		if n, err := strconv.Atoi(f.expiresIn); err == nil {
			expires = fmt.Sprintf("expires in about %d min", (n+30)/60)
		}
		w.say("token info (POST): status 200; email matches: %s; scopes: %s; %s", f.email, scopes, expires)
	}
	v := m3aT2TokenInfo(err == nil, code, f, readErr)
	why := map[string]string{
		m3aHolds:        "both scopes listed, or token info not answered by POST",
		m3aFails:        "token info answered and does not list both cloud-platform and userinfo.email",
		m3aInconclusive: "token info not answered, or not readable: run t2 again",
	}[v]
	if v == m3aHolds && code != http.StatusOK {
		why = "on the impersonation's 200 alone: token info not answered by POST"
	}
	w.say("T2 %s token info: %s (%s)", role, v, why)
	return v
}

// stepT2 is P3's T2: each role's federated token impersonates its own SA,
// both roles' exchanges and impersonations in one round-robin from the setup
// mark, and token info reads each SA token, whose two scopes are part of T2's
// verdict (tokenInfo).
func (w *m3aWalk) stepT2() {
	w.load()
	since := w.since()
	roles := []struct{ role, key string }{{m3aReader, m3aShapeV1Reader}, {m3aWriter, m3aShapeV1Writer}}
	targets := make([]m3aRoundTarget, len(roles))
	follows := make([]m3aFollow, len(roles))
	for i, r := range roles {
		id := w.reader(m3aDeviceA)
		if r.role == m3aWriter {
			id = w.writer(m3aDeviceA)
		}
		targets[i] = m3aRoundTarget{label: "T2 " + r.role + " exchange", aud: w.aud(m3aV1, r.role), p: m3aPresentOf(id), shapes: []m3aShape{w.shapeFor(r.key)}}
		follows[i] = m3aFollow{label: "T2 " + r.role + " impersonating the " + r.role + " SA", target: i, role: r.role}
	}
	res := w.rounds(since, targets, follows)
	var verdicts []string
	for i, r := range roles {
		verdicts = append(verdicts, res.verdicts[i], res.follows[i], w.tokenInfo(res.tokens[i], r.role))
	}
	w.gate("T2", m3aWorstVerdict(verdicts...))
}

// stepT3 is P3's T3: the current reader leaf is saved as old, both leaves are
// renewed with no console step, and each new leaf exchanges.
func (w *m3aWalk) stepT3() {
	w.load()
	since := w.since()
	old := w.reader(m3aDeviceA)
	w.st.OldReaderLeaf = old.LeafDER()
	s := w.store(m3aDeviceA)
	nr, err := s.RenewReaderLeaf(rand.Reader, w.clock.now())
	if err != nil {
		w.stop(w.sc, "renew the reader leaf: %v", err)
	}
	nw, err := s.RenewWriterLeaf(devicekey.GiveConsent(devicekey.ConsentConfirmed), rand.Reader, w.clock.now())
	if err != nil {
		w.stop(w.sc, "renew the writer leaf: %v", err)
	}
	w.recordLeaf(nr.LeafDER(), nw.LeafDER())
	w.save()
	for _, r := range []struct {
		role, key string
		id        devicekey.Identity
	}{{m3aReader, m3aShapeV1Reader, nr}, {m3aWriter, m3aShapeV1Writer, nw}} {
		w.say("T3 %s: renewed", r.role)
		shape := w.shapeFor(r.key)
		_, v := w.positiveVerdict("T3 "+r.role+" new leaf ("+shape.String()+")", since, func() (*kube.ExchangeAnswer, error) {
			return w.exchange(w.aud(m3aV1, r.role), m3aPresentOf(r.id), shape, nil)
		})
		w.gate("T3 "+r.role, v)
	}
}

// stepT4 is P3's T4: through the reader's own SA token, V1's two providers
// read back, each checked by devicekey.CheckProvider. The exchange and the
// impersonation go in one round-robin from the setup mark; then both
// read-backs are polled in one loop from the same mark until each answers
// 200, under the settle rule, since the reader SA's pool viewer grant is an
// IAM change of the same paste (m3aReadBackPollVerdict).
func (w *m3aWalk) stepT4() {
	w.load()
	since := w.since()
	res := w.rounds(since,
		[]m3aRoundTarget{{label: "T4 reader exchange", aud: w.aud(m3aV1, m3aReader), p: m3aPresentOf(w.reader(m3aDeviceA)), shapes: []m3aShape{w.shapeFor(m3aShapeV1Reader)}}},
		[]m3aFollow{{label: "T4 reader impersonating the reader SA", target: 0, role: m3aReader}})
	verdicts := []string{res.verdicts[0], res.follows[0]}
	sa := res.tokens[0]
	roles := []devicekey.Role{devicekey.Reader, devicekey.Writer}
	if sa == nil {
		for _, r := range roles {
			w.say("T4 %s provider: not read (no SA token)", r)
		}
		w.gate("T4", m3aWorstVerdict(verdicts...))
		return
	}
	type readBack struct {
		anchor []byte
		id     devicekey.RoleID
		code   int
		body   []byte
		err    error
	}
	rb := make([]readBack, len(roles))
	for i, r := range roles {
		anchorDER, _, id, err := w.store(m3aDeviceA).Certificates(r)
		if err != nil {
			w.stop(w.sc, "read V1's %s certificates: %v", r, err)
		}
		rb[i].anchor, rb[i].id = anchorDER, id
	}
	out := m3aRoundsReady(w.ctx, w.clock, since, len(roles), nil, func(i int) bool {
		clear(rb[i].body)
		path := "/v1/projects/" + w.st.ProjectNumber + "/locations/global/workloadIdentityPools/" + w.st.Pool + "/providers/" + w.st.provider(m3aV1, roles[i].String())
		rb[i].code, rb[i].body, rb[i].err = w.probeSend(m3aIAMHost, nil, http.MethodGet, path, http.Header{"Authorization": {"Bearer " + sa.Value}, "Accept": {"application/json"}}, nil)
		return rb[i].err == nil && rb[i].code == http.StatusOK
	})
	for i, r := range roles {
		o, b := out[i], rb[i]
		matched := false
		switch {
		case o.ok:
			if err := devicekey.CheckProvider(b.body, b.anchor, b.id); err != nil {
				w.say("T4 %s provider: status 200 after %s%s; differs: %s", r, m3aSeconds(o.delta), m3aBoundNote(o), w.sc.text(err.Error()))
			} else {
				matched = true
				w.say("T4 %s provider: %s", r, w.acceptedLine(since, o, "status 200; trust store, mapping, condition and state match: yes"))
			}
		case b.err != nil:
			w.say("T4 %s provider: NOT ANSWERED at the bound%s: %s", r, m3aBoundNote(o), w.sc.text(b.err.Error()))
		default:
			w.say("T4 %s provider: status %d %s, Google status %s, at the bound%s", r, b.code, http.StatusText(b.code), m3aGoogleStatus(b.body), m3aBoundNote(o))
		}
		verdicts = append(verdicts, m3aReadBackPollVerdict(b.err == nil, b.code, matched))
		clear(b.body)
	}
	w.gate("T4", m3aWorstVerdict(verdicts...))
}

// ---- Step: P4, the negatives ----

// m3aNeg is one negative: what it sends, its positive control, and its two
// checks' lines.
type m3aNeg struct {
	name   string
	gating string // "" for information; else what it gates as
	send   func() error
	ctrl   func() error
	not403 bool // N4 and N10 note a status that is not 403
	checks int
}

// check runs the negative and its control once and prints both.
func (w *m3aWalk) check(n *m3aNeg) m3aCheck {
	n.checks++
	err := n.send()
	acc, _ := m3aAnswered(err)
	cerr := n.ctrl()
	cacc, _ := m3aAnswered(cerr)
	what := "ACCEPTED"
	if !acc {
		what = w.refusal(err)
		var fe *kube.FederationError
		if n.not403 && errors.As(err, &fe) && fe.Status != http.StatusForbidden {
			what += " (the status is not 403)"
		}
	}
	ctl := "ACCEPTED"
	if !cacc {
		ctl = w.refusal(cerr)
	}
	w.say("%s check %d: %s; control: %s", n.name, n.checks, what, ctl)
	// A negative neither accepted nor refused (not sent, not answered, or
	// answered with no decision: a 3xx, a 429, a 5xx) tested nothing: it reads
	// as its control refused.
	return m3aCheckOf(err, cerr)
}

// stepNegatives is P4: N1 to N10, each in the simplest shape T1 recorded for
// its target provider's role, beside its positive control through the same
// Federation, checked at once and again after the settle bound.
func (w *m3aWalk) stepNegatives() {
	w.load()
	rs, ws := w.shapeFor(m3aShapeV1Reader), w.shapeFor(m3aShapeV1Writer)
	bs, _ := w.st.simplest(m3aShapeV1b)
	if len(w.st.OldReaderLeaf) == 0 {
		w.t.Fatal("N5 (i) needs the old reader leaf t3 saves; run t3 first")
	}
	latest, ok := w.st.Marks.latest()
	if !ok {
		w.t.Fatal("no mark is recorded; the negatives measure from the latest")
	}
	now := w.clock.now()
	rAnchor, readerID := w.v1ReaderAnchor()
	writerID := w.roleIDOf(m3aDeviceA, devicekey.Writer)
	v1bID := w.roleIDOf(m3aDeviceB, devicekey.Reader)
	n1Anchor := w.readCert(filepath.Join("variants", "n1", "anchor"), true)
	neg, err := m3aMakeNegativeLeaves(rand.Reader, now, rAnchor, n1Anchor, readerID, writerID, v1bID)
	if err != nil {
		w.stop(w.sc, "make the negatives' chains: %v", err)
	}
	w.recordLeaf(neg.n1.der, neg.n2a.der, neg.n2b.der, neg.n7r.der, neg.n7w.der, neg.n8Expired.der, neg.n8NotYet.der, neg.n9a.der)
	w.recordCA(neg.n2bMid.der, neg.n7rMid.der, neg.n7wMid.der)
	w.save()

	reader, writer, v1b := w.reader(m3aDeviceA), w.writer(m3aDeviceA), w.reader(m3aDeviceB)
	_, writerLeaf, _, err := w.store(m3aDeviceA).Certificates(devicekey.Writer)
	if err != nil {
		w.stop(w.sc, "read V1's writer leaf: %v", err)
	}
	audR, audW, audB := w.aud(m3aV1, m3aReader), w.aud(m3aV1, m3aWriter), w.aud(m3aV1b, m3aReader)
	send := func(aud string, p m3aPresent, s m3aShape) func() error {
		return func() error { _, err := w.exchange(aud, p, s, nil); return err }
	}
	sendSplit := func(aud string, tlsP *m3aPresent, tlsShape m3aShape, subject [][]byte) func() error {
		return func() error {
			var client kube.ClientIdentity // the zero ClientIdentity presents no certificate (N6)
			if tlsP != nil {
				chain, _ := tlsShape.chains(tlsP.leaf, tlsP.mid, tlsP.anchor)
				client = kube.NewClientIdentity(chain, tlsP.signer)
			}
			_, err := w.federation().Exchange(w.ctx, kube.NewExchangeRequest(aud, client, subject, nil))
			return err
		}
	}
	ctrlR := send(audR, m3aPresentOf(reader), rs)
	ctrlW := send(audW, m3aPresentOf(writer), ws)
	readerP, writerP := m3aPresentOf(reader), m3aPresentOf(writer)
	_, oldSubject := rs.chains(w.st.OldReaderLeaf, nil, reader.AnchorDER())
	_, writerSubject := ws.chains(writerLeaf, nil, writer.AnchorDER())

	// The federated tokens N4 and N10 impersonate with, made once.
	token := func(aud string, p m3aPresent, s m3aShape) *auth.Token {
		a, err := w.exchange(aud, p, s, nil)
		if err != nil {
			w.say("a token for N4 or N10 was not made: %s", w.refusal(err))
			return nil
		}
		return a.Token()
	}
	var v1bTok *auth.Token
	if bs != 0 {
		v1bTok = token(audB, m3aPresentOf(v1b), bs)
	}
	readerTok, writerTok := token(audR, readerP, rs), token(audW, writerP, ws)
	imp := func(tok *auth.Token, role string) func() error {
		return func() error { _, err := w.federation().Impersonate(w.ctx, tok, w.email(role)); return err }
	}

	negs := []*m3aNeg{
		{name: "N1", gating: "yes", send: send(audR, m3aPresentCert(neg.n1, n1Anchor.der), rs), ctrl: ctrlR},
		{name: "N2 (a)", gating: "yes", send: send(audR, m3aPresentCert(neg.n2a, rAnchor.der), rs), ctrl: ctrlR},
		{name: "N2 (b)", gating: "yes", send: send(audR, m3aPresentCert(neg.n2b, rAnchor.der, neg.n2bMid), rs), ctrl: ctrlR},
		{name: "N3", gating: "yes", send: send(audR, m3aPresentOf(v1b), rs), ctrl: ctrlR},
		{name: "N4", gating: "yes", send: imp(v1bTok, m3aWriter), ctrl: imp(v1bTok, m3aReader), not403: true},
		{name: "N5 (i)", gating: "yes", send: sendSplit(audR, &readerP, rs, oldSubject), ctrl: ctrlR},
		{name: "N5 (ii)", gating: "yes", send: sendSplit(audW, &readerP, ws, writerSubject), ctrl: ctrlW},
		{name: "N6", gating: "yes", send: sendSplit(audW, nil, ws, writerSubject), ctrl: ctrlW},
		{name: "N7 (i)", send: send(audR, m3aPresentCert(neg.n7r, rAnchor.der, neg.n7rMid), rs), ctrl: ctrlR},
		{name: "N7 (ii)", gating: "as N9", send: send(audR, m3aPresentCert(neg.n7w, rAnchor.der, neg.n7wMid), rs), ctrl: ctrlR},
		{name: "N7 (iii)", gating: "as N1", send: send(audW, m3aPresentCert(neg.n7w, rAnchor.der, neg.n7wMid), ws), ctrl: ctrlW},
		{name: "N8 expired", send: send(audR, m3aPresentCert(neg.n8Expired, rAnchor.der), rs), ctrl: ctrlR},
		{name: "N8 not yet valid", send: send(audR, m3aPresentCert(neg.n8NotYet, rAnchor.der), rs), ctrl: ctrlR},
		{name: "N9 (a) at the reader provider", gating: "yes", send: send(audR, m3aPresentCert(neg.n9a, rAnchor.der), rs), ctrl: ctrlR},
		{name: "N9 (a) at the writer provider", gating: "yes", send: send(audW, m3aPresentCert(neg.n9a, rAnchor.der), ws), ctrl: ctrlW},
		{name: "N9 (b)", gating: "yes", send: send(audW, readerP, ws), ctrl: ctrlW},
		{name: "N9 (c)", gating: "yes", send: send(audR, writerP, rs), ctrl: ctrlR},
		// N10's control is both other cells: the writer's token at the writer
		// SA, and the reader's own token at the reader SA, so a reader token
		// IAM Credentials does not authenticate is no control (N4's is the
		// same token at its own SA).
		{name: "N10", gating: "yes", send: imp(readerTok, m3aWriter), ctrl: m3aBothAccepted(imp(readerTok, m3aReader), imp(writerTok, m3aWriter)), not403: true},
	}
	checks := make([]func() m3aCheck, len(negs))
	for i, n := range negs {
		checks[i] = func() m3aCheck { return w.check(n) }
	}
	w.say("first checks; the second come at the later of the latest mark + %s and 60 s after the last first check", m3aSeconds(m3aSettleBound))
	first, second := m3aNegatives(w.ctx, w.clock, latest, checks)
	failed := false
	for i, n := range negs {
		v := m3aVerdict(first[i], second[i])
		gate := "information"
		if n.gating == "yes" {
			gate = "gating"
		} else if n.gating != "" {
			gate = "gating " + n.gating
		}
		w.say("%s: %s (%s)", n.name, v, gate)
		if n.gating != "" && v != m3aHolds {
			failed = true
		}
	}
	if failed {
		w.t.Errorf("a gating negative did not hold (FAILS or INCONCLUSIVE); see its lines")
	}
}

// ---- Steps: P5 ----

// m3aVariantTarget is one probe-made variant a round-robin sends to.
type m3aVariantTarget struct {
	label, variant string
	p              m3aPresent
}

// variantRounds sends each variant to its provider, in T1's reader shape or
// S1–S4 when T1 recorded none, and, once a variant has an accepted shape, its
// impersonation of the reader SA, every entry in one round-robin from since.
func (w *m3aWalk) variantRounds(since time.Time, shapes []m3aShape, vs []m3aVariantTarget) {
	targets := make([]m3aRoundTarget, len(vs))
	follows := make([]m3aFollow, len(vs))
	for i, v := range vs {
		targets[i] = m3aRoundTarget{label: v.label, aud: w.aud(v.variant, m3aReader), p: v.p, shapes: shapes}
		follows[i] = m3aFollow{label: v.label + " impersonating the reader SA", target: i, role: m3aReader}
	}
	w.rounds(since, targets, follows)
}

// stepVariants is P5's V2 to V8: V2 to V4, V6 to V8 in one round-robin, then
// V5's JWT.
func (w *m3aWalk) stepVariants() {
	w.load()
	since := w.since()
	var vs []m3aVariantTarget
	for _, v := range []string{m3aV2, m3aV3, m3aV4, m3aV6, m3aV7} {
		p := w.readPair(v)
		anchor := p.anchor.der
		if bytes.Equal(p.anchor.der, p.leaf.der) {
			anchor = nil // V3: its one certificate is its own anchor
		}
		vs = append(vs, m3aVariantTarget{strings.ToUpper(v[:1]) + v[1:], v, m3aPresentCert(p.leaf, anchor)})
	}
	vs = append(vs, m3aVariantTarget{"V8", m3aV8, m3aPresentOf(w.reader(m3aDeviceV8))})
	w.variantRounds(since, w.shapesFor(m3aShapeV1Reader), vs)
	w.v5(since)
}

// v5Sender is V5's exchange, once per call: a fresh ES256 JWT at STS's plain
// endpoint, as the token type given. Its key is read once.
func (w *m3aWalk) v5Sender() func(tokenType string) (code int, sent bool, line string, tok *auth.Token) {
	v := w.st.variant(m3aV5)
	key := w.readKey(filepath.Join("variants", m3aV5, "signing.key"))
	jwtAud := m3aV5Audience(w.st.ProjectNumber, w.st.Pool, v.Providers[m3aReader])
	stsAud := w.aud(m3aV5, m3aReader)
	return func(tokenType string) (int, bool, string, *auth.Token) {
		jwt, err := m3aES256JWT(rand.Reader, key, v.KID, v.Issuer, v.Subject, jwtAud, time.Now())
		if err != nil {
			w.stop(w.sc, "sign V5's JWT: %v", err)
		}
		return w.plainExchange(kube.ExchangeForm(stsAud, tokenType, jwt, []string{kube.ScopeCloudPlatform}))
	}
}

// v5 is V5's exchange: an ES256 JWT at STS's plain endpoint, as the jwt token
// type under the settle rule, then once as id_token if that was refused.
func (w *m3aWalk) v5(since time.Time) {
	send := w.v5Sender()
	var line string
	var tok *auth.Token
	o := m3aPositiveOutcome(w.ctx, w.clock, since, func() bool {
		_, _, line, tok = send(m3aTokenTypeJWT)
		return tok != nil
	})
	if o.ok {
		w.say("V5 (jwt): %s", w.acceptedLine(since, o, line))
	} else {
		w.say("V5 (jwt): still refused at the bound%s: %s", m3aBoundNote(o), line)
		_, _, line, tok = send(m3aTokenTypeIDToken)
		if tok != nil {
			line = "ACCEPTED (" + line + ")"
		}
		w.say("V5 (id_token), once: %s", line)
	}
	w.impersonate("V5 impersonating the reader SA", since, tok, m3aReader)
}

// stepContingentBlocks writes contingent.sh, only if T1 refused every shape
// for a role.
func (w *m3aWalk) stepContingentBlocks() {
	w.load()
	needed := false
	for _, k := range []string{m3aShapeV1Reader, m3aShapeV1Writer} {
		passed, ok := w.st.Shapes[k]
		if !ok {
			w.t.Fatal("t1 has not recorded its shapes; run t1 first")
		}
		if passed == [4]bool{} {
			needed = true
		}
	}
	if !needed {
		w.say("contingent.sh: not needed: T1 passed")
		return
	}
	b, err := m3aContingentBlock(w.st)
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	w.writeBlock("contingent.sh", b)
}

// stepContingent is P5's V1x and V1y, S1–S4 each, and each one's
// impersonation of the reader SA, in one round-robin from the contingent
// mark, so V1y's settle times are not taken after V1x's bound.
func (w *m3aWalk) stepContingent() {
	w.load()
	since := w.since()
	var vs []m3aVariantTarget
	for _, v := range []string{m3aV1x, m3aV1y} {
		p := w.readPair(v)
		vs = append(vs, m3aVariantTarget{strings.ToUpper(v[:1]) + v[1:], v, m3aPresentCert(p.leaf, p.anchor.der)})
	}
	w.variantRounds(since, w.shapesFor(m3aShapeV1Reader), vs)
}

// readerExchange is the I steps' reader exchange in T1's reader shape.
func (w *m3aWalk) readerExchange(label string, since time.Time, scopes []string) *kube.ExchangeAnswer {
	shape := w.shapeFor(m3aShapeV1Reader)
	reader := w.reader(m3aDeviceA)
	return w.positive(label+" ("+shape.String()+")", since, func() (*kube.ExchangeAnswer, error) {
		return w.exchange(w.aud(m3aV1, m3aReader), m3aPresentOf(reader), shape, scopes)
	})
}

// stepI1 is I1: generateAccessToken at IAM Credentials' mTLS host, with V1's
// reader leaf as the client certificate and without, through the probe-only
// client.
func (w *m3aWalk) stepI1() {
	w.load()
	a := w.readerExchange("I1 reader exchange", w.since(), nil)
	if a == nil {
		return
	}
	reader := w.reader(m3aDeviceA)
	path, err := kube.GenerateAccessTokenPath(w.email(m3aReader))
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{reader.LeafDER()}, PrivateKey: reader.Signer()}
	for _, c := range []struct {
		label string
		cert  *tls.Certificate
	}{{"with V1's reader leaf (TLS 1.3 at least, so the leaf is never sent in clear)", cert}, {"without a client certificate", nil}} {
		code, body, err := w.probeSend(m3aIAMCredsMTLSHost, c.cert, http.MethodPost, path,
			http.Header{"Authorization": {"Bearer " + a.Token().Value}, "Content-Type": {"application/json"}, "Accept": {"application/json"}}, kube.ImpersonationBody())
		if err != nil {
			w.say("I1 %s: NOT ANSWERED: %s", c.label, w.sc.text(err.Error()))
			continue
		}
		var g struct {
			AccessToken string `json:"accessToken"`
		}
		came := json.Unmarshal(body, &g) == nil && g.AccessToken != ""
		w.say("I1 %s: status %d %s, Google status %s, a token came: %s", c.label, code, http.StatusText(code), m3aGoogleStatus(body), m3aYesNo(came))
		clear(body)
	}
}

// stepI2 is I2: STS asked for userinfo.email as well.
func (w *m3aWalk) stepI2() {
	w.load()
	w.readerExchange("I2 reader exchange, scopes cloud-platform and userinfo.email", w.since(), []string{kube.ScopeCloudPlatform, kube.ScopeUserinfoEmail})
}

// stepI3 is I3: a leaf 20 minutes from its end; its lifetime line reads
// expires_in.
func (w *m3aWalk) stepI3() {
	w.load()
	since := w.since()
	rAnchor, readerID := w.v1ReaderAnchor()
	leaf, err := m3aI3Leaf(rand.Reader, w.clock.now(), rAnchor, readerID)
	if err != nil {
		w.stop(w.sc, "make I3's leaf: %v", err)
	}
	w.recordLeaf(leaf.der)
	w.save()
	shape := w.shapeFor(m3aShapeV1Reader)
	w.positive("I3 leaf ending in 20 min ("+shape.String()+"), expires_in as lifetime", since, func() (*kube.ExchangeAnswer, error) {
		return w.exchange(w.aud(m3aV1, m3aReader), m3aPresentCert(leaf, rAnchor.der), shape, nil)
	})
}

// stepI4 is I4: (a) under V1's reader anchor, a leaf that predates its
// issuer; (b) under V6's anchor, the same length, nested inside it, read
// beside V6's own leaf.
func (w *m3aWalk) stepI4() {
	w.load()
	since := w.since()
	rAnchor, readerID := w.v1ReaderAnchor()
	v6 := w.readPair(m3aV6)
	v6ID, err := devicekey.ParseRoleID(w.st.roleID(m3aV6, m3aReader))
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	a, b, err := m3aI4Leaves(rand.Reader, w.clock.now(), rAnchor, readerID, v6.anchor, v6ID)
	if err != nil {
		w.stop(w.sc, "make I4's leaves: %v", err)
	}
	w.recordLeaf(a.der, b.der)
	w.save()
	shape := w.shapeFor(m3aShapeV1Reader)
	w.positive("I4 (a) a 430-day leaf under V1's reader anchor, which predates its issuer ("+shape.String()+")", since, func() (*kube.ExchangeAnswer, error) {
		return w.exchange(w.aud(m3aV1, m3aReader), m3aPresentCert(a, rAnchor.der), shape, nil)
	})
	w.positive("I4 (b) a 430-day leaf nested in V6's anchor ("+shape.String()+")", since, func() (*kube.ExchangeAnswer, error) {
		return w.exchange(w.aud(m3aV6, m3aReader), m3aPresentCert(b, v6.anchor.der), shape, nil)
	})
	_, err = w.exchange(w.aud(m3aV6, m3aReader), m3aPresentCert(v6.leaf, v6.anchor.der), shape, nil)
	if err == nil {
		w.say("I4 (b) beside it, V6's own leaf: ACCEPTED")
	} else {
		w.say("I4 (b) beside it, V6's own leaf: %s", w.refusal(err))
	}
}

// stepI5 is I5: an audience naming the project's ID.
func (w *m3aWalk) stepI5() {
	w.load()
	since := w.since()
	aud, err := m3aAudienceForProjectID(w.st.Project, w.st.Pool, w.st.provider(m3aV1, m3aReader))
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	shape := w.shapeFor(m3aShapeV1Reader)
	reader := w.reader(m3aDeviceA)
	w.positive("I5 an audience naming the project ID ("+shape.String()+")", since, func() (*kube.ExchangeAnswer, error) {
		return w.exchange(aud, m3aPresentOf(reader), shape, nil)
	})
}

// stepI6 is I6: the mTLS token type at STS's plain endpoint, with no client
// certificate. An acceptance, any 200, gates as N6 (the runbook's deviation
// 9), so I6 is read as a negative (deviation 11): beside a positive
// control at the same endpoint in the same form encoding, V5's JWT exchange
// (as jwt, else as id_token), checked at once and again at the later of the
// latest mark + 10 min and 60 s after the first check. A refusal counts only
// as a 400, 401 or 403 while the control is accepted; a control refused or
// not answered, or an I6 answer that is no decision, reads INCONCLUSIVE, which
// gates until the step is run again.
func (w *m3aWalk) stepI6() {
	w.load()
	latest, ok := w.st.Marks.latest()
	if !ok {
		w.t.Fatal("no mark is recorded; I6's second check measures from the latest")
	}
	shape := w.shapeFor(m3aShapeV1Reader)
	reader := w.reader(m3aDeviceA)
	_, subject := shape.chains(reader.LeafDER(), nil, reader.AnchorDER())
	token, err := kube.SubjectToken(subject)
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	form := kube.ExchangeForm(w.aud(m3aV1, m3aReader), kube.TokenTypeMTLS, token, []string{kube.ScopeCloudPlatform})
	v5 := w.v5Sender()
	checks, accepted := 0, false
	check := func() m3aCheck {
		checks++
		code, sent, line, _ := w.plainExchange(form)
		acc, ref := m3aPlainAnswered(code, sent)
		if acc {
			accepted = true
			line = "ACCEPTED (" + line + ")"
		}
		cacc, ctl := false, ""
		for _, tt := range []struct{ name, typ string }{{"jwt", m3aTokenTypeJWT}, {"id_token", m3aTokenTypeIDToken}} {
			ccode, csent, cline, _ := v5(tt.typ)
			if a, _ := m3aPlainAnswered(ccode, csent); a {
				cacc, ctl = true, ctl+"ACCEPTED as "+tt.name
				break
			}
			ctl += tt.name + " " + cline + "; "
		}
		w.say("I6 check %d, the mTLS token type at the plain endpoint, no certificate (%s subject): %s; control (V5 at the plain endpoint): %s",
			checks, shape, line, strings.TrimSuffix(ctl, "; "))
		return m3aCheckFrom(acc, ref, cacc)
	}
	w.say("I6: first check; the second comes at the later of the latest mark + %s and 60 s after the first", m3aSeconds(m3aSettleBound))
	first, second := m3aNegative(w.ctx, w.clock, latest, check)
	v := m3aVerdict(first, second)
	w.say("I6: %s (gating as N6)", v)
	if accepted {
		w.say("I6: ACCEPTED without a certificate — gates as N6")
	}
	if v != m3aHolds {
		w.t.Errorf("I6 did not hold (FAILS or INCONCLUSIVE); an acceptance without a client certificate gates as N6, and a refused control tested nothing")
	}
}

// i7Leaf is I7's leaf, under its second anchor.
func (w *m3aWalk) i7Leaf() m3aPresent {
	p := w.readPair("i7")
	return m3aPresentCert(p.leaf, p.anchor.der)
}

// stepI7Added is I7 after i7-add.sh: both anchors' leaves, under the settle
// rule.
func (w *m3aWalk) stepI7Added() {
	w.load()
	since := w.since()
	shape := w.shapeFor(m3aShapeV1Reader)
	reader := w.reader(m3aDeviceA)
	w.positive("I7 V1's reader leaf ("+shape.String()+")", since, func() (*kube.ExchangeAnswer, error) {
		return w.exchange(w.aud(m3aV1, m3aReader), m3aPresentOf(reader), shape, nil)
	})
	i7 := w.i7Leaf()
	w.positive("I7 the second anchor's leaf ("+shape.String()+")", since, func() (*kube.ExchangeAnswer, error) {
		return w.exchange(w.aud(m3aV1, m3aReader), i7, shape, nil)
	})
}

// untilRefused polls send until refused while its control is accepted, and
// prints the outcome. It reports whether the refusal came.
func (w *m3aWalk) untilRefused(label string, since time.Time, send, ctrl func() error) bool {
	_, o := m3aUntilRefused(w.ctx, w.clock, since, func() m3aCheck { return m3aCheckOf(send(), ctrl()) })
	return w.refusalLine(label, since, o)
}

// refusalLine prints an until-refused poll's outcome, and reports whether
// the refusal came with its control accepted.
func (w *m3aWalk) refusalLine(label string, since time.Time, o m3aOutcome) bool {
	if o.ok {
		w.say("%s: refused %s", label, w.acceptedTimes(since.Add(o.delta), since))
		return true
	}
	w.say("%s: %s at the bound (%s from the mark)", label, o.last, m3aSeconds(m3aSettleBound))
	return false
}

// acceptedTimes is "after N s", with the latest mark's delta when later.
func (w *m3aWalk) acceptedTimes(at, since time.Time) string {
	return m3aAfter(at, since, w.st.Marks)
}

// stepI7Removed is I7 after i7-remove.sh: V1's reader leaf still accepted,
// and I7's leaf polled until refused, with V1's reader leaf as its control.
func (w *m3aWalk) stepI7Removed() {
	w.load()
	since := w.since()
	shape := w.shapeFor(m3aShapeV1Reader)
	reader := w.reader(m3aDeviceA)
	aud := w.aud(m3aV1, m3aReader)
	ctrl := func() error { _, err := w.exchange(aud, m3aPresentOf(reader), shape, nil); return err }
	w.positive("I7 V1's reader leaf ("+shape.String()+")", since, func() (*kube.ExchangeAnswer, error) {
		return w.exchange(aud, m3aPresentOf(reader), shape, nil)
	})
	i7 := w.i7Leaf()
	w.untilRefused("I7 the removed anchor's leaf", since, func() error { _, err := w.exchange(aud, i7, shape, nil); return err }, ctrl)
}

// ---- Steps: P6 ----

// renew stages a writer anchor renewal and returns its anchor.
func (w *m3aWalk) renew() []byte {
	w.load()
	staged, err := w.store(m3aDeviceA).RenewAnchor(devicekey.Writer, rand.Reader, w.clock.now())
	if err != nil {
		w.stop(w.sc, "stage the writer anchor's renewal: %v", err)
	}
	w.recordLeaf(staged.LeafDER())
	w.recordCA(staged.AnchorDER())
	w.save()
	w.say("staged a writer anchor renewal")
	return staged.AnchorDER()
}

// stepRenew is P6's paste: renew-paste.sh with the staged anchor.
func (w *m3aWalk) stepRenew() {
	anchor := w.renew()
	b, err := m3aRenewPasteBlock(w.st, anchor)
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	w.writeBlock("renew-paste.sh", b)
}

// stepRenewConsole is P6's console edit: console-renew.txt.
func (w *m3aWalk) stepRenewConsole() {
	anchor := w.renew()
	b, err := m3aConsoleRenewText(w.st, anchor)
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	w.writeBlock("console-renew.txt", b)
}

// stepRenewal is P6's checks: the staged leaf exchanges, and the current
// writer leaf is polled until refused, with V1's reader as its control, both
// in one round-robin from the mark, so each delta is its own; then the
// staged leaf impersonates the writer SA; the reader still exchanges; then
// the renewal is committed, only if its leaf exchanged.
func (w *m3aWalk) stepRenewal() {
	w.load()
	since := w.since()
	rs, ws := w.shapeFor(m3aShapeV1Reader), w.shapeFor(m3aShapeV1Writer)
	s := w.store(m3aDeviceA)
	staged, err := s.OpenStaged(devicekey.Writer, devicekey.GiveConsent(devicekey.ConsentConfirmed))
	if err != nil {
		w.stop(w.sc, "open the staged renewal: %v", err)
	}
	audR, audW := w.aud(m3aV1, m3aReader), w.aud(m3aV1, m3aWriter)
	current, reader := w.writer(m3aDeviceA), w.reader(m3aDeviceA)
	newLabel := "P6 the renewed writer leaf (" + ws.String() + ")"
	var a *kube.ExchangeAnswer
	var lastNew error
	oldAccepted := false
	out := m3aRounds(w.ctx, w.clock, since, 2, func(i int) bool {
		if i == 0 {
			ans, err := w.exchange(audW, m3aPresentOf(staged), ws, nil)
			if err != nil {
				w.notSent(newLabel, err)
				lastNew = err
				return false
			}
			a = ans
			return true
		}
		_, oerr := w.exchange(audW, m3aPresentOf(current), ws, nil)
		_, cerr := w.exchange(audR, m3aPresentOf(reader), rs, nil)
		c := m3aCheckOf(oerr, cerr)
		if c.control && c.accepted {
			oldAccepted = true
		}
		return c.control && !c.accepted
	})
	w.positiveLine(newLabel, since, out[0], a, lastNew)
	if a != nil {
		w.impersonate("P6 the renewed writer impersonating the writer SA", since, a.Token(), m3aWriter)
	}
	old := out[1]
	if !old.ok {
		old.last = m3aInconclusivePoll
		if oldAccepted {
			old.last = m3aStillAccepted
		}
	}
	oldRefused := w.refusalLine("P6 the current writer leaf, under the replaced anchor", since, old)
	_, rerr := w.exchange(audR, m3aPresentOf(reader), rs, nil)
	if rerr == nil {
		w.say("P6 V1's reader: ACCEPTED")
	} else {
		w.say("P6 V1's reader: %s", w.refusal(rerr))
	}
	committed := false
	if a != nil {
		if err := s.CommitAnchor(devicekey.Writer); err != nil {
			w.say("committed: no (%s)", w.sc.text(err.Error()))
		} else {
			committed = true
			w.say("committed: yes")
		}
	} else {
		w.say("committed: no (the renewed leaf did not exchange; the writer keeps its current material)")
	}
	w.say("P6 (information): the new leaf accepted: %s; the old leaf refused: %s; the reader works: %s; committed: %s",
		m3aYesNo(a != nil), m3aYesNo(oldRefused), m3aYesNo(rerr == nil), m3aYesNo(committed))
}

// stepRenewDiscard discards a staged writer anchor renewal that Google did
// not take (P6.4: renew-paste.sh or the console's edit refused, and renewal
// run again without a commit), so that renew-console and P7 can go on. It
// discards only while the current writer leaf still exchanges at V1's writer
// provider: once Google holds the staged anchor alone, the staged keys are
// the writer's only working ones, and they are kept.
func (w *m3aWalk) stepRenewDiscard() {
	w.load()
	ws := w.shapeFor(m3aShapeV1Writer)
	_, err := w.exchange(w.aud(m3aV1, m3aWriter), m3aPresentOf(w.writer(m3aDeviceA)), ws, nil)
	if err != nil {
		w.notSent("P6 the current writer leaf", err)
		w.say("P6 the current writer leaf (%s): %s", ws, w.refusal(err))
		w.say("discarded: no (the current writer leaf does not exchange, so the staged renewal may be what Google now trusts; it is kept)")
		return
	}
	w.say("P6 the current writer leaf (%s): ACCEPTED", ws)
	if err := w.store(m3aDeviceA).DiscardStaged(devicekey.Writer); err != nil {
		if errors.Is(err, devicekey.ErrNothingStaged) {
			w.say("discarded: no (nothing was staged)")
			return
		}
		w.stop(w.sc, "discard the staged renewal: %v", err)
	}
	w.say("discarded: yes (the writer keeps its current anchor and leaf)")
}

// ---- Steps: P7 and P10 (a) ----

// waitForMark polls the state every 5 s, for up to 30 minutes, for the named
// mark recorded after this step started. It never writes the state.
func (w *m3aWalk) waitForMark(name, paste string) time.Time {
	w.t.Helper()
	w.say("holding a federated token; paste %s, then mark; waiting for mark %s", paste, name)
	deadline := w.start.Add(m3aHeldWait)
	for {
		st, err := m3aLoadState(w.dir)
		if err != nil {
			w.stop(w.sc, "%v", err)
		}
		if t, ok := st.Marks.after(name, w.start); ok {
			w.st.Marks = st.Marks
			return t
		}
		if !w.clock.now().Before(deadline) {
			w.t.Fatalf("mark %s was not recorded within %s of this step's start; nothing was measured", name, m3aHeldWait)
		}
		if w.clock.sleep(w.ctx, 5*time.Second) != nil {
			w.t.Fatal("the step's bound passed while it waited for its mark")
		}
	}
}

// m3aGatingWatch is one gating new exchange P7 polls until refused, beside
// its control.
type m3aGatingWatch struct {
	label      string
	send, ctrl func() error
}

// m3aHeldWatch is one held token P7 times: its impersonation of an SA, beside
// its control, a token impersonating its own SA.
type m3aHeldWatch struct {
	label    string
	held     *auth.Token
	role     string
	ctrl     *auth.Token
	ctrlRole string
}

// watch polls every gating new exchange and every held token from the mark,
// in one loop (m3aWatch), and prints each one's line. A gating exchange is
// polled at the settle rule's times until the bound (gating); a held token
// every 60 s until refused or expired (information, the runbook's deviation
// 12). Nothing waits for anything else, so each delta is measured from the
// mark. A gating exchange that was not refused with its control accepted
// fails the step.
func (w *m3aWalk) watch(mark time.Time, gating []m3aGatingWatch, held []m3aHeldWatch) {
	things := make([]m3aWatched, 0, len(gating)+len(held))
	for _, g := range gating {
		things = append(things, m3aWatched{poll: func() m3aCheck { return m3aCheckOf(g.send(), g.ctrl()) }})
	}
	for _, h := range held {
		things = append(things, m3aWatched{expiry: h.held.Expiry, poll: func() m3aCheck {
			_, err := w.federation().Impersonate(w.ctx, h.held, w.email(h.role))
			_, cerr := w.federation().Impersonate(w.ctx, h.ctrl, w.email(h.ctrlRole))
			return m3aCheckOf(err, cerr)
		}})
	}
	out := m3aWatch(w.ctx, w.clock, mark, things)
	failed := false
	for i, g := range gating {
		if w.refusalLine(g.label, mark, out[i].outcome()) {
			w.say("%s: holds", g.label)
			continue
		}
		w.say("%s: FAILS or INCONCLUSIVE (see the line above)", g.label)
		failed = true
	}
	for j, h := range held {
		// Every held token impersonated before the paste (heldImpersonates).
		w.say("%s", m3aHeldLine(h.label, out[len(gating)+j], int(h.held.Expiry.Sub(mark)/time.Minute), true))
	}
	if failed {
		w.t.Errorf("a gating refusal did not come; see its lines")
	}
}

// held makes the tokens a held step holds: an exchange, at once. It returns
// the token, or the exchange's error.
func (w *m3aWalk) held(label, aud string, p m3aPresent, s m3aShape) (*auth.Token, error) {
	a, err := w.exchange(aud, p, s, nil)
	if err != nil {
		w.say("%s: %s", label, w.refusal(err))
		return nil, err
	}
	w.say("%s: ACCEPTED (%s)", label, m3aAccepted(a))
	return a.Token(), nil
}

// heldMissing stops a held step whose token was not made, or does not
// impersonate, before it asks for the paste: nothing was measured, and the
// step runs again first.
func (w *m3aWalk) heldMissing(err error, paste string) {
	w.t.Helper()
	w.t.Fatalf("a token to hold was not made, or did not impersonate before the paste (%s); nothing was measured: run %s again before pasting %s", w.refusal(err), w.step, paste)
}

// heldImpersonates impersonates once with a held token, or a control's, at
// role's SA, before the step asks for the paste. A held token's first poll
// comes at the mark, so without this a token whose binding was already gone,
// or not yet settled, would read "refused after 0 s" though no poll ever saw
// it accepted, and that would be recorded as the revocation's window. A
// refusal, or no answer, stops the step before the paste (heldMissing).
func (w *m3aWalk) heldImpersonates(label string, tok *auth.Token, role, paste string) {
	w.t.Helper()
	if _, err := w.federation().Impersonate(w.ctx, tok, w.email(role)); err != nil {
		w.say("%s: %s", label, w.refusal(err))
		w.heldMissing(err, paste)
	}
	w.say("%s: ACCEPTED before the paste", label)
}

// stepHoldBinding is P7 (a): a held writer token, then, after
// revoke-binding, its impersonation every 60 s from the mark until refused or
// expired; the reader's token impersonating the reader SA is its control.
func (w *m3aWalk) stepHoldBinding() {
	w.load()
	rs, ws := w.shapeFor(m3aShapeV1Reader), w.shapeFor(m3aShapeV1Writer)
	wt, werr := w.held("held writer exchange", w.aud(m3aV1, m3aWriter), m3aPresentOf(w.writer(m3aDeviceA)), ws)
	if wt == nil {
		w.heldMissing(werr, "revoke-binding.sh")
	}
	rt, rerr := w.held("control reader exchange", w.aud(m3aV1, m3aReader), m3aPresentOf(w.reader(m3aDeviceA)), rs)
	if rt == nil {
		w.heldMissing(rerr, "revoke-binding.sh")
	}
	w.heldImpersonates("held writer token impersonating the writer SA", wt, m3aWriter, "revoke-binding.sh")
	w.heldImpersonates("control reader token impersonating the reader SA", rt, m3aReader, "revoke-binding.sh")
	mark := w.waitForMark("revoke-binding", "revoke-binding.sh")
	w.watch(mark, nil, []m3aHeldWatch{{label: "P7 (a) the held writer token's impersonation", held: wt, role: m3aWriter, ctrl: rt, ctrlRole: m3aReader}})
}

// stepWriterBack is P7's re-add or re-enable: a writer exchange and an
// impersonation, under the settle rule.
func (w *m3aWalk) stepWriterBack() {
	w.load()
	since := w.since()
	ws := w.shapeFor(m3aShapeV1Writer)
	writer := w.writer(m3aDeviceA)
	a := w.positive("writer exchange ("+ws.String()+")", since, func() (*kube.ExchangeAnswer, error) {
		return w.exchange(w.aud(m3aV1, m3aWriter), m3aPresentOf(writer), ws, nil)
	})
	var fed *auth.Token
	if a != nil {
		fed = a.Token()
	}
	w.impersonate("writer impersonating the writer SA", since, fed, m3aWriter)
}

// stepHoldDisable is P7 (b): after disable-writer, from the mark and in one
// loop, a new writer exchange polled until refused (gating), with V1's reader
// as its control, and the held token's impersonation until refused or
// expired.
func (w *m3aWalk) stepHoldDisable() {
	w.load()
	rs, ws := w.shapeFor(m3aShapeV1Reader), w.shapeFor(m3aShapeV1Writer)
	audR, audW := w.aud(m3aV1, m3aReader), w.aud(m3aV1, m3aWriter)
	writer, reader := w.writer(m3aDeviceA), w.reader(m3aDeviceA)
	wt, werr := w.held("held writer exchange", audW, m3aPresentOf(writer), ws)
	if wt == nil {
		w.heldMissing(werr, "disable-writer.sh")
	}
	rt, rerr := w.held("control reader exchange", audR, m3aPresentOf(reader), rs)
	if rt == nil {
		w.heldMissing(rerr, "disable-writer.sh")
	}
	w.heldImpersonates("held writer token impersonating the writer SA", wt, m3aWriter, "disable-writer.sh")
	w.heldImpersonates("control reader token impersonating the reader SA", rt, m3aReader, "disable-writer.sh")
	mark := w.waitForMark("disable-writer", "disable-writer.sh")
	w.watch(mark,
		[]m3aGatingWatch{{
			label: "P7 (b) a new writer exchange",
			send:  func() error { _, err := w.exchange(audW, m3aPresentOf(writer), ws, nil); return err },
			ctrl:  func() error { _, err := w.exchange(audR, m3aPresentOf(reader), rs, nil); return err },
		}},
		[]m3aHeldWatch{{label: "P7 (b) the held writer token's impersonation", held: wt, role: m3aWriter, ctrl: rt, ctrlRole: m3aReader}})
}

// stepHoldDelete is P7 (c) and P10 (a): after teardown-v1, from the mark and
// in one loop, new reader and writer exchanges polled until refused (gating),
// with V1b's exchange as the control, and each held token's impersonation
// until refused or expired. Each held token and the control impersonate once
// before the paste (heldImpersonates). It holds the reader alone only when the
// held writer exchange was refused with a decision (m3aWriterLeftOut: V1's
// writer provider still disabled); a held writer token whose impersonation was
// refused with a decision (its binding not back) is not timed, while the
// writer's new exchange is still polled. Any other failure stops the step
// before the paste, so the writer provider's deletion is never recorded as
// covered when it was not tested.
func (w *m3aWalk) stepHoldDelete() {
	w.load()
	rs, ws := w.shapeFor(m3aShapeV1Reader), w.shapeFor(m3aShapeV1Writer)
	bs, ok := w.st.simplest(m3aShapeV1b)
	if !ok {
		w.t.Fatal("V1b's shape is not recorded; run t1 (or v1b) first")
	}
	audR, audW, audB := w.aud(m3aV1, m3aReader), w.aud(m3aV1, m3aWriter), w.aud(m3aV1b, m3aReader)
	reader, writer, v1b := w.reader(m3aDeviceA), w.writer(m3aDeviceA), w.reader(m3aDeviceB)
	rt, rerr := w.held("held reader exchange", audR, m3aPresentOf(reader), rs)
	if rt == nil {
		w.heldMissing(rerr, "teardown-v1.sh")
	}
	wt, werr := w.held("held writer exchange", audW, m3aPresentOf(writer), ws)
	bt, berr := w.held("control V1b exchange", audB, m3aPresentOf(v1b), bs)
	if bt == nil {
		w.heldMissing(berr, "teardown-v1.sh")
	}
	if wt == nil {
		if !m3aWriterLeftOut(werr) {
			w.heldMissing(werr, "teardown-v1.sh")
		}
		w.say("writer not re-enabled (its exchange was refused with a decision): holding the reader alone; the writer provider's deletion is not measured")
	}
	w.heldImpersonates("held reader token impersonating the reader SA", rt, m3aReader, "teardown-v1.sh")
	w.heldImpersonates("control V1b token impersonating the reader SA", bt, m3aReader, "teardown-v1.sh")
	holdWriter := wt != nil
	if wt != nil {
		// The writer's binding may not be back (P7 (a)'s re-add refused): then
		// its impersonation is refused with a decision, and the held writer
		// token is not timed; its exchange still works, so the writer
		// provider's deletion is still polled.
		if _, err := w.federation().Impersonate(w.ctx, wt, w.email(m3aWriter)); err != nil {
			w.say("held writer token impersonating the writer SA: %s", w.refusal(err))
			if !m3aWriterLeftOut(err) {
				w.heldMissing(err, "teardown-v1.sh")
			}
			w.say("writer binding not back (its impersonation was refused with a decision): the held writer token is not timed; the writer provider's deletion is still polled")
			holdWriter = false
		} else {
			w.say("held writer token impersonating the writer SA: ACCEPTED before the paste")
		}
	}
	mark := w.waitForMark("teardown-v1", "teardown-v1.sh")
	ctrl := func() error { _, err := w.exchange(audB, m3aPresentOf(v1b), bs, nil); return err }
	gating := []m3aGatingWatch{{
		label: "P7 (c) a new reader exchange",
		send:  func() error { _, err := w.exchange(audR, m3aPresentOf(reader), rs, nil); return err },
		ctrl:  ctrl,
	}}
	held := []m3aHeldWatch{{label: "P7 (c) the held reader token's impersonation", held: rt, role: m3aReader, ctrl: bt, ctrlRole: m3aReader}}
	if wt != nil {
		gating = append(gating, m3aGatingWatch{
			label: "P7 (c) a new writer exchange",
			send:  func() error { _, err := w.exchange(audW, m3aPresentOf(writer), ws, nil); return err },
			ctrl:  ctrl,
		})
		if holdWriter {
			held = append(held, m3aHeldWatch{label: "P7 (c) the held writer token's impersonation", held: wt, role: m3aWriter, ctrl: bt, ctrlRole: m3aReader})
		}
	}
	w.watch(mark, gating, held)
}

// ---- Step: P8 ----

// stepAuditBlock writes audit.sh, with the run's IDs and every leaf's serial
// and fingerprint.
func (w *m3aWalk) stepAuditBlock() {
	w.load()
	b, err := m3aAuditBlock(w.st)
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	w.writeBlock("audit.sh", b)
}

// ---- Steps: W-FED ----

// stepWFEDInit draws W-FED's pool, two providers and two SAs, and enrols one
// writer-capable device, in the M2 walk's directory.
func (w *m3aWalk) stepWFEDInit() {
	project := os.Getenv("FARCAST_WALK_PROJECT")
	if !m3aProjectIDShape(project) {
		w.t.Fatal("FARCAST_WALK_PROJECT must be a project ID (6 to 30 of [a-z0-9-], a letter first); its value is not printed")
	}
	w.st = &m3aState{WFED: true, Project: project, Variants: map[string]*m3aVariant{}, Marks: m3aMarks{},
		Pool: w.newObjectID(devicekey.PoolID), ReaderSA: w.newObjectID(devicekey.ServiceAccountID),
		WriterSA: w.newObjectID(devicekey.ServiceAccountID), APIRecord: w.newObjectID(devicekey.PoolID)}
	_, ids, err := devicekey.Enrol(rand.Reader, filepath.Join(w.dir, m3aDeviceW), []devicekey.Role{devicekey.Reader, devicekey.Writer}, w.clock.now())
	if err != nil {
		w.stop(w.sc, "enrol W-FED's device: %v", err)
	}
	v := &m3aVariant{Providers: map[string]string{}, RoleIDs: map[string]string{}, Anchors: map[string][]byte{}}
	for _, id := range ids {
		role := id.Role().String()
		v.Providers[role] = w.newObjectID(devicekey.ProviderID)
		v.RoleIDs[role] = id.ID().Hex()
		v.Anchors[role] = id.AnchorDER()
		w.recordLeaf(id.LeafDER())
	}
	w.st.Variants[m3aWFED] = v
	w.save()
	w.say("devices enrolled: 1 (writer-capable); providers drawn: %d; service accounts drawn: 2; keys made: %d", len(v.Providers), 2*len(ids))
}

// stepWFEDBlocks writes wfed-setup.sh, wfed-viewer.sh and wfed-teardown.sh.
func (w *m3aWalk) stepWFEDBlocks() {
	w.load()
	blocks, err := m3aWFEDBlocks(w.st)
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	for _, name := range m3aWFEDBlockNames {
		w.writeBlock(name, blocks[name])
	}
}

// wfedShape is FARCAST_WALK_M3A_SHAPE: M3a's simplest passing shape.
func (w *m3aWalk) wfedShape() m3aShape {
	w.t.Helper()
	s, err := parseM3aShape(os.Getenv("FARCAST_WALK_M3A_SHAPE"))
	if err != nil {
		w.t.Fatalf("FARCAST_WALK_M3A_SHAPE: %v; there is no default", err)
	}
	return s
}

// clusterRead sends one request to the cluster's endpoint with a bearer, as
// walkcluster_test.go's send does, but with a token given.
func (w *m3aWalk) clusterRead(ep kube.Endpoint, bearer, method, path string, q url.Values, body []byte) (int, string, []byte, error) {
	target := ep.BaseURL() + path
	if e := q.Encode(); e != "" {
		target += "?" + e
	}
	req, err := http.NewRequestWithContext(w.ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, errors.New("the request could not be built")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := walkHTTPClient(ep).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := m3aReadLimited(resp.Body, walkMaxBody)
	return resp.StatusCode, resp.Header.Get("Content-Type"), answer, err
}

// m3aWFEDReads are W-FED's three reads.
var m3aWFEDReads = []struct {
	label, method, path string
	query               func() url.Values
	body                []byte
}{
	{"GET /version", http.MethodGet, "/version", func() url.Values { return nil }, nil},
	{"the namespace list", http.MethodGet, walkPreflightPath, walkPreflightQuery, nil},
	{"a SelfSubjectReview", http.MethodPost, "/apis/authentication.k8s.io/v1/selfsubjectreviews", func() url.Values { return nil },
		[]byte(`{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`)},
}

// stepWFED is W-FED 3 and 4: the impersonated reader token's three reads at
// the cluster's DNS endpoint, each under the settle rule from wfed-viewer;
// then the same three, once each, with the federated token.
func (w *m3aWalk) stepWFED() {
	w.load()
	shape := w.wfedShape()
	instance := os.Getenv("FARCAST_WALK_INSTANCE")
	if instance == "" {
		w.t.Fatal("FARCAST_WALK_INSTANCE is required: the M2 walk's instance; the probe has no default")
	}
	dir, err := config.Resolve("")
	if err != nil {
		w.stop(w.sc, "%v", err)
	}
	w.env = &Env{Out: os.Stdout, Err: os.Stderr, In: os.Stdin, Printer: &output.Printer{Mode: output.ModeHuman, Out: os.Stdout, Err: os.Stderr}, ConfigDir: dir}
	w.instance = instance
	meta, sc := w.record()
	w.sc = sc
	w.addLiterals()
	ep := w.endpoint(meta, w.sc)

	since := w.since()
	reader := w.reader(m3aDeviceW)
	a := w.positive("W-FED reader exchange ("+shape.String()+")", since, func() (*kube.ExchangeAnswer, error) {
		return w.exchange(w.aud(m3aWFED, m3aReader), m3aPresentOf(reader), shape, nil)
	})
	if a == nil {
		w.t.Fatal("the federated reader's exchange was refused; nothing was read")
	}
	sa := w.impersonate("W-FED reader impersonating the reader SA", since, a.Token(), m3aReader)
	if sa == nil {
		w.t.Fatal("the reader SA's impersonation was refused; nothing was read")
	}
	viewer, ok := w.st.Marks.last("wfed-viewer")
	if !ok {
		w.t.Fatal("mark wfed-viewer is not recorded; paste wfed-viewer.sh, then mark")
	}
	for _, r := range m3aWFEDReads {
		var code int
		var ctype string
		var body []byte
		var last error
		o := m3aPositiveOutcome(w.ctx, w.clock, viewer, func() bool {
			clear(body)
			code, ctype, body, last = w.clusterRead(ep, sa.Value, r.method, r.path, r.query(), r.body)
			return last == nil && code == http.StatusOK
		})
		ok := o.ok
		w.say("W-FED %s with the SA token:", r.label)
		switch {
		case ok:
			w.say("  %s", w.acceptedLine(viewer, o, "status 200"))
		case last != nil:
			w.say("  NOT ANSWERED at the bound: %s", w.sc.text(last.Error()))
		default:
			w.say("  still refused at the bound:")
			w.answer(w.sc, code, ctype, body)
		}
		if ok && r.method == http.MethodPost {
			var rev struct {
				Status struct {
					UserInfo struct {
						Username string `json:"username"`
					} `json:"userInfo"`
				} `json:"status"`
			}
			got := json.Unmarshal(body, &rev) == nil && rev.Status.UserInfo.Username == w.email(m3aReader)
			w.say("  email matches: %s", m3aYesNo(got))
		}
		clear(body)
	}
	for _, r := range m3aWFEDReads {
		code, _, body, err := w.clusterRead(ep, a.Token().Value, r.method, r.path, r.query(), r.body)
		clear(body)
		switch {
		case err != nil:
			w.say("W-FED %s with the federated token: NOT ANSWERED: %s", r.label, w.sc.text(err.Error()))
		case code == http.StatusUnauthorized:
			w.say("W-FED %s with the federated token: 401 (the endpoint refuses the token)", r.label)
		case code == http.StatusForbidden:
			w.say("W-FED %s with the federated token: 403 (authenticated, then refused)", r.label)
		default:
			w.say("W-FED %s with the federated token: status %d %s", r.label, code, http.StatusText(code))
		}
	}
}

// stepWFEDGone is W-FED 5: after the teardown, the reader's and the writer's
// exchanges, both polled until refused in one loop from the teardown's mark
// (m3aWatch), so each delta is its own and the writer's does not wait for
// the reader's poll to end. No positive control exists once everything is
// deleted: each poll's control reads as accepted, and the lines say so. W-FED
// does not gate. No impersonation is polled: a federated token made after the
// teardown's mark would be made after its providers went, and
// wfed-teardown.sh deletes the SAs too, so a refusal there would say nothing
// about the federation's revocation (M3a's P7 measures that).
func (w *m3aWalk) stepWFEDGone() {
	w.load()
	shape := w.wfedShape()
	since := w.since()
	reader, writer := w.reader(m3aDeviceW), w.writer(m3aDeviceW)
	audR, audW := w.aud(m3aWFED, m3aReader), w.aud(m3aWFED, m3aWriter)
	w.say("no positive control exists after the teardown; each refusal below is read alone")
	out := m3aWatch(w.ctx, w.clock, since, []m3aWatched{
		{poll: func() m3aCheck {
			_, err := w.exchange(audR, m3aPresentOf(reader), shape, nil)
			return m3aCheckOf(err, nil)
		}},
		{poll: func() m3aCheck {
			_, err := w.exchange(audW, m3aPresentOf(writer), shape, nil)
			return m3aCheckOf(err, nil)
		}},
	})
	w.refusalLine("W-FED reader exchange", since, out[0].outcome())
	w.refusalLine("W-FED writer exchange", since, out[1].outcome())
}
