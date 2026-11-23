package cli

// The M3a probe's pure parts (ADR 0024 M3a; design §6). The probe
// is walkm3a_test.go, behind the walk tag, and runs only on a walk. What it
// decides with is here, untagged, so that the ordinary test run (./check.sh
// step 6) checks it, as walkscopes_test.go does for the M2 probe:
//   - the environment check, the state with its named marks, and the
//     coordinates line;
//   - the settle rule, the shapes each step sends, and the negatives' verdicts
//     with their positive controls;
//   - the shell quoting, and the Cloud Shell blocks;
//   - the scrub literals, and the token-info reducer.
//
// Nothing here prints, and no error here quotes an ID, a number or a line it
// was given.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/farsight/cli/internal/devicekey"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// ---- The environment ----

// m3aEnvironmentExact are refused by their exact name: GODEBUG can turn on
// HTTP/2's header logging, the SSL_CERT_ pair can add a root, and KUBECONFIG
// has no business in a walk shell.
var m3aEnvironmentExact = []string{"GODEBUG", "SSL_CERT_FILE", "SSL_CERT_DIR", "KUBECONFIG"}

// m3aEnvironmentProxies are refused in any case: Go's proxy lookup reads
// both spellings.
var m3aEnvironmentProxies = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}

// m3aEnvironmentFaults names each variable of environ, os.Environ's form, that
// the probe refuses: those above, and any whose name starts GOOGLE_. It names
// a variable, never its value. The probe-only clients send a bearer over
// HTTP/2, and the token-info client sends a token in its body, so none of
// these may be set.
func m3aEnvironmentFaults(environ []string) []string {
	var out []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if name == "" {
			continue
		}
		switch {
		case slices.Contains(m3aEnvironmentExact, name), strings.HasPrefix(name, "GOOGLE_"):
			out = append(out, name)
		default:
			for _, p := range m3aEnvironmentProxies {
				if strings.EqualFold(name, p) {
					out = append(out, name)
					break
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ---- The state, and its named marks ----

// m3aStateVersion is the state file's version.
const m3aStateVersion = 1

// m3aStateFile is the state's name in the probe's directory.
const m3aStateFile = "state.json"

// m3aReader and m3aWriter are a role's keys in the state's maps, as
// devicekey.Role's String gives them.
const (
	m3aReader = "reader"
	m3aWriter = "writer"
)

// The variants (design §6), by their keys in the state. W-FED's one device is
// m3aWFED, in a state of its own.
const (
	m3aV1   = "v1"
	m3aV1b  = "v1b"
	m3aV1c  = "v1c"
	m3aV1x  = "v1x"
	m3aV1y  = "v1y"
	m3aV2   = "v2"
	m3aV3   = "v3"
	m3aV4   = "v4"
	m3aV5   = "v5"
	m3aV6   = "v6"
	m3aV7   = "v7"
	m3aV8   = "v8"
	m3aWFED = "wfed"
)

// m3aVariant is one variant's coordinates: its providers and role IDs by
// role, its anchors (public DER), and the rest a variant may carry.
type m3aVariant struct {
	Providers map[string]string `json:"providers"`
	RoleIDs   map[string]string `json:"role_ids,omitempty"`
	Anchors   map[string][]byte `json:"anchors,omitempty"`
	Subject   string            `json:"subject,omitempty"`    // V5's sub; V8's constant
	Issuer    string            `json:"issuer,omitempty"`     // V5's https://<32>.invalid
	KID       string            `json:"kid,omitempty"`        // V5's
	PublicKey []byte            `json:"public_key,omitempty"` // V5's uncompressed P-256 point
}

// m3aState is the probe's state: 0600, written atomically, never printed.
type m3aState struct {
	Version       int                    `json:"version"`
	WFED          bool                   `json:"wfed,omitempty"`
	Project       string                 `json:"project"`
	ProjectNumber string                 `json:"project_number,omitempty"`
	Pool          string                 `json:"pool"`
	ReaderSA      string                 `json:"reader_sa"`
	WriterSA      string                 `json:"writer_sa"`
	APIRecord     string                 `json:"api_record"` // the file in Cloud Shell's home naming the APIs the blocks enabled
	Variants      map[string]*m3aVariant `json:"variants"`
	I7Anchor      []byte                 `json:"i7_anchor,omitempty"`
	Shapes        map[string][4]bool     `json:"shapes,omitempty"` // by m3aShapeV1Reader and its kin
	OldReaderLeaf []byte                 `json:"old_reader_leaf,omitempty"`
	Leaves        [][]byte               `json:"leaves,omitempty"` // every leaf the run made, DER, for audit.sh
	CAs           [][]byte               `json:"cas,omitempty"`    // every CA the run made outside a variant's Anchors and I7's: N1's anchor, the negatives' intermediates, each staged anchor; for audit.sh
	Marks         m3aMarks               `json:"marks,omitempty"`
}

// variant is the named variant, or an empty one.
func (st *m3aState) variant(name string) *m3aVariant {
	if v := st.Variants[name]; v != nil {
		return v
	}
	return &m3aVariant{}
}

// provider, roleID and anchor are a variant's, for a role.
func (st *m3aState) provider(name, role string) string { return st.variant(name).Providers[role] }
func (st *m3aState) roleID(name, role string) string   { return st.variant(name).RoleIDs[role] }
func (st *m3aState) anchor(name, role string) []byte   { return st.variant(name).Anchors[role] }

// m3aEmail is a service account's email in project.
func m3aEmail(account, project string) string {
	return account + "@" + project + ".iam.gserviceaccount.com"
}

// errM3aStateMode is a state file that is not a private plain file.
var errM3aStateMode = errors.New("the probe's state is not a private plain file (want 0600, not a link); it was not read")

// m3aStateMax is the largest state the probe reads.
const m3aStateMax = 16 << 20

// m3aLoadState reads dir's state. Its mode is checked before it is opened,
// and its errors name no value.
func m3aLoadState(dir string) (*m3aState, error) {
	path := filepath.Join(dir, m3aStateFile)
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("the probe's state cannot be found: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return nil, errM3aStateMode
	}
	if fi.Size() > m3aStateMax {
		return nil, errors.New("the probe's state is too large")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the probe's state cannot be read: %w", err)
	}
	var st m3aState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, errors.New("the probe's state does not decode")
	}
	if st.Version != m3aStateVersion {
		return nil, errors.New("the probe's state is of another version")
	}
	return &st, nil
}

// m3aSaveState writes st to dir atomically: a temporary file, Sync, rename.
// os.CreateTemp makes it 0600.
func m3aSaveState(dir string, st *m3aState) error {
	st.Version = m3aStateVersion
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, m3aStateFile))
}

// m3aMarkNames are the only marks; each names the IAM change it follows.
var m3aMarkNames = []string{"setup", "console", "contingent", "i7-add", "i7-remove",
	"renew-paste", "renew-console", "revoke-binding", "readd-binding",
	"disable-writer", "enable-writer", "teardown-v1",
	"wfed-setup", "wfed-viewer", "wfed-teardown"}

// m3aMarks are the times each mark was recorded, by name: wall clock, UTC.
type m3aMarks map[string][]time.Time

// m3aCheckMarkName refuses a name that is not one of m3aMarkNames.
func m3aCheckMarkName(name string) error {
	if !slices.Contains(m3aMarkNames, name) {
		return fmt.Errorf("the mark must be one of %s", strings.Join(m3aMarkNames, ", "))
	}
	return nil
}

// add records name at now.
func (m m3aMarks) add(name string, now time.Time) {
	m[name] = append(m[name], now.UTC().Round(0))
}

// last is the latest time of that name.
func (m m3aMarks) last(name string) (time.Time, bool) {
	var out time.Time
	for _, t := range m[name] {
		if t.After(out) {
			out = t
		}
	}
	return out, !out.IsZero()
}

// latest is the latest time of any name.
func (m m3aMarks) latest() (time.Time, bool) {
	var out time.Time
	for name := range m {
		if t, ok := m.last(name); ok && t.After(out) {
			out = t
		}
	}
	return out, !out.IsZero()
}

// after is the first time of that name at or after start: what a held step
// waits for. A mark recorded before the held step started is not its mark.
func (m m3aMarks) after(name string, start time.Time) (time.Time, bool) {
	var out time.Time
	for _, t := range m[name] {
		if !t.Before(start) && (out.IsZero() || t.Before(out)) {
			out = t
		}
	}
	return out, !out.IsZero()
}

// ---- The coordinates line ----

// m3aCoordinatesTag is the first field of the line setup.sh prints last.
const m3aCoordinatesTag = "m3a1"

// m3aParseCoordinates reads the line setup.sh printed: "m3a1 <project id>
// <project number>", then zero or one "\n" and nothing else, so no CR. The ID
// must be the state's, and the number ^[0-9]{1,20}$. It returns the number.
// Its errors never quote the line.
func m3aParseCoordinates(line []byte, projectID string) (string, error) {
	s := string(line)
	s = strings.TrimSuffix(s, "\n")
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e {
			return "", errors.New("the coordinates line holds a control character or a second line; copy the one line again")
		}
	}
	f := strings.Split(s, " ")
	switch {
	case len(f) != 3:
		return "", errors.New("the coordinates line does not have three fields")
	case f[0] != m3aCoordinatesTag:
		return "", errors.New("the coordinates line does not start with this probe's tag")
	case f[1] != projectID:
		return "", errors.New("the coordinates line names another project than the state's")
	}
	n := f[2]
	if len(n) < 1 || len(n) > 20 {
		return "", errors.New("the coordinates line's project number is not a project number")
	}
	for i := 0; i < len(n); i++ {
		if n[i] < '0' || n[i] > '9' {
			return "", errors.New("the coordinates line's project number is not a project number")
		}
	}
	return n, nil
}

// ---- The settle rule ----

// m3aSettleBound is the settle rule's bound (design §6).
const m3aSettleBound = 10 * time.Minute

// m3aSettleWaits are the waits between tries; then 60 s.
var m3aSettleWaits = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second}

// m3aNegativeGap is the least time between a negative's two checks.
const m3aNegativeGap = 60 * time.Second

// m3aExpiryPoll is P7's information timings' poll.
const m3aExpiryPoll = 60 * time.Second

// m3aClock is the probe's clock, faked in tests.
type m3aClock struct {
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// m3aWallClock is the wall clock: UTC, with no monotonic reading, so that its
// times compare with the state's marks, which other processes wrote.
func m3aWallClock() m3aClock {
	return m3aClock{
		now: func() time.Time { return time.Now().UTC().Round(0) },
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
	}
}

// m3aWait is the wait after the i-th try.
func m3aWait(i int) time.Duration {
	return m3aSettleWaits[min(i, len(m3aSettleWaits)-1)]
}

// m3aNextTry sleeps the wait after the i-th try when the next try still falls
// inside the bound from since, and reports whether there is a next try.
func m3aNextTry(ctx context.Context, c m3aClock, since time.Time, i int) bool {
	d := m3aWait(i)
	if c.now().Add(d).Sub(since) >= m3aSettleBound {
		return false
	}
	if c.sleep(ctx, d) != nil {
		return false
	}
	return c.now().Sub(since) < m3aSettleBound
}

// m3aOutcome is how a poll ended.
type m3aOutcome struct {
	ok    bool          // the awaited answer came: an acceptance, or a refusal with its control accepted
	delta time.Duration // when it came, from since
	last  string        // otherwise, at the bound: m3aStillAccepted or m3aInconclusivePoll
	first time.Duration // a positive's first try, from since (m3aPositiveOutcome, m3aRoundsReady)
	tries int           // a positive's tries; 0: never tried
}

// m3aTimingNote says how far a positive's delta is a settle time, from when
// its first try came and how many it took:
//   - first tried at or past the bound from its mark: one try at most, and its
//     delta is the time since the mark, not a settle time (a rerun, or a step
//     that started late);
//   - accepted at its first try: the settle time is at most the delta, which
//     is when that try came, not when the change took;
//   - first tried 5 s or more after the mark: the settle time lies between
//     that and the delta;
//   - otherwise "": tried from the mark, at the settle rule's times.
//
// Never tried, it is "".
func m3aTimingNote(o m3aOutcome) string {
	switch {
	case o.tries == 0:
		return ""
	case o.first >= m3aSettleBound:
		return "first tried " + m3aSeconds(o.first) + " after the mark, past the bound: not a settle time"
	case o.ok && o.tries == 1:
		return "accepted at its first try, " + m3aSeconds(o.first) + " after the mark: the settle time is at most that"
	case o.first >= m3aSettleWaits[0]:
		return "first tried " + m3aSeconds(o.first) + " after the mark"
	}
	return ""
}

// What m3aUntilRefused reports at its bound.
const (
	m3aStillAccepted    = "still accepted"
	m3aInconclusivePoll = "inconclusive"
)

// m3aPositive tries at once, then after each wait (5, 10, 20, 40, 60, 60, …
// seconds), while now − since < bound, and at least once. The first success
// ends it. It returns the success's delta from since, or false at the bound.
func m3aPositive(ctx context.Context, c m3aClock, since time.Time, try func() bool) (time.Duration, bool) {
	o := m3aPositiveOutcome(ctx, c, since, try)
	return o.delta, o.ok
}

// m3aPositiveOutcome is m3aPositive with when its first try came and how many
// it made (m3aTimingNote).
func m3aPositiveOutcome(ctx context.Context, c m3aClock, since time.Time, try func() bool) m3aOutcome {
	return m3aRoundsReady(ctx, c, since, 1, nil, func(int) bool { return try() })[0]
}

// m3aRounds is t1's round-robin: each round tries every shape not yet
// accepted, at m3aPositive's times, and ends when all are accepted or at the
// bound. It returns each shape's delta, or false.
func m3aRounds(ctx context.Context, c m3aClock, since time.Time, n int, try func(i int) bool) []m3aOutcome {
	return m3aRoundsReady(ctx, c, since, n, nil, try)
}

// m3aRoundsReady is m3aRounds with entries that wait for another: an entry
// whose ready reports false is not tried in that round and keeps nothing
// going by itself; from the round in which it is first ready, it is tried at
// the same times as the rest, so its delta is from since too. So an
// impersonation that follows its role's first accepted shape is polled from
// the setup mark, not after the shapes' round-robin has run to its bound. A
// nil ready is always ready. Each outcome records its first try and its
// tries.
func m3aRoundsReady(ctx context.Context, c m3aClock, since time.Time, n int, ready func(i int) bool, try func(i int) bool) []m3aOutcome {
	out := make([]m3aOutcome, n)
	for r := 0; ; r++ {
		pending := false
		for i := range out {
			if out[i].ok || (ready != nil && !ready(i)) {
				continue
			}
			if out[i].tries == 0 {
				out[i].first = c.now().Sub(since)
			}
			out[i].tries++
			if try(i) {
				out[i].ok, out[i].delta = true, c.now().Sub(since)
			} else {
				pending = true
			}
		}
		if !pending || !m3aNextTry(ctx, c, since, r) {
			return out
		}
	}
}

// m3aCheck is one check of a negative, or one poll for a refusal: whether
// the thing tested was accepted, and whether its positive control, sent
// beside it in the same shape through the same Federation, was accepted.
type m3aCheck struct{ accepted, control bool }

// m3aNegatives checks each at once, then, once all have had their first
// check, waits until max(latest+bound, the last first check + 60 s), and
// checks each again. So each negative's second check comes the bound after
// the last IAM change, and at least 60 s after its own first.
func m3aNegatives(ctx context.Context, c m3aClock, latest time.Time, checks []func() m3aCheck) (first, second []m3aCheck) {
	first = make([]m3aCheck, len(checks))
	second = make([]m3aCheck, len(checks))
	for i, check := range checks {
		first[i] = check()
	}
	at := latest.Add(m3aSettleBound)
	if t := c.now().Add(m3aNegativeGap); t.After(at) {
		at = t
	}
	if d := at.Sub(c.now()); d > 0 {
		if c.sleep(ctx, d) != nil {
			return first, second // zero checks: their controls read as refused
		}
	}
	for i, check := range checks {
		second[i] = check()
	}
	return first, second
}

// m3aNegative checks at once, then at max(latest+bound, first+60 s), and
// returns both checks.
func m3aNegative(ctx context.Context, c m3aClock, latest time.Time, check func() m3aCheck) (first, second m3aCheck) {
	f, s := m3aNegatives(ctx, c, latest, []func() m3aCheck{check})
	return f[0], s[0]
}

// The verdicts.
const (
	m3aHolds        = "holds"
	m3aFails        = "FAILS"
	m3aInconclusive = "INCONCLUSIVE"
)

// m3aVerdict reads a negative's two checks:
//   - "FAILS" if the negative was accepted at either;
//   - else "INCONCLUSIVE" if a control was refused at either: nothing showed
//     that a positive still passed, so the refusal tested nothing. It gates
//     as a failure until the step is rerun;
//   - else "holds".
func m3aVerdict(first, second m3aCheck) string {
	switch {
	case first.accepted || second.accepted:
		return m3aFails
	case !first.control || !second.control:
		return m3aInconclusive
	}
	return m3aHolds
}

// m3aUntilRefused polls at m3aPositive's times, while now − since < bound,
// until a poll whose thing is refused while its control is accepted. A poll
// whose control is refused is inconclusive and polling goes on. At the bound
// it returns "still accepted" if a conclusive poll saw an acceptance, else
// "inconclusive". It is m3aWatch with one gating thing.
func m3aUntilRefused(ctx context.Context, c m3aClock, since time.Time, poll func() m3aCheck) (time.Duration, m3aOutcome) {
	o := m3aWatch(ctx, c, since, []m3aWatched{{poll: poll}})[0]
	return o.delta, o.outcome()
}

// m3aUntilExpired is P7's information timing: it polls every 60 s, with no
// bound but the held token's expiry, until a refusal whose control is
// accepted. It returns the delta, or that the token expired first. It is
// m3aWatch with one held thing.
func m3aUntilExpired(ctx context.Context, c m3aClock, since, expiry time.Time, poll func() m3aCheck) (time.Duration, bool) {
	o := m3aWatch(ctx, c, since, []m3aWatched{{poll: poll, expiry: expiry}})[0]
	return o.delta, o.refused
}

// m3aWatched is one thing polled for a refusal from a mark. With expiry zero
// it is a gating poll, at the settle rule's times (m3aPositive's) while
// now − since < bound, and at least once. With an expiry it is a held token's
// information timing (P7, the runbook's deviation 12), every 60 s while now
// is before the expiry. Each poll is one check: the thing, and its control
// beside it.
type m3aWatched struct {
	poll   func() m3aCheck
	expiry time.Time
}

// m3aWatchOutcome is how one watched thing ended.
type m3aWatchOutcome struct {
	refused  bool          // refused while its control was accepted
	delta    time.Duration // when that came, from since
	accepted bool          // a conclusive poll (its control accepted) saw the thing accepted
	polls    int           // how many polls were made
	ended    bool          // unrefused, it reached its bound (gating) or its expiry (held); false when the context ended first
}

// outcome is a gating poll's ending as m3aUntilRefused reports it.
func (o m3aWatchOutcome) outcome() m3aOutcome {
	switch {
	case o.refused:
		return m3aOutcome{ok: true, delta: o.delta}
	case o.accepted:
		return m3aOutcome{last: m3aStillAccepted}
	}
	return m3aOutcome{last: m3aInconclusivePoll}
}

// m3aWatch polls every thing on its own schedule, all from the same start, in
// one loop. So each thing measured from one mark gets its own delta: a held
// token is first polled at the mark, not after a gating poll has used its
// bound, and a second gating poll starts at the mark too, not after the
// first has ended. A thing is done at its first refusal with its control
// accepted, at its bound or expiry, or when ctx ends.
func m3aWatch(ctx context.Context, c m3aClock, since time.Time, things []m3aWatched) []m3aWatchOutcome {
	out := make([]m3aWatchOutcome, len(things))
	next := make([]time.Time, len(things))
	done := make([]bool, len(things))
	start := c.now()
	for i := range next {
		next[i] = start
	}
	for {
		var at time.Time
		pending := false
		for i := range things {
			if !done[i] && (!pending || next[i].Before(at)) {
				at, pending = next[i], true
			}
		}
		if !pending {
			return out
		}
		if d := at.Sub(c.now()); d > 0 && c.sleep(ctx, d) != nil {
			return out
		}
		for i, th := range things {
			if done[i] || next[i].After(at) {
				continue
			}
			held := !th.expiry.IsZero()
			if now := c.now(); (held && !now.Before(th.expiry)) || (!held && out[i].polls > 0 && now.Sub(since) >= m3aSettleBound) {
				done[i], out[i].ended = true, true
				continue
			}
			try := out[i].polls
			p := th.poll()
			out[i].polls++
			if p.control {
				if !p.accepted {
					done[i], out[i].refused, out[i].delta = true, true, c.now().Sub(since)
					continue
				}
				out[i].accepted = true
			}
			now := c.now()
			if held {
				next[i] = now.Add(m3aExpiryPoll)
				if !next[i].Before(th.expiry) {
					done[i], out[i].ended = true, true
				}
				continue
			}
			w := m3aWait(try)
			if now.Add(w).Sub(since) >= m3aSettleBound {
				done[i], out[i].ended = true, true
				continue
			}
			next[i] = now.Add(w)
		}
	}
}

// m3aDecisionStatus reports whether an HTTP status is a decision against the
// request: 400, 401 or 403. A 3xx, a 429, a 5xx or any other status is no
// decision, so a negative answered that way, beside an accepted control,
// tested nothing (the runbook's deviation 11: a refusal for an unrelated
// reason cannot pass M3a).
func m3aDecisionStatus(code int) bool {
	return code == http.StatusBadRequest || code == http.StatusUnauthorized || code == http.StatusForbidden
}

// m3aCertificateAlerts are the TLS alerts that are a decision against the
// client's certificate, in Go's words for them (crypto/tls's alert.go):
// bad_certificate, unsupported_certificate, certificate_revoked,
// certificate_expired, certificate_unknown, unknown_ca, access_denied and
// certificate_required. Every other alert decided nothing about the
// certificate: internal_error is the server's own failure, protocol_version
// and decode_error are the connection's, and handshake_failure and
// decrypt_error name no certificate, so a negative answered with one reads
// INCONCLUSIVE and the operator reads its words.
var m3aCertificateAlerts = []string{
	"tls: bad certificate", "tls: unsupported certificate", "tls: revoked certificate", "tls: expired certificate",
	"tls: unknown certificate", "tls: unknown certificate authority", "tls: access denied", "tls: certificate required",
}

// m3aAnswered classifies an exchange's or an impersonation's error:
//   - accepted: no error, or any 200, a usable token or not;
//   - refused: a decision against the request, a 400, 401 or 403, or one of
//     m3aCertificateAlerts ending the exchange before an answer came;
//   - neither: not sent, not answered, any other alert (internal_error among
//     them, and every alert while an answer was read), an alert at IAM
//     Credentials (kube reads it as unreachable), or any other status, a 3xx,
//     a 429 or a 5xx among them. That tested nothing.
func m3aAnswered(err error) (accepted, refused bool) {
	if err == nil {
		return true, false
	}
	var fe *kube.FederationError
	if !errors.As(err, &fe) {
		return false, false
	}
	switch {
	case fe.Status == http.StatusOK:
		return true, false
	case fe.Handshake:
		return false, fe.Step == kube.StepExchange && slices.Contains(m3aCertificateAlerts, fe.Alert)
	}
	return false, m3aDecisionStatus(fe.Status)
}

// m3aBothAccepted is a control made of two calls: it reads as accepted only
// when both are, and otherwise as the first that was not. N10's is the
// reader's token at the reader SA and the writer's at the writer SA, so a
// reader token IAM Credentials does not authenticate is no control for the
// reader's token at the writer SA.
func m3aBothAccepted(a, b func() error) func() error {
	return func() error {
		if err := a(); !m3aWasAccepted(err) {
			return err
		}
		if err := b(); !m3aWasAccepted(err) {
			return err
		}
		return nil
	}
}

// m3aWasAccepted is m3aAnswered's acceptance alone.
func m3aWasAccepted(err error) bool {
	acc, _ := m3aAnswered(err)
	return acc
}

// m3aWriterLeftOut reports whether hold-delete may hold the reader alone:
// only when the held writer exchange was refused with a decision, as it is
// while V1's writer provider stays disabled (P7 (b)'s re-enable refused).
// Any other failure, a 5xx, a 429, no answer or a firewall hold, made no
// token to hold and tested nothing, so the step stops before the paste.
func m3aWriterLeftOut(err error) bool {
	_, refused := m3aAnswered(err)
	return err != nil && refused
}

// m3aPositiveVerdict is a gating positive's verdict, from whether it was
// accepted and its last answer when it was not:
//   - "holds" when it was accepted;
//   - "FAILS" when its last answer was a decision against it, a 200 without
//     a usable token, or when it was not tried;
//   - "INCONCLUSIVE" when its last answer was no decision (a 3xx, a 429, a
//     5xx, an alert that is not a certificate's, or none): it tested nothing,
//     and gates until the step is run again, as a negative's does.
func m3aPositiveVerdict(accepted bool, last error) string {
	if accepted {
		return m3aHolds
	}
	if last == nil {
		return m3aFails
	}
	if acc, refused := m3aAnswered(last); acc || refused {
		return m3aFails
	}
	return m3aInconclusive
}

// m3aWorstVerdict is several verdicts as one: FAILS if any fails, else
// INCONCLUSIVE if any is, else holds. No verdict at all, or one that is none
// of the three, is FAILS.
func m3aWorstVerdict(vs ...string) string {
	if len(vs) == 0 {
		return m3aFails
	}
	out := m3aHolds
	for _, v := range vs {
		switch v {
		case m3aHolds:
		case m3aInconclusive:
			out = m3aInconclusive
		default:
			return m3aFails
		}
	}
	return out
}

// m3aAnyShapeVerdict is a T1-shaped gating verdict, from whether any shape
// passed and each shape's last answer: holds when one passed; else
// INCONCLUSIVE when any shape's last answer was no decision, since that shape
// tested nothing and may pass on a rerun; else FAILS.
func m3aAnyShapeVerdict(anyPassed bool, lasts []error) string {
	if anyPassed {
		return m3aHolds
	}
	for _, e := range lasts {
		if m3aPositiveVerdict(false, e) == m3aInconclusive {
			return m3aInconclusive
		}
	}
	return m3aFails
}

// m3aReadBackVerdict is T4's read-back of a provider answered with a status
// other than 200: a 3xx, a 429 or a 5xx is no decision (INCONCLUSIVE); any
// other status FAILS.
func m3aReadBackVerdict(code int) string {
	if (code >= 300 && code < 400) || code == http.StatusTooManyRequests || code >= 500 {
		return m3aInconclusive
	}
	return m3aFails
}

// m3aReadBackPollVerdict is T4's verdict for one provider, once its read-back
// was polled from the setup mark until a 200 or the bound (the pool viewer
// grant it needs is an IAM change of the same paste):
//   - a 200 whose provider matched: holds; one that differs: FAILS;
//   - no answer at the bound: INCONCLUSIVE;
//   - another status at the bound: m3aReadBackVerdict's (a 3xx, 429 or 5xx is
//     INCONCLUSIVE; a 400, 401, 403, 404 or any other FAILS).
func m3aReadBackPollVerdict(answered bool, code int, matched bool) string {
	switch {
	case !answered:
		return m3aInconclusive
	case code == http.StatusOK && matched:
		return m3aHolds
	case code == http.StatusOK:
		return m3aFails
	}
	return m3aReadBackVerdict(code)
}

// m3aT2TokenInfo is token info's part in T2's verdict for one role (design
// §6: "both scopes present"; email matches is information):
//   - not answered (no answer came): INCONCLUSIVE, so t2 runs again;
//   - answered with a status other than 200: holds, on generateAccessToken's
//     200 alone, since token info does not answer by POST (the runbook's
//     P3);
//   - 200 and not readable: INCONCLUSIVE;
//   - 200 with both cloud-platform and userinfo.email: holds;
//   - 200 without one of them: FAILS.
func m3aT2TokenInfo(answered bool, code int, f m3aTokenInfoFacts, readErr error) string {
	switch {
	case !answered:
		return m3aInconclusive
	case code != http.StatusOK:
		return m3aHolds
	case readErr != nil:
		return m3aInconclusive
	case slices.Contains(f.scopes, "cloud-platform") && slices.Contains(f.scopes, "userinfo.email"):
		return m3aHolds
	}
	return m3aFails
}

// m3aPlainAnswered classifies an answer from STS's plain endpoint, where the
// probe-only client reads the status itself: sent is false when no answer
// came. Accepted is any 200; refused, a decision (m3aDecisionStatus).
func m3aPlainAnswered(code int, sent bool) (accepted, refused bool) {
	if !sent {
		return false, false
	}
	if code == http.StatusOK {
		return true, false
	}
	return false, m3aDecisionStatus(code)
}

// m3aHostGuard sends only to its own host, over https, with User-Agent
// farcast, as kube's identityTransport does. It is every probe-only client's
// transport; this file holds it, untagged, so the ordinary test run checks
// it (TestWalkM3aProbeClients).
type m3aHostGuard struct {
	host  string
	inner http.RoundTripper
}

func (g m3aHostGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" || req.URL.Host != g.host {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errors.New("the probe-only client sends only to its own host; nothing was sent")
	}
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", kube.UserAgent)
	return g.inner.RoundTrip(r)
}

// m3aHTTPClient is every probe-only client: no proxy, TLS 1.2 or later
// against the system roots with ServerName the host, the host guard, no
// redirect followed, a 30 s timeout, and a client certificate for I1 alone.
// A client that carries a certificate takes TLS 1.3 at least, as the
// exchange transport does (the runbook's deviation 10): in TLS 1.2 the
// client's Certificate message, V1's reader leaf with its role ID, its serial
// and its dates, would cross the network in clear. A refusal at 1.3 is I1's
// answer. Building one dials nothing.
func m3aHTTPClient(host string, cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if cert != nil {
		cfg.MinVersion = tls.VersionTLS13
		c := *cert
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil }
	}
	return &http.Client{
		Transport: m3aHostGuard{host: host, inner: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			TLSClientConfig:       cfg,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}},
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// m3aCheckFrom is one check from its parts: the thing accepted or refused, and
// its control accepted. A thing neither accepted nor refused (not sent, not
// answered, or answered with no decision) tested nothing: the check reads as
// its control refused, so a verdict is INCONCLUSIVE and a poll goes on.
func m3aCheckFrom(accepted, refused, controlAccepted bool) m3aCheck {
	return m3aCheck{accepted: accepted, control: controlAccepted && (accepted || refused)}
}

// m3aCheckOf is one check of a thing sent through kube, beside its control.
func m3aCheckOf(err, controlErr error) m3aCheck {
	acc, ref := m3aAnswered(err)
	cacc, _ := m3aAnswered(controlErr)
	return m3aCheckFrom(acc, ref, cacc)
}

// m3aRoundsOver is m3aRounds over several targets at once, each with its own
// count of shapes: one round tries every pending (target, shape) entry, so
// each target is tried from since, not after another target's rounds have
// ended. It returns each target's outcomes, in order.
func m3aRoundsOver(ctx context.Context, c m3aClock, since time.Time, counts []int, try func(target, i int) bool) [][]m3aOutcome {
	type entry struct{ target, i int }
	var entries []entry
	for t, n := range counts {
		for i := range n {
			entries = append(entries, entry{t, i})
		}
	}
	flat := m3aRounds(ctx, c, since, len(entries), func(k int) bool { return try(entries[k].target, entries[k].i) })
	out := make([][]m3aOutcome, len(counts))
	for k, e := range entries {
		out[e.target] = append(out[e.target], flat[k])
	}
	return out
}

// m3aPlanTarget is one provider in t1's round-robin: its line's label, its
// variant and role, the key its shapes are recorded under, and the verdict
// line T1 prints for it.
type m3aPlanTarget struct {
	label, variant, role, key, verdict string
}

// m3aPlanFollow is one first impersonation in t1's round-robin: its label,
// the target whose first accepted shape's token it uses, the SA's role, and
// whether it gates (V1b's T2) or is information (V1's, which t2 gates).
type m3aPlanFollow struct {
	label  string
	target int
	role   string
	gating bool
}

// m3aT1Plan is t1's round-robin (withV1), or v1b's rerun alone: V1's reader
// and writer and V1b's reader, each in all four shapes, and each one's first
// impersonation, all from the setup mark in one loop (m3aRoundsReady). So no
// target and no binding waits for another's tries to reach the bound: V1b's
// shapes are not first tried when t1 has ended, and an impersonation is
// polled from the round its role's first shape was accepted in.
func m3aT1Plan(withV1 bool) ([]m3aPlanTarget, []m3aPlanFollow) {
	var targets []m3aPlanTarget
	var follows []m3aPlanFollow
	if withV1 {
		targets = append(targets,
			m3aPlanTarget{"T1 reader", m3aV1, m3aReader, m3aShapeV1Reader, "T1 reader"},
			m3aPlanTarget{"T1 writer", m3aV1, m3aWriter, m3aShapeV1Writer, "T1 writer"})
		follows = append(follows,
			m3aPlanFollow{"T1 reader's first binding, impersonating the reader SA (information; T2 gates in t2)", 0, m3aReader, false},
			m3aPlanFollow{"T1 writer's first binding, impersonating the writer SA (information; T2 gates in t2)", 1, m3aWriter, false})
	}
	targets = append(targets, m3aPlanTarget{"V1b reader", m3aV1b, m3aReader, m3aShapeV1b, "V1b T1"})
	follows = append(follows, m3aPlanFollow{"V1b T2 impersonating the reader SA", len(targets) - 1, m3aReader, true})
	return targets, follows
}

// m3aHeldLine is a held token's line in P7 (information): when it was refused,
// that it was accepted until it expired, or neither. "Refused after N s" is a
// revocation's window only when the token was seen accepted, by a conclusive
// poll or by its impersonation before the paste (before); a refusal at the
// first poll with neither is no timing at all, and says so.
func m3aHeldLine(label string, o m3aWatchOutcome, lifeMin int, before bool) string {
	switch {
	case o.refused && (o.accepted || before):
		note := ""
		if before {
			note = "; it impersonated before the paste"
		}
		return fmt.Sprintf("%s: refused after %s (%d polls%s)", label, m3aSeconds(o.delta), o.polls, note)
	case o.refused:
		return fmt.Sprintf("%s: refused at %s with no acceptance seen, before the paste or after it: not a revocation timing (%d polls)", label, m3aSeconds(o.delta), o.polls)
	case !o.ended:
		return fmt.Sprintf("%s: not refused when the step's bound passed (%d polls; a conclusive poll saw it accepted: %s)", label, o.polls, m3aYesNo(o.accepted))
	case o.accepted:
		return fmt.Sprintf("%s: accepted until it expired after %d min (%d polls)", label, lifeMin, o.polls)
	}
	return fmt.Sprintf("%s: no conclusive poll before it expired after %d min (%d polls; each control refused, or no decision)", label, lifeMin, o.polls)
}

// m3aYesNo is "yes" or "no".
func m3aYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ---- The shapes each step sends ----

// The shape records: the role whose provider a shape passed at.
const (
	m3aShapeV1Reader  = "v1-reader"
	m3aShapeV1Writer  = "v1-writer"
	m3aShapeV1b       = "v1b-reader"
	m3aShapeV1cReader = "v1c-reader"
	m3aShapeV1cWriter = "v1c-writer"
)

// m3aRoundRobinSteps send S1 to S4, as t1 does.
var m3aRoundRobinSteps = []string{"console", "t1", "v1b", "contingent"}

// m3aT1Steps are the steps whose Shape column says "T1's": each sends the
// simplest shape t1 (or v1b) recorded for the role whose provider it targets.
// variants is not among them: with none recorded it falls back to S1–S4.
var m3aT1Steps = []string{"t2", "t3", "t4", "negatives", "i1", "i2", "i3", "i4", "i5", "i6",
	"i7-added", "i7-removed", "renewal", "renew-discard", "hold-binding", "writer-back", "hold-disable", "hold-delete"}

// simplest is the simplest shape recorded under key.
func (st *m3aState) simplest(key string) (m3aShape, bool) {
	passed, ok := st.Shapes[key]
	if !ok {
		return 0, false
	}
	return m3aSimplest(passed)
}

// m3aNegativesReady refuses the negatives until t1 (or v1b) has recorded a
// passing shape for V1's reader, V1's writer and V1b: a negative sent in a
// shape Google refuses would read as one that holds.
func m3aNegativesReady(st *m3aState) error {
	for _, k := range []string{m3aShapeV1Reader, m3aShapeV1Writer, m3aShapeV1b} {
		if _, ok := st.simplest(k); !ok {
			return errors.New("the negatives need a passing shape recorded for V1's reader, V1's writer and V1b; run t1 (or v1b, for V1b) first")
		}
	}
	return nil
}

// m3aStepShapes is the shapes step sends to a provider whose role's shapes
// are recorded under key.
func m3aStepShapes(st *m3aState, step, key string) ([]m3aShape, error) {
	all := m3aShapes[:]
	switch {
	case slices.Contains(m3aRoundRobinSteps, step):
		return all, nil
	case step == "variants":
		if s, ok := st.simplest(key); ok {
			return []m3aShape{s}, nil
		}
		return all, nil
	case slices.Contains(m3aT1Steps, step):
		if step == "negatives" {
			if err := m3aNegativesReady(st); err != nil {
				return nil, err
			}
		}
		s, ok := st.simplest(key)
		if !ok {
			return nil, fmt.Errorf("%s sends the simplest shape t1 recorded, and none is recorded for %s; run t1 first", step, key)
		}
		return []m3aShape{s}, nil
	}
	return nil, fmt.Errorf("%s sends no recorded shape", step)
}

// ---- Shell quoting ----

// m3aQuoteAlphabet is every byte a quoted value may hold.
const m3aQuoteAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._:/=&'@-"

// m3aQuote is a POSIX single-quoted word for s, each ' written '\”. It
// refuses an empty value and any byte outside m3aQuoteAlphabet, and its error
// never quotes the value.
func m3aQuote(s string) (string, error) {
	if s == "" {
		return "", errors.New("a block value is empty")
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(m3aQuoteAlphabet, s[i]) < 0 {
			return "", fmt.Errorf("a block value holds a byte outside the quoting alphabet, at offset %d", i)
		}
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'", nil
}

// ---- The blocks (W-FED's too) ----
//
// Every block is a Cloud Shell paste, shaped as readerinit.go:378-432's
// scripts are: sh -s reading a here-document with a neutral tag, set -eu, a
// y/N for the project read from /dev/tty, a bounded retry around each IAM
// call, and each gcloud call's output in a mktemp file that the block reads
// only with grep and then removes. Every gcloud line ends with --quiet
// </dev/null, since the here-document is the shell's standard input, and
// every binding line carries --condition=None. Every value is quoted by
// m3aQuote. The lines print labels, states and yes/no, and no block names a
// product or an instance (audit.sh looks for the user agent).

// m3aHereDocTags are the only here-document tags a block uses.
var m3aHereDocTags = []string{"END_OF_SETUP", "END_OF_STEP", "END_OF_ANCHOR", "END_OF_JWKS", "END_OF_DATA"}

// m3aSetupAPIs are the APIs setup.sh enables, and records as enabled.
var m3aSetupAPIs = []string{"iam.googleapis.com", "iamcredentials.googleapis.com", "sts.googleapis.com", "cloudresourcemanager.googleapis.com"}

// m3aOrgPolicyAPI is the API policies.sh asks before enabling.
const m3aOrgPolicyAPI = "orgpolicy.googleapis.com"

// The roles the blocks grant. m3aPoolViewerRole is IAM Workload Identity Pool
// Viewer, the role Google names for viewing pools and providers [doc:
// https://docs.cloud.google.com/iam/docs/manage-workload-identity-pools-providers,
// read 2026-11-23].
const (
	m3aWIUserRole     = "roles/iam.workloadIdentityUser"
	m3aPoolViewerRole = "roles/iam.workloadIdentityPoolViewer"
	m3aViewerRole     = "roles/container.viewer"
)

// m3aPrincipalPrefix is the principal:// form's prefix for a pool subject
// [X509], built in the shell from the number the block reads.
const m3aPrincipalPrefix = "principal://iam.googleapis.com/projects/$NUMBER/locations/global/workloadIdentityPools/$POOL/subject"

// m3aRetry is the blocks' bounded retries. retry makes 5 tries, waiting 5·n
// s between them (50 s in all). retry_slow, for a grant or binding on a
// service account the same block may have just created, makes 7, waiting
// 10·n s (210 s in all): Google says a new service account may take 60 s or
// more before it can be used, and to retry with backoff [doc:
// https://docs.cloud.google.com/iam/docs/service-accounts-create, read
// 2026-11-23].
const m3aRetry = `retry() {
  n=0
  until "$@"; do
    n=$((n + 1))
    if [ "$n" -ge 5 ]; then
      return 1
    fi
    sleep $((n * 5))
  done
}
retry_slow() {
  n=0
  until "$@"; do
    n=$((n + 1))
    if [ "$n" -ge 7 ]; then
      return 1
    fi
    sleep $((n * 10))
  done
}`

// m3aScript builds one block. After createSA, a setup block's grants and
// bindings use retry_slow, and each refusal marks the setup incomplete
// (complete).
type m3aScript struct {
	b     strings.Builder
	err   error
	fresh bool // a grant or binding may name an SA this block just created
}

func (s *m3aScript) line(parts ...string) {
	for _, p := range parts {
		s.b.WriteString(p)
	}
	s.b.WriteByte('\n')
}

func (s *m3aScript) fail(err error) {
	if s.err == nil {
		s.err = err
	}
}

// q quotes v for the shell, or records why it cannot.
func (s *m3aScript) q(v string) string {
	out, err := m3aQuote(v)
	if err != nil {
		s.fail(err)
		return "''"
	}
	return out
}

func (s *m3aScript) bytes() ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []byte(s.b.String()), nil
}

// open is every block's head: the here-document, set -eu, the y/N for the
// project, the temporary files, retry and yn, and the names the block uses.
// question holds no ' and no %.
func (s *m3aScript) open(st *m3aState, tag, question string, temps ...string) {
	s.line("sh -s <<'", tag, "'")
	s.line("set -eu")
	s.line("PROJECT=", s.q(st.Project))
	s.line("printf '", question, " (project %s) [y/N] ' \"$PROJECT\" >/dev/tty")
	s.line("read -r ANSWER </dev/tty")
	s.line(`[ "$ANSWER" = y ] || { echo 'Nothing was changed.' >&2; exit 1; }`)
	rm := ""
	for _, v := range append([]string{"OUT"}, temps...) {
		s.line(v, `="$(mktemp)"`)
		rm += ` "$` + v + `"`
	}
	s.line("trap 'rm -f", rm, "' EXIT")
	s.line(m3aRetry)
	s.line(`yn() { if grep -qiE -e "$1" "$OUT"; then echo yes; else echo no; fi; }`)
	s.line("POOL=", s.q(st.Pool))
	s.line("READER_SA=", s.q(m3aEmail(st.ReaderSA, st.Project)))
	s.line("WRITER_SA=", s.q(m3aEmail(st.WriterSA, st.Project)))
	s.line(`RECORD="$HOME/"`, s.q(st.APIRecord))
}

// number reads the project's number, which a principal names, and defines
// PRINCIPAL.
func (s *m3aScript) number() {
	s.line(`NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)' --quiet </dev/null 2>"$OUT")" || NUMBER=''`)
	s.line(`case "$NUMBER" in`)
	s.line(`  ''|*[!0-9]*) echo 'project number: not read'; exit 1 ;;`)
	s.line(`esac`)
	s.line(`PRINCIPAL="`, m3aPrincipalPrefix, `"`)
}

// hereDoc writes body into the temporary file named by the variable file.
func (s *m3aScript) hereDoc(file, tag string, body []byte) {
	text := string(body)
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	for _, l := range strings.Split(text, "\n") {
		if l == tag {
			s.fail(errors.New("a here-document's body holds its own tag"))
		}
	}
	s.line(`cat >"$`, file, `" <<'`, tag, `'`)
	s.b.WriteString(text)
	s.line(tag)
}

// refused is a refusal's line: the label, and yes/no for what the message
// names.
func (s *m3aScript) refused(indent, label string, names ...string) {
	words := ""
	for _, n := range names {
		pat, say, _ := strings.Cut(n, "=")
		words += "; the message names " + say + ": $(yn '" + pat + "')"
	}
	s.line(indent, `echo "`, label, `: refused`, words, `"`)
}

// enableAPIs enables m3aSetupAPIs, recording each it enabled. A refusal stops
// the block: the walk stops to ask if billing is named.
func (s *m3aScript) enableAPIs() {
	for _, api := range m3aSetupAPIs {
		s.line(`if gcloud services list --enabled --project="$PROJECT" --format='value(config.name)' --quiet </dev/null >"$OUT" 2>&1 && grep -qix -e `, s.q(api), ` "$OUT"; then`)
		s.line(`  echo 'API `, api, `: already enabled'`)
		s.line(`elif retry gcloud services enable `, s.q(api), ` --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
		s.line(`  echo `, s.q(api), ` >>"$RECORD"`)
		s.line(`  echo 'API `, api, `: enabled'`)
		s.line(`else`)
		s.refused("  ", "API "+api, "billing=billing")
		s.line(`  exit 1`)
		s.line(`fi`)
	}
}

// createPool creates the pool if it is absent; a refusal stops the block.
func (s *m3aScript) createPool() {
	s.line(`if gcloud iam workload-identity-pools describe "$POOL" --location=global --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  echo 'pool: exists'`)
	s.line(`elif retry gcloud iam workload-identity-pools create "$POOL" --location=global --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  echo 'pool: created'`)
	s.line(`else`)
	s.refused("  ", "pool", "polic=a policy")
	s.line(`  exit 1`)
	s.line(`fi`)
}

// m3aProviderSpec is one X509 provider a block creates.
type m3aProviderSpec struct {
	label     string
	id        string
	trust     []byte // the trust store document
	mapping   string
	condition string
	stop      string // non-empty: a refusal stops the block, with this line
}

// providerExists opens the if that skips a provider already there: found,
// and not DELETED, it prints "<label>: exists". So a setup block can be
// pasted again after a failure that stopped it part way, as the pool's and
// the SAs' checks allow.
func (s *m3aScript) providerExists(label, id string) {
	s.line(`if gcloud iam workload-identity-pools providers describe `, s.q(id),
		` --workload-identity-pool="$POOL" --location=global --project="$PROJECT" --format='value(state)' --quiet </dev/null >"$OUT" 2>&1 && ! grep -qi -e deleted "$OUT"; then`)
	s.line(`  echo '`, label, `: exists'`)
}

// createX509 creates one X509 provider from a trust store here-document of
// its own, unless it exists.
func (s *m3aScript) createX509(p m3aProviderSpec) {
	s.hereDoc("TRUST", "END_OF_ANCHOR", p.trust)
	s.providerExists(p.label, p.id)
	s.line(`elif retry gcloud iam workload-identity-pools providers create-x509 `, s.q(p.id),
		` --location=global --workload-identity-pool="$POOL" --project="$PROJECT" --trust-store-config-path="$TRUST" --attribute-mapping=`,
		s.q(p.mapping), ` --attribute-condition=`, s.q(p.condition), ` --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  echo '`, p.label, `: created'`)
	s.line(`else`)
	s.refused("  ", p.label, "polic=a policy", "quota|limit=a quota or limit", "validity|lifetime=validity or lifetime")
	if p.stop != "" {
		s.line(`  echo '`, p.stop, `'`)
		s.line(`  exit 1`)
	}
	s.line(`fi`)
}

// createOIDC creates V5's provider, from a JWKS here-document, unless it
// exists.
func (s *m3aScript) createOIDC(label, id, issuer string, jwks []byte, mapping, condition string) {
	s.hereDoc("JWKS", "END_OF_JWKS", jwks)
	s.providerExists(label, id)
	s.line(`elif retry gcloud iam workload-identity-pools providers create-oidc `, s.q(id),
		` --location=global --workload-identity-pool="$POOL" --project="$PROJECT" --issuer-uri=`, s.q(issuer),
		` --jwk-json-path="$JWKS" --attribute-mapping=`, s.q(mapping), ` --attribute-condition=`, s.q(condition),
		` --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  echo '`, label, `: created'`)
	s.line(`else`)
	s.refused("  ", label, "polic=a policy", "quota|limit=a quota or limit", "validity|lifetime=validity or lifetime")
	s.line(`fi`)
}

// createSA creates a service account if it is absent, with no display name.
func (s *m3aScript) createSA(label, variable, id string) {
	s.line(`if gcloud iam service-accounts describe "$`, variable, `" --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  echo '`, label, `: exists'`)
	s.line(`elif retry gcloud iam service-accounts create `, s.q(id), ` --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  echo '`, label, `: created'`)
	s.line(`else`)
	s.refused("  ", label, "polic=a policy")
	s.line(`  exit 1`)
	s.line(`fi`)
	if !s.fresh {
		s.fresh = true
		s.line(`INCOMPLETE=no`)
	}
}

// retryFor is the retry a grant or binding uses: retry_slow when it may name
// an SA this block just created.
func (s *m3aScript) retryFor() string {
	if s.fresh {
		return "retry_slow"
	}
	return "retry"
}

// incomplete is a grant's or binding's refusal in a setup block: the setup is
// marked incomplete, so complete prints no coordinates line.
func (s *m3aScript) incomplete(indent string) {
	if s.fresh {
		s.line(indent, `INCOMPLETE=yes`)
	}
}

// complete ends a setup block: the coordinates line, which the runbook marks
// setup on at once, only when every grant and binding printed added;
// otherwise a line saying so, and exit 1, so no partial setup is marked.
func (s *m3aScript) complete(paste string) {
	s.line(`if [ "$INCOMPLETE" = yes ]; then`)
	s.line(`  echo 'setup not complete: a grant or binding above was refused (its line says whether it names a policy); paste `, paste, ` again, unless a policy refused it'`)
	s.line(`  exit 1`)
	s.line(`fi`)
	s.line(`echo "`, m3aCoordinatesTag, ` $PROJECT $NUMBER"`)
}

// grantProject grants a project role to a service account.
func (s *m3aScript) grantProject(label, variable, role string) {
	s.line(`if `, s.retryFor(), ` gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$`, variable, `" --role=`, s.q(role),
		` --condition=None --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  echo '`, label, `: added'`)
	s.line(`else`)
	s.refused("  ", label, "polic=a policy")
	s.incomplete("  ")
	s.line(`fi`)
}

// bind grants roles/iam.workloadIdentityUser on a service account to a pool
// subject's principal.
func (s *m3aScript) bind(label, variable, subject string) {
	s.line(`if `, s.retryFor(), ` gcloud iam service-accounts add-iam-policy-binding "$`, variable, `" --project="$PROJECT" --role=`, s.q(m3aWIUserRole),
		` --member="$PRINCIPAL/"`, s.q(subject), ` --condition=None --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  echo '`, label, `: added'`)
	s.line(`else`)
	s.refused("  ", label, "polic=a policy")
	s.incomplete("  ")
	s.line(`fi`)
}

// readSAPolicy and readProjectPolicy read a policy into $POLICY, or empty it
// when it cannot be read, so that every binding then reads as absent.
func (s *m3aScript) readSAPolicy(variable string) {
	s.line(`gcloud iam service-accounts get-iam-policy "$`, variable, `" --project="$PROJECT" --format=json --quiet </dev/null >"$POLICY" 2>&1 || : >"$POLICY"`)
}

func (s *m3aScript) readProjectPolicy() {
	s.line(`gcloud projects get-iam-policy "$PROJECT" --format=json --quiet </dev/null >"$POLICY" 2>&1 || : >"$POLICY"`)
}

// unbind removes a principal's binding, when $POLICY shows it.
func (s *m3aScript) unbind(label, variable, subject string) {
	member := `"$PRINCIPAL/"` + s.q(subject)
	s.line(`if grep -qiF -e `, member, ` "$POLICY"; then`)
	s.line(`  if retry gcloud iam service-accounts remove-iam-policy-binding "$`, variable, `" --project="$PROJECT" --role=`, s.q(m3aWIUserRole),
		` --member=`, member, ` --condition=None --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`    echo '`, label, `: removed'`)
	s.line(`  else`)
	s.refused("    ", label, "polic=a policy")
	s.line(`  fi`)
	s.line(`else`)
	s.line(`  echo '`, label, `: absent'`)
	s.line(`fi`)
}

// ungrantProject removes a service account's project role, when $POLICY
// names the account.
func (s *m3aScript) ungrantProject(label, variable, role string) {
	s.line(`if grep -qiF -e "serviceAccount:$`, variable, `" "$POLICY"; then`)
	s.line(`  if retry gcloud projects remove-iam-policy-binding "$PROJECT" --member="serviceAccount:$`, variable, `" --role=`, s.q(role),
		` --condition=None --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`    echo '`, label, `: removed'`)
	s.line(`  else`)
	s.refused("    ", label, "polic=a policy")
	s.line(`  fi`)
	s.line(`else`)
	s.line(`  echo '`, label, `: absent'`)
	s.line(`fi`)
}

// poolPresent sets POOL_PRESENT: the pool is found, and not DELETED.
func (s *m3aScript) poolPresent() {
	s.line(`POOL_PRESENT=no`)
	s.line(`if gcloud iam workload-identity-pools describe "$POOL" --location=global --project="$PROJECT" --format='value(state)' --quiet </dev/null >"$OUT" 2>&1 && ! grep -qi -e deleted "$OUT"; then`)
	s.line(`  POOL_PRESENT=yes`)
	s.line(`fi`)
}

// deleteProvider deletes a provider that is present: the pool present, the
// provider found and not DELETED.
func (s *m3aScript) deleteProvider(label, id string) {
	q := s.q(id)
	s.line(`if [ "$POOL_PRESENT" = yes ] && gcloud iam workload-identity-pools providers describe `, q,
		` --workload-identity-pool="$POOL" --location=global --project="$PROJECT" --format='value(state)' --quiet </dev/null >"$OUT" 2>&1 && ! grep -qi -e deleted "$OUT"; then`)
	s.line(`  if retry gcloud iam workload-identity-pools providers delete `, q,
		` --workload-identity-pool="$POOL" --location=global --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`    echo '`, label, `: deleted'`)
	s.line(`  else`)
	s.refused("    ", label, "polic=a policy")
	s.line(`  fi`)
	s.line(`else`)
	s.line(`  echo '`, label, `: absent'`)
	s.line(`fi`)
}

// deletePool deletes the pool when poolPresent found it.
func (s *m3aScript) deletePool() {
	s.line(`if [ "$POOL_PRESENT" = yes ]; then`)
	s.line(`  if retry gcloud iam workload-identity-pools delete "$POOL" --location=global --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`    echo 'pool: deleted'`)
	s.line(`  else`)
	s.refused("    ", "pool", "polic=a policy")
	s.line(`  fi`)
	s.line(`else`)
	s.line(`  echo 'pool: absent'`)
	s.line(`fi`)
}

// deleteSA deletes a service account that is present.
func (s *m3aScript) deleteSA(label, variable string) {
	s.line(`if gcloud iam service-accounts describe "$`, variable, `" --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  if retry gcloud iam service-accounts delete "$`, variable, `" --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`    echo '`, label, `: deleted'`)
	s.line(`  else`)
	s.refused("    ", label, "polic=a policy")
	s.line(`  fi`)
	s.line(`else`)
	s.line(`  echo '`, label, `: absent'`)
	s.line(`fi`)
}

// m3aDisableOrder is the order disableAPIs disables the recorded APIs in, so
// that no enabled API depends on a disabled one.
var m3aDisableOrder = []string{"sts.googleapis.com", "iamcredentials.googleapis.com", "iam.googleapis.com", "cloudresourcemanager.googleapis.com"}

// m3aKeptEnabled is disableAPIs' line for an API Google did not disable.
const m3aKeptEnabled = `: kept enabled; Google refuses to disable a service used in the last 30 days without --force`

// disableAPIs disables, last, the APIs the record names (m3aDisableOrder),
// and the Org Policy API only after a y/N. Each is tried once, without
// --force: without it gcloud's services disable refuses a service used in
// the last 30 days or enabled in the last 3 [doc: gcloud's services disable
// reference, as read for the build's review on 2026-11-23], and
// every API this walk enabled is both. An API disabled leaves the record;
// one refused, or the Org Policy API left on, stays in it, and the record is
// kept, so it still names every API the walk enabled and still has on, and
// the block can be pasted again. The operator decides on --force (the
// runbook's P10). The record is removed only when it names nothing.
func (s *m3aScript) disableAPIs() {
	disable := func(indent, api string) {
		s.line(indent, `if gcloud services disable `, s.q(api), ` --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
		s.line(indent, `  echo 'API `, api, `: disabled'`)
		s.line(indent, `  { grep -vix -e `, s.q(api), ` "$RECORD" || :; } >"$KEEP"`)
		s.line(indent, `  cat "$KEEP" >"$RECORD"`)
		s.line(indent, `else`)
		s.line(indent, `  echo "API `, api, m3aKeptEnabled, `; the message names --force: $(yn 'force'); a dependent service: $(yn 'depend')"`)
		s.line(indent, `fi`)
	}
	for _, api := range m3aDisableOrder {
		s.line(`if [ -f "$RECORD" ] && grep -qix -e `, s.q(api), ` "$RECORD"; then`)
		disable("  ", api)
		s.line(`fi`)
	}
	s.line(`if [ -f "$RECORD" ] && grep -qix -e `, s.q(m3aOrgPolicyAPI), ` "$RECORD"; then`)
	s.line(`  printf 'Disable the Org Policy API, which policies.sh enabled? [y/N] ' >/dev/tty`)
	s.line(`  read -r ANSWER </dev/tty`)
	s.line(`  if [ "$ANSWER" = y ]; then`)
	disable("    ", m3aOrgPolicyAPI)
	s.line(`  else`)
	s.line(`    echo 'API `, m3aOrgPolicyAPI, `: left enabled'`)
	s.line(`  fi`)
	s.line(`fi`)
	s.line(`if [ -s "$RECORD" ]; then`)
	s.line(`  echo 'API record: kept; it names the APIs still enabled, and this block can be pasted again'`)
	s.line(`else`)
	s.line(`  rm -f "$RECORD"`)
	s.line(`  echo 'API record: removed'`)
	s.line(`fi`)
}

// updateTrust replaces a provider's trust store.
func (s *m3aScript) updateTrust(label, id string, trust []byte) {
	s.hereDoc("TRUST", "END_OF_ANCHOR", trust)
	s.line(`if retry gcloud iam workload-identity-pools providers update-x509 `, s.q(id),
		` --location=global --workload-identity-pool="$POOL" --project="$PROJECT" --trust-store-config-path="$TRUST" --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  echo '`, label, `: updated'`)
	s.line(`else`)
	s.refused("  ", label, "polic=a policy", "limit=a limit", "validity|lifetime=validity or lifetime")
	s.line(`fi`)
}

// updateFlag sets --disabled or --no-disabled on a provider. Google's page on
// managing pools and providers names both: "To disable or enable the
// provider, also pass the --disabled or --no-disabled flag" [doc:
// https://docs.cloud.google.com/iam/docs/manage-workload-identity-pools-providers,
// read 2026-11-23]; update-x509's reference names --disabled alone, and says
// that existing tokens still grant access after a disable [doc:
// https://docs.cloud.google.com/sdk/gcloud/reference/iam/workload-identity-pools/providers/update-x509,
// read 2026-11-23].
func (s *m3aScript) updateFlag(label, id, flag, done string) {
	s.line(`if retry gcloud iam workload-identity-pools providers update-x509 `, s.q(id),
		` --location=global --workload-identity-pool="$POOL" --project="$PROJECT" `, flag, ` --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`  echo '`, label, `: `, done, `'`)
	s.line(`else`)
	s.refused("  ", label, "polic=a policy", "unrecognized|no-disabled=the flag")
	s.line(`fi`)
}

// m3aTrustStoreYAML is a trust store document for one or more anchors, in
// devicekey.TrustStoreYAML's one-line PEM form. Only i7-add.sh takes two;
// every other trust store comes from devicekey.TrustStoreYAML, which takes
// one, so the product generator never takes two.
func m3aTrustStoreYAML(anchors ...[]byte) ([]byte, error) {
	if len(anchors) == 0 {
		return nil, errors.New("a trust store needs an anchor")
	}
	var b strings.Builder
	b.WriteString("trustStore:\n  trustAnchors:\n")
	for _, der := range anchors {
		c, err := x509.ParseCertificate(der)
		if err != nil || !c.IsCA {
			return nil, errors.New("a trust anchor is not a CA certificate")
		}
		p := strings.TrimSuffix(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "\n")
		b.WriteString(`  - pemCertificate: "` + strings.ReplaceAll(p, "\n", `\n`) + "\"\n")
	}
	return []byte(b.String()), nil
}

// m3aD3Condition is devicekey's condition for a role ID's hex.
func m3aD3Condition(idHex string) (string, error) {
	id, err := devicekey.ParseRoleID(idHex)
	if err != nil {
		return "", err
	}
	c := devicekey.AttributeCondition(id)
	if c == "" {
		return "", errors.New("devicekey gave no condition")
	}
	return c, nil
}

// m3aV5Condition and m3aV5Mapping are V5's [OIDC]; m3aV8Mapping is V8's
// constant subject.
func m3aV5Condition(sub string) string    { return "assertion.sub == '" + sub + "'" }
func m3aV8Mapping(constant string) string { return "google.subject='" + constant + "'" }

const m3aV5Mapping = "google.subject=assertion.sub"

// m3aProviderLabel is a provider's label in the blocks' lines.
func m3aProviderLabel(variant, role string) string {
	switch variant {
	case m3aWFED:
		return "federated " + role + " provider"
	case m3aV1, m3aV1c:
		return strings.ToUpper(variant[:1]) + variant[1:] + " " + role + " provider"
	}
	return strings.ToUpper(variant[:1]) + variant[1:] + " provider"
}

// m3aX509Spec is a variant's X509 provider for a role: its trust store holds
// that role's one anchor, its mapping is D3's (V8's constant), and its
// condition names its own ID (V1y's names both CNs).
func m3aX509Spec(st *m3aState, variant, role, stop string) (m3aProviderSpec, error) {
	p := m3aProviderSpec{label: m3aProviderLabel(variant, role), id: st.provider(variant, role), mapping: devicekey.AttributeMapping, stop: stop}
	var err error
	if p.trust, err = devicekey.TrustStoreYAML(st.anchor(variant, role)); err != nil {
		return p, fmt.Errorf("%s: %w", p.label, err)
	}
	switch variant {
	case m3aV1y:
		p.condition = m3aV1yCondition(st.roleID(variant, role))
	default:
		if p.condition, err = m3aD3Condition(st.roleID(variant, role)); err != nil {
			return p, fmt.Errorf("%s: %w", p.label, err)
		}
	}
	if variant == m3aV8 {
		p.mapping = m3aV8Mapping(st.variant(m3aV8).Subject)
	}
	return p, nil
}

// m3aBind is one workloadIdentityUser binding a block adds.
type m3aBind struct {
	label    string
	variable string // READER_SA or WRITER_SA
	subject  string
	block    string
}

// m3aBindings is the run's binding list: every principal, each on the one SA it
// is bound on, and the block that binds it.
func m3aBindings(st *m3aState) []m3aBind {
	if st.WFED {
		return []m3aBind{
			{"federated reader binding", "READER_SA", st.roleID(m3aWFED, m3aReader), "wfed-setup.sh"},
			{"federated writer binding", "WRITER_SA", st.roleID(m3aWFED, m3aWriter), "wfed-setup.sh"},
		}
	}
	out := []m3aBind{
		{"V1 reader binding", "READER_SA", st.roleID(m3aV1, m3aReader), "setup.sh"},
		{"V1b binding", "READER_SA", st.roleID(m3aV1b, m3aReader), "setup.sh"},
	}
	for _, v := range []string{m3aV2, m3aV3, m3aV4, m3aV6, m3aV7} {
		out = append(out, m3aBind{strings.ToUpper(v[:1]) + v[1:] + " binding", "READER_SA", st.roleID(v, m3aReader), "setup.sh"})
	}
	return append(out,
		m3aBind{"V5 binding", "READER_SA", st.variant(m3aV5).Subject, "setup.sh"},
		m3aBind{"V8 binding", "READER_SA", st.variant(m3aV8).Subject, "setup.sh"},
		m3aBind{"V1 writer binding", "WRITER_SA", st.roleID(m3aV1, m3aWriter), "setup.sh"},
		m3aBind{"V1c reader binding", "READER_SA", st.roleID(m3aV1c, m3aReader), "bind-v1c.sh"},
		m3aBind{"V1c writer binding", "READER_SA", st.roleID(m3aV1c, m3aWriter), "bind-v1c.sh"},
		m3aBind{"V1x binding", "READER_SA", st.roleID(m3aV1x, m3aReader), "contingent.sh"},
		m3aBind{"V1y binding", "READER_SA", st.roleID(m3aV1y, m3aReader), "contingent.sh"},
	)
}

// bindAll adds every binding the list gives to block.
func (s *m3aScript) bindAll(st *m3aState, block string) {
	for _, b := range m3aBindings(st) {
		if b.block == block {
			s.bind(b.label, b.variable, b.subject)
		}
	}
}

// m3aSetupBlock is setup.sh.
func m3aSetupBlock(st *m3aState) ([]byte, error) {
	s := &m3aScript{}
	s.open(st, "END_OF_SETUP", "Create this probe pool, its providers and its two service accounts?", "TRUST", "JWKS")
	s.enableAPIs()
	s.number()
	s.line(`echo 'project number: read'`)
	s.createPool()
	const stop = "Stopped: V1 needs both of its providers; nothing after this was created."
	for _, vr := range [][3]string{
		{m3aV1, m3aReader, stop}, {m3aV1, m3aWriter, stop}, {m3aV1b, m3aReader}, {m3aV2, m3aReader}, {m3aV3, m3aReader},
		{m3aV4, m3aReader}, {m3aV6, m3aReader}, {m3aV7, m3aReader}, {m3aV8, m3aReader},
	} {
		p, err := m3aX509Spec(st, vr[0], vr[1], vr[2])
		if err != nil {
			return nil, err
		}
		s.createX509(p)
	}
	v5 := st.variant(m3aV5)
	jwks, err := m3aV5JWKS(v5)
	if err != nil {
		return nil, err
	}
	s.createOIDC(m3aProviderLabel(m3aV5, m3aReader), st.provider(m3aV5, m3aReader), v5.Issuer, jwks, m3aV5Mapping, m3aV5Condition(v5.Subject))
	s.createSA("reader SA", "READER_SA", st.ReaderSA)
	s.createSA("writer SA", "WRITER_SA", st.WriterSA)
	s.grantProject("reader SA pool viewer grant", "READER_SA", m3aPoolViewerRole)
	s.bindAll(st, "setup.sh")
	s.complete("setup.sh")
	s.line("END_OF_SETUP")
	return s.bytes()
}

// m3aPEM is a certificate's PEM.
func m3aPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// m3aConsoleV1c is console-v1c.txt: not a script, but V1c's two providers'
// fields, labelled, for the console's forms and the reader SA's permissions
// page. The principals need the project's number: until coordinates has
// recorded it, the file says to run blocks again.
func m3aConsoleV1c(st *m3aState) ([]byte, error) {
	var b strings.Builder
	w := func(parts ...string) {
		for _, p := range parts {
			b.WriteString(p)
		}
		b.WriteByte('\n')
	}
	w("V1c: two X509 providers through the console's form, and their two principals on the reader SA.")
	w("Not a script. Everything here is public; copy each field as it stands.")
	w("")
	w("Pool ID: ", st.Pool)
	w("Attribute mapping, for both: google.subject = assertion.issuer.dn.cn")
	w("  (the mapping's whole text: ", devicekey.AttributeMapping, ")")
	for _, role := range []string{m3aReader, m3aWriter} {
		cond, err := m3aD3Condition(st.roleID(m3aV1c, role))
		if err != nil {
			return nil, err
		}
		w("")
		w(m3aProviderLabel(m3aV1c, role))
		w("  Provider ID: ", st.provider(m3aV1c, role))
		w("  Attribute condition: ", cond)
		w("  Trust anchor (PEM):")
		b.WriteString(m3aPEM(st.anchor(m3aV1c, role)))
		if st.ProjectNumber == "" {
			w("  Principal: not yet written; it names the project's number. Run the probe's blocks step again after coordinates.")
			continue
		}
		id, err := devicekey.ParseRoleID(st.roleID(m3aV1c, role))
		if err != nil {
			return nil, err
		}
		principal, err := devicekey.Principal(st.ProjectNumber, st.Pool, id)
		if err != nil {
			return nil, err
		}
		w("  Principal, granted ", m3aWIUserRole, " on the reader SA (", m3aEmail(st.ReaderSA, st.Project), "):")
		w("  ", principal)
	}
	return []byte(b.String()), nil
}

// m3aBindV1cBlock is bind-v1c.sh: the console route's fallback for V1c's two
// bindings.
func m3aBindV1cBlock(st *m3aState) ([]byte, error) {
	s := &m3aScript{}
	s.open(st, "END_OF_STEP", "Bind V1c principals on the reader SA?")
	s.number()
	s.bindAll(st, "bind-v1c.sh")
	s.line("END_OF_STEP")
	return s.bytes()
}

// m3aContingentBlock is contingent.sh: V1x's and V1y's providers, and their
// bindings on the reader SA.
func m3aContingentBlock(st *m3aState) ([]byte, error) {
	s := &m3aScript{}
	s.open(st, "END_OF_STEP", "Create the contingent providers V1x and V1y?", "TRUST")
	s.number()
	for _, v := range []string{m3aV1x, m3aV1y} {
		p, err := m3aX509Spec(st, v, m3aReader, "")
		if err != nil {
			return nil, err
		}
		s.createX509(p)
	}
	s.bindAll(st, "contingent.sh")
	s.line("END_OF_STEP")
	return s.bytes()
}

// m3aI7Block is i7-add.sh (two anchors: V1's reader anchor and I7's) or
// i7-remove.sh (V1's reader anchor alone).
func m3aI7Block(st *m3aState, add bool) ([]byte, error) {
	var trust []byte
	var err error
	if add {
		trust, err = m3aTrustStoreYAML(st.anchor(m3aV1, m3aReader), st.I7Anchor)
	} else {
		trust, err = devicekey.TrustStoreYAML(st.anchor(m3aV1, m3aReader))
	}
	if err != nil {
		return nil, err
	}
	s := &m3aScript{}
	q := "Add a second anchor to V1 reader provider?"
	if !add {
		q = "Leave V1 reader provider with its own anchor alone?"
	}
	s.open(st, "END_OF_STEP", q, "TRUST")
	s.updateTrust(m3aProviderLabel(m3aV1, m3aReader), st.provider(m3aV1, m3aReader), trust)
	s.line("END_OF_STEP")
	return s.bytes()
}

// m3aRenewPasteBlock is renew-paste.sh: V1's writer provider's trust store,
// the staged writer anchor alone.
func m3aRenewPasteBlock(st *m3aState, staged []byte) ([]byte, error) {
	trust, err := devicekey.TrustStoreYAML(staged)
	if err != nil {
		return nil, err
	}
	s := &m3aScript{}
	s.open(st, "END_OF_STEP", "Replace V1 writer provider anchor with the renewed one?", "TRUST")
	s.updateTrust(m3aProviderLabel(m3aV1, m3aWriter), st.provider(m3aV1, m3aWriter), trust)
	s.line("END_OF_STEP")
	return s.bytes()
}

// m3aConsoleRenewText is console-renew.txt: the staged writer anchor and its
// provider, for the console's edit form.
func m3aConsoleRenewText(st *m3aState, staged []byte) ([]byte, error) {
	if _, err := x509.ParseCertificate(staged); err != nil {
		return nil, errors.New("the staged anchor does not parse")
	}
	return []byte("V1 writer provider: replace its one trust anchor through the console's edit form.\n" +
		"Not a script. Everything here is public.\n\n" +
		"Pool ID: " + st.Pool + "\n" +
		"Provider ID: " + st.provider(m3aV1, m3aWriter) + "\n" +
		"The new trust anchor (PEM), in place of the one there:\n" + m3aPEM(staged)), nil
}

// m3aBindingBlock is revoke-binding.sh (remove, when present) or
// readd-binding.sh: V1's writer principal on the writer SA.
func m3aBindingBlock(st *m3aState, remove bool) ([]byte, error) {
	s := &m3aScript{}
	if remove {
		s.open(st, "END_OF_STEP", "Remove V1 writer binding on the writer SA?", "POLICY")
		s.number()
		s.readSAPolicy("WRITER_SA")
		s.unbind("V1 writer binding", "WRITER_SA", st.roleID(m3aV1, m3aWriter))
	} else {
		s.open(st, "END_OF_STEP", "Add V1 writer binding on the writer SA again?")
		s.number()
		s.bind("V1 writer binding", "WRITER_SA", st.roleID(m3aV1, m3aWriter))
	}
	s.line("END_OF_STEP")
	return s.bytes()
}

// m3aWriterFlagBlock is disable-writer.sh or enable-writer.sh.
func m3aWriterFlagBlock(st *m3aState, disable bool) ([]byte, error) {
	s := &m3aScript{}
	label, id := m3aProviderLabel(m3aV1, m3aWriter), st.provider(m3aV1, m3aWriter)
	if disable {
		s.open(st, "END_OF_STEP", "Disable V1 writer provider?")
		s.updateFlag(label, id, "--disabled", "disabled")
	} else {
		s.open(st, "END_OF_STEP", "Enable V1 writer provider again?")
		s.updateFlag(label, id, "--no-disabled", "enabled")
	}
	s.line("END_OF_STEP")
	return s.bytes()
}

// m3aProviderOrder is every provider the probe may have created, in the order
// its teardown deletes them.
var m3aProviderOrder = [][2]string{
	{m3aV1, m3aReader}, {m3aV1, m3aWriter}, {m3aV1b, m3aReader}, {m3aV1c, m3aReader}, {m3aV1c, m3aWriter},
	{m3aV1x, m3aReader}, {m3aV1y, m3aReader}, {m3aV2, m3aReader}, {m3aV3, m3aReader}, {m3aV4, m3aReader},
	{m3aV5, m3aReader}, {m3aV6, m3aReader}, {m3aV7, m3aReader}, {m3aV8, m3aReader},
}

// m3aTeardownV1Block is teardown-v1.sh: V1's two providers only (P7 (c)).
// Their bindings stay, so the measurement isolates the deletion.
func m3aTeardownV1Block(st *m3aState) ([]byte, error) {
	s := &m3aScript{}
	s.open(st, "END_OF_STEP", "Delete V1 two providers, and nothing else?")
	s.poolPresent()
	for _, role := range []string{m3aReader, m3aWriter} {
		s.deleteProvider(m3aProviderLabel(m3aV1, role), st.provider(m3aV1, role))
	}
	s.line("END_OF_STEP")
	return s.bytes()
}

// m3aTeardownBlock is teardown.sh, or W-FED's wfed-teardown.sh. Every binding
// goes first, the project grants included, before any SA is deleted: after an
// SA is deleted its bindings' member becomes deleted:serviceAccount:…?uid=…
// [inf], and a removal naming serviceAccount:<email> no longer matches it.
// Then the providers, the pool, the two SAs, and the APIs the record names.
// Each line skips an absent object.
func m3aTeardownBlock(st *m3aState) ([]byte, error) {
	s := &m3aScript{}
	q := "Remove every object this probe created?"
	if st.WFED {
		q = "Remove the federated reader objects?"
	}
	s.open(st, "END_OF_STEP", q, "POLICY", "KEEP")
	s.number()
	s.readProjectPolicy()
	if st.WFED {
		s.ungrantProject("reader SA viewer grant", "READER_SA", m3aViewerRole)
	} else {
		s.ungrantProject("reader SA pool viewer grant", "READER_SA", m3aPoolViewerRole)
	}
	for _, variable := range []string{"READER_SA", "WRITER_SA"} {
		s.readSAPolicy(variable)
		for _, b := range m3aBindings(st) {
			if b.variable == variable {
				s.unbind(b.label, b.variable, b.subject)
			}
		}
	}
	s.poolPresent()
	if st.WFED {
		for _, role := range []string{m3aReader, m3aWriter} {
			s.deleteProvider(m3aProviderLabel(m3aWFED, role), st.provider(m3aWFED, role))
		}
	} else {
		for _, vr := range m3aProviderOrder {
			s.deleteProvider(m3aProviderLabel(vr[0], vr[1]), st.provider(vr[0], vr[1]))
		}
	}
	s.deletePool()
	s.deleteSA("reader SA", "READER_SA")
	s.deleteSA("writer SA", "WRITER_SA")
	s.disableAPIs()
	s.line("END_OF_STEP")
	return s.bytes()
}

// m3aV5JWKS is V5's JWKS from its recorded public point.
func m3aV5JWKS(v *m3aVariant) ([]byte, error) {
	pub, err := m3aParseP256(v.PublicKey)
	if err != nil {
		return nil, errors.New("V5's recorded public key does not parse")
	}
	return m3aJWKS(pub, v.KID)
}

// m3aStaticBlockNames are the blocks the blocks step writes, in its order.
var m3aStaticBlockNames = []string{"setup.sh", "console-v1c.txt", "bind-v1c.sh", "i7-add.sh", "i7-remove.sh",
	"revoke-binding.sh", "readd-binding.sh", "disable-writer.sh", "enable-writer.sh", "policies.sh",
	"teardown-v1.sh", "teardown.sh"}

// m3aStaticBlocks generates every block that needs no later state.
func m3aStaticBlocks(st *m3aState) (map[string][]byte, error) {
	gens := map[string]func() ([]byte, error){
		"setup.sh":          func() ([]byte, error) { return m3aSetupBlock(st) },
		"console-v1c.txt":   func() ([]byte, error) { return m3aConsoleV1c(st) },
		"bind-v1c.sh":       func() ([]byte, error) { return m3aBindV1cBlock(st) },
		"i7-add.sh":         func() ([]byte, error) { return m3aI7Block(st, true) },
		"i7-remove.sh":      func() ([]byte, error) { return m3aI7Block(st, false) },
		"revoke-binding.sh": func() ([]byte, error) { return m3aBindingBlock(st, true) },
		"readd-binding.sh":  func() ([]byte, error) { return m3aBindingBlock(st, false) },
		"disable-writer.sh": func() ([]byte, error) { return m3aWriterFlagBlock(st, true) },
		"enable-writer.sh":  func() ([]byte, error) { return m3aWriterFlagBlock(st, false) },
		"policies.sh":       func() ([]byte, error) { return m3aPoliciesBlock(st) },
		"teardown-v1.sh":    func() ([]byte, error) { return m3aTeardownV1Block(st) },
		"teardown.sh":       func() ([]byte, error) { return m3aTeardownBlock(st) },
	}
	out := make(map[string][]byte, len(gens))
	for _, name := range m3aStaticBlockNames {
		b, err := gens[name]()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = b
	}
	return out, nil
}

// m3aWFEDBlockNames are W-FED's blocks.
var m3aWFEDBlockNames = []string{"wfed-setup.sh", "wfed-viewer.sh", "wfed-teardown.sh"}

// m3aWFEDBlocks are W-FED's three blocks: the setup for one
// writer-capable device (the pool, its two providers, the two SAs with no
// display name and the writer SA with no role, and the two bindings); the
// viewer grant, for W-FED's step only; and the teardown, the viewer grant and
// the bindings first.
func m3aWFEDBlocks(st *m3aState) (map[string][]byte, error) {
	if !st.WFED {
		return nil, errors.New("W-FED's blocks need W-FED's state")
	}
	setup := &m3aScript{}
	setup.open(st, "END_OF_SETUP", "Create the federated reader pool, its two providers and two service accounts?", "TRUST")
	setup.enableAPIs()
	setup.number()
	setup.line(`echo 'project number: read'`)
	setup.createPool()
	for _, role := range []string{m3aReader, m3aWriter} {
		p, err := m3aX509Spec(st, m3aWFED, role, "Stopped: the federated reader needs both of its providers; nothing after this was created.")
		if err != nil {
			return nil, err
		}
		setup.createX509(p)
	}
	setup.createSA("reader SA", "READER_SA", st.ReaderSA)
	setup.createSA("writer SA", "WRITER_SA", st.WriterSA)
	setup.bindAll(st, "wfed-setup.sh")
	setup.complete("wfed-setup.sh")
	setup.line("END_OF_SETUP")

	viewer := &m3aScript{}
	viewer.open(st, "END_OF_STEP", "Grant the federated reader SA container.viewer on the project, for this step only?")
	viewer.grantProject("reader SA viewer grant", "READER_SA", m3aViewerRole)
	viewer.line("END_OF_STEP")

	out := map[string][]byte{}
	var err error
	if out["wfed-setup.sh"], err = setup.bytes(); err != nil {
		return nil, err
	}
	if out["wfed-viewer.sh"], err = viewer.bytes(); err != nil {
		return nil, err
	}
	if out["wfed-teardown.sh"], err = m3aTeardownBlock(st); err != nil {
		return nil, err
	}
	return out, nil
}

// m3aDigest is a block's digest as the probe prints it: the first 12 hex of
// its SHA-256.
func m3aDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:12]
}

// ---- audit.sh and policies.sh ----

// m3aEncodingNames are the encodings audit.sh looks for each leaf serial and
// fingerprint in. Google's attribute is serialNumberHex [X509]; how the logs
// encode a fingerprint is unknown.
var m3aEncodingNames = []string{"decimal", "lower hex", "upper hex", "colon hex", "base64 std", "base64 url"}

// m3aEncodings is b in each encoding; decimal only when it is given (a
// serial's).
func m3aEncodings(b []byte, decimal string) map[string]string {
	lower := hex.EncodeToString(b)
	upper := strings.ToUpper(lower)
	pairs := make([]string, 0, len(b))
	for i := 0; i+1 < len(upper); i += 2 {
		pairs = append(pairs, upper[i:i+2])
	}
	out := map[string]string{
		"lower hex":  lower,
		"upper hex":  upper,
		"colon hex":  strings.Join(pairs, ":"),
		"base64 std": base64.StdEncoding.EncodeToString(b),
		"base64 url": base64.RawURLEncoding.EncodeToString(b),
	}
	if decimal != "" {
		out["decimal"] = decimal
	}
	return out
}

// m3aAuditScrubOpaque and m3aAuditScrubDigits are audit.sh's scrub of key
// paths, besides the run's literals: every run of 20 or more token characters
// (a pool's or provider's ID is 32 of [a-z0-9], not hex; an SA ID 30) and of
// six or more digits.
const (
	m3aAuditScrubOpaque = "[A-Za-z0-9_-]{20,}"
	m3aAuditScrubDigits = "[0-9]{6,}"
)

// m3aAuditData is the data audit.sh embeds for jq: values only, read with
// yes/no and never printed.
type m3aAuditData struct {
	Literals       []string            `json:"literals"`
	RoleIDs        []string            `json:"role_ids"`
	Serials        map[string][]string `json:"serials"`
	Fingerprints   map[string][]string `json:"fingerprints"`
	CAFingerprints map[string][]string `json:"ca_fingerprints"`
}

// m3aAuditCAs is every CA certificate the run made: each variant's anchors,
// I7's anchor, and the state's CAs (N1's anchor, the negatives'
// intermediates, each staged anchor). Google's X.509 keyInfo carries a trust
// anchor's or an intermediate CA's SHA-256 fingerprint [doc:
// https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity,
// read 2026-11-23], and an anchor's names one device's role for 390 days,
// across its leaves' renewals.
func m3aAuditCAs(st *m3aState) [][]byte {
	var out [][]byte
	for _, name := range slices.Sorted(maps.Keys(st.Variants)) {
		v := st.Variants[name]
		for _, role := range slices.Sorted(maps.Keys(v.Anchors)) {
			out = append(out, v.Anchors[role])
		}
	}
	if len(st.I7Anchor) > 0 {
		out = append(out, st.I7Anchor)
	}
	return append(out, st.CAs...)
}

// m3aAuditDataOf is the run's literals, its subjects, every leaf's serial
// and SHA-256 fingerprint, and every CA's SHA-256 fingerprint (m3aAuditCAs),
// each in each encoding.
func m3aAuditDataOf(st *m3aState) (m3aAuditData, error) {
	d := m3aAuditData{Serials: map[string][]string{}, Fingerprints: map[string][]string{}, CAFingerprints: map[string][]string{}}
	for _, l := range m3aLiterals(st) {
		d.Literals = append(d.Literals, l[0])
	}
	for _, name := range slices.Sorted(maps.Keys(st.Variants)) {
		v := st.Variants[name]
		for _, role := range []string{m3aReader, m3aWriter} {
			if id := v.RoleIDs[role]; id != "" {
				d.RoleIDs = append(d.RoleIDs, id)
			}
		}
		if v.Subject != "" {
			d.RoleIDs = append(d.RoleIDs, v.Subject)
		}
	}
	for _, der := range st.Leaves {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return d, errors.New("a recorded leaf does not parse")
		}
		sum := sha256.Sum256(der)
		for k, v := range m3aEncodings(c.SerialNumber.Bytes(), c.SerialNumber.String()) {
			d.Serials[k] = append(d.Serials[k], v)
		}
		for k, v := range m3aEncodings(sum[:], "") {
			d.Fingerprints[k] = append(d.Fingerprints[k], v)
		}
	}
	for _, der := range m3aAuditCAs(st) {
		if _, err := x509.ParseCertificate(der); err != nil {
			return d, errors.New("a recorded CA does not parse")
		}
		sum := sha256.Sum256(der)
		for k, v := range m3aEncodings(sum[:], "") {
			d.CAFingerprints[k] = append(d.CAFingerprints[k], v)
		}
	}
	return d, nil
}

// m3aAuditDefs are audit.sh's jq definitions. The program holds no ', since
// the shell single-quotes it. A yes names, in words, the services whose
// entries carry it (svc), never a host.
const m3aAuditDefs = `def yesno: if any then "yes" else "no" end;
def svc: (.protoPayload.serviceName // "") as $n | {"sts.googleapis.com": "STS", "iamcredentials.googleapis.com": "IAM Credentials", "iam.googleapis.com": "IAM"}[$n] // "another service";
def where(f): [.[] | select(f) | svc] | unique | if length > 0 then "yes (" + join(", ") + ")" else "no" end;
def scrub: reduce ($D[0].literals[]) as $l (.; split($l) | join("#")) | gsub("` + m3aAuditScrubOpaque + `"; "#") | gsub("` + m3aAuditScrubDigits + `"; "#");
def keypaths: [.[] | paths(scalars) | map(tostring) | join(".") | scrub] | unique | join(", ");
def names($k): where([paths | map(tostring) | join(".") | contains($k)] | any);
def ids: where(tostring as $s | any($D[0].role_ids[]; . as $x | $s | contains($x)));
def which($kind): [.[] | svc as $v | tostring as $s | $D[0][$kind] | to_entries[] | select(any(.value[]; . as $x | $s | contains($x))) | .key + " in " + $v] | unique | if length > 0 then "yes (" + join(", ") + ")" else "no" end;
def agent($w): [.[] | (.protoPayload.requestMetadata.callerSuppliedUserAgent // "") | ascii_downcase | contains($w)] | yesno;
def federated: ((.protoPayload.authenticationInfo.principalSubject // "") != "") or ((.protoPayload.methodName // "") | test("[.](Get|List)[A-Za-z]*$") | not);
`

// m3aAuditReads are audit.sh's four reads: a label, the filter after the
// log's name, which log, and the jq program printed for it. Google asks for
// Data Access's Admin Read on both the IAM API and STS to log "all steps of
// the token-exchange process" [doc:
// https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity,
// read 2026-11-23], without saying which step the IAM API logs, so the fourth
// read takes the IAM API's Data Access entries. It counts them all, and reads
// further only those with a principalSubject or a method that is not a Get or
// a List [inf: the operator's own describe and list calls are Gets and Lists
// with no principalSubject], and also checks every entry for keyInfo, a role
// ID and a fingerprint.
var m3aAuditReads = []struct{ label, filter, log, jq string }{
	{
		"Admin Activity, pools and providers",
		`protoPayload.serviceName=\"iam.googleapis.com\" AND protoPayload.methodName:\"WorkloadIdentityPool\"`,
		"ACTIVITY",
		`"Admin Activity, pools and providers: \(length) entries",
"  the request holds a PEM (BEGIN CERTIFICATE): \([.[] | .protoPayload.request | tostring | contains("BEGIN CERTIFICATE")] | yesno)",
"  holds the condition (assertion.issuer.dn.cn): \([.[] | .protoPayload.request | tostring | contains("assertion.issuer.dn.cn")] | yesno)",
"  holds a role ID: \(ids)"`,
	},
	{
		"Admin Activity, SetIamPolicy on the service accounts",
		`protoPayload.serviceName=\"iam.googleapis.com\" AND protoPayload.methodName:\"SetIAMPolicy\" AND resource.type=\"service_account\"`,
		"ACTIVITY",
		`"Admin Activity, SetIamPolicy on the service accounts: \(length) entries",
"  a binding delta member names a role ID: \([.[] | .protoPayload.serviceData.policyDelta.bindingDeltas[]? | (.member // "") | tostring as $s | any($D[0].role_ids[]; . as $x | $s | contains($x))] | yesno)"`,
	},
	{
		"Data Access, STS and IAM Credentials",
		`(protoPayload.serviceName=\"sts.googleapis.com\" OR protoPayload.serviceName=\"iamcredentials.googleapis.com\")`,
		"DATAACCESS",
		`"Data Access, STS and IAM Credentials: \(length) entries",
"  key paths (scrubbed): \(keypaths)",
"  principalSubject present: \(names("principalSubject"))",
"  keyInfo present: \(names("keyInfo"))",
"  a leaf serial appears: \(which("serials"))",
"  a leaf fingerprint appears: \(which("fingerprints"))",
"  a role ID appears: \(ids)",
"  an anchor or intermediate CA fingerprint appears: \(which("ca_fingerprints"))",
"  the user agent names farcast: \(agent("farcast"))",
"  names the Go default client: \(agent("go-http-client"))",
"  names gl-go: \(agent("gl-go"))"`,
	},
	{
		"Data Access, IAM",
		`protoPayload.serviceName=\"iam.googleapis.com\"`,
		"DATAACCESS",
		`"Data Access, IAM: \(length) entries",
"  in all of them: keyInfo present: \(names("keyInfo")); a role ID appears: \(ids); a leaf fingerprint appears: \(which("fingerprints")); an anchor or intermediate CA fingerprint appears: \(which("ca_fingerprints"))",
(map(select(federated)) |
"  kept (a principalSubject, or a method other than a Get or a List): \(length) entries",
"  key paths (scrubbed): \(keypaths)",
"  principalSubject present: \(names("principalSubject"))",
"  keyInfo present: \(names("keyInfo"))",
"  a leaf serial appears: \(which("serials"))",
"  a leaf fingerprint appears: \(which("fingerprints"))",
"  an anchor or intermediate CA fingerprint appears: \(which("ca_fingerprints"))",
"  a role ID appears: \(ids)",
"  the user agent names farcast: \(agent("farcast"))")`,
	},
}

// m3aAuditBlock is audit.sh (P8): three logging reads, each piped to jq,
// which prints counts, scrubbed key paths and yes/no only. It embeds the
// run's IDs, and every leaf's serial and fingerprint in each encoding.
func m3aAuditBlock(st *m3aState) ([]byte, error) {
	d, err := m3aAuditDataOf(st)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	s := &m3aScript{}
	s.open(st, "END_OF_STEP", "Read this session audit entries, as counts and yes/no only?", "DATA")
	s.hereDoc("DATA", "END_OF_DATA", data)
	s.line("DEFS='", m3aAuditDefs, "'")
	s.line(`ACTIVITY="logName=\"projects/$PROJECT/logs/cloudaudit.googleapis.com%2Factivity\""`)
	s.line(`DATAACCESS="logName=\"projects/$PROJECT/logs/cloudaudit.googleapis.com%2Fdata_access\""`)
	for _, r := range m3aAuditReads {
		s.line(`if gcloud logging read "$`, r.log, ` AND `, r.filter, `" --project="$PROJECT" --freshness=1d --format=json --quiet </dev/null >"$OUT" 2>&1; then`)
		s.line(`  jq -r --slurpfile D "$DATA" "$DEFS"'`, r.jq, `' "$OUT"`)
		s.line(`else`)
		s.refused("  ", r.label+": not read", "permission=a permission")
		s.line(`fi`)
	}
	s.line("END_OF_STEP")
	return s.bytes()
}

// m3aPolicyConstraints is P9's list of constraints, as policies.sh reads
// them. Every name is on Google's constraint list [doc:
// https://docs.cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints,
// both parts read 2026-11-23], and it holds the whole secure-by-default
// baseline (m3aSecureByDefault) and the legacy protocol-forwarding constraint
// that page says may already be applied [doc:
// https://docs.cloud.google.com/resource-manager/docs/secure-by-default-organizations,
// read 2026-11-23]. A name Google does not know prints "not readable", not a
// stop.
var m3aPolicyConstraints = []string{
	"iam.allowedPolicyMemberDomains",
	"iam.managed.allowedPolicyMembers",
	"iam.automaticIamGrantsForDefaultServiceAccounts",
	"iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts",
	"iam.disableServiceAccountKeyCreation",
	"iam.managed.disableServiceAccountKeyCreation",
	"iam.disableServiceAccountKeyUpload",
	"iam.managed.disableServiceAccountKeyUpload",
	"iam.workloadIdentityPoolProviders",
	"iam.managed.workloadIdentityPoolProviders",
	"iam.workloadIdentityPoolAwsAccounts",
	"essentialcontacts.allowedContactDomains",
	"essentialcontacts.managed.allowedContactDomains",
	"compute.managed.restrictProtocolForwardingCreationForTypes",
	"compute.restrictProtocolForwardingCreationForTypes",
	"storage.uniformBucketLevelAccess",
	"storage.publicAccessPrevention",
}

// m3aSecureByDefault is the secure-by-default baseline's seven constraints,
// in the page's order [doc:
// https://docs.cloud.google.com/resource-manager/docs/secure-by-default-organizations,
// read 2026-11-23]. P9 records whether the organization carries them all.
var m3aSecureByDefault = []string{
	"iam.managed.disableServiceAccountKeyCreation",
	"iam.disableServiceAccountKeyUpload",
	"iam.automaticIamGrantsForDefaultServiceAccounts",
	"iam.allowedPolicyMemberDomains",
	"essentialcontacts.managed.allowedContactDomains",
	"compute.managed.restrictProtocolForwardingCreationForTypes",
	"storage.uniformBucketLevelAccess",
}

// m3aWIFConstraints are the two whose allowed values policies.sh counts by
// kind.
var m3aWIFConstraints = []string{"iam.workloadIdentityPoolProviders", "iam.managed.workloadIdentityPoolProviders"}

// m3aPolicyJQ prints a constraint's effective state: enforced yes/no, and for
// a list constraint allow all, deny all, or its counts of values.
const m3aPolicyJQ = `def yesno: if any then "yes" else "no" end;
(.spec.rules // []) as $r |
"\($c): enforced: \([$r[] | .enforce == true] | yesno)",
(if ([$r[] | has("allowAll") or has("denyAll") or has("values")] | any) then
  "  " + (if ([$r[] | .allowAll == true] | any) then "allow all"
    elif ([$r[] | .denyAll == true] | any) then "deny all"
    else "\([$r[] | .values.allowedValues[]?] | length) allowed, \([$r[] | .values.deniedValues[]?] | length) denied values" end)
 else empty end)`

// m3aKindsJQ counts the allowed values of a provider constraint by kind.
const m3aKindsJQ = `[(.spec.rules // [])[] | (.values.allowedValues[]?), ((.parameters // {}) | .. | strings)] |
"  allowed values: \([.[] | select(startswith("https://"))] | length) issuer URI, \([.[] | select(. == "KEY_UPLOAD")] | length) KEY_UPLOAD, \([.[] | select((startswith("https://") | not) and . != "KEY_UPLOAD")] | length) other"`

// m3aPoliciesBlock is policies.sh (P9): a y/N before enabling the Org Policy
// API, recorded for teardown.sh; then each constraint's effective state, and
// the organization's custom constraints on WIF providers, as a count.
func m3aPoliciesBlock(st *m3aState) ([]byte, error) {
	s := &m3aScript{}
	s.open(st, "END_OF_STEP", "Read the organization policies this project sees?")
	s.line(`if gcloud services list --enabled --project="$PROJECT" --format='value(config.name)' --quiet </dev/null >"$OUT" 2>&1 && grep -qix -e `, s.q(m3aOrgPolicyAPI), ` "$OUT"; then`)
	s.line(`  echo 'Org Policy API: already enabled'`)
	s.line(`else`)
	s.line(`  printf 'Enable the Org Policy API for this session (teardown asks before disabling it)? [y/N] ' >/dev/tty`)
	s.line(`  read -r ANSWER </dev/tty`)
	s.line(`  if [ "$ANSWER" = y ] && retry gcloud services enable `, s.q(m3aOrgPolicyAPI), ` --project="$PROJECT" --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`    echo `, s.q(m3aOrgPolicyAPI), ` >>"$RECORD"`)
	s.line(`    echo 'Org Policy API: enabled'`)
	s.line(`  else`)
	s.line(`    echo 'Org Policy API: not enabled; a constraint may read as not readable'`)
	s.line(`  fi`)
	s.line(`fi`)
	s.line("POLICYJQ='", m3aPolicyJQ, "'")
	s.line("KINDSJQ='", m3aKindsJQ, "'")
	for _, c := range m3aPolicyConstraints {
		s.line(`if gcloud org-policies describe `, s.q(c), ` --effective --project="$PROJECT" --format=json --quiet </dev/null >"$OUT" 2>&1; then`)
		s.line(`  jq -r --arg c `, s.q(c), ` "$POLICYJQ" "$OUT"`)
		if slices.Contains(m3aWIFConstraints, c) {
			s.line(`  jq -r "$KINDSJQ" "$OUT"`)
		}
		s.line(`else`)
		s.refused("  ", c+": not readable", "permission=a permission", "not.found|invalid=an unknown constraint")
		s.line(`fi`)
	}
	s.line(`ORG="$(gcloud projects get-ancestors "$PROJECT" --filter='type=organization' --format='value(id)' --quiet </dev/null 2>"$OUT")" || ORG=''`)
	s.line(`case "$ORG" in`)
	s.line(`  ''|*[!0-9]*) echo 'custom constraints on WorkloadIdentityPoolProvider: not readable (no organization read)' ;;`)
	s.line(`  *)`)
	s.line(`    if gcloud org-policies list-custom-constraints --organization="$ORG" --format=json --quiet </dev/null >"$OUT" 2>&1; then`)
	s.line(`      jq -r '"custom constraints on WorkloadIdentityPoolProvider: \([.[] | select((.resourceTypes // []) | index("iam.googleapis.com/WorkloadIdentityPoolProvider"))] | length)"' "$OUT"`)
	s.line(`    else`)
	s.line(`      echo 'custom constraints on WorkloadIdentityPoolProvider: not readable'`)
	s.line(`    fi`)
	s.line(`    ;;`)
	s.line(`esac`)
	s.line(`echo 'principal bindings admitted: see setup.sh lines (added, or refused naming a policy)'`)
	s.line("END_OF_STEP")
	return s.bytes()
}

// ---- Scrubbing ----

// m3aLiterals are the run's values for the scrubber, each with what it
// prints as, longest first: the project ID and number, the pool, every
// provider, both SA IDs and emails, every role ID and subject, V8's
// constant, V5's issuer, its host and its kid, and the API record's name.
func m3aLiterals(st *m3aState) [][2]string {
	var out [][2]string
	seen := map[string]bool{}
	add := func(v, as string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, [2]string{v, as})
		}
	}
	add(st.Project, "$PROJECT")
	add(st.ProjectNumber, "$NUMBER")
	add(st.Pool, "$POOL")
	for _, sa := range []string{st.ReaderSA, st.WriterSA} {
		if sa != "" {
			add(m3aEmail(sa, st.Project), "$SA_EMAIL")
			add(sa, "$SA")
		}
	}
	add(st.APIRecord, "$RECORD")
	for _, name := range slices.Sorted(maps.Keys(st.Variants)) {
		v := st.Variants[name]
		for _, role := range slices.Sorted(maps.Keys(v.Providers)) {
			add(v.Providers[role], "$PROVIDER")
		}
		for _, role := range slices.Sorted(maps.Keys(v.RoleIDs)) {
			add(v.RoleIDs[role], "$ROLE_ID")
		}
		add(v.Subject, "$SUBJECT")
		add(v.Issuer, "$ISSUER")
		if host := strings.TrimPrefix(v.Issuer, "https://"); host != v.Issuer {
			add(host, "$ISSUER")
			add(strings.TrimSuffix(host, ".invalid"), "$ISSUER")
		}
		add(v.KID, "$KID")
	}
	slices.SortStableFunc(out, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
	return out
}

// ---- Token info ----

// m3aTokenInfoFacts are what T2 prints of token info's answer: whether the
// email matches, the scopes by short name, and expires_in. Never azp, aud or
// the email itself.
type m3aTokenInfoFacts struct {
	email     string   // "yes", "no" or "absent"
	scopes    []string // "cloud-platform", "userinfo.email", "<n> other"
	expiresIn string   // digits, or "unreadable" or "absent"
}

// m3aTokenInfo reduces token info's answer. It reads only email, scope and
// expires_in, as strings.
func m3aTokenInfo(body []byte, wantEmail string) (m3aTokenInfoFacts, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return m3aTokenInfoFacts{}, errors.New("token info's answer is not a JSON object")
	}
	str := func(k string) (string, bool) {
		v, ok := raw[k]
		if !ok {
			return "", false
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			return s, true
		}
		var n json.Number
		if json.Unmarshal(v, &n) == nil {
			return n.String(), true
		}
		return "", true
	}
	f := m3aTokenInfoFacts{email: "absent", expiresIn: "absent"}
	if e, ok := str("email"); ok {
		f.email = "no"
		if e != "" && e == wantEmail {
			f.email = "yes"
		}
	}
	if sc, ok := str("scope"); ok {
		other := 0
		var cp, ue bool
		for _, s := range strings.Fields(sc) {
			switch s {
			case kube.ScopeCloudPlatform:
				cp = true
			case kube.ScopeUserinfoEmail:
				ue = true
			default:
				other++
			}
		}
		if cp {
			f.scopes = append(f.scopes, "cloud-platform")
		}
		if ue {
			f.scopes = append(f.scopes, "userinfo.email")
		}
		if other > 0 {
			f.scopes = append(f.scopes, strconv.Itoa(other)+" other")
		}
	}
	if e, ok := str("expires_in"); ok {
		f.expiresIn = "unreadable"
		if n, err := strconv.Atoi(e); err == nil && n >= 0 && len(e) <= 10 {
			f.expiresIn = strconv.Itoa(n)
		}
	}
	return f, nil
}

// m3aReadLimited reads at most max bytes of r, and refuses more.
func m3aReadLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("the answer is larger than the probe reads")
	}
	return b, nil
}

// ---- Which mark a step measures from ----

// m3aStepSinceMark is each step's own mark: the IAM change it tests.
// renewal and writer-back take theirs from FARCAST_WALK_M3A_SINCE, held steps
// wait for theirs, and a negative's second check measures from the latest
// mark of any name.
var m3aStepSinceMark = map[string]string{
	"console": "console", "contingent": "contingent",
	"t1": "setup", "t2": "setup", "t3": "setup", "t4": "setup", "v1b": "setup", "variants": "setup",
	"i1": "setup", "i2": "setup", "i3": "setup", "i4": "setup", "i5": "setup", "i6": "setup",
	"i7-added": "i7-add", "i7-removed": "i7-remove",
	"wfed": "wfed-setup", "wfed-gone": "wfed-teardown",
}

// m3aStepSinceChoices are the marks FARCAST_WALK_M3A_SINCE may name.
var m3aStepSinceChoices = map[string][]string{
	"renewal":     {"renew-paste", "renew-console"},
	"writer-back": {"readd-binding", "enable-writer"},
}

// m3aStepSince is the time step's positives and polls measure from: the last
// time of its own mark, never the latest mark of any name.
func m3aStepSince(marks m3aMarks, step, since string) (time.Time, error) {
	name, ok := m3aStepSinceMark[step]
	if choices, takes := m3aStepSinceChoices[step]; takes {
		if !slices.Contains(choices, since) {
			return time.Time{}, fmt.Errorf("%s measures from FARCAST_WALK_M3A_SINCE, which must be %s", step, strings.Join(choices, " or "))
		}
		name, ok = since, true
	}
	if !ok {
		return time.Time{}, fmt.Errorf("%s measures from no mark of its own", step)
	}
	t, ok := marks.last(name)
	if !ok {
		return time.Time{}, fmt.Errorf("%s measures from the mark %s, which is not recorded; run mark first", step, name)
	}
	return t, nil
}

// m3aSeconds is a delta in whole seconds.
func m3aSeconds(d time.Duration) string {
	return strconv.FormatInt(int64(d/time.Second), 10) + " s"
}

// m3aLatestNote is "M s after the latest mark" where the latest mark is
// later than since, else "".
func m3aLatestNote(at, since time.Time, marks m3aMarks) string {
	if latest, ok := marks.latest(); ok && latest.After(since) {
		return m3aSeconds(at.Sub(latest)) + " after the latest mark"
	}
	return ""
}

// m3aAfter is "after N s", and, where the latest mark is later than since,
// "(M s after the latest mark)": both deltas, never a time.
func m3aAfter(at, since time.Time, marks m3aMarks) string {
	out := "after " + m3aSeconds(at.Sub(since))
	if note := m3aLatestNote(at, since, marks); note != "" {
		out += " (" + note + ")"
	}
	return out
}

// ======== Tests ========

// m3aFakeClock is a clock that moves only when the code sleeps.
type m3aFakeClock struct {
	t      time.Time
	sleeps []time.Duration
}

func (f *m3aFakeClock) clock() m3aClock {
	return m3aClock{
		now: func() time.Time { return f.t },
		sleep: func(_ context.Context, d time.Duration) error {
			f.sleeps = append(f.sleeps, d)
			f.t = f.t.Add(d)
			return nil
		},
	}
}

// m3aT0 is the tests' fixed start.
var m3aT0 = time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

// TestWalkM3aEnvironmentFaults: each variable the probe refuses is named when set,
// the proxies in any case; a clean environment gives none; and no fault holds
// the value.
func TestWalkM3aEnvironmentFaults(t *testing.T) {
	const value = "planted-value-7f3a"
	base := []string{"PATH=/usr/bin:/bin", "HOME=/nowhere", "TMPDIR=/tmp", "FARCAST_WALK=1", "GOFLAGS=-mod=vendor", "MY_HTTPS_PROXY=x", "GODEBUGX=1", "GOOGLEX=1"}
	if got := m3aEnvironmentFaults(base); len(got) != 0 {
		t.Errorf("a clean environment gives faults %q", got)
	}
	for _, name := range []string{"GODEBUG", "SSL_CERT_FILE", "SSL_CERT_DIR", "KUBECONFIG", "GOOGLE_APPLICATION_CREDENTIALS",
		"GOOGLE_SDK_GO_LOGGING_LEVEL", "GOOGLE_API_USE_CLIENT_CERTIFICATE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "all_proxy", "no_proxy", "Https_Proxy"} {
		got := m3aEnvironmentFaults(append(slices.Clone(base), name+"="+value))
		if !slices.Equal(got, []string{name}) {
			t.Errorf("%s set: faults %q, want it named", name, got)
		}
		for _, f := range got {
			if strings.Contains(f, value) {
				t.Errorf("a fault holds the value: %q", f)
			}
		}
	}
	if got := m3aEnvironmentFaults(append(slices.Clone(base), "HTTPS_PROXY=", "GODEBUG=http2debug=2")); !slices.Equal(got, []string{"GODEBUG", "HTTPS_PROXY"}) {
		t.Errorf("faults %q, want GODEBUG and HTTPS_PROXY (an empty value is still set)", got)
	}
}

// TestWalkM3aSettleSchedule: a positive is tried at 0, 5, 15, 35, 75, 135,
// 195, … s, below 600 s; at least once when since is long past; the first
// success ends it; and a negative's second check comes at the later of its
// two times.
func TestWalkM3aSettleSchedule(t *testing.T) {
	fc := &m3aFakeClock{t: m3aT0}
	var tries []time.Duration
	_, ok := m3aPositive(context.Background(), fc.clock(), m3aT0, func() bool {
		tries = append(tries, fc.t.Sub(m3aT0))
		return false
	})
	want := []time.Duration{0, 5, 15, 35, 75, 135, 195, 255, 315, 375, 435, 495, 555}
	for i := range want {
		want[i] *= time.Second
	}
	if ok || !slices.Equal(tries, want) {
		t.Errorf("tries at %v (accepted %v), want %v and not accepted", tries, ok, want)
	}

	fc = &m3aFakeClock{t: m3aT0}
	n := 0
	if _, ok := m3aPositive(context.Background(), fc.clock(), m3aT0.Add(-time.Hour), func() bool { n++; return false }); ok || n != 1 {
		t.Errorf("since long past: %d tries, want exactly 1", n)
	}

	fc = &m3aFakeClock{t: m3aT0}
	n = 0
	d, ok := m3aPositive(context.Background(), fc.clock(), m3aT0, func() bool { n++; return n == 3 })
	if !ok || d != 15*time.Second || n != 3 {
		t.Errorf("accepted at the third try: delta %v, ok %v, %d tries; want 15 s, true, 3", d, ok, n)
	}

	for _, tc := range []struct {
		name   string
		latest time.Time
		second time.Duration
	}{
		{"the bound after the latest mark", m3aT0.Add(-2 * time.Minute), 8 * time.Minute},
		{"60 s after the first check", m3aT0.Add(-time.Hour), time.Minute},
	} {
		fc := &m3aFakeClock{t: m3aT0}
		var at []time.Duration
		m3aNegative(context.Background(), fc.clock(), tc.latest, func() m3aCheck {
			at = append(at, fc.t.Sub(m3aT0))
			return m3aCheck{control: true}
		})
		if len(at) != 2 || at[0] != 0 || at[1] != tc.second {
			t.Errorf("%s: checks at %v, want 0 and %v", tc.name, at, tc.second)
		}
	}
}

// TestWalkM3aRounds: t1's round-robin keeps trying the shapes not yet
// accepted, gives each its own delta or false, and ends once all pass.
func TestWalkM3aRounds(t *testing.T) {
	fc := &m3aFakeClock{t: m3aT0}
	acceptAt := []time.Duration{0, 15 * time.Second, -1, 5 * time.Second}
	tried := make([]int, 4)
	out := m3aRounds(context.Background(), fc.clock(), m3aT0, 4, func(i int) bool {
		tried[i]++
		return acceptAt[i] >= 0 && fc.t.Sub(m3aT0) >= acceptAt[i]
	})
	for i, o := range out {
		switch {
		case acceptAt[i] < 0 && o.ok:
			t.Errorf("shape %d: accepted, want never", i)
		case acceptAt[i] >= 0 && (!o.ok || o.delta != acceptAt[i]):
			t.Errorf("shape %d: %+v, want accepted after %v", i, o, acceptAt[i])
		}
	}
	if tried[0] != 1 || tried[3] != 2 || tried[1] != 3 || tried[2] != 13 {
		t.Errorf("tries per shape %v, want [1 3 13 2]", tried)
	}

	fc = &m3aFakeClock{t: m3aT0}
	all := 0
	out = m3aRounds(context.Background(), fc.clock(), m3aT0, 4, func(i int) bool { all++; return fc.t.After(m3aT0) || i%2 == 0 })
	if all != 6 || fc.t.Sub(m3aT0) != 5*time.Second || !out[1].ok || !out[3].ok {
		t.Errorf("all accepted by the second round: %d tries, %v elapsed; want 6 tries and 5 s", all, fc.t.Sub(m3aT0))
	}

	// Two targets measured from one mark (t1's two roles, console's two, or
	// renewal's two checks) go in one round-robin: the reader's shapes,
	// refused for good, do not hold back the writer's, so a writer accepted at
	// 30 s reads 35 s (its try at 35 s), not the bound.
	fc = &m3aFakeClock{t: m3aT0}
	firstWriterTry := time.Duration(-1)
	over := m3aRoundsOver(context.Background(), fc.clock(), m3aT0, []int{4, 4}, func(target, i int) bool {
		if target == 0 {
			return false
		}
		if firstWriterTry < 0 {
			firstWriterTry = fc.t.Sub(m3aT0)
		}
		return fc.t.Sub(m3aT0) >= 30*time.Second
	})
	if len(over) != 2 || len(over[0]) != 4 || len(over[1]) != 4 {
		t.Fatalf("outcomes %v, want two targets of four", over)
	}
	if firstWriterTry != 0 {
		t.Errorf("the writer was first tried %v after the mark, want at once", firstWriterTry)
	}
	for i := range 4 {
		if over[0][i].ok {
			t.Errorf("reader shape %d accepted, want never", i)
		}
		if o := over[1][i]; !o.ok || o.delta != 35*time.Second {
			t.Errorf("writer shape %d: %+v, want accepted after 35 s, from the mark", i, o)
		}
	}

	// An entry that waits for another (t1's first impersonation of a role,
	// once a shape of the role is accepted) is tried from the round its source
	// was accepted in, at the same times, and measured from the mark: with
	// S1 accepted at 35 s, its binding settled at 45 s, and S4 refused for
	// good, which runs the round-robin to its bound, the impersonation reads
	// 75 s, its first try 35 s, not a try after the bound. An entry whose
	// source never passes is never tried and keeps nothing going.
	fc = &m3aFakeClock{t: m3aT0}
	var impTries []time.Duration
	srcOK := false
	out = m3aRoundsReady(context.Background(), fc.clock(), m3aT0, 3, func(i int) bool {
		return i != 2 || srcOK
	}, func(i int) bool {
		switch i {
		case 0:
			srcOK = fc.t.Sub(m3aT0) >= 30*time.Second
			return srcOK
		case 1:
			return false
		}
		impTries = append(impTries, fc.t.Sub(m3aT0))
		return fc.t.Sub(m3aT0) >= 45*time.Second
	})
	if o := out[2]; !o.ok || o.delta != 75*time.Second || o.first != 35*time.Second || o.tries != 2 {
		t.Errorf("the impersonation: %+v (tried at %v); want accepted after 75 s, first tried at 35 s, 2 tries", o, impTries)
	}
	if o := out[0]; !o.ok || o.delta != 35*time.Second || o.first != 0 || o.tries != 4 {
		t.Errorf("S1: %+v, want accepted after 35 s, first tried at 0 s, 4 tries", o)
	}
	if o := out[1]; o.ok || o.tries != 13 || o.first != 0 {
		t.Errorf("S4: %+v, want 13 tries from the mark and never accepted", o)
	}
	fc = &m3aFakeClock{t: m3aT0}
	never := 0
	out = m3aRoundsReady(context.Background(), fc.clock(), m3aT0, 2, func(i int) bool { return i == 0 }, func(i int) bool {
		if i == 1 {
			never++
		}
		return i == 0
	})
	if never != 0 || out[1].tries != 0 || out[1].ok || fc.t != m3aT0 {
		t.Errorf("an entry never ready: tried %d times, %+v, %v elapsed; want never tried, and the round-robin ended at once", never, out[1], fc.t.Sub(m3aT0))
	}
}

// TestWalkM3aT1PlanMeasuresFromTheMark: t1's one round-robin holds V1's two
// roles, V1b, and each one's first impersonation (V1b's gating), so nothing
// waits for another entry's bound. Driven as the review drove P3 (S4 refused
// for good, the other shapes accepted at 30 s, every binding settled at 45 s,
// which runs the round-robin to its bound), V1b's S1 reads 35 s and each first
// impersonation 75 s, first tried at 35 s: settle times from the mark, where
// running V1b and the impersonations after t1 gave 9m15s and 9m50s.
func TestWalkM3aT1PlanMeasuresFromTheMark(t *testing.T) {
	targets, follows := m3aT1Plan(true)
	wantT := []m3aPlanTarget{
		{"T1 reader", m3aV1, m3aReader, m3aShapeV1Reader, "T1 reader"},
		{"T1 writer", m3aV1, m3aWriter, m3aShapeV1Writer, "T1 writer"},
		{"V1b reader", m3aV1b, m3aReader, m3aShapeV1b, "V1b T1"},
	}
	if !slices.Equal(targets, wantT) {
		t.Fatalf("t1's targets %v, want %v", targets, wantT)
	}
	type fk struct {
		target int
		role   string
		gating bool
	}
	var got []fk
	for _, f := range follows {
		got = append(got, fk{f.target, f.role, f.gating})
	}
	if want := []fk{{0, m3aReader, false}, {1, m3aWriter, false}, {2, m3aReader, true}}; !slices.Equal(got, want) {
		t.Fatalf("t1's first impersonations %v, want %v", got, want)
	}
	rerun, rerunFollows := m3aT1Plan(false)
	if len(rerun) != 1 || rerun[0] != wantT[2] || len(rerunFollows) != 1 || rerunFollows[0].target != 0 || !rerunFollows[0].gating {
		t.Errorf("v1b's rerun plan %v %v, want V1b alone with its gating impersonation", rerun, rerunFollows)
	}

	fc := &m3aFakeClock{t: m3aT0}
	n := 4 * len(targets)
	accepted := make([]bool, len(targets))
	out := m3aRoundsReady(context.Background(), fc.clock(), m3aT0, n+len(follows), func(k int) bool {
		return k < n || accepted[follows[k-n].target]
	}, func(k int) bool {
		if k < n {
			if k%4 == 3 || fc.t.Sub(m3aT0) < 30*time.Second {
				return false
			}
			accepted[k/4] = true
			return true
		}
		return fc.t.Sub(m3aT0) >= 45*time.Second
	})
	if fc.t.Sub(m3aT0) != 555*time.Second {
		t.Errorf("the round-robin ended at %v, want at its last try before the bound, 555 s", fc.t.Sub(m3aT0))
	}
	for k := range n {
		o := out[k]
		if k%4 == 3 {
			if o.ok || o.first != 0 {
				t.Errorf("%s S4: %+v, want tried from the mark and never accepted", targets[k/4].label, o)
			}
			continue
		}
		if !o.ok || o.delta != 35*time.Second || o.first != 0 || m3aTimingNote(o) != "" {
			t.Errorf("%s S%d: %+v (%q), want accepted after 35 s, first tried at once, no note", targets[k/4].label, k%4+1, o, m3aTimingNote(o))
		}
	}
	for j, f := range follows {
		o := out[n+j]
		if !o.ok || o.delta != 75*time.Second || o.first != 35*time.Second || o.tries != 2 {
			t.Errorf("%s: %+v, want accepted after 75 s, first tried at 35 s, in 2 tries", f.label, o)
		}
		if note := m3aTimingNote(o); note != "first tried 35 s after the mark" {
			t.Errorf("%s: note %q", f.label, note)
		}
	}
}

// TestWalkM3aHeldLine: a held token's "refused after N s" is printed only
// when it was seen accepted, by a conclusive poll or by its impersonation
// before the paste; refused at its first poll with neither, its line says
// that is no revocation timing.
func TestWalkM3aHeldLine(t *testing.T) {
	for _, tc := range []struct {
		name   string
		o      m3aWatchOutcome
		before bool
		want   string
	}{
		{"refused, impersonated before the paste", m3aWatchOutcome{refused: true, delta: 0, polls: 1}, true,
			"held: refused after 0 s (1 polls; it impersonated before the paste)"},
		{"refused after a conclusive acceptance", m3aWatchOutcome{refused: true, delta: 120 * time.Second, polls: 3, accepted: true}, false,
			"held: refused after 120 s (3 polls)"},
		{"refused at the first poll, never seen accepted", m3aWatchOutcome{refused: true, delta: 0, polls: 1}, false,
			"held: refused at 0 s with no acceptance seen, before the paste or after it: not a revocation timing (1 polls)"},
		{"accepted until it expired", m3aWatchOutcome{accepted: true, ended: true, polls: 55}, true,
			"held: accepted until it expired after 55 min (55 polls)"},
		{"no conclusive poll", m3aWatchOutcome{ended: true, polls: 55}, true,
			"held: no conclusive poll before it expired after 55 min (55 polls; each control refused, or no decision)"},
		{"the step's bound passed", m3aWatchOutcome{polls: 9, accepted: true}, true,
			"held: not refused when the step's bound passed (9 polls; a conclusive poll saw it accepted: yes)"},
	} {
		if got := m3aHeldLine("held", tc.o, 55, tc.before); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// TestWalkM3aTimingNote: a positive's line says how far its delta is a settle
// time: past the bound it is not one, accepted at its first try it is an
// upper bound, and first tried late it says when; tried from the mark under
// the settle rule it says nothing more.
func TestWalkM3aTimingNote(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    m3aOutcome
		want string
	}{
		{"never tried", m3aOutcome{}, ""},
		{"from the mark, under the rule", m3aOutcome{ok: true, delta: 35 * time.Second, first: time.Second, tries: 4}, ""},
		{"refused from the mark", m3aOutcome{first: 2 * time.Second, tries: 13}, ""},
		{"accepted at its first try", m3aOutcome{ok: true, delta: 3 * time.Second, first: 3 * time.Second, tries: 1},
			"accepted at its first try, 3 s after the mark: the settle time is at most that"},
		{"accepted at its first try, late", m3aOutcome{ok: true, delta: 250 * time.Second, first: 250 * time.Second, tries: 1},
			"accepted at its first try, 250 s after the mark: the settle time is at most that"},
		{"first tried late", m3aOutcome{ok: true, delta: 300 * time.Second, first: 240 * time.Second, tries: 3},
			"first tried 240 s after the mark"},
		{"accepted past the bound", m3aOutcome{ok: true, delta: 590 * time.Second, first: 590 * time.Second, tries: 1},
			"accepted at its first try, 590 s after the mark: the settle time is at most that"},
		{"first tried at the bound", m3aOutcome{ok: true, delta: m3aSettleBound, first: m3aSettleBound, tries: 1},
			"first tried 600 s after the mark, past the bound: not a settle time"},
		{"refused past the bound", m3aOutcome{first: 11 * time.Minute, tries: 1},
			"first tried 660 s after the mark, past the bound: not a settle time"},
	} {
		if got := m3aTimingNote(tc.o); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestWalkM3aNamedMarks: with setup at t0 and console at t0 + 20 min, a step
// measures from its own mark, and prints its delta from the latest one too; a
// negative's second check waits for the latest mark's bound; an unknown name
// is refused; and a held step's wait ignores a mark from before its start.
func TestWalkM3aNamedMarks(t *testing.T) {
	marks := m3aMarks{}
	marks.add("setup", m3aT0)
	marks.add("console", m3aT0.Add(20*time.Minute))
	since, err := m3aStepSince(marks, "t1", "")
	if err != nil || !since.Equal(m3aT0) {
		t.Fatalf("t1 measures from %v (%v), want setup's mark", since, err)
	}
	if s, err := m3aStepSince(marks, "console", ""); err != nil || !s.Equal(m3aT0.Add(20*time.Minute)) {
		t.Errorf("console measures from %v (%v), want console's mark", s, err)
	}
	fc := &m3aFakeClock{t: m3aT0.Add(25 * time.Minute)}
	d, ok := m3aPositive(context.Background(), fc.clock(), since, func() bool { return true })
	if !ok || d != 25*time.Minute {
		t.Errorf("accepted at t0 + 25 min: %v from setup, want 25 min", d)
	}
	if got, want := m3aAfter(fc.t, since, marks), "after 1500 s (300 s after the latest mark)"; got != want {
		t.Errorf("the line reads %q, want %q", got, want)
	}
	if got := m3aAfter(fc.t, marks["console"][0], marks); got != "after 300 s" {
		t.Errorf("measured from the latest mark itself, the line reads %q", got)
	}
	latest, _ := marks.latest()
	fc = &m3aFakeClock{t: m3aT0.Add(21 * time.Minute)}
	var at []time.Time
	m3aNegative(context.Background(), fc.clock(), latest, func() m3aCheck { at = append(at, fc.t); return m3aCheck{control: true} })
	if len(at) != 2 || !at[1].Equal(m3aT0.Add(30*time.Minute)) {
		t.Errorf("the negative's second check at %v, want console's mark + 10 min", at)
	}
	for _, name := range []string{"setup", "teardown-v1", "wfed-viewer"} {
		if err := m3aCheckMarkName(name); err != nil {
			t.Errorf("mark %q refused: %v", name, err)
		}
	}
	for _, name := range []string{"", "Setup", "latest", "teardown", "setup "} {
		if err := m3aCheckMarkName(name); err == nil {
			t.Errorf("mark %q accepted", name)
		}
	}
	marks.add("revoke-binding", m3aT0.Add(30*time.Minute))
	if _, ok := marks.after("revoke-binding", m3aT0.Add(31*time.Minute)); ok {
		t.Error("a held step started after the mark took it as its own")
	}
	marks.add("revoke-binding", m3aT0.Add(40*time.Minute))
	if got, ok := marks.after("revoke-binding", m3aT0.Add(31*time.Minute)); !ok || !got.Equal(m3aT0.Add(40*time.Minute)) {
		t.Errorf("a held step's mark is %v, want the one after its start", got)
	}
	if _, err := m3aStepSince(marks, "renewal", "setup"); err == nil {
		t.Error("renewal took a mark that is not one of its two")
	}
	if _, err := m3aStepSince(marks, "i7-added", ""); err == nil {
		t.Error("i7-added measured from a mark that is not recorded")
	}
}

// TestWalkM3aNegativeVerdicts: an acceptance at either check FAILS; refused at
// both with both controls accepted holds; a refusal while a control is refused
// is INCONCLUSIVE, so a fake that refuses everything never reads as holds.
func TestWalkM3aNegativeVerdicts(t *testing.T) {
	for _, tc := range []struct {
		first, second m3aCheck
		want          string
	}{
		{m3aCheck{true, true}, m3aCheck{false, true}, m3aFails},
		{m3aCheck{false, true}, m3aCheck{true, true}, m3aFails},
		{m3aCheck{true, false}, m3aCheck{false, false}, m3aFails},
		{m3aCheck{false, true}, m3aCheck{false, true}, m3aHolds},
		{m3aCheck{false, false}, m3aCheck{false, true}, m3aInconclusive},
		{m3aCheck{false, true}, m3aCheck{false, false}, m3aInconclusive},
	} {
		if got := m3aVerdict(tc.first, tc.second); got != tc.want {
			t.Errorf("%+v then %+v: %s, want %s", tc.first, tc.second, got, tc.want)
		}
	}
	// A fake exchange that refuses every request, the negative and its control
	// alike.
	refuseAll := func() bool { return false }
	fc := &m3aFakeClock{t: m3aT0}
	first, second := m3aNegative(context.Background(), fc.clock(), m3aT0, func() m3aCheck {
		return m3aCheck{accepted: refuseAll(), control: refuseAll()}
	})
	if got := m3aVerdict(first, second); got != m3aInconclusive {
		t.Errorf("everything refused reads %s, want %s", got, m3aInconclusive)
	}

	// Only a decision is a refusal: a 400, 401 or 403, or a TLS alert that
	// ended the exchange's handshake. A negative answered 3xx, 429 or 5xx, or
	// not answered at all, beside an accepted control, tested nothing and reads
	// INCONCLUSIVE, never holds; any 200 is an acceptance.
	fe := func(step kube.Step, status int, handshake bool) error {
		return &kube.FederationError{Step: step, Status: status, Handshake: handshake}
	}
	// An alert, as kube gives it: Handshake true before any answer came,
	// false while an answer was read; its words in Alert.
	alertAt := func(step kube.Step, handshake bool, words string) error {
		return &kube.FederationError{Step: step, Handshake: handshake, Alert: words}
	}
	// Only a certificate's alert at the exchange is a decision.
	for _, words := range m3aCertificateAlerts {
		c := m3aCheckOf(alertAt(kube.StepExchange, true, words), nil)
		if got := m3aVerdict(c, c); got != m3aHolds {
			t.Errorf("a negative ended by %q beside an accepted control: %s, want %s", words, got, m3aHolds)
		}
	}
	if len(m3aCertificateAlerts) != 8 {
		t.Errorf("%d certificate alerts, want the eight the probe counts", len(m3aCertificateAlerts))
	}
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"400", fe(kube.StepExchange, http.StatusBadRequest, false), m3aHolds},
		{"401", fe(kube.StepImpersonate, http.StatusUnauthorized, false), m3aHolds},
		{"403", fe(kube.StepImpersonate, http.StatusForbidden, false), m3aHolds},
		{"an alert out of shape at the exchange's handshake", fe(kube.StepExchange, 0, true), m3aInconclusive},
		{"an alert at IAM Credentials (unreachable)", fe(kube.StepImpersonate, 0, true), m3aInconclusive},
		{"a certificate alert at IAM Credentials", alertAt(kube.StepImpersonate, true, "tls: certificate required"), m3aInconclusive},
		{"internal_error at the exchange's handshake", alertAt(kube.StepExchange, true, "tls: internal error"), m3aInconclusive},
		{"handshake_failure at the exchange's handshake", alertAt(kube.StepExchange, true, "tls: handshake failure"), m3aInconclusive},
		{"decrypt_error at the exchange's handshake", alertAt(kube.StepExchange, true, "tls: error decrypting message"), m3aInconclusive},
		{"decode_error at the exchange's handshake", alertAt(kube.StepExchange, true, "tls: error decoding message"), m3aInconclusive},
		{"protocol_version at the exchange's handshake", alertAt(kube.StepExchange, true, "tls: protocol version not supported"), m3aInconclusive},
		{"certificate_required while the answer was read", alertAt(kube.StepExchange, false, "tls: certificate required"), m3aInconclusive},
		{"300", fe(kube.StepExchange, http.StatusMultipleChoices, false), m3aInconclusive},
		{"307", fe(kube.StepExchange, http.StatusTemporaryRedirect, false), m3aInconclusive},
		{"404", fe(kube.StepExchange, http.StatusNotFound, false), m3aInconclusive},
		{"429", fe(kube.StepExchange, http.StatusTooManyRequests, false), m3aInconclusive},
		{"500", fe(kube.StepExchange, http.StatusInternalServerError, false), m3aInconclusive},
		{"502", fe(kube.StepImpersonate, http.StatusBadGateway, false), m3aInconclusive},
		{"503", fe(kube.StepExchange, http.StatusServiceUnavailable, false), m3aInconclusive},
		{"not answered", fe(kube.StepExchange, 0, false), m3aInconclusive},
		{"not a federation error", errors.New("EOF"), m3aInconclusive},
		{"a 200 without a usable token", fe(kube.StepExchange, http.StatusOK, false), m3aFails},
		{"no error", nil, m3aFails},
	} {
		c := m3aCheckOf(tc.err, nil)
		if got := m3aVerdict(c, c); got != tc.want {
			t.Errorf("a negative answered %s beside an accepted control: %s, want %s", tc.name, got, tc.want)
		}
		// The same answer as the control's makes any negative INCONCLUSIVE
		// unless the control was accepted.
		if acc, _ := m3aAnswered(tc.err); !acc {
			if got := m3aVerdict(m3aCheckOf(fe(kube.StepExchange, 400, false), tc.err), m3aCheck{false, true}); got != m3aInconclusive {
				t.Errorf("a control answered %s: %s, want %s", tc.name, got, m3aInconclusive)
			}
		}
	}
	// N10's control is two calls, the reader's token at the reader SA and the
	// writer's at the writer SA: accepted only when both are, each made every
	// time. So a reader token IAM Credentials does not authenticate (401) is
	// no control, and N10's 403 beside it reads INCONCLUSIVE, never holds.
	n10 := fe(kube.StepImpersonate, http.StatusForbidden, false)
	answer := func(err error, calls *int) func() error {
		return func() error { *calls++; return err }
	}
	for _, tc := range []struct {
		name string
		a, b error
		want string
	}{
		{"both accepted", nil, nil, m3aHolds},
		{"both answered 200 without a usable token", fe(kube.StepImpersonate, http.StatusOK, false), fe(kube.StepImpersonate, http.StatusOK, false), m3aHolds},
		{"the reader's token refused at its own SA (401)", fe(kube.StepImpersonate, http.StatusUnauthorized, false), nil, m3aInconclusive},
		{"the reader's token refused at its own SA (403)", fe(kube.StepImpersonate, http.StatusForbidden, false), nil, m3aInconclusive},
		{"the reader's own SA answered 503", fe(kube.StepImpersonate, http.StatusServiceUnavailable, false), nil, m3aInconclusive},
		{"the writer's token refused at the writer SA", nil, fe(kube.StepImpersonate, http.StatusForbidden, false), m3aInconclusive},
		{"neither answered", fe(kube.StepImpersonate, 0, false), fe(kube.StepImpersonate, 0, false), m3aInconclusive},
	} {
		var ca, cb int
		ctrl := m3aBothAccepted(answer(tc.a, &ca), answer(tc.b, &cb))
		c := m3aCheckOf(n10, ctrl())
		if got := m3aVerdict(c, c); got != tc.want {
			t.Errorf("N10 refused 403 beside a control where %s: %s, want %s", tc.name, got, tc.want)
		}
		if ca != 1 || (m3aWasAccepted(tc.a) && cb != 1) {
			t.Errorf("N10's control, %s: called %d and %d times; each call it needs is made once", tc.name, ca, cb)
		}
	}

	// STS's plain endpoint (I6 and its V5 control) reads its status the same
	// way: any 200 is an acceptance, and only 400, 401 or 403 a refusal.
	for _, tc := range []struct {
		code      int
		sent      bool
		acc, refd bool
	}{
		{200, true, true, false}, {400, true, false, true}, {401, true, false, true}, {403, true, false, true},
		{302, true, false, false}, {404, true, false, false}, {429, true, false, false}, {500, true, false, false},
		{503, true, false, false}, {0, false, false, false}, {400, false, false, false},
	} {
		if acc, refd := m3aPlainAnswered(tc.code, tc.sent); acc != tc.acc || refd != tc.refd {
			t.Errorf("the plain endpoint's %d (answered %v): accepted %v, refused %v; want %v, %v", tc.code, tc.sent, acc, refd, tc.acc, tc.refd)
		}
	}
	// I6's checks: refused at both beside an accepted V5 control holds; any 200
	// at either fails; a control refused or not answered, or an answer that is
	// no decision, is INCONCLUSIVE.
	plain := func(code int, sent bool, ctrlCode int, ctrlSent bool) m3aCheck {
		acc, refd := m3aPlainAnswered(code, sent)
		cacc, _ := m3aPlainAnswered(ctrlCode, ctrlSent)
		return m3aCheckFrom(acc, refd, cacc)
	}
	for _, tc := range []struct {
		name          string
		first, second m3aCheck
		want          string
	}{
		{"400 twice, the control accepted", plain(400, true, 200, true), plain(400, true, 200, true), m3aHolds},
		{"200 at the second check", plain(400, true, 200, true), plain(200, true, 200, true), m3aFails},
		{"a 200 even with the control refused", plain(200, true, 400, true), plain(400, true, 400, true), m3aFails},
		{"400 with the control refused", plain(400, true, 400, true), plain(400, true, 200, true), m3aInconclusive},
		{"400 with the control not answered", plain(400, true, 0, false), plain(400, true, 200, true), m3aInconclusive},
		{"not answered (a firewall)", plain(0, false, 200, true), plain(0, false, 200, true), m3aInconclusive},
		{"503 beside an accepted control", plain(503, true, 200, true), plain(400, true, 200, true), m3aInconclusive},
	} {
		if got := m3aVerdict(tc.first, tc.second); got != tc.want {
			t.Errorf("I6, %s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestWalkM3aWatchPollsEachFromTheMark: P7's gating new exchanges and its
// held tokens are all polled from the mark, in one loop, each on its own
// schedule. A held token is first polled at the mark, not after a gating poll
// has run to its bound; two held tokens whose expiries are a second apart are
// both polled to their ends; a held token refused at 30 s reads 60 s (its
// second poll), not the end of a gating poll; and only a conclusive poll's
// acceptance reads as "accepted until it expired".
func TestWalkM3aWatchPollsEachFromTheMark(t *testing.T) {
	fc := &m3aFakeClock{t: m3aT0}
	at := func() time.Duration { return fc.t.Sub(m3aT0) }
	polled := make([][]time.Duration, 6)
	poll := func(i int, check func(time.Duration) m3aCheck) func() m3aCheck {
		return func() m3aCheck {
			polled[i] = append(polled[i], at())
			return check(at())
		}
	}
	out := m3aWatch(context.Background(), fc.clock(), m3aT0, []m3aWatched{
		// 0: a gating reader exchange never refused (the bound ends it).
		{poll: poll(0, func(time.Duration) m3aCheck { return m3aCheck{accepted: true, control: true} })},
		// 1: a gating writer exchange refused from 40 s.
		{poll: poll(1, func(d time.Duration) m3aCheck { return m3aCheck{accepted: d < 40*time.Second, control: true} })},
		// 2 and 3: the reader's and the writer's held tokens, accepted to
		// their ends, which are less than a second apart.
		{expiry: m3aT0.Add(52*time.Minute + 500*time.Millisecond), poll: poll(2, func(time.Duration) m3aCheck { return m3aCheck{accepted: true, control: true} })},
		{expiry: m3aT0.Add(52*time.Minute + 200*time.Millisecond), poll: poll(3, func(time.Duration) m3aCheck { return m3aCheck{accepted: true, control: true} })},
		// 4: a held token refused from 30 s.
		{expiry: m3aT0.Add(time.Hour), poll: poll(4, func(d time.Duration) m3aCheck { return m3aCheck{accepted: d < 30*time.Second, control: true} })},
		// 5: a held token whose every control was refused.
		{expiry: m3aT0.Add(5 * time.Minute), poll: poll(5, func(time.Duration) m3aCheck { return m3aCheck{accepted: false, control: false} })},
	})
	for i, p := range polled {
		if len(p) == 0 || p[0] != 0 {
			t.Errorf("thing %d was first polled at %v, want at the mark", i, p)
		}
	}
	if o := out[0]; o.refused || !o.ended || !o.accepted || polled[0][len(polled[0])-1] >= m3aSettleBound {
		t.Errorf("the gating poll never refused: %+v, last poll %v; want ended at the bound, still accepted", o, polled[0][len(polled[0])-1])
	}
	if o := out[1]; !o.refused || o.delta != 75*time.Second {
		t.Errorf("the gating poll refused from 40 s: %+v, want refused at its try at 75 s", o)
	}
	for _, i := range []int{2, 3} {
		o := out[i]
		if o.refused || !o.ended || !o.accepted || o.polls != 53 {
			t.Errorf("held token %d: %+v, want 53 polls (0 to 52 min), accepted until it expired", i, o)
		}
	}
	if o := out[4]; !o.refused || o.delta != time.Minute || o.polls != 2 {
		t.Errorf("the held token refused from 30 s: %+v, want refused at its poll at 60 s", o)
	}
	if o := out[5]; o.refused || !o.ended || o.accepted || o.polls != 5 {
		t.Errorf("the held token with every control refused: %+v, want 5 polls and no conclusive acceptance", o)
	}
	// Each held token's polls are 60 s apart, whatever the gating polls do.
	for i := 1; i < len(polled[3]); i++ {
		if d := polled[3][i] - polled[3][i-1]; d != m3aExpiryPoll {
			t.Fatalf("held token polls %v apart, want %v", d, m3aExpiryPoll)
		}
	}
	// A context that ends stops every poll, and nothing reads as ended.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fc = &m3aFakeClock{t: m3aT0}
	clk := fc.clock()
	clk.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	out = m3aWatch(ctx, clk, m3aT0, []m3aWatched{{expiry: m3aT0.Add(time.Hour), poll: func() m3aCheck { return m3aCheck{true, true} }}})
	if o := out[0]; o.ended || o.refused || o.polls != 1 {
		t.Errorf("with the context ended: %+v, want one poll and not ended", o)
	}
}

// TestWalkM3aUntilRefusedNeedsTheControl: a refusal counts only while its
// control is accepted; at the bound the answer is "still accepted" or
// "inconclusive"; and P7's information timing stops at the token's expiry.
func TestWalkM3aUntilRefusedNeedsTheControl(t *testing.T) {
	polls := []m3aCheck{{false, false}, {false, false}, {false, true}}
	fc := &m3aFakeClock{t: m3aT0}
	i := 0
	d, o := m3aUntilRefused(context.Background(), fc.clock(), m3aT0, func() m3aCheck { p := polls[min(i, 2)]; i++; return p })
	if !o.ok || d != 15*time.Second || i != 3 {
		t.Errorf("refused at the third poll, its control accepted: %v %+v after %d polls; want 15 s", d, o, i)
	}
	fc = &m3aFakeClock{t: m3aT0}
	if d, o := m3aUntilRefused(context.Background(), fc.clock(), m3aT0, func() m3aCheck { return m3aCheck{false, true} }); !o.ok || d != 0 {
		t.Errorf("refused at once: %v %+v", d, o)
	}
	fc = &m3aFakeClock{t: m3aT0}
	if _, o := m3aUntilRefused(context.Background(), fc.clock(), m3aT0, func() m3aCheck { return m3aCheck{true, true} }); o.ok || o.last != m3aStillAccepted {
		t.Errorf("always accepted: %+v, want %q", o, m3aStillAccepted)
	}
	fc = &m3aFakeClock{t: m3aT0}
	if _, o := m3aUntilRefused(context.Background(), fc.clock(), m3aT0, func() m3aCheck { return m3aCheck{false, false} }); o.ok || o.last != m3aInconclusivePoll {
		t.Errorf("every control refused: %+v, want %q", o, m3aInconclusivePoll)
	}

	fc = &m3aFakeClock{t: m3aT0}
	n := 0
	if _, ok := m3aUntilExpired(context.Background(), fc.clock(), m3aT0, m3aT0.Add(5*time.Minute), func() m3aCheck { n++; return m3aCheck{true, true} }); ok || n != 5 {
		t.Errorf("never refused: %d polls (refused %v), want 5 and the expiry", n, ok)
	}
	fc = &m3aFakeClock{t: m3aT0}
	n = 0
	d, ok := m3aUntilExpired(context.Background(), fc.clock(), m3aT0, m3aT0.Add(time.Hour), func() m3aCheck {
		n++
		return m3aCheck{accepted: n < 3, control: n != 2}
	})
	if !ok || d != 2*time.Minute {
		t.Errorf("refused at the third poll: %v %v, want 2 min", d, ok)
	}
	fc = &m3aFakeClock{t: m3aT0}
	n = 0
	if _, ok := m3aUntilExpired(context.Background(), fc.clock(), m3aT0, m3aT0.Add(3*time.Minute), func() m3aCheck { n++; return m3aCheck{false, false} }); ok || n != 3 {
		t.Errorf("refused only while its control was refused: %d polls, taken %v", n, ok)
	}
}

// TestWalkM3aShapesAndTheSimplest: the four shapes' parts, an intermediate's
// place, the simplest shape, and the shape input's spelling.
func TestWalkM3aShapesAndTheSimplest(t *testing.T) {
	L, M, A := []byte("leaf"), []byte("mid"), []byte("anchor")
	str := func(c [][]byte) string { return string(bytes.Join(c, []byte(","))) }
	for _, tc := range []struct {
		s            m3aShape
		tls, subject string
	}{
		{m3aS1, "leaf", "leaf"},
		{m3aS2, "leaf", "leaf,anchor"},
		{m3aS3, "leaf,anchor", "leaf"},
		{m3aS4, "leaf,anchor", "leaf,anchor"},
	} {
		tl, sub := tc.s.chains(L, nil, A)
		if str(tl) != tc.tls || str(sub) != tc.subject {
			t.Errorf("%s: TLS %s, subject %s; want %s and %s", tc.s, str(tl), str(sub), tc.tls, tc.subject)
		}
		tl, sub = tc.s.chains(L, [][]byte{M}, A)
		if !strings.HasPrefix(str(tl), "leaf,mid") || !strings.HasPrefix(str(sub), "leaf,mid") {
			t.Errorf("%s with an intermediate: TLS %s, subject %s; want it after the leaf, before the anchor", tc.s, str(tl), str(sub))
		}
		if tl, _ := tc.s.chains(L, nil, nil); str(tl) != "leaf" {
			t.Errorf("%s with no anchor: TLS %s", tc.s, str(tl))
		}
	}
	if tl, _ := m3aS4.chains(L, [][]byte{M}, A); str(tl) != "leaf,mid,anchor" {
		t.Errorf("S4 with an intermediate: %s", str(tl))
	}
	for passed, want := range map[[4]bool]m3aShape{{true, true, true, true}: m3aS1, {false, true, true, false}: m3aS2, {false, false, false, true}: m3aS4} {
		if got, ok := m3aSimplest(passed); !ok || got != want {
			t.Errorf("simplest of %v = %s, want %s", passed, got, want)
		}
	}
	if _, ok := m3aSimplest([4]bool{}); ok {
		t.Error("a shape was the simplest of none passing")
	}
	for _, s := range []string{"S1", "S2", "S3", "S4"} {
		if got, err := parseM3aShape(s); err != nil || got.String() != s {
			t.Errorf("parseM3aShape(%q) = %s, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "S0", "S5", "s1", " S1", "S1 ", "1", "S", "S12"} {
		if _, err := parseM3aShape(s); err == nil {
			t.Errorf("parseM3aShape(%q) accepted", s)
		}
	}
}

// TestWalkM3aStepsUseTheRecordedShape: every step whose Shape column says
// "T1's" sends the simplest shape recorded for its target provider's role;
// with none recorded, the negatives refuse to start, and variants falls back
// to S1–S4.
func TestWalkM3aStepsUseTheRecordedShape(t *testing.T) {
	st := &m3aState{Shapes: map[string][4]bool{
		m3aShapeV1Reader: {false, true, true, false},
		m3aShapeV1Writer: {false, false, true, true},
		m3aShapeV1b:      {true, false, false, false},
	}}
	for _, step := range m3aT1Steps {
		for key, want := range map[string]m3aShape{m3aShapeV1Reader: m3aS2, m3aShapeV1Writer: m3aS3, m3aShapeV1b: m3aS1} {
			got, err := m3aStepShapes(st, step, key)
			if err != nil || len(got) != 1 || got[0] != want {
				t.Errorf("%s at %s: %v (%v), want [%s]", step, key, got, err, want)
			}
		}
	}
	if got, err := m3aStepShapes(st, "variants", m3aShapeV1Reader); err != nil || !slices.Equal(got, []m3aShape{m3aS2}) {
		t.Errorf("variants: %v (%v), want T1's reader shape", got, err)
	}
	for _, step := range m3aRoundRobinSteps {
		if got, err := m3aStepShapes(st, step, m3aShapeV1Reader); err != nil || len(got) != 4 {
			t.Errorf("%s sends %v (%v), want S1 to S4", step, got, err)
		}
	}
	empty := &m3aState{}
	if got, err := m3aStepShapes(empty, "negatives", m3aShapeV1Reader); err == nil {
		t.Errorf("the negatives ran with no recorded shape, in %v", got)
	}
	if got, err := m3aStepShapes(empty, "variants", m3aShapeV1Reader); err != nil || len(got) != 4 {
		t.Errorf("variants with no recorded shape: %v (%v), want S1 to S4", got, err)
	}
	for _, step := range m3aT1Steps {
		if _, err := m3aStepShapes(empty, step, m3aShapeV1Reader); err == nil {
			t.Errorf("%s ran with no recorded shape", step)
		}
	}
	noV1b := &m3aState{Shapes: map[string][4]bool{m3aShapeV1Reader: {true}, m3aShapeV1Writer: {true}}}
	if _, err := m3aStepShapes(noV1b, "negatives", m3aShapeV1Reader); err == nil {
		t.Error("the negatives ran before v1b recorded its shape")
	}
	refused := &m3aState{Shapes: map[string][4]bool{m3aShapeV1Reader: {}, m3aShapeV1Writer: {true}, m3aShapeV1b: {true}}}
	if _, err := m3aStepShapes(refused, "negatives", m3aShapeV1Reader); err == nil {
		t.Error("the negatives ran with every reader shape refused")
	}
}

// TestWalkM3aCoordinatesLine: the line with no newline or one is read; a CR,
// two newlines, an extra field, another tag, another project and a bad number
// are refused; and no refusal quotes the line.
func TestWalkM3aCoordinatesLine(t *testing.T) {
	const project, number = "probe-project-1", "123456789012"
	for _, ok := range []string{"m3a1 " + project + " " + number, "m3a1 " + project + " " + number + "\n"} {
		if got, err := m3aParseCoordinates([]byte(ok), project); err != nil || got != number {
			t.Errorf("%q: %q, %v", ok, got, err)
		}
	}
	for _, bad := range []string{
		"m3a1 " + project + " " + number + "\r\n",
		"m3a1 " + project + " " + number + "\n\n",
		"m3a1 " + project + " " + number + " extra",
		"m3a2 " + project + " " + number,
		"m3a1 other-project-1 " + number,
		"m3a1 " + project + " 1234x6789012",
		"m3a1 " + project + " ",
		"m3a1 " + project + " 123456789012345678901",
		"m3a1  " + project + " " + number,
		" m3a1 " + project + " " + number,
		"m3a1\t" + project + " " + number,
		"",
	} {
		_, err := m3aParseCoordinates([]byte(bad), project)
		if err == nil {
			t.Errorf("%q was accepted", bad)
			continue
		}
		if strings.Contains(err.Error(), number[:6]) || strings.Contains(err.Error(), project) || strings.Contains(err.Error(), "m3a1") {
			t.Errorf("the refusal of %q quotes it: %v", bad, err)
		}
	}
}

// m3aTestHex is n random bytes in lowercase hex.
func m3aTestHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// m3aTestID is an object ID's shape: a letter, then [a-z0-9], n in all.
func m3aTestID(t *testing.T, n int) string {
	t.Helper()
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	for i := range b {
		if i == 0 {
			b[i] = alpha[int(b[i])%26]
		} else {
			b[i] = alpha[int(b[i])%36]
		}
	}
	return string(b)
}

// m3aTestCA is a self-signed P-256 CA certificate with that CN, made with
// crypto/x509 alone: the blocks need only its DER.
func m3aTestCA(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := m3aNewKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: m3aT0.Add(-time.Hour), NotAfter: m3aT0.Add(390 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// m3aTestLeaf is a leaf under a fresh CA: what the state's leaf list holds.
func m3aTestLeaf(t *testing.T) []byte {
	t.Helper()
	key, err := m3aNewKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := new(big.Int).SetString(m3aTestHex(t, 16), 16)
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: m3aTestHex(t, 16)},
		NotBefore: m3aT0.Add(-time.Hour), NotAfter: m3aT0.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// m3aTestState is a whole probe state with every field set, as init,
// coordinates, t1, v1b, t3 and the marks would leave it.
func m3aTestState(t *testing.T) *m3aState {
	t.Helper()
	st := &m3aState{
		Version: m3aStateVersion, Project: "probe-project-1", ProjectNumber: "123456789012",
		Pool: m3aTestID(t, 32), ReaderSA: m3aTestID(t, 30), WriterSA: m3aTestID(t, 30), APIRecord: m3aTestID(t, 32),
		Variants: map[string]*m3aVariant{},
		Shapes: map[string][4]bool{m3aShapeV1Reader: {true, true, false, false}, m3aShapeV1Writer: {false, true, false, false},
			m3aShapeV1b: {true}, m3aShapeV1cReader: {false, false, true}, m3aShapeV1cWriter: {}},
		Marks: m3aMarks{},
	}
	device := func(name string, roles ...string) {
		v := &m3aVariant{Providers: map[string]string{}, RoleIDs: map[string]string{}, Anchors: map[string][]byte{}}
		for _, r := range roles {
			v.Providers[r] = m3aTestID(t, 32)
			v.RoleIDs[r] = m3aTestHex(t, 16)
			v.Anchors[r] = m3aTestCA(t, v.RoleIDs[r])
		}
		st.Variants[name] = v
	}
	device(m3aV1, m3aReader, m3aWriter)
	device(m3aV1c, m3aReader, m3aWriter)
	for _, v := range []string{m3aV1b, m3aV1x, m3aV1y, m3aV2, m3aV3, m3aV4, m3aV6, m3aV7, m3aV8} {
		device(v, m3aReader)
	}
	st.Variants[m3aV8].Subject = m3aTestHex(t, 16)
	key, err := m3aNewKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	st.Variants[m3aV5] = &m3aVariant{Providers: map[string]string{m3aReader: m3aTestID(t, 32)}, Subject: m3aTestHex(t, 16),
		Issuer: "https://" + m3aTestID(t, 32) + ".invalid", KID: m3aTestID(t, 32), PublicKey: point}
	st.I7Anchor = m3aTestCA(t, st.roleID(m3aV1, m3aReader))
	st.CAs = [][]byte{m3aTestCA(t, st.roleID(m3aV1, m3aReader)), m3aTestCA(t, st.roleID(m3aV1b, m3aReader))}
	st.OldReaderLeaf = m3aTestLeaf(t)
	st.Leaves = [][]byte{m3aTestLeaf(t), m3aTestLeaf(t), st.OldReaderLeaf}
	st.Marks.add("setup", m3aT0)
	st.Marks.add("console", m3aT0.Add(20*time.Minute))
	st.Marks.add("console", m3aT0.Add(21*time.Minute+123456789*time.Nanosecond))
	return st
}

// m3aTestWFEDState is W-FED's state: one writer-capable device.
func m3aTestWFEDState(t *testing.T) *m3aState {
	t.Helper()
	st := &m3aState{Version: m3aStateVersion, WFED: true, Project: "walk-project-1", Pool: m3aTestID(t, 32),
		ReaderSA: m3aTestID(t, 30), WriterSA: m3aTestID(t, 30), APIRecord: m3aTestID(t, 32), Variants: map[string]*m3aVariant{}}
	v := &m3aVariant{Providers: map[string]string{}, RoleIDs: map[string]string{}, Anchors: map[string][]byte{}}
	for _, r := range []string{m3aReader, m3aWriter} {
		v.Providers[r] = m3aTestID(t, 32)
		v.RoleIDs[r] = m3aTestHex(t, 16)
		v.Anchors[r] = m3aTestCA(t, v.RoleIDs[r])
	}
	st.Variants[m3aWFED] = v
	return st
}

// TestWalkM3aStateRoundTrips: every field survives a save and a load, the
// marks by name included; the file is 0600; and a state with any group or
// other bit, or a link, even one to a good state, is refused before it is
// read.
func TestWalkM3aStateRoundTrips(t *testing.T) {
	dir := t.TempDir()
	st := m3aTestState(t)
	if err := m3aSaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, m3aStateFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the state's mode is %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	got, err := m3aLoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(st)
	b, _ := json.Marshal(got)
	if !bytes.Equal(a, b) || !reflect.DeepEqual(st, got) {
		t.Error("the state did not survive a save and a load")
	}
	if len(got.Marks["console"]) != 2 || !got.Marks["console"][1].Equal(st.Marks["console"][1]) {
		t.Error("the marks did not survive by name")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("the save left %d files, want the state alone", len(entries))
	}

	// A 0644 state holding garbage: the mode is refused, not the content,
	// so it was refused before it was read.
	if err := os.WriteFile(filepath.Join(dir, m3aStateFile), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, m3aStateFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m3aLoadState(dir); !errors.Is(err, errM3aStateMode) {
		t.Errorf("a 0644 state: %v, want the mode refused", err)
	}
	// Each group bit refuses it as well as an other bit does: the garbage is
	// never decoded, so the refusal is the mode's.
	for _, mode := range []os.FileMode{0o640, 0o620, 0o610, 0o660, 0o604, 0o602, 0o601} {
		if err := os.Chmod(filepath.Join(dir, m3aStateFile), mode); err != nil {
			t.Fatal(err)
		}
		if _, err := m3aLoadState(dir); !errors.Is(err, errM3aStateMode) {
			t.Errorf("a %#o state: %v, want the mode refused", mode, err)
		}
	}
	link := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, m3aStateFile), filepath.Join(link, m3aStateFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := m3aLoadState(link); !errors.Is(err, errM3aStateMode) {
		t.Errorf("a linked state: %v, want it refused", err)
	}
	// A link is refused for being a link, not for what it names: one to a good
	// 0600 state, which loads by its own path, is refused all the same.
	good, goodLink := t.TempDir(), t.TempDir()
	if err := m3aSaveState(good, st); err != nil {
		t.Fatal(err)
	}
	if _, err := m3aLoadState(good); err != nil {
		t.Fatalf("the good state does not load: %v", err)
	}
	if err := os.Symlink(filepath.Join(good, m3aStateFile), filepath.Join(goodLink, m3aStateFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := m3aLoadState(goodLink); !errors.Is(err, errM3aStateMode) {
		t.Errorf("a link to a 0600 state: %v, want it refused", err)
	}
}

// m3aDoc is one inner here-document of a block.
type m3aDoc struct {
	tag, body string
	line      int // the index in lines of the line that opened it
}

// m3aParsed is a block's script: its tag, its logical lines (continuations
// joined, inner here-document bodies left out), and its inner documents.
type m3aParsed struct {
	tag   string
	lines []string
	docs  []m3aDoc
}

var (
	m3aOuterDoc = regexp.MustCompile(`^sh -s <<'([A-Z_]+)'$`)
	m3aInnerDoc = regexp.MustCompile(`<<'([A-Z_]+)'`)
)

// m3aParse reads a block as the shell would: the outer here-document is the
// script, and each inner one ends at its own tag.
func m3aParse(t *testing.T, name, text string) m3aParsed {
	t.Helper()
	raw := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	m := m3aOuterDoc.FindStringSubmatch(raw[0])
	if m == nil || raw[len(raw)-1] != m[1] {
		t.Fatalf("%s: not one sh -s here-document", name)
	}
	p := m3aParsed{tag: m[1]}
	raw = raw[1 : len(raw)-1]
	for i := 0; i < len(raw); i++ {
		l := raw[i]
		for strings.HasSuffix(l, `\`) && i+1 < len(raw) {
			i++
			l = strings.TrimSuffix(l, `\`) + " " + strings.TrimLeft(raw[i], " ")
		}
		p.lines = append(p.lines, l)
		if m := m3aInnerDoc.FindStringSubmatch(l); m != nil {
			var body []string
			for i++; i < len(raw) && raw[i] != m[1]; i++ {
				body = append(body, raw[i])
			}
			if i == len(raw) {
				t.Fatalf("%s: the here-document %s does not end", name, m[1])
			}
			p.docs = append(p.docs, m3aDoc{tag: m[1], body: strings.Join(body, "\n") + "\n", line: len(p.lines) - 1})
		}
	}
	return p
}

// m3aSplitWords splits one shell line by POSIX rules, as far as the blocks
// need: unquoted text, single quotes, a backslash outside quotes, and double
// quotes with their four escapes ($, `, ", \), leaving $VAR and $(…) as they
// are.
func m3aSplitWords(line string) ([]string, error) {
	var words []string
	var cur strings.Builder
	in := false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; c {
		case ' ', '\t':
			if in {
				words = append(words, cur.String())
				cur.Reset()
				in = false
			}
		case '\'':
			j := strings.IndexByte(line[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("an unterminated single quote")
			}
			cur.WriteString(line[i+1 : i+1+j])
			i += j + 1
			in = true
		case '\\':
			if i+1 >= len(line) {
				return nil, errors.New("a trailing backslash")
			}
			i++
			cur.WriteByte(line[i])
			in = true
		case '"':
			for i++; i < len(line) && line[i] != '"'; i++ {
				if line[i] == '\\' && i+1 < len(line) && strings.IndexByte("$`\"\\", line[i+1]) >= 0 {
					i++
				}
				cur.WriteByte(line[i])
			}
			if i >= len(line) {
				return nil, errors.New("an unterminated double quote")
			}
			in = true
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	if in {
		words = append(words, cur.String())
	}
	return words, nil
}

// m3aGcloudLines are a parsed block's lines that run gcloud.
func m3aGcloudLines(p m3aParsed) []string {
	var out []string
	for _, l := range p.lines {
		if strings.Contains(l, "gcloud ") {
			out = append(out, l)
		}
	}
	return out
}

// m3aWordAfter is the word after the one equal to w, or "".
func m3aWordAfter(words []string, w string) string {
	for i := 0; i+1 < len(words); i++ {
		if words[i] == w {
			return words[i+1]
		}
	}
	return ""
}

// m3aFlag is the value of a --name=value word, or "".
func m3aFlag(words []string, name string) (string, bool) {
	for _, w := range words {
		if v, ok := strings.CutPrefix(w, name+"="); ok {
			return v, true
		}
	}
	return "", false
}

// m3aAllBlocks is every block the probe writes, from one state and W-FED's,
// with a staged anchor for P6's two.
func m3aAllBlocks(t *testing.T, st, wfed *m3aState, staged []byte) map[string][]byte {
	t.Helper()
	out, err := m3aStaticBlocks(st)
	if err != nil {
		t.Fatalf("the blocks: %v", err)
	}
	add := func(name string, b []byte, err error) {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = b
	}
	b, err := m3aContingentBlock(st)
	add("contingent.sh", b, err)
	b, err = m3aRenewPasteBlock(st, staged)
	add("renew-paste.sh", b, err)
	b, err = m3aConsoleRenewText(st, staged)
	add("console-renew.txt", b, err)
	b, err = m3aAuditBlock(st)
	add("audit.sh", b, err)
	w, err := m3aWFEDBlocks(wfed)
	if err != nil {
		t.Fatalf("W-FED's blocks: %v", err)
	}
	for k, v := range w {
		out[k] = v
	}
	return out
}

// TestWalkM3aBlocksNameNoProductOrInstance: no block but audit.sh, which
// looks for the user agent, says farcast in any case; no block uses a
// here-document tag but the neutral ones; and an inner here-document whose
// body holds its own tag on a line of its own, which would end it early and
// run the rest of the body as shell, is refused.
func TestWalkM3aBlocksNameNoProductOrInstance(t *testing.T) {
	st := m3aTestState(t)
	blocks := m3aAllBlocks(t, st, m3aTestWFEDState(t), m3aTestCA(t, st.roleID(m3aV1, m3aWriter)))
	if len(blocks) != len(m3aStaticBlockNames)+4+len(m3aWFEDBlockNames) {
		t.Errorf("%d blocks, want every one", len(blocks))
	}
	anyTag := regexp.MustCompile(`<<-?\s*'?"?([A-Za-z_]+)`)
	for name, b := range blocks {
		if name != "audit.sh" && strings.Contains(strings.ToLower(string(b)), "farcast") {
			t.Errorf("%s names the product", name)
		}
		for _, m := range anyTag.FindAllStringSubmatch(string(b), -1) {
			if !slices.Contains(m3aHereDocTags, m[1]) {
				t.Errorf("%s uses the here-document tag %q", name, m[1])
			}
		}
		if strings.HasSuffix(name, ".sh") {
			p := m3aParse(t, name, string(b))
			if !slices.Contains([]string{"END_OF_SETUP", "END_OF_STEP"}, p.tag) {
				t.Errorf("%s's tag is %s", name, p.tag)
			}
		}
	}
	for _, body := range []string{"END_OF_ANCHOR", "a\nEND_OF_ANCHOR\nb", "a\nEND_OF_ANCHOR", "a\nEND_OF_ANCHOR\n"} {
		s := &m3aScript{}
		s.hereDoc("TRUST", "END_OF_ANCHOR", []byte(body))
		if _, err := s.bytes(); err == nil {
			t.Errorf("an inner here-document whose body holds its tag on a line was accepted (%d bytes)", len(body))
		}
	}
	s := &m3aScript{}
	s.hereDoc("TRUST", "END_OF_ANCHOR", []byte("a END_OF_ANCHOR b\n END_OF_ANCHOR\nEND_OF_ANCHOR \n"))
	if _, err := s.bytes(); err != nil {
		t.Errorf("a body holding the tag only inside a line was refused: %v", err)
	}
}

// TestWalkM3aSetupBlockShape: setup.sh is an sh -s here-document, then set
// -eu; it asks y/N from /dev/tty before any gcloud; it creates one X509
// provider per variant from a trust store of its own, each condition naming
// one ID; V1's refusals stop it and the variants' do not; and its last line
// is the coordinates.
func TestWalkM3aSetupBlockShape(t *testing.T) {
	st := m3aTestState(t)
	b, err := m3aSetupBlock(st)
	if err != nil {
		t.Fatal(err)
	}
	p := m3aParse(t, "setup.sh", string(b))
	if p.tag != "END_OF_SETUP" || p.lines[0] != "set -eu" {
		t.Error("setup.sh must open with sh -s <<'END_OF_SETUP' and then set -eu")
	}
	ask, first := -1, -1
	for i, l := range p.lines {
		if l == "read -r ANSWER </dev/tty" && ask < 0 {
			ask = i
		}
		if strings.Contains(l, "gcloud ") && first < 0 {
			first = i
		}
	}
	if ask < 0 || first < 0 || ask > first {
		t.Errorf("the y/N (line %d) must come before the first gcloud (line %d)", ask, first)
	}
	hexID := regexp.MustCompile(`[0-9a-f]{32}`)
	created := map[string]bool{}
	usedDocs := map[int]bool{}
	v1 := []string{st.provider(m3aV1, m3aReader), st.provider(m3aV1, m3aWriter)}
	for i, l := range p.lines {
		if !strings.Contains(l, " create-x509 ") {
			continue
		}
		words, err := m3aSplitWords(l)
		if err != nil {
			t.Fatal(err)
		}
		id := m3aWordAfter(words, "create-x509")
		if created[id] {
			t.Errorf("provider %s is created twice", id)
		}
		created[id] = true
		doc := -1
		for j, d := range p.docs {
			if d.line < i && d.tag == "END_OF_ANCHOR" {
				doc = j
			}
		}
		// The here-document, then the check that skips a provider already
		// there, then the create, as its elif: setup.sh can be pasted again.
		if doc < 0 || usedDocs[doc] || p.docs[doc].line != i-3 {
			t.Errorf("provider %s does not have a trust store here-document of its own just before its exists check", id)
		}
		if !strings.HasPrefix(l, "elif retry gcloud ") {
			t.Errorf("provider %s is created other than as the elif of its exists check", id)
		}
		if dw, err := m3aSplitWords(p.lines[i-2]); err != nil || !strings.HasPrefix(p.lines[i-2], "if gcloud ") ||
			m3aWordAfter(dw, "describe") != id || !strings.Contains(p.lines[i-2], `! grep -qi -e deleted "$OUT"`) {
			t.Errorf("provider %s is not checked for, as present and not DELETED, before it is created", id)
		}
		if !strings.HasSuffix(p.lines[i-1], `: exists'`) {
			t.Errorf("provider %s does not say it exists when it does", id)
		}
		usedDocs[doc] = true
		cond, _ := m3aFlag(words, "--attribute-condition")
		if ids := slices.Compact(hexID.FindAllString(cond, -1)); len(ids) != 1 {
			t.Errorf("provider %s's condition names %d IDs, want 1", id, len(ids))
		}
		// The else branch, to its fi.
		stops := false
		for j := i + 1; j < len(p.lines) && p.lines[j] != "fi"; j++ {
			if strings.TrimSpace(p.lines[j]) == "exit 1" {
				stops = true
			}
		}
		if stops != slices.Contains(v1, id) {
			t.Errorf("provider %s: a refusal stops the block: %v; want it only for V1's two", id, stops)
		}
	}
	for _, vr := range [][2]string{{m3aV1, m3aReader}, {m3aV1, m3aWriter}, {m3aV1b, m3aReader}, {m3aV2, m3aReader}, {m3aV3, m3aReader},
		{m3aV4, m3aReader}, {m3aV6, m3aReader}, {m3aV7, m3aReader}, {m3aV8, m3aReader}} {
		if !created[st.provider(vr[0], vr[1])] {
			t.Errorf("setup.sh does not create %s's %s provider", vr[0], vr[1])
		}
	}
	if len(created) != 9 {
		t.Errorf("setup.sh creates %d X509 providers, want 9", len(created))
	}
	if n := strings.Count(string(b), " create-oidc "+m3aMustQuote(t, st.provider(m3aV5, m3aReader))+" "); n != 1 {
		t.Errorf("setup.sh creates V5's OIDC provider %d times, want 1", n)
	}
	for i, l := range p.lines {
		if strings.Contains(l, " create-oidc ") && (!strings.HasPrefix(l, "elif retry gcloud ") ||
			!strings.Contains(p.lines[i-2], " providers describe "+m3aMustQuote(t, st.provider(m3aV5, m3aReader))+" ")) {
			t.Error("V5's provider is not checked for before it is created")
		}
	}
	last := p.lines[len(p.lines)-1]
	if last != `echo "m3a1 $PROJECT $NUMBER"` {
		t.Errorf("setup.sh's last line is %q, want the coordinates", last)
	}
	m3aCheckSetupCompletes(t, "setup.sh", string(b), 11)
	wb, err := m3aWFEDBlocks(m3aTestWFEDState(t))
	if err != nil {
		t.Fatal(err)
	}
	m3aCheckSetupCompletes(t, "wfed-setup.sh", string(wb["wfed-setup.sh"]), 2)
	for _, l := range p.lines {
		if strings.HasPrefix(strings.TrimSpace(l), "echo ") && strings.Contains(l, "$NUMBER") && l != last {
			t.Error("setup.sh prints the number before its last line")
		}
	}
}

// m3aCheckSetupCompletes: a setup block prints its coordinates line, on which
// the runbook marks setup at once, only when every grant and binding printed
// added: each of the n grants and bindings after the service accounts' creation
// uses retry_slow, which waits 210 s in all, since a new SA may take 60 s or
// more to be usable, and each refusal sets INCOMPLETE=yes; the coordinates
// line comes after a check that exits 1 on it, and INCOMPLETE starts as no
// after the first SA's creation, before any grant or binding.
func m3aCheckSetupCompletes(t *testing.T, name, text string, n int) {
	t.Helper()
	p := m3aParse(t, name, text)
	start := slices.Index(p.lines, "INCOMPLETE=no")
	created := slices.IndexFunc(p.lines, func(l string) bool { return strings.Contains(l, "service-accounts create ") })
	if start < 0 || created < 0 || start < created {
		t.Fatalf("%s: INCOMPLETE=no is not set after the first service account's creation", name)
	}
	grants := 0
	for i, l := range p.lines {
		if !strings.Contains(l, "add-iam-policy-binding") {
			continue
		}
		grants++
		if i < start || !strings.HasPrefix(l, "if retry_slow gcloud ") {
			t.Errorf("%s: a grant or binding after the SAs' creation without retry_slow: %.80s", name, l)
		}
		var branch []string
		for j := i + 1; j < len(p.lines) && p.lines[j] != "fi"; j++ {
			branch = append(branch, strings.TrimSpace(p.lines[j]))
		}
		if e := slices.Index(branch, "else"); e < 0 || !slices.Contains(branch[e:], "INCOMPLETE=yes") {
			t.Errorf("%s: a grant's or binding's refusal does not mark the setup incomplete", name)
		}
	}
	if grants != n {
		t.Errorf("%s: %d grants and bindings, want %d", name, grants, n)
	}
	k := len(p.lines)
	want := []string{`if [ "$INCOMPLETE" = yes ]; then`, "", "  exit 1", "fi", `echo "m3a1 $PROJECT $NUMBER"`}
	if k < len(want) {
		t.Fatalf("%s is too short", name)
	}
	tail := p.lines[k-len(want):]
	for i, w := range want {
		if w != "" && tail[i] != w {
			t.Errorf("%s: line %d before the end is %q, want %q", name, len(want)-i, tail[i], w)
		}
	}
	if !strings.HasPrefix(tail[1], "  echo 'setup not complete") {
		t.Errorf("%s: an incomplete setup does not say so: %q", name, tail[1])
	}
	waits, tries := 0, 0
	for _, l := range strings.Split(m3aRetry, "\n") {
		if strings.Contains(l, "retry_slow() {") {
			tries = -1
		}
		if tries == -1 && strings.Contains(l, `if [ "$n" -ge `) {
			if _, err := fmt.Sscanf(strings.TrimSpace(l), `if [ "$n" -ge %d ]; then`, &tries); err != nil {
				t.Fatalf("retry_slow's bound does not read: %v", err)
			}
		}
		if tries > 0 && strings.Contains(l, "sleep $((n * ") {
			if _, err := fmt.Sscanf(strings.TrimSpace(l), "sleep $((n * %d))", &waits); err != nil {
				t.Fatalf("retry_slow's wait does not read: %v", err)
			}
			break
		}
	}
	if total := waits * tries * (tries - 1) / 2; total < 180 {
		t.Errorf("retry_slow waits %d s in all (%d tries, %d·n s), want 180 s or more", total, tries, waits)
	}
}

func m3aMustQuote(t *testing.T, s string) string {
	t.Helper()
	q, err := m3aQuote(s)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// TestWalkM3aConditionsSurviveTheShell: split by POSIX rules, every
// --attribute-condition and --attribute-mapping of every block is exactly the
// Go value for its provider; and m3aQuote refuses a byte outside its alphabet.
func TestWalkM3aConditionsSurviveTheShell(t *testing.T) {
	st, wfed := m3aTestState(t), m3aTestWFEDState(t)
	blocks := m3aAllBlocks(t, st, wfed, m3aTestCA(t, st.roleID(m3aV1, m3aWriter)))
	type want struct{ condition, mapping string }
	wants := map[string]want{}
	d3 := func(s *m3aState, v, r string) want {
		id, err := devicekey.ParseRoleID(s.roleID(v, r))
		if err != nil {
			t.Fatal(err)
		}
		return want{devicekey.AttributeCondition(id), devicekey.AttributeMapping}
	}
	for _, vr := range m3aProviderOrder {
		if vr[0] != m3aV5 && vr[0] != m3aV1c { // V1c's are created in the console, from console-v1c.txt
			wants[st.provider(vr[0], vr[1])] = d3(st, vr[0], vr[1])
		}
	}
	for _, r := range []string{m3aReader, m3aWriter} {
		w := d3(st, m3aV1c, r)
		if !strings.Contains(string(blocks["console-v1c.txt"]), "Attribute condition: "+w.condition+"\n") {
			t.Errorf("console-v1c.txt does not give V1c's %s condition exactly", r)
		}
	}
	v8 := wants[st.provider(m3aV8, m3aReader)]
	v8.mapping = "google.subject='" + st.variant(m3aV8).Subject + "'"
	wants[st.provider(m3aV8, m3aReader)] = v8
	y := st.roleID(m3aV1y, m3aReader)
	wants[st.provider(m3aV1y, m3aReader)] = want{"assertion.issuer.dn.cn == '" + y + "' && assertion.subject.dn.cn == '" + y + "-l'", devicekey.AttributeMapping}
	wants[st.provider(m3aV5, m3aReader)] = want{"assertion.sub == '" + st.variant(m3aV5).Subject + "'", "google.subject=assertion.sub"}
	for _, r := range []string{m3aReader, m3aWriter} {
		wants[wfed.provider(m3aWFED, r)] = d3(wfed, m3aWFED, r)
	}
	for w := range maps.Values(wants) {
		if w.condition == "" || !strings.Contains(w.condition, "'") {
			t.Fatal("devicekey gave no condition to compare with")
		}
	}
	seen := map[string]int{}
	for name, b := range blocks {
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		for _, l := range m3aGcloudLines(m3aParse(t, name, string(b))) {
			words, err := m3aSplitWords(l)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			cond, hasCond := m3aFlag(words, "--attribute-condition")
			mapping, hasMap := m3aFlag(words, "--attribute-mapping")
			if !hasCond && !hasMap {
				continue
			}
			id := m3aWordAfter(words, "create-x509")
			if id == "" {
				id = m3aWordAfter(words, "create-oidc")
			}
			w, ok := wants[id]
			if !ok {
				t.Errorf("%s: a condition or mapping for a provider the probe does not know", name)
				continue
			}
			if cond != w.condition || mapping != w.mapping {
				t.Errorf("%s: provider %s's condition or mapping does not survive the shell:\n got %q / %q\nwant %q / %q", name, id, cond, mapping, w.condition, w.mapping)
			}
			seen[id]++
		}
	}
	if len(seen) != len(wants) {
		t.Errorf("%d providers carry a condition in the blocks, want %d", len(seen), len(wants))
	}
	for _, s := range []string{"a'b", "''", "x == 'y' && z == 'w'", "google.subject='abc'", "a b"} {
		q, err := m3aQuote(s)
		if err != nil {
			t.Fatalf("m3aQuote(%q): %v", s, err)
		}
		if words, err := m3aSplitWords("x " + q + " y"); err != nil || len(words) != 3 || words[1] != s {
			t.Errorf("m3aQuote(%q) = %s, which splits to %q", s, q, words)
		}
	}
	for _, bad := range []string{"", "a$b", "a\"b", "a`b", `a\b`, "a\nb", "a;b", "a|b", "a(b", "é", "a\tb", "a,b", "a#b"} {
		if _, err := m3aQuote(bad); err == nil {
			t.Errorf("m3aQuote(%q) was accepted", bad)
		}
	}
}

// TestWalkM3aGcloudLinesReadNoStdin: every gcloud line reads /dev/null and
// is --quiet, so no prompt reads the rest of the here-document; every binding
// line carries --condition=None.
func TestWalkM3aGcloudLinesReadNoStdin(t *testing.T) {
	st := m3aTestState(t)
	blocks := m3aAllBlocks(t, st, m3aTestWFEDState(t), m3aTestCA(t, st.roleID(m3aV1, m3aWriter)))
	total := 0
	for name, b := range blocks {
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		lines := m3aGcloudLines(m3aParse(t, name, string(b)))
		if len(lines) == 0 {
			t.Errorf("%s runs no gcloud", name)
		}
		for _, l := range lines {
			total++
			if !strings.Contains(l, "</dev/null") || !strings.Contains(l, " --quiet") {
				t.Errorf("%s: a gcloud line without </dev/null or --quiet: %.120s", name, l)
			}
			if (strings.Contains(l, "add-iam-policy-binding") || strings.Contains(l, "remove-iam-policy-binding")) && !strings.Contains(l, " --condition=None") {
				t.Errorf("%s: a binding line without --condition=None", name)
			}
		}
	}
	if total < 100 {
		t.Errorf("%d gcloud lines in all; the blocks were not read", total)
	}
}

// TestWalkM3aEveryBlockAsksFirst: every block asks y/N for its project on
// /dev/tty and stops unless the answer is y, and that gate is the line after
// the read and comes before the block's first gcloud or mktemp. A block whose
// read stayed but whose gate went would change IAM without the operator's
// yes.
func TestWalkM3aEveryBlockAsksFirst(t *testing.T) {
	st := m3aTestState(t)
	blocks := m3aAllBlocks(t, st, m3aTestWFEDState(t), m3aTestCA(t, st.roleID(m3aV1, m3aWriter)))
	const read = "read -r ANSWER </dev/tty"
	const gate = `[ "$ANSWER" = y ] || { echo 'Nothing was changed.' >&2; exit 1; }`
	n := 0
	for name, b := range blocks {
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		n++
		p := m3aParse(t, name, string(b))
		r := slices.Index(p.lines, read)
		g := slices.Index(p.lines, gate)
		act := slices.IndexFunc(p.lines, func(l string) bool { return strings.Contains(l, "gcloud ") || strings.Contains(l, "mktemp") })
		switch {
		case r < 1 || g < 0:
			t.Errorf("%s does not ask y/N and stop unless the answer is y", name)
		case g != r+1:
			t.Errorf("%s: the gate is not the line after the read", name)
		case act < 0 || act < g:
			t.Errorf("%s acts before its y/N gate", name)
		case !strings.HasPrefix(p.lines[r-1], "printf '") || !strings.HasSuffix(p.lines[r-1], `(project %s) [y/N] ' "$PROJECT" >/dev/tty`):
			t.Errorf("%s does not ask its question, naming the project, on /dev/tty", name)
		}
	}
	if n != 17 {
		t.Errorf("%d blocks were read, want every one of the 17 scripts", n)
	}
}

// TestWalkM3aEveryPrincipalIsBoundOnce: across setup.sh, bind-v1c.sh and
// contingent.sh, each principal the run binds is bound exactly once, on the
// SA the list names; V5's principal names its sub and V8's its constant; no
// other principal is bound. W-FED's two are bound once each in its setup.
func TestWalkM3aEveryPrincipalIsBoundOnce(t *testing.T) {
	st, wfed := m3aTestState(t), m3aTestWFEDState(t)
	blocks := m3aAllBlocks(t, st, wfed, m3aTestCA(t, st.roleID(m3aV1, m3aWriter)))
	type bound struct{ sa, subject string }
	want := map[bound]bool{}
	for _, v := range []string{m3aV1, m3aV1b, m3aV1c, m3aV2, m3aV3, m3aV4, m3aV6, m3aV7, m3aV1x, m3aV1y} {
		for _, r := range []string{m3aReader, m3aWriter} {
			if id := st.roleID(v, r); id != "" && (v != m3aV1 || r != m3aWriter) {
				want[bound{"$READER_SA", id}] = true
			}
		}
	}
	want[bound{"$READER_SA", st.variant(m3aV5).Subject}] = true
	want[bound{"$READER_SA", st.variant(m3aV8).Subject}] = true
	want[bound{"$WRITER_SA", st.roleID(m3aV1, m3aWriter)}] = true
	if len(want) != 14 {
		t.Fatalf("the expected list has %d principals, want 14", len(want))
	}
	count := func(names []string, prefix string) map[bound]int {
		got := map[bound]int{}
		for _, name := range names {
			p := m3aParse(t, name, string(blocks[name]))
			for _, l := range p.lines {
				if !strings.Contains(l, "service-accounts add-iam-policy-binding") {
					continue
				}
				words, err := m3aSplitWords(l)
				if err != nil {
					t.Fatal(err)
				}
				member, _ := m3aFlag(words, "--member")
				subject, ok := strings.CutPrefix(member, prefix)
				if !ok {
					t.Errorf("%s: a member that is not a pool subject's principal: %q", name, member)
				}
				got[bound{m3aWordAfter(words, "add-iam-policy-binding"), subject}]++
			}
			if !slices.Contains(p.lines, `PRINCIPAL="`+m3aPrincipalPrefix+`"`) {
				t.Errorf("%s does not define PRINCIPAL", name)
			}
		}
		return got
	}
	got := count([]string{"setup.sh", "bind-v1c.sh", "contingent.sh"}, "$PRINCIPAL/")
	for b := range want {
		if got[b] != 1 {
			t.Errorf("%s is bound %d times on %s, want once", b.subject, got[b], b.sa)
		}
	}
	for b, n := range got {
		if !want[b] {
			t.Errorf("an unlisted principal is bound %d times on %s", n, b.sa)
		}
	}
	if got[bound{"$READER_SA", st.roleID(m3aV8, m3aReader)}] != 0 {
		t.Error("V8 is bound by its role ID, not its constant")
	}
	wg := count([]string{"wfed-setup.sh"}, "$PRINCIPAL/")
	if len(wg) != 2 || wg[bound{"$READER_SA", wfed.roleID(m3aWFED, m3aReader)}] != 1 || wg[bound{"$WRITER_SA", wfed.roleID(m3aWFED, m3aWriter)}] != 1 {
		t.Errorf("W-FED binds %v, want its reader ID on the reader SA and its writer ID on the writer SA", wg)
	}
	// The principal the shell builds is devicekey's.
	id, err := devicekey.ParseRoleID(st.roleID(m3aV1, m3aReader))
	if err != nil {
		t.Fatal(err)
	}
	p, err := devicekey.Principal(st.ProjectNumber, st.Pool, id)
	if err != nil {
		t.Fatal(err)
	}
	built := strings.NewReplacer("$NUMBER", st.ProjectNumber, "$POOL", st.Pool).Replace(m3aPrincipalPrefix) + "/" + id.Hex()
	if built != p {
		t.Errorf("the blocks build the principal %q, devicekey %q", built, p)
	}
}

// TestWalkM3aTrustStoresInBlocksParse: every trust store in every block is
// the YAML Google reads, with one anchor (two only in i7-add.sh), no
// intermediateCas, and each pemCertificate decoding to its anchor's DER.
func TestWalkM3aTrustStoresInBlocksParse(t *testing.T) {
	st, wfed := m3aTestState(t), m3aTestWFEDState(t)
	staged := m3aTestCA(t, st.roleID(m3aV1, m3aWriter))
	blocks := m3aAllBlocks(t, st, wfed, staged)
	anchors := map[string][][]byte{}
	for _, vr := range m3aProviderOrder {
		anchors[st.provider(vr[0], vr[1])] = [][]byte{st.anchor(vr[0], vr[1])}
	}
	for _, r := range []string{m3aReader, m3aWriter} {
		anchors[wfed.provider(m3aWFED, r)] = [][]byte{wfed.anchor(m3aWFED, r)}
	}
	special := map[string][][]byte{
		"i7-add.sh":      {st.anchor(m3aV1, m3aReader), st.I7Anchor},
		"renew-paste.sh": {staged},
	}
	stores := 0
	for name, b := range blocks {
		if !strings.HasSuffix(name, ".sh") {
			continue
		}
		p := m3aParse(t, name, string(b))
		for _, d := range p.docs {
			if d.tag != "END_OF_ANCHOR" {
				continue
			}
			stores++
			var id string
			for _, l := range p.lines[d.line+1:] {
				if strings.Contains(l, "--trust-store-config-path") {
					words, _ := m3aSplitWords(l)
					if id = m3aWordAfter(words, "create-x509"); id == "" {
						id = m3aWordAfter(words, "update-x509")
					}
					break
				}
			}
			want, ok := special[name]
			if !ok {
				want = anchors[id]
			}
			var doc map[string]map[string]any
			if err := yaml.Unmarshal([]byte(d.body), &doc); err != nil {
				t.Errorf("%s: a trust store does not parse as YAML: %v", name, err)
				continue
			}
			ts := doc["trustStore"]
			if _, ok := ts["intermediateCas"]; ok || len(ts) != 1 || len(doc) != 1 {
				t.Errorf("%s: the trust store holds %d keys (intermediateCas: %v), want trustAnchors alone", name, len(ts), ok)
			}
			list, _ := ts["trustAnchors"].([]any)
			if len(list) != len(want) || len(want) == 0 {
				t.Errorf("%s: %d trust anchors, want %d", name, len(list), len(want))
				continue
			}
			for i, a := range list {
				m, _ := a.(map[string]any)
				pemText, _ := m["pemCertificate"].(string)
				blk, rest := pem.Decode([]byte(pemText))
				if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || len(m) != 1 {
					t.Errorf("%s: trust anchor %d is not one PEM certificate", name, i)
					continue
				}
				if !bytes.Equal(blk.Bytes, want[i]) {
					t.Errorf("%s: trust anchor %d is not its anchor's DER", name, i)
				}
			}
		}
	}
	// setup.sh 9, contingent.sh 2, i7-add.sh and i7-remove.sh 1 each,
	// renew-paste.sh 1, wfed-setup.sh 2.
	if stores != 9+2+1+1+1+2 {
		t.Errorf("%d trust stores in the blocks, want 16", stores)
	}
}

// m3aEnclosingIfs are the if lines that enclose lines[i], by indentation.
func m3aEnclosingIfs(lines []string, i int) []string {
	indent := func(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }
	var out []string
	level := indent(lines[i])
	for j := i - 1; j >= 0 && level > 0; j-- {
		if d := indent(lines[j]); d < level && strings.HasPrefix(strings.TrimSpace(lines[j]), "if ") {
			out = append(out, lines[j])
			level = d
		}
	}
	return out
}

// TestWalkM3aTeardownSkipsAbsent: in the teardowns and revoke-binding.sh,
// every delete, removal and disable is guarded by a describe, a state or a
// policy check; and the full teardowns remove every binding, the project
// grant included, before any SA is deleted, the providers before the pool,
// the pool before the SAs, and the APIs last.
func TestWalkM3aTeardownSkipsAbsent(t *testing.T) {
	st, wfed := m3aTestState(t), m3aTestWFEDState(t)
	blocks := map[string][]byte{}
	var err error
	if blocks["teardown.sh"], err = m3aTeardownBlock(st); err != nil {
		t.Fatal(err)
	}
	if blocks["teardown-v1.sh"], err = m3aTeardownV1Block(st); err != nil {
		t.Fatal(err)
	}
	if blocks["revoke-binding.sh"], err = m3aBindingBlock(st, true); err != nil {
		t.Fatal(err)
	}
	if blocks["wfed-teardown.sh"], err = m3aTeardownBlock(wfed); err != nil {
		t.Fatal(err)
	}
	guards := []string{" describe ", "get-iam-policy", "grep -qiF", "grep -qix", `"$POOL_PRESENT" = yes`}
	isGuard := func(l string) bool {
		for _, g := range guards {
			if strings.Contains(l, g) {
				return true
			}
		}
		return false
	}
	for name, b := range blocks {
		p := m3aParse(t, name, string(b))
		at := map[string][]int{}
		for i, l := range p.lines {
			if !strings.Contains(l, "gcloud ") {
				continue
			}
			var kind string
			switch {
			case strings.Contains(l, "remove-iam-policy-binding"):
				kind = "unbind"
			case strings.Contains(l, "providers delete"):
				kind = "provider"
			case strings.Contains(l, "workload-identity-pools delete"):
				kind = "pool"
			case strings.Contains(l, "service-accounts delete"):
				kind = "sa"
			case strings.Contains(l, "services disable"):
				kind = "api"
			default:
				continue
			}
			at[kind] = append(at[kind], i)
			if !slices.ContainsFunc(m3aEnclosingIfs(p.lines, i), isGuard) {
				t.Errorf("%s: an unguarded %s: %.100s", name, kind, l)
			}
		}
		if name != "teardown.sh" && name != "wfed-teardown.sh" {
			continue
		}
		last := func(k string) int { return slices.Max(append([]int{-1}, at[k]...)) }
		first := func(k string) int { return slices.Min(append([]int{len(p.lines)}, at[k]...)) }
		for _, k := range []string{"unbind", "provider", "pool", "sa", "api"} {
			if len(at[k]) == 0 {
				t.Errorf("%s: no %s line", name, k)
			}
		}
		if last("unbind") > first("sa") || last("provider") > first("pool") || last("pool") > first("sa") || last("sa") > first("api") {
			t.Errorf("%s: the order is not bindings and grants, providers, the pool, the SAs, then the APIs", name)
		}
		grant := -1
		for i, l := range p.lines {
			if strings.Contains(l, "projects remove-iam-policy-binding") {
				grant = i
			}
		}
		if grant < 0 || grant > first("sa") {
			t.Errorf("%s: the project grant is not removed before the SAs are deleted", name)
		}
	}
}

// TestWalkM3aBlocksAreReproducibleFromState: the same state, saved and read
// back, gives byte-identical blocks and digests.
func TestWalkM3aBlocksAreReproducibleFromState(t *testing.T) {
	st, wfed := m3aTestState(t), m3aTestWFEDState(t)
	staged := m3aTestCA(t, st.roleID(m3aV1, m3aWriter))
	a := m3aAllBlocks(t, st, wfed, staged)
	dir, wdir := t.TempDir(), t.TempDir()
	if err := m3aSaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	if err := m3aSaveState(wdir, wfed); err != nil {
		t.Fatal(err)
	}
	st2, err := m3aLoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	wfed2, err := m3aLoadState(wdir)
	if err != nil {
		t.Fatal(err)
	}
	b := m3aAllBlocks(t, st2, wfed2, staged)
	if len(a) != len(b) {
		t.Fatalf("%d blocks, then %d", len(a), len(b))
	}
	for name := range a {
		if !bytes.Equal(a[name], b[name]) || m3aDigest(a[name]) != m3aDigest(b[name]) {
			t.Errorf("%s differs between two generations from one state", name)
		}
		if len(m3aDigest(a[name])) != 12 {
			t.Errorf("%s's digest is not 12 hex", name)
		}
	}
}

// TestWalkM3aLiteralsCoverEveryID: every ID-bearing field of the state is a
// scrub literal, and the literals are longest first.
func TestWalkM3aLiteralsCoverEveryID(t *testing.T) {
	st := m3aTestState(t)
	lits := m3aLiterals(st)
	have := map[string]bool{}
	for i, l := range lits {
		have[l[0]] = true
		if i > 0 && len(l[0]) > len(lits[i-1][0]) {
			t.Error("the literals are not longest first")
		}
		if !strings.HasPrefix(l[1], "$") || strings.Contains(l[1], l[0]) {
			t.Error("a literal does not print as a placeholder")
		}
	}
	var want []string
	want = append(want, st.Project, st.ProjectNumber, st.Pool, st.ReaderSA, st.WriterSA, st.APIRecord,
		m3aEmail(st.ReaderSA, st.Project), m3aEmail(st.WriterSA, st.Project))
	for _, v := range st.Variants {
		for _, p := range v.Providers {
			want = append(want, p)
		}
		for _, id := range v.RoleIDs {
			want = append(want, id)
		}
		if v.Subject != "" {
			want = append(want, v.Subject)
		}
		if v.KID != "" {
			want = append(want, v.KID, strings.TrimPrefix(v.Issuer, "https://"))
		}
	}
	if len(want) < 35 {
		t.Fatalf("only %d ID-bearing fields in the test state", len(want))
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("an ID-bearing field of %d characters is not a literal", len(w))
		}
	}
	// Replaced longest first, as walkScrubber.text does, no value survives.
	for _, w := range want {
		s := "x " + w + " y"
		for _, l := range lits {
			s = strings.ReplaceAll(s, l[0], l[1])
		}
		if strings.Contains(s, w) {
			t.Errorf("a value of %d characters survives the literals", len(w))
		}
	}
}

// TestWalkM3aAuditBlockEncodingsAndScrub: audit.sh embeds each leaf's serial
// and fingerprint in each encoding, and its scrub replaces a pool or provider
// ID, an SA ID and a 12-digit number.
func TestWalkM3aAuditBlockEncodingsAndScrub(t *testing.T) {
	st := m3aTestState(t)
	b, err := m3aAuditBlock(st)
	if err != nil {
		t.Fatal(err)
	}
	p := m3aParse(t, "audit.sh", string(b))
	var data m3aAuditData
	for _, d := range p.docs {
		if d.tag == "END_OF_DATA" {
			if err := json.Unmarshal([]byte(d.body), &data); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, der := range st.Leaves {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(der)
		sb := c.SerialNumber.Bytes()
		serial := map[string]string{
			"decimal": c.SerialNumber.String(), "lower hex": hex.EncodeToString(sb), "upper hex": strings.ToUpper(hex.EncodeToString(sb)),
			"base64 std": base64.StdEncoding.EncodeToString(sb), "base64 url": base64.RawURLEncoding.EncodeToString(sb),
		}
		fp := map[string]string{
			"lower hex": hex.EncodeToString(sum[:]), "upper hex": strings.ToUpper(hex.EncodeToString(sum[:])),
			"base64 std": base64.StdEncoding.EncodeToString(sum[:]), "base64 url": base64.RawURLEncoding.EncodeToString(sum[:]),
		}
		for _, enc := range m3aEncodingNames {
			if v, ok := serial[enc]; ok && !slices.Contains(data.Serials[enc], v) {
				t.Errorf("a leaf's serial is not embedded in %s", enc)
			}
			if v, ok := fp[enc]; ok && !slices.Contains(data.Fingerprints[enc], v) {
				t.Errorf("a leaf's fingerprint is not embedded in %s", enc)
			}
		}
		colon := regexp.MustCompile(`^[0-9A-F]{2}(:[0-9A-F]{2})+$`)
		if !slices.ContainsFunc(data.Fingerprints["colon hex"], func(s string) bool {
			return colon.MatchString(s) && strings.ReplaceAll(s, ":", "") == strings.ToUpper(hex.EncodeToString(sum[:]))
		}) {
			t.Error("a leaf's fingerprint is not embedded in colon hex")
		}
		if !slices.ContainsFunc(data.Serials["colon hex"], func(s string) bool {
			return strings.ReplaceAll(s, ":", "") == strings.ToUpper(hex.EncodeToString(sb))
		}) {
			t.Error("a leaf's serial is not embedded in colon hex")
		}
	}
	if len(data.Literals) == 0 || !slices.Contains(data.Literals, st.Pool) {
		t.Error("audit.sh does not embed the run's literals")
	}
	// Every CA the run made, each variant's anchors, I7's and the state's
	// others, by its SHA-256 fingerprint in each encoding: Google's X.509
	// keyInfo names a trust anchor or an intermediate CA, not the leaf.
	var cas [][]byte
	for _, v := range st.Variants {
		for _, a := range v.Anchors {
			cas = append(cas, a)
		}
	}
	cas = append(append(cas, st.I7Anchor), st.CAs...)
	if len(cas) < 15 {
		t.Fatalf("the test state holds %d CAs", len(cas))
	}
	for _, der := range cas {
		sum := sha256.Sum256(der)
		for enc, v := range map[string]string{"lower hex": hex.EncodeToString(sum[:]), "upper hex": strings.ToUpper(hex.EncodeToString(sum[:])),
			"base64 std": base64.StdEncoding.EncodeToString(sum[:]), "base64 url": base64.RawURLEncoding.EncodeToString(sum[:])} {
			if !slices.Contains(data.CAFingerprints[enc], v) {
				t.Errorf("a CA's fingerprint is not embedded in %s", enc)
			}
		}
	}
	// Four reads: the IAM API's Data Access entries too, since Google asks
	// for its Admin Read to log every step of the exchange; each Data Access
	// read says whether a CA's fingerprint appears.
	reads := 0
	iamDataAccess := false
	for _, l := range p.lines {
		if !strings.Contains(l, "gcloud logging read ") {
			continue
		}
		reads++
		if strings.Contains(l, `"$DATAACCESS AND protoPayload.serviceName=\"iam.googleapis.com\""`) {
			iamDataAccess = true
		}
	}
	if reads != 4 || !iamDataAccess {
		t.Errorf("audit.sh makes %d logging reads, IAM's Data Access among them: %v; want 4, with it", reads, iamDataAccess)
	}
	if n := strings.Count(string(b), `an anchor or intermediate CA fingerprint appears: \(which("ca_fingerprints"))`); n != 3 {
		t.Errorf("audit.sh looks for a CA's fingerprint in %d places, want 3 (STS and IAM Credentials; IAM's entries, all and kept)", n)
	}
	if !strings.Contains(string(b), `map(select(federated))`) || !strings.Contains(m3aAuditDefs, `test("[.](Get|List)[A-Za-z]*$") | not`) {
		t.Error("audit.sh does not keep the IAM entries a federated caller or a method other than a Get or a List made")
	}
	// jq's gsub patterns, applied as Go reads them: both are plain classes.
	var res []*regexp.Regexp
	for _, m := range regexp.MustCompile(`gsub\("([^"]+)"; "#"\)`).FindAllStringSubmatch(string(b), -1) {
		res = append(res, regexp.MustCompile(m[1]))
	}
	if len(res) < 2 {
		t.Fatalf("audit.sh holds %d scrub patterns, want 2", len(res))
	}
	scrub := func(s string) string {
		for _, re := range res {
			s = re.ReplaceAllString(s, "#")
		}
		return s
	}
	for _, sample := range []string{m3aTestID(t, 32), "g" + m3aTestID(t, 31), m3aTestID(t, 30), "123456789012"} {
		if got := scrub("a." + sample + ".b"); got != "a.#.b" {
			t.Errorf("a key path holding a %d-character value scrubs to %q", len(sample), got)
		}
	}
	if got := scrub("protoPayload.authenticationInfo.principalSubject"); got != "protoPayload.authenticationInfo.principalSubject" {
		t.Errorf("a field name scrubs to %q", got)
	}
}

// TestWalkM3aTokenInfoReduction: the facts hold none of azp, aud or the email;
// the scopes map to short names; and a missing email reads "absent".
func TestWalkM3aTokenInfoReduction(t *testing.T) {
	const email = "reader-planted@probe-project-1.iam.gserviceaccount.com"
	body := `{"azp":"planted-azp-111","aud":"planted-aud-222","email":"` + email + `","email_verified":"true",` +
		`"scope":"` + kube.ScopeCloudPlatform + ` ` + kube.ScopeUserinfoEmail + ` https://www.googleapis.com/auth/other","expires_in":"3599","exp":"1900000000"}`
	f, err := m3aTokenInfo([]byte(body), email)
	if err != nil {
		t.Fatal(err)
	}
	if f.email != "yes" || !slices.Equal(f.scopes, []string{"cloud-platform", "userinfo.email", "1 other"}) || f.expiresIn != "3599" {
		t.Errorf("facts %+v", f)
	}
	all := fmt.Sprintf("%v %+v %#v", f, f, f)
	for _, planted := range []string{"planted-azp-111", "planted-aud-222", email, "reader-planted", "1900000000"} {
		if strings.Contains(all, planted) {
			t.Errorf("a fact holds %q", planted)
		}
	}
	if f, _ := m3aTokenInfo([]byte(body), "another@probe-project-1.iam.gserviceaccount.com"); f.email != "no" {
		t.Errorf("another email reads %q, want no", f.email)
	}
	f, err = m3aTokenInfo([]byte(`{"scope":"`+kube.ScopeCloudPlatform+`","expires_in":3000}`), email)
	if err != nil || f.email != "absent" || !slices.Equal(f.scopes, []string{"cloud-platform"}) || f.expiresIn != "3000" {
		t.Errorf("no email: %+v (%v)", f, err)
	}
	if f, _ := m3aTokenInfo([]byte(`{"expires_in":"soon"}`), email); f.expiresIn != "unreadable" || f.scopes != nil {
		t.Errorf("a bad expires_in: %+v", f)
	}
	if _, err := m3aTokenInfo([]byte(`["x"]`), email); err == nil {
		t.Error("an answer that is not an object was reduced")
	}
}

// TestWalkM3aReadLimitedRefusesMore: an answer up to the bound is read whole,
// and one of even a byte more is refused, never cut to the bound and read as
// if it were whole; the refusal holds none of the answer.
func TestWalkM3aReadLimitedRefusesMore(t *testing.T) {
	const max = 64
	body := func(n int) io.Reader {
		return bytes.NewReader(bytes.Repeat([]byte("ANSWER-TEXT-"), n/12+1)[:n])
	}
	for _, n := range []int{0, 1, max - 1, max} {
		if b, err := m3aReadLimited(body(n), max); err != nil || len(b) != n {
			t.Errorf("%d bytes under a bound of %d: %d read (%v), want all of them", n, max, len(b), err)
		}
	}
	for _, n := range []int{max + 1, max + 2, 4 * max} {
		b, err := m3aReadLimited(body(n), max)
		if err == nil || b != nil {
			t.Errorf("%d bytes under a bound of %d: %d read, want a refusal", n, max, len(b))
			continue
		}
		if strings.Contains(err.Error(), "ANSWER-TEXT") {
			t.Errorf("the refusal holds the answer: %v", err)
		}
	}
}

// TestWalkM3aPolicyBlockNamesItsConstraints: P9's list, as transcribed, and
// policies.sh reads exactly it, in order, with the Org Policy API asked for.
func TestWalkM3aPolicyBlockNamesItsConstraints(t *testing.T) {
	want := []string{
		"iam.allowedPolicyMemberDomains",
		"iam.managed.allowedPolicyMembers",
		"iam.automaticIamGrantsForDefaultServiceAccounts",
		"iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts",
		"iam.disableServiceAccountKeyCreation",
		"iam.managed.disableServiceAccountKeyCreation",
		"iam.disableServiceAccountKeyUpload",
		"iam.managed.disableServiceAccountKeyUpload",
		"iam.workloadIdentityPoolProviders",
		"iam.managed.workloadIdentityPoolProviders",
		"iam.workloadIdentityPoolAwsAccounts",
		"essentialcontacts.allowedContactDomains",
		"essentialcontacts.managed.allowedContactDomains",
		"compute.managed.restrictProtocolForwardingCreationForTypes",
		"compute.restrictProtocolForwardingCreationForTypes",
		"storage.uniformBucketLevelAccess",
		"storage.publicAccessPrevention",
	}
	if !slices.Equal(m3aPolicyConstraints, want) {
		t.Errorf("the constraint list is %q, want %q", m3aPolicyConstraints, want)
	}
	// The secure-by-default baseline's seven, as Google's page lists them
	// (read 2026-11-23), each read, so P9 can say whether the organization
	// carries the whole set; and no name that Google's constraint list does
	// not hold.
	baseline := []string{
		"iam.managed.disableServiceAccountKeyCreation",
		"iam.disableServiceAccountKeyUpload",
		"iam.automaticIamGrantsForDefaultServiceAccounts",
		"iam.allowedPolicyMemberDomains",
		"essentialcontacts.managed.allowedContactDomains",
		"compute.managed.restrictProtocolForwardingCreationForTypes",
		"storage.uniformBucketLevelAccess",
	}
	if !slices.Equal(m3aSecureByDefault, baseline) {
		t.Errorf("the secure-by-default baseline is %q, want %q", m3aSecureByDefault, baseline)
	}
	for _, c := range baseline {
		if !slices.Contains(m3aPolicyConstraints, c) {
			t.Errorf("policies.sh does not read the baseline's %s", c)
		}
	}
	if slices.Contains(m3aPolicyConstraints, "iam.managed.workloadIdentityPoolAwsAccounts") {
		t.Error("policies.sh reads a constraint Google's list does not name")
	}
	b, err := m3aPoliciesBlock(&m3aState{Project: "probe-project-1", Pool: "p" + strings.Repeat("0", 31), ReaderSA: "r" + strings.Repeat("0", 29), WriterSA: "w" + strings.Repeat("0", 29), APIRecord: "a" + strings.Repeat("0", 31)})
	if err != nil {
		t.Fatal(err)
	}
	p := m3aParse(t, "policies.sh", string(b))
	var read []string
	kinds := 0
	for i, l := range p.lines {
		if strings.Contains(l, "org-policies describe ") {
			words, _ := m3aSplitWords(l)
			read = append(read, m3aWordAfter(words, "describe"))
			if !strings.Contains(l, "--effective") {
				t.Error("a constraint is read without --effective")
			}
		}
		if strings.Contains(l, `"$KINDSJQ"`) {
			kinds++
			if !strings.Contains(strings.Join(p.lines[max(0, i-3):i], "\n"), "workloadIdentityPoolProviders") {
				t.Error("allowed values are counted by kind for another constraint")
			}
		}
	}
	if !slices.Equal(read, want) {
		t.Errorf("policies.sh reads %q, want %q", read, want)
	}
	if kinds != 2 {
		t.Errorf("allowed values are counted by kind for %d constraints, want the two provider constraints", kinds)
	}
	ask := slices.IndexFunc(p.lines, func(l string) bool { return strings.Contains(l, "Enable the Org Policy API") })
	enable := slices.IndexFunc(p.lines, func(l string) bool { return strings.Contains(l, "services enable") })
	if ask < 0 || enable < ask {
		t.Error("policies.sh enables the Org Policy API without asking first")
	}
}

// TestWalkM3aTeardownKeepsWhatItCouldNotDisable: the teardowns try each
// recorded API's disable once, without --force (which would disable
// dependents too); an API disabled leaves the record, one Google refused
// stays in it with a "kept enabled" line, and the record is removed only
// when it names nothing, so a refused disable is never lost from the record.
func TestWalkM3aTeardownKeepsWhatItCouldNotDisable(t *testing.T) {
	st, wfed := m3aTestState(t), m3aTestWFEDState(t)
	tail := []string{
		`if [ -s "$RECORD" ]; then`,
		`  echo 'API record: kept; it names the APIs still enabled, and this block can be pasted again'`,
		`else`,
		`  rm -f "$RECORD"`,
		`  echo 'API record: removed'`,
		`fi`,
	}
	for _, c := range []struct {
		name string
		st   *m3aState
	}{{"teardown.sh", st}, {"wfed-teardown.sh", wfed}} {
		b, err := m3aTeardownBlock(c.st)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		p := m3aParse(t, c.name, text)
		for _, l := range m3aGcloudLines(p) {
			if strings.Contains(l, "services disable") && (strings.Contains(l, "retry gcloud") || strings.Contains(l, " --force")) {
				t.Errorf("%s retries a disable, or forces one: %.100s", c.name, l)
			}
		}
		disables := 0
		for i, l := range p.lines {
			if !strings.Contains(l, "gcloud services disable ") {
				continue
			}
			disables++
			words, err := m3aSplitWords(strings.TrimSpace(l))
			if err != nil {
				t.Fatal(err)
			}
			api := m3aWordAfter(words, "disable")
			q := m3aMustQuote(t, api)
			want := []string{
				`echo 'API ` + api + `: disabled'`,
				`{ grep -vix -e ` + q + ` "$RECORD" || :; } >"$KEEP"`,
				`cat "$KEEP" >"$RECORD"`,
				`else`,
				`echo "API ` + api + m3aKeptEnabled + `; the message names --force: $(yn 'force'); a dependent service: $(yn 'depend')"`,
				`fi`,
			}
			if i+len(want) >= len(p.lines) {
				t.Fatalf("%s: %s's disable ends the block", c.name, api)
			}
			for j, w := range want {
				if got := strings.TrimSpace(p.lines[i+1+j]); got != w {
					t.Errorf("%s: %s's disable, line %d after it: %q, want %q", c.name, api, j+1, got, w)
				}
			}
		}
		if disables != len(m3aDisableOrder)+1 {
			t.Errorf("%s: %d disables, want the %d recorded APIs and the Org Policy API", c.name, disables, len(m3aDisableOrder))
		}
		if n := strings.Count(text, `rm -f "$RECORD"`); n != 1 {
			t.Errorf("%s removes the record %d times, want once, when it names nothing", c.name, n)
		}
		at := slices.Index(p.lines, tail[0])
		if at < 0 || at+len(tail) > len(p.lines) || !slices.Equal(p.lines[at:at+len(tail)], tail) {
			t.Errorf("%s does not keep the record while it names an API", c.name)
		}
		left := slices.Index(p.lines, `    echo 'API `+m3aOrgPolicyAPI+`: left enabled'`)
		if left < 0 || strings.Contains(p.lines[left+1], "grep -vix") {
			t.Errorf("%s: the Org Policy API left enabled must stay in the record", c.name)
		}
	}
}

// TestWalkM3aProbeClients: the probe-only clients' host guard sends to its
// own host over https alone, and nothing otherwise; it sets User-Agent
// farcast; the client has no proxy, follows no redirect, and takes TLS 1.3
// exactly when it carries a certificate (I1's), so V1's reader leaf never
// crosses the network in clear.
func TestWalkM3aProbeClients(t *testing.T) {
	const host = "probe-host.invalid"
	var sent []*http.Request
	rt := m3aRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent = append(sent, r)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	g := m3aHostGuard{host: host, inner: rt}
	for _, u := range []string{
		"https://other-host.invalid/x", "http://" + host + "/x", "https://" + host + ":8443/x",
		"https://" + host + ".other.invalid/x", "ftp://" + host + "/x", "https://user@other-host.invalid/x",
	} {
		req, err := http.NewRequest(http.MethodPost, u, strings.NewReader("access_token=planted"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer planted")
		if _, err := g.RoundTrip(req); err == nil {
			t.Errorf("the guard sent to %s", u)
		}
	}
	if _, err := g.RoundTrip(&http.Request{Method: http.MethodGet, Header: http.Header{}}); err == nil {
		t.Error("the guard sent a request with no URL")
	}
	if len(sent) != 0 {
		t.Fatalf("%d requests reached the transport for another host or scheme", len(sent))
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/v1/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "another-agent/1")
	resp, err := g.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(sent) != 1 || sent[0].Header.Get("User-Agent") != kube.UserAgent {
		t.Errorf("the guard sent %d requests; User-Agent %q, want %q", len(sent), sent[0].Header.Get("User-Agent"), kube.UserAgent)
	}
	if req.Header.Get("User-Agent") != "another-agent/1" {
		t.Error("the guard changed the caller's own request")
	}

	leaf := &tls.Certificate{Certificate: [][]byte{{0x30}}}
	for _, cert := range []*tls.Certificate{nil, leaf} {
		c := m3aHTTPClient(host, cert)
		guard, ok := c.Transport.(m3aHostGuard)
		if !ok || guard.host != host {
			t.Fatalf("the client's transport is not the host guard for its host")
		}
		tr, ok := guard.inner.(*http.Transport)
		if !ok {
			t.Fatal("the guard's inner transport is not an *http.Transport")
		}
		cfg := tr.TLSClientConfig
		want := uint16(tls.VersionTLS12)
		if cert != nil {
			want = tls.VersionTLS13
		}
		if cfg == nil {
			t.Fatal("the probe-only client has no TLS config")
		}
		if cfg.MinVersion != want || cfg.ServerName != host || cfg.RootCAs != nil || cfg.InsecureSkipVerify || len(cfg.Certificates) != 0 {
			t.Errorf("with a certificate %v: MinVersion %x, ServerName the host %v, the system roots %v, certificates %d; want MinVersion %x on the system roots, ServerName the host",
				cert != nil, cfg.MinVersion, cfg.ServerName == host, cfg.RootCAs == nil && !cfg.InsecureSkipVerify, len(cfg.Certificates), want)
		}
		if (cfg.GetClientCertificate != nil) != (cert != nil) {
			t.Errorf("with a certificate %v: a client certificate is offered: %v", cert != nil, cfg.GetClientCertificate != nil)
		}
		if cert != nil {
			got, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
			if err != nil || got == cert || len(got.Certificate) != 1 || !bytes.Equal(got.Certificate[0], leaf.Certificate[0]) {
				t.Error("the client certificate offered is not a copy of the one given")
			}
		}
		if tr.Proxy != nil {
			t.Error("the probe-only client reads a proxy")
		}
		if tr.DialContext == nil || c.Timeout != 30*time.Second {
			t.Errorf("the client's dialer or its timeout (%s) is not its own", c.Timeout)
		}
		if c.CheckRedirect == nil || !errors.Is(c.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
			t.Error("the probe-only client follows a redirect")
		}
	}
}

// m3aRoundTripFunc is a RoundTripper from a function.
type m3aRoundTripFunc func(*http.Request) (*http.Response, error)

func (f m3aRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestWalkM3aPositiveVerdicts: a gating positive holds when accepted, FAILS
// on a decision against it, and reads INCONCLUSIVE when its last answer was no
// decision, as a negative does; T2's token info must list both scopes when it
// answers 200; T4's read-back is no decision on a 3xx, 429 or 5xx; and
// hold-delete holds the reader alone only when the writer's exchange was
// refused with a decision.
func TestWalkM3aPositiveVerdicts(t *testing.T) {
	// T4's read-back, polled from the setup mark until a 200: a 401, 403 or
	// 404 at the bound is a decision against it; a 3xx, 429, 5xx or no answer
	// is none; a 200 holds only when the provider matched.
	for _, tc := range []struct {
		name     string
		answered bool
		code     int
		matched  bool
		want     string
	}{
		{"200, matched", true, http.StatusOK, true, m3aHolds},
		{"200, differs", true, http.StatusOK, false, m3aFails},
		{"401 at the bound", true, http.StatusUnauthorized, false, m3aFails},
		{"403 at the bound", true, http.StatusForbidden, false, m3aFails},
		{"404 at the bound", true, http.StatusNotFound, false, m3aFails},
		{"400 at the bound", true, http.StatusBadRequest, false, m3aFails},
		{"307 at the bound", true, http.StatusTemporaryRedirect, false, m3aInconclusive},
		{"429 at the bound", true, http.StatusTooManyRequests, false, m3aInconclusive},
		{"503 at the bound", true, http.StatusServiceUnavailable, false, m3aInconclusive},
		{"no answer at the bound", false, 0, false, m3aInconclusive},
	} {
		if got := m3aReadBackPollVerdict(tc.answered, tc.code, tc.matched); got != tc.want {
			t.Errorf("T4's read-back, %s: %s, want %s", tc.name, got, tc.want)
		}
	}
	fe := func(step kube.Step, status int) error { return &kube.FederationError{Step: step, Status: status} }
	alert := func(words string) error {
		return &kube.FederationError{Step: kube.StepExchange, Handshake: true, Alert: words}
	}
	for _, tc := range []struct {
		name     string
		accepted bool
		last     error
		want     string
		leftOut  bool // m3aWriterLeftOut, for the same last answer
	}{
		{"accepted", true, nil, m3aHolds, false},
		{"not tried", false, nil, m3aFails, false},
		{"400", false, fe(kube.StepExchange, http.StatusBadRequest), m3aFails, true},
		{"401", false, fe(kube.StepImpersonate, http.StatusUnauthorized), m3aFails, true},
		{"403", false, fe(kube.StepImpersonate, http.StatusForbidden), m3aFails, true},
		{"a certificate alert", false, alert("tls: certificate required"), m3aFails, true},
		{"a 200 without a usable token", false, fe(kube.StepExchange, http.StatusOK), m3aFails, false},
		{"307", false, fe(kube.StepExchange, http.StatusTemporaryRedirect), m3aInconclusive, false},
		{"429", false, fe(kube.StepExchange, http.StatusTooManyRequests), m3aInconclusive, false},
		{"500", false, fe(kube.StepExchange, http.StatusInternalServerError), m3aInconclusive, false},
		{"503", false, fe(kube.StepImpersonate, http.StatusServiceUnavailable), m3aInconclusive, false},
		{"not answered", false, fe(kube.StepExchange, 0), m3aInconclusive, false},
		{"internal_error", false, alert("tls: internal error"), m3aInconclusive, false},
		{"not a federation error", false, errors.New("EOF"), m3aInconclusive, false},
	} {
		if got := m3aPositiveVerdict(tc.accepted, tc.last); got != tc.want {
			t.Errorf("a positive %s: %s, want %s", tc.name, got, tc.want)
		}
		if !tc.accepted {
			if got := m3aWriterLeftOut(tc.last); got != tc.leftOut {
				t.Errorf("hold-delete's writer exchange %s: left out %v, want %v", tc.name, got, tc.leftOut)
			}
		}
		if !tc.accepted && tc.last != nil {
			want := tc.want
			if got := m3aAnyShapeVerdict(false, []error{fe(kube.StepExchange, http.StatusBadRequest), tc.last}); got != want {
				t.Errorf("T1, no shape passed and the last one %s: %s, want %s", tc.name, got, want)
			}
		}
	}
	if got := m3aAnyShapeVerdict(true, []error{fe(kube.StepExchange, http.StatusServiceUnavailable)}); got != m3aHolds {
		t.Errorf("T1 with a shape passed: %s, want %s", got, m3aHolds)
	}
	if got := m3aAnyShapeVerdict(false, nil); got != m3aFails {
		t.Errorf("T1 with nothing tried: %s, want %s", got, m3aFails)
	}
	for _, tc := range []struct {
		vs   []string
		want string
	}{
		{nil, m3aFails},
		{[]string{m3aHolds}, m3aHolds},
		{[]string{m3aHolds, m3aInconclusive, m3aHolds}, m3aInconclusive},
		{[]string{m3aInconclusive, m3aFails, m3aHolds}, m3aFails},
		{[]string{""}, m3aFails},
	} {
		if got := m3aWorstVerdict(tc.vs...); got != tc.want {
			t.Errorf("%q as one: %s, want %s", tc.vs, got, tc.want)
		}
	}
	for code, want := range map[int]string{
		http.StatusBadRequest: m3aFails, http.StatusForbidden: m3aFails, http.StatusNotFound: m3aFails,
		http.StatusFound: m3aInconclusive, http.StatusTooManyRequests: m3aInconclusive,
		http.StatusInternalServerError: m3aInconclusive, http.StatusServiceUnavailable: m3aInconclusive,
	} {
		if got := m3aReadBackVerdict(code); got != want {
			t.Errorf("T4's read-back answered %d: %s, want %s", code, got, want)
		}
	}
	const email = "reader-planted@probe-project-1.iam.gserviceaccount.com"
	info := func(scope string) (m3aTokenInfoFacts, error) {
		return m3aTokenInfo([]byte(`{"email":"`+email+`","scope":"`+scope+`","expires_in":"3599"}`), email)
	}
	both, _ := info(kube.ScopeCloudPlatform + " " + kube.ScopeUserinfoEmail)
	cpOnly, _ := info(kube.ScopeCloudPlatform)
	ueOnly, _ := info(kube.ScopeUserinfoEmail)
	more, _ := info(kube.ScopeUserinfoEmail + " https://www.googleapis.com/auth/other " + kube.ScopeCloudPlatform)
	for _, tc := range []struct {
		name     string
		answered bool
		code     int
		f        m3aTokenInfoFacts
		readErr  error
		want     string
	}{
		{"not answered", false, 0, m3aTokenInfoFacts{}, nil, m3aInconclusive},
		{"not answered by POST (405)", true, http.StatusMethodNotAllowed, m3aTokenInfoFacts{}, nil, m3aHolds},
		{"not answered by POST (400)", true, http.StatusBadRequest, m3aTokenInfoFacts{}, nil, m3aHolds},
		{"both scopes", true, http.StatusOK, both, nil, m3aHolds},
		{"both scopes and another", true, http.StatusOK, more, nil, m3aHolds},
		{"cloud-platform alone", true, http.StatusOK, cpOnly, nil, m3aFails},
		{"userinfo.email alone", true, http.StatusOK, ueOnly, nil, m3aFails},
		{"no scope", true, http.StatusOK, m3aTokenInfoFacts{email: "yes"}, nil, m3aFails},
		{"not readable", true, http.StatusOK, m3aTokenInfoFacts{}, errors.New("not an object"), m3aInconclusive},
	} {
		if got := m3aT2TokenInfo(tc.answered, tc.code, tc.f, tc.readErr); got != tc.want {
			t.Errorf("T2's token info %s: %s, want %s", tc.name, got, tc.want)
		}
	}
}
