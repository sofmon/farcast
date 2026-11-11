package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/shrike"
	"github.com/sofmon/farcast/technocore/usage"
)

func tunnelStream(kind event.Kind, role, token, route, reason string) event.Event {
	return event.Event{Kind: kind, Proto: event.ProtoStream, PeerRole: role, PeerToken: token, Host: route, Reason: reason}
}

// The monitor hands back tokens; this machine names them. The operator's own
// leaf is "operator", a keeper this machine enrolled is named with its state,
// and a keeper leaf it has no record of is said to be one — never guessed, and
// never folded into the application table.
func TestUsageNamesTunnelPeersOnlyOnThisMachine(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := meteringInstance(t, dir, "p51")
	m, err := identity.Mint("p51")
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMTLS("p51", config.MTLSMaterial{
		CACertPEM: m.CACertPEM, CAKeyPEM: m.CAKeyPEM, ClientCertPEM: m.ClientCertPEM, ClientKeyPEM: m.ClientKeyPEM,
		ServerCertPEM: m.ServerCertPEM, ServerKeyPEM: m.ServerKeyPEM,
	}); err != nil {
		t.Fatal(err)
	}
	operatorToken, err := identity.LeafTokenPEM(m.ClientCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	const laptop, desk, stranger = "1111111111111111", "2222222222222222", "9999999999999999"
	meta.Keepers = []config.Keeper{
		{Device: "laptop", Revoked: true, LeafTokens: []string{laptop}},
		{Device: "desk", Expires: time.Now().Add(-time.Hour), LeafTokens: []string{"0000000000000000", desk}},
	}
	if err := dir.SaveInstanceMetadata("p51", meta); err != nil {
		t.Fatal(err)
	}
	body := profilesFor(t, time.Now(), func(*usage.Store) {}, nil)

	d := shrikeServing(t, func(mon *shrike.Monitor) {
		mon.Emit(tunnelStream(event.Allow, event.PeerOperator, operatorToken, "shrike", event.ReasonRelayed))
		mon.Emit(tunnelStream(event.Deny, event.PeerKeeper, laptop, "shrike", event.ReasonRoleRefused))
		mon.Emit(tunnelStream(event.Allow, event.PeerKeeper, desk, "keyholder", event.ReasonRelayed))
		mon.Emit(tunnelStream(event.Allow, event.PeerKeeper, stranger, "keyholder", event.ReasonRelayed))
	})
	shown := runUsageWith(t, dir, body, output.ModeHuman, d)
	t.Log("\n" + shown)

	tunnel := shown[strings.Index(shown, "Tunnel —"):]
	for _, want := range []string{
		"operator ", "keeper laptop (revoked)", "keeper desk (expired)",
		"keeper (leaf not enrolled from this machine)", "role_refused 1", "Re-enrolling it from here",
	} {
		if !strings.Contains(tunnel, want) {
			t.Errorf("the tunnel section is missing %q", want)
		}
	}
	if strings.Contains(tunnel, "operator (another leaf)") {
		t.Error("the operator's own leaf was not recognised")
	}
	// The application table is for applications.
	apps := shown[strings.Index(shown, "Network —"):strings.Index(shown, "Tunnel —")]
	if !strings.Contains(apps, "No application has made an outbound connection") || strings.Contains(apps, "(unidentified)") {
		t.Errorf("tunnel streams reached the application table:\n%s", apps)
	}

	// --json carries the same names, for the operator's own tooling.
	js := runUsageWith(t, dir, body, output.ModeJSON, d)
	if !strings.Contains(js, `"who": "keeper laptop (revoked)"`) && !strings.Contains(js, `"who":"keeper laptop (revoked)"`) {
		t.Errorf("--json does not name the keeper:\n%s", js)
	}
}

// Every naming branch, directly: an earlier leaf of a re-enrolled device, an
// operator leaf that is not this machine's, an operator leaf when this
// machine's cannot be read, and a FatLine older than attribution.
func TestTunnelPeerNames(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	keepers := []config.Keeper{
		{Device: "desk", Expires: now.Add(time.Hour), LeafTokens: []string{"old", "new"}},
	}
	for _, tc := range []struct{ role, token, op, want string }{
		{event.PeerKeeper, "new", "op", "keeper desk"},
		{event.PeerKeeper, "old", "op", "keeper desk (an earlier leaf)"},
		{event.PeerKeeper, "", "op", unnamedKeeper},
		{event.PeerOperator, "op", "op", "operator"},
		{event.PeerOperator, "other", "op", "operator (another leaf)"},
		{event.PeerOperator, "other", "", "operator"},
		{"", "", "op", "(peer not reported — FatLine predates attribution)"},
	} {
		if got := tunnelPeerName(tc.role, tc.token, keepers, tc.op, now); got != tc.want {
			t.Errorf("tunnelPeerName(%q, %q, op=%q) = %q, want %q", tc.role, tc.token, tc.op, got, tc.want)
		}
	}
}

// An older monitor folded tunnel streams into the "(unidentified)" application
// row. The report says so when the picture does not claim to separate them,
// and only then.
func TestUsageSaysWhenTheMonitorPredatesTunnelSeparation(t *testing.T) {
	// A picture as an older monitor served it: no tunnel fields at all.
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"since":"2026-11-10T10:00:00Z","events":2,"declared":[],"allowed":[],"violations":[],"apps":[{"hosts":0,"allows":0,"denies":2,"fails":0,"bytes_up":0,"bytes_down":0}]}`))
	}))
	t.Cleanup(old.Close)
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	body := profilesFor(t, time.Now(), func(*usage.Store) {}, nil)
	shown := runUsageWith(t, dir, body, output.ModeHuman, &fakeStreamDialer{addr: strings.TrimPrefix(old.URL, "http://")})
	if !strings.Contains(shown, "(unidentified)") || !strings.Contains(shown, "predates separating them") {
		t.Errorf("an older monitor's unidentified row carries no note:\n%s", shown)
	}

	// The same row from a monitor that separates the tunnel is a real
	// unidentified caller, and carries no note.
	r := usageResult{Network: []shrike.AppStat{{Denies: 2}}, TunnelSeparated: true, Replicas: 1}
	var buf bytes.Buffer
	if err := r.Human(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "(unidentified)") || strings.Contains(buf.String(), "predates separating them") {
		t.Errorf("a current monitor's unidentified row was annotated:\n%s", buf.String())
	}
}

// onlyPrintable fails unless every rune of out prints, line breaks aside: no
// escape, no carriage return, no C1 control (raw 0x9b, or U+009B), no bidi
// override, and nothing that is not UTF-8 at all.
func onlyPrintable(t *testing.T, what, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Errorf("%s: bytes that are not UTF-8 reached the terminal:\n%q", what, out)
		return
	}
	for _, r := range out {
		if r != '\n' && !unicode.IsPrint(r) {
			t.Errorf("%s: %U reached the terminal raw:\n%q", what, r, out)
			return
		}
	}
}

// Review findings PRIV-1 and A-1. For a route FatLine does not serve, the route
// name is whatever path the peer asked for, percent-decoded — and a keeper
// leaf is a peer. Printed raw, it reached the operator's terminal: an escape
// that erases the line above or conceals the rest of the table, an OSC 52
// clipboard write, a carriage return, a raw C1 CSI, a bidi override. Every
// one is quoted, the columns are measured on what is printed, and the row a
// hostile one sits beside is printed whole on its own line.
func TestUsageTunnelQuotesWhatThePeerSent(t *testing.T) {
	hostile := []string{
		"\x1b[1A\x1b[2K\x1b]52;c;ZXZpbA==\x07x", // erase the line above, write the clipboard
		"\x1b[8mkeyholder\r",                    // conceal what follows, then overwrite this row
		"key\x9b2Jholder\u202erelso\u009b8m",    // raw C1 CSI, a bidi override, U+009B
	}
	var stats []shrike.TunnelStat
	for _, route := range hostile {
		stats = append(stats, shrike.TunnelStat{
			Role: event.PeerKeeper, Peer: "aaaaaaaaaaaaaaaa", Route: route,
			Refused: 1, Reasons: map[string]int64{event.ReasonUnknownRoute: 1},
		})
	}
	// The row the injected ones would hide: the same keeper's own refusal.
	stats = append(stats, shrike.TunnelStat{
		Role: event.PeerKeeper, Peer: "aaaaaaaaaaaaaaaa", Route: "shrike",
		Refused: 3, Reasons: map[string]int64{event.ReasonRoleRefused: 3},
	})
	// A role, and a reason, are the monitor's word too.
	stats = append(stats, shrike.TunnelStat{
		Role: "operator\x1b[2K", Peer: "bbbbbbbbbbbbbbbb", Route: "keyholder",
		Relayed: 1, Reasons: map[string]int64{"relayed\r": 1},
	})
	// The keeper is one this machine enrolled, so no note follows the table
	// and every line below is the table's own.
	keepers := []config.Keeper{{Device: "laptop", LeafTokens: []string{"aaaaaaaaaaaaaaaa"}}}
	rows := attributeTunnel(stats, keepers, "", time.Now())
	for i, route := range hostile {
		if rows[i].Route != route {
			t.Fatalf("attributeTunnel changed the route %q to %q; --json carries it as it came", route, rows[i].Route)
		}
	}

	var buf bytes.Buffer
	usageResult{Tunnel: rows, TunnelSeparated: true}.writeTunnel(&buf)
	out := buf.String()
	t.Log("\n" + out)
	onlyPrintable(t, "the tunnel table", out)

	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	// A blank line, the title, the header, and one line per row: nothing
	// joined two rows, and nothing split one.
	if want := 3 + len(stats); len(lines) != want {
		t.Fatalf("%d line(s); want %d — a row was joined or split:\n%s", len(lines), want, out)
	}
	header, body := lines[2], lines[3:]
	for i, route := range hostile {
		if !strings.Contains(body[i], strings.Trim(strconv.QuoteToGraphic(route), `"`)) {
			t.Errorf("row %d does not show what the peer sent, quoted: %q", i, body[i])
		}
	}
	if !strings.Contains(body[len(hostile)], "shrike") || !strings.Contains(body[len(hostile)], "role_refused 3") {
		t.Errorf("the keeper's own refusal, after the injected rows, is not printed whole: %q", body[len(hostile)])
	}
	// The columns are measured on what is printed: every row's "last seen"
	// sits under the header's, however long its quoted route.
	col := utf8.RuneCountInString(header[:strings.Index(header, "last seen")])
	for i, l := range body {
		at := strings.Index(l, "—")
		if at < 0 || utf8.RuneCountInString(l[:at]) != col {
			t.Errorf("row %d's last-seen column is not under the header's (rune %d):\n%s\n%s", i, col, header, l)
		}
	}
}
