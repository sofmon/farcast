package parser

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// --- Failure cases: one per validation rule in manifest/README.md ---------

type failureCase struct {
	name    string
	yaml    string
	wantAll []string // all substrings must appear in the joined error
}

func TestParse_ValidationRules(t *testing.T) {
	cases := []failureCase{
		// Rule 1 — malformed YAML.
		{
			name:    "Rule01_MalformedYAML",
			yaml:    "name: my-app\napps: [ - broken",
			wantAll: []string{"yaml:"},
		},
		// Rule 2 — empty document.
		{
			name:    "Rule02_EmptyDocument",
			yaml:    "\n   \n# just a comment\n",
			wantAll: []string{"empty"},
		},
		// Rule 3 — unknown top-level key.
		{
			name: "Rule03_UnknownTopLevelKey",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
extra: nope
`,
			wantAll: []string{"extra"},
		},
		// Rule 4 — name missing.
		{
			name: "Rule04_NameMissing",
			yaml: `apps:
  - name: server
    containerfile: ./Containerfile
`,
			wantAll: []string{"name", "required"},
		},
		// Rule 5 — name not a string.
		{
			name: "Rule05_NameNotString",
			yaml: `name: 42
apps:
  - name: server
    containerfile: ./Containerfile
`,
			wantAll: []string{"name"},
		},
		// Rule 6 — name empty.
		{
			name: "Rule06_NameEmpty",
			yaml: `name: ""
apps:
  - name: server
    containerfile: ./Containerfile
`,
			wantAll: []string{"name", "empty"},
		},
		// Rule 7 — name contains invalid chars.
		{
			name: "Rule07_NameInvalidChars",
			yaml: `name: My_App
apps:
  - name: server
    containerfile: ./Containerfile
`,
			wantAll: []string{"name"},
		},
		// Rule 8 — name does not start with a letter.
		{
			name: "Rule08_NameStartsWithDigit",
			yaml: `name: 1service
apps:
  - name: server
    containerfile: ./Containerfile
`,
			wantAll: []string{"name", "lowercase letter"},
		},
		// Rule 9 — name ends with hyphen.
		{
			name: "Rule09_NameTrailingHyphen",
			yaml: `name: my-app-
apps:
  - name: server
    containerfile: ./Containerfile
`,
			wantAll: []string{"name", "hyphen"},
		},
		// Rule 10 — name longer than 63 chars.
		{
			name: "Rule10_NameTooLong",
			yaml: "name: " + strings.Repeat("a", 64) + `
apps:
  - name: server
    containerfile: ./Containerfile
`,
			wantAll: []string{"name", "63"},
		},
		// Rule 11 — apps missing.
		{
			name:    "Rule11_AppsMissing",
			yaml:    `name: my-app`,
			wantAll: []string{"apps", "required"},
		},
		// Rule 12 — apps not a list.
		{
			name: "Rule12_AppsNotList",
			yaml: `name: my-app
apps: "server"
`,
			wantAll: []string{"apps"},
		},
		// Rule 13 — apps empty list.
		{
			name: "Rule13_AppsEmptyList",
			yaml: `name: my-app
apps: []
`,
			wantAll: []string{"apps", "at least one"},
		},
		// Rule 14 — duplicate app names.
		{
			name: "Rule14_DuplicateAppName",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./a/Containerfile
  - name: server
    containerfile: ./b/Containerfile
`,
			wantAll: []string{"duplicate app name", `"server"`},
		},
		// Rule 15 — app entry not a mapping.
		{
			name: "Rule15_AppNotMapping",
			yaml: `name: my-app
apps:
  - "just a string"
`,
			wantAll: []string{"apps"},
		},
		// Rule 16 — unknown per-app key.
		{
			name: "Rule16_UnknownAppKey",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    ports: [8080]
`,
			wantAll: []string{"ports"},
		},
		// Rule 17 — app name invalid (missing).
		{
			name: "Rule17_AppNameMissing",
			yaml: `name: my-app
apps:
  - containerfile: ./Containerfile
`,
			wantAll: []string{"apps[0].name", "required"},
		},
		// Rule 18 — containerfile missing.
		{
			name: "Rule18_ContainerfileMissing",
			yaml: `name: my-app
apps:
  - name: server
`,
			wantAll: []string{"apps[0].containerfile", "required"},
		},
		// Rule 19 — containerfile absolute path.
		{
			name: "Rule19_ContainerfileAbsolute",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: /etc/Containerfile
`,
			wantAll: []string{"apps[0].containerfile", "relative"},
		},
		// Rule 20 — containerfile contains "..".
		{
			name: "Rule20_ContainerfileDotDot",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./services/../Containerfile
`,
			wantAll: []string{"apps[0].containerfile", ".."},
		},
		// Rule 21 — context empty.
		{
			name: "Rule21_ContextEmpty",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    context: ""
`,
			wantAll: []string{"apps[0].context", "empty"},
		},
		// Rule 22 — context absolute.
		{
			name: "Rule22_ContextAbsolute",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    context: /opt/build
`,
			wantAll: []string{"apps[0].context", "relative"},
		},
		// Rule 23 — context contains "..".
		{
			name: "Rule23_ContextDotDot",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    context: ../shared
`,
			wantAll: []string{"apps[0].context", ".."},
		},
		// Rule 24 — external not a list.
		{
			name: "Rule24_ExternalNotList",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external: "api.stripe.com"
`,
			wantAll: []string{"external"},
		},
		// Rule 25 — external entry not a mapping.
		{
			name: "Rule25_ExternalEntryNotMapping",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - "api.stripe.com"
`,
			wantAll: []string{"external"},
		},
		// Rule 26 — unknown per-external key.
		{
			name: "Rule26_UnknownExternalKey",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: api.stripe.com
        reason: Payments
        port: 443
`,
			wantAll: []string{"port"},
		},
		// Rule 27 — host missing.
		{
			name: "Rule27_HostMissing",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - reason: Payments
`,
			wantAll: []string{"external[0].host", "required"},
		},
		// Rule 28 — host not a valid DNS hostname.
		{
			name: "Rule28_HostInvalid",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: "https://api.stripe.com"
        reason: Payments
`,
			wantAll: []string{"external[0].host", "scheme"},
		},
		// Rule 29 — reason empty.
		{
			name: "Rule29_ReasonEmpty",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: api.stripe.com
        reason: ""
`,
			wantAll: []string{"external[0].reason", "empty"},
		},
		// Rule 30 — duplicate host within a single app.
		{
			name: "Rule30_DuplicateExternalHostWithinApp",
			yaml: `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: api.stripe.com
        reason: Payments
      - host: api.stripe.com
        reason: Payouts
`,
			wantAll: []string{"duplicate host", "api.stripe.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error, got nil manifest=%+v", m)
			}
			if m != nil {
				t.Fatalf("expected nil manifest on error, got %+v", m)
			}
			if !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("expected errors.Is(err, ErrInvalidManifest) to be true, got err=%v", err)
			}
			msg := err.Error()
			for _, want := range tc.wantAll {
				if !strings.Contains(msg, want) {
					t.Errorf("error message %q does not contain %q", msg, want)
				}
			}
		})
	}
}

// --- Aggregation: one manifest trips several rules at once ----------------

func TestParse_AggregatesMultipleErrors(t *testing.T) {
	y := `name: Bad_Name
apps:
  - name: server
    containerfile: /abs/Containerfile
    external:
      - host: "https://evil.example.com"
        reason: ""
`
	_, err := Parse([]byte(y))
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	wants := []string{
		"name",                       // top-level bad name
		"apps[0].containerfile",      // absolute path
		"apps[0].external[0].host",   // scheme
		"apps[0].external[0].reason", // empty
	}
	for _, w := range wants {
		if !strings.Contains(msg, w) {
			t.Errorf("aggregated error missing %q; full message:\n%s", w, msg)
		}
	}
}

// --- Happy-path: minimal manifest -----------------------------------------

func TestParse_MinimalSingleApp(t *testing.T) {
	y := `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
`
	m, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Name != "my-app" {
		t.Errorf("name = %q, want my-app", m.Name)
	}
	if len(m.Apps) != 1 {
		t.Fatalf("apps len = %d, want 1", len(m.Apps))
	}
	if m.Apps[0].Name != "server" {
		t.Errorf("apps[0].name = %q, want server", m.Apps[0].Name)
	}
	if m.Apps[0].Containerfile != "./Containerfile" {
		t.Errorf("apps[0].containerfile = %q, want ./Containerfile", m.Apps[0].Containerfile)
	}
	if m.Apps[0].Context != "" {
		t.Errorf("apps[0].context = %q, want empty", m.Apps[0].Context)
	}
	if m.Apps[0].External != nil {
		t.Errorf("apps[0].external = %v, want nil", m.Apps[0].External)
	}
}

func TestParse_SingleAppWithExternal(t *testing.T) {
	y := `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: api.stripe.com
        reason: Payment processing
      - host: smtp.mailgun.org
        reason: Transactional email delivery
`
	m, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Apps[0].External) != 2 {
		t.Fatalf("external len = %d, want 2", len(m.Apps[0].External))
	}
	if m.Apps[0].External[0].Host != "api.stripe.com" {
		t.Errorf("external[0].host = %q", m.Apps[0].External[0].Host)
	}
}

func TestParse_Monorepo(t *testing.T) {
	y := `name: my-platform
apps:
  - name: api
    containerfile: ./services/api/Containerfile
    context: .
    external:
      - host: api.stripe.com
        reason: Payment processing
  - name: worker
    containerfile: ./services/worker/Containerfile
    context: .
  - name: web
    containerfile: ./services/web/Containerfile
`
	m, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Apps) != 3 {
		t.Fatalf("apps len = %d, want 3", len(m.Apps))
	}
	if m.Apps[0].Context != "." {
		t.Errorf("apps[0].context = %q, want .", m.Apps[0].Context)
	}
	if m.Apps[2].Context != "" {
		t.Errorf("apps[2].context = %q, want empty", m.Apps[2].Context)
	}
}

// Same host in two different apps is allowed — each app has its own
// independent allowlist.
func TestParse_SameHostAcrossDifferentApps(t *testing.T) {
	y := `name: my-platform
apps:
  - name: api
    containerfile: ./a/Containerfile
    external:
      - host: api.stripe.com
        reason: Payments from api
  - name: worker
    containerfile: ./b/Containerfile
    external:
      - host: api.stripe.com
        reason: Payments from worker
`
	if _, err := Parse([]byte(y)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Empty external list is permitted — it is equivalent to omitting external.
func TestParse_EmptyExternalList(t *testing.T) {
	y := `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external: []
`
	m, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Apps[0].External) != 0 {
		t.Errorf("external len = %d, want 0", len(m.Apps[0].External))
	}
}

// --- Edge cases -----------------------------------------------------------

func TestParse_NameBoundaryLengths(t *testing.T) {
	// 63 chars: valid.
	n63 := "a" + strings.Repeat("b", 62)
	if len(n63) != 63 {
		t.Fatal("precondition")
	}
	y := "name: " + n63 + "\napps:\n  - name: server\n    containerfile: ./Containerfile\n"
	if _, err := Parse([]byte(y)); err != nil {
		t.Errorf("63-char name should be valid, got %v", err)
	}

	// 64 chars: invalid.
	n64 := n63 + "c"
	y = "name: " + n64 + "\napps:\n  - name: server\n    containerfile: ./Containerfile\n"
	if _, err := Parse([]byte(y)); err == nil {
		t.Error("64-char name should be invalid")
	}
}

func TestParse_SingleCharacterName(t *testing.T) {
	y := `name: a
apps:
  - name: b
    containerfile: ./Containerfile
`
	if _, err := Parse([]byte(y)); err != nil {
		t.Errorf("single-character names should be valid, got %v", err)
	}
}

func TestParse_BOMAndCRLF(t *testing.T) {
	// UTF-8 BOM + CRLF line endings.
	y := "\uFEFFname: my-app\r\napps:\r\n  - name: server\r\n    containerfile: ./Containerfile\r\n"
	if _, err := Parse([]byte(y)); err != nil {
		t.Errorf("BOM + CRLF should parse, got %v", err)
	}
}

func TestParse_UnicodeReason(t *testing.T) {
	y := `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: api.stripe.com
        reason: "支付处理 — payments"
`
	m, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(m.Apps[0].External[0].Reason, "支付") {
		t.Errorf("reason not preserved: %q", m.Apps[0].External[0].Reason)
	}
}

func TestParse_HostIsIPAddress(t *testing.T) {
	y := `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: 127.0.0.1
        reason: Local
`
	_, err := Parse([]byte(y))
	if err == nil || !strings.Contains(err.Error(), "IP") {
		t.Errorf("expected IP-rejection error, got %v", err)
	}
}

func TestParse_HostLocalhost(t *testing.T) {
	y := `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: localhost
        reason: Local
`
	if _, err := Parse([]byte(y)); err != nil {
		t.Errorf("localhost should be a valid hostname, got %v", err)
	}
}

func TestParse_HostWildcardRejected(t *testing.T) {
	y := `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: "*.stripe.com"
        reason: Any stripe subdomain
`
	_, err := Parse([]byte(y))
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Errorf("expected wildcard rejection, got %v", err)
	}
}

func TestParse_HostWithPortRejected(t *testing.T) {
	y := `name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: api.stripe.com:443
        reason: Payments
`
	if _, err := Parse([]byte(y)); err == nil {
		t.Error("host with port should be rejected")
	}
}

// --- Example-manifest round-trip ------------------------------------------

func TestParseFile_Examples(t *testing.T) {
	cases := []struct {
		path     string
		wantName string
		wantApps int
	}{
		{"../examples/single-app/farcast", "my-app", 1},
		{"../examples/single-app-with-external/farcast", "my-app", 1},
		{"../examples/monorepo/farcast", "my-platform", 3},
	}
	for _, tc := range cases {
		t.Run(filepath.Base(filepath.Dir(tc.path)), func(t *testing.T) {
			m, err := ParseFile(tc.path)
			if err != nil {
				t.Fatalf("ParseFile(%s) failed: %v", tc.path, err)
			}
			if m.Name != tc.wantName {
				t.Errorf("name = %q, want %q", m.Name, tc.wantName)
			}
			if len(m.Apps) != tc.wantApps {
				t.Errorf("apps len = %d, want %d", len(m.Apps), tc.wantApps)
			}
		})
	}
}

func TestParseFile_NotFound(t *testing.T) {
	_, err := ParseFile("../examples/does-not-exist/farcast")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
