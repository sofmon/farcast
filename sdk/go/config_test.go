package farcast

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestConfigReadsTheEnvironment(t *testing.T) {
	t.Setenv("APP_GREETING", "hello")
	t.Setenv("APP_WORKERS", "12")
	t.Setenv("APP_DEBUG", "true")

	c := Config()
	if v, ok := c.Get("APP_GREETING"); !ok || v != "hello" {
		t.Errorf("Get = (%q, %v), want (hello, true)", v, ok)
	}
	if v := c.GetString("APP_GREETING", "def"); v != "hello" {
		t.Errorf("GetString = %q, want hello", v)
	}
	if v := c.GetInt("APP_WORKERS", 1); v != 12 {
		t.Errorf("GetInt = %d, want 12", v)
	}
	if !c.GetBool("APP_DEBUG", false) {
		t.Error("GetBool = false, want true")
	}
	if v, err := c.Require("APP_GREETING"); err != nil || v != "hello" {
		t.Errorf("Require = (%q, %v), want (hello, nil)", v, err)
	}
}

func TestConfigAbsentKeysFallBackToDefaults(t *testing.T) {
	c := Config()
	if v, ok := c.Get("APP_NOT_SET_ANYWHERE"); ok || v != "" {
		t.Errorf("Get = (%q, %v), want empty/false", v, ok)
	}
	if v := c.GetString("APP_NOT_SET_ANYWHERE", "def"); v != "def" {
		t.Errorf("GetString = %q, want def", v)
	}
	if v := c.GetInt("APP_NOT_SET_ANYWHERE", 7); v != 7 {
		t.Errorf("GetInt = %d, want 7", v)
	}
	if !c.GetBool("APP_NOT_SET_ANYWHERE", true) {
		t.Error("GetBool = false, want the default true")
	}
	_, err := c.Require("APP_NOT_SET_ANYWHERE")
	if !errors.Is(err, ErrConfigMissing) {
		t.Errorf("Require err = %v, want ErrConfigMissing", err)
	}
}

// An empty value is what a mis-rendered template produces. Reading it as
// present would let Require — whose whole job is to catch configuration that
// did not arrive — hand back "" and let the application start on it.
func TestConfigTreatsAnEmptyValueAsAbsent(t *testing.T) {
	t.Setenv("APP_EMPTY", "")

	c := Config()
	if v, ok := c.Get("APP_EMPTY"); ok || v != "" {
		t.Errorf("Get = (%q, %v), want empty/false", v, ok)
	}
	if v := c.GetString("APP_EMPTY", "def"); v != "def" {
		t.Errorf("GetString = %q, want the default", v)
	}
	if _, err := c.Require("APP_EMPTY"); !errors.Is(err, ErrConfigMissing) {
		t.Errorf("Require err = %v, want ErrConfigMissing", err)
	}
}

// The reserved namespace is the load-bearing refusal: one of its entries is
// this application's egress credential, and Config is documented as
// non-secret. A capability that returned it would eventually log it.
func TestConfigRefusesThePlatformNamespace(t *testing.T) {
	t.Setenv("FARCAST_FATLINE_PROXY", "http://app:credential@fatline:3128")
	t.Setenv("FARCAST_APP_NAME", "api")

	c := Config()
	for _, key := range []string{"FARCAST_FATLINE_PROXY", "FARCAST_APP_NAME", "farcast_app_name"} {
		if v, ok := c.Get(key); ok || v != "" {
			t.Errorf("Get(%q) = (%q, %v), want empty/false", key, v, ok)
		}
		if v := c.GetString(key, "def"); v != "def" {
			t.Errorf("GetString(%q) = %q, want the default", key, v)
		}
	}
	_, err := c.Require("FARCAST_FATLINE_PROXY")
	if !errors.Is(err, ErrConfigReserved) {
		t.Errorf("Require err = %v, want ErrConfigReserved", err)
	}
	// Reserved must not read as missing: the variable IS set, and an operator
	// told otherwise would go and set it again.
	if errors.Is(err, ErrConfigMissing) {
		t.Error("a reserved key reported ErrConfigMissing, which would send an operator to set a variable that is already set")
	}
	if err != nil && strings.Contains(err.Error(), "credential") {
		t.Errorf("the refusal quoted the value: %v", err)
	}
}

func TestReservedCoversTheWholeNamespace(t *testing.T) {
	for _, key := range []string{"FARCAST_APP_NAME", "farcast_storage_ca", " FARCAST_X"} {
		if !Reserved(key) {
			t.Errorf("Reserved(%q) = false, want true", key)
		}
	}
	for _, key := range []string{"", "APP_NAME", "MY_FARCAST_THING"} {
		if Reserved(key) {
			t.Errorf("Reserved(%q) = true, want false", key)
		}
	}
}

// Identity has accessors precisely because Config refuses the namespace it
// lives in; without them an application could not learn its own name.
func TestIdentityAccessors(t *testing.T) {
	t.Setenv("FARCAST_APP_NAME", "api")
	t.Setenv("FARCAST_INSTANCE_ID", "prod")
	if got := AppName(); got != "api" {
		t.Errorf("AppName = %q, want api", got)
	}
	if got := InstanceID(); got != "prod" {
		t.Errorf("InstanceID = %q, want prod", got)
	}
}

// A value that is present and unparseable is a misconfiguration. The frozen
// contract says fall back to the default; falling back in silence is what
// makes the typo undiagnosable.
func TestConfigWarnsOnAnUnparseableValue(t *testing.T) {
	var buf bytes.Buffer
	restore := SetLogWriter(&buf)
	defer restore()
	warned.Clear()

	t.Setenv("APP_WORKERS", "eight")
	t.Setenv("APP_DEBUG", "yes-please")

	c := Config()
	if v := c.GetInt("APP_WORKERS", 4); v != 4 {
		t.Errorf("GetInt = %d, want the default 4", v)
	}
	if c.GetBool("APP_DEBUG", false) {
		t.Error("GetBool = true, want the default false")
	}

	out := buf.String()
	for _, want := range []string{"APP_WORKERS", "APP_DEBUG", "an integer", "a boolean"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warnings do not mention %q:\n%s", want, out)
		}
	}
	// The key is named and the value never is: an application's own
	// configuration is its own business, and a warning is not the place to
	// decide somebody's connection string is safe to print.
	for _, leaked := range []string{"eight", "yes-please"} {
		if strings.Contains(out, leaked) {
			t.Errorf("the warning quoted the value %q:\n%s", leaked, out)
		}
	}
}

// One warning per key, not one per call: a bad value is a fact about the
// deployment, and a getter called once per request would otherwise turn it
// into a log flood.
func TestConfigWarnsOncePerKey(t *testing.T) {
	var buf bytes.Buffer
	restore := SetLogWriter(&buf)
	defer restore()
	warned.Clear()

	t.Setenv("APP_TIMEOUT", "soon")
	c := Config()
	for range 5 {
		_ = c.GetInt("APP_TIMEOUT", 30)
	}

	if n := strings.Count(buf.String(), "APP_TIMEOUT"); n != 1 {
		t.Errorf("APP_TIMEOUT warned %d times, want 1:\n%s", n, buf.String())
	}
}

func TestConfigGetIntAndBoolAcceptSurroundingSpace(t *testing.T) {
	t.Setenv("APP_WORKERS", "  12\n")
	t.Setenv("APP_DEBUG", " true ")
	t.Setenv("APP_NAME", " spaced ")

	c := Config()
	if v := c.GetInt("APP_WORKERS", 1); v != 12 {
		t.Errorf("GetInt = %d, want 12", v)
	}
	if !c.GetBool("APP_DEBUG", false) {
		t.Error("GetBool = false, want true")
	}
	// Strings are returned verbatim: whitespace is a transcription artefact
	// when a number was meant and possibly meaningful when a string was.
	if v := c.GetString("APP_NAME", ""); v != " spaced " {
		t.Errorf("GetString = %q, want it verbatim", v)
	}
}

// json.Marshal of a struct carrying config is a normal thing to do; it must
// not become a way to ship the platform's namespace.
func TestConfigIsNotAWayToDumpTheEnvironment(t *testing.T) {
	t.Setenv("FARCAST_STORAGE_CA", "-----BEGIN CERTIFICATE-----")
	c := Config()
	blob, err := json.Marshal(map[string]string{
		"ca": c.GetString("FARCAST_STORAGE_CA", ""),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(blob, []byte("BEGIN CERTIFICATE")) {
		t.Errorf("a reserved value reached a marshalled document: %s", blob)
	}
}
