package translate

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/fatline/policy"
)

// secretData decodes a rendered Secret's data: the bytes each value carries,
// which is what the container reads.
func secretData(t *testing.T, docs []map[string]any, name string) map[string]string {
	t.Helper()
	raw, ok := at(t, pick(t, docs, "Secret", name), "data").(map[string]any)
	if !ok {
		t.Fatalf("%s: data is not a map", name)
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("%s: data.%s is a %T, not a string", name, k, v)
		}
		b, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil {
			t.Fatalf("%s: data.%s is not standard base64: %v", name, k, err)
		}
		out[k] = string(b)
	}
	return out
}

var stringDataKey = regexp.MustCompile(`(?m)^[ \t]*["']?stringData["']?[ \t]*:`)

// Server-side apply cannot own a Secret's stringData: the API server folds it
// into data on every write and never returns it, so the field a manager
// applied is never the field it reads back. Kubernetes says so in as many
// words, and ADR 0023 decision 2 renders data: only.
func TestEgressSecretCarriesDataNotStringData(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  func() Config
		keys []string
	}{
		{"storage wired", sampleConfig, []string{"FARCAST_FATLINE_PROXY", "FARCAST_STORAGE_CLIENT_CERT", "FARCAST_STORAGE_CLIENT_KEY"}},
		{"no storage", func() Config {
			c := sampleConfig()
			c.Storage, c.StorageCAPEM = nil, nil
			return c
		}, []string{"FARCAST_FATLINE_PROXY"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, docs := render(t, tc.cfg())
			// The template's comment quotes Kubernetes, so the word is there;
			// no line may use it as a key.
			if stringDataKey.MatchString(out) {
				t.Error("the stream still carries a stringData key")
			}
			for _, app := range []string{"api", "web"} {
				secret := pick(t, docs, "Secret", app+"-egress")
				if _, ok := secret["stringData"]; ok {
					t.Errorf("%s-egress carries stringData", app)
				}
				data := secretData(t, docs, app+"-egress")
				if len(data) != len(tc.keys) {
					t.Errorf("%s-egress carries %d keys, want %d: %v", app, len(data), len(tc.keys), tc.keys)
				}
				for _, k := range tc.keys {
					if _, ok := data[k]; !ok {
						t.Errorf("%s-egress has no data.%s", app, k)
					}
				}
			}
		})
	}
}

// todaysValue is what the egress Secret gave the application while it was
// rendered as stringData: the PEM laid out by indentPEM under a "|" block
// scalar, read back by a YAML reader. data: must decode to exactly these
// bytes, or every running application would see its identity change shape on
// the next deploy.
func todaysValue(t *testing.T, pem []byte) string {
	t.Helper()
	var m map[string]string
	if err := yaml.Unmarshal([]byte("v: |\n"+indentPEM(pem)+"\n"), &m); err != nil {
		t.Fatal(err)
	}
	return m["v"]
}

func TestEgressSecretDataDecodesToTodaysValues(t *testing.T) {
	c := sampleConfig()
	// One PEM with no final newline, one with one, one with several: each
	// reads as the PEM with exactly one.
	c.Storage["api"] = AppStorage{
		CertPEM: []byte("-----BEGIN CERTIFICATE-----\nAPILEAF\n-----END CERTIFICATE-----\n"),
		KeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\nAPIKEY\n-----END PRIVATE KEY-----\n\n\n"),
		Scope:   "app-my-platform-api", SecretsPrefix: "app/my-platform/api/secrets/",
	}
	_, docs := render(t, c)

	for _, app := range []string{"api", "web"} {
		data := secretData(t, docs, app+"-egress")

		wantProxy := policy.ProxyURL("http", FatLineService+"."+SystemNamespace+".svc.cluster.local",
			FatLineEgressPort, app, c.Credentials[app])
		if got := data["FARCAST_FATLINE_PROXY"]; got != wantProxy {
			t.Errorf("%s: FARCAST_FATLINE_PROXY = %q, want %q", app, got, wantProxy)
		}

		st := c.Storage[app]
		for key, pem := range map[string][]byte{
			"FARCAST_STORAGE_CLIENT_CERT": st.CertPEM,
			"FARCAST_STORAGE_CLIENT_KEY":  st.KeyPEM,
		} {
			want := strings.TrimRight(string(pem), "\n") + "\n"
			if got := data[key]; got != want {
				t.Errorf("%s: %s = %q, want %q", app, key, got, want)
			}
			if got, block := data[key], todaysValue(t, pem); got != block {
				t.Errorf("%s: %s = %q, but the stringData block scalar read %q", app, key, got, block)
			}
		}
	}
}
