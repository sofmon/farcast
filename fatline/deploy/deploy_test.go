package deploy

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func sampleConfig() Config {
	return Config{
		Image:         "example/fatline:test",
		CACertPEM:     []byte("CA-PEM"),
		ServerCertPEM: []byte("SRV-CRT"),
		ServerKeyPEM:  []byte("SRV-KEY"),
	}
}

func TestRenderValidation(t *testing.T) {
	cases := map[string]Config{
		"missing image":    {CACertPEM: []byte("x"), ServerCertPEM: []byte("y"), ServerKeyPEM: []byte("z")},
		"missing material": {Image: "img"},
		"unknown carrier":  {Image: "img", Carrier: "Weird", CACertPEM: []byte("x"), ServerCertPEM: []byte("y"), ServerKeyPEM: []byte("z")},
	}
	for name, c := range cases {
		if _, err := Render(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func docsByKind(t *testing.T, out []byte) map[string]map[string]any {
	t.Helper()
	res := map[string]map[string]any{}
	for d := range strings.SplitSeq(string(out), "\n---\n") {
		if strings.TrimSpace(d) == "" {
			continue
		}
		var m map[string]any
		if err := yaml.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("rendered document is not valid YAML: %v\n%s", err, d)
		}
		kind, _ := m["kind"].(string)
		res[kind] = m
	}
	return res
}

func TestRenderDocuments(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	docs := docsByKind(t, out)
	for _, want := range []string{"Namespace", "Secret", "Deployment", "Service"} {
		if _, ok := docs[want]; !ok {
			t.Fatalf("missing %s document; got kinds %v", want, keys(docs))
		}
	}

	// Default carrier is the public load balancer.
	spec, ok := docs["Service"]["spec"].(map[string]any)
	if !ok || spec["type"] != "LoadBalancer" {
		t.Fatalf("service spec=%v, want type LoadBalancer", docs["Service"]["spec"])
	}

	// The Secret round-trips the mTLS material, base64-encoded.
	data, ok := docs["Secret"]["data"].(map[string]any)
	if !ok {
		t.Fatal("secret has no data map")
	}
	if got := b64(t, data["ca.crt"]); got != "CA-PEM" {
		t.Errorf("ca.crt=%q, want CA-PEM", got)
	}
	if got := b64(t, data["server.key"]); got != "SRV-KEY" {
		t.Errorf("server.key=%q, want SRV-KEY", got)
	}
	// The CA *private key* must never be in the workload.
	if _, leaked := data["ca.key"]; leaked {
		t.Error("CA private key must never appear in the rendered Secret")
	}
}

func TestRenderAutopilotCompliant(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"runAsNonRoot: true", "allowPrivilegeEscalation: false", "requests:", "cpu: 100m", "memory: 128Mi", "- ALL"} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered workload missing %q (Autopilot compliance)", want)
		}
	}
	for _, forbidden := range []string{"privileged: true", "hostNetwork"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("workload must not use %q", forbidden)
		}
	}
}

func TestRenderClusterIPCarrier(t *testing.T) {
	c := sampleConfig()
	c.Carrier = CarrierClusterIP
	out, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "type: ClusterIP") {
		t.Fatal("expected a ClusterIP service for the cluster-internal carrier")
	}
}

func b64(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("secret value is not a string: %T", v)
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("secret value is not valid base64: %v", err)
	}
	return string(decoded)
}

func keys(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
