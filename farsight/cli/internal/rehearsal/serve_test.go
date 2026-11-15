package rehearsal

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// A18-7 and A18-18, mutation O40: the rig's cluster keeps no request log. A
// rehearsal serves for up to 25 days, and every /token body holds a signed
// assertion, so nothing it was sent stays in its memory: kubetest's Requests
// is nil after an API request and a /token request were answered, and each
// answer reached calls.log, which is written from what was answered, never
// with a body.
func TestTheRigsClusterKeepsNoRequestLog(t *testing.T) {
	rig, err := Start(t.Context(), Options{Dir: filepath.Join(t.TempDir(), "r"), Home: t.TempDir()})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := rig.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if rig.cluster == nil {
		t.Fatal("the rig holds no handle on its cluster")
	}
	ca, ok, err := config.Dir(rig.ConfigDir).LoadClusterCA(rig.spec.Instance)
	if err != nil || !ok {
		t.Fatalf("the rig's cluster CA: %v, %v", ok, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("the rig's cluster CA does not parse")
	}
	logged := func() int {
		data, _ := os.ReadFile(filepath.Join(rig.Dir, callsLog))
		return strings.Count(string(data), "\n")
	}
	before := logged()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	for _, req := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/namespaces", ""},
		{http.MethodPost, "/token", "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=not.a.jwt"},
	} {
		r, err := http.NewRequestWithContext(t.Context(), req.method, "https://"+rig.ClusterAddr+req.path, strings.NewReader(req.body))
		if err != nil {
			t.Fatal(err)
		}
		if req.body != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatalf("%s %s: %v", req.method, req.path, err)
		}
		_ = resp.Body.Close()
	}
	deadline := time.Now().Add(10 * time.Second)
	for logged()-before < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := logged() - before; n != 2 {
		t.Fatalf("calls.log gained %d answers, want the 2 sent", n)
	}
	if reqs := rig.cluster.Requests(); reqs != nil {
		t.Errorf("the rig's cluster kept %d requests", len(reqs))
	}
}
