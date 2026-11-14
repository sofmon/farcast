package kube

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCAPEM is one self-signed P-256 CA certificate, made once.
var testCAPEM = sync.OnceValue(func() []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kube test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
})

// TestParseEndpoint is §3.1's rule on its own, every accepted and refused
// form, each refusal asserted by its whole message. The pairing with a
// credential, and the zero dials, are TestEndpointRule's (§10.3).
func TestParseEndpoint(t *testing.T) {
	const region = "us-central1"
	ca := testCAPEM()
	noCert := []byte("this file holds no certificate\n")
	longLabel := strings.Repeat("a", 64) + ".us-central1.gke.goog"

	type accepted struct {
		mode              Mode
		host, port        string
		baseURL, tokenURL string
	}
	cases := []struct {
		name     string
		recorded string
		region   string // region when empty
		caPEM    []byte
		want     *accepted
		wantMsg  string
	}{
		// Accepted, Google.
		{name: "google", recorded: "uid.us-central1.gke.goog",
			want: &accepted{ModeGoogle, "uid.us-central1.gke.goog", "443", "https://uid.us-central1.gke.goog", GoogleTokenURL}},
		{name: "google with port 443", recorded: "uid.us-central1.gke.goog:443",
			want: &accepted{ModeGoogle, "uid.us-central1.gke.goog", "443", "https://uid.us-central1.gke.goog", GoogleTokenURL}},
		{name: "google is lower-cased", recorded: "UID.US-Central1.GKE.goog",
			want: &accepted{ModeGoogle, "uid.us-central1.gke.goog", "443", "https://uid.us-central1.gke.goog", GoogleTokenURL}},
		{name: "the region is compared lower-cased", recorded: "uid.us-central1.gke.goog", region: "US-CENTRAL1",
			want: &accepted{ModeGoogle, "uid.us-central1.gke.goog", "443", "https://uid.us-central1.gke.goog", GoogleTokenURL}},
		{name: "google, the region deeper", recorded: "gke-0123.a.us-central1.gke.goog",
			want: &accepted{ModeGoogle, "gke-0123.a.us-central1.gke.goog", "443", "https://gke-0123.a.us-central1.gke.goog", GoogleTokenURL}},

		// Accepted, loopback.
		{name: "loopback v4", recorded: "127.0.0.1:6443", caPEM: ca,
			want: &accepted{ModeLoopback, "127.0.0.1", "6443", "https://127.0.0.1:6443", "https://127.0.0.1:6443/token"}},
		{name: "loopback v6", recorded: "[::1]:6443", caPEM: ca,
			want: &accepted{ModeLoopback, "::1", "6443", "https://[::1]:6443", "https://[::1]:6443/token"}},
		{name: "anywhere in 127/8", recorded: "127.4.5.6:1", caPEM: ca,
			want: &accepted{ModeLoopback, "127.4.5.6", "1", "https://127.4.5.6:1", "https://127.4.5.6:1/token"}},
		{name: "the highest port", recorded: "127.0.0.1:65535", caPEM: ca,
			want: &accepted{ModeLoopback, "127.0.0.1", "65535", "https://127.0.0.1:65535", "https://127.0.0.1:65535/token"}},
		{name: "a loopback endpoint ignores the region", recorded: "127.0.0.1:6443", region: "europe-west1", caPEM: ca,
			want: &accepted{ModeLoopback, "127.0.0.1", "6443", "https://127.0.0.1:6443", "https://127.0.0.1:6443/token"}},

		// E-shape.
		{name: "empty", recorded: "", wantMsg: fmt.Sprintf(msgShape, "")},
		{name: "localhost", recorded: "localhost:6443", caPEM: ca, wantMsg: fmt.Sprintf(msgShape, "localhost:6443")},
		{name: "localhost without a port", recorded: "localhost", caPEM: ca, wantMsg: fmt.Sprintf(msgShape, "localhost")},
		{name: "another domain", recorded: "evil.example", wantMsg: fmt.Sprintf(msgShape, "evil.example")},
		{name: "gke.goog alone", recorded: "gke.goog", wantMsg: fmt.Sprintf(msgShape, "gke.goog")},
		{name: "gke.goog not at the end", recorded: "a.gke.goog.evil.example", wantMsg: fmt.Sprintf(msgShape, "a.gke.goog.evil.example")},
		{name: "gke.goog as a suffix of a label", recorded: "agke.goog", wantMsg: fmt.Sprintf(msgShape, "agke.goog")},
		{name: "a trailing dot", recorded: "uid.us-central1.gke.goog.", wantMsg: fmt.Sprintf(msgShape, "uid.us-central1.gke.goog.")},
		{name: "a trailing dot before the port", recorded: "uid.us-central1.gke.goog.:443", wantMsg: fmt.Sprintf(msgShape, "uid.us-central1.gke.goog.:443")},
		{name: "a scheme", recorded: "https://uid.us-central1.gke.goog", wantMsg: fmt.Sprintf(msgShape, "https://uid.us-central1.gke.goog")},
		{name: "a path", recorded: "uid.us-central1.gke.goog/api", wantMsg: fmt.Sprintf(msgShape, "uid.us-central1.gke.goog/api")},
		{name: "a query", recorded: "uid.us-central1.gke.goog?x=1", wantMsg: fmt.Sprintf(msgShape, "uid.us-central1.gke.goog?x=1")},
		{name: "a fragment", recorded: "uid.us-central1.gke.goog#x", wantMsg: fmt.Sprintf(msgShape, "uid.us-central1.gke.goog#x")},
		{name: "user info", recorded: "u@uid.us-central1.gke.goog", wantMsg: fmt.Sprintf(msgShape, "u@uid.us-central1.gke.goog")},
		{name: "whitespace", recorded: " uid.us-central1.gke.goog", wantMsg: fmt.Sprintf(msgShape, " uid.us-central1.gke.goog")},
		{name: "a label of 64 characters", recorded: longLabel, wantMsg: fmt.Sprintf(msgShape, longLabel)},
		{name: "a label of 63 characters", recorded: longLabel[1:],
			want: &accepted{ModeGoogle, longLabel[1:], "443", "https://" + longLabel[1:], GoogleTokenURL}},
		{name: "an underscore", recorded: "u_id.us-central1.gke.goog", wantMsg: fmt.Sprintf(msgShape, "u_id.us-central1.gke.goog")},
		{name: "a bare IPv6 mapped literal", recorded: "::ffff:127.0.0.1", caPEM: ca, wantMsg: fmt.Sprintf(msgShape, "::ffff:127.0.0.1")},
		{name: "a bare ::1", recorded: "::1", caPEM: ca, wantMsg: fmt.Sprintf(msgShape, "::1")},
		{name: "[::1] without a port", recorded: "[::1]", caPEM: ca, wantMsg: fmt.Sprintf(msgShape, "[::1]")},
		{name: "a bracketed IPv4 literal", recorded: "[127.0.0.1]:6443", caPEM: ca, wantMsg: fmt.Sprintf(msgShape, "[127.0.0.1]:6443")},
		{name: "a bracketed name", recorded: "[uid.us-central1.gke.goog]:443", wantMsg: fmt.Sprintf(msgShape, "[uid.us-central1.gke.goog]:443")},
		{name: "text after the brackets' port", recorded: "[::1]:6443]", caPEM: ca, wantMsg: fmt.Sprintf(msgShape, "[::1]:6443]")},

		// E-mapped.
		{name: "an IPv4-mapped loopback", recorded: "[::ffff:127.0.0.1]:6443", caPEM: ca, wantMsg: fmt.Sprintf(msgMapped, "[::ffff:127.0.0.1]:6443")},

		// E-range.
		{name: "a private address, no CA", recorded: "10.0.0.5:443", wantMsg: fmt.Sprintf(msgRange, "10.0.0.5:443")},
		{name: "a private address, with a CA", recorded: "10.0.0.5:443", caPEM: ca, wantMsg: fmt.Sprintf(msgRange, "10.0.0.5:443")},
		{name: "just past 127/8", recorded: "128.0.0.1:6443", caPEM: ca, wantMsg: fmt.Sprintf(msgRange, "128.0.0.1:6443")},
		{name: "the unspecified address", recorded: "0.0.0.0:6443", caPEM: ca, wantMsg: fmt.Sprintf(msgRange, "0.0.0.0:6443")},
		{name: "::2", recorded: "[::2]:6443", caPEM: ca, wantMsg: fmt.Sprintf(msgRange, "[::2]:6443")},
		{name: "::1 with a zone", recorded: "[::1%lo0]:6443", caPEM: ca, wantMsg: fmt.Sprintf(msgRange, "[::1%lo0]:6443")},

		// E-port.
		{name: "loopback without a port", recorded: "127.0.0.1", caPEM: ca, wantMsg: fmt.Sprintf(msgPort, "127.0.0.1", "")},
		{name: "loopback with an empty port", recorded: "127.0.0.1:", caPEM: ca, wantMsg: fmt.Sprintf(msgPort, "127.0.0.1:", "")},
		{name: "loopback port 0", recorded: "127.0.0.1:0", caPEM: ca, wantMsg: fmt.Sprintf(msgPort, "127.0.0.1:0", "0")},
		{name: "loopback port past 65535", recorded: "127.0.0.1:65536", caPEM: ca, wantMsg: fmt.Sprintf(msgPort, "127.0.0.1:65536", "65536")},
		{name: "a leading zero", recorded: "127.0.0.1:06443", caPEM: ca, wantMsg: fmt.Sprintf(msgPort, "127.0.0.1:06443", "06443")},
		{name: "a sign", recorded: "127.0.0.1:+6443", caPEM: ca, wantMsg: fmt.Sprintf(msgPort, "127.0.0.1:+6443", "+6443")},
		{name: "a named port", recorded: "127.0.0.1:https", caPEM: ca, wantMsg: fmt.Sprintf(msgPort, "127.0.0.1:https", "https")},
		{name: "[::1] with an empty port", recorded: "[::1]:", caPEM: ca, wantMsg: fmt.Sprintf(msgPort, "[::1]:", "")},
		{name: "google on another port", recorded: "uid.us-central1.gke.goog:8443", wantMsg: fmt.Sprintf(msgPort, "uid.us-central1.gke.goog:8443", "8443")},
		{name: "google with an empty port", recorded: "uid.us-central1.gke.goog:", wantMsg: fmt.Sprintf(msgPort, "uid.us-central1.gke.goog:", "")},

		// E-region.
		{name: "another region", recorded: "uid.europe-west1.gke.goog", wantMsg: fmt.Sprintf(msgRegion, "uid.europe-west1.gke.goog", region)},
		{name: "the region as the first label only", recorded: "us-central1.gke.goog", wantMsg: fmt.Sprintf(msgRegion, "us-central1.gke.goog", region)},
		{name: "a zone, not the region", recorded: "uid.us-central1-c.gke.goog", wantMsg: fmt.Sprintf(msgRegion, "uid.us-central1-c.gke.goog", region)},
		{name: "no region recorded", recorded: "uid.us-central1.gke.goog", region: "-", wantMsg: fmt.Sprintf(msgRegion, "uid.us-central1.gke.goog", "")},

		// E-googleCA.
		{name: "google with a CA file", recorded: "uid.us-central1.gke.goog", caPEM: ca, wantMsg: fmt.Sprintf(msgGoogleCA, "uid.us-central1.gke.goog", "cluster-ca.crt")},
		{name: "google with an empty CA file", recorded: "uid.us-central1.gke.goog", caPEM: []byte{}, wantMsg: fmt.Sprintf(msgGoogleCA, "uid.us-central1.gke.goog", "cluster-ca.crt")},

		// E-noCA and E-noCert.
		{name: "loopback without a CA file", recorded: "127.0.0.1:6443", wantMsg: fmt.Sprintf(msgNoCA, "127.0.0.1:6443")},
		{name: "loopback v6 without a CA file", recorded: "[::1]:6443", wantMsg: fmt.Sprintf(msgNoCA, "[::1]:6443")},
		{name: "a CA file with no certificate", recorded: "127.0.0.1:6443", caPEM: noCert, wantMsg: "cluster-ca.crt holds no certificate"},
		{name: "an empty CA file", recorded: "127.0.0.1:6443", caPEM: []byte{}, wantMsg: "cluster-ca.crt holds no certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := region
			switch tc.region {
			case "":
			case "-":
				r = ""
			default:
				r = tc.region
			}
			ep, err := ParseEndpoint(tc.recorded, r, tc.caPEM)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("ParseEndpoint(%q) accepted it as %+v", tc.recorded, ep)
				}
				if !errors.Is(err, ErrEndpointRefused) {
					t.Errorf("error %v does not wrap ErrEndpointRefused", err)
				}
				if err.Error() != tc.wantMsg {
					t.Errorf("error = %q\nwant    %q", err.Error(), tc.wantMsg)
				}
				if ep != (Endpoint{}) {
					t.Errorf("a refusal returned a non-zero Endpoint %+v", ep)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEndpoint(%q): %v", tc.recorded, err)
			}
			if ep.Mode != tc.want.mode || ep.Host != tc.want.host || ep.Port != tc.want.port {
				t.Errorf("got mode %v host %q port %q, want %v %q %q", ep.Mode, ep.Host, ep.Port, tc.want.mode, tc.want.host, tc.want.port)
			}
			if got := ep.BaseURL(); got != tc.want.baseURL {
				t.Errorf("BaseURL() = %q, want %q", got, tc.want.baseURL)
			}
			if got := ep.TokenURL(); got != tc.want.tokenURL {
				t.Errorf("TokenURL() = %q, want %q", got, tc.want.tokenURL)
			}
			switch ep.Mode {
			case ModeGoogle:
				if ep.CA != nil {
					t.Error("a Google endpoint carries a CA pool; it must trust the system roots alone")
				}
			case ModeLoopback:
				if ep.CA == nil {
					t.Error("a loopback endpoint carries no CA pool")
				}
			}
		})
	}
}

// TestZeroEndpointNamesNoURL: an Endpoint ParseEndpoint did not make names
// nowhere to dial.
func TestZeroEndpointNamesNoURL(t *testing.T) {
	var e Endpoint
	if e.BaseURL() != "" || e.TokenURL() != "" {
		t.Errorf("zero Endpoint: BaseURL %q TokenURL %q, want both empty", e.BaseURL(), e.TokenURL())
	}
	if ModeGoogle.String() != "Google" || ModeLoopback.String() != "loopback" || Mode(0).String() != "unknown" {
		t.Errorf("mode names: %q %q %q", ModeGoogle, ModeLoopback, Mode(0))
	}
}
