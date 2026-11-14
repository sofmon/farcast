package kube

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// testRSAKey is one RSA-2048 key, made once for every test that needs one.
var testRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

func rsaPKCS8PEM(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(testRSAKey())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func rsaPKCS1PEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testRSAKey())}))
}

func ecPEMs(t *testing.T) (pkcs8, sec1 string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	derEC, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derEC}))
}

// keyJSON renders a key file from fields; a nil value leaves the field out.
func keyJSON(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	m := map[string]any{}
	for k, v := range fields {
		if v != nil {
			m[k] = v
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestServiceAccountJSONIsCheckedExactly is §3.2's parse, mode-free (§10.3):
// it refuses what is not a service-account key with an email and an RSA key,
// and accepts both a Google-shaped and a loopback-shaped key, because where a
// key may go is the pairing's question, not the parser's.
func TestServiceAccountJSONIsCheckedExactly(t *testing.T) {
	pkcs8 := rsaPKCS8PEM(t)
	ecPKCS8, ecSEC1 := ecPEMs(t)
	const googleEmail = "farcast-installer@project-1.iam.gserviceaccount.com"
	google := func(over map[string]any) map[string]any {
		m := map[string]any{
			"type":                        "service_account",
			"project_id":                  "project-1",
			"private_key_id":              "0123abcd",
			"private_key":                 pkcs8,
			"client_email":                googleEmail,
			"client_id":                   "1234567890",
			"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
			"token_uri":                   GoogleTokenURL,
			"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
			"universe_domain":             "googleapis.com",
		}
		for k, v := range over {
			m[k] = v
		}
		return m
	}

	refused := []struct {
		name  string
		body  []byte
		field string
	}{
		{"an authorized_user file", keyJSON(t, google(map[string]any{"type": "authorized_user"})), "type"},
		{"an external_account file", keyJSON(t, google(map[string]any{"type": "external_account"})), "type"},
		{"no type", keyJSON(t, google(map[string]any{"type": nil})), "type"},
		{"a type that is not a string", keyJSON(t, google(map[string]any{"type": 5})), "type"},
		{"an EC key in PKCS#8", keyJSON(t, google(map[string]any{"private_key": ecPKCS8})), "private_key"},
		{"an EC key in SEC 1", keyJSON(t, google(map[string]any{"private_key": ecSEC1})), "private_key"},
		{"a key that is not PEM", keyJSON(t, google(map[string]any{"private_key": "not a key"})), "private_key"},
		{"a PEM block that is not a key", keyJSON(t, google(map[string]any{"private_key": string(testCAPEM())})), "private_key"},
		{"no key", keyJSON(t, google(map[string]any{"private_key": nil})), "private_key"},
		{"no email", keyJSON(t, google(map[string]any{"client_email": nil})), "client_email"},
		{"an email without @", keyJSON(t, google(map[string]any{"client_email": "farcast-installer.iam.gserviceaccount.com"})), "client_email"},
		{"an email with two @", keyJSON(t, google(map[string]any{"client_email": "a@b@iam.gserviceaccount.com"})), "client_email"},
		{"an email without a local part", keyJSON(t, google(map[string]any{"client_email": "@project-1.iam.gserviceaccount.com"})), "client_email"},
		{"an email without a domain", keyJSON(t, google(map[string]any{"client_email": "farcast-installer@"})), "client_email"},
		{"an http token_uri", keyJSON(t, google(map[string]any{"token_uri": "http://oauth2.googleapis.com/token"})), "token_uri"},
		{"a relative token_uri", keyJSON(t, google(map[string]any{"token_uri": "/token"})), "token_uri"},
		{"a token_uri without a scheme", keyJSON(t, google(map[string]any{"token_uri": "oauth2.googleapis.com/token"})), "token_uri"},
		{"a token_uri with no host", keyJSON(t, google(map[string]any{"token_uri": "https:///token"})), "token_uri"},
		{"a body that is not JSON", []byte("type: service_account\n"), "not a JSON object"},
		{"a JSON array", []byte(`[{"type":"service_account"}]`), "not a JSON object"},
		{"trailing data", append(keyJSON(t, google(nil)), []byte(" {}")...), "not a JSON object"},
		{"an empty body", nil, "not a JSON object"},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			c, err := ParseServiceAccountJSON(tc.body)
			if err == nil {
				t.Fatalf("parsed as %+v", c)
			}
			if !errors.Is(err, ErrCredentialInvalid) {
				t.Errorf("error %v does not wrap ErrCredentialInvalid", err)
			}
			if want := fmt.Sprintf(msgCredential, tc.field); err.Error() != want {
				t.Errorf("error = %q, want %q", err.Error(), want)
			}
			for _, secret := range []string{"PRIVATE KEY", "farcast-installer", "0123abcd"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q carries %q", err.Error(), secret)
				}
			}
		})
	}

	accepted := []struct {
		name string
		body []byte
		want Credential
	}{
		{
			name: "a Google key, every field Google writes",
			body: keyJSON(t, google(nil)),
			want: Credential{Email: googleEmail, PrivateKeyID: "0123abcd", PrivateKeyPEM: []byte(pkcs8), TokenURI: GoogleTokenURL, UniverseDomain: "googleapis.com"},
		},
		{
			name: "a Google key without token_uri, universe_domain or key id",
			body: keyJSON(t, google(map[string]any{"token_uri": nil, "universe_domain": nil, "private_key_id": nil})),
			want: Credential{Email: googleEmail, PrivateKeyPEM: []byte(pkcs8)},
		},
		{
			name: "a loopback key, PKCS#1, its token_uri on 127.0.0.1",
			body: keyJSON(t, map[string]any{
				"type":         "service_account",
				"client_email": "writer@kubetest.invalid",
				"private_key":  rsaPKCS1PEM(),
				"token_uri":    "https://127.0.0.1:6443/token",
			}),
			want: Credential{Email: "writer@kubetest.invalid", PrivateKeyPEM: []byte(rsaPKCS1PEM()), TokenURI: "https://127.0.0.1:6443/token"},
		},
		{
			name: "a key whose universe and token endpoint are another's: the pairing refuses it, not the parse",
			body: keyJSON(t, google(map[string]any{"token_uri": "https://evil.example/token", "universe_domain": "example.com"})),
			want: Credential{Email: googleEmail, PrivateKeyID: "0123abcd", PrivateKeyPEM: []byte(pkcs8), TokenURI: "https://evil.example/token", UniverseDomain: "example.com"},
		},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			c, err := ParseServiceAccountJSON(tc.body)
			if err != nil {
				t.Fatalf("ParseServiceAccountJSON: %v", err)
			}
			if c.Email != tc.want.Email || c.PrivateKeyID != tc.want.PrivateKeyID || string(c.PrivateKeyPEM) != string(tc.want.PrivateKeyPEM) ||
				c.TokenURI != tc.want.TokenURI || c.UniverseDomain != tc.want.UniverseDomain {
				t.Errorf("got email %q kid %q token_uri %q universe %q (key %d bytes), want %q %q %q %q (key %d bytes)",
					c.Email, c.PrivateKeyID, c.TokenURI, c.UniverseDomain, len(c.PrivateKeyPEM),
					tc.want.Email, tc.want.PrivateKeyID, tc.want.TokenURI, tc.want.UniverseDomain, len(tc.want.PrivateKeyPEM))
			}
		})
	}
}
