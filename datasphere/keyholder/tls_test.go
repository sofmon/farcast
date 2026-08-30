package keyholder

import "testing"

func TestAllowPusher(t *testing.T) {
	allow := AllowPusher("prod")

	allowed := []string{
		"farcast://prod/operator",
		"farcast://prod/keeper/laptop",
		"farcast://prod/keeper/phone-2",
	}
	for _, uri := range allowed {
		if !allow(uri) {
			t.Errorf("AllowPusher refused %q", uri)
		}
	}

	refused := []string{
		"",
		"farcast://prod/keeper/",          // unnamed: could not be revoked alone
		"farcast://prod/keeper",           // not a device
		"farcast://staging/operator",      // another instance
		"farcast://staging/keeper/laptop", // another instance's keeper
		"farcast://prod/app/web",          // an application
		"farcast://prod/operator/extra",   // not the operator identity
		"farcast://prodx/operator",        // prefix confusion
		"https://prod/operator",           // wrong scheme
		"farcast://prod/OPERATOR",         // case matters
	}
	for _, uri := range refused {
		if allow(uri) {
			t.Errorf("AllowPusher accepted %q", uri)
		}
	}
}

func TestLoadTLSErrorsDoNotEchoMaterial(t *testing.T) {
	key := "-----BEGIN PRIVATE KEY-----\nSUPERSECRETKEYBYTES\n-----END PRIVATE KEY-----"
	_, err := LoadTLS([]byte("not a cert"), []byte(key))
	if err == nil {
		t.Fatal("LoadTLS accepted malformed material")
	}
	if got := err.Error(); containsAny(got, "SUPERSECRETKEYBYTES", "BEGIN PRIVATE KEY", "not a cert") {
		t.Fatalf("LoadTLS echoed its input: %q", got)
	}
}

func TestLoadCAPoolRejectsGarbage(t *testing.T) {
	if _, err := LoadCAPool([]byte("nothing here")); err == nil {
		t.Fatal("LoadCAPool accepted material with no certificate")
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
