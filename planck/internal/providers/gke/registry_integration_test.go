//go:build integration

// These tests drive the instance-registry capability (ADR 0007) against a live
// GCP project. They are excluded from normal builds and CI by the
// //go:build integration tag: they create real cloud resources and need real
// credentials. Run them deliberately.
//
// Token minting only (cheap, creates nothing — one OAuth2 token exchange):
//
//	FARCAST_GKE_TEST_PROJECT=my-proj \
//	FARCAST_GKE_TEST_CREDENTIALS=/path/to/sa-key.json \
//	go test -tags integration -run TestIntegrationRegistryToken ./planck/internal/providers/gke/
//
// Full ensure → grant → delete lifecycle (creates a repository — extra opt-in):
//
//	FARCAST_GKE_TEST_PROJECT=my-proj \
//	FARCAST_GKE_TEST_CREDENTIALS=/path/to/sa-key.json \
//	FARCAST_GKE_TEST_LOCATION=us-central1 \
//	FARCAST_GKE_TEST_REGISTRY=1 \
//	go test -tags integration -timeout 10m -run TestIntegrationRegistryLifecycle ./planck/internal/providers/gke/
//
// The service account needs roles/artifactregistry.admin (repository create,
// delete and repository-level setIamPolicy) and the project-get permission that
// roles/container.admin already carries. Storage for an empty repository is
// free, but the lifecycle test is gated a second time anyway: it mutates IAM on
// a real resource.
package gke

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/planck"
)

// registryProvider builds the GKE provider and asserts the optional capability,
// which is also the assertion every caller makes.
func registryProvider(t *testing.T, cfg planck.Config) planck.RegistryProvider {
	t.Helper()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rp, ok := p.(planck.RegistryProvider)
	if !ok {
		t.Fatal("the GKE provider must satisfy planck.RegistryProvider")
	}
	return rp
}

// TestIntegrationRegistryToken confirms the stored key can mint a registry
// credential. It creates nothing — the right first check that auth is wired.
func TestIntegrationRegistryToken(t *testing.T) {
	rp := registryProvider(t, testConfig(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tok, err := rp.RegistryToken(ctx)
	if err != nil {
		t.Fatalf("RegistryToken: %v", err)
	}
	if tok.Username != "oauth2accesstoken" {
		t.Errorf("username = %q, want oauth2accesstoken", tok.Username)
	}
	if tok.Password == "" {
		t.Error("expected an access token")
	}
	if !tok.Expiry.After(time.Now()) {
		t.Errorf("expiry = %v, want a token that is still valid", tok.Expiry)
	}
	// Short-lived by contract: a registry push credential that outlives the
	// command that minted it is a standing supply-chain foothold.
	if tok.Expiry.After(time.Now().Add(2 * time.Hour)) {
		t.Errorf("expiry = %v, want a short-lived token", tok.Expiry)
	}
	if strings.Contains(tok.String(), tok.Password) {
		t.Error("String() leaked the access token")
	}
}

// TestIntegrationRegistryLifecycle ensures a real repository, checks the
// repo-scoped pull grant lands, re-ensures to prove idempotence, and deletes it.
// Teardown is registered up front so a mid-test failure still removes the
// repository — a leaked repository is billable storage nobody is watching.
func TestIntegrationRegistryLifecycle(t *testing.T) {
	if os.Getenv("FARCAST_GKE_TEST_REGISTRY") != "1" {
		t.Skip("set FARCAST_GKE_TEST_REGISTRY=1 to run the ensure→delete registry lifecycle")
	}
	cfg := testConfig(t)
	rp := registryProvider(t, cfg)

	location := cfg.Location
	if location == "" {
		location = defaultLocation
	}
	instance := fmt.Sprintf("it-%d", time.Now().Unix())
	ref := planck.RegistryRef{Name: repositoryName(instance), Location: location}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := rp.DeleteRegistry(ctx, ref); err != nil {
			t.Errorf("cleanup DeleteRegistry(%q): %v", ref.Name, err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	reg, err := rp.EnsureRegistry(ctx, planck.RegistrySpec{
		Name:     instance,
		Location: location,
		Cluster:  planck.ClusterRef{Name: repositoryName(instance), Location: location},
		Labels:   map[string]string{"farcast-instance": instance},
	})
	if err != nil {
		t.Fatalf("EnsureRegistry: %v", err)
	}
	if reg.Ref != ref {
		t.Errorf("ref = %+v, want %+v", reg.Ref, ref)
	}
	wantPrefix := fmt.Sprintf("%s-docker.pkg.dev/%s/%s", location, cfg.Project, ref.Name)
	if reg.Prefix != wantPrefix {
		t.Errorf("prefix = %q, want %q", reg.Prefix, wantPrefix)
	}
	if !strings.HasPrefix(reg.Puller, "serviceAccount:") || !strings.HasSuffix(reg.Puller, "-compute@developer.gserviceaccount.com") {
		t.Errorf("puller = %q, want the node service account principal", reg.Puller)
	}

	// The defensive ensure `farcast connect` runs on every reconnect must be a
	// no-op, not an error.
	again, err := rp.EnsureRegistry(ctx, planck.RegistrySpec{Name: instance, Location: location})
	if err != nil {
		t.Fatalf("second EnsureRegistry (idempotence): %v", err)
	}
	if again.Prefix != reg.Prefix || again.Puller != reg.Puller {
		t.Errorf("re-ensure = %+v, want the same registry as %+v", again, reg)
	}

	if err := rp.DeleteRegistry(ctx, ref); err != nil {
		t.Fatalf("DeleteRegistry: %v", err)
	}
	// Idempotent teardown: `farcast release` must converge on a re-run.
	if err := rp.DeleteRegistry(ctx, ref); err != nil {
		t.Fatalf("DeleteRegistry on an absent repository: %v", err)
	}
}
