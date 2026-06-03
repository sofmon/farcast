//go:build integration

// These tests drive the real GKE adapter against a live GCP project. They are
// excluded from normal builds and CI by the //go:build integration tag to
// protect FarCast's cost pillar: creating a cluster costs real money and takes
// several minutes. Run them deliberately.
//
// Credential check only (cheap, read-only — lists clusters):
//
//	FARCAST_GKE_TEST_PROJECT=my-proj \
//	FARCAST_GKE_TEST_CREDENTIALS=/path/to/sa-key.json \
//	go test -tags integration -run TestIntegrationValidate ./planck/internal/providers/gke/
//
// Full create → ready → delete lifecycle (SLOW, COSTS MONEY — extra opt-in):
//
//	FARCAST_GKE_TEST_PROJECT=my-proj \
//	FARCAST_GKE_TEST_CREDENTIALS=/path/to/sa-key.json \
//	FARCAST_GKE_TEST_LOCATION=us-central1 \
//	FARCAST_GKE_TEST_CREATE=1 \
//	go test -tags integration -timeout 30m -run TestIntegrationClusterLifecycle ./planck/internal/providers/gke/
//
// With FARCAST_GKE_TEST_PROJECT unset the tests skip. When
// FARCAST_GKE_TEST_CREDENTIALS is omitted, Application Default Credentials are
// used.
package gke

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sofmon/farcast/planck"
)

// testConfig builds a planck.Config from the FARCAST_GKE_TEST_* environment,
// skipping the test when no project is configured.
func testConfig(t *testing.T) planck.Config {
	t.Helper()
	project := os.Getenv("FARCAST_GKE_TEST_PROJECT")
	if project == "" {
		t.Skip("set FARCAST_GKE_TEST_PROJECT (and credentials) to run GKE integration tests")
	}
	cfg := planck.Config{
		Project:  project,
		Location: os.Getenv("FARCAST_GKE_TEST_LOCATION"),
	}
	if path := os.Getenv("FARCAST_GKE_TEST_CREDENTIALS"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read FARCAST_GKE_TEST_CREDENTIALS: %v", err)
		}
		cfg.Credentials = data
	}
	return cfg
}

// TestIntegrationValidate confirms the credentials reach the project. It is
// read-only and cheap — the right first check that wiring works end to end.
func TestIntegrationValidate(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := p.Validate(ctx); err != nil {
		t.Fatalf("Validate against the live project: %v", err)
	}
}

// TestIntegrationClusterLifecycle provisions a real Autopilot cluster, asserts
// it becomes ready with a kubeconfig, and tears it down. It is gated a second
// time behind FARCAST_GKE_TEST_CREATE=1 because it is slow and bills real
// money; teardown is registered up front so a mid-test failure still cleans up.
func TestIntegrationClusterLifecycle(t *testing.T) {
	if os.Getenv("FARCAST_GKE_TEST_CREATE") != "1" {
		t.Skip("set FARCAST_GKE_TEST_CREATE=1 to run the create→delete lifecycle (slow, costs money)")
	}
	cfg := testConfig(t)
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	location := cfg.Location
	if location == "" {
		location = defaultLocation
	}
	name := fmt.Sprintf("farcast-it-%d", time.Now().Unix())
	ref := planck.ClusterRef{Name: name, Location: location}

	// Register teardown before creating, so the cluster is removed even if an
	// assertion below fails.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if err := p.DeleteCluster(ctx, ref); err != nil {
			t.Errorf("cleanup DeleteCluster(%q): %v", name, err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	c, err := p.CreateCluster(ctx, planck.ClusterSpec{Name: name, Location: location})
	if err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	if c.Status != planck.StatusRunning {
		t.Errorf("status = %v, want running", c.Status)
	}
	if len(c.Kubeconfig) == 0 {
		t.Error("expected a kubeconfig for the ready cluster")
	}

	st, err := p.ClusterStatus(ctx, ref)
	if err != nil {
		t.Fatalf("ClusterStatus: %v", err)
	}
	if st != planck.StatusRunning {
		t.Errorf("ClusterStatus = %v, want running", st)
	}
}
