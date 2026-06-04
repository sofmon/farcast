package gke

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/planck"
)

// fakeClient is a programmable clusterAPI for exercising the adapter's logic
// without the cloud SDK.
type fakeClient struct {
	validateErr error
	states      []stateResult // returned by successive get() calls; the last repeats
	getCalls    int
	created     *createInput
	createErr   error
	deleteErr   error
	deleteCalls int
}

type stateResult struct {
	state  clusterState
	exists bool
	err    error
}

func (f *fakeClient) validate(context.Context) error { return f.validateErr }

func (f *fakeClient) get(context.Context, planck.ClusterRef) (clusterState, bool, error) {
	i := f.getCalls
	f.getCalls++
	if i >= len(f.states) {
		i = len(f.states) - 1
	}
	r := f.states[i]
	return r.state, r.exists, r.err
}

func (f *fakeClient) create(_ context.Context, in createInput) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = &in
	return nil
}

func (f *fakeClient) delete(context.Context, planck.ClusterRef) error {
	f.deleteCalls++
	return f.deleteErr
}

func newTestProvider(api clusterAPI) *provider {
	return &provider{api: api, defaultLocation: "us-central1", pollInterval: time.Millisecond}
}

func TestCreateClusterProvisionsAndWaits(t *testing.T) {
	api := &fakeClient{states: []stateResult{
		{exists: false}, // existence check → not found
		{state: clusterState{RawStatus: "PROVISIONING"}, exists: true},
		{state: clusterState{RawStatus: "RUNNING", Endpoint: "uid.us-central1.gke.goog"}, exists: true},
	}}
	p := newTestProvider(api)

	c, err := p.CreateCluster(context.Background(), planck.ClusterSpec{Name: "demo"})
	if err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	if api.created == nil {
		t.Fatal("expected create() to be called")
	}
	if !api.created.Autopilot {
		t.Error("created cluster should have Autopilot enabled")
	}
	if !api.created.PrivateControlPlane {
		t.Error("created cluster should have the private control plane enabled (ADR 0004)")
	}
	if api.created.Location != "us-central1" {
		t.Errorf("location = %q, want default us-central1", api.created.Location)
	}
	if c.Status != planck.StatusRunning {
		t.Errorf("status = %v, want running", c.Status)
	}
	if c.Endpoint != "uid.us-central1.gke.goog" {
		t.Errorf("endpoint = %q, want the DNS endpoint", c.Endpoint)
	}
	if len(c.Kubeconfig) == 0 {
		t.Error("expected a kubeconfig")
	}
}

func TestCreateClusterIdempotent(t *testing.T) {
	api := &fakeClient{states: []stateResult{
		{state: clusterState{RawStatus: "RUNNING", Endpoint: "uid.us-central1.gke.goog"}, exists: true},
	}}
	p := newTestProvider(api)

	if _, err := p.CreateCluster(context.Background(), planck.ClusterSpec{Name: "demo"}); err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	if api.created != nil {
		t.Error("create() must not be called when the cluster already exists")
	}
}

func TestCreateClusterRejectsBadName(t *testing.T) {
	p := newTestProvider(&fakeClient{states: []stateResult{{exists: false}}})
	if _, err := p.CreateCluster(context.Background(), planck.ClusterSpec{Name: "Bad_Name"}); err == nil {
		t.Fatal("expected an error for an invalid cluster name")
	}
}

func TestCreateClusterContextCancelled(t *testing.T) {
	api := &fakeClient{states: []stateResult{
		{exists: false},
		{state: clusterState{RawStatus: "PROVISIONING"}, exists: true}, // never reaches Running
	}}
	p := newTestProvider(api)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.CreateCluster(ctx, planck.ClusterSpec{Name: "demo"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestClusterStatusNotFound(t *testing.T) {
	p := newTestProvider(&fakeClient{states: []stateResult{{exists: false}}})
	st, err := p.ClusterStatus(context.Background(), planck.ClusterRef{Name: "demo"})
	if !errors.Is(err, planck.ErrClusterNotFound) {
		t.Fatalf("err = %v, want ErrClusterNotFound", err)
	}
	if st != planck.StatusUnknown {
		t.Errorf("status = %v, want unknown", st)
	}
}

func TestDeleteClusterIdempotent(t *testing.T) {
	api := &fakeClient{} // delete returns nil even though no cluster exists
	p := newTestProvider(api)
	if err := p.DeleteCluster(context.Background(), planck.ClusterRef{Name: "demo"}); err != nil {
		t.Fatalf("DeleteCluster: %v", err)
	}
	if api.deleteCalls != 1 {
		t.Errorf("delete called %d times, want 1", api.deleteCalls)
	}
}

func TestValidatePropagates(t *testing.T) {
	wantErr := errors.New("bad creds")
	p := newTestProvider(&fakeClient{validateErr: wantErr})
	if err := p.Validate(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestMapStatus(t *testing.T) {
	cases := map[string]planck.ClusterStatus{
		"RUNNING":      planck.StatusRunning,
		"PROVISIONING": planck.StatusProvisioning,
		"reconciling":  planck.StatusProvisioning,
		"STOPPING":     planck.StatusDeleting,
		"ERROR":        planck.StatusError,
		"DEGRADED":     planck.StatusError,
		"WAT":          planck.StatusUnknown,
		"":             planck.StatusUnknown,
	}
	for raw, want := range cases {
		if got := mapStatus(raw); got != want {
			t.Errorf("mapStatus(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestBuildKubeconfig(t *testing.T) {
	kc := string(buildKubeconfig("demo", "uid.us-central1.gke.goog"))
	for _, want := range []string{"name: demo", "server: https://uid.us-central1.gke.goog", "gke-gcloud-auth-plugin"} {
		if !strings.Contains(kc, want) {
			t.Errorf("kubeconfig missing %q:\n%s", want, kc)
		}
	}
	// The DNS endpoint uses a publicly-trusted cert (ADR 0004), so the kubeconfig
	// must not pin the cluster CA.
	if strings.Contains(kc, "certificate-authority-data") {
		t.Errorf("kubeconfig must not embed certificate-authority-data:\n%s", kc)
	}
}

func TestNewRequiresProject(t *testing.T) {
	if _, err := New(planck.Config{}); err == nil {
		t.Fatal("expected New to require a project")
	}
	if _, err := New(planck.Config{Project: "p"}); err != nil {
		t.Fatalf("New with a project: %v", err)
	}
}
