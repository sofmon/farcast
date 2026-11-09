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
	deleteOp    string     // the operation delete returns
	opStates    []opResult // returned by successive operationDone() calls; the last repeats
	opCalls     int
	opNames     []string
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
	if len(f.states) == 0 {
		return clusterState{}, false, nil
	}
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

func (f *fakeClient) delete(context.Context, planck.ClusterRef) (string, error) {
	f.deleteCalls++
	return f.deleteOp, f.deleteErr
}

func (f *fakeClient) operationDone(_ context.Context, op string) (bool, error) {
	f.opNames = append(f.opNames, op)
	i := f.opCalls
	f.opCalls++
	if len(f.opStates) == 0 {
		return true, nil
	}
	if i >= len(f.opStates) {
		i = len(f.opStates) - 1
	}
	return f.opStates[i].done, f.opStates[i].err
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
	api := &fakeClient{states: []stateResult{{exists: false}}}
	p := newTestProvider(api)
	if err := p.DeleteCluster(context.Background(), planck.ClusterRef{Name: "demo"}); err != nil {
		t.Fatalf("DeleteCluster: %v", err)
	}
	if api.deleteCalls != 0 {
		t.Errorf("delete called %d times for an absent cluster, want 0", api.deleteCalls)
	}
}

var (
	running  = stateResult{state: clusterState{RawStatus: "RUNNING"}, exists: true}
	stopping = stateResult{state: clusterState{RawStatus: "STOPPING"}, exists: true}
	failed   = stateResult{state: clusterState{RawStatus: "ERROR"}, exists: true}
	gone     = stateResult{exists: false}
)

// Release dropped the instance record the moment GKE accepted the delete —
// about 200 seconds before the cluster was gone on the 5.3 walk. The delete
// now returns once the cluster is absent.
func TestDeleteClusterWaitsUntilGone(t *testing.T) {
	api := &fakeClient{states: []stateResult{running, stopping, stopping, gone},
		deleteOp: "projects/p/locations/l/operations/op-1", opStates: []opResult{{done: false}, {done: false}, {done: true}}}
	if err := newTestProvider(api).DeleteCluster(context.Background(), planck.ClusterRef{Name: "demo"}); err != nil {
		t.Fatalf("DeleteCluster: %v", err)
	}
	if api.getCalls != 4 || len(api.opNames) == 0 || api.opNames[0] != api.deleteOp {
		t.Errorf("returned after %d look(s), waiting on %v; want it to wait until the cluster is gone", api.getCalls, api.opNames)
	}
}

func TestDeleteClusterOperationFailureIsAnError(t *testing.T) {
	api := &fakeClient{states: []stateResult{running, stopping}, deleteOp: "op",
		opStates: []opResult{{done: true, err: errors.New("quota")}}}
	err := newTestProvider(api).DeleteCluster(context.Background(), planck.ClusterRef{Name: "demo"})
	if err == nil || !strings.Contains(err.Error(), "demo") {
		t.Fatalf("DeleteCluster = %v; want the failed operation, naming the cluster", err)
	}
}

// A delete already in flight — an earlier release interrupted — is waited on,
// not requested again: GKE refuses a second operation meanwhile.
func TestDeleteClusterAlreadyStoppingWaitsWithoutReissuing(t *testing.T) {
	api := &fakeClient{states: []stateResult{stopping, stopping, gone}}
	if err := newTestProvider(api).DeleteCluster(context.Background(), planck.ClusterRef{Name: "demo"}); err != nil {
		t.Fatalf("DeleteCluster: %v", err)
	}
	if api.deleteCalls != 0 {
		t.Errorf("a second delete was requested while one was running")
	}
}

func TestDeleteClusterContextCancelledWhileStopping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	api := &fakeClient{states: []stateResult{running, stopping}}
	p := newTestProvider(api)
	p.pollInterval = 50 * time.Millisecond
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	err := p.DeleteCluster(ctx, planck.ClusterRef{Name: "demo"})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, planck.ErrDeleteInProgress) || api.deleteCalls != 1 {
		t.Fatalf("DeleteCluster = %v after %d delete(s); want 'still being deleted' wrapping context.Canceled", err, api.deleteCalls)
	}
}

func TestDeleteClusterThatComesBackIsAFailure(t *testing.T) {
	for name, after := range map[string]stateResult{"error": failed, "running": running} {
		api := &fakeClient{states: []stateResult{running, stopping, after}}
		if err := newTestProvider(api).DeleteCluster(context.Background(), planck.ClusterRef{Name: "demo"}); err == nil {
			t.Errorf("a cluster %s again after STOPPING was reported deleted", name)
		}
	}
}

// Right after the request the cluster may still show the state from before
// it — and deleting one a failed install left in ERROR is ordinary.
func TestDeleteClusterStaleStateBeforeStoppingIsNotAFailure(t *testing.T) {
	api := &fakeClient{states: []stateResult{failed, failed, stopping, gone}, deleteOp: "op", opStates: []opResult{{done: false}}}
	if err := newTestProvider(api).DeleteCluster(context.Background(), planck.ClusterRef{Name: "demo"}); err != nil {
		t.Fatalf("DeleteCluster: %v", err)
	}
}

func TestDeleteClusterGoneRightAfterTheRequest(t *testing.T) {
	api := &fakeClient{states: []stateResult{running, gone}}
	if err := newTestProvider(api).DeleteCluster(context.Background(), planck.ClusterRef{Name: "demo"}); err != nil || api.deleteCalls != 1 {
		t.Fatalf("DeleteCluster = %v after %d delete(s)", err, api.deleteCalls)
	}
}

func TestOperationPath(t *testing.T) {
	c := &gkeClient{project: "p"}
	for in, want := range map[string]string{
		"op-1":                                   "projects/p/locations/l/operations/op-1",
		"projects/p/locations/l/operations/op-2": "projects/p/locations/l/operations/op-2",
		"":                                       "",
	} {
		if got := c.operationPath("l", in); got != want {
			t.Errorf("operationPath(%q) = %q, want %q", in, got, want)
		}
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

func TestPrivateControlPlaneConfig(t *testing.T) {
	c := privateControlPlaneConfig()
	ip := c.GetIpEndpointsConfig()
	if ip.GetEnablePublicEndpoint() {
		t.Error("public control-plane endpoint must be disabled (ADR 0004)")
	}
	if !ip.GetEnabled() {
		t.Error("the internal IP endpoint must stay enabled")
	}
	// GKE rejects a disabled public endpoint unless master authorized networks
	// is enabled — the constraint a live create caught.
	if !ip.GetAuthorizedNetworksConfig().GetEnabled() {
		t.Error("master authorized networks must be enabled when the public endpoint is off")
	}
	if n := len(ip.GetAuthorizedNetworksConfig().GetCidrBlocks()); n != 0 {
		t.Errorf("authorized-networks CIDR list = %d entries, want empty (operators use the DNS endpoint)", n)
	}
	if !c.GetDnsEndpointConfig().GetAllowExternalTraffic() {
		t.Error("the DNS endpoint must allow external traffic for operator access")
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

// TestLazyClientWiring exercises a provider built by New (api starts nil) so
// every operation must construct the client via client(). It guards against
// methods dereferencing a nil p.api directly — the bug the release path hit.
func TestLazyClientWiring(t *testing.T) {
	orig := newClient
	t.Cleanup(func() { newClient = orig })
	up := stateResult{state: clusterState{RawStatus: "RUNNING", Endpoint: "uid.us-central1.gke.goog"}, exists: true}
	fake := &fakeClient{states: []stateResult{up, up, up, up, {exists: false}}}
	built := 0
	newClient = func(planck.Config) (clusterAPI, error) {
		built++
		return fake, nil
	}

	p, err := New(planck.Config{Project: "p"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := p.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, err := p.CreateCluster(ctx, planck.ClusterSpec{Name: "demo"}); err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	if _, err := p.ClusterStatus(ctx, planck.ClusterRef{Name: "demo"}); err != nil {
		t.Fatalf("ClusterStatus: %v", err)
	}
	if err := p.DeleteCluster(ctx, planck.ClusterRef{Name: "demo"}); err != nil {
		t.Fatalf("DeleteCluster: %v", err)
	}
	if built != 1 {
		t.Errorf("newClient called %d times, want 1 (built once, then reused)", built)
	}
}
