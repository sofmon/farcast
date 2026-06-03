package gke

import (
	"context"
	"errors"

	"github.com/sofmon/farcast/planck"
)

// clusterAPI is the narrow seam over the cloud's cluster-management API,
// expressed in neutral terms so the adapter's logic (defaults, status
// mapping, readiness polling, idempotency, kubeconfig assembly) is unit
// testable without the cloud SDK. The real implementation wraps
// cloud.google.com/go/container; see newClient.
type clusterAPI interface {
	// validate performs a cheap, side-effect-free permission probe.
	validate(ctx context.Context) error
	// get returns the current state of a cluster and whether it exists.
	get(ctx context.Context, ref planck.ClusterRef) (clusterState, bool, error)
	// create requests creation of a cluster. It returns once the create
	// operation is accepted (not necessarily ready).
	create(ctx context.Context, in createInput) error
	// delete requests deletion; deleting an absent cluster returns nil.
	delete(ctx context.Context, ref planck.ClusterRef) error
}

// createInput is the neutral, defaults-resolved description of the cluster to
// create. The adapter builds it from a planck.ClusterSpec.
type createInput struct {
	Name      string
	Location  string
	Version   string // empty = provider default
	Labels    map[string]string
	Autopilot bool // always true for FarCast (ADR 0003)
}

// clusterState is the neutral snapshot the seam returns for a cluster.
type clusterState struct {
	RawStatus string // cloud-native status string, e.g. "RUNNING"
	Endpoint  string // API server host
	CACert    []byte // cluster CA certificate, for the kubeconfig
}

// errClientNotWired reports that the real GCP-backed client has not been
// built yet. The adapter's logic and its unit tests run against a fake
// clusterAPI; wiring the real client means vendoring
// cloud.google.com/go/container and implementing it here (see
// planck/README.md → "First adapter: GKE Autopilot").
var errClientNotWired = errors.New("gke: GCP client not wired — vendor cloud.google.com/go/container and implement newClient")

// newClient builds the real GCP-backed clusterAPI from cfg. Until the Google
// Cloud SDK is vendored it returns a stub whose operations report
// errClientNotWired, so the package builds and the adapter's logic stays
// fully testable in the meantime.
func newClient(_ planck.Config) (clusterAPI, error) {
	return stubClient{}, nil
}

type stubClient struct{}

var _ clusterAPI = stubClient{}

func (stubClient) validate(context.Context) error { return errClientNotWired }

func (stubClient) get(context.Context, planck.ClusterRef) (clusterState, bool, error) {
	return clusterState{}, false, errClientNotWired
}

func (stubClient) create(context.Context, createInput) error { return errClientNotWired }

func (stubClient) delete(context.Context, planck.ClusterRef) error { return errClientNotWired }
