package gke

import (
	"context"
	"fmt"

	container "cloud.google.com/go/container/apiv1"
	"cloud.google.com/go/container/apiv1/containerpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/sofmon/farcast/planck"
)

// clusterAPI is the narrow seam over the cloud's cluster-management API,
// expressed in neutral terms so the adapter's logic (defaults, status mapping,
// readiness polling, idempotency, kubeconfig assembly) stays unit testable
// without the cloud SDK. The real implementation, gkeClient, wraps
// cloud.google.com/go/container's ClusterManagerClient; the unit tests use a
// fake (see gke_test.go).
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
	// PrivateControlPlane applies FarCast's control-plane network isolation
	// (ADR 0004): public IP endpoint off, internal endpoint on, IAM-gated DNS
	// endpoint on. Always true for FarCast.
	PrivateControlPlane bool
}

// clusterState is the neutral snapshot the seam returns for a cluster.
type clusterState struct {
	RawStatus string // cloud-native status string, e.g. "RUNNING"
	Endpoint  string // control-plane DNS endpoint, e.g. uid.us-central1.gke.goog (ADR 0004)
}

// gkeClient is the real clusterAPI, backed by the GKE cluster-management API.
// One client is scoped to a single GCP project; each call supplies the
// cluster's location and name via a ClusterRef/createInput.
type gkeClient struct {
	svc     *container.ClusterManagerClient
	project string
}

var _ clusterAPI = (*gkeClient)(nil)

// newClient builds a GCP-backed clusterAPI from cfg. When cfg.Credentials is
// set it is treated as a service-account key JSON; otherwise Application
// Default Credentials are used. The gRPC connection lives for the life of the
// process — FarCast's callers (the planck harness and `farcast install`) are
// short-lived — so the client is not explicitly closed.
//
// It is a package variable so tests can substitute a fake and exercise the
// provider's lazy-construction path without real credentials.
var newClient = func(cfg planck.Config) (clusterAPI, error) {
	var opts []option.ClientOption
	if len(cfg.Credentials) > 0 {
		// Restrict the accepted credential to a service-account key (FarCast's
		// operator supplies an SA key JSON) rather than the deprecated
		// WithCredentialsJSON, which loads any credential type — a security
		// risk when the material may come from an untrusted source.
		opts = append(opts, option.WithAuthCredentialsJSON(option.ServiceAccount, cfg.Credentials))
	}
	svc, err := container.NewClusterManagerClient(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("gke: build cluster-manager client: %w", err)
	}
	return &gkeClient{svc: svc, project: cfg.Project}, nil
}

// locationPath is the GKE "projects/P/locations/L" parent path. Pass "-" as
// location to address every location in the project.
func (c *gkeClient) locationPath(location string) string {
	return fmt.Sprintf("projects/%s/locations/%s", c.project, location)
}

// clusterPath is the fully-qualified "projects/P/locations/L/clusters/N" name.
func (c *gkeClient) clusterPath(ref planck.ClusterRef) string {
	return fmt.Sprintf("%s/clusters/%s", c.locationPath(ref.Location), ref.Name)
}

func (c *gkeClient) validate(ctx context.Context) error {
	// Listing clusters across every location is a cheap, read-only probe that
	// exercises the credentials and the container.clusters.list permission.
	if _, err := c.svc.ListClusters(ctx, &containerpb.ListClustersRequest{
		Parent: c.locationPath("-"),
	}); err != nil {
		return fmt.Errorf("gke: validate credentials: %w", err)
	}
	return nil
}

func (c *gkeClient) get(ctx context.Context, ref planck.ClusterRef) (clusterState, bool, error) {
	cl, err := c.svc.GetCluster(ctx, &containerpb.GetClusterRequest{Name: c.clusterPath(ref)})
	if status.Code(err) == codes.NotFound {
		return clusterState{}, false, nil
	}
	if err != nil {
		return clusterState{}, false, err
	}
	// FarCast clusters expose only the DNS endpoint to operators (ADR 0004); the
	// public IP endpoint is disabled, so cl.GetEndpoint() is not used.
	return clusterState{
		RawStatus: cl.GetStatus().String(),
		Endpoint:  cl.GetControlPlaneEndpointsConfig().GetDnsEndpointConfig().GetEndpoint(),
	}, true, nil
}

func (c *gkeClient) create(ctx context.Context, in createInput) error {
	cluster := &containerpb.Cluster{
		Name:           in.Name,
		ResourceLabels: in.Labels,
		Autopilot:      &containerpb.Autopilot{Enabled: in.Autopilot},
	}
	if in.Version != "" {
		cluster.InitialClusterVersion = in.Version
	}
	if in.PrivateControlPlane {
		// ADR 0004: no public control-plane IP. Keep the internal IP endpoint
		// for in-cluster/VPC access, disable the public endpoint, and enable the
		// IAM-gated DNS endpoint for external operator access.
		cluster.ControlPlaneEndpointsConfig = &containerpb.ControlPlaneEndpointsConfig{
			IpEndpointsConfig: &containerpb.ControlPlaneEndpointsConfig_IPEndpointsConfig{
				Enabled:              new(true),
				EnablePublicEndpoint: new(false),
			},
			DnsEndpointConfig: &containerpb.ControlPlaneEndpointsConfig_DNSEndpointConfig{
				AllowExternalTraffic: new(true),
			},
		}
	}
	// CreateCluster returns once the long-running operation is accepted; the
	// adapter polls get() until the cluster reports Running.
	_, err := c.svc.CreateCluster(ctx, &containerpb.CreateClusterRequest{
		Parent:  c.locationPath(in.Location),
		Cluster: cluster,
	})
	return err
}

func (c *gkeClient) delete(ctx context.Context, ref planck.ClusterRef) error {
	_, err := c.svc.DeleteCluster(ctx, &containerpb.DeleteClusterRequest{Name: c.clusterPath(ref)})
	if status.Code(err) == codes.NotFound {
		return nil // already gone — deletion is idempotent
	}
	return err
}
