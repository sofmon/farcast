package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kernel"
)

// The golden vectors: the CLI's JSON, byte for byte, for every case the map
// has to draw. They are the contract between this CLI and the FarCast app —
// the app's tests decode them — so a change that alters a byte fails here
// first, and is made deliberately:
//
//	FARCAST_UPDATE_VECTORS=1 go test ./farsight/cli/internal/cli/ -run Vector
//
// rewrites them. World vectors come only from the pure builder fed literal
// inputs, so they never depend on a clock, a hostname or a temp directory.

const updateVectorsEnv = "FARCAST_UPDATE_VECTORS"

var (
	vectorNow   = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	vectorStamp = buildStamp{Version: "v0.0.0-vector", Commit: "0e54eb1"}
)

func digestOf(c string) string { return "@sha256:" + strings.Repeat(c, 64) }

const vecRegistry = "europe-west4-docker.pkg.dev/proj-atlas/farcast-atlas"

var (
	vecFatLineImage   = vecRegistry + "/fatline" + digestOf("1")
	vecShrikeImage    = vecRegistry + "/shrike" + digestOf("2")
	vecKernelImage    = vecRegistry + "/technocore" + digestOf("3")
	vecKeyholderImage = vecRegistry + "/datasphered" + digestOf("4")
)

func wl(kind, ns, name string, ready, desired int, images ...string) cluster.Workload {
	return cluster.Workload{Kind: kind, Namespace: ns, Name: name, Ready: ready, Desired: desired, Images: images}
}

func credentialOf(c string) string { return strings.Repeat(c, 64) }

// vectorCheckpoint is a real kernel checkpoint, built through the real ledger.
//
// Every rate is a binary fraction and every interval a whole number of hours,
// so the sums are exact whatever order the ledger adds its buckets in: a
// vector that changed with map iteration order would be no vector at all.
func vectorCheckpoint(t *testing.T, mutate func(*kernel.Checkpoint)) string {
	t.Helper()
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	ledger, err := cost.NewLedger(start, end)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	for app, rate := range map[string]float64{
		"api": 0.0625, "web": 0.03125, "technocore": 0.015625, "fatline": 0.03125, "datasphered": 0.03125,
	} {
		ledger.Accrue(at, app, rate, 132*time.Hour)
	}
	// What the model expected for the window, so calibration stays exactly 1.
	if _, err := ledger.Confirm(cost.Confirmation{
		Start: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC),
		USD: 0.171875 * 27, AsOf: time.Date(2026, 11, 9, 6, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	cp := kernel.Checkpoint{
		Version: kernel.CheckpointVersion, Ledger: ledger.Snapshot(), Last: at.Add(55 * time.Minute),
		Observed: kernel.Observation{
			At: at.Add(55*time.Minute + 123456789), Pods: 7, RateHourlyUSD: 0.171875,
			Carrier: string(kernel.CarrierLoadBalancer), Level: cost.LevelOK.String(), Limit: 50,
		},
	}
	if mutate != nil {
		mutate(&cp)
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func vectorMeta() *config.InstanceMetadata {
	return &config.InstanceMetadata{
		Name: "atlas", Provider: "gke", Project: "proj-atlas", Region: "europe-west4",
		Cluster: "farcast-atlas", Endpoint: "gke-1a2b3c.europe-west4.gke.goog", Status: config.InstanceRunning,
		CostLimit:    config.CostLimit{Amount: 50, Currency: "USD", Period: "monthly"},
		CloudLogging: config.CloudLoggingSystem, GCloudAccount: "operator@example.org",
		FatLineDeployed: true,
		Carrier:         &config.Carrier{Type: "nlb", Endpoint: "203.0.113.7:443", ServerName: "fatline.atlas.farcast"},
		Registry:        &config.Registry{Prefix: vecRegistry, FatLineDigest: vecFatLineImage},
		Storage:         &config.Storage{Bucket: "farcast-atlas-5f3a9c21"},
		Kernel: &config.Kernel{Deployed: true, Applied: true, Image: vecKernelImage,
			Namespaces: []string{"farcast-system", "shop"}, Limit: 50, Currency: "USD", Period: "monthly"},
		Keyholder: &config.Keyholder{Deployed: true, Image: vecKeyholderImage, Replicas: 2, Generation: 7},
		Keepers: []config.Keeper{{
			Device: "phone", EnrolledAt: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC),
			Expires: time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC), LeafTokens: []string{"phone-leaf-1", "phone-leaf-2"},
		}},
		Deployments: map[string]config.Deployment{
			"shop": {Repository: "https://github.com/example/shop", Ref: "refs/heads/main",
				Commit: "4f2a9c1e8b7d6a5f4e3c2b1a0f9e8d7c6b5a4938", ManifestDigest: "sha256:" + strings.Repeat("9", 64),
				DeployedAt: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC), StorageWired: true},
		},
	}
}

// healthyInputs is an instance where everything was read and nothing is
// wrong. Every other case starts here and changes what it is about.
func healthyInputs(t *testing.T) worldInputs {
	t.Helper()
	since := time.Date(2026, 11, 11, 8, 0, 0, 123456789, time.UTC) // nanoseconds, to prove the truncation
	return worldInputs{
		Now: vectorNow.Add(987654321), Stamp: vectorStamp, Name: "atlas", Meta: vectorMeta(),
		Apps: appsInput{
			System: []cluster.Workload{
				wl("Deployment", "farcast-system", "fatline", 2, 2, vecFatLineImage, vecShrikeImage),
				wl("Deployment", "farcast-system", "technocore", 1, 1, vecKernelImage),
				wl("StatefulSet", "farcast-system", "datasphered", 2, 2, vecKeyholderImage),
			},
			Namespaces: []string{"farcast-system", "shop"},
			Workloads: map[string][]cluster.Workload{
				"shop": {
					wl("Deployment", "shop", "web", 1, 1, vecRegistry+"/app/shop/web"+digestOf("5")),
					wl("Deployment", "shop", "api", 2, 2, vecRegistry+"/app/shop/api"+digestOf("6")),
				},
			},
			Meter: meterInput{Namespaces: []string{"farcast-system", "shop"}},
		},
		Spend: spendInput{Found: true, Raw: vectorCheckpoint(t, nil)},
		Policy: policyInput{Doc: &policy.Document{Version: policy.Version, Apps: []policy.App{
			{Name: "api", Namespace: "shop", CredentialSHA256: credentialOf("a"), External: []parser.External{
				{Host: "api.stripe.com", Reason: "payment processing"},
				{Host: "sentry.io", Reason: "error reporting"},
			}},
			{Name: "web", Namespace: "shop", CredentialSHA256: credentialOf("b")},
		}}},
		Network: networkInput{
			Tunnel: true, OperatorToken: "operator-leaf",
			Snapshot: shrike.Snapshot{
				Replica: "fatline-5d8c7b9f4-x2k7q", Since: since, Events: 4211,
				Declared: []string{"api.stripe.com", "sentry.io"},
				Allowed: []shrike.HostStat{{
					App: "api", Namespace: "shop", Host: "api.stripe.com", Port: "443", Declared: true,
					Allows: 120, Fails: 2, BytesUp: 1 << 20, BytesDown: 4 << 20,
					LastSeen: time.Date(2026, 11, 12, 9, 55, 30, 500000000, time.UTC),
				}},
				Tunnel: []shrike.TunnelStat{
					{Role: event.PeerOperator, Peer: "operator-leaf", Route: "shrike", Relayed: 3,
						LastSeen: time.Date(2026, 11, 12, 9, 59, 0, 0, time.UTC)},
					{Role: event.PeerKeeper, Peer: "phone-leaf-2", Route: "datasphered", Relayed: 2,
						LastSeen: time.Date(2026, 11, 12, 6, 0, 0, 0, time.UTC)},
				},
				TunnelSeparated: true,
			},
		},
		Seal: sealInput{Replicas: []replicaRead{
			{Ordinal: 0, State: &keyholder.State{Phase: "unsealed", Generation: 7, Since: since}},
			{Ordinal: 1, State: &keyholder.State{Phase: "unsealed", Generation: 7, Since: since}},
		}},
	}
}

type worldVector struct {
	name   string
	inputs func(t *testing.T) worldInputs
}

func worldVectors() []worldVector {
	return []worldVector{
		{"healthy", healthyInputs},
		{"never_connected", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Meta.FatLineDeployed, in.Meta.Carrier, in.Meta.Keyholder, in.Meta.Keepers = false, nil, nil, nil
			in.Apps.System = in.Apps.System[1:2] // the kernel alone
			p := &sectionProblem{Kind: kindNotConnected, Message: `instance "atlas" has no tunnel recorded, so its traffic and seal state cannot be read; 'farcast connect atlas' opens one`}
			in.Network = networkInput{Problem: p}
			in.Seal = sealInput{Skipped: true}
			in.Policy = policyInput{Doc: &policy.Document{Version: policy.Version}}
			delete(in.Meta.Deployments, "shop")
			in.Apps.Namespaces, in.Apps.Workloads = []string{"farcast-system"}, map[string][]cluster.Workload{}
			in.Apps.Meter.Namespaces = []string{"farcast-system"}
			in.Meta.Kernel.Namespaces = []string{"farcast-system"}
			return in
		}},
		{"no_kernel", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Meta.Kernel = nil
			in.Apps.System = []cluster.Workload{in.Apps.System[0], in.Apps.System[2]}
			in.Apps.Meter.Namespaces = []string{}
			in.Spend = spendInput{Problem: &sectionProblem{Kind: kindKernelAbsent,
				Message: `instance "atlas" has no kernel, so nothing is metering it; run 'farcast kernel deploy atlas'`}}
			return in
		}},
		{"tunnel_down", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			p := &sectionProblem{Kind: kindTunnelUnreachable,
				Message: "the FatLine tunnel did not open: fatline: connect https://203.0.113.7:443: dial tcp 203.0.113.7:443: i/o timeout"}
			in.Network = networkInput{Problem: p}
			in.Seal = sealInput{Problem: p}
			return in
		}},
		{"sealed_replica", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Seal.Replicas[1].State = &keyholder.State{Phase: "restart-sealed", Since: vectorNow.Add(-20 * time.Minute)}
			return in
		}},
		{"cost_reached_stopped_apps", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Spend.Raw = vectorCheckpoint(t, func(cp *kernel.Checkpoint) {
				cp.Observed.Level, cp.Observed.Limit = cost.LevelReached.String(), 20
			})
			in.Apps.Workloads["shop"] = []cluster.Workload{
				wl("Deployment", "shop", "api", 0, 0, vecRegistry+"/app/shop/api"+digestOf("6")),
				wl("Deployment", "shop", "web", 0, 0, vecRegistry+"/app/shop/web"+digestOf("5")),
			}
			return in
		}},
		{"stale_checkpoint", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Spend.Raw = vectorCheckpoint(t, func(cp *kernel.Checkpoint) {
				cp.Observed.At = vectorNow.Add(-40 * time.Minute)
				cp.Last = cp.Observed.At
			})
			return in
		}},
		{"unmetered_namespace", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Apps.Namespaces = append(in.Apps.Namespaces, "lab")
			in.Apps.Workloads["lab"] = []cluster.Workload{wl("Deployment", "lab", "notebook", 1, 1, vecRegistry+"/app/lab/notebook"+digestOf("7"))}
			return in
		}},
		{"checkpoint_version_skew", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Spend.Raw = vectorCheckpoint(t, func(cp *kernel.Checkpoint) { cp.Version = kernel.CheckpointVersion + 1 })
			return in
		}},
		{"shared_app_name", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Apps.Namespaces = append(in.Apps.Namespaces, "blog")
			in.Apps.Meter.Namespaces = append(in.Apps.Meter.Namespaces, "blog")
			in.Meta.Kernel.Namespaces = append(in.Meta.Kernel.Namespaces, "blog")
			in.Apps.Workloads["blog"] = []cluster.Workload{wl("Deployment", "blog", "web", 1, 1, vecRegistry+"/app/blog/web"+digestOf("8"))}
			in.Meta.Deployments["blog"] = config.Deployment{Repository: "https://github.com/example/blog", Ref: "refs/heads/main",
				Commit: "1111111111111111111111111111111111111111", ManifestDigest: "sha256:" + strings.Repeat("8", 64),
				DeployedAt: time.Date(2026, 11, 11, 7, 0, 0, 0, time.UTC)}
			return in
		}},
		{"mixed_evidence", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Network.Snapshot.Violations = []shrike.Violation{{
				Severity: shrike.SeverityWarning, App: "api", Namespace: "shop", Host: "API.Stripe.com.", Port: "80",
				Reason: event.ReasonCleartext, Count: 4,
				FirstSeen: vectorNow.Add(-3 * time.Hour), LastSeen: vectorNow.Add(-10 * time.Minute),
			}}
			return in
		}},
		{"drift", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Network.Snapshot.Allowed = append(in.Network.Snapshot.Allowed,
				shrike.HostStat{App: "api", Namespace: "shop", Host: "tracker.example", Port: "443", Allows: 9,
					LastSeen: vectorNow.Add(-5 * time.Minute)},
				// Removed by the last redeploy, and last seen before it: the
				// monitor's table outlives the policy, and this is not drift.
				shrike.HostStat{App: "api", Namespace: "shop", Host: "old-cdn.example", Port: "443", Allows: 40,
					LastSeen: time.Date(2026, 11, 10, 11, 0, 0, 0, time.UTC)},
			)
			return in
		}},
		{"unattributed_denial", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Network.Snapshot.Violations = []shrike.Violation{{
				Severity: shrike.SeverityCritical, Host: "203.0.113.99", Port: "25", Reason: event.ReasonUnknownApp, Count: 12,
				FirstSeen: vectorNow.Add(-50 * time.Minute), LastSeen: vectorNow.Add(-2 * time.Minute),
			}}
			return in
		}},
		{"hostile_host_name", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Network.Snapshot.Violations = []shrike.Violation{{
				Severity: shrike.SeverityWarning, App: "web", Namespace: "shop",
				Host: "pay\u202epal\u009b.example\u0085", Port: "443", Reason: event.ReasonNotInAllowlist, Count: 1,
				FirstSeen: vectorNow.Add(-5 * time.Minute), LastSeen: vectorNow.Add(-5 * time.Minute),
			}}
			return in
		}},
		{"host_cap_exceeded", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			var many []parser.External
			for i := range hostCap + 5 {
				many = append(many, parser.External{Host: fmt.Sprintf("h%03d.example", i), Reason: "bulk"})
			}
			in.Policy.Doc.Apps[1].External = many
			return in
		}},
		{"keepers", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Apps.System[0] = wl("Deployment", "farcast-system", "fatline", 1, 1, vecFatLineImage, vecShrikeImage)
			in.Network.Snapshot.Since = vectorNow.Add(-50 * time.Hour)
			in.Meta.Keepers = append(in.Meta.Keepers,
				config.Keeper{Device: "laptop", EnrolledAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
					Expires: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), LeafTokens: []string{"laptop-leaf-1"}},
				config.Keeper{Device: "nas", EnrolledAt: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC),
					Expires: time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC), LeafTokens: []string{"nas-leaf-1"}},
			)
			in.Network.Snapshot.Tunnel = append(in.Network.Snapshot.Tunnel,
				shrike.TunnelStat{Role: event.PeerKeeper, Peer: "a-leaf-from-another-machine", Route: "datasphered", Relayed: 1,
					LastSeen: vectorNow.Add(-3 * time.Hour)})
			return in
		}},
		{"release_incomplete", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Meta.Status = config.InstanceDeleting
			p := &sectionProblem{Kind: kindKubectlFailed, Message: "kubectl get deployments,statefulsets -n farcast-system -o json: " +
				"Unable to connect to the server: dial tcp: lookup gke-1a2b3c.europe-west4.gke.goog: no such host"}
			in.Apps = appsInput{Problem: p, Meter: meterInput{Problem: p}}
			in.Spend = spendInput{Problem: p}
			in.Policy = policyInput{Problem: p}
			tp := &sectionProblem{Kind: kindTimeout, Message: "the FatLine tunnel did not open: context deadline exceeded"}
			in.Network = networkInput{Problem: tp}
			in.Seal = sealInput{Problem: tp}
			return in
		}},
		{"nothing_read", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			p := &sectionProblem{Kind: kindGCloudSignedOut, Message: "kubectl get deployments,statefulsets -n farcast-system -o json: " +
				"ERROR: (gcloud.auth.print-access-token) There was a problem refreshing your current auth tokens: Reauthentication failed."}
			in.Apps = appsInput{Problem: p, Meter: meterInput{Problem: p}}
			in.Spend = spendInput{Problem: p}
			in.Policy = policyInput{Problem: p}
			tp := &sectionProblem{Kind: kindTunnelUnreachable, Message: "the FatLine tunnel did not open: remote error: tls: bad certificate"}
			in.Network = networkInput{Problem: tp}
			in.Seal = sealInput{Problem: tp}
			return in
		}},
		{"system_namespace_rows", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			// A manifest named farcast-system deploys into the system
			// namespace, which the map draws as components and never as a
			// group. Its policy entry, its allowed row and its refusal are
			// said in a caveat and counted on the boundary — never drawn at,
			// or alerted on, an application the document does not hold.
			in.Policy.Doc.Apps = append(in.Policy.Doc.Apps, policy.App{Name: "sync", Namespace: "farcast-system",
				CredentialSHA256: credentialOf("c"), External: []parser.External{{Host: "mirror.example", Reason: "mirroring"}}})
			in.Network.Snapshot.Allowed = append(in.Network.Snapshot.Allowed, shrike.HostStat{
				App: "sync", Namespace: "farcast-system", Host: "mirror.example", Port: "443", Declared: true, Allows: 5,
				LastSeen: vectorNow.Add(-5 * time.Minute)})
			in.Network.Snapshot.Violations = []shrike.Violation{{
				Severity: shrike.SeverityWarning, App: "sync", Namespace: "farcast-system", Host: "queue.example", Port: "5671",
				Reason: event.ReasonNotInAllowlist, Count: 6,
				FirstSeen: vectorNow.Add(-30 * time.Minute), LastSeen: vectorNow.Add(-10 * time.Minute),
			}}
			return in
		}},
		{"account_in_message", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			// GKE's refusal names the caller as its token spells it; gcloud's
			// credential error names the account it tried — the pinned one,
			// or a work identity whose token was cached for this instance's
			// context; a service account's address carries the project.
			forbidden := &sectionProblem{Kind: kindKubectlFailed, Message: "kubectl get deployments,statefulsets -n farcast-system -o json: " +
				`Error from server (Forbidden): deployments.apps is forbidden: User "Operator@Example.org" cannot list resource "deployments" ` +
				`in API group "apps" in the namespace "farcast-system": requires one of ["container.deployments.list"] permission(s).`}
			in.Apps = appsInput{Problem: forbidden, Meter: meterInput{Problem: forbidden}}
			in.Spend = spendInput{Problem: &sectionProblem{Kind: kindKubectlFailed, Message: "kubectl get configmap technocore-checkpoint " +
				`-n farcast-system --ignore-not-found -o json: Error from server (Forbidden): configmaps "technocore-checkpoint" is forbidden: ` +
				`User "reader@proj-atlas.iam.gserviceaccount.com" cannot get resource "configmaps" in the namespace "farcast-system"`}}
			in.Policy = policyInput{Problem: &sectionProblem{Kind: kindGCloudSignedOut, Message: "read the instance's egress policy: " +
				"kubectl get configmap fatline-policy -n farcast-system --ignore-not-found -o json: ERROR: (gcloud.auth.print-access-token) " +
				"Your current active account [someone@work.example] does not have any valid credentials\nPlease run:\n\n  $ gcloud auth login"}}
			return in
		}},
		{"removed_app_violation", func(t *testing.T) worldInputs {
			in := healthyInputs(t)
			in.Network.Snapshot.Violations = []shrike.Violation{{
				Severity: shrike.SeverityWarning, App: "worker", Namespace: "shop", Host: "queue.example", Port: "5671",
				Reason: event.ReasonNotInAllowlist, Count: 3,
				FirstSeen: vectorNow.Add(-30 * time.Minute), LastSeen: vectorNow.Add(-20 * time.Minute),
			}}
			return in
		}},
	}
}

// vectorBytes is a value exactly as the CLI prints it with -o json.
func vectorBytes(t *testing.T, r output.Result) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := (&output.Printer{Mode: output.ModeJSON, Out: &out, Err: &out}).Print(r); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// checkVector compares got against the committed vector, or rewrites it.
func checkVector(t *testing.T, dir, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", dir, name+".json")
	if os.Getenv(updateVectorsEnv) != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run with %s=1 to write it)", path, err, updateVectorsEnv)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from what the CLI now prints.\n got: %s\nwant: %s\nIf the change is deliberate, rerun with %s=1 and review the diff.",
			path, got, want, updateVectorsEnv)
	}
}

func TestWorldVectors(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range worldVectors() {
		t.Run(v.name, func(t *testing.T) {
			if seen[v.name] {
				t.Fatalf("two vectors are named %q", v.name)
			}
			seen[v.name] = true
			doc := buildWorld(v.inputs(t))
			got := vectorBytes(t, doc)
			// The same inputs, built again, are the same bytes.
			if again := vectorBytes(t, buildWorld(v.inputs(t))); !bytes.Equal(got, again) {
				t.Fatalf("two builds from the same inputs differ:\n%s\n%s", got, again)
			}
			checkVector(t, "world", v.name, got)
		})
	}
}
