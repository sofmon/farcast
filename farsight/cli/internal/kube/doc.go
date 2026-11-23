// Package kube is farcast's own client for an instance's Kubernetes API
// server (ADR 0023 decision 2, milestone M2). It replaces the kubectl
// subprocess, the gke-gcloud-auth-plugin and gcloud on the cluster path: it
// mints its own token in memory, speaks HTTPS and JSON to the instance's DNS
// endpoint, and writes with server-side apply.
//
// Its dependency surface is deliberately four packages beyond the standard
// library, all already linked into farcast, so the vendored module count does
// not move:
//   - github.com/sofmon/farcast/technocore/kube, as tkube, for its sentinels,
//     its Status and ObjectMeta, and its quantity parsers;
//   - cloud.google.com/go/auth, the root package only (never httptransport,
//     whose header helper would add Google's trust-boundary header to cluster
//     requests);
//   - github.com/goccy/go-yaml and its parser and ast packages, used only to
//     check and identify rendered documents, never to re-encode them.
//
// TestKubeImportsOnlyItsFour holds that list.
//
// The kernel never links this package: technocore cannot import
// farsight/cli/internal/... under Go's internal-package rule, and the kernel's
// own small client stays in technocore/kube (ADR 0009 decision 3).
//
// The pure half of the package needs no server and is tested by tables:
//   - endpoint.go classifies a recorded endpoint (ParseEndpoint);
//   - credential.go parses a service-account key without deciding where it
//     may go (ParseServiceAccountJSON);
//   - kinds.go is the table of kinds farcast applies;
//   - stream.go splits and checks a rendered stream (SplitStream);
//   - rollout.go and reads.go port kubectl's rollout status rules and its
//     choice of a workload's pod for logs;
//   - readerkey.go makes the reader identity's key and generic certificate.
//
// federated.go is the identity path's wire code (ADR 0024 decision 8), wired
// into no command until M3b.
package kube
