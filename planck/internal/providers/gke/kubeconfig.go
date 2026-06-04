package gke

import "fmt"

// buildKubeconfig assembles a kubeconfig that reaches the cluster at its
// control-plane DNS endpoint and authenticates via the gke-gcloud-auth-plugin
// exec credential (the standard external-access method for GKE).
//
// No certificate-authority-data is embedded: the DNS endpoint is fronted by
// Google with a publicly-trusted certificate (ADR 0004), so clients validate it
// against the system trust store rather than the cluster's self-signed CA.
// FarCast's in-cluster components use the in-cluster config instead; this
// kubeconfig is for the operator/CLI side.
func buildKubeconfig(name, endpoint string) []byte {
	return fmt.Appendf(nil, `apiVersion: v1
kind: Config
clusters:
- name: %[1]s
  cluster:
    server: https://%[2]s
contexts:
- name: %[1]s
  context:
    cluster: %[1]s
    user: %[1]s
current-context: %[1]s
users:
- name: %[1]s
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: gke-gcloud-auth-plugin
      provideClusterInfo: true
`, name, endpoint)
}
