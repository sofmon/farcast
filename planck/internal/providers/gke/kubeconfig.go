package gke

import (
	"encoding/base64"
	"fmt"
)

// buildKubeconfig assembles a kubeconfig that reaches the cluster at endpoint,
// trusting caCert, and authenticates via the gke-gcloud-auth-plugin exec
// credential (the standard external-access method for GKE). FarCast's
// in-cluster components use the in-cluster config instead; this kubeconfig is
// for the operator/CLI side.
func buildKubeconfig(name, endpoint string, caCert []byte) []byte {
	ca := base64.StdEncoding.EncodeToString(caCert)
	return fmt.Appendf(nil, `apiVersion: v1
kind: Config
clusters:
- name: %[1]s
  cluster:
    server: https://%[2]s
    certificate-authority-data: %[3]s
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
`, name, endpoint, ca)
}
