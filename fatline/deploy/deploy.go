// Package deploy renders FatLine's own Kubernetes workload — the Namespace,
// mTLS Secret, Deployment, and Service that run FatLine inside an instance — as
// a multi-document YAML apply stream. FatLine owns the shape of how it is
// deployed; `farcast connect` (2.3) pipes the output to `kubectl apply -f -`.
//
// It is the one-off precursor to Planck's general manifest→workload translator
// (4.2). It deliberately renders plain YAML rather than depending on a
// Kubernetes client library — the operator-side toolchain stays minimal-deps
// (the CLI uses kubectl, ADR 0006). Every container carries resource requests
// and drops privilege, so the workload is GKE Autopilot-admission-compliant
// (ADR 0003).
package deploy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"text/template"
)

// Carrier is how the operator's tunnel traffic reaches FatLine.
type Carrier string

const (
	// CarrierLoadBalancer fronts FatLine with a public, mTLS-gated L4 passthrough
	// load balancer (the default 2.3 point of presence, ADR 0005).
	CarrierLoadBalancer Carrier = "LoadBalancer"
	// CarrierClusterIP exposes FatLine only inside the cluster (the control-plane
	// port-forward fallback's service type; bound in a later phase).
	CarrierClusterIP Carrier = "ClusterIP"
)

// Defaults for the FatLine workload.
const (
	DefaultNamespace  = "farcast-system"
	DefaultName       = "fatline"
	DefaultTunnelPort = 8443
	DefaultEgressPort = 3128
	secretName        = "fatline-mtls"
	tlsMountPath      = "/etc/fatline/tls"
)

// Config parameterizes the rendered FatLine workload. The Secret carries the CA
// *certificate* (to verify operator clients) plus FatLine's own server leaf+key
// — never the CA private key, which stays on the operator's machine.
type Config struct {
	Namespace  string  // default DefaultNamespace
	Name       string  // default DefaultName
	Image      string  // FatLine container image (required)
	Carrier    Carrier // default CarrierLoadBalancer
	TunnelPort int     // default DefaultTunnelPort
	EgressPort int     // default DefaultEgressPort

	CACertPEM     []byte
	ServerCertPEM []byte
	ServerKeyPEM  []byte
}

func (c *Config) withDefaults() {
	if c.Namespace == "" {
		c.Namespace = DefaultNamespace
	}
	if c.Name == "" {
		c.Name = DefaultName
	}
	if c.Carrier == "" {
		c.Carrier = CarrierLoadBalancer
	}
	if c.TunnelPort == 0 {
		c.TunnelPort = DefaultTunnelPort
	}
	if c.EgressPort == 0 {
		c.EgressPort = DefaultEgressPort
	}
}

// Render produces the Kubernetes apply stream (Namespace, Secret, Deployment,
// Service) as multi-document YAML for `kubectl apply -f -`.
func Render(c Config) ([]byte, error) {
	c.withDefaults()
	if c.Image == "" {
		return nil, errors.New("deploy: FatLine image is required")
	}
	if len(c.CACertPEM) == 0 || len(c.ServerCertPEM) == 0 || len(c.ServerKeyPEM) == 0 {
		return nil, errors.New("deploy: incomplete mTLS material (need CA cert + server leaf+key)")
	}
	if c.Carrier != CarrierLoadBalancer && c.Carrier != CarrierClusterIP {
		return nil, fmt.Errorf("deploy: unknown carrier %q", c.Carrier)
	}

	data := templateData{
		Namespace:  c.Namespace,
		Name:       c.Name,
		Image:      c.Image,
		Carrier:    string(c.Carrier),
		TunnelPort: c.TunnelPort,
		EgressPort: c.EgressPort,
		SecretName: secretName,
		MountPath:  tlsMountPath,
		CACert:     base64.StdEncoding.EncodeToString(c.CACertPEM),
		ServerCert: base64.StdEncoding.EncodeToString(c.ServerCertPEM),
		ServerKey:  base64.StdEncoding.EncodeToString(c.ServerKeyPEM),
	}
	var buf bytes.Buffer
	if err := workloadTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("deploy: render workload: %w", err)
	}
	return buf.Bytes(), nil
}

type templateData struct {
	Namespace  string
	Name       string
	Image      string
	Carrier    string
	TunnelPort int
	EgressPort int
	SecretName string
	MountPath  string
	CACert     string
	ServerCert string
	ServerKey  string
}

// workloadTemplate renders an Autopilot-compliant FatLine workload: resource
// requests on the container, no privilege, runs as non-root, drops all caps.
// FatLine terminates mTLS in userspace, so only the tunnel port is exposed; the
// egress proxy is in-cluster only (apps reach it via the SDK env var, 4.2).
var workloadTemplate = template.Must(template.New("fatline").Parse(`apiVersion: v1
kind: Namespace
metadata:
  name: {{.Namespace}}
  labels:
    app.kubernetes.io/managed-by: farcast
---
apiVersion: v1
kind: Secret
metadata:
  name: {{.SecretName}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: fatline
type: Opaque
data:
  ca.crt: {{.CACert}}
  server.crt: {{.ServerCert}}
  server.key: {{.ServerKey}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: fatline
    app.kubernetes.io/managed-by: farcast
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: fatline
  template:
    metadata:
      labels:
        app.kubernetes.io/name: fatline
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        # The mTLS material is mounted 0440 and owned by this group. Without
        # fsGroup the kubelet leaves the secret owned by root, and FatLine —
        # which runs as 65532 and must not run as root — cannot read the key it
        # was given. (Caught by the first live deploy: permission denied on
        # server.crt, crash-looping.)
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: fatline
          image: {{.Image}}
          args:
            - --tunnel-listen=:{{.TunnelPort}}
            - --egress-listen=:{{.EgressPort}}
            - --cert={{.MountPath}}/server.crt
            - --key={{.MountPath}}/server.key
            - --ca={{.MountPath}}/ca.crt
          ports:
            - name: tunnel
              containerPort: {{.TunnelPort}}
            - name: egress
              containerPort: {{.EgressPort}}
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: mtls
              mountPath: {{.MountPath}}
              readOnly: true
      volumes:
        - name: mtls
          secret:
            secretName: {{.SecretName}}
            # 0440: readable by the running user's group, never world-readable,
            # never writable. Paired with fsGroup above — 0400 would be
            # root-only and the non-root container could not read it.
            defaultMode: 288
---
apiVersion: v1
kind: Service
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: fatline
    app.kubernetes.io/managed-by: farcast
spec:
  type: {{.Carrier}}
  selector:
    app.kubernetes.io/name: fatline
  ports:
    - name: tunnel
      port: {{.TunnelPort}}
      targetPort: tunnel
`))
