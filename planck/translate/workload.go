package translate

import "text/template"

// workloadTemplate renders a translated deployment.
//
// Three things here differ from how FarCast deploys its OWN components, and
// each is a deliberate judgement rather than an oversight:
//
//   - **No runAsNonRoot.** Autopilot permits root, and requiring non-root
//     would reject a large share of perfectly ordinary application images for
//     a property FarCast cannot supply on the operator's behalf. FarCast's own
//     images run non-root because FarCast builds them.
//   - **No readOnlyRootFilesystem.** Applications write to /tmp; system
//     components do not.
//   - **allowPrivilegeEscalation: false, all capabilities dropped, and the
//     RuntimeDefault seccomp profile are NOT relaxed**, because none of them
//     stops an ordinary application from running. An app that needs a low port
//     publishes a high one and lets the Service map it.
var workloadTemplate = template.Must(template.New("workloads").Parse(`apiVersion: v1
kind: Namespace
metadata:
  name: {{.Namespace}}
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: {{.Deployment}}
{{- if .Instance}}
    farcast.sofmon.com/instance: {{.Instance}}
{{- end}}
{{- range .Apps}}
---
apiVersion: v1
kind: Secret
metadata:
  name: {{.Name}}-egress
  namespace: {{$.Namespace}}
  labels:
    app.kubernetes.io/name: {{.Name}}
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: {{$.Deployment}}
# This application's egress credential, inside the proxy address it is given.
#
# It rides as userinfo because that is the universal HTTP proxy convention —
# every standard client turns it into Proxy-Authorization on its own — which is
# what lets ADR 0013 change how an application is identified without changing
# the application (decision 2).
#
# What it authorises is exactly this app's declared hosts, nothing wider, and it
# is reminted on every deploy.
stringData:
  FARCAST_FATLINE_PROXY: {{.ProxyURL}}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{.Name}}
  namespace: {{$.Namespace}}
  labels:
    app.kubernetes.io/name: {{.Name}}
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: {{$.Deployment}}
data:
  # FARCAST_FATLINE_PROXY is NOT here. It carries this application's egress
  # credential (ADR 0013), so it lives in the Secret below — a ConfigMap is
  # readable by anything that can read ConfigMaps, and this value is what tells
  # FatLine which application is asking.
{{- if $.HasStorage}}
  FARCAST_STORAGE_ENDPOINT: https://{{$.StorageService}}.{{$.SystemNamespace}}.svc.cluster.local:{{$.StoragePort}}
  FARCAST_STORAGE_STATUS_ENDPOINT: https://{{$.StorageStatusService}}.{{$.SystemNamespace}}.svc.cluster.local:{{$.StorageStatusPort}}
  FARCAST_STORAGE_SCOPE: {{$.StorageScope}}
  # The address an app dials and the identity the keyholder must present are
  # different things and are carried separately, on purpose — the certificate
  # names an instance-scoped identity that never appears in public DNS.
  FARCAST_STORAGE_SERVER_NAME: {{$.StorageServerName}}
  # The instance CA certificate. A certificate, not a key: it is published in
  # every TLS handshake, and guarding it more than this would imply otherwise.
  FARCAST_STORAGE_CA: |
{{$.StorageCA}}
{{- end}}
{{- if $.HasSecrets}}
  # Where this application's secrets live, fully qualified. The SDK never
  # derives it: a prefix guessed one segment away addresses somebody else's
  # subtree, or one the keyholder does not protect.
  #
  # The path organises; it does not isolate. The keyholder's data path
  # authenticates the server only and every application declares the same
  # scope, so it cannot tell which application is asking and this prefix is
  # not a boundary between them (ADR 0017). What it does buy is that the
  # keyholder refuses application writes and deletes under secrets/, so a
  # secret is created and removed by the operator and by nobody else.
  FARCAST_SECRETS_PREFIX: {{$.SecretsPrefix}}{{.Name}}/
{{- end}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.Name}}
  namespace: {{$.Namespace}}
  labels:
    app.kubernetes.io/name: {{.Name}}
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: {{$.Deployment}}
    # TechnoCore stops applications and only applications (ADR 0009 decision
    # 6). Without this label the kernel treats the workload as unclassified
    # and protects it, which sounds safer and means a cost shutdown cannot
    # contain the thing it was deployed to contain.
    farcast.sofmon.com/tier: app
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: {{.Name}}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: {{.Name}}
        # Both labels go on the POD, not only the workload. A controller does
        # not copy its own labels onto the pods it creates, and TechnoCore
        # meters pods: without managed-by here the application is invisible to
        # the cost meter, which reports $0 and looks healthy while doing it.
        # Found on a live cluster during the 4.1 walk.
        app.kubernetes.io/managed-by: farcast
        app.kubernetes.io/part-of: {{$.Deployment}}
        farcast.sofmon.com/tier: app
    spec:
      # An application is handed no Kubernetes identity. It talks to FarCast's
      # services over the network with the credentials in its ConfigMap; it has
      # no business reaching the API server, and a projected token is the
      # difference between an app compromise and a cluster compromise.
      automountServiceAccountToken: false
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: {{.Name}}
          image: {{.Image}}
          envFrom:
            - configMapRef:
                name: {{.Name}}
            # The proxy address, with this application's egress credential in
            # it. There is no direct-dial fallback: the NetworkPolicy below
            # denies everything else, so an app that ignores the variable fails
            # closed rather than quietly bypassing the boundary (ADR 0005), and
            # one that reaches FatLine without the credential is refused
            # because FatLine cannot tell whose declarations to enforce.
            - secretRef:
                name: {{.Name}}-egress
          ports:
            - name: http
              containerPort: {{$.Port}}
          resources:
            requests:
              cpu: {{$.RequestCPUMilli}}m
              memory: {{$.RequestMemMiB}}Mi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
---
apiVersion: v1
kind: Service
metadata:
  name: {{.Name}}
  namespace: {{$.Namespace}}
  labels:
    app.kubernetes.io/name: {{.Name}}
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: {{$.Deployment}}
spec:
  # ClusterIP, never LoadBalancer. An application does not get its own public
  # address: the instance has exactly one point of presence and it is FatLine's
  # (ADR 0005). A translator that emitted a LoadBalancer would hand every app a
  # way around the boundary — and a standing bill nobody approved.
  type: ClusterIP
  selector:
    app.kubernetes.io/name: {{.Name}}
  ports:
    - name: http
      port: {{$.Port}}
      targetPort: http
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{.Name}}
  namespace: {{$.Namespace}}
  labels:
    app.kubernetes.io/name: {{.Name}}
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: {{$.Deployment}}
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: {{.Name}}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Reachable from its own deployment and nowhere else. Apps in one manifest
    # are one system and may talk; apps in another deployment are a different
    # tenant of the same instance.
    - from:
        - podSelector: {}
  egress:
    # DNS, by both paths a GKE cluster may use. The namespaceSelector covers
    # a cluster whose pods talk to kube-dns directly; the ipBlock covers
    # NodeLocal DNSCache, which listens on a LINK-LOCAL address on the node
    # and is what GKE Autopilot actually runs.
    #
    # Without the second one an application resolves nothing — not even
    # FatLine's proxy — and the failure looks like a broken application
    # rather than a policy. Found on the 4.2 walk.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
        - ipBlock:
            cidr: {{$.NodeLocalDNS}}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # FatLine's forward proxy — the only route to anything outside the
    # cluster. This is what makes the deny-by-default boundary real rather
    # than advisory: an app that ignores FARCAST_FATLINE_PROXY does not reach
    # the internet by another path, it simply fails.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{$.SystemNamespace}}
          podSelector:
            matchLabels:
              app.kubernetes.io/name: {{$.FatLineWorkload}}
      ports:
        - protocol: TCP
          port: {{$.FatLineEgressPort}}
{{- if $.HasStorage}}
    # The keyholder's data and status ports.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{$.SystemNamespace}}
          podSelector:
            matchLabels:
              app.kubernetes.io/name: {{$.StorageService}}
      ports:
        - protocol: TCP
          port: {{$.StoragePort}}
        - protocol: TCP
          port: {{$.StorageStatusPort}}
{{- end}}
{{- end}}
`))
