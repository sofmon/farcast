package fetch

import (
	"strings"
	"text/template"
)

// indent shifts a block scalar's body to its position in the document. A
// script that lands one space out is a Job Kubernetes rejects at apply time,
// which is a long way from the mistake.
func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l == "" {
			continue // no trailing whitespace on blank lines
		}
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

var workloadTemplate = template.Must(template.New("fetch").
	Funcs(template.FuncMap{"indent": indent}).
	Parse(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{.ServiceAccount}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: farcast-fetcher
    app.kubernetes.io/managed-by: farcast
# Deliberately separate from farcast-builder, and deliberately unbound.
#
# The builder's account carries a Workload Identity grant that can write to the
# instance's registry. A fetch reads one text file and pushes nothing, so it
# gets an identity with no grant at all — and, below, a policy that cannot even
# reach the endpoint an identity would be minted at.
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{.JobName}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: farcast-fetcher
    app.kubernetes.io/managed-by: farcast
# What a manifest read may reach: a Git host, and DNS to find it.
#
# This is strictly tighter than the build's policy next door. The build is
# allowed the cloud metadata server because it must mint a token to push; a
# fetch pushes nothing, so link-local is excluded here without an exception
# (ADR 0010 decision 11).
{{- if .EgressHosts}}
# Declared for this read: {{range .EgressHosts}}{{.}} {{end}}
{{- end}}
spec:
  podSelector:
    matchLabels:
      farcast.sofmon.com/fetch: {{.JobName}}
  policyTypes:
    - Ingress
    - Egress
  # Nothing may reach a fetch. It serves nothing and listens for nothing.
  ingress: []
  egress:
    # DNS, by both of the paths a GKE cluster may use: kube-dns directly, and
    # NodeLocal DNSCache on a link-local address that the rule below otherwise
    # excludes.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
        - ipBlock:
            cidr: {{.NodeLocalDNS}}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # The Git host, over TLS. It is outside the cluster and cannot be named
    # more precisely than this without a hostname-aware policy engine.
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              # The cluster's own ranges: a fetch has no business reaching
              # another pod, a Service, or the node it runs on.
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
              # Link-local in full, with no exception carved out of it. This
              # is the line that makes the fetch weaker than the build.
              - 169.254.0.0/16
      ports:
        - protocol: TCP
          port: 443
---
apiVersion: batch/v1
kind: Job
metadata:
  name: {{.JobName}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: farcast-fetcher
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: {{.Instance}}
    farcast.sofmon.com/fetch: {{.JobName}}
    # A read is instance machinery, not an application. A cost shutdown stops
    # applications; the Job's own deadline is what bounds this one's cost.
    farcast.sofmon.com/tier: system
spec:
  # One attempt. A repository that does not exist, a ref that does not resolve
  # and a missing manifest all fail identically on a second try.
  backoffLimit: 0
  activeDeadlineSeconds: {{.DeadlineSeconds}}
  ttlSecondsAfterFinished: {{.TTLSeconds}}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: farcast-fetcher
        app.kubernetes.io/managed-by: farcast
        app.kubernetes.io/part-of: {{.Instance}}
        farcast.sofmon.com/fetch: {{.JobName}}
        farcast.sofmon.com/tier: system
    spec:
      restartPolicy: Never
      serviceAccountName: {{.ServiceAccount}}
      securityContext:
        # The image runs as a non-root user and the clone lands on an
        # emptyDir. Without this the volume is root-owned and the first write
        # fails.
        fsGroup: {{.FSGroup}}
        seccompProfile:
          type: RuntimeDefault
      volumes:
        - name: workspace
          emptyDir: {}
        - name: tmp
          emptyDir: {}
      containers:
        - name: git
          image: {{.Fetcher}}
          # The image's entrypoint is git itself, so the shell is asked for
          # explicitly rather than inherited.
          command: ["/bin/sh", "-c"]
          args:
            - |
{{indent .Script 14}}
          env:
            - name: FARCAST_REPO
              value: "{{.Repo}}"
            - name: FARCAST_REF
              value: "{{.Ref}}"
            - name: FARCAST_MANIFEST
              value: "{{.Manifest}}"
{{- if .GitSecret}}
            - name: GIT_USERNAME
              valueFrom:
                secretKeyRef:
                  name: {{.GitSecret}}
                  key: {{.SecretGitUser}}
            - name: GIT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{.GitSecret}}
                  key: {{.SecretGitToken}}
{{- end}}
          volumeMounts:
            - name: workspace
              mountPath: {{.WorkDir}}
            - name: tmp
              mountPath: /tmp
          resources:
            requests:
              cpu: {{.RequestCPUMilli}}m
              memory: {{.RequestMemMiB}}Mi
          securityContext:
            allowPrivilegeEscalation: false
            # Unlike the builder next door, this one CAN have a read-only
            # root: it clones into a volume rather than unpacking image layers
            # into its own filesystem.
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          terminationMessagePolicy: File
`))
