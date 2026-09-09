package cli

import (
	"io"
	"strings"
)

// The builder pushes under its own cloud identity, and FarCast does not grant
// that identity push access — see writePushGrant for why, and for what the
// reason actually is.
//
// This file exists because the grant used to be printed in exactly one place:
// the SUCCESS result of `farcast build`. So it appeared after a build that had
// already worked, and never on the failure it explains. `farcast run` did not
// print it at all, though [the 4.3 runbook] said it did. The 5.1b walk hit
// precisely that: a build failed at push with a raw Kaniko error, several
// minutes of clone and build already paid for, and nothing anywhere naming the
// one command that fixes it.
//
// [the 4.3 runbook]: ../../../../docs/runbooks/phase-4-3-validation.md

// pushDenied reports whether a build's own output is Artifact Registry
// refusing the push.
//
// Matched on the permission the registry names rather than on prose: the
// builder is a third-party image this project has pinned but does not control
// ([ADR 0011]), so its wording is not FarCast's to rely on — but the IAM
// permission in the cloud's own error is.
//
// [ADR 0011]: ../../../../docs/adr/0011-build-toolchain-mirroring.md
func pushDenied(logs string) bool {
	if strings.Contains(logs, "artifactregistry.repositories.uploadArtifacts") {
		return true
	}
	// The generic shape, for a registry that phrases it differently: a denial
	// that is specifically about pushing.
	lower := strings.ToLower(logs)
	return strings.Contains(lower, "denied") &&
		(strings.Contains(lower, "push permission") || strings.Contains(lower, "push access"))
}

// pushGrant describes the identity that needs the grant and the repository it
// needs it on.
type pushGrant struct {
	Instance       string
	Project        string
	Region         string
	Namespace      string
	ServiceAccount string
}

// writePushGrant prints the exact command that grants the builder push.
//
// FarCast does not apply it. The reason is NOT that this CLI cannot change a
// repository's IAM — it demonstrably can, and does: `EnsureRegistry` already
// reads and writes that same repository's policy to give the cluster's nodes
// pull access. The reason is what the grant is FOR. The builder executes the
// operator's own Containerfile, so push access means code FarCast did not
// write can put images into the one registry this instance runs from. That is
// a decision for a human, once, deliberately — not something an install should
// arrange quietly on their behalf.
func writePushGrant(w io.Writer, g pushGrant) {
	project := orPlaceholder(g.Project)
	region := g.Region
	if region == "" {
		region = "<region>"
	}
	fprintf(w, "  PROJNUM=$(gcloud projects describe %s --format='value(projectNumber)')\n", project)
	fprintf(w, "  PRINCIPAL=\"principal://iam.googleapis.com/projects/$PROJNUM/locations/global/workloadIdentityPools/%s.svc.id.goog/subject/ns/%s/sa/%s\"\n",
		project, g.Namespace, g.ServiceAccount)
	fprintf(w, "  gcloud artifacts repositories add-iam-policy-binding farcast-%s \\\n", g.Instance)
	fprintf(w, "    --location %s --member \"$PRINCIPAL\" --role roles/artifactregistry.writer\n", region)
}

// explainPushDenial turns a build failure that is really a missing grant into
// the instruction that fixes it, and returns whether it did.
//
// It writes to stderr rather than into the returned error because the grant is
// four lines of shell: an error string is the wrong shape for something an
// operator is meant to copy.
func explainPushDenial(w io.Writer, logs string, g pushGrant) bool {
	if !pushDenied(logs) {
		return false
	}
	fprintln(w)
	fprintln(w, "That is not a problem with the Containerfile: the build worked and the push")
	fprintln(w, "was refused. The builder pushes under its own cloud identity, and that")
	fprintln(w, "identity has not been granted write access to this instance's registry:")
	fprintln(w)
	writePushGrant(w, g)
	fprintln(w)
	fprintln(w, "The grant is on the ONE repository, not the project. Artifact Registry can")
	fprintln(w, "take a few minutes to honour it on the registry endpoint even once the API")
	fprintln(w, "reports it, so a retry that fails immediately is worth repeating once.")
	return true
}
