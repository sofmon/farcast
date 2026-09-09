package cli

import (
	"bytes"
	"strings"
	"testing"
)

// The exact string Artifact Registry returned on the 5.1b walk. Matching the
// permission rather than the prose is deliberate: the builder is a pinned
// third-party image whose wording FarCast does not control.
const arDenial = `error checking push permissions -- make sure you entered the correct tag name, ` +
	`and that you are authenticated correctly, and try again: checking push permission for ` +
	`"us-central1-docker.pkg.dev/proj/farcast-p51b/app/demo/reacher:abc": creating push check transport ` +
	`for us-central1-docker.pkg.dev failed: GET https://us-central1-docker.pkg.dev/v2/token?scope=... : ` +
	`DENIED: Permission 'artifactregistry.repositories.uploadArtifacts' denied on resource ` +
	`'//artifactregistry.googleapis.com/projects/proj/locations/us-central1/repositories/farcast-p51b'`

func TestARefusedPushIsRecognised(t *testing.T) {
	if !pushDenied(arDenial) {
		t.Error("the denial Artifact Registry actually returns was not recognised")
	}
	// A Containerfile that genuinely failed must not be mistaken for one.
	for _, notIt := range []string{
		"error building image: failed to execute command: exit status 1",
		"/bin/sh: apk: not found",
		"",
		"COPY failed: no source files were specified",
	} {
		if pushDenied(notIt) {
			t.Errorf("a real build failure was reported as a permission problem: %q", notIt)
		}
	}
}

// The failure path is the only place this matters. Printing it after a build
// that already worked — which is what the code did — is printing it when it
// cannot be needed.
func TestAPushDenialExplainsItselfWithTheCommandThatFixesIt(t *testing.T) {
	var buf bytes.Buffer
	if !explainPushDenial(&buf, arDenial, pushGrant{
		Instance: "p51b", Project: "proj", Region: "us-central1",
		Namespace: "farcast-system", ServiceAccount: "farcast-builder",
	}) {
		t.Fatal("the denial was not explained")
	}
	out := buf.String()
	t.Log("\n" + out)
	for _, want := range []string{
		"not a problem with the Containerfile",
		"add-iam-policy-binding farcast-p51b",
		"--location us-central1",
		"roles/artifactregistry.writer",
		"ns/farcast-system/sa/farcast-builder",
		"ONE repository, not the project",
		// The walk's own observation: the registry endpoint lagged the API.
		"few minutes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the explanation is missing %q", want)
		}
	}
	// No placeholder survives when the instance knows its own region and
	// project — the command exists to be copied.
	for _, leftover := range []string{"<region>", "<project>"} {
		if strings.Contains(out, leftover) {
			t.Errorf("the copyable command still contains %q", leftover)
		}
	}
}

func TestAnOrdinaryBuildFailureIsNotExplainedAway(t *testing.T) {
	var buf bytes.Buffer
	if explainPushDenial(&buf, "error building image: exit status 1", pushGrant{Instance: "p"}) {
		t.Error("a Containerfile failure was explained as a missing grant")
	}
	if buf.Len() != 0 {
		t.Errorf("it wrote %q anyway", buf.String())
	}
}

// When the instance's own metadata is missing the placeholders come back,
// because a half-filled command is worse than one that shows its gaps.
func TestPlaceholdersSurviveWhenNothingIsKnown(t *testing.T) {
	var buf bytes.Buffer
	writePushGrant(&buf, pushGrant{Instance: "x", Namespace: "ns", ServiceAccount: "sa"})
	out := buf.String()
	if !strings.Contains(out, "<project>") || !strings.Contains(out, "<region>") {
		t.Errorf("an unknown project or region did not show as a placeholder:\n%s", out)
	}
}
