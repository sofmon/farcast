package fetch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Report is what a successful fetch says about what it read.
//
// [ADR 0010] decision 6 is explicit that moving the manifest read into the
// instance costs auditability rather than prevention, and that the mitigation
// is these two values: a device that cannot reach the repository can at least
// record precisely which commit, and precisely which bytes, it approved — and
// any device that CAN reach the repository can check both out of band.
//
// [ADR 0010]: ../../docs/adr/0010-application-image-builds.md
type Report struct {
	// Commit is the resolved commit SHA. It is what the build is pinned to,
	// so a branch that moves between the read and the build cannot change
	// what was approved.
	Commit string

	// ManifestDigest is sha256 of the manifest file the instance parsed,
	// computed in the Pod.
	ManifestDigest string
}

// ParseReport reads a fetch Job's termination message.
//
// A fetch that could not find the manifest writes a sentence there instead,
// which is why an unparseable message is returned verbatim: the operator
// wants "no farcast at <commit> in <repo>", not a complaint about the format
// of a field they have never heard of.
func ParseReport(msg string) (Report, error) {
	var r Report
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return r, fmt.Errorf("fetch: the read reported nothing; the Pod may have been evicted before it finished")
	}
	for _, field := range strings.Fields(msg) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "commit":
			r.Commit = value
		case "manifest":
			r.ManifestDigest = value
		}
	}
	if !isHex(r.Commit, 40) && !isHex(r.Commit, 64) {
		return Report{}, fmt.Errorf("fetch: the read did not report a commit: %s", msg)
	}
	if _, ok := strings.CutPrefix(r.ManifestDigest, "sha256:"); !ok {
		return Report{}, fmt.Errorf("fetch: the read did not report a manifest digest: %s", msg)
	}
	if !isHex(strings.TrimPrefix(r.ManifestDigest, "sha256:"), 64) {
		return Report{}, fmt.Errorf("fetch: the read reported a malformed manifest digest: %s", msg)
	}
	return r, nil
}

// Verify checks the manifest the caller received against the digest the
// instance computed.
//
// The manifest arrives through the Pod's log and the digest through the Pod's
// status, so this catches the failure those two channels do not share: a log
// that was truncated or rotated leaves bytes that parse perfectly and are not
// what the instance read. It is not a defence against a dishonest instance —
// decision 6 says plainly that the gate was never that — and pretending
// otherwise here would be the overstatement this project treats as worse than
// not promising at all.
func (r Report) Verify(manifest []byte) error {
	sum := sha256.Sum256(manifest)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != r.ManifestDigest {
		return fmt.Errorf("fetch: the manifest that arrived hashes to %s but the instance read %s; "+
			"the log was truncated or altered in transit, and approving it would be approving different bytes",
			got, r.ManifestDigest)
	}
	return nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		switch ch := s[i]; {
		case ch >= '0' && ch <= '9', ch >= 'a' && ch <= 'f':
		default:
			return false
		}
	}
	return true
}
