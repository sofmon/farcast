//go:build !darwin

package keeper

import "fmt"

// ExcludeFromBackup reports that this build cannot make the guarantee.
//
// This is a refusal rather than a shrug, and the distinction matters. On macOS
// there is one backup pipeline with a documented exclusion attribute, so the
// promise is checkable. Elsewhere there is no single pipeline to exclude from
// — backups are whatever agent the operator installed — so FarCast cannot
// verify the absence of one, and saying "excluded" would be asserting
// something nobody checked.
//
// The operator can still make the guarantee themselves and record that they
// did; what this build will not do is make it on their behalf. See ADR 0008's
// keeper-fleet finding 2, which is where the rule comes from.
func ExcludeFromBackup(dir string) error {
	return fmt.Errorf(
		"keeper: this platform has no backup pipeline FarCast can verifiably exclude %s from, "+
			"so it cannot promise the bundle stays off a backup", dir)
}
