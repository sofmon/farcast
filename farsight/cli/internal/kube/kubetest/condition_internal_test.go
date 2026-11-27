package kubetest

import "testing"

// TestConditionRoleIDReadsD3sFormAlone: the STS fake evaluates a provider's
// stored condition only in D3's exact form, one role ID in both places, and
// holds any other text for nothing. AddProvider writes only that form, so
// the rule is held here, where the stored text can be another.
func TestConditionRoleIDReadsD3sFormAlone(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	const other = "fedcba9876543210fedcba9876543210"
	if got, ok := conditionRoleID(conditionIssuerPart + id + conditionMiddle + id + conditionEnd); !ok || got != id {
		t.Errorf("D3's condition: %q, %v; want %q", got, ok, id)
	}
	for name, condition := range map[string]string{
		"two IDs":                 conditionIssuerPart + id + conditionMiddle + other + conditionEnd,
		"an ID out of shape":      conditionIssuerPart + "ABC" + conditionMiddle + "ABC" + conditionEnd,
		"a space more":            conditionIssuerPart + id + "' &&  assertion.subject.dn.cn == '" + id + conditionEnd,
		"the subject alone":       "assertion.subject.dn.cn == '" + id + "'",
		"no closing quote":        conditionIssuerPart + id + conditionMiddle + id,
		"a clause more":           conditionIssuerPart + id + conditionMiddle + id + conditionEnd + " || true",
		"the empty condition":     "",
		"the issuer's half alone": conditionIssuerPart + id + conditionEnd,
	} {
		if got, ok := conditionRoleID(condition); ok {
			t.Errorf("%s: %q holds; want nothing", name, got)
		}
	}
}
