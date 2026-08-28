package keyholder

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"testing"

	"github.com/sofmon/farcast/datasphere"
)

// The SDK is a separate module and cannot import this package, so the wire
// codes exist in two files. This asserts the two copies agree.
//
// If it fails, make them match. Do not relax the assertion: an application
// deployed against one build must classify correctly against another, and a
// code that means one thing here and another there is a misclassification an
// application acts on — writing over intact data, or reporting loss that did
// not happen.
func TestWireCodesMatchTheSDK(t *testing.T) {
	ours := constBlock(t, "wire.go")
	theirs := constBlock(t, "../../sdk/go/wire.go")

	for name, want := range map[string]string{
		"CodeSealed": CodeSealed, "CodeNotFound": CodeNotFound,
		"CodeIntegrity": CodeIntegrity, "CodeInvalidKey": CodeInvalidKey,
		"CodeTooLarge": CodeTooLarge, "CodePermission": CodePermission,
	} {
		got, ok := theirs[name]
		if !ok {
			t.Errorf("the SDK does not declare %s; every code an application classifies must exist on both sides", name)
			continue
		}
		if got != want {
			t.Errorf("%s = %q here and %q in the SDK", name, want, got)
		}
		if ours[name] != want {
			t.Errorf("%s parsed as %q from our own source", name, ours[name])
		}
	}

	// The SDK must not carry a code this keyholder never emits: an
	// application would branch on a condition that cannot arrive.
	for name := range theirs {
		if _, ok := ours[name]; !ok {
			t.Errorf("the SDK declares %s, which this keyholder never emits", name)
		}
	}
}

var constRe = regexp.MustCompile(`(?m)^\s*(Code[A-Za-z]+)\s*=\s*"([^"]*)"`)

func constBlock(t *testing.T, path string) map[string]string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]string{}
	for _, m := range constRe.FindAllStringSubmatch(string(src), -1) {
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatalf("no Code constants found in %s", path)
	}
	return out
}

func TestClassify(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{nil, http.StatusOK, ""},
		{ErrSealed, http.StatusServiceUnavailable, CodeSealed},
		{fmt.Errorf("wrapped: %w", ErrSealed), http.StatusServiceUnavailable, CodeSealed},
		{ErrOutOfScope, http.StatusForbidden, CodePermission},
		{datasphere.ErrObjectNotFound, http.StatusNotFound, CodeNotFound},
		{datasphere.ErrIntegrity, http.StatusBadGateway, CodeIntegrity},
		{datasphere.ErrUnknownKey, http.StatusBadGateway, CodeIntegrity},
		{datasphere.ErrInvalidKey, http.StatusBadRequest, CodeInvalidKey},
		{datasphere.ErrTooLarge, http.StatusRequestEntityTooLarge, CodeTooLarge},
		{ErrOperatorHold, http.StatusConflict, CodeOperatorHold},
		{ErrGenerationTooOld, http.StatusConflict, CodeGenerationOld},
		{ErrInstanceMismatch, http.StatusConflict, CodeInstanceMismatch},
		{datasphere.ErrBundleInvalid, http.StatusBadRequest, CodeBadRequest},
		{errors.New("something unforeseen"), http.StatusInternalServerError, ""},
	}
	for _, tc := range cases {
		status, code := classify(tc.err)
		if status != tc.status || code != tc.code {
			t.Errorf("classify(%v) = %d/%q, want %d/%q", tc.err, status, code, tc.status, tc.code)
		}
	}
}

// The two confusions ADR 0008 decision 7 names. A seal must never reach an
// application as absence (it would start over and overwrite intact data) and
// an unknown key must never reach it as absence either (same outcome, second
// route).
func TestSealAndIntegrityAreNeverNotFound(t *testing.T) {
	for _, err := range []error{ErrSealed, datasphere.ErrUnknownKey, datasphere.ErrIntegrity} {
		if _, code := classify(err); code == CodeNotFound {
			t.Errorf("classify(%v) produced %q — silent data loss by a second route", err, CodeNotFound)
		}
	}
}

// An unrecognized error must not be guessed at.
func TestUnknownErrorsGetNoCode(t *testing.T) {
	status, code := classify(errors.New("brand new failure mode"))
	if code != "" {
		t.Errorf("an unrecognized error was given code %q; it must carry none", code)
	}
	if status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", status)
	}
}
