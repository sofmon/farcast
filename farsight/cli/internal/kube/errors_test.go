package kube

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	tkube "github.com/sofmon/farcast/technocore/kube"
)

func apiError(code int, reason, message string) *APIError {
	return &APIError{
		Method: "PATCH",
		Path:   "/apis/apps/v1/namespaces/web/deployments/api",
		Status: Status{Status: tkube.Status{Kind: "Status", Status: "Failure", Code: code, Reason: reason, Message: message}},
	}
}

// TestAPIErrorTextAndUnwrap: the text names the request and the server's own
// words, and Unwrap is tkube's mapping, so errors.Is works through wrapping.
func TestAPIErrorTextAndUnwrap(t *testing.T) {
	e := apiError(404, "NotFound", `deployments.apps "api" not found`)
	if want := `kube: PATCH /apis/apps/v1/namespaces/web/deployments/api: 404 NotFound: deployments.apps "api" not found`; e.Error() != want {
		t.Errorf("Error() = %q, want %q", e.Error(), want)
	}
	if want := "kube: PATCH /apis/apps/v1/namespaces/web/deployments/api: 503 Service Unavailable"; apiError(503, "", "").Error() != want {
		t.Errorf("Error() without reason or message = %q, want %q", apiError(503, "", "").Error(), want)
	}

	for _, c := range []struct {
		code   int
		reason string
		want   error
	}{
		{401, "Unauthorized", tkube.ErrUnauthorized},
		{403, "Forbidden", tkube.ErrForbidden},
		{404, "NotFound", tkube.ErrNotFound},
		{409, "AlreadyExists", tkube.ErrConflict},
		{409, "Conflict", tkube.ErrConflict},
	} {
		wrapped := fmt.Errorf("deploy: %w", apiError(c.code, c.reason, "m"))
		if !errors.Is(wrapped, c.want) {
			t.Errorf("%d %s does not unwrap to %v", c.code, c.reason, c.want)
		}
	}
	for _, code := range []int{400, 410, 422, 429, 500, 503} {
		if u := apiError(code, "", "").Unwrap(); u != nil {
			t.Errorf("%d unwraps to %v, want nil", code, u)
		}
	}
}

// TestStatusCauseWireNameIsReason pins the decode of a Status's details: a
// cause's type is the JSON key "reason" (meta/v1 StatusCause).
func TestStatusCauseWireNameIsReason(t *testing.T) {
	body := `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"Apply failed with 1 conflict",
	  "reason":"Conflict","code":409,
	  "details":{"name":"api","group":"apps","kind":"deployments",
	    "causes":[{"reason":"FieldManagerConflict","message":"conflict with \"technocore\"","field":".spec.replicas"}]}}`
	var s Status
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatal(err)
	}
	if s.Code != 409 || s.Reason != "Conflict" || s.Kind != "Status" {
		t.Errorf("embedded tkube.Status not decoded: %+v", s.Status)
	}
	if s.Details == nil || s.Details.Name != "api" || s.Details.Group != "apps" || s.Details.Kind != "deployments" || len(s.Details.Causes) != 1 {
		t.Fatalf("details = %+v", s.Details)
	}
	if c := s.Details.Causes[0]; c.Type != "FieldManagerConflict" || c.Field != ".spec.replicas" || c.Message == "" {
		t.Errorf("cause = %+v", c)
	}
}

// TestFieldConflicts: only a 409 carrying FieldManagerConflict causes is a
// server-side apply conflict, wrapped or not.
func TestFieldConflicts(t *testing.T) {
	conflict := apiError(409, "Conflict", "Apply failed with 2 conflicts")
	conflict.Status.Details = &StatusDetails{Causes: []StatusCause{
		{Type: "FieldManagerConflict", Field: ".spec.replicas"},
		{Type: "FieldValueInvalid", Field: ".spec.x"},
		{Type: "FieldManagerConflict", Field: ".spec.template.spec.containers[name=\"api\"].resources.requests.cpu"},
	}}
	causes, ok := FieldConflicts(fmt.Errorf("apply: %w", conflict))
	if !ok || len(causes) != 2 || causes[0].Field != ".spec.replicas" || causes[1].Type != "FieldManagerConflict" {
		t.Errorf("FieldConflicts = %+v, %v; want the two FieldManagerConflict causes", causes, ok)
	}

	alreadyExists := apiError(409, "AlreadyExists", "exists")
	invalid := apiError(422, "Invalid", "invalid")
	invalid.Status.Details = &StatusDetails{Causes: []StatusCause{{Type: "FieldManagerConflict"}}}
	otherCauses := apiError(409, "Conflict", "rv")
	otherCauses.Status.Details = &StatusDetails{Causes: []StatusCause{{Type: "FieldValueInvalid"}}}
	for name, err := range map[string]error{
		"a 409 AlreadyExists without details":  alreadyExists,
		"a 422 that carries the cause":         invalid,
		"a 409 whose causes are not conflicts": otherCauses,
		"not an APIError":                      errors.New("kube: something"),
		"nil":                                  nil,
	} {
		if causes, ok := FieldConflicts(err); ok || causes != nil {
			t.Errorf("%s: FieldConflicts = %+v, %v; want nil, false", name, causes, ok)
		}
	}
}

// TestRefusalTextIsExactlyItsMessage: a refusal's text is the pinned message
// alone, and it still unwraps to its sentinel.
func TestRefusalTextIsExactlyItsMessage(t *testing.T) {
	err := fmt.Errorf("open: %w", refuse(ErrEndpointRefused, "the instance records %q", "x"))
	if err.Error() != `open: the instance records "x"` {
		t.Errorf("text = %q", err.Error())
	}
	if !errors.Is(err, ErrEndpointRefused) || errors.Is(err, ErrCredentialInvalid) {
		t.Error("the refusal does not unwrap to exactly its sentinel")
	}
}
