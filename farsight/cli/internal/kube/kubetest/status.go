package kubetest

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// wireStatus is meta/v1's Status as the API server writes it, in its field
// order. kubetest writes its own wire types rather than kube's, so a client
// that read a field under the wrong name fails against this fake.
type wireStatus struct {
	Kind       string       `json:"kind"`
	APIVersion string       `json:"apiVersion"`
	Metadata   struct{}     `json:"metadata"`
	Status     string       `json:"status"`
	Message    string       `json:"message,omitempty"`
	Reason     string       `json:"reason,omitempty"`
	Details    *wireDetails `json:"details,omitempty"`
	Code       int          `json:"code"`
}

// wireDetails is meta/v1's StatusDetails.
type wireDetails struct {
	Name   string      `json:"name,omitempty"`
	Group  string      `json:"group,omitempty"`
	Kind   string      `json:"kind,omitempty"`
	UID    string      `json:"uid,omitempty"`
	Causes []wireCause `json:"causes,omitempty"`
}

// wireCause is meta/v1's StatusCause. Its Type field's wire name is "reason"
// (`json:"reason,omitempty"` on metav1.StatusCause.Type).
type wireCause struct {
	Type    string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
	Field   string `json:"field,omitempty"`
}

// googleError is the JSON error Google's front ends answer with: not a
// Kubernetes Status.
type googleError struct {
	Error googleErrorBody `json:"error"`
}

type googleErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// defaultReason is the Kubernetes StatusReason the API server gives a code
// (meta/v1 StatusReason* constants).
func defaultReason(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "BadRequest"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusNotFound:
		return "NotFound"
	case http.StatusMethodNotAllowed:
		return "MethodNotAllowed"
	case http.StatusNotAcceptable:
		return "NotAcceptable"
	case http.StatusConflict:
		return "Conflict"
	case http.StatusGone:
		return "Expired"
	case http.StatusRequestEntityTooLarge:
		return "RequestEntityTooLarge"
	case http.StatusUnsupportedMediaType:
		return "UnsupportedMediaType"
	case http.StatusUnprocessableEntity:
		return "Invalid"
	case http.StatusTooManyRequests:
		return "TooManyRequests"
	case http.StatusInternalServerError:
		return "InternalError"
	case http.StatusServiceUnavailable:
		return "ServiceUnavailable"
	case http.StatusGatewayTimeout:
		return "Timeout"
	}
	return ""
}

// googleStatus is the canonical status name Google's JSON errors carry.
func googleStatus(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "INVALID_ARGUMENT"
	case http.StatusUnauthorized:
		return "UNAUTHENTICATED"
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "ABORTED"
	case http.StatusTooManyRequests:
		return "RESOURCE_EXHAUSTED"
	case http.StatusServiceUnavailable:
		return "UNAVAILABLE"
	case http.StatusInternalServerError:
		return "INTERNAL"
	}
	return "UNKNOWN"
}

// writeStatus answers code with a Failure Status. An empty reason is the
// code's own.
func writeStatus(w http.ResponseWriter, code int, reason, message string, details *wireDetails) {
	if reason == "" {
		reason = defaultReason(code)
	}
	writeJSON(w, code, wireStatus{
		Kind: "Status", APIVersion: "v1", Status: "Failure",
		Message: message, Reason: reason, Details: details, Code: code,
	})
}

// writeJSON answers code with v as JSON.
func writeJSON(w http.ResponseWriter, code int, v any) {
	writeRaw(w, code, "application/json", mustMarshal(v))
}

func writeRaw(w http.ResponseWriter, code int, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// writeAnswer writes an answer a closure or a script gave: 0 is 200, and a
// body that begins with { or [ is JSON.
func writeAnswer(w http.ResponseWriter, code int, body []byte) {
	if code == 0 {
		code = http.StatusOK
	}
	ct := "text/plain; charset=utf-8"
	if t := bytes.TrimLeft(body, " \t\r\n"); len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		ct = "application/json"
	}
	writeRaw(w, code, ct, body)
}

// writeInjected writes one answer Fail queued (its comment has the rules).
func writeInjected(w http.ResponseWriter, f injected, ri requestInfo, email string) {
	st := f.st.Status // the embedded tkube.Status: kind, status, message, reason, code
	if f.code == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	if st.Kind != "" && st.Kind != "Status" {
		msg := st.Message
		if msg == "" {
			msg = "The caller does not have permission"
		}
		writeJSON(w, f.code, googleError{Error: googleErrorBody{Code: f.code, Message: msg, Status: googleStatus(f.code)}})
		return
	}
	body := wireStatus{Kind: "Status", APIVersion: "v1", Status: st.Status, Message: st.Message, Reason: st.Reason, Code: st.Code}
	if body.Code == 0 {
		body.Code = f.code
	}
	if body.Status == "" {
		body.Status = "Failure"
		if f.code < 400 {
			body.Status = "Success"
		}
	}
	if body.Reason == "" {
		body.Reason = defaultReason(f.code)
	}
	if sd := f.st.Details; sd != nil {
		d := &wireDetails{Name: sd.Name, Group: sd.Group, Kind: sd.Kind}
		for _, c := range sd.Causes {
			d.Causes = append(d.Causes, wireCause{Type: c.Type, Message: c.Message, Field: c.Field})
		}
		body.Details = d
	}
	if body.Message == "" {
		if f.code == http.StatusForbidden {
			body.Message = forbiddenMessage(ri, email)
			if body.Details == nil {
				body.Details = &wireDetails{Name: ri.authzName, Group: ri.group, Kind: ri.resource}
			}
		} else {
			body.Message = http.StatusText(f.code)
		}
	}
	writeJSON(w, f.code, body)
}

// writeForbidden is the API server's answer to a request no rule allows.
func writeForbidden(w http.ResponseWriter, ri requestInfo, email string) {
	var details *wireDetails
	if ri.resourceRequest {
		details = &wireDetails{Name: ri.authzName, Group: ri.group, Kind: ri.resource}
	}
	writeStatus(w, http.StatusForbidden, "", forbiddenMessage(ri, email), details)
}

// forbiddenMessage is the API server's text for a denied request: the
// authorizer's "User %q cannot %s resource %q in API group %q in the
// namespace %q" (or "at the cluster scope"), behind NewForbidden's
// "<resource>[.<group>] [<name>] is forbidden: ". A port, from memory and
// not fetched, of k8s.io/apiserver v0.37.2
// pkg/endpoints/handlers/responsewriters/errors.go (forbiddenMessage) and of
// k8s.io/apimachinery v0.37.2 pkg/api/errors (NewForbidden).
func forbiddenMessage(ri requestInfo, email string) string {
	if !ri.resourceRequest {
		return fmt.Sprintf("forbidden: User %q cannot %s path %q", email, ri.verb, ri.path)
	}
	resource := ri.resource
	if ri.subresource != "" {
		resource += "/" + ri.subresource
	}
	why := fmt.Sprintf("User %q cannot %s resource %q in API group %q at the cluster scope", email, ri.verb, resource, ri.group)
	if ri.namespace != "" {
		why = fmt.Sprintf("User %q cannot %s resource %q in API group %q in the namespace %q", email, ri.verb, resource, ri.group, ri.namespace)
	}
	gr := ri.resource
	if ri.group != "" {
		gr += "." + ri.group
	}
	if ri.authzName != "" {
		return fmt.Sprintf("%s %q is forbidden: %s", gr, ri.authzName, why)
	}
	return fmt.Sprintf("%s is forbidden: %s", gr, why)
}

// quoteWarning is a warning text as a quoted-string (RFC 9110 §5.6.4), with
// " and \ escaped, as k8s.io/apimachinery v0.37.2 pkg/util/net/http.go
// (NewWarningHeader) writes it [a port from memory, not fetched].
func quoteWarning(text string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range text {
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// notEmulated is the answer to every method and path the emulation does not
// cover.
func notEmulated(w http.ResponseWriter, r *http.Request) {
	writeStatus(w, http.StatusMethodNotAllowed, "",
		"the server does not allow this method on the requested resource (kubetest emulates no "+r.Method+" "+strconv.Quote(r.URL.Path)+")", nil)
}
