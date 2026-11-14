package kube

import (
	"context"
	"encoding/json"
	"net/http"
)

// ResourceAttributes is one thing a SelfSubjectAccessReview asks about
// (authorization.k8s.io/v1 ResourceAttributes): may this client's identity
// do Verb on Resource (and Subresource) in Group, in Namespace, by Name. An
// empty field is the wire's empty value.
type ResourceAttributes struct {
	Namespace, Verb, Group, Resource, Subresource, Name string
}

// selfSubjectAccessReviewPath is where a review is created. It is never
// stored: the answer is the review with its status.
const selfSubjectAccessReviewPath = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"

// selfReview is authorization.k8s.io/v1 SelfSubjectAccessReview on the wire.
type selfReview struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Spec       selfReviewSpec `json:"spec"`
}

type selfReviewSpec struct {
	ResourceAttributes wireAttributes `json:"resourceAttributes"`
}

// wireAttributes is ResourceAttributes with its wire names, field for field,
// so one converts to the other.
type wireAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	Verb        string `json:"verb,omitempty"`
	Group       string `json:"group,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

// SelfSubjectAccessReview asks the API server whether this client's identity
// may do one thing (§7.2, reader grant). POST
// /apis/authorization.k8s.io/v1/selfsubjectaccessreviews.
//
// An answer without a status is unreadable, never read as not allowed. So is
// one that is not allowed and reports an evaluationError: the authorizer
// could not finish the check (k8s.io/api v0.37.2 authorization/v1,
// SubjectAccessReviewStatus), so its "no" proves nothing, whether or not it
// is also denied. An allowed answer is allowed, whatever error it reports.
// The server's words are never quoted. Like every POST, it is not retried on
// 429 or 503.
func (c *Client) SelfSubjectAccessReview(ctx context.Context, a ResourceAttributes) (allowed bool, err error) {
	body, err := json.Marshal(selfReview{
		APIVersion: "authorization.k8s.io/v1",
		Kind:       "SelfSubjectAccessReview",
		Spec:       selfReviewSpec{ResourceAttributes: wireAttributes(a)},
	})
	if err != nil {
		return false, err
	}
	var answer struct {
		Status *struct {
			Allowed         bool   `json:"allowed"`
			EvaluationError string `json:"evaluationError"`
		} `json:"status"`
	}
	cl := call{method: http.MethodPost, path: selfSubjectAccessReviewPath, contentType: mediaJSON, body: body}
	if err := c.decode(ctx, cl, &answer); err != nil {
		return false, err
	}
	if answer.Status == nil {
		return false, refuse(ErrUnreadable, "the API server's answer to %s %s carries no status", cl.method, cl.path)
	}
	if answer.Status.Allowed {
		return true, nil
	}
	if answer.Status.EvaluationError != "" {
		return false, refuse(ErrUnreadable, "the API server could not fully evaluate the review of %s %s; its answer proves nothing", a.Verb, a.Resource)
	}
	return false, nil
}
