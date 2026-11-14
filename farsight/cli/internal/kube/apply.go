package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// Apply is one server-side apply of one document (§5.3). It returns the
// metadata of the object the server answered with.
//
// The request is
//
//	PATCH {base}{Kind.Path(ns,name)}?fieldManager=farcast&fieldValidation=Strict&force=<force>
//	Content-Type: application/apply-patch+yaml
//
// with the document's own bytes as its body, unchanged: the API server parses
// them as it parses kubectl's input today. A missing object is created. A 409
// whose causes are FieldManagerConflict is the server refusing to take fields
// another manager owns; FieldConflicts reads them. An apply is retried on 429
// and 503 (§3.4).
//
// The body is d.Raw, so Apply does not trust d's other fields to describe it:
// a Document built by hand, rather than by SplitStream, is held to the same
// checks. Its Kind must be a row of Kinds, and §5.2's checks run again on
// d.Raw alone (rawFault), which must be one document of d's kind, namespace
// and name, the Names of its kind's row included. So a ClusterRoleBinding of
// any other name, or a Secret whose bytes carry stringData, is refused here
// and nothing is sent, whoever built the Document, whatever its Kind.Names
// says.
func (c *Client) Apply(ctx context.Context, d Document, force bool) (ObjectMeta, error) {
	fault := kindFault(d.Kind)
	if fault == "" {
		fault = addressFault(d.Kind, d.Namespace, d.Name)
	}
	if fault == "" && len(d.Raw) == 0 {
		fault = "it has no bytes"
	}
	if fault == "" {
		fault = rawFault(d)
	}
	if fault != "" {
		return ObjectMeta{}, refuse(ErrRefusedDocument, "kube: document %d (%s %q) is refused: %s; nothing was sent", d.Index, d.Kind.Kind, d.Name, fault)
	}
	path := d.Kind.Path(d.Namespace, d.Name)
	q := writeQuery()
	q.Set("force", strconv.FormatBool(force))
	var answer struct {
		Metadata ObjectMeta `json:"metadata"`
	}
	err := c.decode(ctx, call{
		method:      http.MethodPatch,
		path:        path,
		query:       q,
		contentType: mediaApplyPatch,
		body:        d.Raw,
		retry:       true,
	}, &answer)
	if err != nil {
		return ObjectMeta{}, err
	}
	return answer.Metadata, nil
}

// deleteOptions is the body of DeleteSecret's request (meta/v1 DeleteOptions).
type deleteOptions struct {
	APIVersion    string        `json:"apiVersion"`
	Kind          string        `json:"kind"`
	Preconditions preconditions `json:"preconditions"`
}

type preconditions struct {
	UID string `json:"uid"`
}

// DeleteSecret deletes one Secret, preconditioned on its uid (§9.8). It is
// the only delete in the package.
//
// The uid is required: a delete without it could remove a Secret of the same
// name that another writer made since it was read. A uid that is no longer the
// stored one is a 409 that unwraps to tkube.ErrConflict, and an absent Secret
// a 404. It is never retried on 429 or 503.
func (c *Client) DeleteSecret(ctx context.Context, namespace, name, uid string) error {
	path, err := objectPath(kindSecret, namespace, name)
	if err != nil {
		return err
	}
	if uid == "" {
		return refuse(ErrRefusedDocument, "kube: the delete of Secret %s/%s names no uid, and farcast deletes only on its uid's precondition; nothing was sent", namespace, name)
	}
	body, err := json.Marshal(deleteOptions{APIVersion: "v1", Kind: "DeleteOptions", Preconditions: preconditions{UID: uid}})
	if err != nil {
		return err
	}
	_, err = c.do(ctx, call{
		method:      http.MethodDelete,
		path:        path,
		contentType: mediaJSON,
		body:        body,
	})
	return err
}
