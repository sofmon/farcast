package kube

import (
	"context"
	"net/http"
	"net/url"
	"slices"
)

// Object is any kind's metadata, as GetObject and ListObjects read it. It
// declares metadata only, so a full answer, a Secret's included, is decoded
// into metadata and its values are discarded unread.
type Object struct {
	Kind     Kind       `json:"-"` // set from the request's Kind after decoding, never from the body
	Metadata ObjectMeta `json:"metadata"`
}

// ListObjects lists one kind's objects, metadata only: GET
// k.ListPath(namespace), "" being every namespace, with the label selector,
// paged, asking for a PartialObjectMetadataList. A server that answers with
// full objects is decoded into Object, which declares metadata only, so a
// Secret's values are discarded unread. Each Object's Kind is k, never read
// from the answer.
func (c *Client) ListObjects(ctx context.Context, k Kind, namespace, selector string) ([]Object, error) {
	if f := kindFault(k); f != "" {
		return nil, notSent(f)
	}
	path, err := listPath(k, namespace)
	if err != nil {
		return nil, err
	}
	var q url.Values
	if selector != "" {
		q = url.Values{"labelSelector": {selector}}
	}
	items, err := listAll[Object](ctx, c, path, q, acceptPartialList)
	if err != nil {
		return nil, err
	}
	for i := range items {
		items[i].Kind = stampKind(k)
	}
	return items, nil
}

// GetObject reads one object's metadata, asking for a PartialObjectMetadata.
// Its Kind is k, never read from the answer, whose kind is
// PartialObjectMetadata or, from a server that sends the whole object, the
// object's own.
func (c *Client) GetObject(ctx context.Context, k Kind, namespace, name string) (Object, error) {
	if f := kindFault(k); f != "" {
		return Object{}, notSent(f)
	}
	path, err := objectPath(k, namespace, name)
	if err != nil {
		return Object{}, err
	}
	var o Object
	if err := c.decode(ctx, call{method: http.MethodGet, path: path, accept: acceptPartial, retry: true}, &o); err != nil {
		return Object{}, err
	}
	o.Kind = stampKind(k)
	return o, nil
}

// stampKind is k as an Object carries it, with its own copy of Names.
func stampKind(k Kind) Kind {
	k.Names = slices.Clone(k.Names)
	return k
}
