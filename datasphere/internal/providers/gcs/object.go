package gcs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/sofmon/farcast/datasphere"
)

// The four object operations. Names arriving here are opaque tokens and bodies
// are ciphertext; this file's only judgement calls are about the wire.

// metaHeaderPrefix is how GCS surfaces an object's custom metadata on a media
// download.
const metaHeaderPrefix = "X-Goog-Meta-"

// Put stores an object and its metadata in one atomic request.
//
// uploadType=multipart is load-bearing rather than an optimization:
// uploadType=media cannot set metadata at all, and a two-call
// upload-then-patch would leave a window in which an object exists without the
// sealed name that identifies it — precisely the torn state the Provider
// contract forbids.
func (p *provider) Put(ctx context.Context, bucket string, obj datasphere.Object) error {
	if obj.Name == "" {
		return fmt.Errorf("gcs: an object name is required")
	}
	body, contentType, err := multipartBody(obj)
	if err != nil {
		return err
	}
	query := url.Values{"uploadType": {"multipart"}, "fields": {"name"}}
	target := p.upload + "b/" + url.PathEscape(bucket) + "/o?" + query.Encode()

	rep, err := p.send(ctx, http.MethodPost, target, contentType, body, maxResponseBytes)
	if err != nil {
		return err
	}
	if !okStatus(rep.status) {
		return fmt.Errorf("gcs: put object into %q: %w", bucket, parseAPIError(rep.status, rep.body))
	}
	return nil
}

// Get retrieves an object's bytes.
//
// Metadata is lifted from X-Goog-Meta-* response headers when the service sends
// them, so this stays one round trip. Measured against real GCS on 2026-08-27,
// the JSON API does not send them on an alt=media download, so Meta comes back
// empty in practice — which costs nothing, because nothing depends on it: the
// encrypting layer above reads names from listings and, failing that, from the
// object's own authoritative header, which is exactly why a blob is
// self-describing in the first place. The lift stays because the XML API and
// other clouds do send them, and an empty map is the honest answer either way.
func (p *provider) Get(ctx context.Context, bucket, name string) (*datasphere.Object, error) {
	rep, err := p.send(ctx, http.MethodGet, p.objectURL(bucket, name)+"?alt=media", "", nil, maxObjectBytes)
	if err != nil {
		return nil, err
	}
	if rep.status == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", datasphere.ErrObjectNotFound, name)
	}
	if !okStatus(rep.status) {
		return nil, fmt.Errorf("gcs: get object from %q: %w", bucket, parseAPIError(rep.status, rep.body))
	}
	return &datasphere.Object{Name: name, Data: rep.body, Meta: metaFromHeader(rep.header)}, nil
}

// List returns every object under prefix, paginating internally.
//
// The field mask is what keeps this to one round trip per page: names, sizes,
// and the metadata map carrying each object's sealed name are all the layer
// above needs to render a listing, so it never has to fetch an object to learn
// what it is called.
func (p *provider) List(ctx context.Context, bucket, prefix string) ([]datasphere.ObjectInfo, error) {
	var out []datasphere.ObjectInfo
	err := p.eachPage(ctx, bucket, prefix, "items(name,size,metadata),nextPageToken", func(items []objectResource) error {
		for _, item := range items {
			out = append(out, datasphere.ObjectInfo{
				Name: item.Name,
				Size: parseSize(item.Size),
				Meta: item.Metadata,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("gcs: list objects in %q: %w", bucket, err)
	}
	return out, nil
}

// Delete removes an object. Deleting an absent object is success — teardown
// and re-runs have to converge.
func (p *provider) Delete(ctx context.Context, bucket, name string) error {
	err := p.doJSON(ctx, http.MethodDelete, p.objectURL(bucket, name), nil, nil)
	if err == nil || isHTTPStatus(err, http.StatusNotFound) {
		return nil
	}
	return fmt.Errorf("gcs: delete object from %q: %w", bucket, err)
}

// eachPage walks an object listing, calling fn once per page.
func (p *provider) eachPage(ctx context.Context, bucket, prefix, fields string, fn func([]objectResource) error) error {
	pageToken := ""
	for {
		query := url.Values{
			"fields":     {fields},
			"maxResults": {strconv.Itoa(maxListResults)},
			// Google pretty-prints JSON by default, which on a thousand-entry
			// page is pure padding between the adapter and its response cap.
			"prettyPrint": {"false"},
		}
		// The prefix is a query VALUE, where url.Values' standard
		// percent-encoding is correct and equivalent to a raw "/" — the server
		// decodes query values before matching. The only real hazard on this
		// side is double-encoding, which is why the prefix is set here rather
		// than pre-escaped by the caller.
		if prefix != "" {
			query.Set("prefix", prefix)
		}
		if pageToken != "" {
			query.Set("pageToken", pageToken)
		}
		var page objectListPage
		// The listing cap, not the ordinary one: a full page of long names and
		// their sealed-name mirrors runs to megabytes.
		if err := p.doJSONLimit(ctx, http.MethodGet, p.base+"b/"+url.PathEscape(bucket)+"/o?"+query.Encode(), nil, &page, maxListBytes); err != nil {
			return err
		}
		if err := fn(page.Items); err != nil {
			return err
		}
		if page.NextPageToken == "" {
			return nil
		}
		pageToken = page.NextPageToken
	}
}

// objectURL builds an object endpoint.
//
// The "/" separators inside a tokenized stored name must be percent-encoded in
// the URL PATH: a raw "/" changes the route and addresses a different resource
// entirely. url.PathEscape does escape "/", which is exactly why it is used
// here and why a plain path join would be a bug.
func (p *provider) objectURL(bucket, name string) string {
	return p.base + "b/" + url.PathEscape(bucket) + "/o/" + url.PathEscape(name)
}

// multipartBody frames an object as multipart/related: a JSON metadata part
// naming the object and carrying its metadata map, then the media part.
func multipartBody(obj datasphere.Object) ([]byte, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	metadata, err := json.Marshal(objectResource{Name: obj.Name, Metadata: obj.Meta})
	if err != nil {
		return nil, "", fmt.Errorf("gcs: encode object metadata: %w", err)
	}
	part, err := writer.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json; charset=UTF-8"}})
	if err != nil {
		return nil, "", fmt.Errorf("gcs: frame metadata part: %w", err)
	}
	if _, err := part.Write(metadata); err != nil {
		return nil, "", fmt.Errorf("gcs: write metadata part: %w", err)
	}
	media, err := writer.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/octet-stream"}})
	if err != nil {
		return nil, "", fmt.Errorf("gcs: frame media part: %w", err)
	}
	if _, err := media.Write(obj.Data); err != nil {
		return nil, "", fmt.Errorf("gcs: write media part: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("gcs: close multipart body: %w", err)
	}
	return buf.Bytes(), "multipart/related; boundary=" + writer.Boundary(), nil
}

// metaFromHeader lifts an object's custom metadata out of a media download's
// response headers.
func metaFromHeader(header http.Header) map[string]string {
	var meta map[string]string
	for key, values := range header {
		if len(values) == 0 || !strings.HasPrefix(key, metaHeaderPrefix) {
			continue
		}
		if meta == nil {
			meta = make(map[string]string)
		}
		meta[strings.ToLower(strings.TrimPrefix(key, metaHeaderPrefix))] = values[0]
	}
	return meta
}

// parseSize reads a listing entry's size. It is informational — it feeds
// `storage ls` and usage reporting — so a size the cloud renders unparseably
// leaves it zero rather than failing a listing the recovery flows depend on.
func parseSize(size string) int64 {
	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
