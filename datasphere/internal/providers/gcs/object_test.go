package gcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere"
)

// The four object operations on the wire.
//
// Everything arriving here is already opaque — a tokenized name and a
// ciphertext body — so the only judgement calls left are about the wire, and
// the wire is where the traps are: a "/" that must be percent-encoded in a
// path but must NOT be double-encoded in a query, a multipart framing that is
// load-bearing rather than an optimization, and a size the API renders as a
// JSON string precisely because it does not fit a float64.

// storedName is a tokenized name of the shape the encrypting layer produces:
// two 32-character path-chained HMAC tokens joined by "/".
const storedName = "6f1a9c2233445566778899aabbccddee/0011223344556677889900aabbccddee"

// TestPutFramesOneAtomicMultipartRequest. uploadType=multipart is load-bearing:
// uploadType=media cannot set metadata at all, and an upload-then-patch pair
// would leave a window in which an object exists without the sealed name that
// identifies it — the torn state the Provider contract forbids.
func TestPutFramesOneAtomicMultipartRequest(t *testing.T) {
	p, fake := newTestProvider(t, jsonReply(http.StatusOK, fmt.Sprintf(`{"name":%q}`, storedName)))

	// Deliberately not text: a blob is a binary envelope, and a framing that
	// only works for printable bytes would pass a lazier test.
	payload := []byte{0x46, 0x43, 0x44, 0x53, 0x01, 0x00, 0xff, 0xfe, 0x0d, 0x0a, 0x00}
	meta := map[string]string{"farcast-name": "AAECAwQFBgcICQoLDA0ODw=="}

	if err := p.Put(context.Background(), testBucket, datasphere.Object{Name: storedName, Data: payload, Meta: meta}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if n := fake.count(); n != 1 {
		t.Fatalf("made %d requests, want exactly one upload: %v", n, fake.trace())
	}
	req := fake.request(t, 0)
	if req.method != http.MethodPost {
		t.Errorf("method = %s, want POST", req.method)
	}
	// Uploads go to the upload host, not the resource host.
	want := uploadAPIBase + "b/" + testBucket + "/o?fields=name&uploadType=multipart"
	if req.url != want {
		t.Errorf("url = %q, want %q", req.url, want)
	}
	if got := req.query(t).Get("uploadType"); got != "multipart" {
		t.Errorf("uploadType = %q, want multipart", got)
	}

	mediaType, params, err := mime.ParseMediaType(req.header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse Content-Type %q: %v", req.header.Get("Content-Type"), err)
	}
	if mediaType != "multipart/related" {
		t.Fatalf("media type = %q, want multipart/related", mediaType)
	}
	if params["boundary"] == "" {
		t.Fatal("no boundary in the Content-Type: the body is unparseable without one")
	}

	reader := multipart.NewReader(bytes.NewReader(req.body), params["boundary"])

	metaPart, err := reader.NextPart()
	if err != nil {
		t.Fatalf("read the metadata part: %v", err)
	}
	if got := metaPart.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("metadata part Content-Type = %q, want application/json", got)
	}
	metaBody, err := io.ReadAll(metaPart)
	if err != nil {
		t.Fatalf("read the metadata part body: %v", err)
	}
	var resource objectResource
	if err := json.Unmarshal(metaBody, &resource); err != nil {
		t.Fatalf("decode the metadata part: %v", err)
	}
	// In JSON the name is a value, so the "/" separators stay raw here — the
	// escaping obligation belongs to URL paths, and applying it in both places
	// would store the object under a name nothing could read back.
	if resource.Name != storedName {
		t.Errorf("object name = %q, want %q", resource.Name, storedName)
	}
	if len(resource.Metadata) != len(meta) {
		t.Fatalf("metadata = %v, want %v", resource.Metadata, meta)
	}
	for k, v := range meta {
		if resource.Metadata[k] != v {
			t.Errorf("metadata[%q] = %q, want %q", k, resource.Metadata[k], v)
		}
	}

	mediaPart, err := reader.NextPart()
	if err != nil {
		t.Fatalf("read the media part: %v", err)
	}
	if got := mediaPart.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("media part Content-Type = %q, want application/octet-stream", got)
	}
	mediaBody, err := io.ReadAll(mediaPart)
	if err != nil {
		t.Fatalf("read the media part body: %v", err)
	}
	// Byte-exact: a ciphertext that is off by a byte fails authentication at
	// read time, long after the write that broke it.
	if !bytes.Equal(mediaBody, payload) {
		t.Errorf("media part = %#v, want %#v", mediaBody, payload)
	}

	if _, err := reader.NextPart(); !errors.Is(err, io.EOF) {
		t.Errorf("expected exactly two parts, got a third (err = %v)", err)
	}
}

// TestPutRejectsAnEmptyName before the wire: an unnamed object would land
// under whatever name the service chose, unreachable forever.
func TestPutRejectsAnEmptyName(t *testing.T) {
	p, fake := newTestProvider(t)
	if err := p.Put(context.Background(), testBucket, datasphere.Object{Data: []byte("x")}); err == nil {
		t.Fatal("expected a refusal")
	}
	if n := fake.count(); n != 0 {
		t.Errorf("made %d requests, want none: %v", n, fake.trace())
	}
}

// TestPutSurfacesAFailedUpload: an upload reported as success would be silent
// data loss — nothing above this layer re-reads what it just wrote.
func TestPutSurfacesAFailedUpload(t *testing.T) {
	p, _ := newTestProvider(t, errorReply(http.StatusForbidden, "PERMISSION_DENIED", "does not have storage.objects.create access"))
	err := p.Put(context.Background(), testBucket, datasphere.Object{Name: storedName, Data: []byte("x")})
	if err == nil {
		t.Fatal("expected a failed upload to surface")
	}
	if !strings.Contains(err.Error(), testBucket) {
		t.Errorf("err = %v, want it to name the bucket", err)
	}
}

// TestGetPercentEncodesTheNameInThePath is a named wire trap. A tokenized name
// carries "/" separators, and a raw "/" in the URL path does not address the
// object — it changes the route and addresses a different resource entirely.
func TestGetPercentEncodesTheNameInThePath(t *testing.T) {
	body := []byte{0x46, 0x43, 0x44, 0x53, 0x01, 0xff, 0x00}
	header := http.Header{
		"Content-Type":                 []string{"application/octet-stream"},
		"X-Goog-Meta-Farcast-Name":     []string{"AAECAwQFBgcICQoLDA0ODw=="},
		"X-Goog-Meta-Farcast-Revision": []string{"1"},
		"X-Goog-Generation":            []string{"1730000000000000"},
	}
	p, fake := newTestProvider(t, mediaReply(http.StatusOK, header, body))

	obj, err := p.Get(context.Background(), testBucket, storedName)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	req := fake.request(t, 0)
	if req.method != http.MethodGet {
		t.Errorf("method = %s, want GET", req.method)
	}
	escaped := strings.ReplaceAll(storedName, "/", "%2F")
	want := jsonAPIBase + "b/" + testBucket + "/o/" + escaped + "?alt=media"
	if req.url != want {
		t.Errorf("url = %q, want %q", req.url, want)
	}
	if strings.Contains(req.url, "/o/"+storedName) {
		t.Errorf("url = %q, want the name's separators percent-encoded, never raw", req.url)
	}
	if got := req.query(t).Get("alt"); got != "media" {
		t.Errorf("alt = %q, want media (without it the response is the JSON resource, not the bytes)", got)
	}

	if obj.Name != storedName {
		t.Errorf("name = %q, want %q", obj.Name, storedName)
	}
	if !bytes.Equal(obj.Data, body) {
		t.Errorf("data = %#v, want %#v", obj.Data, body)
	}
	// Custom metadata arrives as X-Goog-Meta-*: prefix stripped, lowercased,
	// and nothing else from the response headers along with it.
	want2 := map[string]string{"farcast-name": "AAECAwQFBgcICQoLDA0ODw==", "farcast-revision": "1"}
	if len(obj.Meta) != len(want2) {
		t.Fatalf("meta = %v, want %v", obj.Meta, want2)
	}
	for k, v := range want2 {
		if obj.Meta[k] != v {
			t.Errorf("meta[%q] = %q, want %q", k, obj.Meta[k], v)
		}
	}
}

// TestGetMissingObject: the sentinel is what the layer above branches on, so a
// plain error here would turn a missing key into an unclassifiable failure.
func TestGetMissingObject(t *testing.T) {
	p, _ := newTestProvider(t, errorReply(http.StatusNotFound, "NOT_FOUND", "No such object."))

	obj, err := p.Get(context.Background(), testBucket, storedName)
	if !errors.Is(err, datasphere.ErrObjectNotFound) {
		t.Fatalf("err = %v, want ErrObjectNotFound", err)
	}
	if obj != nil {
		t.Errorf("object = %+v, want nothing", obj)
	}
}

// TestGetSurfacesOtherFailures: only 404 is a missing object. A 403 is a
// credential problem, and mapping it to "not found" would let a recovery flow
// conclude the data is gone.
func TestGetSurfacesOtherFailures(t *testing.T) {
	p, _ := newTestProvider(t, errorReply(http.StatusForbidden, "PERMISSION_DENIED", "does not have storage.objects.get access"))

	_, err := p.Get(context.Background(), testBucket, storedName)
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, datasphere.ErrObjectNotFound) {
		t.Fatalf("err = %v, want a plain error: a 403 is not proof the object is absent", err)
	}
}

// TestListFieldMaskPrefixAndPagination pins the three things a listing has to
// get right: the field mask that keeps List to one round trip per page, the
// prefix encoding, and page threading.
func TestListFieldMaskPrefixAndPagination(t *testing.T) {
	prefix := "6f1a9c2233445566778899aabbccddee/"
	p, fake := newTestProvider(t,
		jsonReply(http.StatusOK, `{"items":[
			{"name":"6f1a9c2233445566778899aabbccddee/aa11","size":"1234","metadata":{"farcast-name":"AAEC"}}
		],"nextPageToken":"page-2"}`),
		jsonReply(http.StatusOK, `{"items":[
			{"name":"6f1a9c2233445566778899aabbccddee/bb22","size":"9007199254740993"}
		]}`),
	)

	got, err := p.List(context.Background(), testBucket, prefix)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if n := fake.count(); n != 2 {
		t.Fatalf("made %d requests, want one per page: %v", n, fake.trace())
	}

	first := fake.request(t, 0)
	q := first.query(t)
	// The mask is what makes one list call per page enough: names, sizes, and
	// the metadata map carrying each object's sealed name. Drop "metadata" and
	// every listing degrades into a per-object fetch.
	if got := q.Get("fields"); got != "items(name,size,metadata),nextPageToken" {
		t.Errorf("fields = %q, want items(name,size,metadata),nextPageToken", got)
	}
	// The prefix is a query VALUE. url.Values' percent-encoding of "/" is
	// correct and equivalent to a raw one, because the server decodes query
	// values before matching; the only real hazard on this side is
	// double-encoding, which would silently match nothing.
	if got := q.Get("prefix"); got != prefix {
		t.Errorf("prefix decodes to %q, want %q — a double-encoded prefix matches no object", got, prefix)
	}
	if strings.Contains(first.url, "%252F") {
		t.Errorf("url = %q, want the prefix encoded once, not twice", first.url)
	}
	if _, ok := q["pageToken"]; ok {
		t.Errorf("url = %q, want no pageToken on the first page", first.url)
	}

	second := fake.request(t, 1)
	if got := second.query(t).Get("pageToken"); got != "page-2" {
		t.Errorf("pageToken = %q, want the token the first page returned", got)
	}
	if got := second.query(t).Get("prefix"); got != prefix {
		t.Errorf("second page prefix = %q, want it carried through", got)
	}

	want := []datasphere.ObjectInfo{
		{Name: "6f1a9c2233445566778899aabbccddee/aa11", Size: 1234, Meta: map[string]string{"farcast-name": "AAEC"}},
		// Above 2^53: the API renders sizes as JSON strings for exactly this
		// reason, and decoding one through a float64 would silently round it.
		{Name: "6f1a9c2233445566778899aabbccddee/bb22", Size: 9007199254740993},
	}
	if len(got) != len(want) {
		t.Fatalf("listed %d objects, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Size != want[i].Size {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
		for k, v := range want[i].Meta {
			if got[i].Meta[k] != v {
				t.Errorf("entry %d meta[%q] = %q, want %q", i, k, got[i].Meta[k], v)
			}
		}
	}
}

// TestListWithoutAPrefixOmitsTheParameter: an empty prefix means "everything",
// and sending prefix= would be a different request.
func TestListWithoutAPrefixOmitsTheParameter(t *testing.T) {
	p, fake := newTestProvider(t, jsonReply(http.StatusOK, `{"items":[]}`))

	if _, err := p.List(context.Background(), testBucket, ""); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, ok := fake.request(t, 0).query(t)["prefix"]; ok {
		t.Errorf("url = %q, want no prefix parameter at all", fake.request(t, 0).url)
	}
}

// TestDeleteObjectAbsentIsSuccess: teardown and re-runs have to converge, and
// an object that is already gone is the outcome that was wanted.
func TestDeleteObjectAbsentIsSuccess(t *testing.T) {
	p, fake := newTestProvider(t, errorReply(http.StatusNotFound, "NOT_FOUND", "No such object."))

	if err := p.Delete(context.Background(), testBucket, storedName); err != nil {
		t.Fatalf("deleting an absent object must succeed: %v", err)
	}
	req := fake.request(t, 0)
	if req.method != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", req.method)
	}
	escaped := strings.ReplaceAll(storedName, "/", "%2F")
	if want := jsonAPIBase + "b/" + testBucket + "/o/" + escaped; req.url != want {
		t.Errorf("url = %q, want %q", req.url, want)
	}
}

// TestDeleteObjectSurfacesOtherFailures: absence is success, refusal is not —
// a delete that quietly failed would leave ciphertext the operator ordered
// destroyed, and DeleteBucket would then fail on a bucket it thinks is empty.
func TestDeleteObjectSurfacesOtherFailures(t *testing.T) {
	p, _ := newTestProvider(t, errorReply(http.StatusForbidden, "PERMISSION_DENIED", "does not have storage.objects.delete access"))

	if err := p.Delete(context.Background(), testBucket, storedName); err == nil {
		t.Fatal("expected a refused delete to surface")
	}
}

// TestListAcceptsAFullPageOfLongNames pins the response cap against the size a
// listing can legitimately reach.
//
// The adapter originally reused the ordinary JSON cap here, on the premise —
// written into the constant's own comment — that "listings are kilobytes". They
// are not. A page is a thousand entries, and every entry carries the object's
// name plus the metadata map holding its sealed logical name. At the key sizes
// the module advertises as legal, that is megabytes, and an over-cap body is
// refused outright on a non-retryable path: the bucket would become permanently
// unlistable, with Store.List's header fallback never reached because the
// failure is in the page fetch rather than in any one object's mirror.
//
// The page below is built at the module's own worst case, and the test asserts
// it exceeds the ordinary cap before asserting it is accepted — so this cannot
// quietly stop testing anything if that cap is ever raised.
func TestListAcceptsAFullPageOfLongNames(t *testing.T) {
	const (
		// 30 segments of 32 hex characters, slash-separated: the longest stored
		// path the logical-key limits can produce.
		maxStoredName = 30*32 + 29
		// base64 of a sealed name for a 1024-byte logical key: 12-byte nonce,
		// 1056 bytes of padded plaintext, 16-byte tag.
		maxMirror = 1448
	)
	segment := strings.Repeat("ab", 16)
	name := segment + strings.Repeat("/"+segment, 29)
	if len(name) != maxStoredName {
		t.Fatalf("built a %d-byte name, want %d", len(name), maxStoredName)
	}
	mirror := strings.Repeat("A", maxMirror)

	items := make([]string, maxListResults)
	for i := range items {
		// Vary the leading characters so the names are distinct without
		// changing their length.
		items[i] = fmt.Sprintf(`{"name":%q,"size":"4096","metadata":{"farcast-name":%q}}`,
			fmt.Sprintf("%04x", i)+name[4:], mirror)
	}
	page := `{"items":[` + strings.Join(items, ",") + `]}`

	if int64(len(page)) <= maxResponseBytes {
		t.Fatalf("the synthetic page is %d bytes, which no longer exceeds the ordinary %d-byte cap; this test has stopped testing anything",
			len(page), maxResponseBytes)
	}

	p, _ := newTestProvider(t, jsonReply(http.StatusOK, page))
	got, err := p.List(context.Background(), testBucket, "")
	if err != nil {
		t.Fatalf("List over a %d-byte page = %v", len(page), err)
	}
	if len(got) != maxListResults {
		t.Fatalf("List returned %d objects, want %d", len(got), maxListResults)
	}
	if got[0].Meta["farcast-name"] != mirror {
		t.Error("the sealed-name mirror did not survive the page")
	}
}

// TestListDisablesPrettyPrinting: Google pretty-prints JSON unless told not to,
// which on a thousand-entry page is pure padding between the adapter and its
// response cap.
func TestListDisablesPrettyPrinting(t *testing.T) {
	p, fake := newTestProvider(t, jsonReply(http.StatusOK, `{"items":[]}`))
	if _, err := p.List(context.Background(), testBucket, ""); err != nil {
		t.Fatal(err)
	}
	if got := fake.request(t, 0).query(t).Get("prettyPrint"); got != "false" {
		t.Errorf("prettyPrint = %q, want %q", got, "false")
	}
}
