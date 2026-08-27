package gcs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
)

// Streaming on the wire: the resumable upload protocol and ranged reads.
//
// This protocol is hand-issued, so every one of its sharp edges is ours to get
// right and ours to prove. The edges are not hypothetical — each test below is
// named after a way the upload silently produces no object, or produces the
// wrong bytes, while every Go-level assertion still passes:
//
//   - a stream ending exactly on a window boundary never sends its terminator,
//     so the session expires and the object simply never exists;
//   - a 308 taken at face value looks like a redirect to net/http and like
//     success to a naive reader — the first re-sends the window somewhere else,
//     the second reports a stored object that is not there;
//   - a resend that does not first ask what the service committed writes the
//     same bytes twice at the wrong offset;
//   - an abort riding the caller's context is a no-op exactly when it is
//     needed, because a dead context is the usual reason to be aborting;
//   - and a 200 in answer to a Range request means a proxy stripped the header,
//     so accepting it hands back bytes from offset zero for a read that asked
//     for offset five gigabytes.
//
// All of it runs over the package's fake RoundTripper: no listener, no
// network, no credentials, no cloud spend.

// testSession is the opaque upload session URI GCS returns in Location. It is
// deliberately not derivable from anything the client knows: the client must
// use what the header said and nothing else.
const testSession = "https://storage.googleapis.com/upload/storage/v1/b/" + testBucket +
	"/o?uploadType=resumable&upload_id=AEnB2Uq7fakesessiontoken"

// streamBytes builds a deterministic payload.
//
// Deterministic matters here: the window assertions compare what the cloud
// received against the slice of the stream it should have carried, so an
// off-by-one window boundary shows up as a specific wrong byte rather than as
// "some other random bytes".
func streamBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

// headers builds a response header set through Set, so the keys are
// canonicalized exactly as a real response's would be.
func headers(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

// sessionStarted is the reply to a resumable initiation: the session URI rides
// in Location and nowhere else.
func sessionStarted(session string) *http.Response {
	return mediaReply(http.StatusOK, headers("Location", session), nil)
}

// resumeIncomplete is what GCS answers while it expects more bytes — a 200
// carrying the override header, which is the shape it sends once asked not to
// reply 308. committed is how many bytes it holds; zero omits the Range header
// entirely, which is how "nothing landed" arrives.
func resumeIncomplete(committed int) *http.Response {
	h := headers("X-Http-Status-Code-Override", "308")
	if committed > 0 {
		h.Set("Range", fmt.Sprintf("bytes=0-%d", committed-1))
	}
	return mediaReply(http.StatusOK, h, nil)
}

// objectStored is the finalizing reply: the object resource, under the
// fields=name projection the session was opened with.
func objectStored() *http.Response {
	return jsonReply(http.StatusOK, fmt.Sprintf(`{"name":%q}`, storedName))
}

// streamMediaPart returns the media half of a multipart insert, so the small
// path can be compared byte-for-byte against what was streamed in.
func streamMediaPart(t *testing.T, req capturedRequest) []byte {
	t.Helper()
	_, params, err := mime.ParseMediaType(req.header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse Content-Type %q: %v", req.header.Get("Content-Type"), err)
	}
	reader := multipart.NewReader(bytes.NewReader(req.body), params["boundary"])
	if _, err := reader.NextPart(); err != nil {
		t.Fatalf("read the metadata part: %v", err)
	}
	media, err := reader.NextPart()
	if err != nil {
		t.Fatalf("read the media part: %v", err)
	}
	data, err := io.ReadAll(media)
	if err != nil {
		t.Fatalf("read the media part body: %v", err)
	}
	return data
}

// assertWindow checks one resumable PUT end to end: the session it targets,
// the exact Content-Range, and the exact bytes.
func assertWindow(t *testing.T, req capturedRequest, session, wantRange string, wantBody []byte) {
	t.Helper()
	if req.method != http.MethodPut {
		t.Errorf("method = %s, want PUT", req.method)
	}
	if req.url != session {
		t.Errorf("url = %q, want the session URI %q", req.url, session)
	}
	if got := req.header.Get("Content-Range"); got != wantRange {
		t.Errorf("Content-Range = %q, want %q", got, wantRange)
	}
	if got := req.header.Get("X-GUploader-No-308"); got != "yes" {
		t.Errorf("X-GUploader-No-308 = %q, want %q", got, "yes")
	}
	if !bytes.Equal(req.body, wantBody) {
		t.Errorf("window %q carried %d bytes and wanted %d, first difference at index %d",
			wantRange, len(req.body), len(wantBody), firstDiff(req.body, wantBody))
	}
}

// firstDiff reports where two payloads diverge, so a window assertion over
// megabytes fails with a number rather than with a screenful of bytes.
func firstDiff(got, want []byte) int {
	for i := range min(len(got), len(want)) {
		if got[i] != want[i] {
			return i
		}
	}
	return min(len(got), len(want))
}

// putStream is the call under test, with the arguments every test shares.
func putStream(ctx context.Context, p *provider, data []byte) error {
	return p.PutStream(ctx, testBucket, datasphere.StreamObject{
		Name: storedName,
		Data: bytes.NewReader(data),
		Size: -1,
		Meta: map[string]string{"farcast-name": "AAECAwQFBgcICQoLDA0ODw=="},
	})
}

// recordLengths wraps a responder, capturing each request's declared
// Content-Length. The shared harness records methods, URLs, headers and
// bodies, but Content-Length is not a request header in net/http — it is
// rendered from ContentLength — so "this request declared no body at all" has
// to be read here.
func recordLengths(lengths *[]int64, respond func(*http.Request) (*http.Response, error)) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		*lengths = append(*lengths, r.ContentLength)
		return respond(r)
	}
}

// noDelete asserts a run finished without abandoning its session, which is the
// other half of "the object was finalized": a successful upload has nothing to
// abort.
func noDelete(t *testing.T, fake *fakeCloud) {
	t.Helper()
	for _, call := range fake.trace() {
		if strings.HasPrefix(call, http.MethodDelete+" ") {
			t.Errorf("the session was abandoned after a successful upload: %v", fake.trace())
		}
	}
}

// TestPutStreamRefusesAnUnnamedOrSourcelessObject before the wire. An unnamed
// object would land under whatever name the service chose, unreachable
// forever; a nil source would open a billable session for nothing.
func TestPutStreamRefusesAnUnnamedOrSourcelessObject(t *testing.T) {
	for _, tc := range []struct {
		name string
		obj  datasphere.StreamObject
	}{
		{"no name", datasphere.StreamObject{Data: bytes.NewReader([]byte("x")), Size: -1}},
		{"no source", datasphere.StreamObject{Name: storedName, Size: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, fake := newTestProvider(t)
			if err := p.PutStream(context.Background(), testBucket, tc.obj); err == nil {
				t.Fatal("expected a refusal")
			}
			if n := fake.count(); n != 0 {
				t.Errorf("made %d requests, want none: %v", n, fake.trace())
			}
		})
	}
}

// TestPutStreamThatEndsInsideTheBufferIsOneOrdinaryInsert.
//
// The whole point of buffering the head of a stream is that the common case —
// a small object arriving through the streaming API — costs exactly one
// request and stays atomic for free. A resumable session here would be three
// round trips and a window in which a failure leaves server-side state behind.
func TestPutStreamThatEndsInsideTheBufferIsOneOrdinaryInsert(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{
		// A zero-byte object is legal and must not become a session either.
		{"an empty stream", 0},
		{"a few kilobytes", 4096},
		{"one byte short of the buffer", streamBufferBytes - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := streamBytes(tc.size)
			p, fake := newTestProvider(t, objectStored())

			if err := putStream(context.Background(), p, payload); err != nil {
				t.Fatalf("PutStream: %v", err)
			}

			if n := fake.count(); n != 1 {
				t.Fatalf("made %d requests, want exactly one insert: %v", n, fake.trace())
			}
			req := fake.request(t, 0)
			if req.method != http.MethodPost {
				t.Errorf("method = %s, want POST", req.method)
			}
			// The upload host, and the shipped multipart insert — not a session.
			want := uploadAPIBase + "b/" + testBucket + "/o?fields=name&uploadType=multipart"
			if req.url != want {
				t.Errorf("url = %q, want %q", req.url, want)
			}
			if got := req.query(t).Get("uploadType"); got != "multipart" {
				t.Errorf("uploadType = %q, want multipart: a stream that ends inside the buffer must not open a session", got)
			}
			if got := streamMediaPart(t, req); !bytes.Equal(got, payload) {
				t.Errorf("the insert carried %d bytes and wanted %d, first difference at index %d",
					len(got), len(payload), firstDiff(got, payload))
			}
		})
	}
}

// TestPutStreamOpensAResumableSessionAndWalksTheWindows pins the protocol's
// spine: the initiation, where the session URI comes from, and the offset
// arithmetic across enough windows that an off-by-one has somewhere to hide.
func TestPutStreamOpensAResumableSessionAndWalksTheWindows(t *testing.T) {
	const tail = 1 << 20
	total := 2*uploadWindowBytes + tail
	payload := streamBytes(total)

	p, fake := newTestProvider(t,
		sessionStarted(testSession),
		resumeIncomplete(uploadWindowBytes),
		resumeIncomplete(2*uploadWindowBytes),
		objectStored(),
	)

	if err := putStream(context.Background(), p, payload); err != nil {
		t.Fatalf("PutStream: %v", err)
	}
	if n := fake.count(); n != 4 {
		t.Fatalf("made %d requests, want an initiation plus three windows: %v", n, fake.trace())
	}

	init := fake.request(t, 0)
	if init.method != http.MethodPost {
		t.Errorf("method = %s, want POST", init.method)
	}
	if want := uploadAPIBase + "b/" + testBucket + "/o?fields=name&uploadType=resumable"; init.url != want {
		t.Errorf("url = %q, want %q", init.url, want)
	}
	if got := init.query(t).Get("uploadType"); got != "resumable" {
		t.Errorf("uploadType = %q, want resumable", got)
	}
	if got := init.header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json: the initiation body is the object resource", got)
	}
	// The initiation is where the object's name and its metadata map are set;
	// there is no later request that could carry them, so a session opened
	// without them stores a blob with no sealed-name mirror.
	if got := jsonField(t, init.body, "name"); got != storedName {
		t.Errorf("name = %v, want %q", got, storedName)
	}
	if got := jsonField(t, init.body, "metadata", "farcast-name"); got != "AAECAwQFBgcICQoLDA0ODw==" {
		t.Errorf("metadata[farcast-name] = %v, want the sealed-name mirror", got)
	}

	// The window arithmetic is derived from the constants rather than
	// transcribed, so a retuned window retunes the expectations with it. The
	// SHAPE of every header is pinned literally in TestContentRangeRendering,
	// which is where the wire format itself lives.
	for i, w := range []struct {
		contentRange string
		from, to     int
	}{
		{fmt.Sprintf("bytes 0-%d/*", uploadWindowBytes-1), 0, uploadWindowBytes},
		{fmt.Sprintf("bytes %d-%d/*", uploadWindowBytes, 2*uploadWindowBytes-1), uploadWindowBytes, 2 * uploadWindowBytes},
		// Only the last window knows the length, and it is the only one that
		// may declare it: a total on an earlier window finalizes the object
		// short.
		{fmt.Sprintf("bytes %d-%d/%d", 2*uploadWindowBytes, total-1, total), 2 * uploadWindowBytes, total},
	} {
		assertWindow(t, fake.request(t, i+1), testSession, w.contentRange, payload[w.from:w.to])
	}
	noDelete(t, fake)
}

// TestPutStreamEndingOnAWindowBoundaryStillSendsTheTerminator.
//
// This is the case that breaks in silence. Every window has been sent and
// acknowledged, so nothing has failed — but until a request carries the total,
// GCS holds an open session and no object. The upload "succeeds" and the data
// is not there.
func TestPutStreamEndingOnAWindowBoundaryStillSendsTheTerminator(t *testing.T) {
	// Asserted rather than assumed: with the buffer and the window equal, the
	// smallest boundary-ending stream is exactly one window. If they ever
	// diverge the arithmetic below stops describing what happens, and this says
	// so instead of quietly testing something else.
	if streamBufferBytes != uploadWindowBytes {
		t.Fatalf("this test assumes the buffer (%d) and the window (%d) are the same size; re-derive the expectations",
			streamBufferBytes, uploadWindowBytes)
	}
	payload := streamBytes(uploadWindowBytes)

	p, fake := newTestProvider(t,
		sessionStarted(testSession),
		resumeIncomplete(uploadWindowBytes),
		objectStored(),
	)

	if err := putStream(context.Background(), p, payload); err != nil {
		t.Fatalf("PutStream: %v", err)
	}
	if n := fake.count(); n != 3 {
		t.Fatalf("made %d requests, want the initiation, one window and the terminator: %v", n, fake.trace())
	}
	assertWindow(t, fake.request(t, 1), testSession, fmt.Sprintf("bytes 0-%d/*", uploadWindowBytes-1), payload)

	term := fake.request(t, 2)
	if term.method != http.MethodPut {
		t.Errorf("terminator method = %s, want PUT", term.method)
	}
	if term.url != testSession {
		t.Errorf("terminator url = %q, want the session URI", term.url)
	}
	if len(term.body) != 0 {
		t.Errorf("the terminator carried %d bytes, want none: every byte was already sent", len(term.body))
	}
	want := fmt.Sprintf("bytes */%d", uploadWindowBytes)
	if got := term.header.Get("Content-Range"); got != want {
		t.Errorf("terminator Content-Range = %q, want %q — without the total nothing finalizes the object", got, want)
	}
	// The object exists only because the run ended on a success status; a
	// finalized upload also has no session left to abandon.
	noDelete(t, fake)
}

// TestResumableRequestsCarryTheNo308Header. Go's net/http treats 308 as a
// redirect, so the belt half of the belt-and-braces is asking GCS not to send
// one — on every request of the protocol, not just the windows.
func TestResumableRequestsCarryTheNo308Header(t *testing.T) {
	p, fake := newTestProvider(t,
		sessionStarted(testSession),
		resumeIncomplete(uploadWindowBytes),
		objectStored(),
	)
	if err := putStream(context.Background(), p, streamBytes(uploadWindowBytes)); err != nil {
		t.Fatalf("PutStream: %v", err)
	}
	for i := range fake.count() {
		req := fake.request(t, i)
		if got := req.header.Get("X-GUploader-No-308"); got != "yes" {
			t.Errorf("request %d (%s) X-GUploader-No-308 = %q, want %q", i, req.method, got, "yes")
		}
	}
}

// TestResumableTreatsAnOverridden308AsIncompleteNotSuccess.
//
// Asked not to reply 308, GCS answers 200 with the real status in a header.
// Reading only the status code turns "I am still waiting for the rest" into
// "stored", and the final request is where that difference is observable: the
// session is open, the object does not exist, and the caller is told it does.
func TestResumableTreatsAnOverridden308AsIncompleteNotSuccess(t *testing.T) {
	p, fake := newTestProvider(t,
		sessionStarted(testSession),
		resumeIncomplete(uploadWindowBytes),
		// The terminator, answered "still incomplete".
		resumeIncomplete(uploadWindowBytes),
		jsonReply(http.StatusOK, `{}`), // the abort
	)

	err := putStream(context.Background(), p, streamBytes(uploadWindowBytes))
	if err == nil {
		t.Fatal("a session that never finalized must not be reported as a stored object")
	}
	if !strings.Contains(err.Error(), "not finalized") {
		t.Errorf("err = %v, want it to say the upload was never finalized", err)
	}
	last := fake.request(t, fake.count()-1)
	if last.method != http.MethodDelete {
		t.Errorf("last request = %s %s, want the session abandoned: %v", last.method, last.url, fake.trace())
	}
}

// TestResumableHandlesARaw308WithoutFollowingIt is the braces half.
//
// The bare 308 works today only because GCS omits Location — an accident, not
// a foundation. The reply below carries one precisely so that the redirect
// machinery would fire: without CheckRedirect, net/http re-sends the whole
// window to wherever that header points, which is both a wasted upload and an
// upload to an address the service chose.
func TestResumableHandlesARaw308WithoutFollowingIt(t *testing.T) {
	payload := streamBytes(uploadWindowBytes)
	raw := mediaReply(statusResumeIncomplete, headers(
		"Location", testSession+"&followed=1",
		"Range", fmt.Sprintf("bytes=0-%d", uploadWindowBytes-1),
	), nil)

	p, fake := newTestProvider(t, sessionStarted(testSession), raw, objectStored())

	if err := putStream(context.Background(), p, payload); err != nil {
		t.Fatalf("PutStream: %v", err)
	}
	if n := fake.count(); n != 3 {
		t.Fatalf("made %d requests, want the initiation, the window and the terminator: %v", n, fake.trace())
	}
	for i := range fake.count() {
		if strings.Contains(fake.request(t, i).url, "followed=1") {
			t.Fatalf("request %d followed the 308's Location: %q", i, fake.request(t, i).url)
		}
	}
	// Treated as "resume incomplete": the upload carried on to the terminator
	// rather than stopping or restarting.
	if got := fake.request(t, 2).header.Get("Content-Range"); got != fmt.Sprintf("bytes */%d", uploadWindowBytes) {
		t.Errorf("Content-Range after the raw 308 = %q, want the terminator", got)
	}
}

// TestResumableQueriesTheCommittedOffsetBeforeResending.
//
// A blind resend is the protocol's most expensive mistake: the service may
// hold none, some or all of the window, so re-PUTting it at the original
// offset either duplicates bytes or writes them where they do not belong. The
// query is a body-less PUT — Content-Length 0, Content-Range "bytes */…" — and
// it must come BEFORE any data.
func TestResumableQueriesTheCommittedOffsetBeforeResending(t *testing.T) {
	payload := streamBytes(streamBufferBytes + 1)
	var lengths []int64
	p, fake := newTestProviderFunc(t, recordLengths(&lengths, queued(t,
		sessionStarted(testSession),
		// The window is sent and the answer is a transient failure.
		errorReply(http.StatusServiceUnavailable, "UNAVAILABLE", "try again"),
		// The query: everything landed after all.
		resumeIncomplete(uploadWindowBytes),
		objectStored(),
	)))

	if err := putStream(context.Background(), p, payload); err != nil {
		t.Fatalf("PutStream: %v", err)
	}
	if n := fake.count(); n != 4 {
		t.Fatalf("made %d requests, want the initiation, the window, the query and the last window: %v", n, fake.trace())
	}

	query := fake.request(t, 2)
	if query.method != http.MethodPut {
		t.Errorf("query method = %s, want PUT", query.method)
	}
	if query.url != testSession {
		t.Errorf("query url = %q, want the session URI", query.url)
	}
	if got := query.header.Get("Content-Range"); got != "bytes */*" {
		t.Errorf("query Content-Range = %q, want %q — the length is still unknown here", got, "bytes */*")
	}
	if len(query.body) != 0 {
		t.Errorf("the query carried %d bytes, want none: it asks a question, it does not resend", len(query.body))
	}
	if lengths[2] != 0 {
		t.Errorf("query Content-Length = %d, want 0", lengths[2])
	}

	// The finding this test exists for: after the failure the next thing that
	// carries data is the NEXT window, not a repeat of the first.
	next := fake.request(t, 3)
	if got := next.header.Get("Content-Range"); got != fmt.Sprintf("bytes %d-%d/%d", uploadWindowBytes, uploadWindowBytes, uploadWindowBytes+1) {
		t.Errorf("Content-Range after the query = %q, want the window after the one that already landed", got)
	}
	if !bytes.Equal(next.body, payload[uploadWindowBytes:]) {
		t.Errorf("the resend carried %d bytes, want the %d that had not landed", len(next.body), len(payload)-uploadWindowBytes)
	}
}

// TestResumableTreatsACompletedQueryAsSuccess.
//
// A 200 or 201 to the offset query means the upload finished and only the
// acknowledgement was lost. Treating that as an error would report data loss
// for data that is stored, and would send `farcast storage cp` round again to
// re-upload gigabytes that are already there.
func TestResumableTreatsACompletedQueryAsSuccess(t *testing.T) {
	payload := streamBytes(streamBufferBytes + 1)
	p, fake := newTestProvider(t,
		sessionStarted(testSession),
		resumeIncomplete(uploadWindowBytes),
		// The terminating window's acknowledgement is lost.
		errorReply(http.StatusServiceUnavailable, "UNAVAILABLE", "try again"),
		// The query finds a finished object.
		objectStored(),
	)

	if err := putStream(context.Background(), p, payload); err != nil {
		t.Fatalf("a lost acknowledgement over a completed upload is success, got %v", err)
	}
	if n := fake.count(); n != 4 {
		t.Fatalf("made %d requests, want the initiation, two windows and the query: %v", n, fake.trace())
	}
	query := fake.request(t, 3)
	// By this point the length IS known, and the query must say so rather than
	// "*" — the total is what tells the service which object it is being asked
	// about finalizing.
	if want := fmt.Sprintf("bytes */%d", len(payload)); query.header.Get("Content-Range") != want {
		t.Errorf("query Content-Range = %q, want %q", query.header.Get("Content-Range"), want)
	}
	if len(query.body) != 0 {
		t.Errorf("the query carried %d bytes, want none", len(query.body))
	}
	// Success means no abort: the object is stored, and a DELETE here would be
	// aimed at a session that became one.
	noDelete(t, fake)
}

// TestResumableSessionExpiredSaysSo.
//
// A 404 to the query means the session is gone. The upload cannot be resumed —
// it has to restart from zero under a fresh DEK, because the old session's
// committed bytes were sealed under a key this stream will not reuse — and the
// error has to say that, since the operator's next move depends on it.
func TestResumableSessionExpiredSaysSo(t *testing.T) {
	payload := streamBytes(streamBufferBytes + 1)
	p, fake := newTestProviderFunc(t, func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodPost:
			return sessionStarted(testSession), nil
		case r.Method == http.MethodDelete:
			return jsonReply(http.StatusOK, `{}`), nil
		case strings.HasPrefix(r.Header.Get("Content-Range"), "bytes */"):
			return errorReply(http.StatusNotFound, "NOT_FOUND", "No such upload session."), nil
		default:
			return errorReply(http.StatusServiceUnavailable, "UNAVAILABLE", "try again"), nil
		}
	})

	err := putStream(context.Background(), p, payload)
	if err == nil {
		t.Fatal("an expired session must not be reported as a stored object")
	}
	if !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "restart") {
		t.Errorf("err = %v, want it to say the session expired and the upload must be restarted", err)
	}

	// However often it asks, it never re-sends: the window's bytes go out
	// exactly once, before the session turned out to be gone.
	//
	// Only data-bearing PUTs count. The session-initiation POST carries a body
	// too — the object's JSON metadata — but it is not the window's bytes, and
	// counting it would make this assertion measure the wrong thing.
	carried := 0
	for i := range fake.count() {
		req := fake.request(t, i)
		if req.method == http.MethodPut && len(req.body) > 0 {
			carried++
		}
	}
	if carried != 1 {
		t.Errorf("%d requests carried data, want exactly one: %v", carried, fake.trace())
	}
}

// TestResumableAbortsTheSessionWhenTheUploadFails. A session left dangling is
// server-side state the operator did not ask for and may be billed for, and
// nothing else in the system knows it exists — the URI lives only in this
// call's stack.
func TestResumableAbortsTheSessionWhenTheUploadFails(t *testing.T) {
	p, fake := newTestProvider(t,
		sessionStarted(testSession),
		errorReply(http.StatusForbidden, "PERMISSION_DENIED", "does not have storage.objects.create access"),
		jsonReply(http.StatusOK, `{}`),
	)

	if err := putStream(context.Background(), p, streamBytes(streamBufferBytes+1)); err == nil {
		t.Fatal("expected the refused window to surface")
	}
	if n := fake.count(); n != 3 {
		t.Fatalf("made %d requests, want the initiation, the window and the abort: %v", n, fake.trace())
	}
	abort := fake.request(t, 2)
	if abort.method != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", abort.method)
	}
	if abort.url != testSession {
		t.Errorf("url = %q, want the session URI %q", abort.url, testSession)
	}
}

// TestResumableAbortsOnAContextThatIsAlreadyDead is the half that matters.
//
// The overwhelmingly common reason to be aborting is that the caller's context
// died — a cancelled `farcast storage cp`, a deadline, a Ctrl-C. An abort
// issued on that same context is a no-op precisely when it is needed, so it
// runs detached, and the only way to see the difference is to kill the context
// and watch for the DELETE anyway.
func TestResumableAbortsOnAContextThatIsAlreadyDead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, fake := newTestProviderFunc(t, func(r *http.Request) (*http.Response, error) {
		switch r.Method {
		case http.MethodPost:
			return sessionStarted(testSession), nil
		case http.MethodPut:
			// The caller gives up exactly where a caller does: mid-upload.
			cancel()
			return nil, errors.New("connection reset by peer")
		case http.MethodDelete:
			return jsonReply(http.StatusOK, `{}`), nil
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			return jsonReply(http.StatusInternalServerError, `{}`), nil
		}
	})

	err := putStream(ctx, p, streamBytes(streamBufferBytes+1))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if ctx.Err() == nil {
		t.Fatal("this test is only meaningful with the caller's context dead")
	}
	if n := fake.count(); n != 3 {
		t.Fatalf("made %d requests, want the initiation, the window and the abort: %v", n, fake.trace())
	}
	abort := fake.request(t, 2)
	if abort.method != http.MethodDelete || abort.url != testSession {
		t.Errorf("last request = %s %q, want DELETE of the session URI — the abort must not ride the dead context",
			abort.method, abort.url)
	}
}

// TestGetStreamRequestsTheExactRange.
//
// The header probe is the case that makes this a correctness requirement
// rather than an optimization: Store.List's name-recovery fallback asks for
// the first 1,168 bytes of an object that may be gigabytes, and gets them only
// if the range is rendered exactly right.
func TestGetStreamRequestsTheExactRange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		offset    int64
		length    int64
		wantRange string
		status    int
	}{
		// crypto.MaxHeaderLen, spelled out: the adapter knows nothing about
		// blob formats, and this is the request it must produce for one.
		{"a header probe", 0, 1168, "bytes=0-1167", http.StatusPartialContent},
		{"a frame in the middle", 4096, 1024, "bytes=4096-5119", http.StatusPartialContent},
		{"an offset to the end", 4096, -1, "bytes=4096-", http.StatusPartialContent},
		// Length -1 from offset zero is the whole object, and asking for it
		// with a Range header would invite the 200 that the ranged path has to
		// refuse.
		{"the whole object", 0, -1, "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := streamBytes(64)
			p, fake := newTestProvider(t, mediaReply(tc.status, nil, body))

			r, err := p.GetStream(context.Background(), testBucket, storedName, tc.offset, tc.length)
			if err != nil {
				t.Fatalf("GetStream: %v", err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("read the stream: %v", err)
			}
			if err := r.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Errorf("stream = %#v, want %#v", got, body)
			}

			req := fake.request(t, 0)
			if req.method != http.MethodGet {
				t.Errorf("method = %s, want GET", req.method)
			}
			// The same path escaping the whole-object Get owes: a raw "/" in a
			// tokenized name addresses a different resource entirely.
			escaped := strings.ReplaceAll(storedName, "/", "%2F")
			if want := jsonAPIBase + "b/" + testBucket + "/o/" + escaped + "?alt=media"; req.url != want {
				t.Errorf("url = %q, want %q", req.url, want)
			}
			if got := req.header.Get("Range"); got != tc.wantRange {
				t.Errorf("Range = %q, want %q", got, tc.wantRange)
			}
			if _, ok := req.header["Range"]; ok && tc.wantRange == "" {
				t.Error("an unranged read must send no Range header at all")
			}
		})
	}
}

// TestGetStreamMissingObjectIsTheSentinel: the layer above branches on it, and
// a plain error would turn a missing key into an unclassifiable failure.
func TestGetStreamMissingObjectIsTheSentinel(t *testing.T) {
	p, _ := newTestProvider(t, errorReply(http.StatusNotFound, "NOT_FOUND", "No such object."))

	r, err := p.GetStream(context.Background(), testBucket, storedName, 0, 1168)
	if !errors.Is(err, datasphere.ErrObjectNotFound) {
		t.Fatalf("err = %v, want ErrObjectNotFound", err)
	}
	if r != nil {
		t.Error("a failed GetStream must not hand back a reader to close")
	}
}

// TestGetStreamRefusesAWholeObjectAnswerToARangedRequest.
//
// A 200 to a request that carried a Range means something between here and GCS
// stripped the header. There is no safe fallback: the caller asked for bytes at
// an offset and would silently receive bytes from zero — a header probe becomes
// a multi-gigabyte download, and a frame read decrypts the wrong frame.
func TestGetStreamRefusesAWholeObjectAnswerToARangedRequest(t *testing.T) {
	p, _ := newTestProvider(t, mediaReply(http.StatusOK, nil, streamBytes(4096)))

	r, err := p.GetStream(context.Background(), testBucket, storedName, 1<<20, 1168)
	if err == nil {
		t.Fatal("a whole-object answer to a ranged read must be refused, never accepted as data from the wrong offset")
	}
	if r != nil {
		t.Error("a refused GetStream must not hand back a reader")
	}
	if !strings.Contains(err.Error(), "proxy") || !strings.Contains(err.Error(), "Range") {
		t.Errorf("err = %v, want it to name a proxy stripping the Range header", err)
	}
}

// TestGetStreamRetriesTransientFailures. The retry is on the request only:
// once bytes have been handed to the caller there is no safe way to replay
// them, so this is the one window in which a retry is honest.
func TestGetStreamRetriesTransientFailures(t *testing.T) {
	body := streamBytes(32)
	p, fake := newTestProvider(t,
		errorReply(http.StatusServiceUnavailable, "UNAVAILABLE", "try again"),
		mediaReply(http.StatusPartialContent, nil, body),
	)

	r, err := p.GetStream(context.Background(), testBucket, storedName, 0, 32)
	if err != nil {
		t.Fatalf("a transient 503 must be retried, not surfaced: %v", err)
	}
	defer func() { _ = r.Close() }()
	if got, _ := io.ReadAll(r); !bytes.Equal(got, body) {
		t.Errorf("stream = %#v, want %#v", got, body)
	}
	if n := fake.count(); n != 2 {
		t.Errorf("made %d attempts, want the failure plus one retry", n)
	}
}

// TestGetStreamRejectsANegativeOffset before the wire: it would render as a
// suffix range, which asks for the LAST n bytes — a silently different read.
func TestGetStreamRejectsANegativeOffset(t *testing.T) {
	p, fake := newTestProvider(t)
	if _, err := p.GetStream(context.Background(), testBucket, storedName, -1, 16); err == nil {
		t.Fatal("expected a refusal")
	}
	if n := fake.count(); n != 0 {
		t.Errorf("made %d requests, want none: %v", n, fake.trace())
	}
}

// TestListReportsTheCreationTime.
//
// Created rides the listing projection at no extra cost, and it is what lets
// `storage usage` report an age and a growth rate on its first run rather than
// its second. It is informational, though, so an unparseable timestamp must
// leave the field zero rather than fail a listing the recovery flows depend
// on — the cloud writes this field, and a listing that a malformed timestamp
// could kill would be a cloud-triggered outage of the one call that can still
// find billable objects when the keyring cannot name them.
func TestListReportsTheCreationTime(t *testing.T) {
	p, fake := newTestProvider(t, jsonReply(http.StatusOK, `{"items":[
		{"name":"aa/01","size":"131","timeCreated":"2026-08-27T11:22:33.456Z"},
		{"name":"aa/02","size":"131","timeCreated":"yesterday afternoon"},
		{"name":"aa/03","size":"131"}
	]}`))

	got, err := p.List(context.Background(), testBucket, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// One round trip per page still: the timestamp is part of the same
	// projection, not a second call.
	if n := fake.count(); n != 1 {
		t.Fatalf("made %d requests, want one: %v", n, fake.trace())
	}
	fields := fake.request(t, 0).query(t).Get("fields")
	if !strings.Contains(fields, "timeCreated") {
		t.Errorf("fields = %q, want the projection to ask for timeCreated", fields)
	}
	if len(got) != 3 {
		t.Fatalf("listed %d objects, want 3", len(got))
	}

	// GCS renders milliseconds; the value is normalized to UTC so callers
	// comparing two listings are never comparing two zones.
	want := time.Date(2026, 8, 27, 11, 22, 33, 456_000_000, time.UTC)
	if !got[0].Created.Equal(want) {
		t.Errorf("Created = %v, want %v", got[0].Created, want)
	}
	if loc := got[0].Created.Location(); loc != time.UTC {
		t.Errorf("Created location = %v, want UTC", loc)
	}
	for _, i := range []int{1, 2} {
		if !got[i].Created.IsZero() {
			t.Errorf("entry %d Created = %v, want the zero time", i, got[i].Created)
		}
	}
}

// TestContentRangeRendering pins the header's shape literally. Everything else
// in this file derives its expectations from the window constants, so this is
// where the wire format is actually frozen.
func TestContentRangeRendering(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int64
		n      int
		total  int64
		want   string
	}{
		{"the first window of an unknown length", 0, 8 << 20, -1, "bytes 0-8388607/*"},
		{"a later window", 8 << 20, 8 << 20, -1, "bytes 8388608-16777215/*"},
		{"the final, partial window", 16 << 20, 1 << 20, 17825792, "bytes 16777216-17825791/17825792"},
		{"a single byte", 0, 1, 1, "bytes 0-0/1"},
		// The terminator for a stream that ended on a window boundary: no
		// bytes left to send, and the total is the whole point of the request.
		{"the zero-length terminator", 8 << 20, 0, 8 << 20, "bytes */8388608"},
		// Only ever sent as a status query, where the length is still unknown.
		{"a status query", 0, 0, -1, "bytes */*"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := contentRange(tc.offset, tc.n, tc.total); got != tc.want {
				t.Errorf("contentRange(%d, %d, %d) = %q, want %q", tc.offset, tc.n, tc.total, got, tc.want)
			}
		})
	}
}

// TestByteRangeRendering. The end is inclusive, which is the off-by-one that
// would otherwise cost one byte of every ranged read — invisible on a probe
// that over-reads anyway, and a truncated frame everywhere else.
func TestByteRangeRendering(t *testing.T) {
	for _, tc := range []struct {
		offset, length int64
		want           string
	}{
		{0, 1168, "bytes=0-1167"},
		{1168, 1, "bytes=1168-1168"},
		{4096, -1, "bytes=4096-"},
		{0, -1, "bytes=0-"},
	} {
		if got := byteRange(tc.offset, tc.length); got != tc.want {
			t.Errorf("byteRange(%d, %d) = %q, want %q", tc.offset, tc.length, got, tc.want)
		}
	}
}

// TestCommittedBytesFromRangeHeader. The header is a last-byte index and the
// answer is a count, so the +1 is load-bearing: reading it as a count would
// re-send one byte at every resume and corrupt the object at the seam.
func TestCommittedBytesFromRangeHeader(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   int64
	}{
		{"bytes=0-8388607", 8 << 20},
		{"bytes=0-0", 1},
		// No Range at all is GCS's way of saying nothing landed.
		{"", 0},
		{"bytes=0-not-a-number", 0},
		{"garbage", 0},
	} {
		if got := committedBytes(tc.header); got != tc.want {
			t.Errorf("committedBytes(%q) = %d, want %d", tc.header, got, tc.want)
		}
	}
}

// TestUploadWindowIsChunkAligned. GCS requires every window but the last to be
// a multiple of 256 KiB and rejects the upload otherwise, so the constant is
// not free to be retuned to any convenient number.
func TestUploadWindowIsChunkAligned(t *testing.T) {
	if uploadWindowBytes%resumableChunkAlignment != 0 {
		t.Errorf("upload window %d is not a multiple of %d", uploadWindowBytes, resumableChunkAlignment)
	}
	if uploadWindowBytes <= 0 || streamBufferBytes <= 0 {
		t.Error("both sizes must be positive")
	}
}
