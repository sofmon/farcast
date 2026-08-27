package gcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
)

// Streaming: uploads of unbounded size, and ranged reads.
//
// GCS offers two upload shapes and this adapter uses both, because using only
// the second would make every small write pay for a session it does not need.
// Below a threshold an object goes out as the single multipart request the
// non-streaming path already uses; above it, a resumable session.
//
// The resumable protocol is hand-issued here rather than vendored. The module
// README's decision 8 named streaming as the trigger to re-open that trade, and
// re-measuring closed it the same way: the official clients cost +18 modules
// (plus 18 forced upgrades of modules the shipped Planck provider depends on)
// or +1 for the generated client, against a CLI that already hand-rolled a
// 3,000-line OCI distribution client rather than vendor into the binary holding
// the operator's cloud credentials. What that buys us is the obligation to get
// the protocol's sharp edges right, each of which is called out below.

const (
	// streamBufferBytes is how much of a stream is held before committing to a
	// transport. A stream that ends inside this window becomes one ordinary
	// multipart insert, so a small streaming write costs exactly one request.
	streamBufferBytes = 8 << 20

	// uploadWindowBytes is how much is sent per resumable PUT. GCS requires
	// every window except the last to be a multiple of 256 KiB.
	uploadWindowBytes = 8 << 20

	// resumableChunkAlignment is that 256 KiB requirement, asserted rather
	// than assumed.
	resumableChunkAlignment = 256 << 10

	// abortTimeout bounds the best-effort session abort, which deliberately
	// runs on a context detached from the caller's.
	abortTimeout = 5 * time.Second

	// statusResumeIncomplete is GCS's "send me more" answer to a window PUT.
	statusResumeIncomplete = 308
)

// errSessionGone reports that the upload session no longer exists. It is
// terminal, not retryable: there is nothing left to resume against, and asking
// again only delays telling the caller. Restarting means a new session under a
// new data key, which is the caller's decision because it needs a source that
// can rewind.
var errSessionGone = errors.New("gcs: the resumable upload session has expired; the upload must be restarted")

// PutStream stores an object of unbounded size.
func (p *provider) PutStream(ctx context.Context, bucket string, obj datasphere.StreamObject) error {
	if obj.Name == "" {
		return errors.New("gcs: an object name is required")
	}
	if obj.Data == nil {
		return errors.New("gcs: a data stream is required")
	}

	// Buffer the head of the stream. If it ends here the object is small and
	// the shipped single-request path is both cheaper and atomic for free.
	head := make([]byte, streamBufferBytes)
	n, err := io.ReadFull(obj.Data, head)
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return p.Put(ctx, bucket, datasphere.Object{Name: obj.Name, Data: head[:n], Meta: obj.Meta})
	case err != nil:
		return fmt.Errorf("gcs: read object stream: %w", err)
	}
	return p.putResumable(ctx, bucket, obj, head[:n])
}

// putResumable runs a resumable session for a stream whose head is already in
// hand. On any failure it abandons the session rather than leaving it dangling.
func (p *provider) putResumable(ctx context.Context, bucket string, obj datasphere.StreamObject, head []byte) error {
	session, err := p.startResumable(ctx, bucket, obj)
	if err != nil {
		return err
	}

	if err := p.uploadWindows(ctx, session, io.MultiReader(bytes.NewReader(head), obj.Data)); err != nil {
		// Abandon on a context DETACHED from the caller's. The overwhelmingly
		// common reason to be aborting is that ctx died, so an abort riding ctx
		// would be a no-op exactly when it is needed.
		p.abortResumable(context.WithoutCancel(ctx), session)
		return err
	}
	return nil
}

// startResumable opens an upload session and returns its URI.
func (p *provider) startResumable(ctx context.Context, bucket string, obj datasphere.StreamObject) (string, error) {
	metadata, err := json.Marshal(objectResource{Name: obj.Name, Metadata: obj.Meta})
	if err != nil {
		return "", fmt.Errorf("gcs: encode object metadata: %w", err)
	}
	query := url.Values{"uploadType": {"resumable"}, "fields": {"name"}}
	target := p.upload + "b/" + url.PathEscape(bucket) + "/o?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(metadata))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	resp, err := p.uploadDo(req)
	if err != nil {
		return "", fmt.Errorf("gcs: start resumable upload: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if !okStatus(resp.StatusCode) {
		return "", fmt.Errorf("gcs: start resumable upload into %q: %w", bucket, parseAPIError(resp.StatusCode, body))
	}
	session := resp.Header.Get("Location")
	if session == "" {
		return "", errors.New("gcs: resumable upload accepted with no session URI")
	}
	return session, nil
}

// uploadWindows sends the stream a window at a time until the source is
// exhausted, then finalizes.
func (p *provider) uploadWindows(ctx context.Context, session string, src io.Reader) error {
	if uploadWindowBytes%resumableChunkAlignment != 0 {
		return fmt.Errorf("gcs: upload window %d is not a multiple of %d", uploadWindowBytes, resumableChunkAlignment)
	}
	window := make([]byte, uploadWindowBytes)
	var sent int64
	for {
		n, err := io.ReadFull(src, window)
		final := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		if err != nil && !final {
			return fmt.Errorf("gcs: read object stream: %w", err)
		}

		total := int64(-1)
		if final {
			total = sent + int64(n)
		}
		// The zero-length terminator matters: a stream that ends exactly on a
		// window boundary still needs a final request carrying the total, or
		// the object is never finalized and the session simply expires.
		done, err := p.uploadWindow(ctx, session, window[:n], sent, total)
		if err != nil {
			return err
		}
		sent += int64(n)
		if final {
			if !done {
				return fmt.Errorf("gcs: upload of %d bytes was not finalized", sent)
			}
			return nil
		}
	}
}

// uploadWindow sends one window and reports whether the object is complete.
// total is -1 while the length is still unknown.
func (p *provider) uploadWindow(ctx context.Context, session string, data []byte, offset, total int64) (bool, error) {
	backoff := retryBackoff
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepWithContext(ctx, jitter(backoff)); err != nil {
				return false, err
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			// Never re-send blindly: ask what the service actually committed.
			// A completed answer here means the upload finished and only the
			// acknowledgement was lost, which is success, not a retry.
			committed, done, err := p.resumableOffset(ctx, session, total)
			switch {
			case errors.Is(err, errSessionGone):
				return false, err
			case err != nil:
				lastErr = err
				continue
			case done:
				return true, nil
			case committed != offset+int64(len(data)) && committed != offset:
				return false, fmt.Errorf("gcs: resumable session committed %d bytes, cannot resume a window at %d", committed, offset)
			case committed == offset+int64(len(data)):
				return false, nil // this window already landed
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPut, session, bytes.NewReader(data))
		if err != nil {
			return false, err
		}
		req.ContentLength = int64(len(data))
		req.Header.Set("Content-Range", contentRange(offset, len(data), total))
		resp, err := p.uploadDo(req)
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			lastErr = err
			continue
		}
		status := resumableStatus(resp)
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()

		switch {
		case status == statusResumeIncomplete:
			return false, nil
		case okStatus(status):
			return true, nil
		case retryableStatus(status):
			lastErr = parseAPIError(status, body)
			continue
		default:
			return false, fmt.Errorf("gcs: upload window at %d: %w", offset, parseAPIError(status, body))
		}
	}
	return false, fmt.Errorf("gcs: giving up on a resumable window after %d attempts: %w", maxAttempts, lastErr)
}

// resumableOffset queries how much of the session the service has committed,
// reporting done when the object turned out to be complete already.
func (p *provider) resumableOffset(ctx context.Context, session string, total int64) (int64, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, session, nil)
	if err != nil {
		return 0, false, err
	}
	req.ContentLength = 0
	req.Header.Set("Content-Range", "bytes */"+totalOrStar(total))
	resp, err := p.uploadDo(req)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	status := resumableStatus(resp)
	switch {
	case okStatus(status):
		return 0, true, nil
	case status == statusResumeIncomplete:
		return committedBytes(resp.Header.Get("Range")), false, nil
	case status == http.StatusNotFound:
		// The session is gone. Restarting means a fresh session under a fresh
		// data key — never resuming an old one over a possibly different byte
		// stream, which is the one way this scheme could be broken.
		return 0, false, fmt.Errorf("%w: %w", errSessionGone, parseAPIError(status, body))
	default:
		return 0, false, parseAPIError(status, body)
	}
}

// abortResumable releases a session's server-side state, best effort.
func (p *provider) abortResumable(ctx context.Context, session string) {
	ctx, cancel := context.WithTimeout(ctx, abortTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, session, nil)
	if err != nil {
		return
	}
	req.ContentLength = 0
	resp, err := p.uploadDo(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	_ = resp.Body.Close()
}

// GetStream returns a reader over a byte range of an object.
//
// Retries wrap only the request, never a partially consumed body: once bytes
// have been handed to the caller there is no safe way to replay them, so a
// failure mid-stream surfaces to the caller instead of being papered over.
func (p *provider) GetStream(ctx context.Context, bucket, name string, offset, length int64) (io.ReadCloser, error) {
	if offset < 0 {
		return nil, fmt.Errorf("gcs: offset must not be negative, got %d", offset)
	}
	ranged := offset > 0 || length >= 0
	target := p.objectURL(bucket, name) + "?alt=media"

	hc, err := p.client()
	if err != nil {
		return nil, err
	}
	backoff := retryBackoff
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepWithContext(ctx, jitter(backoff)); err != nil {
				return nil, err
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		if ranged {
			req.Header.Set("Range", byteRange(offset, length))
		}
		resp, err := hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			continue
		}
		switch {
		case resp.StatusCode == http.StatusNotFound:
			_ = resp.Body.Close()
			return nil, fmt.Errorf("%w: %s", datasphere.ErrObjectNotFound, name)
		case retryableStatus(resp.StatusCode):
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
			_ = resp.Body.Close()
			lastErr = parseAPIError(resp.StatusCode, body)
			continue
		case ranged && resp.StatusCode == http.StatusOK:
			// A 200 to a ranged request means something stripped the header.
			// Accepting it would hand the caller bytes from the wrong offset
			// and turn a header probe into a full-object download.
			_ = resp.Body.Close()
			return nil, fmt.Errorf("gcs: ranged read of %q was answered with the whole object; a proxy is stripping the Range header", name)
		case !okStatus(resp.StatusCode):
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
			_ = resp.Body.Close()
			return nil, fmt.Errorf("gcs: get object from %q: %w", bucket, parseAPIError(resp.StatusCode, body))
		}
		return resp.Body, nil
	}
	return nil, fmt.Errorf("gcs: giving up after %d attempts: %w", maxAttempts, lastErr)
}

// uploadDo issues one upload-protocol request.
//
// It does not follow redirects, which is the first thing that breaks if it is
// forgotten: Go's net/http treats 308 as a redirect, and GCS answers a partial
// upload with 308. That works today only because GCS omits Location, which is
// not a foundation. The header below asks GCS to answer 200 with an override
// header instead, and CheckRedirect makes the raw 308 safe either way.
func (p *provider) uploadDo(req *http.Request) (*http.Response, error) {
	hc, err := p.client()
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-GUploader-No-308", "yes")
	uploader := &http.Client{
		Transport:     hc.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return uploader.Do(req)
}

// resumableStatus reads a response's effective status, honouring the override
// header GCS sends when asked not to reply 308.
func resumableStatus(resp *http.Response) int {
	if override := resp.Header.Get("X-Http-Status-Code-Override"); override != "" {
		if code, err := strconv.Atoi(override); err == nil {
			return code
		}
	}
	return resp.StatusCode
}

// contentRange renders the Content-Range of one upload window. total is -1
// while the stream's length is still unknown.
func contentRange(offset int64, n int, total int64) string {
	if n == 0 {
		return "bytes */" + totalOrStar(total)
	}
	return fmt.Sprintf("bytes %d-%d/%s", offset, offset+int64(n)-1, totalOrStar(total))
}

func totalOrStar(total int64) string {
	if total < 0 {
		return "*"
	}
	return strconv.FormatInt(total, 10)
}

// committedBytes reads how much the service holds from a Range response
// header of the form "bytes=0-<last>". An absent header means nothing landed.
func committedBytes(header string) int64 {
	_, last, found := strings.Cut(strings.TrimPrefix(header, "bytes="), "-")
	if !found {
		return 0
	}
	n, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		return 0
	}
	return n + 1
}

// byteRange renders a Range request header; length -1 means to the end.
func byteRange(offset, length int64) string {
	if length < 0 {
		return fmt.Sprintf("bytes=%d-", offset)
	}
	return fmt.Sprintf("bytes=%d-%d", offset, offset+length-1)
}
