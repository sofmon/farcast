package kube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// logChunk is the size of each write StreamLog makes to its writer.
const logChunk = 32 << 10

// StreamLog copies one container's log to w (§4): GET
// /api/v1/namespaces/<ns>/pods/<pod>/log, with container, tailLines, follow
// and previous as o gives them.
//
// TailLines < 0 is everything, sent as no tailLines parameter at all: the API
// defines everything as the parameter absent, and kubectl v0.37.2
// (pkg/cmd/logs/logs.go, LogsOptions.ToLogOptions) omits it for its default
// of -1. Otherwise it is sent as a decimal integer, 0 included.
//
// A log is a stream: it has no per-request deadline and no size cap, and a
// followed one runs until ctx ends, when StreamLog returns ctx's error. A
// followed one also has no ResponseHeaderTimeout, because the kubelet sends
// its headers only with the first line; one that does not follow keeps it. A
// failure of w is returned as it is.
func (c *Client) StreamLog(ctx context.Context, namespace, pod string, o LogOptions, w io.Writer) error {
	path, err := objectPath(kindPod, namespace, pod)
	if err != nil {
		return err
	}
	q := url.Values{}
	if o.Container != "" {
		q.Set("container", o.Container)
	}
	if o.TailLines >= 0 {
		q.Set("tailLines", strconv.Itoa(o.TailLines))
	}
	if o.Follow {
		q.Set("follow", "true")
	}
	if o.Previous {
		q.Set("previous", "true")
	}
	cl := call{method: http.MethodGet, path: path + "/log", query: q, retry: true, stream: true, follow: o.Follow}
	resp, done, err := c.open(ctx, cl)
	if err != nil {
		return err
	}
	defer done()

	buf := make([]byte, logChunk)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if errors.Is(rerr, io.EOF) {
			return nil
		}
		if rerr != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("kube: %s %s: %w", cl.method, cl.path, ctx.Err())
			}
			return unreachable(ctx, ctx, 0, cl, rerr)
		}
	}
}
