package kube

import (
	"context"
	"net/http"
	"time"
)

// SetSleep replaces c's wait between retries, for package kube_test: the
// retry tests record the waits instead of sleeping them.
func SetSleep(c *Client, f func(ctx context.Context, d time.Duration) error) { c.sleep = f }

// SetAttemptTimeout shortens c's per-attempt deadline of a non-streaming
// request (60 s in a product client), for package kube_test.
func SetAttemptTimeout(c *Client, d time.Duration) { c.attemptTimeout = d }

// SetResponseHeaderTimeout shortens the API transport's wait for an answer's
// headers (30 s in a product client), for package kube_test. The follow
// client, which has none, is left as it is. Call it before c sends anything.
func SetResponseHeaderTimeout(c *Client, d time.Duration) {
	c.api.Transport.(*apiTransport).inner.(*http.Transport).ResponseHeaderTimeout = d
}

// The documents stream_test.go hides a refused key in, from go-yaml alone
// (C-C2-1, C-C2-2), for package kube_test's Apply rows.
const (
	FlowHidingStatus          = flowHidingStatus
	QuestionHidingStringData  = questionHidingStringData
	MultiLineHidingStringData = multiLineHidingStringData
	BareEntryHidingStringData = bareEntryHidingStringData
	LoneQuestionHidingStatus  = loneQuestionHidingStatus
)

// UTF16Polyglot is stream_test.go's UTF-16LE polyglot Secret.
func UTF16Polyglot() string { return utf16Polyglot() }
