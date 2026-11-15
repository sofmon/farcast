package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// errReaderOnly is Open's refusal until ADR 0023 M2.5, when it accepts the
// writer too.
var errReaderOnly = errors.New("cluster: until ADR 0023 M2.5 Open builds a reader only")

// Open builds a Client that reaches the cluster in-process, through
// internal/kube (ADR 0023 decision 2), as one of the instance's identities. It
// starts no program, dials nothing and mints nothing until a method is called.
//
// Until ADR 0023 M2.5 it builds a reader only: it refuses any identity but
// kube.Reader, and any legacyKubeconfig, which only a writer's transitional
// kubectl Apply will use. An Open'd client answers NamespacesLabelled and CanI
// in-process; every other method returns an error naming itself, and never
// runs kubectl (ADR 0023 M2.4 moves the reads).
//
// warnings receives each distinct API Warning header text, once, as
// "Warning (cluster): <text>\n", after the call whose answer carried it. A
// text that would not print as it is (a control character, a bidi override,
// invalid UTF-8) is written Go-quoted instead, because it comes from the
// server. A nil warnings discards them.
func Open(cfg kube.Config, warnings io.Writer, legacyKubeconfig string) (*Client, error) {
	if cfg.Identity != kube.Reader || legacyKubeconfig != "" {
		return nil, errReaderOnly
	}
	kc, err := kube.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{kube: kc, warnings: warnings}, nil
}

// CanI asks the API server whether this client's identity may do one thing:
// kube.Client.SelfSubjectAccessReview, for the proof 'farcast reader grant'
// makes that the reader cannot write (ADR 0023 §7.2). It is in-process only:
// a kubectl client refuses it and runs nothing.
func (c *Client) CanI(ctx context.Context, a kube.ResourceAttributes) (bool, error) {
	if c.kube == nil {
		return false, errors.New("cluster: CanI is in-process only, and this client runs kubectl")
	}
	allowed, err := c.kube.SelfSubjectAccessReview(ctx, a)
	c.flushWarnings()
	if err != nil {
		return false, err
	}
	return allowed, nil
}

// namespacesInProcess is NamespacesLabelled on an Open'd client: kube's
// ListNamespaces with the selector, paged, the names sorted.
func (c *Client) namespacesInProcess(ctx context.Context, selector string) ([]string, error) {
	names, err := c.kube.ListNamespaces(ctx, selector)
	c.flushWarnings()
	if err != nil {
		return nil, err
	}
	return names, nil
}

// kubectlOnly refuses a method an Open'd client does not have in-process yet.
// It is the first thing every such method does, so an Open'd client, which
// has no Runner, never reaches one.
func (c *Client) kubectlOnly(method string) error {
	if c.kube != nil {
		return fmt.Errorf("cluster: %s is not in-process until ADR 0023 M2.4", method)
	}
	return nil
}

// flushWarnings writes every Warning text the kube client has seen and this
// client has not yet written. kube keeps each distinct text once, in the
// order first seen, so what is new is the tail after the last count written.
func (c *Client) flushWarnings() {
	texts := c.kube.Warnings()
	c.warnMu.Lock()
	defer c.warnMu.Unlock()
	if len(texts) <= c.warned {
		return
	}
	fresh := texts[c.warned:]
	c.warned = len(texts)
	if c.warnings == nil {
		return
	}
	for _, t := range fresh {
		if !output.Printable(t) {
			t = strconv.QuoteToGraphic(t)
		}
		_, _ = fmt.Fprintf(c.warnings, "Warning (cluster): %s\n", t)
	}
}
