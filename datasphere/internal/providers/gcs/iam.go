package gcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/sofmon/farcast/datasphere"
)

// A bucket's IAM policy (datasphere.BucketGrants; ADR 0023 M2.8, design §33,
// A33-13): the read a plan states the keyholder's grant from, and the one
// read-modify-write that applies it under the operator's consent.
//
// The adapter writes back the WHOLE policy, so everything it does not mean to
// change goes back exactly as the server sent it. Each binding is kept as its
// raw bytes and only its role, its members and whether it has a condition are
// read; a binding this adapter does not change is written back byte for byte,
// conditions, fields it does not know and member order included. A binding
// with a condition is never counted as a grant and never rewritten: a
// conditional grant is not a guarantee of access, and rewriting one would
// widen or delete somebody else's grant.
//
// Both calls are covered by the devstorage.full_control scope the adapter
// already asks for, and neither follows a redirect (sendIAM).

const (
	// iamPolicyVersion is the policy version every read asks for and every
	// write sends. Google documents it as required to be 3 or greater for a
	// bucket with IAM Conditions, and a request for an older version than
	// the policy needs as failing (design §9.7).
	iamPolicyVersion = 3

	// maxPolicyWrites bounds EnsureGrant's writes. A write refused as stale,
	// a 409 or a 412, is read and built again once. After a second such
	// refusal the policy is read once more and nothing is written: the
	// grant done is a change, and not done is ErrPolicyChanged. That GCS
	// answers a write whose etag is stale with either code is [unverified]
	// (design §33, A33-13). send's own retries of a 429 or a 5xx replay one
	// write unchanged and are not counted.
	maxPolicyWrites = 2
)

var _ datasphere.BucketGrants = (*provider)(nil)

// bucketPolicy is a bucket's IAM policy as getIamPolicy returns it, each
// binding as the bytes the server sent.
type bucketPolicy struct {
	Version  int64             `json:"version"`
	Etag     string            `json:"etag"`
	Bindings []json.RawMessage `json:"bindings"`
}

// policyBinding is what this adapter reads of one binding.
type policyBinding struct {
	role    string
	members []string
	// conditioned is true when the binding has a condition key at all.
	conditioned bool
}

// newBinding is a binding this adapter adds: a role with one member and no
// condition.
type newBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// GrantState reads the bucket's policy once and observes member and shared
// in it (datasphere.BucketGrants). A 403 is unknown for both, with no error;
// any other failure is an error.
func (p *provider) GrantState(ctx context.Context, bucket string, roles []string, member, shared string) (state, sharedState datasphere.GrantState, sharedRoles []string, err error) {
	if err := checkGrantArgs(bucket, roles, member, shared); err != nil {
		return "", "", nil, err
	}
	_, peeked, err := p.readPolicy(ctx, bucket)
	if errors.Is(err, datasphere.ErrPermissionDenied) {
		return datasphere.GrantUnknown, datasphere.GrantUnknown, nil, nil
	}
	if err != nil {
		return "", "", nil, err
	}
	held, sharedRoles := observeGrant(peeked, roles, member, shared)
	state, sharedState = datasphere.GrantMissing, datasphere.GrantMissing
	if held {
		state = datasphere.GrantPresent
	}
	if len(sharedRoles) > 0 {
		sharedState = datasphere.GrantPresent
	}
	return state, sharedState, sharedRoles, nil
}

// EnsureGrant makes each role's binding with no condition hold member, and
// none of them hold shared (datasphere.BucketGrants):
//
//  1. it reads the policy, with its etag;
//  2. it is done when every role holds member and none holds shared;
//  3. it adds member to each role's binding with no condition, or adds
//     {role, members: [member]} when the role has none;
//  4. it removes shared from every binding of those roles with no condition,
//     and drops a binding that is left with no member;
//  5. it rewrites only the bindings it changed, and every other byte for byte;
//  6. it PUTs the policy with the etag it read and version 3;
//  7. on a 409 or a 412, taken as the policy changed since the read (which
//     code GCS answers a stale etag with is [unverified], design §33,
//     A33-13), it goes back to 1 once. After a second one it reads once
//     more and writes nothing: the grant done there is a change, and not
//     done is ErrPolicyChanged.
//
// changed is true when it sent a write and the policy holds the grant: the
// write it sent landed, or a read after a stale one finds the grant done.
// That write may be its own: send replays a write whose answer was lost,
// with the same etag, and a replay of one that landed is refused as stale.
// The wire cannot tell that from another writer's change, so it is reported
// as a change, and a removal of shared it may have made is never hidden.
// This holds for the second write as for the first. A grant found done
// before any write is sent is not a change.
//
// Its errors:
//   - ErrPolicyUnconfirmed, when a write may have landed unseen: a write no
//     answer settles (cancelled in flight, a transport failure, send's
//     retries of a 429 or a 5xx given up, a response over the cap), a
//     refusal other than a 409 or a 412 of a write one of whose earlier
//     attempts failed in transport, failed reading its body, or got a 5xx,
//     or, after any write was sent, a read that failed, or a read it would
//     write from that came without an etag or held a policy it could not
//     build. A failed read's own error stays wrapped too,
//     ErrPermissionDenied for a 403 included; such a refusal's own error
//     stays wrapped with no sentinel of its own. The read after the second
//     stale write writes nothing, so its etag is not needed: done there is
//     a change, not done is ErrPolicyChanged;
//   - ErrPermissionDenied, for a 403 on a read, or on a write none of whose
//     earlier attempts failed in transport, failed reading its body, or got
//     a 5xx;
//   - ErrPolicyChanged, when both writes were refused as stale and the read
//     after them finds the grant not done;
//   - ErrPolicyRejected, for any other refusal of such a write, a redirect
//     included: neither request of the policy follows one.
//
// A refusal other than a 409 or a 412 settles a write, as one that did not
// change the policy, only when none of its earlier attempts failed in
// transport, failed reading its body, or got a 5xx: such an attempt may
// have landed, and its replay be refused for another reason. A 429 does
// not unsettle it, since the server did not process that attempt. A
// failure before any write was sent changed nothing. One case is not
// detected: a write of its own that landed with its answer lost and that
// another writer then undid before a read found the grant not done. A
// later refusal, or ErrPolicyChanged, then keeps its own sentinel.
func (p *provider) EnsureGrant(ctx context.Context, bucket string, roles []string, member, shared string) (changed bool, err error) {
	if err := checkGrantArgs(bucket, roles, member, shared); err != nil {
		return false, err
	}
	// sent is whether a write has been sent: from then on a failure may
	// follow a write that landed.
	sent := false
	failed := func(err error) error {
		if sent && !errors.Is(err, datasphere.ErrPolicyUnconfirmed) {
			return fmt.Errorf("%w (%w)", datasphere.ErrPolicyUnconfirmed, err)
		}
		return err
	}
	// stale is the last write's refusal as stale, once there is one.
	var stale error
	for read := 1; ; read++ {
		pol, peeked, err := p.readPolicy(ctx, bucket)
		if err != nil {
			return false, failed(err)
		}
		if held, sharedRoles := observeGrant(peeked, roles, member, shared); held && len(sharedRoles) == 0 {
			return sent, nil
		}
		if read > maxPolicyWrites {
			// Every write was refused as stale, and this read, which
			// writes nothing, finds the grant not done.
			return false, stale
		}
		if pol.Etag == "" {
			// Without an etag the write would not be conditional on the read,
			// and could overwrite a change made since.
			return false, failed(fmt.Errorf("gcs: the IAM policy of bucket %q came without an etag, so a write built from it could overwrite a change made since; it was not sent", bucket))
		}
		body, err := grantedPolicy(pol, peeked, roles, member, shared)
		if err != nil {
			return false, failed(fmt.Errorf("gcs: build the IAM policy of bucket %q: %w", bucket, err))
		}
		sent = true
		answered, err := p.putPolicy(ctx, bucket, body)
		switch {
		case err == nil:
			return true, nil
		case !answered:
			return false, fmt.Errorf("gcs: set the IAM policy of bucket %q: %w (%w)", bucket, datasphere.ErrPolicyUnconfirmed, err)
		case isHTTPStatus(err, http.StatusConflict), isHTTPStatus(err, http.StatusPreconditionFailed):
			stale = fmt.Errorf("gcs: set the IAM policy of bucket %q: %w (%w)", bucket, datasphere.ErrPolicyChanged, err)
		case isHTTPStatus(err, http.StatusForbidden):
			return false, fmt.Errorf("gcs: set the IAM policy of bucket %q: %w (%w)", bucket, datasphere.ErrPermissionDenied, err)
		default:
			return false, fmt.Errorf("gcs: set the IAM policy of bucket %q: %w (%w)", bucket, datasphere.ErrPolicyRejected, err)
		}
	}
}

// checkGrantArgs refuses a grant that names no bucket, no role, a role twice,
// no member or no shared principal, or the same principal as both, before
// anything is sent.
func checkGrantArgs(bucket string, roles []string, member, shared string) error {
	switch {
	case bucket == "":
		return errors.New("gcs: a bucket's IAM needs the bucket's name")
	case len(roles) == 0:
		return errors.New("gcs: a bucket grant needs at least one role")
	case member == "" || shared == "":
		return errors.New("gcs: a bucket grant needs its member and the shared principal it replaces")
	case member == shared:
		return errors.New("gcs: a bucket grant's member and the shared principal it replaces are one principal")
	}
	for i, r := range roles {
		if r == "" || slices.Contains(roles[:i], r) {
			return fmt.Errorf("gcs: a bucket grant's roles must be distinct and named: %q", roles)
		}
	}
	return nil
}

// readPolicy is getIamPolicy at version 3, and what this adapter reads of each
// binding. A 403 wraps ErrPermissionDenied and a 404 ErrBucketNotFound.
func (p *provider) readPolicy(ctx context.Context, bucket string) (bucketPolicy, []policyBinding, error) {
	target := fmt.Sprintf("%sb/%s/iam?optionsRequestedPolicyVersion=%d", p.base, url.PathEscape(bucket), iamPolicyVersion)
	var pol bucketPolicy
	rep, err := p.sendIAM(ctx, http.MethodGet, target, nil)
	if err == nil {
		err = decodeReply(rep, &pol)
	}
	if err != nil {
		switch {
		case isHTTPStatus(err, http.StatusForbidden):
			return bucketPolicy{}, nil, fmt.Errorf("gcs: read the IAM policy of bucket %q: %w (%w)", bucket, datasphere.ErrPermissionDenied, err)
		case isHTTPStatus(err, http.StatusNotFound):
			return bucketPolicy{}, nil, fmt.Errorf("gcs: read the IAM policy of bucket %q: %w (%w)", bucket, datasphere.ErrBucketNotFound, err)
		}
		return bucketPolicy{}, nil, fmt.Errorf("gcs: read the IAM policy of bucket %q: %w", bucket, err)
	}
	peeked := make([]policyBinding, len(pol.Bindings))
	for i, raw := range pol.Bindings {
		b, err := peekBinding(raw)
		if err != nil {
			return bucketPolicy{}, nil, fmt.Errorf("gcs: binding %d of the IAM policy of bucket %q does not decode: %w", i, bucket, err)
		}
		peeked[i] = b
	}
	return pol, peeked, nil
}

// peekBinding reads a binding's role, its members, and whether it has a
// condition key, null included.
func peekBinding(raw json.RawMessage) (policyBinding, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return policyBinding{}, err
	}
	var b policyBinding
	if r, ok := fields["role"]; ok {
		if err := json.Unmarshal(r, &b.role); err != nil {
			return policyBinding{}, fmt.Errorf("its role: %w", err)
		}
	}
	if m, ok := fields["members"]; ok {
		if err := json.Unmarshal(m, &b.members); err != nil {
			return policyBinding{}, fmt.Errorf("its members: %w", err)
		}
	}
	_, b.conditioned = fields["condition"]
	return b, nil
}

// holdsMember reports whether a binding of role with no condition holds
// member exactly.
func holdsMember(bindings []policyBinding, role, member string) bool {
	for _, b := range bindings {
		if b.role == role && !b.conditioned && slices.Contains(b.members, member) {
			return true
		}
	}
	return false
}

// observeGrant is design §33's two observations of one policy: whether every
// role holds member, and the roles, in roles' order, that hold shared.
func observeGrant(bindings []policyBinding, roles []string, member, shared string) (held bool, sharedRoles []string) {
	held = true
	for _, role := range roles {
		if !holdsMember(bindings, role, member) {
			held = false
		}
		if holdsMember(bindings, role, shared) {
			sharedRoles = append(sharedRoles, role)
		}
	}
	return held, sharedRoles
}

// grantedPolicy is the PUT body that grants member every role and removes
// shared from them (EnsureGrant's steps 3 to 6): the bindings in their order,
// each changed one rebuilt, each other one as it was read, then the new ones
// in roles' order; the etag of the read; version 3.
func grantedPolicy(pol bucketPolicy, peeked []policyBinding, roles []string, member, shared string) ([]byte, error) {
	granted := map[string]bool{}
	for _, role := range roles {
		granted[role] = holdsMember(peeked, role, member)
	}
	out := make([]json.RawMessage, 0, len(pol.Bindings)+len(roles))
	for i, raw := range pol.Bindings {
		b := peeked[i]
		if b.conditioned || !slices.Contains(roles, b.role) {
			out = append(out, raw)
			continue
		}
		members := slices.DeleteFunc(slices.Clone(b.members), func(m string) bool { return m == shared })
		changed := len(members) != len(b.members)
		if !granted[b.role] {
			members = append(members, member)
			granted[b.role], changed = true, true
		}
		switch {
		case !changed:
			out = append(out, raw)
		case len(members) == 0:
			// Left with no member: dropped, as IAM itself would.
		default:
			rebuilt, err := withMembers(raw, members)
			if err != nil {
				return nil, err
			}
			out = append(out, rebuilt)
		}
	}
	for _, role := range roles {
		if granted[role] {
			continue
		}
		added, err := marshalUnescaped(newBinding{Role: role, Members: []string{member}})
		if err != nil {
			return nil, err
		}
		out = append(out, added)
	}
	etag, err := marshalUnescaped(pol.Etag)
	if err != nil {
		return nil, err
	}
	// Assembled by hand: encoding/json would compact and HTML-escape the raw
	// bindings, and they go back as they came.
	var body bytes.Buffer
	body.WriteString(`{"bindings":[`)
	for i, b := range out {
		if i > 0 {
			body.WriteByte(',')
		}
		body.Write(b)
	}
	fmt.Fprintf(&body, `],"etag":%s,"version":%d}`, etag, iamPolicyVersion)
	return body.Bytes(), nil
}

// withMembers is a binding with its members replaced and every other field
// kept.
func withMembers(raw json.RawMessage, members []string) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	m, err := marshalUnescaped(members)
	if err != nil {
		return nil, err
	}
	fields["members"] = m
	return marshalUnescaped(fields)
}

// marshalUnescaped is json.Marshal without HTML escaping or the trailing
// newline.
func marshalUnescaped(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// putPolicy is setIamPolicy: the body as built, sent through sendIAM, whose
// retries of a 429 or a 5xx replay it unchanged, the same etag included.
// answered is whether the server's final answer settles the write: a 2xx;
// a 409 or a 412, which the read after it settles; or another refusal send
// does not retry, a redirect included, when none of the write's earlier
// attempts failed in transport, failed reading its body, or got a 5xx.
// After such an attempt, which may have landed, that refusal answers only
// the replay: it is returned as its *apiError, unanswered. send's own
// error (a cancellation, a transport failure, retries given up, a response
// over the cap) settles nothing either: the write may have landed.
func (p *provider) putPolicy(ctx context.Context, bucket string, body []byte) (answered bool, err error) {
	rep, err := p.sendIAM(ctx, http.MethodPut, p.base+"b/"+url.PathEscape(bucket)+"/iam", body)
	if err != nil {
		return false, err
	}
	if !okStatus(rep.status) {
		err := parseAPIError(rep.status, rep.body)
		stale := isHTTPStatus(err, http.StatusConflict) || isHTTPStatus(err, http.StatusPreconditionFailed)
		return !rep.unsettled || stale, err
	}
	return true, nil
}

// sendIAM is send for a bucket's IAM policy, through a client that follows
// no redirect, as uploadDo's does. net/http would follow a 301, a 302 or a
// 303 to the PUT as a GET, and report that GET's answer as the write's: a
// 2xx there would be a change no write made. A 3xx is returned as the
// answer it is, a refusal.
func (p *provider) sendIAM(ctx context.Context, method, target string, body []byte) (*reply, error) {
	hc, err := p.client()
	if err != nil {
		return nil, err
	}
	noRedirect := &http.Client{
		Transport:     hc.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	contentType := ""
	if body != nil {
		contentType = "application/json"
	}
	return sendVia(ctx, noRedirect, method, target, contentType, body, maxResponseBytes)
}
