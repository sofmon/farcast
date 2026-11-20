package cli

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The two Workload Identity principals a grant can name (ADR 0023 M2.8,
// design §33, A33-4 and A33-10), in one place, so that the plan's fact, the
// read of a policy, the policy write and the printed command all name the
// same principal.
//
// Every GKE cluster in a project shares the project's Workload Identity pool,
// and IAM does not tell its clusters apart. So the principal a ServiceAccount
// is named by, …/subject/ns/<namespace>/sa/<name>, is shared by every FarCast
// instance in the project: one instance's grant to it lets another's
// keyholder or builder use it. A grant therefore names the principal Google
// documents for one ServiceAccount object, by the uid the API server gave it;
// the shared one is what a grant removes. The uid principal on a bucket's and
// a repository's policy is unverified until the M2 walk.

// serviceAccountUIDShape is a uid as the API server issues one: a
// lowercase RFC 4122 UUID.
var serviceAccountUIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// saUIDPlaceholderPrefix begins every uid placeholder (saUIDPlaceholder).
const saUIDPlaceholderPrefix = "farcast-placeholder:sa-uid:"

// The principals' formats, by project number, project ID (Google's pool for
// a project is <project>.svc.id.goog), and the uid, or the namespace and name.
const (
	// workloadUIDSegment is what precedes the uid in a uid principal.
	workloadUIDSegment          = ".svc.id.goog/kubernetes.serviceaccount.uid/"
	workloadUIDPrincipalFormat  = "principal://iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s" + workloadUIDSegment + "%s"
	workloadNamePrincipalFormat = "principal://iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s.svc.id.goog/subject/ns/%s/sa/%s"
)

// The helpers' refusals, each internal and defence in depth: a record's
// values are checked by the command that read the record (msgUnsafeRecord),
// and a uid the API server sent by its read (document_unreadable). The uid's
// refusal quotes nothing the server sent. The project's is msgUnsafeRecord's
// sentence without the instance's name, which these helpers are not given.
const (
	msgUnsafeGrantProject = "the instance's record holds a project ID that is not one Google issues (%q); farcast renders nothing from it"
	msgUnsafeGrantNumber  = "a project number of %d reached a grant, and Google numbers every project from 1; farcast renders nothing from it"
	msgUnsafeGrantUID     = "a ServiceAccount uid that is not one the API server issues reached a grant; farcast renders nothing from it"
	msgUnsafeGrantName    = "a namespace or ServiceAccount name that is not a DNS label (%q) reached a grant; farcast renders nothing from it"
)

// saUIDPlaceholder is the uid a plan binds for a ServiceAccount the command
// creates (A33-19): the real uid exists only once the account does. A
// policy is matched against it locally, where no binding can hold it, and
// nothing about it is ever sent or printed as a command.
func saUIDPlaceholder(namespace, name string) string {
	return saUIDPlaceholderPrefix + namespace + "/" + name
}

// saUIDPlaceholderOf is the namespace and name a uid placeholder stands
// for, or ok false when uid is not exactly one: saUIDPlaceholder's output for
// a namespace and a name that are each a DNS label (validNamespace).
func saUIDPlaceholderOf(uid string) (namespace, name string, ok bool) {
	rest, found := strings.CutPrefix(uid, saUIDPlaceholderPrefix)
	if !found {
		return "", "", false
	}
	namespace, name, found = strings.Cut(rest, "/")
	if !found || validNamespace(namespace) != nil || validNamespace(name) != nil {
		return "", "", false
	}
	return namespace, name, true
}

// placeholderServiceAccount is the namespace and name of the ServiceAccount
// a uid principal stands for when it carries the uid placeholder, or ok
// false when it carries none.
func placeholderServiceAccount(principal string) (namespace, name string, ok bool) {
	_, uid, found := strings.Cut(principal, workloadUIDSegment)
	if !found {
		return "", "", false
	}
	return saUIDPlaceholderOf(uid)
}

// checkGrantProject refuses a project number or ID a principal cannot be
// built from.
func checkGrantProject(number int64, project string) error {
	if number <= 0 {
		return withKind(kindInternal, fmt.Errorf(msgUnsafeGrantNumber, number))
	}
	if !projectIDShape.MatchString(project) {
		return withKind(kindInternal, fmt.Errorf(msgUnsafeGrantProject, project))
	}
	return nil
}

// workloadUIDPrincipal is the principal of the one ServiceAccount whose uid
// is uid, in project's Workload Identity pool. uid is the API server's, or
// exactly a placeholder of saUIDPlaceholder.
func workloadUIDPrincipal(number int64, project, uid string) (string, error) {
	if err := checkGrantProject(number, project); err != nil {
		return "", err
	}
	if !serviceAccountUIDShape.MatchString(uid) {
		if _, _, ok := saUIDPlaceholderOf(uid); !ok {
			return "", withKind(kindInternal, errors.New(msgUnsafeGrantUID))
		}
	}
	return fmt.Sprintf(workloadUIDPrincipalFormat, number, project, uid), nil
}

// workloadNamePrincipal is the principal every ServiceAccount named
// namespace/serviceAccount shares, in every cluster of project's pool: the
// one a grant removes.
func workloadNamePrincipal(number int64, project, namespace, serviceAccount string) (string, error) {
	if err := checkGrantProject(number, project); err != nil {
		return "", err
	}
	for _, v := range []string{namespace, serviceAccount} {
		if validNamespace(v) != nil {
			return "", withKind(kindInternal, fmt.Errorf(msgUnsafeGrantName, v))
		}
	}
	return fmt.Sprintf(workloadNamePrincipalFormat, number, project, namespace, serviceAccount), nil
}

// serviceAccountReader is what a plan reads a ServiceAccount's uid through
// (design §33, A33-18): *cluster.Client's GetMeta, metadata only. It is its
// own narrow interface, kept out of pinPlanReader, which storage key pin and
// rotate share.
type serviceAccountReader interface {
	GetMeta(ctx context.Context, k kube.Kind, namespace, name string) (kube.Object, error)
}

// msgReaderLacksServiceAccounts is a plan's refusal when the cluster's RBAC
// refuses the instance's reader the read of a ServiceAccount a grant names
// (A33-17): a reader granted before ADR 0023 M2.8, whose rule set lacks it.
// The namespace, the account, "bucket" or "push", and the instance.
const msgReaderLacksServiceAccounts = "the instance's reader may not read the ServiceAccount %s/%s, whose uid the %s grant names since ADR 0023 M2.8; " +
	"run 'farcast reader grant %s' again, which adds that read, then plan again"

// readServiceAccountUID is the uid of the ServiceAccount namespace/name, as
// the plan in mode m reads it through rd (A33-18): the reader under --plan
// and --confirm, the writer otherwise. grant is the grant that names it,
// plan.GrantBucket or plan.GrantPush, and instance the instance's name.
//
// An account that does not exist is "", with no error: the plan then binds
// the uid placeholder (A33-19). Under --plan and --confirm an RBAC 403 is a
// reader granted before ADR 0023 M2.8, refused, kind forbidden, with
// msgReaderLacksServiceAccounts, which names 'farcast reader grant' once and
// wraps the sentinel, never the server's error, so the reader's email it
// names is not echoed; it is marked as the reader's, so writerRefused adds
// nothing. Any other error is the plan's read error (planRead). A uid that
// is not one the API server issues is document_unreadable: the only refusal
// a uid the server sent meets, the principals' and the printers' checks
// behind it being defence in depth.
func readServiceAccountUID(ctx context.Context, rd serviceAccountReader, m consentMode, instance, namespace, name, grant string) (string, error) {
	k, _ := kube.KindOf("v1", "ServiceAccount")
	obj, err := rd.GetMeta(ctx, k, namespace, name)
	switch {
	case errors.Is(err, tkube.ErrNotFound):
		return "", nil
	case err != nil && m != consentNone && forbiddenByRBAC(err):
		return "", &readerPhaseError{fmt.Errorf(msgReaderLacksServiceAccounts+" (%w)", namespace, name, grant, instance, tkube.ErrForbidden)}
	case err != nil:
		return "", planRead(m, fmt.Errorf("read the ServiceAccount %s/%s: %w", namespace, name, err), instance)
	}
	uid := obj.Metadata.UID
	if !serviceAccountUIDShape.MatchString(uid) {
		return "", fmt.Errorf("the ServiceAccount %s/%s has the uid %q, which is not one the API server issues: %w", namespace, name, uid, kube.ErrUnreadable)
	}
	return uid, nil
}
