package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/planck"
	pbuild "github.com/sofmon/farcast/planck/build"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
)

// The builder pushes under its own cloud identity, and FarCast does not grant
// that identity push access — see writePushGrant for why, and for what the
// reason actually is.
//
// This file exists because the grant used to be printed in exactly one place:
// the SUCCESS result of `farcast build`. So it appeared after a build that had
// already worked, and never on the failure it explains. `farcast run` did not
// print it at all, though [the 4.3 runbook] said it did. The 5.1b walk hit
// precisely that: a build failed at push with a raw Kaniko error, several
// minutes of clone and build already paid for, and nothing anywhere naming the
// one command that fixes it.
//
// Since ADR 0023 M2.8 (design §33, A33-22) build's and run's deploy plans read
// the grant's state from the repository's own IAM policy, as the installer
// key, in every mode, and bind it as a grant fact. A grant that is not
// present is a notice, never a block: the read cannot see a grant at the
// project, through a group or by a wider role (A33-3). The grant names the
// builder's ServiceAccount by its uid, which every cluster in the project's
// Workload Identity pool does not share, and the printed commands remove the
// principal every instance in the project shares (A33-4). The uid member on
// a repository's policy is unverified until the M2 walk.
//
// [the 4.3 runbook]: ../../../../docs/runbooks/phase-4-3-validation.md

// pushRole is the one role the builder's push grant names.
const pushRole = "roles/artifactregistry.writer"

// builderAccount is the builder's ServiceAccount as a grant fact and the
// texts name it.
const builderAccount = pbuild.Namespace + "/" + pbuild.ServiceAccount

// registryNameShape is the shape a printed command takes a repository or a
// location in (A33-15): what registryRefFor returns for a record farcast
// wrote.
var registryNameShape = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// The push grant's texts (design §33, A33-15, A33-22).
const (
	// msgRegistryUnnamed is build's and run's refusal of a record that
	// names an image registry by its prefix and not its repository or its
	// location, which only a hand edit makes: registryRefFor would fall
	// back to a repository the adapter never names (A33-15).
	msgRegistryUnnamed = "instance %q's record names an image registry but not its repository or its location; farcast reads and renders nothing from it"

	msgPushGrantMissing = "The builder's ServiceAccount farcast-system/farcast-builder pushes under its own cloud identity, and the repository's own policy " +
		"does not hold roles/artifactregistry.writer for it by its uid (a grant at the project, through a group or by a wider role does not show here). " +
		"If nothing wider covers it, the push is refused after the build has run. Grant it in Cloud Shell:"
	msgPushGrantShared = "The repository's own policy grants the builder roles/artifactregistry.writer by its uid, and still grants it to the principal " +
		"every FarCast instance in project %q shares. Remove that one in Cloud Shell:"
	msgPushGrantUnknown = "The stored credential may not read the repository's IAM policy, so whether the builder may push is not known."
	msgPushGrantPending = "The builder's ServiceAccount farcast-system/farcast-builder does not exist yet: this command creates it, and prints the commands " +
		"that grant it by its uid right after the build starts. Until that grant is in place and IAM has propagated, the push is refused unless a " +
		"wider grant covers it. 'farcast kernel deploy' creates the account ahead of any build."
	// msgPlanBeforeGrant ends a notice whose grant is not in place: the
	// plan binds the state it read (A33-22).
	msgPlanBeforeGrant = "A plan made before this grant cannot be confirmed after it."
	// msgPushGrantNow introduces the commands printed right after a build's
	// apply, once the account a plan bound the placeholder for exists.
	msgPushGrantNow = "The builder's ServiceAccount exists now; grant it while the build runs, and a grant that lands before the push lets this build succeed:"
	// msgPushGrantUnread is the one line printed in place of the commands
	// when the builder's ServiceAccount could not be read after the apply:
	// the error, and the instance.
	msgPushGrantUnread = "the builder's ServiceAccount farcast-system/farcast-builder could not be read (%v); 'farcast build %s … --plan' states the grant"
)

// refuseUnnamedRegistry refuses a record whose registry has a prefix and no
// repository or location (msgRegistryUnnamed), kind internal, before
// anything is read or printed. recordRegistry always records both.
func refuseUnnamedRegistry(meta *config.InstanceMetadata) error {
	if r := meta.Registry; r != nil && r.Prefix != "" && (r.Repository == "" || r.Location == "") {
		return withKind(kindInternal, fmt.Errorf(msgRegistryUnnamed, meta.Name))
	}
	return nil
}

// pushGrantRecord is the record's values a push grant's commands print, each
// checked (A33-15): the project against Google's project-ID shape, and the
// repository and the location registryRefFor names against
// registryNameShape. A value that fails refuses, kind internal, with
// msgUnsafeRecord's words, before anything is read.
func pushGrantRecord(meta *config.InstanceMetadata) (project, repository, location string, err error) {
	if err := refuseUnnamedRegistry(meta); err != nil {
		return "", "", "", err
	}
	if !projectIDShape.MatchString(meta.Project) {
		return "", "", "", withKind(kindInternal, fmt.Errorf(msgUnsafeRecord, meta.Name, "project ID", meta.Project))
	}
	ref := registryRefFor(meta)
	for _, v := range []struct{ field, value string }{{"repository", ref.Name}, {"location", ref.Location}} {
		if !registryNameShape.MatchString(v.value) {
			return "", "", "", withKind(kindInternal, fmt.Errorf(msgUnsafeRecord, meta.Name, v.field, v.value))
		}
	}
	return meta.Project, ref.Name, ref.Location, nil
}

// pushGrant is the builder's push grant as a plan read it (A33-22): the
// fact the plan binds, and what its printed commands are made from.
type pushGrant struct {
	fact plan.GrantFact
	// instance names the instance; project, repository and location are the
	// record's, each checked (pushGrantRecord); number is the project's, 0
	// when the provider states none.
	instance, project, repository, location string
	number                                  int64
	// uid is farcast-builder's uid as the plan read it, "" when the account
	// did not exist and the plan bound the uid placeholder (A33-19).
	uid string
}

// pending reports whether the plan bound the uid placeholder: the account
// did not exist when the plan read it.
func (g pushGrant) pending() bool { return g.uid == "" }

// readPushGrant is the push grant's read (A33-22), as the installer key, in
// every mode: uid is farcast-builder's as the plan read it, "" when it does
// not exist. In order: the record's values, checked (pushGrantRecord); the
// installer's key, a blank one refused before the provider opens
// (loadInstallerKey); the provider, whose optional planck.GrantReader, when
// it has none, leaves both principals "" and both states unknown with
// nothing read (MS-6); the project number; the two principals (A33-10); and
// one read of the repository's IAM policy, which observes both. With the
// uid placeholder no binding can hold the principal, so its state is
// missing, and the shared principal is still read: the match is local, and
// nothing about the placeholder is sent. The grant is never applied.
func readPushGrant(ctx context.Context, env *Env, meta *config.InstanceMetadata, open providerOpener, uid string) (pushGrant, plan.GrantFact, error) {
	project, repository, location, err := pushGrantRecord(meta)
	if err != nil {
		return pushGrant{}, plan.GrantFact{}, err
	}
	g := pushGrant{
		instance: meta.Name, project: project, repository: repository, location: location, uid: uid,
		fact: plan.GrantFact{
			Type: plan.TypeGrant, Name: plan.GrantPush, Target: meta.Registry.Prefix, ServiceAccount: builderAccount,
			Roles: []string{pushRole}, State: plan.GrantUnknown, Shared: plan.GrantUnknown,
		},
	}
	creds, err := loadInstallerKey(env.ConfigDir, meta.Name)
	if err != nil {
		return pushGrant{}, plan.GrantFact{}, err
	}
	p, err := open(meta, creds)
	if err != nil {
		return pushGrant{}, plan.GrantFact{}, err
	}
	reader, ok := p.(planck.GrantReader)
	if !ok {
		return g, g.fact, nil
	}
	if g.number, err = reader.ProjectNumber(ctx); err != nil {
		return pushGrant{}, plan.GrantFact{}, fmt.Errorf("read the number of project %q with instance %q's installer key: %w", project, meta.Name, err)
	}
	principalUID := uid
	if g.pending() {
		principalUID = saUIDPlaceholder(tcdeploy.DefaultNamespace, pbuild.ServiceAccount)
	}
	if g.fact.Principal, err = workloadUIDPrincipal(g.number, project, principalUID); err != nil {
		return pushGrant{}, plan.GrantFact{}, err
	}
	if g.fact.SharedPrincipal, err = workloadNamePrincipal(g.number, project, tcdeploy.DefaultNamespace, pbuild.ServiceAccount); err != nil {
		return pushGrant{}, plan.GrantFact{}, err
	}
	state, shared, err := reader.RegistryGrant(ctx, registryRefFor(meta), pushRole, g.fact.Principal, g.fact.SharedPrincipal)
	if err != nil {
		return pushGrant{}, plan.GrantFact{}, fmt.Errorf("read the IAM policy of repository %s in %s with instance %q's installer key: %w", repository, location, meta.Name, err)
	}
	g.fact.State, g.fact.Shared = string(state), string(shared)
	if g.pending() && state != planck.GrantUnknown {
		// A principal no account holds yet: no binding can grant it. A
		// policy the key may not read stays unknown for both, as the bucket
		// grant's does, so the commands carry both conditional blocks, the
		// shared principal's removal included.
		g.fact.State = plan.GrantMissing
	}
	return g, g.fact, nil
}

// notice is the plan's notice of the push grant (A23-26, A33-22), "" when
// none is due: the account the plan bound the placeholder for, which this
// command creates; a policy the installer key may not read, with both
// blocks of the commands; a grant the repository's own policy does not
// hold, with its commands; and a grant it holds while it still grants the
// principal every instance in the project shares, with the commands that
// remove that one. A grant present with the shared principal missing has
// none.
func (g pushGrant) notice() (string, error) {
	var intro string
	switch {
	case g.pending():
		return msgPushGrantPending, nil
	case g.fact.State == plan.GrantUnknown:
		intro = msgPushGrantUnknown
	case g.fact.State != plan.GrantPresent:
		intro = msgPushGrantMissing
	case g.fact.Shared != plan.GrantMissing:
		intro = fmt.Sprintf(msgPushGrantShared, g.project)
	default:
		return "", nil
	}
	text, err := g.text(g.uid)
	if err != nil {
		return "", err
	}
	if g.fact.State == plan.GrantMissing {
		text += "\n" + msgPlanBeforeGrant
	}
	return intro + "\n" + text, nil
}

// text is the printed commands for the account whose uid is uid, with the
// plan's states, without a trailing newline.
func (g pushGrant) text(uid string) (string, error) {
	l, err := g.lines(uid)
	if err != nil {
		return "", err
	}
	var w strings.Builder
	writePushGrant(&w, l)
	return strings.TrimRight(w.String(), "\n"), nil
}

// lines are what writePushGrant prints for the account whose uid is uid,
// the one the plan read or, when it bound the placeholder, the one read
// once the account exists, with the plan's states: each value checked
// (A33-15). uid must be the API server's: a placeholder, or any other uid
// that is not of serviceAccountUIDShape, is A33-10's internal refusal, and
// nothing is printed.
func (g pushGrant) lines(uid string) (pushGrantLines, error) {
	if !serviceAccountUIDShape.MatchString(uid) {
		return pushGrantLines{}, withKind(kindInternal, errors.New(msgUnsafeGrantUID))
	}
	number, quote := g.number, "'"
	if number == 0 {
		// No number is known: the commands read it into PROJNUM, and name
		// the principals with it, double-quoted.
		number, quote = 1, `"`
	}
	member, err := workloadUIDPrincipal(number, g.project, uid)
	if err != nil {
		return pushGrantLines{}, err
	}
	shared, err := workloadNamePrincipal(number, g.project, tcdeploy.DefaultNamespace, pbuild.ServiceAccount)
	if err != nil {
		return pushGrantLines{}, err
	}
	if g.number == 0 {
		member, shared = projnumPrincipal(member), projnumPrincipal(shared)
	}
	return pushGrantLines{
		project: g.project, repository: g.repository, location: g.location, projnum: g.number == 0,
		member: quote + member + quote, sharedMember: quote + shared + quote,
		state: g.fact.State, shared: g.fact.Shared,
	}, nil
}

// projnumPrincipal is a principal made for project number 1 with the number
// replaced by ${PROJNUM}, the shell variable the printed commands read it
// into when the provider states no number (A33-15, MS-6).
func projnumPrincipal(principal string) string {
	const numbered = "principal://iam.googleapis.com/projects/1/"
	return strings.Replace(principal, numbered, "principal://iam.googleapis.com/projects/${PROJNUM}/", 1)
}

// pushGrantLines is what writePushGrant prints (A33-15), every value
// checked before it was made (pushGrant.lines): the project, the
// repository and the location, single-quoted when printed; member and
// sharedMember, the uid principal and the shared one, already quoted;
// projnum when no project number is known; and the plan's two states.
type pushGrantLines struct {
	project, repository, location string
	member, sharedMember          string
	projnum                       bool
	state, shared                 string
}

// writePushGrant prints the commands that grant the builder push by its uid,
// and remove the principal every instance in the project shares, for a
// human to run in Cloud Shell. Its introduction is the caller's.
//
// FarCast does not apply it. The reason is NOT that this CLI cannot change a
// repository's IAM — it demonstrably can, and does: `EnsureRegistry` already
// reads and writes that same repository's policy to give the cluster's nodes
// pull access. The reason is what the grant is FOR. The builder executes the
// operator's own Containerfile, so push access means code FarCast did not
// write can put images into the one registry this instance runs from. That is
// a decision for a human, once, deliberately — not something an install should
// arrange quietly on their behalf.
//
// Each command is one line, with no backslash continuation, so a paste runs
// each alone, and every value in it is single-quoted, or, with no project
// number known, double-quoted around ${PROJNUM}, which the first line sets.
// The add comes before the remove, so a running builder is never cut off.
// With the state unknown both blocks print, each introduced by its
// condition.
func writePushGrant(w io.Writer, g pushGrantLines) {
	binding := func(verb, member string) string {
		return fmt.Sprintf("  gcloud artifacts repositories %s-iam-policy-binding '%s' --project '%s' --location '%s' --member %s --role '%s' --condition=None",
			verb, g.repository, g.project, g.location, member, pushRole)
	}
	if g.projnum {
		fprintf(w, "  PROJNUM=$(gcloud projects describe '%s' --format='value(projectNumber)')\n", g.project)
	}
	if g.state == plan.GrantUnknown {
		fprintf(w, "If repository '%s' does not grant it yet:\n", g.repository)
		fprintln(w, binding("add", g.member))
		fprintf(w, "If it still grants the principal every FarCast instance in project '%s' shares, wait for IAM, then:\n", g.project)
		fprintln(w, binding("remove", g.sharedMember))
		return
	}
	adds := g.state != plan.GrantPresent
	if adds {
		fprintln(w, binding("add", g.member))
	}
	if g.shared != plan.GrantPresent {
		return
	}
	if adds {
		fprintf(w, "Then wait for IAM (typically 2 minutes, up to 7 or more), and remove the binding every FarCast instance in project '%s' shares:\n", g.project)
	} else {
		fprintf(w, "Remove the binding every FarCast instance in project '%s' shares:\n", g.project)
	}
	fprintln(w, binding("remove", g.sharedMember))
}

// grantText is the commands for the push grant g once its account exists,
// as a build prints them after its apply and on a refused push: for the uid
// the plan read, or, when it bound the placeholder, the uid read through cl
// as the writer, then known, or "" when that read failed. It is best effort:
// the build is applied and billed, so a read that fails is the one line
// msgPushGrantUnread in place of the commands, never an error.
func grantText(ctx context.Context, cl serviceAccountReader, g pushGrant, uid *string) string {
	if *uid == "" {
		read, err := readServiceAccountUID(ctx, cl, consentNone, g.instance, tcdeploy.DefaultNamespace, pbuild.ServiceAccount, plan.GrantPush)
		if err == nil && read == "" {
			err = errors.New("it was applied and is not found")
		}
		if err != nil {
			// The line names the account already: the read's error and a uid
			// it would not take each lead with it.
			why := err.Error()
			for _, lead := range []string{"read the ServiceAccount " + builderAccount + ": ", "the ServiceAccount " + builderAccount + " "} {
				if rest, ok := strings.CutPrefix(why, lead); ok {
					why = rest
					break
				}
			}
			return fmt.Sprintf(msgPushGrantUnread, terminalText(why), g.instance)
		}
		*uid = read
	}
	text, err := g.text(*uid)
	if err != nil {
		return fmt.Sprintf(msgPushGrantUnread, terminalText(err.Error()), g.instance)
	}
	return text
}

// pushGrantNow prints, right after a build's apply and before its wait, the
// commands that grant the builder push, when its plan bound the uid
// placeholder: the account exists from the apply on, and a grant that lands
// before the push lets the build succeed (A33-22). It reads the uid as the
// writer, cl, best effort (grantText), and returns it, "" when the read
// failed; a plan that bound a real uid reads and prints nothing here.
func pushGrantNow(ctx context.Context, env *Env, cl serviceAccountReader, g pushGrant) string {
	uid := g.uid
	if !g.pending() {
		return uid
	}
	text := grantText(ctx, cl, g, &uid)
	if uid != "" {
		fprintln(env.Err, msgPushGrantNow)
	}
	fprintln(env.Err, text)
	return uid
}

// pushDenied reports whether a build's own output is Artifact Registry
// refusing the push.
//
// Matched on the permission the registry names rather than on prose: the
// builder is a third-party image this project has pinned but does not control
// ([ADR 0011]), so its wording is not FarCast's to rely on — but the IAM
// permission in the cloud's own error is.
//
// [ADR 0011]: ../../../../docs/adr/0011-build-toolchain-mirroring.md
func pushDenied(logs string) bool {
	if strings.Contains(logs, "artifactregistry.repositories.uploadArtifacts") {
		return true
	}
	// The generic shape, for a registry that phrases it differently: a denial
	// that is specifically about pushing.
	lower := strings.ToLower(logs)
	return strings.Contains(lower, "denied") &&
		(strings.Contains(lower, "push permission") || strings.Contains(lower, "push access"))
}

// explainPushDenial turns a build failure that is really a missing grant into
// the instruction that fixes it, and returns whether it did. planned is the
// grant's state as the plan read it, and text the commands, made only when
// it does (grantText), always with the add (pushGrant.denied): for the uid
// known, read as the writer when the plan bound the placeholder, or the one
// line that says the account could not be read.
//
// A grant the plan read present was refused all the same: IAM may not have
// propagated it yet, or Artifact Registry may not honour a grant by uid,
// which is unverified until the M2 walk (design §33, A33-4 (f)). It says so
// rather than that nothing grants it, and still prints the add, which puts
// the grant back if it has gone since.
//
// It writes to stderr rather than into the returned error because the grant is
// several lines of shell: an error string is the wrong shape for something an
// operator is meant to copy.
func explainPushDenial(w io.Writer, logs, planned string, text func() string) bool {
	if !pushDenied(logs) {
		return false
	}
	fprintln(w)
	fprintln(w, "That is not a problem with the Containerfile: the build worked and the push")
	if planned == plan.GrantPresent {
		fprintln(w, "was refused. The builder pushes under its own cloud identity, and when this")
		fprintln(w, "build was planned, the repository's own policy granted it write access by")
		fprintln(w, "its ServiceAccount's uid. IAM may not have propagated that grant yet, or")
		fprintln(w, "Artifact Registry may not honour a grant by uid, which is unverified until")
		fprintln(w, "the M2 walk. If the grant is no longer there, add it again in Cloud Shell:")
	} else {
		fprintln(w, "was refused. The builder pushes under its own cloud identity, and nothing")
		fprintln(w, "grants that identity write access to this instance's registry. Grant it by")
		fprintln(w, "its ServiceAccount's uid in Cloud Shell:")
	}
	fprintln(w)
	fprintln(w, text())
	fprintln(w)
	fprintln(w, "The grant is on the ONE repository, not the project. Artifact Registry can")
	fprintln(w, "take a few minutes to honour it on the registry endpoint even once the API")
	fprintln(w, "reports it, so a retry that fails immediately is worth repeating once.")
	return true
}

// denied is g as a refused push prints its commands: with the add even when
// the plan read the grant present, since the push was refused all the same;
// the shared principal's state stays as the plan read it, so its removal
// still follows the add.
func (g pushGrant) denied() pushGrant {
	if g.fact.State == plan.GrantPresent {
		g.fact.State = plan.GrantMissing
	}
	return g
}

// pushGrantResult is the push grant as a build's result reports it: the
// principal, the uid one once the account exists, and the states the plan
// read.
type pushGrantResult struct {
	Principal string `json:"principal"`
	State     string `json:"state"`
	Shared    string `json:"shared"`
}

// result is g as a build's result reports it, for the account whose uid is
// uid when it is known since the plan.
func (g pushGrant) result(uid string) pushGrantResult {
	principal := g.fact.Principal
	if g.pending() && uid != "" && g.number != 0 {
		if p, err := workloadUIDPrincipal(g.number, g.project, uid); err == nil {
			principal = p
		}
	}
	return pushGrantResult{Principal: principal, State: g.fact.State, Shared: g.fact.Shared}
}
