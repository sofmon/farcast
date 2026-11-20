package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"

	"github.com/sofmon/farcast/datasphere"
	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/farsight/cli/internal/storage"
	"github.com/sofmon/farcast/planck"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// fakeBucketGrants is the instance's bucket IAM as a test fake (ADR 0023
// M2.8, design §33, A33-14): its opens, the states its State answers, an
// error for each call, and every call, in order, also appended to log when
// one is set. A State or an Ensure that is not refused stands for the
// labels proved first, as *storage.Grants proves them.
type fakeBucketGrants struct {
	mu sync.Mutex
	// state and shared answer State; "" is missing. sharedRoles are the
	// roles that hold the shared principal; every role when nil and shared
	// is present.
	state, shared datasphere.GrantState
	sharedRoles   []string
	// openErr refuses each open, stateErr each State and ensureErr each
	// Ensure.
	openErr, stateErr, ensureErr error
	// opened counts the opens, reads the policy reads and sets the policy
	// writes; calls records each read and write.
	opened, reads, sets int
	calls               []bucketGrantCall
	// log, when set, has "iam get gs://<bucket>" and "iam put gs://<bucket>"
	// appended for each read and write, for a test that orders them against
	// other fakes' calls.
	log *[]string
	// onEnsure runs as Ensure is called, before it answers.
	onEnsure func()
}

// bucketGrantCall is one read or write of the policy: its method, State or
// Ensure, the bucket, the roles and the two principals.
type bucketGrantCall struct {
	Method, Bucket, Member, Shared string
	Roles                          []string
}

// open is the command's openBucketGrants seam.
func (f *fakeBucketGrants) open(context.Context, *Env, *config.InstanceMetadata) (bucketGrants, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened++
	if f.openErr != nil {
		return nil, f.openErr
	}
	return f, nil
}

// answer is the states State answers, without the lock.
func (f *fakeBucketGrants) answer() (state, shared datasphere.GrantState, sharedRoles []string) {
	state, shared = f.state, f.shared
	if state == "" {
		state = datasphere.GrantMissing
	}
	if shared == "" {
		shared = datasphere.GrantMissing
	}
	switch {
	case shared != datasphere.GrantPresent:
	case f.sharedRoles != nil:
		sharedRoles = slices.Clone(f.sharedRoles)
	default:
		sharedRoles = slices.Clone(bucketRoles)
	}
	return state, shared, sharedRoles
}

func (f *fakeBucketGrants) record(method, bucket string, roles []string, member, shared string) {
	f.calls = append(f.calls, bucketGrantCall{Method: method, Bucket: bucket, Member: member, Shared: shared, Roles: slices.Clone(roles)})
	if f.log != nil {
		verb := map[string]string{"State": "get", "Ensure": "put"}[method]
		*f.log = append(*f.log, "iam "+verb+" gs://"+bucket)
	}
}

func (f *fakeBucketGrants) State(_ context.Context, bucket string, roles []string, member, shared string) (datasphere.GrantState, datasphere.GrantState, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	f.record("State", bucket, roles, member, shared)
	if f.stateErr != nil {
		return "", "", nil, f.stateErr
	}
	state, sharedState, sharedRoles := f.answer()
	return state, sharedState, sharedRoles, nil
}

// Ensure writes the grant: the uid principal holds both roles, and the
// shared one none, from then on. It reports a change unless that was so.
func (f *fakeBucketGrants) Ensure(_ context.Context, bucket string, roles []string, member, shared string) (bool, error) {
	if f.onEnsure != nil {
		f.onEnsure()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets++
	f.record("Ensure", bucket, roles, member, shared)
	if f.ensureErr != nil {
		return false, f.ensureErr
	}
	state, sharedState, _ := f.answer()
	changed := state != datasphere.GrantPresent || sharedState == datasphere.GrantPresent
	f.state, f.shared, f.sharedRoles = datasphere.GrantPresent, datasphere.GrantMissing, nil
	return changed, nil
}

// counts are the opens, reads and writes so far.
func (f *fakeBucketGrants) counts() (opened, reads, sets int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opened, f.reads, f.sets
}

// members are the members each call named, in order.
func (f *fakeBucketGrants) members() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.Method+" "+c.Member)
	}
	return out
}

// bucketGrantOf is the one bucket grant fact a plan carries, or the zero
// fact when it carries none.
func bucketGrantOf(b plan.Bound) (plan.GrantFact, bool) {
	for _, f := range b.Facts {
		if g, ok := f.(plan.GrantFact); ok && g.Name == plan.GrantBucket {
			return g, true
		}
	}
	return plan.GrantFact{}, false
}

// keyholderSharedMember is the principal every keyholder in project's pool
// shares, at number.
func keyholderSharedMember(number int64, project string) string {
	return strings.Replace(builderSharedMember(number, project), "/sa/farcast-builder", "/sa/datasphered", 1)
}

// fixtureBucket is the bucket the bucket grant's fixtures name.
const fixtureBucket = "farcast-atlas-0a1b2c3d"

// fixtureBucketGrant is the keyholder's bucket grant a plan of the atlas
// fixture read: project proj-atlas at the fixture number, datasphered at its
// fixture uid, with the states given, every role holding the shared
// principal when it is present, not applied.
func fixtureBucketGrant(state, shared string) bucketGrant {
	g := bucketGrant{
		instance: "atlas", project: "proj-atlas", number: fixtureProjectNumber, uid: fixtureKeyholderUID, capable: true,
		fact: plan.GrantFact{Type: plan.TypeGrant, Name: plan.GrantBucket, Target: "gs://" + fixtureBucket, ServiceAccount: keyholderAccount,
			Principal:       uidMember(fixtureProjectNumber, "proj-atlas", fixtureKeyholderUID),
			SharedPrincipal: keyholderSharedMember(fixtureProjectNumber, "proj-atlas"),
			Roles:           slices.Clone(bucketRoles), State: state, Shared: shared},
	}
	if shared == plan.GrantPresent {
		g.sharedRoles = slices.Clone(bucketRoles)
	}
	return g
}

// The rig's bucket and its two principals: writeInstance's project
// proj-test1 at the fixture number, datasphered at its fixture uid.
const rigBucket = "farcast-atlas-0b0b0b0b"

var (
	rigMember       = uidMember(fixtureProjectNumber, "proj-test1", fixtureKeyholderUID)
	rigSharedMember = keyholderSharedMember(fixtureProjectNumber, "proj-test1")
)

// ask runs storage deploy with flags in a terminal whose answers, one a
// line, are answers: what it printed, and its error.
func (r *storageRig) ask(t *testing.T, answers string, flags ...string) (stdout, stderr string, err error) {
	t.Helper()
	env, out, errb := testEnvBoth(r.dir, output.ModeHuman)
	env.In = iotest.OneByteReader(strings.NewReader(answers))
	c := r.cmd(t, flags...)
	c.interactive = func(*Env) bool { return true }
	err = c.Run(t.Context(), env, []string{writeName})
	return out.String(), errb.String(), err
}

// confirmGrant is the rig's plan with --grant-bucket and flags, then its
// --confirm: what the confirm printed, and its error.
func (r *storageRig) confirmGrant(t *testing.T, flags ...string) (stdout, stderr string, err error) {
	t.Helper()
	doc := r.plan(t, append([]string{"--grant-bucket"}, flags...)...)
	return r.run(t, append([]string{"--grant-bucket", "--confirm", doc.Digest}, flags...)...)
}

// TestBucketGrantNeedsConsent (design §33, A33-2, A33-24, mutation 106):
// --grant-bucket changes a bucket's IAM policy, so it is accepted with
// --plan, with --confirm, and in a terminal that answers its own question;
// beside --yes it is refused before anything is read, naming --plan; --plan
// beside --yes is the three answers' usage error first; and with no
// terminal and no answer it is refused, naming the plan's route.
func TestBucketGrantNeedsConsent(t *testing.T) {
	t.Run("--plan", func(t *testing.T) {
		r := newStorageRig(t, nil)
		b := decodedBound(t, r.plan(t, "--grant-bucket"))
		if g, ok := bucketGrantOf(b); !ok || !g.Apply || !slices.Contains(b.Options, plan.Option{Flag: "grant-bucket", Value: "true"}) {
			t.Errorf("--plan --grant-bucket binds %+v and the options %+v; want the grant applied, the flag bound", g, b.Options)
		}
		r.wroteNothing(t)
	})
	t.Run("--confirm", func(t *testing.T) {
		r := newStorageRig(t, nil)
		if _, stderr, err := r.confirmGrant(t); err != nil {
			t.Fatalf("--grant-bucket --confirm = %v\n%s", err, stderr)
		}
		if _, _, sets := r.bg.counts(); sets != 1 {
			t.Errorf("wrote the bucket's policy %d times; want once", sets)
		}
	})
	t.Run("a terminal's question", func(t *testing.T) {
		r := newStorageRig(t, nil)
		_, stderr, err := r.ask(t, "y\ny\n", "--grant-bucket")
		if err != nil {
			t.Fatalf("--grant-bucket in a terminal = %v\n%s", err, stderr)
		}
		if _, _, sets := r.bg.counts(); sets != 1 || !strings.Contains(stderr, "Grant roles/storage.objectAdmin") {
			t.Errorf("wrote the bucket's policy %d times after asking:\n%s\nwant once, asked", sets, stderr)
		}
	})
	for _, tc := range []struct {
		name, instance string
		flags          []string
		want           string
	}{
		{"--yes", writeName, []string{"--yes"}, fmt.Sprintf(msgGrantBucketYes, writeName, writeName)},
		{"--yes, an invalid name", "Not_An_Instance", []string{"--yes"}, fmt.Sprintf(msgGrantBucketYes, "<instance>", "<instance>")},
		{"-y", writeName, []string{"-y"}, fmt.Sprintf(msgGrantBucketYes, writeName, writeName)},
		{"--plan --yes", writeName, []string{"--plan", "--yes"}, msgConsentExclusive},
		{"no terminal and no answer", writeName, nil, msgGrantBucketTerminal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStorageRig(t, nil)
			reads := observeConfigReads(t)
			env, out, errb := testEnvBoth(r.dir, output.ModeHuman) // stdin is no terminal
			err := r.cmd(t, append([]string{"--grant-bucket"}, tc.flags...)...).Run(t.Context(), env, []string{tc.instance})
			if err == nil || err.Error() != tc.want || exitCodeOf(err) != 2 {
				t.Errorf("--grant-bucket %v = %v (exit %d); want %q, a usage error", tc.flags, err, exitCodeOf(err), tc.want)
			}
			if got := reads(); len(got) != 0 {
				t.Errorf("read %q before refusing", got)
			}
			if opened, _, _ := r.bg.counts(); opened+r.writers+r.opened != 0 || out.Len()+errb.Len() != 0 {
				t.Errorf("opened the bucket's IAM %d times, the writer %d and the provider %d, and printed %q %q", opened, r.writers, r.opened, out, errb)
			}
			r.wroteNothing(t)
		})
	}
}

// TestInteractiveGrantBucketAsksNamingEverything (design §33, A33-24,
// mutation 138): in a terminal --grant-bucket asks its own question after
// the cost's, naming the bucket, the uid principal, both roles and the
// shared principal it removes; one that only removes says so; one for an
// account and a bucket this deploy creates names them as such. Declining
// writes no policy, prints Aborted. and deploys nothing.
func TestInteractiveGrantBucketAsksNamingEverything(t *testing.T) {
	asked := func(stderr string) string {
		for l := range strings.Lines(stderr) {
			if strings.HasPrefix(l, "Deploy it? [y/N]: Grant ") || strings.HasPrefix(l, "Deploy it? [y/N]: Remove ") {
				q, _ := strings.CutPrefix(l, "Deploy it? [y/N]: ")
				q, _, _ = strings.Cut(q, " [y/N]: ")
				return q
			}
		}
		return ""
	}
	first := func(r *storageRig) {
		delete(r.accounts, dsdeploy.DefaultName)
		r.mintsBucket(nil)
	}
	for _, tc := range []struct {
		name          string
		state, shared datasphere.GrantState
		edit          func(m *config.InstanceMetadata)
		prepare       func(r *storageRig)
		want          string
	}{
		{"missing, the shared principal held", datasphere.GrantMissing, datasphere.GrantPresent, nil, nil,
			"Grant roles/storage.objectAdmin and roles/storage.legacyBucketReader on gs://" + rigBucket + " to " + rigMember +
				", and remove them from " + rigSharedMember + `, which every FarCast instance in project "proj-test1" shares?`},
		{"missing, the shared principal gone", datasphere.GrantMissing, datasphere.GrantMissing, nil, nil,
			"Grant roles/storage.objectAdmin and roles/storage.legacyBucketReader on gs://" + rigBucket + " to " + rigMember + "?"},
		{"present, the shared principal held", datasphere.GrantPresent, datasphere.GrantPresent, nil, nil,
			"Remove roles/storage.objectAdmin and roles/storage.legacyBucketReader on gs://" + rigBucket + " from " + rigSharedMember +
				`, which every FarCast instance in project "proj-test1" shares? The keyholder's uid already holds both.`},
		{"a first deploy", "", "", func(m *config.InstanceMetadata) { m.Storage = nil }, first,
			"Grant roles/storage.objectAdmin and roles/storage.legacyBucketReader on the bucket this deploy creates to " + msgGrantPendingPrincipal + "?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, answer := range []string{"y", "n"} {
				r := newStorageRig(t, tc.edit)
				if tc.prepare != nil {
					tc.prepare(r)
				}
				r.bg.state, r.bg.shared = tc.state, tc.shared
				_, stderr, err := r.ask(t, "y\n"+answer+"\n", "--grant-bucket")
				if err != nil {
					t.Fatalf("answering %s: %v\n%s", answer, err, stderr)
				}
				if got := asked(stderr); got != tc.want {
					t.Errorf("asked %q\n\nwant %q", got, tc.want)
				}
				_, _, sets := r.bg.counts()
				if answer == "y" {
					if sets != 1 || len(r.fc.applied) != 2 {
						t.Errorf("an accepted grant wrote the policy %d times and applied %d streams; want once, and the keyholder", sets, len(r.fc.applied))
					}
					continue
				}
				if sets != 0 || !strings.HasSuffix(stderr, "Aborted.\n") {
					t.Errorf("a declined grant wrote the policy %d times, and said %q", sets, stderr)
				}
				r.wroteNothing(t)
			}
		})
	}
}

// TestFirstDeployGrantIsMissingUnread (design §33, A33-25): a first deploy
// names the bucket it creates by its placeholder and reads no policy, the
// bucket not existing: both states are missing. With --grant-bucket the
// policy write is a cloud fact on the placeholder bucket and there is no
// grant notice; without it, the notice says the commands print once the
// account and the bucket exist.
func TestFirstDeployGrantIsMissingUnread(t *testing.T) {
	for _, grant := range []bool{false, true} {
		t.Run(fmt.Sprintf("--grant-bucket=%v", grant), func(t *testing.T) {
			r := newStorageRig(t, func(m *config.InstanceMetadata) { m.Storage = nil })
			delete(r.accounts, dsdeploy.DefaultName)
			var flags []string
			if grant {
				flags = []string{"--grant-bucket"}
			}
			b := decodedBound(t, r.plan(t, flags...))
			g, ok := bucketGrantOf(b)
			target := "gs://" + placeholderBucket(writeName)
			if !ok || g.Target != target || g.State != plan.GrantMissing || g.Shared != plan.GrantMissing || g.Apply != grant {
				t.Errorf("the grant is %+v; want %s, both states missing, applied %v", g, target, grant)
			}
			if _, reads, sets := r.bg.counts(); reads+sets != 0 {
				t.Errorf("read the policy %d times and wrote it %d; want neither", reads, sets)
			}
			var cloud []plan.CloudFact
			for _, f := range b.Facts {
				if c, ok := f.(plan.CloudFact); ok && c.Action == plan.CloudSetBucketGrant {
					cloud = append(cloud, c)
				}
			}
			notice := fmt.Sprintf(msgBucketGrantPending, "the bucket this deploy creates")
			switch {
			case grant && (len(cloud) != 1 || cloud[0].Target != target || slices.Contains(noticesOf(b), notice)):
				t.Errorf("the policy writes are %+v, and the notices %q; want one, on %s, and no grant notice", cloud, noticesOf(b), target)
			case !grant && (len(cloud) != 0 || !slices.Contains(noticesOf(b), notice)):
				t.Errorf("the policy writes are %+v, and the notices %q; want none, and %q", cloud, noticesOf(b), notice)
			}
		})
	}
}

// TestFirstDeployBindsThePlaceholderUID (design §33, A33-19): with the
// keyholder's ServiceAccount absent the plan binds its uid placeholder in
// the grant's principal, reads the policy for the shared principal alone,
// matching locally, and states the grant missing; the same record planned
// again is the same plan.
func TestFirstDeployBindsThePlaceholderUID(t *testing.T) {
	r := newStorageRig(t, nil)
	delete(r.accounts, dsdeploy.DefaultName)
	r.bg.state, r.bg.shared = datasphere.GrantPresent, datasphere.GrantPresent
	doc := r.plan(t)
	g, _ := bucketGrantOf(decodedBound(t, doc))
	want := uidMember(fixtureProjectNumber, "proj-test1", saUIDPlaceholder(tcdeploy.DefaultNamespace, dsdeploy.DefaultName))
	if g.Principal != want || g.State != plan.GrantMissing || g.Shared != plan.GrantPresent {
		t.Errorf("the grant is %+v; want the principal %s, missing, the shared principal present", g, want)
	}
	if got := r.bg.members(); !slices.Equal(got, []string{"State " + want}) {
		t.Errorf("the policy was read for %q; want once, matched locally", got)
	}
	if again := r.plan(t); again.Digest != doc.Digest {
		t.Errorf("the same record planned again is %s, not %s", again.Digest, doc.Digest)
	}
}

// TestBucketGrantUnknownStateIsBlocked (design §33, A33-25, mutation 109c):
// a policy the stored credential may not read (a 403) is unknown for both
// principals. --grant-bucket there is a block, forbidden, naming the bucket:
// its plan carries no fact, and its --confirm refuses with nothing written.
// Without the flag the plan is not blocked, and its notice is both blocks
// of the commands, each under its condition.
func TestBucketGrantUnknownStateIsBlocked(t *testing.T) {
	unknown := func(r *storageRig) { r.bg.state, r.bg.shared = datasphere.GrantUnknown, datasphere.GrantUnknown }
	t.Run("--grant-bucket", func(t *testing.T) {
		r := newStorageRig(t, nil)
		unknown(r)
		doc := r.plan(t, "--grant-bucket")
		b := decodedBound(t, doc)
		want := fmt.Sprintf(msgBucketGrantUnreadable, rigBucket)
		if len(b.Blocked) != 1 || b.Blocked[0].Kind != kindForbidden || b.Blocked[0].Message != want || len(b.Facts) != 0 {
			t.Fatalf("the plan blocks %+v with %d facts; want %q, forbidden, and no fact", b.Blocked, len(b.Facts), want)
		}
		_, _, err := r.run(t, "--grant-bucket", "--confirm", doc.Digest)
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindForbidden {
			t.Errorf("--confirm = %v; want %q, forbidden", err, want)
		}
		if r.writers != 0 {
			t.Errorf("the writer opened %d times", r.writers)
		}
		r.wroteNothing(t)
	})
	t.Run("not applied", func(t *testing.T) {
		r := newStorageRig(t, nil)
		unknown(r)
		b := decodedBound(t, r.plan(t))
		g, _ := bucketGrantOf(b)
		if len(b.Blocked) != 0 || g.State != plan.GrantUnknown || g.Shared != plan.GrantUnknown {
			t.Fatalf("the plan blocks %+v and binds %+v; want it unblocked, both states unknown", b.Blocked, g)
		}
		notice := strings.Join(noticesOf(b), "\n")
		for _, want := range []string{"If gs://" + rigBucket + " does not grant it yet:",
			"If it still grants the principal every FarCast instance in project 'proj-test1' shares, wait for IAM, then:",
			"remove-iam-policy-binding 'gs://" + rigBucket + "' --member '" + rigSharedMember + "' --role 'roles/storage.objectAdmin'",
			"remove-iam-policy-binding 'gs://" + rigBucket + "' --member '" + rigSharedMember + "' --role 'roles/storage.legacyBucketReader'"} {
			if !strings.Contains(notice, want) {
				t.Errorf("the notice lacks %q:\n%s", want, notice)
			}
		}
		if strings.Contains(notice, msgPlanBeforeGrant) {
			t.Errorf("the notice says a grant would change a plan whose policy cannot be read:\n%s", notice)
		}
	})
}

// TestSharedPresentWithGrantPresentStillWrites (design §33, A33-25): with
// the uid principal holding both roles and the shared one still holding
// them, --grant-bucket still writes the policy, once, to remove the shared
// principal: the plan states the write as a cloud fact. With the shared
// principal gone there is nothing to write: no cloud fact, no write, and the
// notice says the grant is in place.
func TestSharedPresentWithGrantPresentStillWrites(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shared datasphere.GrantState
		writes int
	}{
		{"the shared principal held", datasphere.GrantPresent, 1},
		{"the shared principal gone", datasphere.GrantMissing, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStorageRig(t, nil)
			r.bg.state, r.bg.shared = datasphere.GrantPresent, tc.shared
			doc := r.plan(t, "--grant-bucket")
			b := decodedBound(t, doc)
			cloud := 0
			for _, f := range b.Facts {
				if c, ok := f.(plan.CloudFact); ok && c.Action == plan.CloudSetBucketGrant && c.Target == "gs://"+rigBucket {
					cloud++
				}
			}
			present := fmt.Sprintf(msgBucketGrantPresent, rigBucket)
			if cloud != tc.writes || (tc.writes == 0) != slices.Contains(noticesOf(b), present) {
				t.Errorf("the plan states %d policy writes and the notices %q; want %d", cloud, noticesOf(b), tc.writes)
			}
			stdout, stderr, err := r.run(t, "--grant-bucket", "--confirm", doc.Digest)
			if err != nil {
				t.Fatalf("--confirm = %v\n%s", err, stderr)
			}
			_, _, sets := r.bg.counts()
			if sets != tc.writes {
				t.Errorf("wrote the policy %d times; want %d", sets, tc.writes)
			}
			want := map[int]string{0: bucketGrantPresent, 1: bucketGrantApplied}[tc.writes]
			if !strings.Contains(stdout, `"bucket_grant":"`+want+`"`) {
				t.Errorf("the result is %s; want the bucket grant %s", stdout, want)
			}
			if tc.writes == 1 {
				if got := r.bg.members(); got[len(got)-1] != "Ensure "+rigMember || r.bg.calls[len(r.bg.calls)-1].Shared != rigSharedMember {
					t.Errorf("the write named %q; want the uid principal, removing the shared one", got)
				}
			}
		})
	}
}

// labelledGrants is the storage provider of TestBucketGrantRefusesABucketNotTheInstances:
// bucket IAM over a bucket whose labels prove it this instance's, until
// notOwned, counting its reads and writes of the policy. It holds no
// objects: any other call is a nil interface's.
type labelledGrants struct {
	datasphere.Provider
	mu                       sync.Mutex
	notOwned                 bool
	validated, reads, writes int
}

func (p *labelledGrants) Name() string { return labelledProviderName }

func (p *labelledGrants) Validate(_ context.Context, ref datasphere.BucketRef) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.validated++
	if p.notOwned || ref.Instance != writeName {
		return fmt.Errorf("%w: its labels name the instance other", datasphere.ErrNotOwned)
	}
	return nil
}

func (p *labelledGrants) GrantState(context.Context, string, []string, string, string) (datasphere.GrantState, datasphere.GrantState, []string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reads++
	return datasphere.GrantMissing, datasphere.GrantMissing, nil, nil
}

func (p *labelledGrants) EnsureGrant(context.Context, string, []string, string, string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writes++
	return true, nil
}

func (p *labelledGrants) counts() (validated, reads, writes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.validated, p.reads, p.writes
}

// labelledProviderName is the storage provider labelledGrants is registered
// as, once, answering with the labelledGrants of the test that runs.
const labelledProviderName = "cli-test-labelled"

var (
	labelledOnce    sync.Once
	labelledCurrent atomic.Pointer[labelledGrants]
)

// useLabelledGrants makes the storage provider labelledProviderName answer
// with a fresh labelledGrants for the rest of the test, and returns it.
func useLabelledGrants(t *testing.T) *labelledGrants {
	t.Helper()
	labelledOnce.Do(func() {
		datasphere.Register(labelledProviderName, func(datasphere.Config) (datasphere.Provider, error) {
			if p := labelledCurrent.Load(); p != nil {
				return p, nil
			}
			return nil, errors.New("test: no labelled storage provider in this test")
		})
	})
	p := &labelledGrants{}
	labelledCurrent.Store(p)
	t.Cleanup(func() { labelledCurrent.Store(nil) })
	return p
}

// TestBucketGrantRefusesABucketNotTheInstances (design §33, A33-14,
// A33-27, mutation 109h): the bucket's labels are proved before its policy
// is read or written, through the instance's real bucket IAM opener (the
// installer's key, storage.OpenBucketGrants), here over a storage provider
// of this test's. A recorded bucket whose labels name another instance is
// refused at the plan, internal, its policy never read; one whose labels
// change after the comparison is refused at the policy write, internal,
// naming what was written before, its policy never written, and nothing
// after the keyholder's account applied.
func TestBucketGrantRefusesABucketNotTheInstances(t *testing.T) {
	labelled := func(m *config.InstanceMetadata) { m.Storage.Provider = labelledProviderName }
	t.Run("at the plan", func(t *testing.T) {
		p := useLabelledGrants(t)
		p.notOwned = true
		r := newStorageRig(t, labelled)
		r.openGrants = openInstanceBucketGrants
		_, _, err := r.run(t, "--plan", "--grant-bucket")
		if err == nil || !strings.HasPrefix(err.Error(), `the recorded storage bucket for "atlas" did not validate: `) ||
			!errors.Is(err, datasphere.ErrNotOwned) || kindOf(classified(err)) != kindInternal {
			t.Errorf("--plan over another instance's bucket = %v; want the labels' refusal, internal", err)
		}
		if validated, reads, writes := p.counts(); validated != 1 || reads+writes != 0 {
			t.Errorf("validated %d times, read the policy %d and wrote it %d; want the labels alone", validated, reads, writes)
		}
	})
	t.Run("at the policy write", func(t *testing.T) {
		p := useLabelledGrants(t)
		r := newStorageRig(t, labelled)
		r.openGrants = openInstanceBucketGrants
		doc := r.plan(t, "--grant-bucket")
		r.onWriter = func() { p.notOwned = true }
		_, _, err := r.run(t, "--grant-bucket", "--confirm", doc.Digest)
		suffix := "; the keyholder's ServiceAccount farcast-system/datasphered was applied, and nothing else was written"
		if err == nil || !strings.HasPrefix(err.Error(), `the recorded storage bucket for "atlas" did not validate: `) || !strings.HasSuffix(err.Error(), suffix) ||
			!errors.Is(err, datasphere.ErrNotOwned) || kindOf(classified(err)) != kindInternal {
			t.Errorf("--confirm over a bucket relabelled since = %v; want the labels' refusal, internal, ending %q", err, suffix)
		}
		if _, reads, writes := p.counts(); reads != 2 || writes != 0 {
			t.Errorf("read the policy %d times and wrote it %d; want the two plans' reads, and no write", reads, writes)
		}
		r.accountOnly(t)
	})
}

// beyondTheAccount is the streams of applied other than storage deploy's
// first, the keyholder's account alone (design §33, A33-26): every stream
// of any other command.
func beyondTheAccount(t *testing.T, applied [][]byte) [][]byte {
	t.Helper()
	var out [][]byte
	for _, s := range applied {
		if appliedKindsOf(t, s) != "Namespace/farcast-system ServiceAccount/datasphered" {
			out = append(out, s)
		}
	}
	return out
}

// TestStorageDeployAppliesTheAccountFirst (design §33, A33-26, mutation
// 137): under --grant-bucket's --confirm the deploy applies the Namespace
// and the keyholder's ServiceAccount, reads the account as the writer,
// writes the bucket's policy, pushes the image, writes the pin, records the
// keyholder, and only then applies the rest of its workload, the replicas
// among it. The plan's writes are in that order too: the account's, the
// policy's, the pin's, then the workload's.
func TestStorageDeployAppliesTheAccountFirst(t *testing.T) {
	r := newStorageRig(t, nil)
	r.bg.shared = datasphere.GrantPresent
	doc := r.plan(t, "--grant-bucket")
	var log []string
	recorded := func() bool {
		m, err := r.dir.LoadInstanceMetadata(writeName)
		return err == nil && m.Keyholder != nil && m.Keyholder.Image != ""
	}
	r.onWriter = func() {
		// After the comparison: the plan's own reads are not this order.
		log = nil
		r.fc.log, r.fb.log, r.ps.log, r.bg.log = &log, &log, &log, &log
		r.ps.onWrite = func() {
			if recorded() {
				t.Error("the keyholder was recorded before its pin was written")
			}
		}
		r.fc.onApply = func() {
			if want := len(r.fc.applied) == 2; recorded() != want {
				t.Errorf("apply %d: the keyholder recorded %v; want %v", len(r.fc.applied), !want, want)
			}
		}
	}
	if _, stderr, err := r.run(t, "--grant-bucket", "--confirm", doc.Digest); err != nil {
		t.Fatalf("--confirm = %v\n%s", err, stderr)
	}
	b := decodedBound(t, doc)
	var workload []string
	for _, w := range applyWrites(b)[2:] {
		workload = append(workload, w.Kind+"/"+w.Name)
	}
	var got []string
	for _, l := range log {
		verb, _, _ := strings.Cut(l, " ")
		switch verb {
		case "pin", "push":
			got = append(got, verb)
		default:
			got = append(got, l)
		}
	}
	want := []string{"apply Namespace/farcast-system ServiceAccount/datasphered", "get ServiceAccount/datasphered",
		"iam put gs://" + rigBucket, "push", "pin", "apply " + strings.Join(workload, " ")}
	if !slices.Equal(got, want) {
		t.Errorf("the deploy wrote, in order,\n  %q\nwant\n  %q", got, want)
	}

	// The plan's facts in the same order.
	var facts []string
	for _, f := range b.Facts {
		switch f := f.(type) {
		case plan.WriteFact:
			facts = append(facts, f.Kind+"/"+f.Name)
		case plan.CloudFact:
			if f.Action == plan.CloudSetBucketGrant {
				facts = append(facts, "iam "+f.Target)
			}
		case plan.GrantFact:
			facts = append(facts, "grant")
		}
	}
	wantFacts := append([]string{"Namespace/farcast-system", "ServiceAccount/datasphered", "grant", "iam gs://" + rigBucket, "ConfigMap/datasphered-pin"}, workload...)
	if !slices.Equal(facts, wantFacts) {
		t.Errorf("the plan's writes are, in order,\n  %q\nwant\n  %q", facts, wantFacts)
	}
}

// TestFirstDeployGrantNamesTheCreatedUID (design §33, A33-19, A33-26,
// mutation 134): a first deploy whose keyholder's ServiceAccount does not
// exist binds the uid's placeholder; under --grant-bucket's --confirm the
// account is applied, its uid read, and the one policy write names that
// uid's principal on the bucket the deploy created, never the placeholder.
func TestFirstDeployGrantNamesTheCreatedUID(t *testing.T) {
	r := newStorageRig(t, func(m *config.InstanceMetadata) { m.Storage = nil })
	delete(r.accounts, dsdeploy.DefaultName)
	r.mintsBucket(nil)
	doc := r.plan(t, "--grant-bucket")
	if g, _ := bucketGrantOf(decodedBound(t, doc)); !strings.Contains(g.Principal, saUIDPlaceholderPrefix) {
		t.Fatalf("the plan names %s; want the uid's placeholder", g.Principal)
	}
	stdout, stderr, err := r.run(t, "--grant-bucket", "--confirm", doc.Digest)
	if err != nil {
		t.Fatalf("--confirm = %v\n%s", err, stderr)
	}
	if got := r.bg.members(); !slices.Equal(got, []string{"Ensure " + rigMember}) || r.bg.calls[0].Bucket != "farcast-atlas-0a1b2c3d" {
		t.Errorf("the policy was written for %q on %+v; want the created account's uid principal, %s, on the bucket created", got, r.bg.calls, rigMember)
	}
	if !strings.Contains(stdout, `"bucket_grant":"applied"`) {
		t.Errorf("the result is %s; want the grant applied", stdout)
	}
}

// TestBucketGrantRefusedLeavesNoKeyholder (design §33, A33-26, A33-27,
// mutation 109f): a policy write Google refuses stops the deploy after the
// keyholder's account and before anything else: no registry ensured, no
// image pushed, no pin written, no keyholder recorded, no replica applied.
func TestBucketGrantRefusedLeavesNoKeyholder(t *testing.T) {
	r := newStorageRig(t, nil)
	r.bg.ensureErr = fmt.Errorf("gcs: set the IAM policy of bucket %q: %w (403 Forbidden)", rigBucket, datasphere.ErrPermissionDenied)
	pinBefore := r.ps.version
	if _, _, err := r.confirmGrant(t); err == nil {
		t.Fatal("a refused policy write deployed the keyholder")
	}
	r.accountOnly(t)
	if len(r.fp.ensured)+len(r.fb.embedded)+len(r.fb.built) != 0 || r.ps.version != pinBefore {
		t.Errorf("ensured %d registries, pushed %d, built %d and wrote the pin %d times after the refusal",
			len(r.fp.ensured), len(r.fb.embedded), len(r.fb.built), r.ps.version-pinBefore)
	}
}

// TestBucketGrantRefusalNamesTheBucketNotTheCluster (design §33, A33-27,
// mutation 109e): Google's 403 on the policy write is the bucket's, kind
// forbidden, naming the bucket and never the cluster or the installer's
// account on it, with the commands printed first and what was written
// before it said. A policy changed under both writes is plan_changed; any
// other refusal of the write is internal, the policy unchanged, the commands
// printed first. A write that no answer settles is internal too, and says
// that it may have landed, not that the policy is unchanged, with the write
// sent named in what was written; a failure before any write was sent says
// no write was made, not that Google refused one.
func TestBucketGrantRefusalNamesTheBucketNotTheCluster(t *testing.T) {
	const (
		written = "the keyholder's ServiceAccount farcast-system/datasphered was applied, and nothing else was written"
		sent    = "the keyholder's ServiceAccount farcast-system/datasphered was applied, a write of gs://" + rigBucket +
			"'s IAM policy was sent, and nothing else was written"
	)
	for _, tc := range []struct {
		name     string
		err      error
		want     string
		kind     string
		commands bool
	}{
		{"Google's 403", fmt.Errorf("gcs: set the IAM policy of bucket %q: %w (403 Forbidden)", rigBucket, datasphere.ErrPermissionDenied),
			"the stored credential may not change gs://" + rigBucket + "'s IAM policy (gcs: set the IAM policy of bucket \"" + rigBucket +
				"\": datasphere: the cloud refused this credential (403 Forbidden)); run the printed commands instead; " + written,
			kindForbidden, true},
		{"a policy changed under both writes", fmt.Errorf("gcs: set the IAM policy of bucket %q: %w (412)", rigBucket, datasphere.ErrPolicyChanged),
			"gs://" + rigBucket + "'s IAM policy changed while the grant was written; " + written + "; " + msgPlanAgain,
			kindPlanChanged, false},
		{"any other refusal of the write", fmt.Errorf("gcs: set the IAM policy of bucket %q: %w (400 INVALID_ARGUMENT)", rigBucket, datasphere.ErrPolicyRejected),
			"Google refused the new IAM policy of gs://" + rigBucket + " (gcs: set the IAM policy of bucket \"" + rigBucket +
				"\": datasphere: the cloud refused the new IAM policy (400 INVALID_ARGUMENT)); its policy is unchanged; run the printed commands, or report it; " + written,
			kindInternal, true},
		// A write cancelled in flight, or never answered, may have landed,
		// the shared principal's removal included: never "unchanged", and
		// the clause names the write sent, never "nothing else was
		// written" without it.
		{"a write no answer settles", fmt.Errorf("gcs: set the IAM policy of bucket %q: %w (%w)", rigBucket, datasphere.ErrPolicyUnconfirmed, context.Canceled),
			"whether gs://" + rigBucket + "'s new IAM policy took effect is not known (gcs: set the IAM policy of bucket \"" + rigBucket +
				"\": datasphere: a write of the bucket's IAM policy was sent, and whether it took effect is not known (context canceled)); " +
				"'farcast storage deploy " + writeName + " --plan' reads it, and the printed commands finish the grant if it did not; " + sent,
			kindInternal, true},
		{"a 403 on the read after a stale write", fmt.Errorf("%w (%w)", datasphere.ErrPolicyUnconfirmed, datasphere.ErrPermissionDenied),
			"whether gs://" + rigBucket + "'s new IAM policy took effect is not known (" + datasphere.ErrPolicyUnconfirmed.Error() + " (" + datasphere.ErrPermissionDenied.Error() + ")); " +
				"'farcast storage deploy " + writeName + " --plan' reads it, and the printed commands finish the grant if it did not; " + sent,
			kindInternal, true},
		// Nothing was sent, so nothing was refused by Google.
		{"a read before any write", fmt.Errorf("gcs: read the IAM policy of bucket %q: %w (404)", rigBucket, datasphere.ErrBucketNotFound),
			"the grant on gs://" + rigBucket + " was not written (gcs: read the IAM policy of bucket \"" + rigBucket +
				"\": datasphere: bucket does not exist (404)); its policy is unchanged; run the printed commands, or report it; " + written,
			kindInternal, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStorageRig(t, nil)
			r.bg.ensureErr = tc.err
			_, stderr, err := r.confirmGrant(t)
			if err == nil || err.Error() != tc.want || kindOf(classified(err)) != tc.kind {
				t.Fatalf("--confirm = %v (kind %s);\nwant %q, %s", err, kindOf(classified(err)), tc.want, tc.kind)
			}
			if errors.Is(err, tkube.ErrForbidden) || strings.Contains(err.Error(), "installer service account") || strings.Contains(err.Error(), "cluster") {
				t.Errorf("the refusal %q is said to be the cluster's", err)
			}
			add := "  gcloud storage buckets add-iam-policy-binding 'gs://" + rigBucket + "' --member '" + rigMember + "' --role 'roles/storage.objectAdmin' --condition=None\n"
			if strings.Contains(stderr, add) != tc.commands {
				t.Errorf("printed the commands: %v; want %v:\n%s", !tc.commands, tc.commands, stderr)
			}
			r.accountOnly(t)
		})
	}
}

// TestRefusalAfterTheGrantNamesThePolicyChange (design §33, A33-26,
// mutation 143): a refusal after the policy write names, in the order they
// were written, the bucket and the keyring on a first deploy, the
// keyholder's account, and the policy change, the shared principal's
// removal included, then what else was written; an apply's own failure
// ends with the stream's sentence instead.
func TestRefusalAfterTheGrantNamesThePolicyChange(t *testing.T) {
	const (
		minted  = "the bucket and the keyring were ensured"
		account = "the keyholder's ServiceAccount farcast-system/datasphered was applied"
		changed = "'s IAM policy now grants the keyholder's uid principal roles/storage.objectAdmin and roles/storage.legacyBucketReader and no longer grants the shared principal"
	)
	t.Run("the registry moved, on a first deploy", func(t *testing.T) {
		r := newStorageRig(t, func(m *config.InstanceMetadata) { m.Storage = nil })
		r.mintsBucket(nil)
		planned := r.fp.registry.Prefix
		doc := r.plan(t, "--grant-bucket")
		moved := &planck.Registry{Ref: planck.RegistryRef{Name: "farcast-moved", Location: "us-central1"}, Prefix: "us-central1-docker.pkg.dev/proj-test1/farcast-moved"}
		r.onWriter = func() { r.fp.registry = moved }
		_, _, err := r.run(t, "--grant-bucket", "--confirm", doc.Digest)
		want := fmt.Sprintf(msgRegistryMoved, writeName, moved.Prefix, planned) + "; " + minted + ", " + account +
			", gs://farcast-atlas-0a1b2c3d" + changed + ", and nothing else was written; " + msgPlanAgain
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged {
			t.Errorf("--confirm = %v;\nwant %q", err, want)
		}
	})
	t.Run("the identity unread", func(t *testing.T) {
		r := newStorageRig(t, nil)
		r.bg.onEnsure = func() {
			if err := os.Remove(filepath.Join(r.dir.InstancePath(writeName), "fatline", "ca.key")); err != nil {
				t.Error(err)
			}
		}
		_, _, err := r.confirmGrant(t)
		suffix := "; " + account + ", gs://" + rigBucket + changed + ", the instance's registry was ensured and recorded, " +
			"the keyholder's image was pushed to the instance's registry, and nothing else was written"
		if err == nil || !strings.HasPrefix(err.Error(), fmt.Sprintf("load identity for %q: ", writeName)) || !strings.HasSuffix(err.Error(), suffix) {
			t.Errorf("--confirm = %v;\nwant the identity's refusal ending %q", err, suffix)
		}
		r.accountOnly(t)
	})
	for _, first := range []bool{false, true} {
		t.Run(fmt.Sprintf("the account's own apply, a first deploy %v", first), func(t *testing.T) {
			edit, want := func(*config.InstanceMetadata) {}, "; the stream stopped at its first failing document"
			if first {
				edit, want = func(m *config.InstanceMetadata) { m.Storage = nil }, "; "+minted+", and the stream stopped at its first failing document"
			}
			r := newStorageRig(t, edit)
			r.mintsBucket(nil)
			r.fc.applyErr = errors.New("the API server said no")
			_, _, err := r.confirmGrant(t)
			if err == nil || !strings.HasPrefix(err.Error(), "apply the keyholder's ServiceAccount: the API server said no") || !strings.HasSuffix(err.Error(), want) {
				t.Errorf("--confirm = %v; want the account's apply refused, ending %q", err, want)
			}
			if _, _, sets := r.bg.counts(); sets != 0 || len(r.fc.applied) != 1 {
				t.Errorf("wrote the policy %d times and applied %d streams; want neither the policy nor more than the account", sets, len(r.fc.applied))
			}
		})
	}
}

// TestConfirmWithoutGrantBucketSetsNoPolicy (design §33, A33-26, mutation
// 109g): without --grant-bucket nothing writes the bucket's policy, however
// it reads: the deploy prints the commands, by the account's uid, before the
// replicas start, and the result says the grant was printed.
func TestConfirmWithoutGrantBucketSetsNoPolicy(t *testing.T) {
	r := newStorageRig(t, nil)
	r.bg.shared = datasphere.GrantPresent
	doc := r.plan(t)
	stdout, stderr, err := r.run(t, "--confirm", doc.Digest)
	if err != nil {
		t.Fatalf("--confirm = %v\n%s", err, stderr)
	}
	if _, _, sets := r.bg.counts(); sets != 0 {
		t.Errorf("wrote the bucket's policy %d times", sets)
	}
	for _, want := range []string{"add-iam-policy-binding 'gs://" + rigBucket + "' --member '" + rigMember + "'",
		"remove-iam-policy-binding 'gs://" + rigBucket + "' --member '" + rigSharedMember + "'"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the deploy did not print %q:\n%s", want, stderr)
		}
	}
	if !strings.Contains(stdout, `"bucket_grant":"printed"`) {
		t.Errorf("the result is %s; want the grant printed", stdout)
	}
	var b strings.Builder
	if err := (deployResult{Instance: writeName, Replicas: 2, BucketGrant: bucketGrantPrinted, firstDeploy: true}).Human(&b); err != nil ||
		!strings.Contains(b.String(), "The bucket grant printed above has to be in place first.") || !strings.Contains(b.String(), "--grant-bucket grants it before they start.") {
		t.Errorf("a first deploy's result says %q; want the grant to put in place first, and --grant-bucket", b.String())
	}
}

// TestConfirmedBucketGrantPrintsNoCommands (design §33, A33-26, A33-28): a
// grant applied under --grant-bucket's --confirm prints no command, and the
// result says it was applied; one already in place prints the line that
// says so, and the result says present.
func TestConfirmedBucketGrantPrintsNoCommands(t *testing.T) {
	for _, tc := range []struct {
		name          string
		state, shared datasphere.GrantState
		result        string
	}{
		{"applied", datasphere.GrantMissing, datasphere.GrantPresent, bucketGrantApplied},
		{"in place", datasphere.GrantPresent, datasphere.GrantMissing, bucketGrantPresent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStorageRig(t, nil)
			r.bg.state, r.bg.shared = tc.state, tc.shared
			stdout, stderr, err := r.confirmGrant(t)
			if err != nil {
				t.Fatalf("--confirm = %v\n%s", err, stderr)
			}
			if strings.Contains(stderr, "gcloud ") {
				t.Errorf("printed commands for a grant it applied:\n%s", stderr)
			}
			inPlace := tc.result == bucketGrantPresent
			if said := strings.Contains(stderr, fmt.Sprintf(msgBucketGrantPresent, rigBucket)); said != inPlace {
				t.Errorf("the grant in place said: %v; want %v:\n%s", said, inPlace, stderr)
			}
			if !strings.Contains(stdout, `"bucket_grant":"`+tc.result+`"`) {
				t.Errorf("the result is %s; want the grant %s", stdout, tc.result)
			}
			var b strings.Builder
			if err := (deployResult{Instance: writeName, Replicas: 2, BucketGrant: tc.result}).Human(&b); err != nil || strings.Contains(b.String(), "bucket grant printed above") {
				t.Errorf("the result says %q; want no printed grant named", b.String())
			}
		})
	}
}

// TestARemoveOnlyGrantIsPrinted (design §33, A33-28): without
// --grant-bucket, a grant in place while the shared principal still holds
// the roles leaves commands to run, the removes, so the result says printed,
// not present.
func TestARemoveOnlyGrantIsPrinted(t *testing.T) {
	r := newStorageRig(t, nil)
	r.bg.state, r.bg.shared = datasphere.GrantPresent, datasphere.GrantPresent
	doc := r.plan(t)
	stdout, stderr, err := r.run(t, "--confirm", doc.Digest)
	if err != nil {
		t.Fatalf("--confirm = %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, `"bucket_grant":"printed"`) || !strings.Contains(stderr, "remove-iam-policy-binding 'gs://"+rigBucket+"' --member '"+rigSharedMember+"'") {
		t.Errorf("the result is %s and stderr\n%s\nwant printed, with the remove lines", stdout, stderr)
	}
	if _, _, sets := r.bg.counts(); sets != 0 {
		t.Errorf("wrote the bucket's policy %d times", sets)
	}
}

// TestAGrantFoundInPlaceIsNotAPolicyChange (design §33, A33-26, A33-28): a
// grant the policy write finds already done, by another's change between
// the plan and step 3b, sent no write. The result says present, not
// applied, and a refusal after it does not list a policy change among what
// this command wrote.
func TestAGrantFoundInPlaceIsNotAPolicyChange(t *testing.T) {
	inPlace := func(r *storageRig) func() {
		return func() {
			r.bg.state, r.bg.shared, r.bg.sharedRoles = datasphere.GrantPresent, datasphere.GrantMissing, nil
		}
	}
	t.Run("the result", func(t *testing.T) {
		r := newStorageRig(t, nil)
		r.bg.shared = datasphere.GrantPresent
		doc := r.plan(t, "--grant-bucket")
		r.bg.onEnsure = inPlace(r)
		stdout, stderr, err := r.run(t, "--grant-bucket", "--confirm", doc.Digest)
		if err != nil || !strings.Contains(stdout, `"bucket_grant":"present"`) {
			t.Errorf("--confirm = %v, %s\n%s\nwant the grant present", err, stdout, stderr)
		}
	})
	t.Run("a later refusal", func(t *testing.T) {
		r := newStorageRig(t, nil)
		r.bg.shared = datasphere.GrantPresent
		doc := r.plan(t, "--grant-bucket")
		set := inPlace(r)
		r.bg.onEnsure = func() {
			set()
			if err := os.Remove(filepath.Join(r.dir.InstancePath(writeName), "fatline", "ca.key")); err != nil {
				t.Error(err)
			}
		}
		_, _, err := r.run(t, "--grant-bucket", "--confirm", doc.Digest)
		want := "; the keyholder's ServiceAccount farcast-system/datasphered was applied, the instance's registry was ensured and recorded, " +
			"the keyholder's image was pushed to the instance's registry, and nothing else was written"
		if err == nil || strings.Contains(err.Error(), "IAM policy now grants") || !strings.HasSuffix(err.Error(), want) {
			t.Errorf("--confirm = %v;\nwant a refusal ending %q, which names no policy change", err, want)
		}
	})
}

// forbiddenAfterApply is a writer whose RBAC refuses it every
// ServiceAccount read once it has applied a stream.
type forbiddenAfterApply struct{ *fakeCluster }

func (f forbiddenAfterApply) GetMeta(ctx context.Context, k kube.Kind, namespace, name string) (kube.Object, error) {
	if len(f.applied) > 0 {
		return kube.Object{}, &kube.APIError{Method: "GET", Path: "/api/v1/namespaces/" + namespace + "/serviceaccounts/" + name, KubernetesStatus: true,
			Status: kube.Status{Status: tkube.Status{Code: 403, Reason: "Forbidden",
				Message: `serviceaccounts "` + name + `" is forbidden: User "installer@proj-test1.iam.gserviceaccount.com" cannot get resource "serviceaccounts"`}}}
	}
	return f.fakeCluster.GetMeta(ctx, k, namespace, name)
}

// TestTheAccountReadAfterItsApplyIsTheWriters (design §33, A33-26 step 3):
// step 2b reads the keyholder's ServiceAccount as the writer that applied
// it, in mode consentNone, under --confirm too. A 403 there is the writer's,
// kind forbidden, and never the reader's 'farcast reader grant', which
// could not help; an account applied and then not found is its own
// refusal, internal, naming what was written.
func TestTheAccountReadAfterItsApplyIsTheWriters(t *testing.T) {
	t.Run("a 403", func(t *testing.T) {
		r := newStorageRig(t, nil)
		doc := r.plan(t)
		c := r.cmd(t, "--confirm", doc.Digest)
		c.deployer.newCluster = func(clusterRef) (clusterApplier, error) { r.writers++; return forbiddenAfterApply{r.fc}, nil }
		env, _, errb := testEnvBoth(r.dir, output.ModeJSON)
		err := c.Run(t.Context(), env, []string{writeName})
		if err == nil || strings.Contains(err.Error(), "reader grant") || kindOf(classified(err)) != kindForbidden ||
			!strings.Contains(err.Error(), "the keyholder's ServiceAccount farcast-system/datasphered was applied, and nothing else was written") {
			t.Errorf("--confirm = %v (kind %s)\n%s\nwant the writer's 403, forbidden, naming what was written, never the reader's", err, kindOf(classified(err)), errb)
		}
		r.accountOnly(t)
	})
	t.Run("not found", func(t *testing.T) {
		r := newStorageRig(t, nil)
		doc := r.plan(t)
		r.fc.onApply = func() { delete(r.fc.accounts, dsdeploy.DefaultName) }
		_, _, err := r.run(t, "--confirm", doc.Digest)
		want := "the ServiceAccount farcast-system/datasphered was applied and then not found; " +
			"the keyholder's ServiceAccount farcast-system/datasphered was applied, and nothing else was written"
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal {
			t.Errorf("--confirm = %v (kind %s);\nwant %q, internal", err, kindOf(classified(err)), want)
		}
		r.accountOnly(t)
	})
}

// bucketGrantNamesTheUID is TestGrantNamesTheServiceAccountUID's bucket
// rows (design §33, A33-4, A33-25, mutation 126): the bucket grant names
// the keyholder's ServiceAccount by its uid. The fact's principal, the
// policy read's and write's member and the printed add commands carry the
// fixture's uid principal, and the principal every instance in the project
// shares appears only as the fact's shared principal and in the commands
// that remove it.
func bucketGrantNamesTheUID(t *testing.T) {
	sharedOnlyInRemoves := func(t *testing.T, what, text string) {
		t.Helper()
		for _, l := range strings.Split(text, "\n") {
			if strings.Contains(l, "subject/ns/") && !strings.Contains(l, "remove-iam-policy-binding") && !strings.HasPrefix(l, "  the shared principal ") &&
				!strings.Contains(l, `"shared_principal":`) {
				t.Errorf("%s names the shared principal outside a remove: %s", what, l)
			}
		}
	}
	t.Run("the plan", func(t *testing.T) {
		r := newStorageRig(t, nil)
		r.bg.shared = datasphere.GrantPresent
		b := decodedBound(t, r.plan(t))
		g, _ := bucketGrantOf(b)
		if g.Principal != rigMember || g.SharedPrincipal != rigSharedMember || !slices.Equal(r.bg.members(), []string{"State " + rigMember}) {
			t.Errorf("the grant names %s and %s, and the policy was read for %q; want %s", g.Principal, g.SharedPrincipal, r.bg.members(), rigMember)
		}
		notice := strings.Join(noticesOf(b), "\n")
		if !strings.Contains(notice, "add-iam-policy-binding 'gs://"+rigBucket+"' --member '"+rigMember+"'") {
			t.Errorf("the notice does not add %s:\n%s", rigMember, notice)
		}
		for _, f := range b.Facts {
			if _, ok := f.(plan.GrantFact); ok {
				continue
			}
			raw, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			if n, ok := f.(plan.NoticeFact); ok {
				text = n.Text
			}
			sharedOnlyInRemoves(t, "a "+f.FactType(), text)
		}
		sharedOnlyInRemoves(t, "the rendering", renderPlan(t, b))
	})
	t.Run("the policy write", func(t *testing.T) {
		r := newStorageRig(t, nil)
		r.bg.shared = datasphere.GrantPresent
		if _, stderr, err := r.confirmGrant(t); err != nil {
			t.Fatalf("--confirm = %v\n%s", err, stderr)
		}
		if c := r.bg.calls[len(r.bg.calls)-1]; c.Method != "Ensure" || c.Member != rigMember || c.Shared != rigSharedMember {
			t.Errorf("the policy write was %+v; want the uid principal, removing the shared one", c)
		}
	})
	t.Run("the printed commands", func(t *testing.T) {
		r := newStorageRig(t, nil)
		r.bg.shared = datasphere.GrantPresent
		_, stderr, err := r.run(t, "--yes")
		if err != nil {
			t.Fatalf("--yes = %v\n%s", err, stderr)
		}
		if !strings.Contains(stderr, "add-iam-policy-binding 'gs://"+rigBucket+"' --member '"+rigMember+"'") {
			t.Errorf("the commands do not add %s:\n%s", rigMember, stderr)
		}
		sharedOnlyInRemoves(t, "the commands", stderr)
	})
}

// noGrantReader is a provider with the registry and without
// planck.GrantReader: a cloud that hosts images and states no project
// number.
type noGrantReader struct {
	planck.Provider
	planck.RegistryProvider
}

// bucketGrantsWithoutTheCapability is TestGrantsWithoutTheCapabilityAreUnknown's
// bucket rows (design §33, MS-6, A33-25): a storage provider without bucket
// IAM, and a compute provider that states no project number, leave both
// states unknown and read no policy; --grant-bucket there is the internal
// block. With no number the principals are "" and the commands read it
// into PROJNUM, naming the principals double-quoted around it.
func bucketGrantsWithoutTheCapability(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(r *storageRig)
		number  bool
	}{
		{"no bucket IAM", func(r *storageRig) { r.bg.openErr = storage.ErrNoBucketGrants }, true},
		{"no project number", func(r *storageRig) { r.fpOpen = noGrantReader{r.fp, r.fp} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStorageRig(t, nil)
			tc.prepare(r)
			b := decodedBound(t, r.plan(t))
			g, _ := bucketGrantOf(b)
			if g.State != plan.GrantUnknown || g.Shared != plan.GrantUnknown || (g.Principal == "") == tc.number {
				t.Errorf("the grant is %+v; want both states unknown, a principal: %v", g, tc.number)
			}
			if _, reads, _ := r.bg.counts(); reads != 0 {
				t.Errorf("read the policy %d times", reads)
			}
			notice := strings.Join(noticesOf(b), "\n")
			if projnum := strings.Contains(notice, "  PROJNUM=$(gcloud projects describe 'proj-test1' --format='value(projectNumber)')") ||
				strings.Contains(notice, `--member "principal://iam.googleapis.com/projects/${PROJNUM}/`); projnum == tc.number {
				t.Errorf("the notice reads the number into PROJNUM: %v; want %v:\n%s", projnum, !tc.number, notice)
			}
			blocked := decodedBound(t, r.plan(t, "--grant-bucket"))
			if len(blocked.Blocked) != 1 || blocked.Blocked[0].Kind != kindInternal || blocked.Blocked[0].Message != msgBucketGrantIncapable {
				t.Errorf("--grant-bucket's plan blocks %+v; want %q, internal", blocked.Blocked, msgBucketGrantIncapable)
			}
		})
	}
}

// bucketGrantLinesFor is the bucket grant's printed lines for the fixture,
// by the members given: the introduction, an add per role, the wait, a
// remove per role, the remove's introduction alone, and the closing lines.
func bucketGrantLinesFor(member, shared string) (intro string, adds []string, wait string, removes []string, removeAlone string, closing []string) {
	cmd := func(verb, m, role string) string {
		return "  gcloud storage buckets " + verb + "-iam-policy-binding 'gs://" + fixtureBucket + "' --member '" + m + "' --role '" + role + "' --condition=None"
	}
	for _, role := range bucketRoles {
		adds = append(adds, cmd("add", member, role))
		removes = append(removes, cmd("remove", shared, role))
	}
	return "Before this keyholder can start, its ServiceAccount farcast-system/datasphered needs read/write access to the bucket, granted to it by its uid. In Cloud Shell, run:",
		adds,
		"Then wait for IAM (typically 2 minutes, up to 7 or more), and remove the binding every FarCast instance in project 'proj-atlas' shares:",
		removes,
		"Remove the binding every FarCast instance in project 'proj-atlas' shares:",
		[]string{"The grant is on the BUCKET, not the project, and object access is", "separated from bucket reads so the keyholder cannot delete its own bucket."}
}

// bucketPrinterAddsBeforeItRemoves is TestPrintedGrantAddsBeforeItRemoves's
// bucket rows (design §33, A33-15, mutation 133): the commands add the
// keyholder's uid principal to both roles before they remove the shared
// one, so a running keyholder is never cut off; a remove names only a role
// that holds the shared principal, one line when only one does; each
// command is one line, every value single-quoted.
func bucketPrinterAddsBeforeItRemoves(t *testing.T) {
	intro, adds, wait, removes, removeAlone, closing := bucketGrantLinesFor(
		uidMember(fixtureProjectNumber, "proj-atlas", fixtureKeyholderUID), keyholderSharedMember(fixtureProjectNumber, "proj-atlas"))
	join := func(parts ...[]string) []string { return slices.Concat(parts...) }
	for _, tc := range []struct {
		name          string
		state, shared string
		sharedRoles   []string
		want          []string
	}{
		{"missing, the shared principal held", plan.GrantMissing, plan.GrantPresent, bucketRoles,
			join([]string{intro}, adds, []string{wait}, removes, closing)},
		{"missing, the shared principal held by one role", plan.GrantMissing, plan.GrantPresent, []string{"roles/storage.legacyBucketReader"},
			join([]string{intro}, adds, []string{wait}, removes[1:], closing)},
		{"missing, the shared principal gone", plan.GrantMissing, plan.GrantMissing, nil, join([]string{intro}, adds, closing)},
		{"present, the shared principal held", plan.GrantPresent, plan.GrantPresent, bucketRoles, join([]string{removeAlone}, removes)},
		{"present, the shared principal held by one role", plan.GrantPresent, plan.GrantPresent, []string{"roles/storage.objectAdmin"},
			join([]string{removeAlone}, removes[:1])},
		{"unknown", plan.GrantUnknown, plan.GrantUnknown, nil, join([]string{intro, "If gs://" + fixtureBucket + " does not grant it yet:"}, adds,
			[]string{"If it still grants the principal every FarCast instance in project 'proj-atlas' shares, wait for IAM, then:"}, removes, closing)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := fixtureBucketGrant(tc.state, tc.shared)
			g.sharedRoles = tc.sharedRoles
			text, err := g.printed(fixtureBucket, fixtureKeyholderUID)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Split(strings.Trim(text, "\n"), "\n"); !slices.Equal(got, tc.want) {
				t.Errorf("the commands are\n%s\nwant\n%s", text, strings.Join(tc.want, "\n"))
			}
			if strings.Contains(text, "\\") {
				t.Errorf("a command continues over a backslash:\n%s", text)
			}
		})
	}
}

// bucketPrinterNeedsNoDescribe is TestNoPrintedGrantDescribesTheProject's
// bucket rows (design §33, A33-15): with the project number known no
// command asks gcloud for it; with none known the first command reads it
// into PROJNUM, and the principals are double-quoted around it.
func bucketPrinterNeedsNoDescribe(t *testing.T) {
	for _, state := range []string{plan.GrantMissing, plan.GrantPresent, plan.GrantUnknown} {
		shared := plan.GrantPresent
		if state == plan.GrantUnknown {
			shared = plan.GrantUnknown
		}
		g := fixtureBucketGrant(state, shared)
		text, err := g.printed(fixtureBucket, fixtureKeyholderUID)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(text, "projects describe") || strings.Contains(text, "PROJNUM") {
			t.Errorf("%s: a command asks gcloud for the number it was given:\n%s", state, text)
		}
		g.number = 0
		text, err = g.printed(fixtureBucket, fixtureKeyholderUID)
		member := `--member "principal://iam.googleapis.com/projects/${PROJNUM}/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/`
		if err != nil || !strings.Contains(text, "\n  PROJNUM=$(gcloud projects describe 'proj-atlas' --format='value(projectNumber)')\n") ||
			!strings.Contains(text, member) || strings.Contains(text, "123456789012") {
			t.Errorf("%s with no number known: %v\n%s\nwant PROJNUM read first, the principals around it", state, err, text)
		}
	}
}
