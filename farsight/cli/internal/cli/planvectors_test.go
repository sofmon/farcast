package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/planck"
	"github.com/sofmon/farcast/technocore/cost"
)

// The plan vectors (ADR 0023 M2.6, A23-29): each command's printed plan, byte
// for byte, made by the command itself through its seams against the atlas
// fixture's record, with this farcast's stamp and clock fixed at the world
// vectors' own. The commands of M2.6a and M2.6b read no cluster. Those of
// M2.6c — kernel deploy, storage deploy, storage key pin and storage key
// rotate — read it as the instance's reader, through vectorCluster, a fixed
// cluster that holds atlas's namespaces and no key pin yet, and the storage
// commands read the ids and times of vectorKeyring's keys. connect's,
// redeploy's, kernel deploy's and storage deploy's read the registry,
// through a fake provider and a fake builder whose registry holds no carried
// image's version tag, as a release farcast at the vector stamp that carries
// the fake components. They are produced in Go and are not copied to
// FarSightKit until ADR 0021 step 7.1. Each part of M2.6 adds the vectors of
// the commands it wires, and M2.8 git-credential's, which read the record
// alone. M2.7 added migrate's, which M2.9a removed (design A37-10).
//
//	FARCAST_UPDATE_VECTORS=1 go test ./farsight/cli/internal/cli/ -run Vector
//
// rewrites them.

// planVectorMeta is the atlas fixture's record as the plan vectors bind it:
// vectorMeta, which records no creation time, with one.
func planVectorMeta() *config.InstanceMetadata {
	meta := vectorMeta()
	meta.CreatedAt = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	return meta
}

// vectorClock is the plan vectors' clock.
func vectorClock() time.Time { return vectorNow }

// usePlanVectorStamp binds the vector stamp in every plan for the rest of
// the test.
func usePlanVectorStamp(t *testing.T) {
	t.Helper()
	saved := planStamp
	planStamp = func() plan.Stamp { return plan.Stamp(vectorStamp) }
	t.Cleanup(func() { planStamp = saved })
}

// planVector is one command's plan as a vector: the record it is made from,
// and the command, its flags parsed and its clock fixed.
type planVector struct {
	name string
	edit func(meta *config.InstanceMetadata)
	cmd  func(t *testing.T, flags ...string) Command
	args []string
	// flags are the command's own; the vector adds --plan.
	flags []string
	// prepare, when set, writes what the record alone cannot say: the
	// installer's key, for a plan that reads the registry, and the CA
	// certificate, for one that loads the instance's material.
	prepare func(t *testing.T, dir config.Dir)
	// deploy marks run's deploy plan: the vector is what --confirm with the
	// fetch plan's digest prints, in place of --plan.
	deploy bool
}

// vectorRevision is the revision the plan vectors' farcast was built at,
// and its carried components with it: the vector stamp's commit, padded to
// a full revision.
const vectorRevision = "0e54eb1" + "000000000000000000000000000000000"

// vectorCACert is the CA certificate the redeploy vector's instance holds:
// the P-256 instance CA of FatLine's PKI fixture
// (fatline/internal/crypto/testdata/pki/p256.json), public test data trusted
// nowhere else. A plan reads this certificate, never a key.
const vectorCACert = `-----BEGIN CERTIFICATE-----
MIIBgTCCASigAwIBAgIBATAKBggqhkjOPQQDAjAnMSUwIwYDVQQDExxGYXJDYXN0
IEluc3RhbmNlIENBOiBmaXh0dXJlMB4XDTI2MTExMjIzNTkwMFoXDTI4MTExMjAw
MDAwMFowJzElMCMGA1UEAxMcRmFyQ2FzdCBJbnN0YW5jZSBDQTogZml4dHVyZTBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABKzz0I4jC96W7jkv8aWX74iKrR+K6VLS
CCY6Z7kgoh83TUg/NwdBbLfv4I3LMHMCoGyJAD3zG6fkzwK39m4kmIOjRTBDMA4G
A1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRfkcan
ANozTsWRo/M0WTCnmTAtUTAKBggqhkjOPQQDAgNHADBEAiBiNjtZwv8ke+G2G4ua
l/Sig68fxXr2d1zabessMsHgfgIgfwhUyL2Kj8TckPDYzuBynlRASMXCH432NYq3
6/j1u9k=
-----END CERTIFICATE-----
`

// vectorDeployer makes d the plan vectors' farcast: a release at the vector
// stamp, built at vectorRevision and carrying the fake components built
// there, its clock the vectors'. Its provider is a fake, and its builder one
// whose registry holds no version tag, so a plan pushes each carried image.
// It finds no checkout, and its writer refuses: a plan opens none.
func vectorDeployer(d *fatlineDeployer) {
	carried := newFakeCarried()
	carried.revision = vectorRevision
	d.carried = carried
	d.build = func() buildinfo.Info {
		return buildinfo.Info{Version: vectorStamp.Version, Commit: vectorStamp.Commit, Date: "2026-11-01T09:00:00Z", Revision: vectorRevision}
	}
	d.now = vectorClock
	d.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return &fakeProvider{}, nil
	}
	d.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{resolveFn: notFoundForTags} }
	d.findSource = func(string) (string, error) { return "", errors.New("test: the vectors build nothing") }
	d.findToolchain = fakeToolchain
	d.newCluster = func(clusterRef) (clusterApplier, error) { return nil, errors.New("test: a plan opened the writer") }
}

// vectorKey stores the installer's key, a stand-in, for a plan that reads
// the registry with it.
func vectorKey(t *testing.T, dir config.Dir) {
	t.Helper()
	if err := dir.SaveInstanceCredentials("atlas", &config.InstanceCredentials{Provider: "gke", ServiceAccountKey: standInKey}); err != nil {
		t.Fatal(err)
	}
}

// vectorFirstConnect is the atlas record before its first connect: FatLine
// not deployed, no carrier, and no image recorded for FatLine or Shrike.
func vectorFirstConnect(m *config.InstanceMetadata) {
	m.FatLineDeployed, m.Carrier, m.Registry.FatLineDigest = false, nil, ""
	delete(m.SystemImages, "fatline")
	delete(m.SystemImages, "shrike")
}

// vectorRedeployed is the atlas record as a redeploy over another release
// finds it: FatLine and Shrike run images an earlier farcast pushed into the
// registry's system paths, so the plan, made with --embedded, replaces both
// and says so.
func vectorRedeployed(m *config.InstanceMetadata) {
	fl, sh := vecRegistry+"/system/fatline"+digestOf("1"), vecRegistry+"/system/shrike"+digestOf("2")
	m.Registry.FatLineDigest = fl
	m.SystemImages["fatline"] = config.SystemImage{Image: fl, Origin: config.OriginEmbedded, Go: "go1.27.4", Farcast: "v0.0.0-earlier"}
	m.SystemImages["shrike"] = config.SystemImage{Image: sh, Origin: config.OriginEmbedded, Go: "go1.27.4", Farcast: "v0.0.0-earlier"}
}

// vectorMaterial is the redeploy vector's key and CA certificate: the
// instance's material as far as a plan reads it.
func vectorMaterial(t *testing.T, dir config.Dir) {
	t.Helper()
	vectorKey(t, dir)
	if err := dir.SaveInstanceMTLS("atlas", config.MTLSMaterial{CACertPEM: []byte(vectorCACert)}); err != nil {
		t.Fatal(err)
	}
}

// vectorSystemUID is farcast-system's uid in vectorCluster, the one A23-29
// chose for the vectors' reader seams.
const vectorSystemUID = "00000000-0000-4000-8000-000000000026"

// vectorCluster is the cluster the plan vectors of M2.6c read, as the
// instance's reader: the atlas fixture's namespaces, farcast-system at
// vectorSystemUID, no key pin yet, and the ServiceAccounts the vector's
// accounts name, each at its uid (ADR 0023 M2.8, design §33 A33-40), any
// other not found. It answers nothing else, and is opened as nothing but the
// reader (vectorReader).
type vectorCluster struct{ accounts map[string]string }

func (vectorCluster) Namespaces(context.Context) ([]string, error) {
	return []string{"farcast-system", "shop"}, nil
}

func (vectorCluster) NamespaceUID(context.Context, string) (string, error) {
	return vectorSystemUID, nil
}

func (vectorCluster) ConfigMapData(context.Context, string, string) (map[string]string, string, bool, error) {
	return nil, "", false, nil
}

func (c vectorCluster) GetMeta(_ context.Context, k kube.Kind, namespace, name string) (kube.Object, error) {
	return accountMeta(c.accounts, k, namespace, name)
}

// vectorReader is a plan's reader seam over vectorCluster, holding the
// keyholder's and the builder's ServiceAccounts at their fixture uids, which
// refuses any identity but the reader's.
func vectorReader(r clusterRef) (vectorCluster, error) {
	if r.Identity != kube.Reader {
		return vectorCluster{}, fmt.Errorf("test: a vector's plan opened the cluster as %q", r.Identity)
	}
	return vectorCluster{accounts: fixtureAccounts()}, nil
}

// vectorPinReader is vectorReader as the storage commands' seam.
func vectorPinReader(r clusterRef) (pinPlanReader, error) {
	c, err := vectorReader(r)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// vectorKeyholderReader is vectorReader as storage deploy's seam, whose
// cluster holds the ServiceAccounts accounts names (A33-40): the fixture's
// for a deploy over the recorded bucket, and none for a first deploy, whose
// plan binds the uid placeholder.
func vectorKeyholderReader(accounts map[string]string) func(clusterRef) (keyholderPlanReader, error) {
	return func(r clusterRef) (keyholderPlanReader, error) {
		c, err := vectorReader(r)
		if err != nil {
			return nil, err
		}
		c.accounts = accounts
		return c, nil
	}
}

// vectorBucketGrants is the bucket IAM the storage vectors read (A33-40):
// a policy that grants the roles to the principal every keyholder in the
// project shares, and not to the keyholder's uid.
func vectorBucketGrants(context.Context, *Env, *config.InstanceMetadata) (bucketGrants, error) {
	return &fakeBucketGrants{shared: datasphere.GrantPresent}, nil
}

// vectorNoPinWriter and vectorNoKeyholder are the storage commands' writer
// and keyholder in the vectors: a plan opens neither.
func vectorNoPinWriter(clusterRef) (pinStore, error) {
	return nil, errors.New("test: a vector's plan opened the pin as the writer")
}

func vectorNoKeyholder(context.Context, *Env, string) (sealStateClient, func(), error) {
	return nil, nil, errors.New("test: a vector's plan opened the keyholder")
}

// vectorReaderKey puts atlas's reader key on this machine, as 'reader init'
// left it: a plan that reads the cluster needs the reader granted, which it
// tells by the file's presence, and never reads it here.
func vectorReaderKey(t *testing.T, dir config.Dir) {
	t.Helper()
	if err := dir.SaveReaderKey("atlas", []byte("not read"), []byte("not read")); err != nil {
		t.Fatal(err)
	}
}

// vectorKeyring is atlas's keyring for the storage vectors, written as
// keys.yaml: the instance's key space and one application scope, shop/web,
// each with one name key and one key-encryption key, at fixed ids and times.
// Its key material is a counted pattern, test data trusted nowhere; a plan
// reads the ids and the times, never a key, and TestPlanVectors checks that
// no vector holds one.
func vectorKeyring(t *testing.T, dir config.Dir) {
	t.Helper()
	scope, err := datasphere.AppScopeName("shop", "web")
	if err != nil {
		t.Fatal(err)
	}
	// Each key counts up from its first byte, so none of them reads as the
	// fixtures' digests, which repeat one hex digit.
	key := func(b byte) string {
		k := make([]byte, 32)
		for i := range k {
			k[i] = b + byte(i)
		}
		return base64.StdEncoding.EncodeToString(k)
	}
	const created = "2026-11-01T09:00:00Z"
	keys := fmt.Sprintf(`version: 2
name_keys:
- id: "a7a7000000000001"
  key: %s
  created: %s
keys:
- id: "a7a7000000000002"
  key: %s
  created: %s
scopes:
- name: %s
  prefix: %s
  created: %s
  name_keys:
  - id: "a7a7000000000003"
    key: %s
    created: %s
  keys:
  - id: "a7a7000000000004"
    key: %s
    created: %s
`, key(0x11), created, key(0x22), created, scope, datasphere.AppScopePrefix("shop", "web"), created, key(0x33), created, key(0x44), created)
	if _, err := datasphere.ParseKeyring([]byte(keys)); err != nil {
		t.Fatalf("the vectors' keyring does not parse: %v", err)
	}
	if err := dir.CreateInstanceKeyring("atlas", []byte(keys)); err != nil {
		t.Fatal(err)
	}
}

// vectorRunManifest is the manifest run's vectors read from
// github.com/example/shop: web, whose scope atlas's keyring already holds,
// and api, which is new and reaches one host.
const vectorRunManifest = `name: shop
apps:
  - name: web
    containerfile: web/Containerfile
    context: web
  - name: api
    containerfile: api/Containerfile
    external:
      - host: api.stripe.com
        reason: payment processing
`

// vectorRunJobUID is the fetch Job's uid in vectorRunCluster.
const vectorRunJobUID = "00000000-0000-4000-8000-0000000000f1"

var (
	vectorRunArgs  = []string{"atlas", "github.com/example/shop"}
	vectorRunFlags = []string{"--fetcher-image", fetcherDigest, "--builder-image", builderDigest}
)

// vectorRunCluster is the cluster run's deploy vector reads, as the
// instance's reader: the fetch Job, finished, at vectorRunJobUID, which read
// vectorRunManifest; the kernel's ledger, fresh at the vectors' clock and
// below the limit; atlas's namespaces; shop's web Deployment, which the
// kernel adapted after farcast last applied it, and a StatefulSet beside it;
// another deployment's egress policy at resourceVersion 41; no key pin; and
// the ServiceAccounts accounts names, each at its uid, any other not found
// (design §33, A33-40).
type vectorRunCluster struct {
	ledger   string
	accounts map[string]string
}

func (c vectorRunCluster) GetMeta(_ context.Context, k kube.Kind, namespace, name string) (kube.Object, error) {
	return accountMeta(c.accounts, k, namespace, name)
}

func (vectorRunCluster) NamespaceUID(context.Context, string) (string, error) {
	return vectorSystemUID, nil
}

func (vectorRunCluster) Namespaces(context.Context) ([]string, error) {
	return []string{"farcast-system", "shop"}, nil
}

func (c vectorRunCluster) ConfigMapValue(_ context.Context, ns, name, key string) (string, bool, error) {
	if ns+"/"+name+"/"+key == ledgerKey {
		return c.ledger, true, nil
	}
	return "", false, nil
}

func (vectorRunCluster) ConfigMapData(_ context.Context, ns, name string) (map[string]string, string, bool, error) {
	if ns != fldeploy.DefaultNamespace || name != fldeploy.PolicyConfigMap {
		return nil, "", false, nil
	}
	doc := &policy.Document{Version: policy.Version, Apps: []policy.App{{Name: "worker", Namespace: "jobs",
		CredentialSHA256: credentialOf("e"), External: []parser.External{{Host: "queue.example", Reason: "jobs"}}}}}
	body, err := doc.Marshal()
	if err != nil {
		return nil, "", false, err
	}
	return map[string]string{fldeploy.PolicyKey: string(body)}, "41", true, nil
}

func (vectorRunCluster) JobState(context.Context, string, string) (cluster.JobResult, bool, error) {
	return cluster.JobResult{Succeeded: true, UID: vectorRunJobUID}, true, nil
}

func (vectorRunCluster) WaitJob(context.Context, string, string, time.Duration) (cluster.JobResult, error) {
	return cluster.JobResult{Succeeded: true, Message: reportFor(vectorRunManifest), UID: vectorRunJobUID}, nil
}

func (vectorRunCluster) JobLogs(context.Context, string, string, int) (string, error) {
	return vectorRunManifest, nil
}

func (vectorRunCluster) DeploymentState(_ context.Context, ns, name string) (cluster.DeploymentState, error) {
	if ns != "shop" || name != "web" {
		return cluster.DeploymentState{}, nil
	}
	replicas := int32(1)
	return cluster.DeploymentState{
		Present: true, Replicas: &replicas,
		Requests:      map[string]cluster.Requests{"web": {CPUMilli: 250, MemMiB: 512}},
		AdaptedAt:     time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC),
		LastAppliedAt: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC),
	}, nil
}

func (vectorRunCluster) Workloads(_ context.Context, ns string) ([]cluster.Workload, error) {
	return []cluster.Workload{wl("Deployment", ns, "web", 1, 1), wl("StatefulSet", ns, "db", 1, 1)}, nil
}

// vectorRunWriter is run's writer in the deploy vector: --confirm with the
// fetch plan's digest applies the read through it, and nothing else.
type vectorRunWriter struct{ vectorRunCluster }

func (vectorRunWriter) Apply(_ context.Context, stream []byte) error {
	if !strings.Contains(string(stream), "name: fetch-") {
		return errors.New("test: a vector's run applied more than its read")
	}
	return nil
}

func (vectorRunWriter) ApplyAt(context.Context, []byte, string) error {
	return errors.New("test: a vector's run wrote the egress policy")
}

func (vectorRunWriter) RolloutStatus(context.Context, string, string, time.Duration) error {
	return errors.New("test: a vector's run waited on a rollout")
}

// vectorRun is run for its vectors: its reader vectorRunCluster, opened as
// nothing but the reader; its writer, for the read alone; its clock the
// vectors'; and every seam that would mint, push or reach the keyholder
// refused.
func vectorRun(t *testing.T, flags ...string) Command {
	c := withFlags(t, &runCommand{}, flags...)
	cl := vectorRunCluster{ledger: savedCheckpoint(t, cost.LevelOK.String(), vectorNow.Add(-time.Minute)), accounts: fixtureAccounts()}
	c.newPlanReader = func(r clusterRef) (runPlanReader, error) {
		if r.Identity != kube.Reader {
			return nil, fmt.Errorf("test: a vector's plan read the cluster as %q", r.Identity)
		}
		return cl, nil
	}
	c.newCluster = func(r clusterRef) (runCluster, error) {
		if r.Identity != kube.Writer {
			return nil, fmt.Errorf("test: a vector's run wrote as %q", r.Identity)
		}
		return vectorRunWriter{cl}, nil
	}
	c.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
	c.openProvider = vectorPushProvider(map[string]planck.GrantState{vectorBuilderSharedPrincipal: planck.GrantPresent})
	c.newKeyholder = vectorNoKeyholder
	c.newPinStore = vectorNoPinWriter
	c.mintCredential = func(string, string) (string, error) {
		return "", errors.New("test: a vector's plan minted a credential")
	}
	c.now = vectorClock
	return c
}

// vectorRunMaterial is what run's deploy vector reads on this machine: the
// reader's key, atlas's keyring, the CA certificate, and a stand-in ca.key,
// whose size alone the plan reads (A28-9), and never its bytes.
func vectorRunMaterial(t *testing.T, dir config.Dir) {
	t.Helper()
	vectorReaderKey(t, dir)
	vectorKeyring(t, dir)
	if err := dir.SaveInstanceMTLS("atlas", config.MTLSMaterial{CACertPEM: []byte(vectorCACert), CAKeyPEM: []byte("a stand-in, never read\n")}); err != nil {
		t.Fatal(err)
	}
}

// vectorRegistryNamed is the atlas record with its registry's repository and
// location recorded beside its prefix, as the ensure records them: build's
// and run's plans refuse a record without them (design §33, A33-15).
func vectorRegistryNamed(m *config.InstanceMetadata) {
	m.Registry.Repository, m.Registry.Location = "farcast-atlas", "europe-west4"
}

// vectorPushProvider is the provider build's and run's vectors read the push
// grant through (A33-40): the fixture number, and a repository policy that
// holds the principals of states, each by its member, any other missing.
func vectorPushProvider(states map[string]planck.GrantState) providerOpener {
	return func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return &fakeProvider{grantStates: states}, nil
	}
}

// The builder's two principals in the vectors' project, at the fixture
// number: its uid one, and the one every instance in the project shares.
const (
	vectorBuilderPrincipal       = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/kubernetes.serviceaccount.uid/" + fixtureBuilderUID
	vectorBuilderSharedPrincipal = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/subject/ns/farcast-system/sa/farcast-builder"
)

// vectorConfirmations is the confirmed window the kernel_confirm vector's
// record already holds, so the plan's windows_after has two.
func vectorConfirmations(m *config.InstanceMetadata) {
	m.Kernel.Confirmations = []config.KernelConfirmation{{
		Start: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC),
		USD: 1.03, AsOf: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC),
	}}
}

func planVectors() []planVector {
	return []planVector{
		{"kernel_meter", nil, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &kernelMeterCommand{}, flags...)
			c.deployer.now = vectorClock
			return c
		}, []string{"atlas", "web"}, nil, nil, false},
		{"kernel_confirm", vectorConfirmations, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &kernelConfirmCommand{}, flags...)
			c.deployer.now = vectorClock
			return c
		}, []string{"atlas"}, []string{"--amount", "2.71"}, nil, false},
		{"reader_grant", nil, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &readerGrantCommand{}, flags...)
			c.now = vectorClock
			return c
		}, []string{"atlas"}, nil, nil, false},
		// connect's first deploy: the material minted, the carried images
		// pushed, the load balancer's cost.
		{"connect_first", vectorFirstConnect, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, newConnectCommand(), flags...)
			vectorDeployer(&c.fatlineDeployer)
			c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
				return nil, errors.New("test: a plan dialled the carrier")
			}
			return c
		}, []string{"atlas"}, nil, vectorKey, false},
		// redeploy over the material the instance holds, replacing what an
		// earlier release deployed.
		{"redeploy", vectorRedeployed, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, newRedeployCommand(), flags...)
			vectorDeployer(&c.fatlineDeployer)
			return c
		}, []string{"atlas"}, []string{"--embedded"}, vectorMaterial, false},
		// build, its builder named, read as the reader (design §33, A33-21):
		// farcast-system's uid, the builder's ServiceAccount at its fixture
		// uid, and, with the installer's key, a repository policy that
		// grants it push by that uid and not the shared principal, so no
		// notice.
		{"build", vectorRegistryNamed, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &buildCommand{}, flags...)
			c.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
			c.newCluster = func(clusterRef) (jobWaiter, error) { return nil, errors.New("test: a plan opened the writer") }
			c.newPlanReader = func(r clusterRef) (buildPlanReader, error) { return vectorReader(r) }
			c.openProvider = vectorPushProvider(map[string]planck.GrantState{vectorBuilderPrincipal: planck.GrantPresent})
			c.now = vectorClock
			return c
		}, []string{"atlas"}, []string{"--repo", "https://github.com/example/shop", "--app", "api", "--builder-image", builderDigest}, func(t *testing.T, dir config.Dir) {
			vectorKey(t, dir)
			vectorReaderKey(t, dir)
		}, false},
		// kernel deploy, as the reader reads the cluster: the kernel's image,
		// its settings, and every document of its workload.
		{"kernel_deploy", nil, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &kernelDeployCommand{}, flags...)
			vectorDeployer(&c.deployer)
			c.newPlanReader = func(r clusterRef) (kernelPlanReader, error) { return vectorReader(r) }
			return c
		}, []string{"atlas"}, nil, func(t *testing.T, dir config.Dir) {
			vectorKey(t, dir)
			vectorReaderKey(t, dir)
		}, false},
		// storage deploy over the recorded bucket: the keyholder's image, its
		// leaf, a restart of the replicas deployed, the Namespace and the
		// keyholder's ServiceAccount, its bucket grant by the account's uid,
		// read missing while the shared principal holds both roles and not
		// applied, the pin this keyring implies, created, the rest of the
		// keyholder's workload, and the grant's commands as a notice (design
		// §33, A33-40).
		{"storage_deploy", nil, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &storageDeployCommand{}, flags...)
			vectorDeployer(&c.deployer)
			c.newPlanReader = vectorKeyholderReader(fixtureAccounts())
			c.newPinStore = vectorNoPinWriter
			c.openBucketGrants = vectorBucketGrants
			c.ensureStorage = func(context.Context, *Env, string) error { return errors.New("test: a vector's plan minted storage") }
			return c
		}, []string{"atlas"}, nil, func(t *testing.T, dir config.Dir) {
			vectorMaterial(t, dir)
			vectorReaderKey(t, dir)
			vectorKeyring(t, dir)
		}, false},
		// storage deploy's first deploy with --grant-bucket: the bucket and
		// the keyholder's ServiceAccount do not exist yet, so the grant names
		// both placeholders, reads no policy and binds both states missing,
		// and is applied, as the cloud fact on the placeholder bucket says;
		// no grant notice (A33-40).
		{"storage_deploy_grant", func(m *config.InstanceMetadata) { m.Storage, m.Keyholder = nil, nil }, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &storageDeployCommand{}, flags...)
			vectorDeployer(&c.deployer)
			c.newPlanReader = vectorKeyholderReader(map[string]string{})
			c.newPinStore = vectorNoPinWriter
			c.openBucketGrants = vectorBucketGrants
			c.ensureStorage = func(context.Context, *Env, string) error { return errors.New("test: a vector's plan minted storage") }
			return c
		}, []string{"atlas"}, []string{"--grant-bucket"}, func(t *testing.T, dir config.Dir) {
			vectorMaterial(t, dir)
			vectorReaderKey(t, dir)
		}, false},
		// storage key pin: the pin this keyring implies, created.
		{"storage_key_pin", nil, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &keyPinCommand{}, flags...)
			c.newPlanReader = vectorPinReader
			c.newPinStore = vectorNoPinWriter
			c.newKeyholder = vectorNoKeyholder
			c.now = vectorClock
			return c
		}, []string{"atlas"}, nil, func(t *testing.T, dir config.Dir) {
			vectorReaderKey(t, dir)
			vectorKeyring(t, dir)
		}, false},
		// storage key rotate, with the keyholder deployed: a key for the
		// instance's key space and for shop/web, and the hold and final pins
		// over the new key's placeholder id.
		{"storage_key_rotate", nil, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &keyRotateCommand{}, flags...)
			c.newPlanReader = vectorPinReader
			c.newPinStore = vectorNoPinWriter
			c.newKeyholder = vectorNoKeyholder
			c.now = vectorClock
			return c
		}, []string{"atlas"}, nil, func(t *testing.T, dir config.Dir) {
			vectorReaderKey(t, dir)
			vectorKeyring(t, dir)
		}, false},
		// run's fetch plan: the manifest read, its Job's cost, the fetcher
		// and the read's three documents. It reads keys.yaml for the scope
		// every application once shared, and no cluster.
		{"run_fetch", vectorRegistryNamed, vectorRun, vectorRunArgs, vectorRunFlags, vectorKeyring, false},
		// run's deploy plan, as --confirm with the fetch plan's digest prints
		// it, computed as the reader over vectorRunCluster: shop's two
		// applications, web adapted by the kernel and its scope already
		// minted, api new, with its scope and key and the pin they raise,
		// and a StatefulSet kept; and the builder's push grant, missing by
		// its fixture uid while the shared principal holds it, with its
		// notice (design §33, A33-40).
		{"run_deploy", vectorRegistryNamed, vectorRun, vectorRunArgs, vectorRunFlags, func(t *testing.T, dir config.Dir) {
			vectorRunMaterial(t, dir)
			vectorKey(t, dir)
		}, true},
		// git-credential set (M2.8, design §33, A33-40): the Secret
		// farcast-system/repo-git, rendered from the placeholders. Its
		// --username is a marker, which no plan binds, and its --token-file
		// names a file that does not exist, which no plan reads.
		{"git_credential_set", nil, vectorGitCredential(plan.GitCredentialSet), []string{"atlas"},
			[]string{"--name", "repo-git", "--username", vectorGitUsername, "--token-file", vectorGitTokenFile}, nil, false},
		// git-credential rm: the delete of farcast-system/repo-git, on the
		// uid its read finds after consent.
		{"git_credential_rm", nil, vectorGitCredential(plan.GitCredentialRm), []string{"atlas"},
			[]string{"--name", "repo-git"}, nil, false},
	}
}

// The git_credential_set vector's data flags (A33-40): a username marker,
// which no plan may bind, and a token file that does not exist, which no
// plan may read.
const (
	vectorGitUsername  = "VECTOR-GIT-USERNAME-MARKER"
	vectorGitTokenFile = "/nonexistent/farcast-vector/git-token"
)

// vectorGitCredential is git-credential set or rm for its vectors: its clock
// the vectors', and its writer and its token refused, for a plan opens and
// reads neither.
func vectorGitCredential(action string) func(t *testing.T, flags ...string) Command {
	return func(t *testing.T, flags ...string) Command {
		c := withFlags(t, &gitCredentialCommand{action: action}, flags...)
		c.newCluster = func(clusterRef) (gitCredentialCluster, error) {
			return nil, errors.New("test: a vector's plan opened the writer")
		}
		c.readToken = func(*Env, string) ([]byte, error) {
			return nil, errors.New("test: a vector's plan read the token")
		}
		c.now = vectorClock
		return c
	}
}

// runPlanVector runs v, with extra flags, against a config directory that
// holds the vector's record and what its prepare writes, and nothing else,
// and returns what it printed in JSON mode, and its error.
func runPlanVector(t *testing.T, v planVector, extra ...string) (*Env, *bytes.Buffer, error) {
	t.Helper()
	// run's deploy plan is what confirming its fetch plan prints: the fetch
	// plan first, from the same record, then its digest confirmed.
	if v.deploy && slices.Equal(extra, []string{"--plan"}) {
		fetch := v
		fetch.deploy = false
		_, out, err := runPlanVector(t, fetch, "--plan")
		if err != nil {
			return nil, nil, err
		}
		extra = []string{"--confirm", printedDocument(t, out.Bytes()).Digest}
	}
	dir := vectorConfigDir(t)
	meta := planVectorMeta()
	if v.edit != nil {
		v.edit(meta)
	}
	writeRecord(t, dir, meta)
	if v.prepare != nil {
		v.prepare(t, dir)
	}
	env, out := testEnv(dir, output.ModeJSON)
	err := v.cmd(t, append(append([]string(nil), v.flags...), extra...)...).Run(t.Context(), env, v.args)
	return env, out, err
}

func TestPlanVectors(t *testing.T) {
	usePlanVectorStamp(t)
	seen := map[string]bool{}
	for _, v := range planVectors() {
		t.Run(v.name, func(t *testing.T) {
			if seen[v.name] {
				t.Fatalf("two vectors are named %q", v.name)
			}
			seen[v.name] = true
			env, out, err := runPlanVector(t, v, "--plan")
			if err != nil {
				t.Fatal(err)
			}
			got := out.Bytes()
			// A vector made over a keyring holds none of its keys (A23-25).
			if held, err := env.ConfigDir.InstanceKeyringExists("atlas"); err != nil || held {
				encoded, raw := keyMaterialOf(t, env.ConfigDir, "atlas")
				for i, key := range raw {
					for _, form := range []string{encoded[i], base64.RawStdEncoding.EncodeToString(key), base64.URLEncoding.EncodeToString(key),
						base64.RawURLEncoding.EncodeToString(key), hex.EncodeToString(key)} {
						if bytes.Contains(got, []byte(form)) {
							t.Fatalf("the vector holds key %d of its keyring, as %s", i, form)
						}
					}
				}
			}
			doc := printedDocument(t, got)
			if b := decodedBound(t, doc); len(b.Blocked) != 0 || len(b.Facts) == 0 || b.Target.Project != "proj-atlas" {
				t.Fatalf("the vector is not a plan of the atlas fixture: %s", got)
			}
			// The same record, planned again, is the same bytes.
			if _, again, err := runPlanVector(t, v, "--plan"); err != nil || !bytes.Equal(got, again.Bytes()) {
				t.Fatalf("two plans from one record differ (%v):\n%s\n%s", err, got, again)
			}
			checkVector(t, "plan", v.name, got)
		})
	}
}

// TestPlanErrorVectors is the envelope --confirm prints for a plan that
// changed: kernel confirm, confirming the digest of no plan, printed as the
// router prints an error.
func TestPlanErrorVectors(t *testing.T) {
	usePlanVectorStamp(t)
	t.Run("plan_changed", func(t *testing.T) {
		var v planVector
		for _, pv := range planVectors() {
			if pv.name == "kernel_confirm" {
				v = pv
			}
		}
		env, out, err := runPlanVector(t, v, "--confirm", "sha256:"+strings.Repeat("0", 64))
		if kindOf(classified(err)) != kindPlanChanged || out.Len() != 0 {
			t.Fatalf("kernel confirm of another plan = %v, printing %q; want plan_changed", err, out)
		}
		env.Printer.PrintError(classified(err), exitCodeOf(err))
		checkVector(t, "plan", "error_plan_changed", out.Bytes())
	})
}
