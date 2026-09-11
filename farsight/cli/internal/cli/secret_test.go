package cli

// `farcast secret` — the operator's half of the SDK's Secrets capability.
//
// As in storage_test.go, nothing above the cloud is stubbed: every test drives
// a real datasphere.Store through the CLI's own storage.Open over an in-memory
// provider, so what is asserted is real ciphertext under a real tokenized
// name.
//
// The assertion that matters most is the one against Planck: the operator
// writes to a key an application reads, and the two are computed in different
// packages from different inputs. A mistake there does not fail loudly — it
// stores a secret nothing will ever fetch.

import (
	"bytes"
	"context"
	"flag"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/planck/translate"
)

// secretEnv is newDataEnv with a keyholder recorded, which is the state
// `farcast storage deploy` leaves behind and what the secret verbs need in
// order to agree with what applications are handed.
func secretEnv(t *testing.T, mode output.Mode, stdin string) (*Env, *bytes.Buffer, *bytes.Buffer, config.Dir) {
	t.Helper()
	env, out, errb, dir, _ := newDataEnv(t, mode)
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatalf("SaveInstanceMetadata: %v", err)
	}
	// The scopes `farcast run` mints when it deploys these applications. A
	// secret belongs inside one, so without them there is nowhere to put it.
	mintAppScopes(t, env, "apps", "api", "web")
	env.In = strings.NewReader(stdin)
	return env, out, errb, dir
}

// mintAppScopes does to the keyring what deploying those applications would.
func mintAppScopes(t *testing.T, env *Env, namespace string, apps ...string) {
	t.Helper()
	session := dataSession(t, env)
	keys := session.Keyring
	for _, app := range apps {
		scope, err := datasphere.NewAppScope(namespace, app)
		if err != nil {
			t.Fatal(err)
		}
		grown, err := keys.AddScope(scope)
		if err != nil {
			t.Fatal(err)
		}
		keys = grown
	}
	encoded, err := keys.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := env.ConfigDir.SaveInstanceKeyring("prod", encoded); err != nil {
		t.Fatal(err)
	}
}

func setSecret(t *testing.T, env *Env, args []string, cmd *secretSetCommand) error {
	t.Helper()
	return cmd.Run(context.Background(), env, args)
}

func TestSecretSetStoresUnderTheApplicationsOwnPrefix(t *testing.T) {
	env, out, _, _ := secretEnv(t, output.ModeHuman, "hunter2")

	if err := setSecret(t, env, []string{"prod", "apps/api", "DB_PASSWORD"}, &secretSetCommand{}); err != nil {
		t.Fatalf("secret set: %v", err)
	}

	session := dataSession(t, env)
	const key = "app/apps/api/secrets/DB_PASSWORD"
	if got := readStored(t, session, key); got != "hunter2" {
		t.Errorf("stored value = %q, want hunter2", got)
	}
	// The cloud holds ciphertext under a tokenized name: neither the key nor
	// the value appears in the bucket.
	stored := storedNameFor(t, session, key)
	if strings.Contains(stored, "DB_PASSWORD") || strings.Contains(stored, "secrets") {
		t.Errorf("the stored name leaks the logical key: %q", stored)
	}
	if strings.Contains(out.String(), "hunter2") {
		t.Errorf("the value was echoed back:\n%s", out)
	}
}

// The operator writes where the application reads. The two keys are built in
// different packages from different inputs — the CLI from the keyring's scope,
// Planck from the namespace and application it is deploying — and a divergence
// stores a secret nothing will ever fetch.
func TestSecretKeyMatchesWhatPlanckHandsTheApplication(t *testing.T) {
	const ns, app = "my-platform", "api"

	rendered, err := translate.Render(translate.Config{
		Manifest: parser.Manifest{
			Name: ns,
			Apps: []parser.App{{Name: app, Containerfile: "./Containerfile"}},
		},
		Images:            map[string]string{app: "reg/api@sha256:" + strings.Repeat("a", 64)},
		Credentials:       map[string]string{app: "cred"},
		StorageServerName: "p.datasphered.farcast",
		StorageCAPEM:      []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"),
		Storage: map[string]translate.AppStorage{app: {
			CertPEM: []byte("c"), KeyPEM: []byte("k"),
			Scope:         mustAppScopeName(t, ns, app),
			SecretsPrefix: datasphere.AppSecretsPrefix(ns, app),
		}},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	const want = "FARCAST_SECRETS_PREFIX: "
	line := ""
	for _, l := range strings.Split(string(rendered), "\n") {
		if strings.Contains(l, want) {
			line = strings.TrimSpace(strings.SplitN(l, want, 2)[1])
			break
		}
	}
	if line == "" {
		t.Fatal("Planck rendered no secrets prefix")
	}

	// The CLI's key comes from the scope the keyring actually holds, which is
	// the material that encrypts the object.
	scope, err := datasphere.NewAppScope(ns, app)
	if err != nil {
		t.Fatal(err)
	}
	key, err := secretKey(scope, "DB_PASSWORD")
	if err != nil {
		t.Fatalf("secretKey: %v", err)
	}
	if got := line + "DB_PASSWORD"; got != key {
		t.Errorf("the application reads %q and the CLI writes %q", got, key)
	}
}

func mustAppScopeName(t *testing.T, ns, app string) string {
	t.Helper()
	name, err := datasphere.AppScopeName(ns, app)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

// A trailing newline is the shell's, not the operator's: `echo x |` appends
// one and it would become part of the credential.
func TestSecretSetTrimsTheShellsNewline(t *testing.T) {
	env, out, _, _ := secretEnv(t, output.ModeHuman, "hunter2\n")
	if err := setSecret(t, env, []string{"prod", "apps/api", "TOKEN"}, &secretSetCommand{}); err != nil {
		t.Fatalf("secret set: %v", err)
	}
	if got := readStored(t, dataSession(t, env), "app/apps/api/secrets/TOKEN"); got != "hunter2" {
		t.Errorf("stored %q, want the newline removed", got)
	}
	// Reported, because a silent edit of a credential is worse than either
	// choice made loudly.
	if !strings.Contains(out.String(), "trailing newline") {
		t.Errorf("the removal was not reported:\n%s", out)
	}

	env, _, _, _ = secretEnv(t, output.ModeHuman, "hunter2\n")
	if err := setSecret(t, env, []string{"prod", "apps/api", "TOKEN"}, &secretSetCommand{raw: true}); err != nil {
		t.Fatalf("secret set --raw: %v", err)
	}
	if got := readStored(t, dataSession(t, env), "app/apps/api/secrets/TOKEN"); got != "hunter2\n" {
		t.Errorf("--raw stored %q, want the newline kept", got)
	}
}

// There is no --value flag, and there must never be one: a value on the
// command line is visible to every process on the machine while the command
// runs, and it lands in shell history.
func TestSecretSetTakesNoValueFlag(t *testing.T) {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	(&secretSetCommand{}).SetFlags(fs)
	for _, name := range []string{"value", "from-literal", "secret", "data"} {
		if fs.Lookup(name) != nil {
			t.Errorf("secret set registered --%s; a value on argv is world-readable while the command runs", name)
		}
	}
}

func TestSecretSetRefusals(t *testing.T) {
	t.Run("an empty value", func(t *testing.T) {
		env, _, _, _ := secretEnv(t, output.ModeHuman, "")
		err := setSecret(t, env, []string{"prod", "apps/api", "TOKEN"}, &secretSetCommand{})
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Errorf("err = %v, want a refusal naming the empty value", err)
		}
	})

	t.Run("something the size of a file", func(t *testing.T) {
		env, _, _, _ := secretEnv(t, output.ModeHuman, strings.Repeat("x", maxSecretBytes+1))
		err := setSecret(t, env, []string{"prod", "apps/api", "TOKEN"}, &secretSetCommand{})
		if err == nil || !strings.Contains(err.Error(), "at most") {
			t.Errorf("err = %v, want the size cap", err)
		}
		// Truncating would be the worst outcome of the three.
		if err == nil {
			t.Fatal("oversize value was accepted")
		}
	})

	t.Run("a name that would leave the subtree", func(t *testing.T) {
		for _, name := range []string{"../../master/key", "a/b", ".hidden", ""} {
			env, _, _, _ := secretEnv(t, output.ModeHuman, "v")
			if err := setSecret(t, env, []string{"prod", "apps/api", name}, &secretSetCommand{}); err == nil {
				t.Errorf("secret set accepted the name %q", name)
			}
		}
	})

	t.Run("an application name no manifest could carry", func(t *testing.T) {
		for _, app := range []string{"apps/API", "apps/1api", "api", "", "apps/"} {
			env, _, _, _ := secretEnv(t, output.ModeHuman, "v")
			if err := setSecret(t, env, []string{"prod", app, "TOKEN"}, &secretSetCommand{}); err == nil {
				t.Errorf("secret set accepted the application name %q", app)
			}
		}
	})

	t.Run("replacing without --force", func(t *testing.T) {
		env, _, _, _ := secretEnv(t, output.ModeHuman, "first")
		if err := setSecret(t, env, []string{"prod", "apps/api", "TOKEN"}, &secretSetCommand{}); err != nil {
			t.Fatalf("secret set: %v", err)
		}
		env.In = strings.NewReader("second")
		err := setSecret(t, env, []string{"prod", "apps/api", "TOKEN"}, &secretSetCommand{})
		if err == nil || !strings.Contains(err.Error(), "--force") {
			t.Errorf("err = %v, want a refusal naming --force", err)
		}
		if got := readStored(t, dataSession(t, env), "app/apps/api/secrets/TOKEN"); got != "first" {
			t.Errorf("the refused write changed the value to %q", got)
		}

		env.In = strings.NewReader("second")
		if err := setSecret(t, env, []string{"prod", "apps/api", "TOKEN"}, &secretSetCommand{force: true}); err != nil {
			t.Fatalf("secret set --force: %v", err)
		}
		if got := readStored(t, dataSession(t, env), "app/apps/api/secrets/TOKEN"); got != "second" {
			t.Errorf("--force stored %q, want second", got)
		}
	})
}

func TestSecretLsNamesOnly(t *testing.T) {
	env, out, _, _ := secretEnv(t, output.ModeHuman, "hunter2")
	if err := setSecret(t, env, []string{"prod", "apps/api", "DB_PASSWORD"}, &secretSetCommand{}); err != nil {
		t.Fatalf("secret set: %v", err)
	}
	env.In = strings.NewReader("s3cret")
	if err := setSecret(t, env, []string{"prod", "apps/web", "SESSION_KEY"}, &secretSetCommand{}); err != nil {
		t.Fatalf("secret set: %v", err)
	}
	out.Reset()

	if err := (&secretLsCommand{}).Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("secret ls: %v", err)
	}
	listing := out.String()
	for _, want := range []string{"api", "DB_PASSWORD", "web", "SESSION_KEY"} {
		if !strings.Contains(listing, want) {
			t.Errorf("the listing omits %q:\n%s", want, listing)
		}
	}
	for _, value := range []string{"hunter2", "s3cret"} {
		if strings.Contains(listing, value) {
			t.Errorf("the listing printed a value:\n%s", listing)
		}
	}

	out.Reset()
	if err := (&secretLsCommand{}).Run(context.Background(), env, []string{"prod", "apps/api"}); err != nil {
		t.Fatalf("secret ls api: %v", err)
	}
	if scoped := out.String(); strings.Contains(scoped, "SESSION_KEY") {
		t.Errorf("listing one application reported another's:\n%s", scoped)
	}
}

func TestSecretRm(t *testing.T) {
	env, out, _, _ := secretEnv(t, output.ModeHuman, "hunter2")
	if err := setSecret(t, env, []string{"prod", "apps/api", "TOKEN"}, &secretSetCommand{}); err != nil {
		t.Fatalf("secret set: %v", err)
	}
	out.Reset()

	// Non-interactive without --yes is a refusal that SAYS SO, not a prompt
	// nobody can answer. The distinction matters: reading a confirmation from
	// a closed stdin also fails, and an operator handed that error learns
	// nothing about what to do next.
	err := (&secretRmCommand{}).Run(context.Background(), env, []string{"prod", "apps/api", "TOKEN"})
	if err == nil {
		t.Fatal("secret rm deleted without confirmation")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("err = %v, want a refusal naming --yes", err)
	}
	if got := readStored(t, dataSession(t, env), "app/apps/api/secrets/TOKEN"); got != "hunter2" {
		t.Errorf("the refused delete removed the value (%q)", got)
	}

	if err := (&secretRmCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod", "apps/api", "TOKEN"}); err != nil {
		t.Fatalf("secret rm -y: %v", err)
	}
	if keys := storedKeys(t, dataSession(t, env), "app/apps/api/secrets/"); len(keys) != 0 {
		t.Errorf("the secret survived the delete: %v", keys)
	}

	// A name that is not there is reported. Silent success would let an
	// operator believe they had revoked a credential that is still live.
	err = (&secretRmCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod", "apps/api", "TOKEN"})
	if err == nil || !strings.Contains(err.Error(), "no secret named") {
		t.Errorf("err = %v, want a report that there is no such secret", err)
	}
}

// A secret belongs to one application in one namespace, and the command says
// so: the same manifest deployed twice is two applications with two scopes,
// and a bare name could not tell them apart.
func TestSecretRequiresANamespacedApplication(t *testing.T) {
	env, _, _, _ := secretEnv(t, output.ModeHuman, "hunter2")
	for _, bad := range []string{"api", "apps/", "/api", "apps/API"} {
		if err := setSecret(t, env, []string{"prod", bad, "TOKEN"}, &secretSetCommand{}); err == nil {
			t.Errorf("secret set accepted %q as an application", bad)
		}
	}

	// A bare application name is the plausible mistake — it is what the
	// command took until decision 5 — so its refusal shows the form wanted
	// rather than complaining about a name that looks perfectly valid.
	err := setSecret(t, env, []string{"prod", "api", "TOKEN"}, &secretSetCommand{})
	if err == nil {
		t.Fatal("secret set accepted a bare application name")
	}
	for _, want := range []string{"<namespace>/<application>", "api"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not show %q: %v", want, err)
		}
	}
}

// A scope is minted when the application is deployed. A secret for one that
// was never deployed would sit under keys nothing holds — readable by the
// operator, invisible to everyone else, and wrong exactly when relied on.
func TestSecretRefusesAnUndeployedApplication(t *testing.T) {
	env, _, _, _ := secretEnv(t, output.ModeHuman, "hunter2")
	err := setSecret(t, env, []string{"prod", "apps/never-deployed", "TOKEN"}, &secretSetCommand{})
	if err == nil {
		t.Fatal("secret set stored a secret for an application with no scope")
	}
	for _, want := range []string{"no storage scope", "farcast run"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// Each application's secrets are inside its own scope, so a listing asks each
// scope in turn and attributes what it finds.
func TestSecretLsSpansEveryApplicationScope(t *testing.T) {
	env, out, _, _ := secretEnv(t, output.ModeHuman, "hunter2")
	if err := setSecret(t, env, []string{"prod", "apps/api", "DB_PASSWORD"}, &secretSetCommand{}); err != nil {
		t.Fatal(err)
	}
	env.In = strings.NewReader("s3cret")
	if err := setSecret(t, env, []string{"prod", "apps/web", "SESSION_KEY"}, &secretSetCommand{}); err != nil {
		t.Fatal(err)
	}
	out.Reset()

	if err := (&secretLsCommand{}).Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("secret ls: %v", err)
	}
	listing := out.String()
	for _, want := range []string{"apps/api", "DB_PASSWORD", "apps/web", "SESSION_KEY"} {
		if !strings.Contains(listing, want) {
			t.Errorf("the listing omits %q:\n%s", want, listing)
		}
	}
	for _, value := range []string{"hunter2", "s3cret"} {
		if strings.Contains(listing, value) {
			t.Errorf("the listing printed a value:\n%s", listing)
		}
	}

	// Scoped to one application, the neighbour's is absent.
	out.Reset()
	if err := (&secretLsCommand{}).Run(context.Background(), env, []string{"prod", "apps/api"}); err != nil {
		t.Fatalf("secret ls apps/api: %v", err)
	}
	if scoped := out.String(); strings.Contains(scoped, "SESSION_KEY") {
		t.Errorf("listing one application reported another's:\n%s", scoped)
	}
}

// The stored key lives inside the application's own scope, so the path carries
// no second copy of the application's name.
func TestSecretKeyLivesInsideTheApplicationsScope(t *testing.T) {
	env, _, _, _ := secretEnv(t, output.ModeHuman, "hunter2")
	if err := setSecret(t, env, []string{"prod", "apps/api", "DB_PASSWORD"}, &secretSetCommand{}); err != nil {
		t.Fatal(err)
	}
	session := dataSession(t, env)
	if got := readStored(t, session, "app/apps/api/secrets/DB_PASSWORD"); got != "hunter2" {
		t.Errorf("stored value = %q", got)
	}
	// And it routes to the application's scope rather than to master.
	store, err := session.StoreFor("app/apps/api/secrets/DB_PASSWORD")
	if err != nil {
		t.Fatal(err)
	}
	if store == session.Store {
		t.Error("a secret was written into the master key space")
	}
}
