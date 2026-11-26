package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
)

// ADR 0024 M3b.2: config's pending store and identity paths check a name by
// config.ValidateInstanceName, its own copy of the rule 'farcast install'
// names instances by. The two are held equal here, as keeper's is
// (TestKeeperInstanceRuleIsInstallsRule), rather than by making config import
// cli: every name one accepts the other accepts, every name one refuses the
// other refuses, and the longest name is the same. The names are derived, not
// listed, so a range one character wider in either rule is seen: every byte
// value as a whole name, first, in the middle and last, and every length up
// to two past the longest, of letters and of a hyphenated name.
func TestConfigInstanceRuleIsInstallsRule(t *testing.T) {
	if config.MaxInstanceName != maxInstanceName {
		t.Errorf("config.MaxInstanceName = %d; install allows %d", config.MaxInstanceName, maxInstanceName)
	}
	names := []string{"", "prod", "farcast-reader-atlas", "a--b", "../x", "a/b", "é", "aé", "a\u200b"}
	for b := range 256 {
		c := string([]byte{byte(b)})
		names = append(names, c, c+"a", "a"+c, "a"+c+"a", "a"+c+"-a")
	}
	for n := 1; n <= maxInstanceName+2; n++ {
		names = append(names, strings.Repeat("a", n), "a"+strings.Repeat("-0", n/2)+strings.Repeat("z", n%2))
	}
	accepted := 0
	for _, n := range names {
		c, i := config.ValidateInstanceName(n), validateInstanceName(n)
		if (c == nil) != (i == nil) {
			t.Errorf("%q: config.ValidateInstanceName = %v, validateInstanceName = %v", n, c, i)
		}
		if i == nil {
			accepted++
		}
	}
	// A rule that accepted nothing, or everything, would agree with its copy
	// and prove nothing: the derived names hold both.
	if accepted == 0 || accepted == len(names) {
		t.Errorf("install's rule accepts %d of %d derived names", accepted, len(names))
	}
}

// installedBlank rewrites name's credentials.yaml with a blank key, as an
// install with Application Default Credentials wrote it.
func installedBlank(t *testing.T, dir config.Dir, name, key string) {
	t.Helper()
	if err := dir.SaveInstanceCredentials(name, &config.InstanceCredentials{Provider: "gke", ServiceAccountKey: key}); err != nil {
		t.Fatal(err)
	}
}

// ADR 0024 M3b.2: release reads the installer's key through
// config.LoadInstanceCredentials, which refuses a blank key, or one of white
// space, as config.ErrNoServiceAccountKey; release keeps its own "load
// credentials for" words around it, and deletes nothing and opens no
// provider.
func TestReleaseRefusesABlankInstallerKey(t *testing.T) {
	for _, row := range []struct{ name, key string }{{"blank", ""}, {"white space", " \n\t"}} {
		t.Run(row.name, func(t *testing.T) {
			f := &fakeProvider{}
			prov := registerFake(t, f)
			env, _, _, dir := newInstallEnv(t, output.ModeHuman)
			recordInstance(t, dir, "prod", prov)
			installedBlank(t, dir, "prod", row.key)
			err := (&releaseCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod"})
			if !errors.Is(err, config.ErrNoServiceAccountKey) || !strings.HasPrefix(err.Error(), `load credentials for "prod": `) {
				t.Errorf("release = %v; want the blank key refused under release's words", err)
			}
			if kind := kindOf(classified(err)); kind != kindCredentialMissing {
				t.Errorf("release's refusal of a blank key is kind %s; want %s, as loadInstallerKey's", kind, kindCredentialMissing)
			}
			if f.deleteCalls != 0 || len(f.regDeleted) != 0 {
				t.Errorf("a refused release deleted %d clusters and %d registries", f.deleteCalls, len(f.regDeleted))
			}
			if exists, _ := dir.InstanceExists("prod"); !exists {
				t.Error("a refused release removed the instance's record")
			}
		})
	}
}

// ADR 0024 M3b.2: the package-level ensureRegistry, which toolchain calls,
// reads the installer's key through config.LoadInstanceCredentials too, so a
// blank key is refused there under its own words, and the provider is never
// opened with it.
func TestEnsureRegistryRefusesABlankInstallerKey(t *testing.T) {
	for _, key := range []string{"", " \n\t"} {
		env, _, _, dir := newInstallEnv(t, output.ModeHuman)
		recordInstance(t, dir, "prod", "gke")
		installedBlank(t, dir, "prod", key)
		meta, err := dir.LoadInstanceMetadata("prod")
		if err != nil {
			t.Fatal(err)
		}
		opened := 0
		open := func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
			opened++
			return nil, errors.New("not reached")
		}
		access, err := ensureRegistry(context.Background(), env, "prod", meta, open)
		if access != nil || !errors.Is(err, config.ErrNoServiceAccountKey) || !strings.HasPrefix(err.Error(), `load credentials for "prod": `) {
			t.Errorf("key %q: ensureRegistry = %v, %v; want the blank key refused under its words", key, access != nil, err)
		}
		if kind := kindOf(classified(err)); kind != kindCredentialMissing {
			t.Errorf("key %q: ensureRegistry's refusal is kind %s; want %s, as loadInstallerKey's", key, kind, kindCredentialMissing)
		}
		if opened != 0 {
			t.Errorf("key %q: the provider was opened %d times with no key", key, opened)
		}
	}
}

// ADR 0024 M3b.2 (the fix round's S3): a credentials.yaml that does not
// parse is refused by release and by the package-level ensureRegistry in
// words that quote no byte of it, as loadInstallerKey's own refusal does:
// config.LoadInstanceCredentials names the file and the fault alone, where
// the YAML library's text quotes the lines around the fault, which hold the
// installer's private key. Nothing is deleted and no provider opened.
func TestCredentialsParseFaultQuotesNoKey(t *testing.T) {
	const secret = "MIIEvSECRETSECRET"
	body := "provider: gke\nservice_account_key: |\n  {\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n" + secret + "\"}\n bad: [\n"
	write := func(t *testing.T, dir config.Dir) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir.InstancePath("prod"), "credentials.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	quotes := func(err error) bool {
		return err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "PRIVATE")
	}
	for _, m := range []struct {
		label string
		mode  output.Mode
	}{{"human", output.ModeHuman}, {"json", output.ModeJSON}} {
		mode := m.mode
		t.Run("release, "+m.label, func(t *testing.T) {
			f := &fakeProvider{}
			prov := registerFake(t, f)
			env, out, errb, dir := newInstallEnv(t, mode)
			recordInstance(t, dir, "prod", prov)
			write(t, dir)
			err := (&releaseCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod"})
			if quotes(err) || !strings.HasPrefix(err.Error(), `load credentials for "prod": parse `) {
				t.Errorf("release = %v; want the fault refused, quoting none of the file", err)
			}
			if strings.Contains(out.String()+errb.String(), secret) {
				t.Error("release printed the installer key")
			}
			if f.deleteCalls != 0 || len(f.regDeleted) != 0 {
				t.Errorf("a refused release deleted %d clusters and %d registries", f.deleteCalls, len(f.regDeleted))
			}
		})
	}
	t.Run("ensureRegistry", func(t *testing.T) {
		env, _, _, dir := newInstallEnv(t, output.ModeHuman)
		recordInstance(t, dir, "prod", "gke")
		write(t, dir)
		meta, err := dir.LoadInstanceMetadata("prod")
		if err != nil {
			t.Fatal(err)
		}
		opened := 0
		open := func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
			opened++
			return nil, errors.New("not reached")
		}
		access, err := ensureRegistry(context.Background(), env, "prod", meta, open)
		if access != nil || quotes(err) || !strings.HasPrefix(err.Error(), `load credentials for "prod": parse `) {
			t.Errorf("ensureRegistry = %v, %v; want the fault refused, quoting none of the file", access != nil, err)
		}
		if opened != 0 {
			t.Errorf("the provider was opened %d times", opened)
		}
	})
	t.Run("loadInstallerKey", func(t *testing.T) {
		_, _, _, dir := newInstallEnv(t, output.ModeHuman)
		recordInstance(t, dir, "prod", "gke")
		write(t, dir)
		if _, err := loadInstallerKey(dir, "prod"); quotes(err) || !strings.Contains(err.Error(), "does not parse (a YAML syntax error at line 4") {
			t.Errorf("loadInstallerKey = %v; want its refusal, by fault and position", err)
		}
	})
}

// ADR 0024 M3b.2: the commands that load the installer's key themselves,
// here a storage read and a secret read, refuse a blank key under their own
// words, with the kind loadInstallerKey's refusal of it names,
// credential_missing, in the JSON error a script reads; never internal.
func TestBlankKeyRefusalsAreCredentialMissing(t *testing.T) {
	for _, args := range [][]string{{"storage", "ls", "prod:"}, {"secret", "ls", "prod"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			_, _, _, dir := newInstallEnv(t, output.ModeHuman)
			recordInstance(t, dir, "prod", "gke")
			installedBlank(t, dir, "prod", "")
			var out, errb bytes.Buffer
			full := append([]string{"farcast", "-o", "json", "--config", string(dir)}, args...)
			code := run(context.Background(), full, strings.NewReader(""), &out, &errb)
			var got struct {
				Error struct {
					Message string `json:"message"`
					Code    int    `json:"code"`
					Kind    string `json:"kind"`
				} `json:"error"`
			}
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatalf("%v: stdout is not a JSON error (%v)\nstdout: %s\nstderr: %s", args, err, out.String(), errb.String())
			}
			if code == 0 || got.Error.Kind != kindCredentialMissing ||
				!strings.HasPrefix(got.Error.Message, `load credentials for "prod": `) ||
				!strings.Contains(got.Error.Message, config.ErrNoServiceAccountKey.Error()) {
				t.Errorf("%v = exit %d, %+v; want the blank key refused under its words, kind %s", args, code, got.Error, kindCredentialMissing)
			}
		})
	}
}
