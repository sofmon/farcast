package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// The reader certificate's lifetime in days, `reader init --days N` (design
// §7.2): 365 by default, from 1 to 3650, the bounds kube.NewReaderKey keeps.
const (
	readerDefaultDays = 365
	readerMinDays     = 1
	readerMaxDays     = 3650
)

// The two kinds of script `reader init` prints, as its JSON names them.
const (
	readerScriptInit   = "init"
	readerScriptRotate = "rotate"
)

// The refusals of a certificate that is not the one the script may carry
// (design §7.2, "The certificate is rendered only from a parsed one").
const (
	msgReaderCertNotOurs     = "instances/%s/reader.crt is not the certificate of this instance's reader key; delete instances/%s/reader.key and reader.crt, then run 'farcast reader init %s' again"
	msgNextReaderCertNotOurs = "instances/%s/reader.crt.next is not the certificate of this instance's next reader key; run 'farcast reader init %s --rotate' again"
)

// readerInitCommand makes the reader's key on this machine and prints the
// script the human pastes into Cloud Shell to upload its certificate. It is
// local only: it writes nothing remote and needs no plan (design §7.2).
type readerInitCommand struct {
	rotate bool
	days   daysFlag
}

// daysFlag is --days: an int that knows whether it was given, so init can say
// when it made no key and the lifetime asked for went unused.
type daysFlag struct {
	set bool
	n   int
}

func (d *daysFlag) String() string {
	if d == nil || !d.set {
		return strconv.Itoa(readerDefaultDays)
	}
	return strconv.Itoa(d.n)
}

func (d *daysFlag) Set(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("%q is not a whole number of days", s)
	}
	d.set, d.n = true, n
	return nil
}

func (d *daysFlag) value() int {
	if !d.set {
		return readerDefaultDays
	}
	return d.n
}

func (*readerInitCommand) Name() string { return "init" }
func (*readerInitCommand) Synopsis() string {
	return "Make the reader's key and print the Cloud Shell script that uploads it"
}

func (*readerInitCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast reader init <instance> [--rotate] [--days N]

Make the instance's reader key on this machine, an RSA-2048 key in
instances/<instance>/reader.key (0600), with a self-signed certificate whose
subject is CN=unused, and print the script that uploads that certificate.

Paste the script into Cloud Shell as an Owner of the instance's project. It
runs in a child shell, holds only the public certificate, and:
  - stops, changing nothing, if an organization policy blocks
    service-account key upload (iam.disableServiceAccountKeyUpload or
    iam.managed.disableServiceAccountKeyUpload);
  - creates the account farcast-reader-<8 hex>, unless it exists;
  - grants it roles/container.clusterViewer on the project;
  - uploads the certificate, and prints the key id to record with
    'farcast reader record <instance> --key-id <id>'.

Run again before the key is recorded, it makes no new key and prints the
same script. Once a key is recorded it refuses: --rotate makes a new key,
in reader.key.next, and prints a script that only uploads it. Reads keep
using the old key until 'farcast reader record' is given the new id.

--days N is the certificate's lifetime, from 1 to 3650 days, 365 by
default. The key expires with it, and --rotate is the remedy. Where the
organization policy iam.serviceAccountKeyExpiryHours is enforced, the
uploaded key must expire within it: pass a --days no greater than its days
(at most 90). At 1h or 8h no reader key can be made.

With --output json it prints {"instance","email","script","script_sha256",
"script_kind"}, where script_kind is init or rotate.`)
}

func (c *readerInitCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.rotate, "rotate", false, "make a new key beside the recorded one and print the script that uploads it")
	fs.Var(&c.days, "days", "the certificate's lifetime in days, from 1 to 3650 (default 365)")
}

func (c *readerInitCommand) Run(_ context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("reader init takes one instance name")
	}
	name := args[0]
	days := c.days.value()
	if days < readerMinDays || days > readerMaxDays {
		return usagef("--days must be from %d to %d; got %d", readerMinDays, readerMaxDays, days)
	}
	meta, err := loadReaderRecord(env.ConfigDir, name)
	if err != nil {
		return err
	}
	_, email, _, err := checkedReader(meta)
	if err != nil {
		return err
	}
	now := time.Now

	if c.rotate {
		if meta.Reader == nil {
			return fmt.Errorf("instance %q has no reader identity to rotate; run 'farcast reader init %s'", name, name)
		}
		if meta.Reader.KeyID == "" {
			return fmt.Errorf("instance %q's reader key is not yet uploaded, so there is nothing to rotate; 'farcast reader init %s' prints its script again", name, name)
		}
		// Beside the key in use, which every read keeps using until
		// 'reader record' is given the new key's id.
		keyPEM, certPEM, err := newReaderKey(now(), days)
		if err != nil {
			return err
		}
		if err := env.ConfigDir.SaveNextReaderKey(name, keyPEM, certPEM); err != nil {
			return err
		}
		return printReaderScript(env, name, meta, readerScriptRotate)
	}

	switch {
	case meta.Reader == nil:
		if err := makeReaderKey(env.ConfigDir, name, now(), days); err != nil {
			return err
		}
		if _, err := env.ConfigDir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
			if m.Reader != nil {
				return fmt.Errorf("instance %q's reader was recorded by another command while this one ran; run 'farcast reader init %s' again", name, name)
			}
			m.Reader = &config.Reader{Email: email}
			m.UpdatedAt = now().UTC()
			return nil
		}); err != nil {
			return fmt.Errorf("record instance %q's reader: %w", name, err)
		}
	case meta.Reader.KeyID != "":
		return fmt.Errorf("instance %q already has a reader (%s); --rotate makes a new key and prints the script that uploads it", name, email)
	default:
		// Recorded, and not yet uploaded. A key that exists may be the one
		// the human's paste uploaded and has not recorded, so it is kept and
		// its script printed again. A missing one was never uploaded.
		held, err := env.ConfigDir.ReaderKeyExists(name)
		if err != nil {
			return err
		}
		if !held {
			if err := makeReaderKey(env.ConfigDir, name, now(), days); err != nil {
				return err
			}
		} else if c.days.set {
			fprintf(env.Err, "Note: instances/%s/reader.key exists and no key id is recorded for it, so no key was made and --days was not used. "+
				"To make one with another lifetime, delete instances/%s/reader.key and reader.crt first.\n", name, name)
		}
	}
	return printReaderScript(env, name, meta, readerScriptInit)
}

// newReaderKey makes a reader key whose certificate is valid from an hour
// before now, so a clock a little behind Google's still uploads it, for days
// days (design §7.2 step 4).
func newReaderKey(now time.Time, days int) (keyPEM, certPEM []byte, err error) {
	return kube.NewReaderKey(rand.Reader, now.Add(-time.Hour), days)
}

// makeReaderKey makes the reader's key and writes it as reader.key and
// reader.crt.
func makeReaderKey(dir config.Dir, name string, now time.Time, days int) error {
	keyPEM, certPEM, err := newReaderKey(now, days)
	if err != nil {
		return err
	}
	return dir.SaveReaderKey(name, keyPEM, certPEM)
}

// loadReaderRecord loads an instance's record for a reader command, and
// refuses one whose recorded name is not the instance's: every file the
// command touches is under the name given, and every line it prints is
// rendered from the recorded one, which checkedReader checks.
func loadReaderRecord(dir config.Dir, name string) (*config.InstanceMetadata, error) {
	meta, err := dir.LoadInstanceMetadata(name)
	if err != nil {
		return nil, fmt.Errorf("load instance %q: %w", name, err)
	}
	if _, _, _, err := checkedReader(meta); err != nil {
		return nil, err
	}
	if meta.Name != name {
		return nil, fmt.Errorf("instance %q's record names the instance %q; farcast renders nothing from it", name, meta.Name)
	}
	return meta, nil
}

// readerScriptResult is what `reader init` prints: the script on stdout, and
// with --output json the document {"instance","email","script",
// "script_sha256","script_kind"}.
type readerScriptResult struct {
	Instance     string `json:"instance"`
	Email        string `json:"email"`
	Script       string `json:"script"`
	ScriptSHA256 string `json:"script_sha256"`
	ScriptKind   string `json:"script_kind"`
}

// Human writes the script and nothing else, so stdout is exactly what is
// pasted and what the stderr line's digest covers.
func (r readerScriptResult) Human(w io.Writer) error {
	_, err := io.WriteString(w, r.Script)
	return err
}

// printReaderScript renders the init or rotate script and prints it: in human
// mode preceded on stderr by the line that names its digest.
func printReaderScript(env *Env, name string, meta *config.InstanceMetadata, kind string) error {
	script, email, err := renderReaderScript(env.ConfigDir, name, meta, kind)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(script)
	digest := hex.EncodeToString(sum[:])
	if env.Printer.Mode == output.ModeHuman {
		fprintf(env.Err, "Paste this into Cloud Shell as a project Owner (sha256 %s). It holds only the public certificate.\n", digest)
	}
	return env.Printer.Print(readerScriptResult{
		Instance: meta.Name, Email: email, Script: string(script), ScriptSHA256: digest, ScriptKind: kind,
	})
}

// renderReaderScript renders the init script from reader.crt, or the rotate
// script from reader.crt.next. It checks the record again here, at render
// time, and takes every substituted value from checkedReader, never from the
// record's bytes. The certificate it carries is re-encoded from a parsed
// one (readerCertificate), so nothing else in the file reaches the script.
func renderReaderScript(dir config.Dir, name string, meta *config.InstanceMetadata, kind string) (script []byte, email string, err error) {
	project, email, _, err := checkedReader(meta)
	if err != nil {
		return nil, "", err
	}
	var (
		certFile, keyFile []byte
		certErr, keyErr   error
		notOurs           string
	)
	switch kind {
	case readerScriptInit:
		certFile, certErr = dir.LoadReaderCert(name)
		keyFile, keyErr = dir.LoadReaderKey(name)
		notOurs = fmt.Sprintf(msgReaderCertNotOurs, name, name, name)
	case readerScriptRotate:
		certFile, certErr = dir.LoadNextReaderCert(name)
		keyFile, keyErr = dir.LoadNextReaderKey(name)
		notOurs = fmt.Sprintf(msgNextReaderCertNotOurs, name, name)
	default:
		return nil, "", fmt.Errorf("cli: %q is not a reader script", kind)
	}
	for _, e := range []error{certErr, keyErr} {
		if e != nil && !errors.Is(e, fs.ErrNotExist) {
			return nil, "", e
		}
	}
	if certErr != nil || keyErr != nil {
		return nil, "", errors.New(notOurs)
	}
	cert, ok := readerCertificate(certFile, keyFile)
	if !ok {
		return nil, "", errors.New(notOurs)
	}
	if kind == readerScriptRotate {
		return readerRotateScript(meta.Name, project, email, cert), email, nil
	}
	return readerInitScript(meta.Name, project, readerName(meta.Name), cert), email, nil
}

// readerCertificate is the certificate a reader script may carry: certFile
// must be exactly one CERTIFICATE block with no headers and nothing after it,
// which parses, holds an RSA-2048 public key equal to keyFile's, and whose
// subject is exactly CN=unused. What it returns is that certificate
// re-encoded from its DER, so text before the block, which pem.Decode skips,
// never reaches the script, and no line of the file can end a here-document
// early in an Owner's shell.
func readerCertificate(certFile, keyFile []byte) ([]byte, bool) {
	block, rest := pem.Decode(certFile)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() != 2048 {
		return nil, false
	}
	key, ok := readerPrivateKey(keyFile)
	if !ok || !key.PublicKey.Equal(pub) {
		return nil, false
	}
	if !bytes.Equal(cert.RawSubject, cnUnused) {
		return nil, false
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), true
}

// readerPrivateKey is the RSA key in a reader.key: one PKCS#8 PRIVATE KEY
// block, as kube.NewReaderKey writes it.
func readerPrivateKey(keyFile []byte) (*rsa.PrivateKey, bool) {
	block, _ := pem.Decode(keyFile)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, false
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, false
	}
	key, ok := k.(*rsa.PrivateKey)
	return key, ok
}

// cnUnused is the DER of the one subject a reader certificate may have,
// CN=unused, encoded as crypto/x509 encodes a template's subject.
var cnUnused = func() []byte {
	b, err := asn1.Marshal(pkix.Name{CommonName: "unused"}.ToRDNSequence())
	if err != nil {
		panic(err)
	}
	return b
}()

// readerRetry is the scripts' retry function: Google advises retrying a new
// service account's first uses with backoff, and this waits 8, 16, 24, 32 and
// 40 seconds, about two minutes in all.
const readerRetry = `retry() {
  n=0
  until "$@"; do
    n=$((n + 1))
    if [ "$n" -ge 6 ]; then
      echo "FarCast: gave up after 6 tries: $*" >&2
      return 1
    fi
    sleep $((n * 8))
  done
}
`

// readerInitTemplate is the init script exactly as design §7.2 prints it.
// {{NAME}}, {{PROJECT}} and {{SA}} are replaced by checked values, which hold
// only lowercase letters, digits and hyphens, and {{CERT}} by a re-encoded
// certificate.
const readerInitTemplate = `sh -s <<'FARCAST_READER'
# FarCast: the read-only identity for instance {{NAME}} (ADR 0023 M2).
# Public material only. Run once, as an Owner of project {{PROJECT}}.
set -eu
PROJECT='{{PROJECT}}'
SA='{{SA}}'
EMAIL="$SA@$PROJECT.iam.gserviceaccount.com"
` + readerRetry + `if [ "$(gcloud resource-manager org-policies describe iam.disableServiceAccountKeyUpload \
    --effective --project "$PROJECT" --format 'value(booleanPolicy.enforced)' 2>/dev/null)" = True ]; then
  echo "FarCast: project $PROJECT blocks service-account key upload (organization policy iam.disableServiceAccountKeyUpload); its reader cannot be set up until an organization administrator allows it. Nothing was changed." >&2
  exit 1
fi
if [ "$(gcloud org-policies describe iam.managed.disableServiceAccountKeyUpload \
    --effective --project "$PROJECT" --format 'value(spec.rules[0].enforce)' 2>/dev/null)" = True ]; then
  echo "FarCast: project $PROJECT blocks service-account key upload (organization policy iam.managed.disableServiceAccountKeyUpload); its reader cannot be set up until an organization administrator allows it. Nothing was changed." >&2
  exit 1
fi
gcloud iam service-accounts describe "$EMAIL" --project "$PROJECT" >/dev/null 2>&1 ||
  gcloud iam service-accounts create "$SA" --project "$PROJECT" \
    --display-name 'FarCast reader for {{NAME}}'
retry gcloud projects add-iam-policy-binding "$PROJECT" --condition=None \
  --member "serviceAccount:$EMAIL" --role 'roles/container.clusterViewer' >/dev/null
CERT="$(mktemp)"
cat > "$CERT" <<'FARCAST_CERT'
{{CERT}}FARCAST_CERT
KEY_ID=$(retry gcloud iam service-accounts keys upload "$CERT" \
  --iam-account="$EMAIL" --project "$PROJECT" --format 'value(name.basename())') || {
  rm -f "$CERT"
  echo "FarCast: the key upload was refused. The account $EMAIL and its clusterViewer binding stay; remove them with:" >&2
  echo "  gcloud projects remove-iam-policy-binding '$PROJECT' --condition=None --member 'serviceAccount:$EMAIL' --role 'roles/container.clusterViewer'" >&2
  echo "  gcloud iam service-accounts delete '$EMAIL' --project '$PROJECT' --quiet" >&2
  exit 1
}
rm -f "$CERT"
echo
echo "Now run, on the machine that holds this instance:"
echo "  farcast reader record {{NAME}} --key-id $KEY_ID"
FARCAST_READER
`

// readerRotateTemplate is the rotate script exactly as design §7.2 prints it.
// It creates nothing and grants nothing. {{EMAIL}} is checkedReader's email.
const readerRotateTemplate = `sh -s <<'FARCAST_READER'
# FarCast: a new key for the read-only identity of instance {{NAME}} (ADR 0023 M2).
# Public material only. It creates nothing and grants nothing.
set -eu
PROJECT='{{PROJECT}}'
EMAIL='{{EMAIL}}'
` + readerRetry + `CERT="$(mktemp)"
cat > "$CERT" <<'FARCAST_CERT'
{{CERT}}FARCAST_CERT
KEY_ID=$(retry gcloud iam service-accounts keys upload "$CERT" \
  --iam-account="$EMAIL" --project "$PROJECT" --format 'value(name.basename())')
rm -f "$CERT"
echo
echo "Now run, on the machine that holds this instance:"
echo "  farcast reader record {{NAME}} --key-id $KEY_ID"
FARCAST_READER
`

// readerInitScript renders the init script. name, project and sa must come
// from checkedReader; certPEM from readerCertificate, which ends it with a
// newline.
func readerInitScript(name, project, sa string, certPEM []byte) []byte {
	return []byte(strings.NewReplacer(
		"{{NAME}}", name, "{{PROJECT}}", project, "{{SA}}", sa, "{{CERT}}", string(certPEM),
	).Replace(readerInitTemplate))
}

// readerRotateScript renders the rotate script, from the same checked values.
func readerRotateScript(name, project, email string, certPEM []byte) []byte {
	return []byte(strings.NewReplacer(
		"{{NAME}}", name, "{{PROJECT}}", project, "{{EMAIL}}", email, "{{CERT}}", string(certPEM),
	).Replace(readerRotateTemplate))
}
