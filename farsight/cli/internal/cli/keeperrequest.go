package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/keeper"
	"github.com/sofmon/farcast/fatline/identity"
)

// ------------------------------------------------------------ request

// keeperRequestCommand runs on the keeper DEVICE. It makes the device's key
// where install's rules hold, and writes the PKCS#10 request that carries the
// key's public half to the operator (ADR 0020 decision 3). FarCast never
// sends the key anywhere; the request holds no secret.
type keeperRequestCommand struct {
	out        string
	replace    bool
	acceptRisk bool
	// now is the clock the record is stamped with; nil is time.Now.
	now func() time.Time
}

func (*keeperRequestCommand) Name() string { return "request" }
func (*keeperRequestCommand) Synopsis() string {
	return "Make this device a key, and the request that enrols it"
}

func (*keeperRequestCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast keeper request <instance> --out <path> [--replace] [--accept-backup-risk]

Run on the keeper DEVICE, first. It makes this device a key for the instance,
and writes the request that enrols it.

The key is generated here, in this device's keeper directory, under the rules
'keeper install' applies — a synced folder is refused, the exclusion from the
backup pipeline is read back, the directory is 0700 and the key 0600 — and
FarCast never sends it anywhere: no request, packet or command carries it. It
is a file, not bound to hardware, and with --accept-backup-risk a backup may
still copy it. The request carries only the key's public half: it holds no
secret. Carry it to the machine that holds the instance's CA key.

It prints the key's fingerprint. The operator compares it before enrolling, so
read it to them from this screen, or carry it separately from the request:

  farcast keeper enroll <instance> <device> --request <path> --key-sha256 <fingerprint> ...

Then install the packet that comes back here with 'farcast keeper install'.

Flags:
      --out <path>             Where to write the request (never overwritten)
      --replace                Discard a request pending here and make a new one
      --accept-backup-risk     Make the key even though the exclusion is unverifiable

A device makes a new key for each instance and each request. One request is
pending per instance at a time: --replace discards it, and a packet issued
for the discarded one is then refused by install.`)
}

func (c *keeperRequestCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.out, "out", "", "where to write the request")
	fs.BoolVar(&c.replace, "replace", false, "discard a pending request and make a new one")
	fs.BoolVar(&c.acceptRisk, "accept-backup-risk", false, "make the key without a verifiable backup exclusion")
}

func (c *keeperRequestCommand) Run(_ context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("keeper request takes one instance argument")
	}
	name := args[0]
	if err := keeper.ValidateInstance(name); err != nil {
		return err
	}
	if c.out == "" {
		return usagef("--out is required: the request is a file you carry to the operator's machine")
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}

	// The request file is claimed before any key exists: a path that is
	// already taken is refused with nothing generated, and with --replace a
	// bad --out cannot discard the pending request before the command fails.
	file, err := os.OpenFile(c.out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; refusing to overwrite it", c.out)
		}
		return err
	}
	abandon := func() {
		_ = file.Close()
		_ = os.Remove(c.out)
	}

	dir := env.ConfigDir.KeeperDir(name)
	replaced := false
	if c.replace {
		if pending, perr := keeper.PendingRequest(dir); perr == nil && pending != nil {
			replaced = true
		}
	}
	rec, gen, err := keeper.NewRequest(dir, name, c.acceptRisk, c.replace, now())
	if err != nil {
		abandon()
		if errors.Is(err, keeper.ErrPendingRequest) {
			return fmt.Errorf("%w\nRe-run with --replace to discard it and make a new one", err)
		}
		return err
	}
	// The key is on disk; this process has no further use for it.
	clear(gen.KeyPEM)

	if _, err := file.Write(gen.RequestPEM); err != nil {
		abandon()
		// A request no file carries is one nobody can enrol, so it is not
		// left pending.
		_ = keeper.DiscardRequest(dir)
		return fmt.Errorf("writing %s: %w; nothing is pending", c.out, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(c.out)
		_ = keeper.DiscardRequest(dir)
		return fmt.Errorf("writing %s: %w; nothing is pending", c.out, err)
	}

	return env.Printer.Print(keeperRequestResult{
		Instance: name, Request: c.out, Dir: dir,
		KeySHA256: rec.KeySHA256, KeyStore: rec.KeyStore,
		BackupExcluded: rec.BackupExcluded, BackupNote: rec.BackupNote,
		Replaced: replaced, CreatedAt: rec.CreatedAt,
	})
}

type keeperRequestResult struct {
	Instance       string    `json:"instance"`
	Request        string    `json:"request"`
	Dir            string    `json:"dir"`
	KeySHA256      string    `json:"key_sha256"`
	KeyStore       string    `json:"key_store"`
	BackupExcluded bool      `json:"backup_excluded"`
	BackupNote     string    `json:"backup_note,omitempty"`
	Replaced       bool      `json:"replaced,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func (r keeperRequestResult) Human(w io.Writer) error {
	fprintf(w, "✓ this device has a new key for %q, and the request that enrols it\n", r.Instance)
	if r.Replaced {
		fprintf(w, "  replaced    the request pending here; a packet issued for it is now refused\n")
	}
	fprintf(w, "  request     %s — carry it to the operator's machine; it holds no secret\n", r.Request)
	fprintf(w, "  key         held in a file under %s (mode 0600)\n", r.Dir)
	first, second := fingerprintLines(r.KeySHA256)
	fprintf(w, "  key sha256  %s\n", first)
	fprintf(w, "              %s\n", second)
	if r.BackupExcluded {
		fprintf(w, "  backup      excluded, and the exclusion was read back\n")
	} else {
		fprintf(w, "  backup      NOT verifiably excluded — %s\n", backupNote(r.BackupNote))
		fprintf(w, "              You accepted this. Keep the directory off every backup and sync path yourself.\n")
	}
	fprintf(w, "\nThe operator compares this fingerprint before enrolling: farcast keeper enroll %s <device> --request %s "+
		"--key-sha256 %s --out <path> --passphrase-file <path>\n", r.Instance, r.Request, r.KeySHA256)
	return nil
}

// fingerprintLines is a key fingerprint as two lines of 8 groups, the way a
// person reads one aloud and compares it by eye.
func fingerprintLines(fp string) (string, string) {
	grouped := strings.Fields(identity.FormatFingerprint(fp))
	if len(grouped) != 16 {
		return fp, ""
	}
	return strings.Join(grouped[:8], " "), strings.Join(grouped[8:], " ")
}
