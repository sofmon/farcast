// Command datasphere is a thin manual harness for exercising a DataSphere
// provider and the encrypting Store against real cloud credentials — the way
// to test the storage stack before the farcast CLI wires it in (phase 3.3). It
// is NOT the user-facing CLI (that is `farcast`).
//
// Every verb that touches data goes through the full Store. There is
// deliberately no raw or plaintext bypass mode: a debug flag that ships
// plaintext to a bucket is a standing footgun aimed at the module's reason to
// exist, and it does not exist here or anywhere else.
//
// Usage:
//
//	datasphere keygen        --keys keys.yaml
//	datasphere mint-name     --instance NAME
//	datasphere validate      --provider gcs --project P --location R [--credentials key.json] [--bucket B --instance NAME]
//	datasphere ensure-bucket --provider gcs --project P --location R --instance NAME --bucket B
//	datasphere delete-bucket --provider gcs --project P --instance NAME --bucket B
//	datasphere put <key> <file>   --provider gcs ... --instance NAME --bucket B --keys keys.yaml
//	datasphere get <key> [file]   ...
//	datasphere ls  [prefix]       ...  [--tokens]
//	datasphere rm  <key>          ...
//	datasphere serve              --instance NAME --bucket B --provider gcs --project P --location R
//	                              [--listen :8443] [--status-listen :8444] [--unseal-listen :9443]
//
// Use "-" as a file operand to read from stdin or write to stdout.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sofmon/farcast/datasphere"
	_ "github.com/sofmon/farcast/datasphere/providers"
)

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

// options is the harness's whole flag surface, shared across the verbs.
type options struct {
	provider string
	project  string
	location string
	instance string
	bucket   string
	creds    string
	keys     string
	tokens   bool
}

func run(args []string, out, errw io.Writer) int {
	if len(args) < 2 {
		usage(errw)
		return 2
	}
	cmd := args[1]

	var opt options
	fs := flag.NewFlagSet("datasphere "+cmd, flag.ContinueOnError)
	fs.SetOutput(errw)
	fs.StringVar(&opt.provider, "provider", "gcs", "cloud provider")
	fs.StringVar(&opt.project, "project", "", "cloud project / account")
	fs.StringVar(&opt.location, "location", "", "region")
	fs.StringVar(&opt.instance, "instance", "", "instance name; stamped into the bucket's ownership labels")
	fs.StringVar(&opt.bucket, "bucket", "", "bucket name (mint one with `datasphere mint-name`)")
	fs.StringVar(&opt.creds, "credentials", "", "path to a credentials JSON file (optional)")
	fs.StringVar(&opt.keys, "keys", "keys.yaml", "path to the instance keyring")
	fs.BoolVar(&opt.tokens, "tokens", false, "ls: also print the opaque name each key is stored under")
	var sopt serveOptions
	serveFlags(fs, &sopt)
	if err := fs.Parse(hoistFlags(args[2:])); err != nil {
		return 2
	}
	operands := fs.Args()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if cmd != "serve" {
		// Every other verb is a one-shot operation; serve runs until it is
		// signalled, so it must not carry a deadline.
		ctx, cancel = context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
	}

	switch cmd {
	case "keygen":
		return keygen(opt, out, errw)
	case "mint-name":
		return mintName(opt, out, errw)
	case "validate":
		return validate(ctx, opt, out, errw)
	case "ensure-bucket":
		return ensureBucket(ctx, opt, out, errw)
	case "delete-bucket":
		return deleteBucket(ctx, opt, out, errw)
	case "serve":
		// The keyholder never reads a keyring from disk — that is the whole
		// point of it — so being handed one is a misunderstanding worth
		// naming rather than ignoring.
		given := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "keys" {
				given = true
			}
		})
		if given {
			return fail(errw, "datasphere: serve takes no --keys: the keyholder holds only what is pushed to it, in memory\n")
		}
		return serve(ctx, opt, sopt, out, errw)
	case "put", "get", "ls", "rm":
		return object(ctx, cmd, opt, operands, out, errw)
	default:
		usage(errw)
		return 2
	}
}

// keygen mints a keyring and writes it where nothing can be overwritten by
// accident. Losing this file is worse than losing the instance's CA key — the
// CA costs a re-mint, this costs the data — so the create is exclusive and the
// warning is not optional.
func keygen(opt options, out, errw io.Writer) int {
	if dir := filepath.Dir(opt.keys); dir != "." {
		if err := os.MkdirAll(dir, datasphere.KeysDirMode); err != nil {
			return fail(errw, "datasphere: create keyring directory: %v\n", err)
		}
	}
	file, err := os.OpenFile(opt.keys, os.O_WRONLY|os.O_CREATE|os.O_EXCL, datasphere.KeysFileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fail(errw, "datasphere: a keyring already exists at %s; refusing to overwrite it.\n%s\n", opt.keys, datasphere.KeyLossWarning)
		}
		return fail(errw, "datasphere: create keyring: %v\n", err)
	}
	defer func() { _ = file.Close() }()

	keyring, err := datasphere.NewKeyring()
	if err != nil {
		return fail(errw, "%v\n", err)
	}
	data, err := keyring.Marshal()
	if err != nil {
		return fail(errw, "%v\n", err)
	}
	if _, err := file.Write(data); err != nil {
		return fail(errw, "datasphere: write keyring: %v\n", err)
	}
	emit(out, "wrote a new keyring to %s (mode %04o)\n", opt.keys, datasphere.KeysFileMode)
	emit(out, "WARNING: %s\n", datasphere.KeyLossWarning)
	emit(out, "Back it up the way you back up the instance's CA key: copy the instance directory offline.\n")
	return 0
}

// mintName offers a bucket name. The harness has no local record to write it
// into, so the operator is the record: note the name down before creating
// anything with it, because the random suffix exists nowhere else.
func mintName(opt options, out, errw io.Writer) int {
	if opt.instance == "" {
		return fail(errw, "datasphere: --instance is required\n")
	}
	name, err := datasphere.MintBucketName(opt.instance)
	if err != nil {
		return fail(errw, "%v\n", err)
	}
	emit(out, "%s\n", name)
	emit(errw, "Record this name before creating the bucket: its random suffix exists nowhere else, and an unrecorded bucket is billable storage nobody is watching.\n")
	return 0
}

func validate(ctx context.Context, opt options, out, errw io.Writer) int {
	provider, code := openProvider(opt, errw)
	if provider == nil {
		return code
	}
	ref := datasphere.BucketRef{Name: opt.bucket, Location: opt.location, Instance: opt.instance}
	if err := provider.Validate(ctx, ref); err != nil {
		return fail(errw, "%v\n", err)
	}
	if opt.bucket == "" {
		emit(out, "credentials OK\n")
	} else {
		emit(out, "credentials OK; bucket %q belongs to instance %q\n", opt.bucket, opt.instance)
	}
	return 0
}

func ensureBucket(ctx context.Context, opt options, out, errw io.Writer) int {
	provider, code := openProvider(opt, errw)
	if provider == nil {
		return code
	}
	spec := datasphere.BucketSpec{Name: opt.bucket, Instance: opt.instance, Location: opt.location}
	bucket, err := provider.EnsureBucket(ctx, spec)
	if err != nil && !errors.Is(err, datasphere.ErrRetentionForced) {
		if errors.Is(err, datasphere.ErrNotOwned) {
			fail(errw, "%v\n", err)
			return fail(errw, "datasphere: that name is taken by a bucket this instance does not own. Mint a new one with `datasphere mint-name --instance %s`, record it, and retry.\n", opt.instance)
		}
		return fail(errw, "%v\n", err)
	}
	if err != nil {
		warn(errw, err)
	}
	if bucket == nil {
		return fail(errw, "datasphere: the provider reported no bucket\n")
	}
	emit(out, "bucket %q ready in %s\n", bucket.Ref.Name, bucket.Ref.Location)
	// Cost is surfaced, never gated: gating cents trains an operator to click
	// through the gates that matter.
	emit(out, "cost: a bucket has no fixed fee — $0.00 until data is written, then Standard single-region storage per GiB-month plus operations.\n")
	return 0
}

func deleteBucket(ctx context.Context, opt options, out, errw io.Writer) int {
	provider, code := openProvider(opt, errw)
	if provider == nil {
		return code
	}
	if opt.bucket == "" || opt.instance == "" {
		return fail(errw, "datasphere: --bucket and --instance are both required\n")
	}
	ref := datasphere.BucketRef{Name: opt.bucket, Location: opt.location, Instance: opt.instance}
	err := provider.DeleteBucket(ctx, ref)
	if err != nil && !errors.Is(err, datasphere.ErrRetentionForced) {
		return fail(errw, "%v\n", err)
	}
	if err != nil {
		warn(errw, err)
	}
	emit(out, "bucket %q deleted; its data is permanently unreadable\n", opt.bucket)
	return 0
}

// object runs the verbs that go through the Store.
func object(ctx context.Context, cmd string, opt options, operands []string, out, errw io.Writer) int {
	store, code := openStore(ctx, opt, errw)
	if store == nil {
		return code
	}

	switch cmd {
	case "put":
		if len(operands) != 2 {
			return fail(errw, "usage: datasphere put [flags] <key> <file>\n")
		}
		data, err := readInput(operands[1])
		if err != nil {
			return fail(errw, "datasphere: read %s: %v\n", operands[1], err)
		}
		if err := store.Write(ctx, operands[0], data); err != nil {
			return fail(errw, "%v\n", err)
		}
		stored, _ := store.StoredName(operands[0])
		emit(out, "wrote %d bytes to %q (stored as %s)\n", len(data), operands[0], stored)
	case "get":
		if len(operands) < 1 || len(operands) > 2 {
			return fail(errw, "usage: datasphere get [flags] <key> [file]\n")
		}
		data, err := store.Read(ctx, operands[0])
		if err != nil {
			return fail(errw, "%v\n", err)
		}
		target := "-"
		if len(operands) == 2 {
			target = operands[1]
		}
		if err := writeOutput(target, data, out); err != nil {
			return fail(errw, "datasphere: write %s: %v\n", target, err)
		}
	case "ls":
		prefix := ""
		if len(operands) == 1 {
			prefix = operands[0]
		} else if len(operands) > 1 {
			return fail(errw, "usage: datasphere ls [flags] [prefix]\n")
		}
		names, err := store.List(ctx, prefix)
		// A joined error here reports objects whose names could not be
		// recovered. The names that DID resolve are still printed: hiding them
		// would turn one unreadable object into an unusable listing.
		if err != nil {
			warn(errw, err)
		}
		for _, name := range names {
			if !opt.tokens {
				emit(out, "%s\n", name)
				continue
			}
			stored, err := store.StoredName(name)
			if err != nil {
				return fail(errw, "%v\n", err)
			}
			emit(out, "%s\t%s\n", stored, name)
		}
	case "rm":
		if len(operands) != 1 {
			return fail(errw, "usage: datasphere rm [flags] <key>\n")
		}
		if err := store.Delete(ctx, operands[0]); err != nil {
			return fail(errw, "%v\n", err)
		}
		emit(out, "deleted %q\n", operands[0])
	}
	return 0
}

// openProvider builds the configured provider.
func openProvider(opt options, errw io.Writer) (datasphere.Provider, int) {
	cfg := datasphere.Config{Project: opt.project, Location: opt.location}
	if opt.creds != "" {
		data, err := os.ReadFile(opt.creds)
		if err != nil {
			return nil, fail(errw, "datasphere: reading credentials: %v\n", err)
		}
		cfg.Credentials = data
	}
	provider, err := datasphere.Open(opt.provider, cfg)
	if err != nil {
		return nil, fail(errw, "%v\n", err)
	}
	return provider, 0
}

// openStore is the composition root's enforcement point for the write path:
// the recorded bucket is validated — ownership labels, instance and all —
// before a Store exists to write through it. Tampered local metadata therefore
// cannot point writes at a stranger's bucket.
func openStore(ctx context.Context, opt options, errw io.Writer) (*datasphere.Store, int) {
	if opt.bucket == "" || opt.instance == "" {
		return nil, fail(errw, "datasphere: --bucket and --instance are both required\n")
	}
	provider, code := openProvider(opt, errw)
	if provider == nil {
		return nil, code
	}
	ref := datasphere.BucketRef{Name: opt.bucket, Location: opt.location, Instance: opt.instance}
	if err := provider.Validate(ctx, ref); err != nil {
		return nil, fail(errw, "%v\n", err)
	}
	keyring, code := loadKeyring(opt.keys, errw)
	if code != 0 {
		return nil, code
	}
	store, err := datasphere.NewStore(provider, opt.bucket, keyring)
	if err != nil {
		return nil, fail(errw, "%v\n", err)
	}
	return store, 0
}

// loadKeyring reads and parses the operator's keys file. The package itself
// never touches the file — that is the caller's job, and its modes are the
// caller's responsibility, which is why a loose one is called out here.
func loadKeyring(path string, errw io.Writer) (datasphere.Keyring, int) {
	info, err := os.Stat(path)
	if err != nil {
		return datasphere.Keyring{}, fail(errw, "datasphere: reading keyring: %v\n%s\n", err, datasphere.KeyLossWarning)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		emit(errw, "Warning: keyring %s is mode %04o; it must be %04o — anyone else with an account on this machine can read the keys.\n", path, perm, datasphere.KeysFileMode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return datasphere.Keyring{}, fail(errw, "datasphere: reading keyring: %v\n", err)
	}
	keyring, err := datasphere.ParseKeyring(data)
	if err != nil {
		return datasphere.Keyring{}, fail(errw, "%v\n", err)
	}
	return keyring, 0
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path string, data []byte, out io.Writer) error {
	if path == "-" {
		_, err := out.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// hoistFlags moves leading operands behind the flags, so that both
// `put <key> <file> --bucket B` and `put --bucket B <key> <file>` parse. The
// standard flag package stops at the first non-flag argument, and an operator
// typing the natural order should not be told their command is malformed.
func hoistFlags(args []string) []string {
	split := 0
	for split < len(args) && !isFlag(args[split]) {
		split++
	}
	if split == 0 {
		return args
	}
	return append(append([]string{}, args[split:]...), args[:split]...)
}

// isFlag reports whether an argument opens the flag section. A lone "-" does
// not: it is this harness's stdin/stdout operand, and the flag package treats
// it as an operand too. Stopping the hoist there would take the documented
// `put <key> - --bucket B` and leave the flags behind the terminator — every
// flag silently unparsed, and the key and the file swapped.
func isFlag(arg string) bool { return len(arg) > 1 && arg[0] == '-' }

func usage(errw io.Writer) {
	emit(errw, `usage:
  datasphere keygen        --keys keys.yaml
  datasphere mint-name     --instance NAME
  datasphere validate      --provider gcs --project P --location R [--credentials key.json] [--bucket B --instance NAME]
  datasphere ensure-bucket --provider gcs --project P --location R --instance NAME --bucket B
  datasphere delete-bucket --provider gcs --project P --instance NAME --bucket B
  datasphere put <key> <file>   --provider gcs ... --instance NAME --bucket B --keys keys.yaml
  datasphere get <key> [file]   ...
  datasphere ls  [prefix]       ...  [--tokens]
  datasphere rm  <key>          ...
  datasphere serve              --instance NAME --bucket B --provider gcs --project P --location R
                                [--listen :8443] [--status-listen :8444] [--unseal-listen :9443]

Use "-" as a file operand for stdin/stdout.
`)
}

func emit(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

func warn(w io.Writer, err error) { emit(w, "Warning: %v\n", err) }

// fail reports an error and returns the exit code, so call sites read as
// `return fail(...)`.
func fail(w io.Writer, format string, a ...any) int {
	emit(w, format, a...)
	return 1
}
