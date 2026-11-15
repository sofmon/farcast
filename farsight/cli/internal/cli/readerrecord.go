package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// msgPreviousReaderKey is what `reader record` prints after a rotation: the
// key it replaced still works in Google until the human deletes it. 'world'
// reads as the reader (ADR 0023 M2.4), so a world that reads is the proof
// that the new key works (design §7.2, A18-16).
const msgPreviousReaderKey = "The previous key %s still works. Once 'farcast world %s' reads, delete it from Cloud Shell: %s"

// readerRecordCommand records the key id the Cloud Shell script printed. It is
// local only (design §7.2).
type readerRecordCommand struct {
	keyID string
}

func (*readerRecordCommand) Name() string { return "record" }
func (*readerRecordCommand) Synopsis() string {
	return "Record the key id the Cloud Shell script printed"
}

func (*readerRecordCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast reader record <instance> --key-id <id>

Record the id Google gave the reader key the Cloud Shell script uploaded:
the 40 hex characters the script prints at its end.

After 'farcast reader init', it records the id. After 'farcast reader init
--rotate', it switches the instance to the new key: reader.key.next becomes
reader.key, and the next read signs with it. The read-only grant stays, since
the account is the same; the previous key still works in Google, and the
command prints the Cloud Shell line that deletes it.

It changes nothing on this machine or in Google if the id is not one Google
prints, or the instance's reader record is not the one farcast derives.`)
}

func (c *readerRecordCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.keyID, "key-id", "", "the key id the Cloud Shell script printed (40 hex characters)")
}

func (c *readerRecordCommand) Run(_ context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("reader record takes one instance name and --key-id <id>")
	}
	name := args[0]
	if !keyIDShape.MatchString(c.keyID) {
		return usagef("the key id %q is not the 40 hex characters Google prints", c.keyID)
	}
	meta, err := loadReaderRecord(env.ConfigDir, name)
	if err != nil {
		return err
	}
	if meta.Reader == nil {
		return fmt.Errorf("instance %q has no reader identity; run 'farcast reader init %s'", name, name)
	}
	if derived, ok := recordedReaderIsDerived(env.ConfigDir, meta); !ok {
		return fmt.Errorf("instance %q records the reader %q, which is not the reader farcast derives for it (%s); nothing was changed", name, meta.Reader.Email, derived)
	}
	project, email, current, err := checkedReader(meta)
	if err != nil {
		return err
	}
	rotated, err := env.ConfigDir.NextReaderKeyExists(name)
	if err != nil {
		return err
	}
	result := readerRecordResult{Instance: meta.Name, Email: email, KeyID: c.keyID}
	if rotated {
		if current == "" {
			return fmt.Errorf("instance %q has a rotated key waiting (reader.key.next) but records no key in use; run 'farcast reader init %s --rotate' again", name, name)
		}
		if c.keyID == current {
			return errors.New("that is the key in use; record the id the rotate script printed")
		}
		// The key moves first. If the record then fails, reader.key is the
		// new key and .next is gone, so running this again records the id;
		// the other order would leave the old key under the new id, and a
		// re-run would refuse it as the key in use.
		if err := env.ConfigDir.PromoteNextReaderKey(name); err != nil {
			return err
		}
		result.PreviousKeyID = current
		result.DeletePrevious = fmt.Sprintf("gcloud iam service-accounts keys delete '%s' --iam-account '%s' --project '%s'", current, email, project)
	}
	// GrantedAt and Scope stay: the RBAC subject is the account's email,
	// which a new key does not change.
	if _, err := env.ConfigDir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
		if m.Reader == nil {
			return fmt.Errorf("instance %q's reader was removed by another command while this one ran", name)
		}
		m.Reader.KeyID = c.keyID
		m.UpdatedAt = time.Now().UTC()
		return nil
	}); err != nil {
		if rotated {
			return fmt.Errorf("record instance %q's reader key: %w; reader.key is already the new key, so run 'farcast reader record %s --key-id %s' again", name, err, name, c.keyID)
		}
		return fmt.Errorf("record instance %q's reader key: %w", name, err)
	}
	return env.Printer.Print(result)
}

// recordedReaderIsDerived is openCluster's check of the recorded reader email
// (design §3.5), made without opening anything: in Google mode it must be
// readerEmail(name, project), and in loopback mode readerName(name) at a name
// under .invalid. The mode is loopback only for an endpoint kube.ParseEndpoint
// accepts as loopback with its cluster CA; anything else is held to the
// Google rule, the stricter one.
func recordedReaderIsDerived(dir config.Dir, meta *config.InstanceMetadata) (derived string, ok bool) {
	mode := kube.ModeGoogle
	if meta.Endpoint != "" {
		if ca, present, err := dir.LoadClusterCA(meta.Name); err == nil {
			if !present {
				ca = nil
			}
			if ep, err := kube.ParseEndpoint(meta.Endpoint, meta.Region, ca); err == nil {
				mode = ep.Mode
			}
		}
	}
	return derivedReader(meta.Reader.Email, meta.Name, meta.Project, mode)
}

// readerRecordResult is what `reader record` recorded.
type readerRecordResult struct {
	Instance string `json:"instance"`
	Email    string `json:"email"`
	KeyID    string `json:"key_id"`
	// PreviousKeyID is the key a rotation replaced, which still works in
	// Google; DeletePrevious is the Cloud Shell line that deletes it. Both are
	// empty after a first record.
	PreviousKeyID  string `json:"previous_key_id,omitempty"`
	DeletePrevious string `json:"delete_previous_key,omitempty"`
}

func (r readerRecordResult) Human(w io.Writer) error {
	fprintf(w, "✓ instance %q's reader %s now signs with key %s\n", r.Instance, r.Email, r.KeyID)
	if r.PreviousKeyID != "" {
		fprintf(w, msgPreviousReaderKey+"\n", r.PreviousKeyID, r.Instance, r.DeletePrevious)
	}
	return nil
}
