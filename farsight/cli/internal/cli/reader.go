package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// The reader identity (ADR 0023 M2.3, design §7.2): a per-instance Google
// service account the cluster reads are to run as (ADR 0023 M2.4), so a read
// never mints a token for the installer, which can write; until then only
// 'reader grant' reads as it. The human creates the account and
// uploads its key's certificate in Cloud Shell; farcast makes the key and
// applies the account's Kubernetes RBAC.

// readerName is the reader service account's ID for an instance:
// "farcast-reader-" and the first 8 hex characters of the name's SHA-256. It
// is 23 characters, inside Google's 6 to 30; an instance name can be 32, so
// the name is hashed and never embedded.
func readerName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "farcast-reader-" + hex.EncodeToString(sum[:])[:8]
}

// readerEmail is the reader service account's email in a Google project.
func readerEmail(name, project string) string {
	return readerName(name) + "@" + project + ".iam.gserviceaccount.com"
}

var (
	// projectIDShape is Google's project-ID shape: 6 to 30 characters,
	// lowercase letters, digits and hyphens, starting with a letter and not
	// ending with a hyphen.
	projectIDShape = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	// keyIDShape is a service-account key id as Google prints it: 40
	// lowercase hex characters.
	keyIDShape = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// msgUnsafeRecord is checkedReader's refusal: the field, and its value quoted.
const msgUnsafeRecord = "instance %q's record holds a %s that is not one Google issues (%q); farcast renders nothing from it"

// checkedReader is an instance record's reader values, checked before
// anything is rendered from them: every Cloud Shell line farcast prints for
// the reader takes its project, email and key id from here, never from the
// record's bytes, so a quote or a $( edited into the record never runs in an
// Owner's shell.
//
// It requires that the instance name pass validateInstanceName, that the
// project have Google's project-ID shape, and that a stored key id be 40
// lowercase hex characters. The email is rebuilt from the checked name and
// project, readerEmail(name, project), and the recorded one is not read: a
// caller that must refuse a hand-edited email compares meta.Reader.Email
// itself. keyID is "" when no reader or no key id is recorded.
func checkedReader(meta *config.InstanceMetadata) (project, email, keyID string, err error) {
	if meta == nil {
		return "", "", "", fmt.Errorf("cli: checkedReader needs the instance's record")
	}
	if validateInstanceName(meta.Name) != nil {
		return "", "", "", fmt.Errorf(msgUnsafeRecord, meta.Name, "name", meta.Name)
	}
	if !projectIDShape.MatchString(meta.Project) {
		return "", "", "", fmt.Errorf(msgUnsafeRecord, meta.Name, "project ID", meta.Project)
	}
	if meta.Reader != nil && meta.Reader.KeyID != "" {
		if !keyIDShape.MatchString(meta.Reader.KeyID) {
			return "", "", "", fmt.Errorf(msgUnsafeRecord, meta.Name, "key id", meta.Reader.KeyID)
		}
		keyID = meta.Reader.KeyID
	}
	return meta.Project, readerEmail(meta.Name, meta.Project), keyID, nil
}

// newReaderCommand builds the `farcast reader` group: the instance's
// read-only identity, made on this machine (init), uploaded by the human in
// Cloud Shell, recorded (record), and granted and verified read-only in the
// cluster (grant).
func newReaderCommand() Command {
	subs := NewRegistry()
	subs.Register(&readerInitCommand{})
	subs.Register(&readerRecordCommand{})
	subs.Register(&readerGrantCommand{})
	return &group{
		name:     "reader",
		synopsis: "The instance's read-only identity (init, record, grant)",
		subs:     subs,
		usage: `
Usage: farcast reader <init|record|grant> <instance> [flags]

An instance's read-only identity (ADR 0023 M2): a Google service account of
its own, farcast-reader- and 8 hex characters of the instance name's SHA-256.
From ADR 0023 M2.4 farcast's cluster reads run as it, so a read never mints a
token for the installer, which can write; until then only 'reader grant'
reads as it.

Setting it up takes four steps, one of them yours in Cloud Shell:

  farcast reader init <instance> [--days N]
      makes the key on this machine and prints a script holding only its
      public certificate
  the script, pasted into Cloud Shell as an Owner of the instance's project,
      creates the account, grants it roles/container.clusterViewer, uploads
      the certificate and prints the key id Google gave it
  farcast reader record <instance> --key-id <id>
      records that id
  farcast reader grant <instance>
      grants the account read access in the instance's cluster, then checks,
      as the account, that it can read and cannot write

Subcommands:
  init    Make the reader's key and print the Cloud Shell script that uploads it
  record  Record the key id the Cloud Shell script printed
  grant   Grant the reader read access in the cluster, and verify it read-only

Nothing farcast prints for Cloud Shell is taken from the instance's record as
it is: the project, the account and the key id are checked against the shapes
Google issues first, and a record that fails is refused.`,
	}
}
