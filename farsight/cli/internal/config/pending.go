package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
)

// The pending store's names, under the config root:
//
//	pending/              0700
//	  <name>/             0700  one pending install or device add
//	    pending.yaml      0600  the Pending record
//	    identity/         0700  the device's keys, made by devicekey
//
// It sits beside instances/, never in it, so a pending entry is no instance:
// ListInstances never lists one, and no command that takes an instance can
// open one by its name. Its keys move into the instance only at the hand-off
// (AdoptPending), after their enrolment is verified: AdoptPending refuses an
// entry that holds keys, or whose record puts a role on the certificate
// route, until its state is PendingVerified.
const (
	pendingSubdir  = "pending"
	pendingFile    = "pending.yaml"
	identitySubdir = "identity"
)

// PendingKind is what began a pending entry.
type PendingKind string

// The pending kinds.
const (
	PendingInstall   PendingKind = "install"    // 'farcast install', before its record exists
	PendingDeviceAdd PendingKind = "device_add" // 'farcast device add' on a machine with no record of the instance
)

// PendingState is how far a pending entry has come.
type PendingState string

// The pending states, in their order.
const (
	// PendingKeysMade: the IDs are drawn and recorded, and the keys made, or
	// about to be: the record is written before devicekey makes the keys.
	PendingKeysMade PendingState = "keys_made"
	// PendingSetupShown: the certificates, the setup block and the guide
	// were shown.
	PendingSetupShown PendingState = "setup_shown"
	// PendingCoordinatesReceived: the human's line came back.
	PendingCoordinatesReceived PendingState = "coordinates_received"
	// PendingVerified: every role this entry enrols passed D4's
	// verification. It is recorded before devicekey's EnrolmentVerified is
	// called for any of them, so a resume that finds it, and meets
	// devicekey's ErrNotEnrolling, has nothing left to verify.
	//
	// config cannot see devicekey's enrolling markers, so this state is the
	// only evidence of a verification it has, and the hand-off's caller keeps
	// the order: SavePending at PendingVerified, then EnrolmentVerified for
	// each role the entry enrols, then AdoptPending. A resume that finds an
	// entry at PendingVerified calls EnrolmentVerified for each of those roles
	// again before it hands off (a window already closed is no error there),
	// so no marker moves into the instance with the keys.
	PendingVerified PendingState = "verified"
)

// PendingDraw is the IDs a pending entry drew, recorded before anything that
// uses them is shown or made, so an abandoned entry can always print the
// teardown of what its setup created. Each is a non-secret coordinate.
type PendingDraw struct {
	Pool           string `yaml:"pool,omitempty"`
	ReaderProvider string `yaml:"reader_provider,omitempty"`
	WriterProvider string `yaml:"writer_provider,omitempty"`
	ReaderAccount  string `yaml:"reader_account,omitempty"`
	WriterAccount  string `yaml:"writer_account,omitempty"`
	NodeAccount    string `yaml:"node_account,omitempty"`
	ConditionTitle string `yaml:"condition_title,omitempty"`
}

// Pending is one pending install's or device add's record, pending.yaml.
//
// Nothing secret lives here. The keys are in identity/ beside it.
type Pending struct {
	Kind      PendingKind  `yaml:"kind"`
	Name      string       `yaml:"name"`
	Provider  string       `yaml:"provider"`
	Project   string       `yaml:"project,omitempty"`
	Region    string       `yaml:"region,omitempty"`
	CostLimit CostLimit    `yaml:"cost_limit"`
	CreatedAt time.Time    `yaml:"created_at"`
	State     PendingState `yaml:"state"`
	Draw      PendingDraw  `yaml:"draw"`
	// Route is the route the entry enrols on: the certificate route, or a
	// fallback; never none.
	Route Route `yaml:"route"`
	// ProjectNumber is the project's number, from the human's line; "" until
	// it came back.
	ProjectNumber string `yaml:"project_number,omitempty"`
}

// The pending store's sentinels.
var (
	// ErrNoPending is a name with no pending entry. The error that carries
	// it matches fs.ErrNotExist too.
	ErrNoPending = errors.New("no pending install or device add by that name on this machine")
	// ErrPendingExists is a pending entry CreatePending would have made, and
	// that is already there.
	ErrPendingExists = errors.New("a pending install or device add by that name already exists on this machine")
	// ErrPendingRecord is a pending.yaml holding a value outside the shape
	// farcast writes it in, or naming another instance than its directory.
	// The error that carries it names the field, never the value.
	ErrPendingRecord = errors.New("the pending record is not one farcast writes")
	// ErrInstanceRecorded is a name that has an instance record on this
	// machine where only a pending entry may be.
	ErrInstanceRecorded = errors.New("the instance has a record on this machine")
	// ErrUnsafePath is a path in the pending store or an instance's
	// identity that is a symbolic link, or not a directory or file of its
	// own, or a directory other accounts can reach.
	ErrUnsafePath = errors.New("not a private directory or file of its own")
	// ErrPendingUnverified is a hand-off of a pending entry whose enrolment
	// is not recorded as verified (PendingVerified), while it holds keys or
	// its record puts a role on the certificate route: its keys would move
	// into the instance with their enrolment windows still open.
	ErrPendingUnverified = errors.New("the pending entry's enrolment is not recorded as verified")
)

// noPending is a missing pending entry, marked ErrNoPending.
type noPending struct{ name string }

func (e *noPending) Error() string {
	return fmt.Sprintf("instance %q: %v", e.name, ErrNoPending)
}
func (e *noPending) Unwrap() []error { return []error{ErrNoPending, fs.ErrNotExist} }

// pendingRefused is ErrPendingRecord, with what is wrong.
func pendingRefused(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrPendingRecord}, a...)...)
}

// PendingDir is the root of every pending entry on this machine.
func (d Dir) PendingDir() string { return filepath.Join(string(d), pendingSubdir) }

// pendingEntry is name's pending directory. Its callers validate name first.
func (d Dir) pendingEntry(name string) string { return filepath.Join(d.PendingDir(), name) }

// PendingIdentityDir is the directory a pending entry's keys are made in,
// <config>/pending/<name>/identity, for devicekey.Enrol. It refuses a name
// 'farcast install' would refuse before it builds the path, and a symbolic
// link, a non-directory or a directory other accounts can reach in place of
// pending/, pending/<name>/ or identity/, where each is there
// (ErrUnsafePath). It needs none of them to be there.
func (d Dir) PendingIdentityDir(name string) (string, error) {
	if err := ValidateInstanceName(name); err != nil {
		return "", err
	}
	if err := checkTree(d.PendingDir(), name, identitySubdir); err != nil {
		return "", err
	}
	return filepath.Join(d.pendingEntry(name), identitySubdir), nil
}

// checkTree checks root, root/name and root/name/sub with checkDir, each
// that is there, top down; the first one absent ends it, as nothing below it
// can be there.
func checkTree(root, name, sub string) error {
	for _, p := range []string{root, filepath.Join(root, name), filepath.Join(root, name, sub)} {
		present, err := checkDir(p, true)
		if err != nil {
			return err
		}
		if !present {
			return nil
		}
	}
	return nil
}

// checkDir reports whether path is there, refusing with ErrUnsafePath
// anything there but a real directory, read by Lstat so a symbolic link is
// never followed, and, when private, a directory whose mode lets another
// account in. Removing a directory needs it real only: a widened mode, which
// is when what it holds is exposed, does not keep that on disk.
func checkDir(path string, private bool) (present bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return false, fmt.Errorf("%s is a symbolic link: %w", path, ErrUnsafePath)
	case !fi.IsDir():
		return false, fmt.Errorf("%s is not a directory: %w", path, ErrUnsafePath)
	case private && fi.Mode().Perm()&0o077 != 0:
		return false, fmt.Errorf("%s is mode %04o, which other accounts on this machine can reach: %w", path, fi.Mode().Perm(), ErrUnsafePath)
	}
	return true, nil
}

// checkFile refuses with ErrUnsafePath anything at path but a regular file,
// read by Lstat, so a symbolic link is refused, not followed. Nothing there
// is no refusal: the read or the write that follows says so, or makes it.
func checkFile(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is a symbolic link or not a file of its own: %w", path, ErrUnsafePath)
	}
	return nil
}

// pendingPresent reports whether name has a pending entry, refusing an
// unsafe pending/ or pending/<name>/ (checkDir, private as given). name is
// validated by the caller.
func (d Dir) pendingPresent(name string, private bool) (bool, error) {
	present, err := checkDir(d.PendingDir(), private)
	if err != nil || !present {
		return false, err
	}
	return checkDir(d.pendingEntry(name), private)
}

// checkPending refuses a Pending that is not one farcast writes: a kind, a
// state or a route farcast does not write (none is not a pending route), a
// name 'farcast install' would refuse, and a project, a project number or a
// drawn ID out of its shape, each checked where it is present, as
// CheckedIdentity checks the record's; and two roles or two accounts sharing
// a drawn ID. The error names the field, never the value.
func checkPending(p *Pending) error {
	if p == nil {
		return pendingRefused("no record")
	}
	switch p.Kind {
	case PendingInstall, PendingDeviceAdd:
	default:
		return pendingRefused("kind is neither %s nor %s", PendingInstall, PendingDeviceAdd)
	}
	if ValidateInstanceName(p.Name) != nil {
		return pendingRefused("name is not one 'farcast install' would create")
	}
	switch p.State {
	case PendingKeysMade, PendingSetupShown, PendingCoordinatesReceived, PendingVerified:
	default:
		return pendingRefused("state is not a pending state farcast writes")
	}
	if !p.Route.valid() || p.Route == RouteNone {
		return pendingRefused("route is not a route a pending entry enrols on")
	}
	if err := checkShapes(pendingRefused, []shaped{
		{"project", p.Project, projectIDShape, shapeProject},
		{"project_number", p.ProjectNumber, projectNumberShape, shapeNumber},
		{"draw.pool", p.Draw.Pool, longIDShape, shapeLongID},
		{"draw.reader_provider", p.Draw.ReaderProvider, longIDShape, shapeLongID},
		{"draw.writer_provider", p.Draw.WriterProvider, longIDShape, shapeLongID},
		{"draw.reader_account", p.Draw.ReaderAccount, shortIDShape, shapeShortID},
		{"draw.writer_account", p.Draw.WriterAccount, shortIDShape, shapeShortID},
		{"draw.node_account", p.Draw.NodeAccount, shortIDShape, shapeShortID},
		{"draw.condition_title", p.Draw.ConditionTitle, shortIDShape, shapeShortID},
	}); err != nil {
		return err
	}
	if p.Draw.ReaderProvider != "" && p.Draw.ReaderProvider == p.Draw.WriterProvider {
		return pendingRefused("draw names one provider for both roles")
	}
	return distinctAccounts(pendingRefused, "draw", p.Draw.ReaderAccount, p.Draw.WriterAccount, p.Draw.NodeAccount)
}

// CreatePending makes name's pending entry, <config>/pending/<name>/ at
// 0700, and writes p into it as pending.yaml, 0600. The entry's directory is
// made with one exclusive mkdir, so of two commands beginning the same name
// at once one is refused with ErrPendingExists and nothing of the other's is
// touched. It makes no identity/: devicekey makes that, with the keys.
//
// It refuses, before it makes anything: a name 'farcast install' would
// refuse; a p that is not one farcast writes (ErrPendingRecord), or that
// names another instance; a name that already has an instance directory
// (ErrInstanceRecorded), because a name is pending or recorded, never both,
// but inside AdoptPending; and an unsafe pending/ (ErrUnsafePath). An
// entry whose pending.yaml could not be written is removed again.
func (d Dir) CreatePending(name string, p *Pending) error {
	if err := ValidateInstanceName(name); err != nil {
		return err
	}
	if err := checkPending(p); err != nil {
		return err
	}
	if p.Name != name {
		return pendingRefused("it names another instance than %q", name)
	}
	if err := d.Ensure(); err != nil {
		return err
	}
	if _, err := os.Lstat(d.instanceDir(name)); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return err
		}
		return fmt.Errorf("instance %q: %w; a recorded instance is never pending", name, ErrInstanceRecorded)
	}
	if err := os.Mkdir(d.PendingDir(), 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create %s: %w", d.PendingDir(), err)
	}
	if _, err := checkDir(d.PendingDir(), true); err != nil {
		return err
	}
	entry := d.pendingEntry(name)
	if err := os.Mkdir(entry, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("instance %q: %w", name, ErrPendingExists)
		}
		return fmt.Errorf("create %s: %w", entry, err)
	}
	data, err := yaml.Marshal(p)
	if err == nil {
		err = writeFileAtomic(filepath.Join(entry, pendingFile), data)
	}
	if err != nil {
		// The entry is this call's own and holds nothing: writeFileAtomic
		// removes its temporary file.
		_ = os.Remove(entry)
		return fmt.Errorf("write instance %q's pending record: %w", name, err)
	}
	return nil
}

// SavePending writes p over name's pending.yaml, whole or not at all
// (writeFileAtomic), at 0600. It refuses what CreatePending refuses of p and
// of the name, a name with no pending entry (ErrNoPending), and a symbolic
// link or anything but a private directory in place of pending/ or
// pending/<name>/, or anything but a file in place of pending.yaml
// (ErrUnsafePath).
func (d Dir) SavePending(name string, p *Pending) error {
	if err := ValidateInstanceName(name); err != nil {
		return err
	}
	if err := checkPending(p); err != nil {
		return err
	}
	if p.Name != name {
		return pendingRefused("it names another instance than %q", name)
	}
	present, err := d.pendingPresent(name, true)
	if err != nil {
		return err
	}
	if !present {
		return &noPending{name: name}
	}
	path := filepath.Join(d.pendingEntry(name), pendingFile)
	if err := checkFile(path); err != nil {
		return err
	}
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode instance %q's pending record: %w", name, err)
	}
	return writeFileAtomic(path, data)
}

// LoadPending reads name's pending.yaml, through readFile, so ObserveReads
// sees it. It reads strictly: a field this build does not know, or a key
// given twice, is refused. It refuses a name 'farcast install' would refuse
// before it builds a path, a name with no pending entry (ErrNoPending), an
// unsafe pending/, pending/<name>/ or pending.yaml (ErrUnsafePath), a
// record that is not one farcast writes (ErrPendingRecord), and a record that
// names another instance than its directory: a copied or renamed entry is
// not the entry it claims to be.
//
// An entry whose pending.yaml is missing is the read's fs.ErrNotExist, not
// ErrNoPending: the entry is there. Two stops leave one: a CreatePending
// that stopped between its mkdir and its write, with no record beside it,
// which an abandon removes; and a RemovePending that stopped inside its
// removal, which unlinks the entry's files before the entry, beside the
// record of a hand-off whose keys have moved, which ResumeAdoption finishes.
func (d Dir) LoadPending(name string) (*Pending, error) {
	if err := ValidateInstanceName(name); err != nil {
		return nil, err
	}
	present, err := d.pendingPresent(name, true)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, &noPending{name: name}
	}
	path := filepath.Join(d.pendingEntry(name), pendingFile)
	if err := checkFile(path); err != nil {
		return nil, err
	}
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var p Pending
	if err := yaml.UnmarshalWithOptions(data, &p, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := checkPending(&p); err != nil {
		return nil, err
	}
	if p.Name != name {
		return nil, pendingRefused("%s names another instance than its directory", path)
	}
	return &p, nil
}

// ListPending returns the names of the pending entries on this machine,
// sorted: each directory in pending/ whose name 'farcast install' would
// accept. A file, or a directory whose name it would refuse, is not an
// entry and is passed over, as ListInstances passes over a file in
// instances/. A symbolic link among them is refused (ErrUnsafePath):
// whatever it points at is not where farcast keeps keys. No pending/ is no
// entries.
func (d Dir) ListPending() ([]string, error) {
	present, err := checkDir(d.PendingDir(), true)
	if err != nil || !present {
		return nil, err
	}
	entries, err := os.ReadDir(d.PendingDir())
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symbolic link: %w", filepath.Join(d.PendingDir(), e.Name()), ErrUnsafePath)
		}
		if e.IsDir() && ValidateInstanceName(e.Name()) == nil {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// PendingExists reports whether name has a pending entry. It refuses a name
// 'farcast install' would refuse before it builds a path, and a symbolic
// link or anything but a private directory in place of pending/ or
// pending/<name>/ (ErrUnsafePath). It reads no file.
func (d Dir) PendingExists(name string) (bool, error) {
	if err := ValidateInstanceName(name); err != nil {
		return false, err
	}
	return d.pendingPresent(name, true)
}

// PendingOnly is the abandon precondition: name has a pending entry, and no
// instance record. It refuses a name with no pending entry (ErrNoPending),
// and a name with a record, metadata.yaml in its instance directory
// (ErrInstanceRecorded): an abandon acts on a pending entry alone, never on
// a finished record, which is release's. An instance directory holding no
// record, which only an AdoptPending that stopped after its first step
// leaves, does not stop it. A symbolic link, or anything but a real
// directory, in place of pending/ or pending/<name>/ is refused
// (ErrUnsafePath); a widened mode is not, as an abandon removes what it
// exposes. It reads no file.
func (d Dir) PendingOnly(name string) error {
	if err := ValidateInstanceName(name); err != nil {
		return err
	}
	exists, err := d.pendingPresent(name, false)
	if err != nil {
		return err
	}
	if !exists {
		return &noPending{name: name}
	}
	if _, err := os.Lstat(filepath.Join(d.instanceDir(name), metadataFile)); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return err
		}
		return fmt.Errorf("instance %q: %w; a recorded instance is released, not abandoned", name, ErrInstanceRecorded)
	}
	return nil
}

// RemovePending removes name's pending entry: pending.yaml, and identity/
// with whatever keys are still in it. It refuses a name 'farcast install'
// would refuse before it builds a path, a name with no pending entry
// (ErrNoPending), and a symbolic link or anything but a real directory in
// place of pending/, pending/<name>/ or identity/, or anything but a file in
// place of pending.yaml (ErrUnsafePath). A widened mode does not stop it:
// that is when the keys are exposed, and removing them is the fix.
//
// When the name has no record, it first removes the instance directory an
// AdoptPending that stopped after its first step left beside the entry
// (removeUnrecorded), which would otherwise read as an instance whose record
// is unreadable and keep the name from a new install. It removes it before
// the entry, so a stop between the two leaves an entry that is abandoned
// again. A record, and an instance directory holding anything else, it
// leaves as they are: a recorded instance is release's.
func (d Dir) RemovePending(name string) error {
	if err := ValidateInstanceName(name); err != nil {
		return err
	}
	present, err := d.pendingPresent(name, false)
	if err != nil {
		return err
	}
	if !present {
		return &noPending{name: name}
	}
	entry := d.pendingEntry(name)
	if err := checkFile(filepath.Join(entry, pendingFile)); err != nil {
		return err
	}
	if _, err := checkDir(filepath.Join(entry, identitySubdir), false); err != nil {
		return err
	}
	if err := d.removeUnrecorded(name); err != nil {
		return err
	}
	if err := os.RemoveAll(entry); err != nil {
		return fmt.Errorf("remove instance %q's pending entry: %w", name, err)
	}
	return nil
}

// recordTempPrefix begins the name writeFileAtomic gives metadata.yaml's
// temporary file, which a process that dies inside SaveInstanceMetadata's
// write leaves in the instance directory.
const recordTempPrefix = ".tmp-" + metadataFile + "-"

// recordLeftovers reports whether name's instance directory, which is there,
// holds nothing but what an AdoptPending that stopped after its first step
// can leave in it: nothing, or the temporary files of a record whose write
// did not finish, each a regular file. files are those temporary files.
func (d Dir) recordLeftovers(name string) (files []string, only bool, err error) {
	entries, err := os.ReadDir(d.instanceDir(name))
	if err != nil {
		return nil, false, err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasPrefix(e.Name(), recordTempPrefix) {
			return nil, false, nil
		}
		files = append(files, filepath.Join(d.instanceDir(name), e.Name()))
	}
	return files, true, nil
}

// removeLeftovers removes the temporary files recordLeftovers found.
func removeLeftovers(name string, files []string) error {
	for _, f := range files {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove instance %q's unfinished record: %w", name, err)
		}
	}
	return nil
}

// removeUnrecorded removes name's instance directory when it is a real
// directory in a real instances/, read by Lstat, and holds nothing but
// recordLeftovers' leftovers. Anything else there, a record included, it
// leaves as it is and does not refuse: the abandon that calls it acts on the
// pending entry, and what is in instances/ is not the entry's.
func (d Dir) removeUnrecorded(name string) error {
	for _, p := range []string{d.instancesDir(), d.instanceDir(name)} {
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return nil
		}
	}
	files, only, err := d.recordLeftovers(name)
	if err != nil || !only {
		return err
	}
	if err := removeLeftovers(name, files); err != nil {
		return err
	}
	if err := os.Remove(d.instanceDir(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove instance %q's directory, which holds no record: %w", name, err)
	}
	return nil
}

// The hand-off's steps, as adoptFault names them.
const (
	adoptCreate   = "create"
	adoptRecord   = "record"
	adoptIdentity = "identity"
	adoptRemove   = "remove"
)

// adoptFault, when set, is asked before each of the hand-off's steps whether
// to stop there, with the error it returns: the tests' crash windows. Nil in
// product code.
var adoptFault atomic.Pointer[func(step string) error]

// stopAt is adoptFault's answer for step: nil in product code.
func stopAt(step string) error {
	if f := adoptFault.Load(); f != nil {
		return (*f)(step)
	}
	return nil
}

// ErrAdoptionMismatch is a record that is not the hand-off of the pending
// entry by its name: it names another project, or an identity other than
// the one the entry drew. The error that carries it names the field, never
// the value.
var ErrAdoptionMismatch = errors.New("the instance record is not the hand-off of its pending entry")

// AdoptPending hands name's pending entry over to an instance record, in
// pitfall 10.1's order, D7's:
//  1. CreateInstance;
//  2. SaveInstanceMetadata, of meta, which holds the Identity and the status
//     the entry's kind gives it (below);
//  3. the rename of pending/<name>/identity to instances/<name>/identity;
//  4. RemovePending.
//
// So the record names the keys before they move, and the keys are in the
// instance before the pending entry goes: a stop at any point leaves either
// the pending entry whole, or a record ResumeAdoption finishes. It undoes
// nothing on a failure. An instance directory that is there and holds
// nothing, or nothing but the temporary files of a record whose write did
// not finish (recordLeftovers), is taken as step 1 done, since only an
// AdoptPending that stopped after it leaves one beside a pending entry;
// AdoptPending again removes those files and finishes that hand-off, which
// ResumeAdoption cannot, as it has no record to read.
//
// The record's status is provisioning for an install's entry, whose cluster
// is yet to be made, and running for a device add's, whose instance is
// there already (the M3b plan's M3b.16).
//
// It refuses, before step 1: a name 'farcast install' would refuse; a name
// with no pending entry, or one LoadPending refuses; a meta that names
// another instance, a status other than the entry's kind's, or an Identity
// CheckedIdentity refuses; a meta that is not this entry's hand-off
// (ErrAdoptionMismatch); a certificate-route role when the entry holds no
// identity/, as the record would name keys that are not there; an entry not
// at PendingVerified while it holds an identity/ or the record puts a role
// on the certificate route (ErrPendingUnverified), as the keys would move
// with their enrolment windows open; an instance directory that holds
// anything else, or a record; an identity/ already in the instance; and a
// symbolic link, or anything but a private directory, in place of the
// directories it moves keys between (ErrUnsafePath).
func (d Dir) AdoptPending(name string, meta *InstanceMetadata) error {
	if err := ValidateInstanceName(name); err != nil {
		return err
	}
	p, err := d.LoadPending(name)
	if err != nil {
		return err
	}
	status := InstanceProvisioning
	if p.Kind == PendingDeviceAdd {
		status = InstanceRunning
	}
	switch {
	case meta == nil:
		return errors.New("adopt a pending entry: no instance record to adopt it into")
	case meta.Name != name:
		return fmt.Errorf("adopt instance %q's pending entry: the record names another instance", name)
	case meta.Status != status:
		return fmt.Errorf("adopt instance %q's pending %s: the record's status is not %s", name, p.Kind, status)
	}
	id, err := CheckedIdentity(meta)
	if err != nil {
		return err
	}
	if err := adoptionMatches(p, meta); err != nil {
		return err
	}
	src, dst, err := d.adoptionPaths(name)
	if err != nil {
		return err
	}
	srcPresent, err := checkDir(src, true)
	if err != nil {
		return err
	}
	if !srcPresent {
		for _, r := range id.Roles {
			if r.Route == RouteCertificate {
				return fmt.Errorf("adopt instance %q's pending entry: its %s role is on the %s route, and the entry holds no identity/ with its keys", name, r.Role, RouteCertificate)
			}
		}
	}
	if err := requireVerified(p, id, srcPresent); err != nil {
		return err
	}
	instPresent, err := checkDir(d.instanceDir(name), true)
	if err != nil {
		return err
	}
	var leftovers []string
	if instPresent {
		files, only, err := d.recordLeftovers(name)
		if err != nil {
			return err
		}
		if !only {
			return fmt.Errorf("adopt instance %q's pending entry: %w, or holds something already, at %s", name, ErrInstanceRecorded, d.instanceDir(name))
		}
		leftovers = files
	}

	if err := stopAt(adoptCreate); err != nil {
		return err
	}
	if !instPresent {
		if err := d.CreateInstance(name); err != nil {
			return err
		}
	}
	if err := stopAt(adoptRecord); err != nil {
		return err
	}
	if err := removeLeftovers(name, leftovers); err != nil {
		return err
	}
	if err := d.SaveInstanceMetadata(name, meta); err != nil {
		return err
	}
	if srcPresent {
		if err := d.moveIdentity(name, src, dst); err != nil {
			return err
		}
	}
	if err := stopAt(adoptRemove); err != nil {
		return err
	}
	return d.RemovePending(name)
}

// ResumeAdoption finishes a hand-off AdoptPending began and did not finish:
// when name has both a pending entry and an instance record, it moves the
// entry's identity/ into the instance, unless it is there already, and then
// removes the entry. Each of its steps can stop and be run again.
//
// It refuses: a name 'farcast install' would refuse; a name with no pending
// entry (ErrNoPending), or one LoadPending refuses; a name with no record,
// marked ErrNoInstanceRecord, whose hand-off stopped before its record and
// is finished by AdoptPending again; a record whose Identity
// CheckedIdentity refuses, or that is not this entry's hand-off
// (ErrAdoptionMismatch); an entry AdoptPending would refuse as not verified
// (ErrPendingUnverified); an identity/ in both the entry and the instance,
// where neither is moved over the other; and a symbolic link, or anything
// but a private directory, in place of either (ErrUnsafePath).
//
// An identity/ in neither is no refusal: the entry's route kept no keys in
// one (fallback 3), or something outside farcast removed them, which the
// record's first use reports.
//
// An entry whose pending.yaml is gone beside a record is the hand-off's
// step 4 stopped inside RemovePending, which unlinks the entry's files
// before the entry, and ResumeAdoption finishes it (finishRemoval).
func (d Dir) ResumeAdoption(name string) error {
	if err := ValidateInstanceName(name); err != nil {
		return err
	}
	p, err := d.LoadPending(name)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist) && !errors.Is(err, ErrNoPending):
		return d.finishRemoval(name, err)
	default:
		return err
	}
	src, dst, err := d.adoptionPaths(name)
	if err != nil {
		return err
	}
	meta, err := d.LoadInstanceMetadata(name)
	if errors.Is(err, ErrNoInstanceRecord) {
		return fmt.Errorf("resume instance %q's hand-off: %w; its hand-off stopped before its record, and adopting the entry again finishes it", name, err)
	}
	if err != nil {
		return fmt.Errorf("resume instance %q's hand-off: %w", name, err)
	}
	id, err := CheckedIdentity(meta)
	if err != nil {
		return err
	}
	if err := adoptionMatches(p, meta); err != nil {
		return err
	}
	srcPresent, err := checkDir(src, true)
	if err != nil {
		return err
	}
	if err := requireVerified(p, id, srcPresent); err != nil {
		return err
	}
	if srcPresent {
		if err := d.moveIdentity(name, src, dst); err != nil {
			return err
		}
	}
	if err := stopAt(adoptRemove); err != nil {
		return err
	}
	return d.RemovePending(name)
}

// finishRemoval is ResumeAdoption for name's entry whose pending.yaml is
// gone (loadErr, LoadPending's fs.ErrNotExist). Beside a record that
// CheckedIdentity passes and that names this instance, with no identity/ in
// the entry, it is the hand-off's step 4 stopped inside RemovePending, after
// the keys moved, and it removes the entry, as step 4 would have: the entry
// holds nothing step 4 does not remove. With no record it is a
// CreatePending that stopped before its write, which is abandoned, not
// handed off; and keys in an entry with no pending record are left to the
// operator. Each is refused with nothing changed.
func (d Dir) finishRemoval(name string, loadErr error) error {
	meta, err := d.LoadInstanceMetadata(name)
	if errors.Is(err, ErrNoInstanceRecord) {
		return fmt.Errorf("resume instance %q's hand-off: %w; the entry holds no pending record and the instance no record, and an entry that was never written is abandoned, not handed off", name, loadErr)
	}
	if err != nil {
		return fmt.Errorf("resume instance %q's hand-off: %w", name, err)
	}
	if _, err := CheckedIdentity(meta); err != nil {
		return err
	}
	if meta.Name != name {
		return fmt.Errorf("instance %q: %w: name differs", name, ErrAdoptionMismatch)
	}
	src, err := d.PendingIdentityDir(name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(src); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return err
		}
		return fmt.Errorf("resume instance %q's hand-off: %w; the entry still holds an identity/ with no pending record beside it, and nothing is moved or removed", name, loadErr)
	}
	if err := stopAt(adoptRemove); err != nil {
		return err
	}
	return d.RemovePending(name)
}

// requireVerified refuses, as ErrPendingUnverified, a hand-off of p before
// its state is PendingVerified, when the entry holds an identity/ (keys) or
// the record puts any role on the certificate route. config cannot see
// devicekey's enrolling markers (PendingVerified says why the state is
// enough). A hand-off with no keys and no certificate-route role, fallback
// 3's, is left to its caller's own check (the M3b plan's M3b.14).
func requireVerified(p *Pending, id *Identity, keys bool) error {
	if p.State == PendingVerified {
		return nil
	}
	certificate := false
	for _, r := range id.Roles {
		certificate = certificate || r.Route == RouteCertificate
	}
	if keys || certificate {
		return fmt.Errorf("adopt instance %q's pending entry: %w; it is at %s, and is handed off only at %s", p.Name, ErrPendingUnverified, p.State, PendingVerified)
	}
	return nil
}

// adoptionPaths are the hand-off's identity/ in the pending entry and in the
// instance, refusing an unsafe pending/, pending/<name>/, instances/ or
// instances/<name>/ (checkTree).
func (d Dir) adoptionPaths(name string) (src, dst string, err error) {
	src, err = d.PendingIdentityDir(name)
	if err != nil {
		return "", "", err
	}
	dst, err = d.InstanceIdentityDir(name)
	if err != nil {
		return "", "", err
	}
	return src, dst, nil
}

// moveIdentity is the hand-off's step 3: it renames src to dst, refusing a
// dst that is there, whatever it is. rename(2) would put a directory over an
// empty one, and a directory there is not the hand-off's to replace.
func (d Dir) moveIdentity(name, src, dst string) error {
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return err
		}
		return fmt.Errorf("adopt instance %q's pending entry: %s is there already, and the entry's keys are not moved over it", name, dst)
	}
	if err := stopAt(adoptIdentity); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("adopt instance %q's pending entry: move its keys: %w", name, err)
	}
	return nil
}

// adoptionMatches refuses a record that is not the hand-off of p: one that
// names another instance or project, that holds no Identity, or whose
// Identity differs from any ID p drew, or from p's project number, where p
// has one. Without it, a pending entry's keys could move into another
// install's record of the same name.
func adoptionMatches(p *Pending, meta *InstanceMetadata) error {
	mismatch := func(field string) error {
		return fmt.Errorf("instance %q: %w: %s differs", p.Name, ErrAdoptionMismatch, field)
	}
	if meta.Name != p.Name {
		return mismatch("name")
	}
	if meta.Project != p.Project {
		return mismatch("project")
	}
	id := meta.Identity
	if id == nil {
		return mismatch("identity")
	}
	provider := func(role string) string {
		for _, r := range id.Roles {
			if r.Role == role {
				return r.Provider
			}
		}
		return ""
	}
	for _, f := range []struct{ field, drew, has string }{
		{"identity.project_number", p.ProjectNumber, id.ProjectNumber},
		{"identity.pool", p.Draw.Pool, id.Pool},
		{"identity.reader_account", p.Draw.ReaderAccount, id.ReaderAccount},
		{"identity.writer_account", p.Draw.WriterAccount, id.WriterAccount},
		{"identity.node_account", p.Draw.NodeAccount, id.NodeAccount},
		{"identity.condition_title", p.Draw.ConditionTitle, id.ConditionTitle},
		{"the reader's provider", p.Draw.ReaderProvider, provider(RoleReader)},
		{"the writer's provider", p.Draw.WriterProvider, provider(RoleWriter)},
	} {
		if f.drew != "" && f.drew != f.has {
			return mismatch(f.field)
		}
	}
	return nil
}
