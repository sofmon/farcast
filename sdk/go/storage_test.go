package farcast

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The sentinels an application branches on must be mutually distinct. A
// collision here would be silent: errors.Is would classify one condition as
// another and the application would take the wrong branch.
func TestStorageSentinelsAreDistinct(t *testing.T) {
	named := map[string]error{
		"ErrNotImplemented":     ErrNotImplemented,
		"ErrStorageSealed":      ErrStorageSealed,
		"ErrObjectNotFound":     ErrObjectNotFound,
		"ErrIntegrity":          ErrIntegrity,
		"ErrInvalidKey":         ErrInvalidKey,
		"ErrTooLarge":           ErrTooLarge,
		"ErrPermission":         ErrPermission,
		"ErrStorageUnavailable": ErrStorageUnavailable,
	}
	for aName, a := range named {
		for bName, b := range named {
			if aName == bName {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("%s classifies as %s; sentinels must be distinct", aName, bName)
			}
		}
	}
}

// ADR 0008 decision 7 names these two confusions specifically. A seal read as
// "this build never can" makes an application give up permanently on a
// condition that clears in minutes; a seal read as "no such object" makes it
// start over and overwrite intact data. Both are named in the ADR as the
// reason this contract was fixed before any application existed.
func TestSealedIsNotNotImplementedAndNotNotFound(t *testing.T) {
	if errors.Is(ErrStorageSealed, ErrNotImplemented) {
		t.Error("a seal must never classify as ErrNotImplemented: storage returns, this does not")
	}
	if errors.Is(ErrStorageSealed, ErrObjectNotFound) {
		t.Error("a seal must never classify as ErrObjectNotFound: that is silent data loss by a second route")
	}
}

// The wire mapping must be total. An unrecognized code has to land somewhere,
// and the two nearest sentinels are the two that cost data.
func TestStorageErrorMappingIsTotal(t *testing.T) {
	for _, code := range []string{"", "wat", "not-found-ish", "SEALED", "  sealed  "} {
		got := storageError(code)
		if !errors.Is(got, ErrStorageUnavailable) {
			t.Errorf("storageError(%q) = %v; unrecognized codes must be ErrStorageUnavailable", code, got)
		}
	}
}

func TestStorageErrorMapsEveryCode(t *testing.T) {
	want := map[string]error{
		CodeSealed:     ErrStorageSealed,
		CodeNotFound:   ErrObjectNotFound,
		CodeIntegrity:  ErrIntegrity,
		CodeInvalidKey: ErrInvalidKey,
		CodeTooLarge:   ErrTooLarge,
		CodePermission: ErrPermission,
	}
	for code, expect := range want {
		if got := storageError(code); !errors.Is(got, expect) {
			t.Errorf("storageError(%q) = %v, want %v", code, got, expect)
		}
	}
	if len(storageErrors) != len(want) {
		t.Errorf("storageErrors has %d entries, test covers %d — a new code needs a test and a sentinel",
			len(storageErrors), len(want))
	}
}

// Codes are frozen: renaming or reusing one silently reclassifies errors for
// every application already deployed against an older keyholder.
func TestWireCodeValuesAreFrozen(t *testing.T) {
	frozen := map[string]string{
		"CodeSealed":     "sealed",
		"CodeNotFound":   "not-found",
		"CodeIntegrity":  "integrity",
		"CodeInvalidKey": "invalid-key",
		"CodeTooLarge":   "too-large",
		"CodePermission": "permission",
	}
	got := map[string]string{
		"CodeSealed":     CodeSealed,
		"CodeNotFound":   CodeNotFound,
		"CodeIntegrity":  CodeIntegrity,
		"CodeInvalidKey": CodeInvalidKey,
		"CodeTooLarge":   CodeTooLarge,
		"CodePermission": CodePermission,
	}
	for name, want := range frozen {
		if got[name] != want {
			t.Errorf("%s = %q, want %q — wire codes are frozen", name, got[name], want)
		}
	}
}

// A hand-written fake in an application's own tests implements the four
// frozen methods and nothing else. It must keep compiling and must not be
// mistaken for a status-capable implementation.
type fakeStorage struct{ StorageAPI }

type statusStorage struct {
	StorageAPI
	st StorageStatus
}

func (s statusStorage) Status(context.Context) (StorageStatus, error) { return s.st, nil }

func TestStorageStatusOfWithoutSeam(t *testing.T) {
	_, err := StorageStatusOf(context.Background(), fakeStorage{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("StorageStatusOf on a plain StorageAPI = %v, want ErrNotImplemented", err)
	}
}

func TestStorageStatusOfWithSeam(t *testing.T) {
	when := time.Now()
	s := statusStorage{st: StorageStatus{
		State:      StorageSealed,
		Reason:     SealRestart,
		Since:      when,
		Generation: 7,
	}}
	got, err := StorageStatusOf(context.Background(), s)
	if err != nil {
		t.Fatalf("StorageStatusOf: %v", err)
	}
	if !got.Sealed() {
		t.Error("Sealed() = false for a sealed status")
	}
	if got.Reason != SealRestart || got.Generation != 7 || !got.Since.Equal(when) {
		t.Errorf("status round-trip lost fields: %+v", got)
	}
}

// The stub must report "not implemented", never a seal — an application must
// not conclude that a build without storage is merely sealed and wait for an
// operator who has nothing to unseal.
func TestStubIsNotImplementedNotSealed(t *testing.T) {
	s := Storage()
	ctx := context.Background()
	if _, err := s.Read(ctx, "k"); !errors.Is(err, ErrNotImplemented) || errors.Is(err, ErrStorageSealed) {
		t.Errorf("stub Read = %v, want ErrNotImplemented", err)
	}
	if err := s.Write(ctx, "k", nil); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("stub Write = %v", err)
	}
	if _, err := s.List(ctx, ""); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("stub List = %v", err)
	}
	if err := s.Delete(ctx, "k"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("stub Delete = %v", err)
	}
}

// StorageAPI is frozen at four methods: applications implement it to fake
// storage, so a fifth method breaks every one of them. Status lives on a
// separate optional interface for exactly that reason.
func TestStorageAPIStaysFourMethods(t *testing.T) {
	var _ StorageAPI = fourMethodsOnly{}
}

type fourMethodsOnly struct{}

func (fourMethodsOnly) Read(context.Context, string) ([]byte, error)   { return nil, nil }
func (fourMethodsOnly) Write(context.Context, string, []byte) error    { return nil }
func (fourMethodsOnly) List(context.Context, string) ([]string, error) { return nil, nil }
func (fourMethodsOnly) Delete(context.Context, string) error           { return nil }
