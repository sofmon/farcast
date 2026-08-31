package storage

import (
	"context"
	"testing"

	"github.com/sofmon/farcast/datasphere"
	_ "github.com/sofmon/farcast/datasphere/providers"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// A session must address a scoped object with the scope's keyring and an
// operator object with the master's. Getting this wrong does not error — it
// reports stored, billed, recoverable data as missing or corrupt.
func TestSessionRoutesKeysToTheOwningKeyring(t *testing.T) {
	ctx := context.Background()

	master, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := datasphere.NewScope("app", "app/")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := master.AddScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	// Through disk form, exactly as the CLI loads it.
	encoded, err := keys.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if keys, err = datasphere.ParseKeyring(encoded); err != nil {
		t.Fatal(err)
	}

	provider := newFakeProvider(config.Dir(t.TempDir()), "p")
	store, err := datasphere.NewStore(provider, "bkt", keys)
	if err != nil {
		t.Fatal(err)
	}
	session := &Session{
		Instance: "p", Bucket: "bkt", Provider: provider,
		Store: store, Keyring: keys,
		provider: provider, scopes: map[string]*datasphere.Store{},
	}

	// An application writes into its scope, as the keyholder does.
	scoped, err := session.StoreFor("app/doc")
	if err != nil {
		t.Fatal(err)
	}
	if scoped == session.Store {
		t.Fatal("a scoped key was routed to the master keyring")
	}
	if err := scoped.Write(ctx, "app/doc", []byte("app data")); err != nil {
		t.Fatal(err)
	}
	// The operator writes outside every scope.
	if err := session.Store.Write(ctx, "system/note", []byte("operator data")); err != nil {
		t.Fatal(err)
	}

	// Each is readable through the session's own routing.
	for key, want := range map[string]string{"app/doc": "app data", "system/note": "operator data"} {
		s, err := session.StoreFor(key)
		if err != nil {
			t.Fatalf("StoreFor(%q): %v", key, err)
		}
		got, err := s.Read(ctx, key)
		if err != nil {
			t.Fatalf("read %q through its owning keyring: %v", key, err)
		}
		if string(got) != want {
			t.Errorf("read %q = %q, want %q", key, got, want)
		}
	}

	// A key outside every scope must NOT be routed to a scope.
	if s, _ := session.StoreFor("system/note"); s != session.Store {
		t.Error("an unscoped key was routed to a scope")
	}

	// The scoped store is reused rather than rebuilt per call.
	again, _ := session.StoreFor("app/other")
	if again != scoped {
		t.Error("StoreFor rebuilt a scope's Store instead of reusing it")
	}

	// Every key space is enumerable, and between them they see everything.
	spaces, err := session.KeySpaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(spaces) != 2 {
		t.Fatalf("KeySpaces returned %d, want master + one scope", len(spaces))
	}
	seen := map[string]bool{}
	for _, space := range spaces {
		entries, _ := space.Store.ListEntries(ctx, "")
		for _, e := range entries {
			seen[e.Key] = true
		}
	}
	for _, want := range []string{"app/doc", "system/note"} {
		if !seen[want] {
			t.Errorf("%q is invisible across every key space; it is stored and billed but unlistable", want)
		}
	}
}
