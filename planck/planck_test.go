package planck

import (
	"context"
	"strings"
	"testing"
)

type fakeProvider struct{ name string }

func (f fakeProvider) Name() string                                  { return f.name }
func (fakeProvider) Validate(context.Context) error                  { return nil }
func (fakeProvider) DeleteCluster(context.Context, ClusterRef) error { return nil }

func (fakeProvider) CreateCluster(context.Context, ClusterSpec) (*Cluster, error) {
	return &Cluster{}, nil
}

func (fakeProvider) ClusterStatus(context.Context, ClusterRef) (ClusterStatus, error) {
	return StatusRunning, nil
}

func TestRegisterAndOpen(t *testing.T) {
	name := t.Name()
	Register(name, func(Config) (Provider, error) { return fakeProvider{name: name}, nil })

	p, err := Open(name, Config{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if p.Name() != name {
		t.Errorf("Name() = %q, want %q", p.Name(), name)
	}
}

func TestOpenUnknown(t *testing.T) {
	_, err := Open("nope-"+t.Name(), Config{})
	if err == nil {
		t.Fatal("expected an error for an unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error = %v, want it to mention 'unknown provider'", err)
	}
}

func TestProvidersListed(t *testing.T) {
	name := t.Name()
	Register(name, func(Config) (Provider, error) { return fakeProvider{name: name}, nil })

	found := false
	for _, n := range Providers() {
		if n == name {
			found = true
		}
	}
	if !found {
		t.Errorf("Providers() = %v, missing %q", Providers(), name)
	}
}

func TestRegisterPanicsOnDuplicate(t *testing.T) {
	name := t.Name()
	Register(name, func(Config) (Provider, error) { return fakeProvider{name: name}, nil })
	defer func() {
		if recover() == nil {
			t.Error("expected Register to panic on a duplicate name")
		}
	}()
	Register(name, func(Config) (Provider, error) { return fakeProvider{name: name}, nil })
}

// ADR 0023 M2.7 (A30-34): a Cluster carries no credential, so String names
// its Ref, Status and Endpoint, exactly, and redacts nothing.
func TestClusterStringNamesRefStatusAndEndpoint(t *testing.T) {
	c := Cluster{
		Ref:      ClusterRef{Name: "demo", Location: "us-central1"},
		Status:   StatusRunning,
		Endpoint: "203.0.113.1",
	}
	if got, want := c.String(), "Cluster{Ref:us-central1/demo Status:running Endpoint:203.0.113.1}"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestConfigStringRedactsCredentials(t *testing.T) {
	c := Config{Project: "proj", Credentials: []byte("SUPER-SECRET-KEY")}
	s := c.String()
	if strings.Contains(s, "SUPER-SECRET-KEY") {
		t.Errorf("String() leaked credentials: %s", s)
	}
	if !strings.Contains(s, "proj") {
		t.Errorf("String() = %q, want the project", s)
	}
}
