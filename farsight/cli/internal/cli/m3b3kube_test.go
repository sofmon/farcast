package cli

// ADR 0024 M3b.3's chain, from package cli, where devicekey's and kube's
// types meet: what M3b.7 wires as a read command's reader (openRole), run
// here end to end over kubetest's fakes and nothing else. No product file of
// this package calls it yet.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/devicekey"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// TestM3b3FederatedReaderChain: a device enrolled by devicekey opens its
// reader for a read, and its leaf and signer become kube's client identity;
// with the reader provider's audience and the reader account's email, that
// is the reader's federated credential over a loopback Federation. Its
// cluster client reads a cluster fake as the reader's account, which the
// RBAC 'reader grant' applies, rendered for that email, decides; its IAM reader's
// get and list answers are what devicekey's CheckNamedProvider,
// ParseProvider and ParseProviders accept, page tokens included; and the
// whole chain exchanges the reader's leaf once, alone, and never the
// writer's.
func TestM3b3FederatedReaderChain(t *testing.T) {
	const project, number, pool = "proj-0001", "123456789012", "pool1234"
	ctx := t.Context()
	now := time.Now()
	store, enrolled, err := devicekey.Enrol(rand.Reader, filepath.Join(t.TempDir(), "identity"), []devicekey.Role{devicekey.Reader, devicekey.Writer}, now)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.OpenForRead(rand.Reader, now)
	if err != nil {
		t.Fatal(err)
	}
	writer := enrolled[1] // from Enrol's memory: no writer key is opened here
	if reader.Role() != devicekey.Reader || !reader.ID().Equal(enrolled[0].ID()) || writer.Role() != devicekey.Writer {
		t.Fatal("the opened reader is not the reader enrolled")
	}
	readerAccount := readerEmail("m3b3-instance", project)
	writerAccount := "farcast-writer-0a1b2c3d@" + project + ".iam.gserviceaccount.com"

	fake := kubetest.NewFederation(t)
	fake.AddProvider(number, pool, "provreader1", reader.AnchorDER(), reader.ID().Hex())
	fake.AddProvider(number, pool, "provwriter1", writer.AnchorDER(), writer.ID().Hex())
	fake.Bind(reader.ID().Hex(), readerAccount)
	fake.Bind(writer.ID().Hex(), writerAccount)
	fake.GrantPoolViewer(readerAccount)
	for i := range 11 { // a second page of the list
		fake.AddProvider(number, pool, fmt.Sprintf("provother%02d", i), reader.AnchorDER(), reader.ID().Hex())
	}

	fed, err := kube.NewLoopbackFederation(fake.STSAddr(), fake.IAMAddr(), fake.IAMAPIAddr(), fake.Roots())
	if err != nil {
		t.Fatal(err)
	}
	aud, err := kube.Audience(number, pool, "provreader1")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := kube.NewFederatedCredential(fed, aud, kube.NewClientIdentity([][]byte{reader.LeafDER()}, reader.Signer()), readerAccount, kube.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// The cluster, as the reader's account, under the RBAC 'reader grant'
	// applies.
	rbac, err := renderReaderRBAC(readerAccount, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := kubetest.New(t, kubetest.WithFederation(fake), kubetest.WithRBAC(readerAccount, rbac), kubetest.WithFederatedIdentity("reader", readerAccount))
	ep, err := kube.ParseEndpoint(s.Endpoint(), "", s.CAPEM())
	if err != nil {
		t.Fatal(err)
	}
	c, err := kube.New(kube.Config{Endpoint: ep, Credential: cred, Identity: kube.Reader})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListNamespaces(ctx, ""); err != nil {
		t.Fatalf("the reader's namespaces read: %v", err)
	}
	if _, err := c.ListPods(ctx, "kube-system", ""); !errors.Is(err, tkube.ErrForbidden) || !strings.Contains(err.Error(), `User "`+readerAccount+`"`) {
		t.Errorf("a read the reader's RBAC does not grant: %v; want a 403 naming the reader's account", err)
	}
	for _, r := range s.Requests() {
		if r.As != "reader" {
			t.Errorf("the cluster fake saw %s %s as %q, want the reader", r.Method, r.Path, r.As)
		}
	}

	// IAM's API, read back as devicekey reads it.
	ir, err := kube.NewIAMReader(cred)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ir.GetProvider(ctx, number, pool, "provreader1")
	if err != nil {
		t.Fatal(err)
	}
	if err := devicekey.CheckNamedProvider(got, number, pool, "provreader1", reader.AnchorDER(), reader.ID()); err != nil {
		t.Errorf("the reader's provider, read back: %v", err)
	}
	if err := devicekey.CheckNamedProvider(got, number, pool, "provreader1", writer.AnchorDER(), writer.ID()); err == nil {
		t.Error("the reader's provider passed as the writer's")
	}
	fake.RemoveProvider(number, pool, "provwriter1")
	deleted, err := ir.GetProvider(ctx, number, pool, "provwriter1")
	if err != nil {
		t.Fatal(err)
	}
	if lp, err := devicekey.ParseProvider(deleted, number, pool, "provwriter1"); err != nil || lp.State != devicekey.ProviderDeleted || !lp.RoleID.Equal(writer.ID()) {
		t.Errorf("the deleted writer provider: %+v, %v", lp, err)
	}
	if err := devicekey.CheckNamedProvider(deleted, number, pool, "provwriter1", writer.AnchorDER(), writer.ID()); err == nil {
		t.Error("CheckNamedProvider took a DELETED provider")
	}

	pages, err := ir.ListProviders(ctx, number, pool)
	if err != nil {
		t.Fatal(err)
	}
	var listed []devicekey.ListedProvider
	for i, page := range pages {
		ps, next, err := devicekey.ParseProviders(page, number, pool)
		if err != nil {
			t.Fatalf("page %d: %v", i+1, err)
		}
		if (next == "") != (i == len(pages)-1) {
			t.Errorf("page %d of %d: nextPageToken %v", i+1, len(pages), next != "")
		}
		listed = append(listed, ps...)
	}
	if len(pages) != 2 || len(listed) != 13 {
		t.Errorf("%d pages, %d providers; want 2 and 13", len(pages), len(listed))
	}
	byID := map[string]devicekey.ListedProvider{}
	for _, p := range listed {
		byID[p.ID] = p
	}
	if p := byID["provreader1"]; p.State != devicekey.ProviderActive || p.Disabled || !p.RoleID.Equal(reader.ID()) {
		t.Errorf("the reader's provider in the list: %+v", p)
	}
	if p := byID["provwriter1"]; p.State != devicekey.ProviderDeleted || !p.RoleID.Equal(writer.ID()) {
		t.Errorf("the deleted writer provider in the list: %+v", p)
	}

	// One exchange, of the reader's leaf alone; the writer's never.
	var exchanges int
	for _, r := range fake.Requests() {
		switch r.Server {
		case "sts":
			exchanges++
			if len(r.PeerCertificates) != 1 || string(r.PeerCertificates[0]) != string(reader.LeafDER()) || r.Form.Get("audience") != aud {
				t.Error("an exchange presented something other than the reader's leaf, at the reader's audience")
			}
		default:
			if r.PeerCertificates != nil {
				t.Errorf("a request at %s carried a client certificate", r.Server)
			}
		}
	}
	if exchanges != 1 {
		t.Errorf("%d exchanges, want 1", exchanges)
	}
	var accounts []string
	for _, sa := range fake.ServiceAccountTokens() {
		accounts = append(accounts, sa.Email)
	}
	if len(accounts) != 2 || slices.ContainsFunc(accounts, func(a string) bool { return a != readerAccount }) {
		t.Errorf("impersonated %q, want the reader's account twice: the cluster's and IAM's API's", accounts)
	}
}
