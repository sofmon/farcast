package cli

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// walkScopes is the walk probe's scope choice (walkcluster_test.go, build tag
// walk), from v, FARCAST_WALK_SCOPE's value. Empty, or
// cloud-platform+userinfo.email, is farcast's own pair, kube.TokenScopes, in
// the order farcast sends it (design A22-7). userinfo.email alone is the scope
// farcast minted with at 2482810, which the 2026-11-16 probe walk found the DNS
// endpoint refuses with 401; it stays so that refusal can be reproduced.
// cloud-platform alone is the other half. It returns the scopes and the name
// the probe prints for them.
//
// It is here, untagged, although only walk-tagged code calls it, so that the
// ordinary test run checks it (TestWalkScopes): the walk probe itself runs
// only on a walk, and a wrong default or a wrong name would go into its record.
func walkScopes(v string) ([]string, string, error) {
	switch v {
	case "", "cloud-platform+userinfo.email":
		return kube.TokenScopes(), "cloud-platform and userinfo.email (farcast's own)", nil
	case "userinfo.email":
		return []string{kube.ScopeUserinfoEmail}, "userinfo.email alone (refused by the DNS endpoint on the 2026-11-16 walk)", nil
	case "cloud-platform":
		return []string{kube.ScopeCloudPlatform}, "cloud-platform alone", nil
	default:
		return nil, "", fmt.Errorf("FARCAST_WALK_SCOPE=%q: want empty or cloud-platform+userinfo.email (farcast's own), userinfo.email or cloud-platform", v)
	}
}

// TestWalkScopes: the walk probe mints with farcast's own pair, exactly
// kube.TokenScopes, unless FARCAST_WALK_SCOPE names one scope alone; the name
// it prints names exactly the scopes it mints with, so a walk record cannot
// carry a scope it did not send; and every other value is refused, not read
// as some nearby set.
func TestWalkScopes(t *testing.T) {
	short := map[string]string{
		"cloud-platform": kube.ScopeCloudPlatform,
		"userinfo.email": kube.ScopeUserinfoEmail,
	}
	for _, tc := range []struct {
		v    string
		want []string
	}{
		{"", kube.TokenScopes()},
		{"cloud-platform+userinfo.email", kube.TokenScopes()},
		{"userinfo.email", []string{kube.ScopeUserinfoEmail}},
		{"cloud-platform", []string{kube.ScopeCloudPlatform}},
	} {
		got, name, err := walkScopes(tc.v)
		if err != nil {
			t.Errorf("FARCAST_WALK_SCOPE=%q: %v", tc.v, err)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("FARCAST_WALK_SCOPE=%q mints with %q, want %q", tc.v, got, tc.want)
		}
		for s, scope := range short {
			if strings.Contains(name, s) != slices.Contains(got, scope) {
				t.Errorf("FARCAST_WALK_SCOPE=%q prints %q for the scopes %q", tc.v, name, got)
			}
		}
		if strings.Contains(name, "alone") != (len(got) == 1) {
			t.Errorf("FARCAST_WALK_SCOPE=%q prints %q for %d scopes", tc.v, name, len(got))
		}
		if strings.Contains(name, "farcast's own") != slices.Equal(got, kube.TokenScopes()) {
			t.Errorf("FARCAST_WALK_SCOPE=%q prints %q for %q; farcast's own is %q", tc.v, name, got, kube.TokenScopes())
		}
	}
	for _, v := range []string{
		"cloud-platform userinfo.email",
		"userinfo.email+cloud-platform",
		"cloud-platform+userinfo.email ",
		" cloud-platform",
		"Cloud-Platform",
		kube.ScopeCloudPlatform,
		kube.ScopeUserinfoEmail,
		"compute",
		"none",
	} {
		got, name, err := walkScopes(v)
		if err == nil || got != nil || name != "" {
			t.Errorf("FARCAST_WALK_SCOPE=%q = %q, %q, %v; want it refused", v, got, name, err)
			continue
		}
		if want := fmt.Sprintf("FARCAST_WALK_SCOPE=%q", v); !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal of %q is %q; want it to name %s", v, err, want)
		}
	}
}
