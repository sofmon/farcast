package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/planck"
)

// The resolution rules for FarCast's own images (ADR 0023 M1, design
// §1.3.8), run through the commands against the fake builder and the fake
// carried components. Nothing here compiles, pulls or pushes anything.

const prodName = "prod"

// repoOf is a component's repository in the fake registry of "prod".
func repoOf(component string) string { return instanceRepo(prodName, component) }

// imageIn is a component's image in prod's registry, at a digest made of one
// hex digit.
func imageIn(component, hexDigit string) string { return repoOf(component) + "@" + sha(hexDigit) }

// carriedRef is the image the fake release carries for a component.
func carriedRef(component string) string { return imageIn(component, tagDigest) }

var testBuiltAt = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// deployRun is what one command run left behind.
type deployRun struct {
	err    error
	fb     *fakeBuilder
	fc     *fakeCluster
	fp     *fakeProvider
	stderr string
	stdout string
	meta   *config.InstanceMetadata
}

func (r deployRun) applied() string {
	var b strings.Builder
	for _, m := range r.fc.applied {
		b.Write(m)
	}
	return b.String()
}

// recordFatLine sets FatLine's deploy record and, when prov is not empty, its
// provenance.
func recordFatLine(meta *config.InstanceMetadata, image string, prov config.SystemImage) {
	recordDeployedImage(meta, image)
	if prov.Origin != "" {
		prov.Image = image
		recordSystemImage(meta, components.FatLine.Name, prov)
	}
}

// redeployProd redeploys a connected "prod" whose record setup prepares, with
// the command shaped by configure.
func redeployProd(t *testing.T, mode output.Mode, fb *fakeBuilder, setup func(*config.InstanceMetadata), configure func(*redeployCommand)) deployRun {
	t.Helper()
	dir := config.Dir(t.TempDir())
	meta := connectedInstance(t, dir, prodName)
	if setup != nil {
		setup(meta)
		if err := dir.SaveInstanceMetadata(prodName, meta); err != nil {
			t.Fatal(err)
		}
	}
	fc, fp := &fakeCluster{}, &fakeProvider{}
	c := testRedeploy(fp, fb)
	c.assumeYes = true
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
	if configure != nil {
		configure(c)
	}
	env, out, errb := testEnvBoth(dir, mode)
	err := c.Run(context.Background(), env, []string{prodName})
	after, lerr := dir.LoadInstanceMetadata(prodName)
	if lerr != nil {
		t.Fatal(lerr)
	}
	return deployRun{err: err, fb: fb, fc: fc, fp: fp, stderr: errb.String(), stdout: out.String(), meta: after}
}

func noErr(t *testing.T, r deployRun) {
	t.Helper()
	if r.err != nil {
		t.Fatalf("the deploy failed: %v\nstderr:\n%s", r.err, r.stderr)
	}
}

func notFoundForTags(ref string) (string, error) {
	if strings.Contains(ref, "@sha256:") {
		return ref, nil
	}
	return "", image.ErrNotFound
}

// foreignForTags answers a digest as itself and every version tag with an
// image this farcast does not carry, sha256:f…: a tag moved under the
// release.
func foreignForTags(ref string) (string, error) {
	if strings.Contains(ref, "@sha256:") {
		return ref, nil
	}
	return pinnedRef(ref, "f"), nil
}

func TestEmbeddedImageIsPushedWhenTheTagIsMissing(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{resolveFn: notFoundForTags}, nil, nil)
	noErr(t, r)
	if len(r.fb.embedded) != 2 || len(r.fb.built) != 0 {
		t.Fatalf("pushed %d carried images and built %d; want fatline and shrike pushed, nothing built", len(r.fb.embedded), len(r.fb.built))
	}
	art, _ := newFakeCarried().Lookup("fatline")
	got := r.fb.embedded[0]
	want := image.EmbeddedOptions{
		Ref: repoOf("fatline") + ":" + testVersion, Package: "./fatline/cmd/fatline", BinaryPath: "/fatline",
		Layer: []byte("layer fatline"), LayerDigest: art.Layer, LayerSize: art.LayerSize, DiffID: art.DiffID,
		Manifest: art.Manifest, GoVersion: art.GoVersion,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("PushEmbedded got %+v\nwant %+v", got, want)
	}
	if !strings.Contains(r.applied(), carriedRef("fatline")) || deployedImage(r.meta) != carriedRef("fatline") {
		t.Errorf("deployed %q, want %s", deployedImage(r.meta), carriedRef("fatline"))
	}
	wantRec := config.SystemImage{Image: carriedRef("fatline"), Origin: config.OriginEmbedded, Go: carriedGo, Farcast: testVersion}
	if rec := r.meta.SystemImages["fatline"]; rec != wantRec {
		t.Errorf("recorded %+v, want %+v", rec, wantRec)
	}
}

func TestEmbeddedImageIsReusedWhenTheTagHoldsIt(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, nil, nil)
	noErr(t, r)
	if len(r.fb.embedded) != 0 || len(r.fb.built) != 0 {
		t.Fatalf("pushed %d and built %d; a tag that holds the carried image is reused", len(r.fb.embedded), len(r.fb.built))
	}
	if len(onlyFatline(r.fb.resolved)) != 1 || onlyFatline(r.fb.resolved)[0] != instanceImageRef(prodName) {
		t.Errorf("looked up %v, want the version tag", r.fb.resolved)
	}
	if deployedImage(r.meta) != carriedRef("fatline") {
		t.Errorf("deployed %q", deployedImage(r.meta))
	}
}

func TestAForeignDigestAtTheVersionTagIsNeverDeployed(t *testing.T) {
	foreign := func(ref string) (string, error) {
		if strings.Contains(ref, "@sha256:") {
			return ref, nil
		}
		return pinnedRef(ref, "f"), nil
	}
	// In JSON mode too: the warning is never only for a terminal.
	r := redeployProd(t, output.ModeJSON, &fakeBuilder{resolveFn: foreign}, nil, nil)
	noErr(t, r)
	for _, want := range []string{"warning:", sha("f"), sha("e"), "will not be deployed"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr does not name %q:\n%s", want, r.stderr)
		}
	}
	if len(r.fb.embedded) != 2 {
		t.Errorf("pushed %d carried images over the foreign tags, want 2", len(r.fb.embedded))
	}
	applied := r.applied()
	if strings.Contains(applied, sha("f")) || !strings.Contains(applied, carriedRef("fatline")) {
		t.Errorf("the rendered manifests do not name only the carried image:\n%s", applied)
	}
	if r.meta.SystemImages["fatline"].Image != carriedRef("fatline") {
		t.Errorf("recorded %+v", r.meta.SystemImages["fatline"])
	}
}

func TestPushEmbeddedFailureStopsTheDeploy(t *testing.T) {
	fb := &fakeBuilder{resolveFn: notFoundForTags, pushErr: fmt.Errorf("image: fatline: %w", image.ErrNotTheReleasedImage)}
	r := redeployProd(t, output.ModeHuman, fb, nil, nil)
	if !errors.Is(r.err, image.ErrNotTheReleasedImage) {
		t.Fatalf("err = %v, want the push's refusal", r.err)
	}
	if len(r.fc.applied) != 0 {
		t.Error("applied a workload after the push failed")
	}
	if len(r.meta.SystemImages) != 0 {
		t.Errorf("recorded %+v after the push failed", r.meta.SystemImages)
	}
}

func TestDevAndDirtyVersionsAreRefusedForCarriedComponents(t *testing.T) {
	for _, info := range []buildinfo.Info{
		{Version: "dev", Revision: testRevision},
		{Version: "v0.0.0-20261113155828-006e479afcf0+dirty", Revision: testRevision},
		{Version: testVersion, Revision: testRevision, Modified: true},
	} {
		t.Run(info.Version, func(t *testing.T) {
			fb := &fakeBuilder{}
			r := redeployProd(t, output.ModeHuman, fb, nil, func(c *redeployCommand) {
				c.build = func() buildinfo.Info { return info }
			})
			if !errors.Is(r.err, buildinfo.ErrNotRelease) {
				t.Fatalf("err = %v, want a refusal wrapping ErrNotRelease", r.err)
			}
			if !strings.Contains(r.err.Error(), info.Version) || !strings.Contains(r.err.Error(), "--source") {
				t.Errorf("the refusal does not name the version and the way out: %v", r.err)
			}
			if len(fb.resolved) != 0 || len(fb.embedded) != 0 || len(r.fc.applied) != 0 {
				t.Errorf("a refused farcast reached the registry or the cluster: resolved=%v pushed=%d applied=%d",
					fb.resolved, len(fb.embedded), len(r.fc.applied))
			}
		})
	}
}

func TestCarriedBaseMismatchIsRefused(t *testing.T) {
	carried := newFakeCarried()
	carried.base = "gcr.io/distroless/static:nonroot@" + sha("0")
	fb := &fakeBuilder{}
	r := redeployProd(t, output.ModeHuman, fb, nil, func(c *redeployCommand) { c.carried = carried })
	if !errors.Is(r.err, buildinfo.ErrNotRelease) {
		t.Fatalf("err = %v, want a refusal wrapping ErrNotRelease", r.err)
	}
	if !strings.Contains(r.err.Error(), carried.base) || !strings.Contains(r.err.Error(), image.BaseImage) {
		t.Errorf("the refusal does not name both bases: %v", r.err)
	}
	if len(fb.resolved) != 0 {
		t.Errorf("looked up %v before refusing", fb.resolved)
	}
}

func TestCarriedComponentsFromAnotherRevisionAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*fakeCarried, *buildinfo.Info)
	}{
		{"another revision", func(c *fakeCarried, _ *buildinfo.Info) { c.revision = strings.Repeat("9", 40) }},
		{"no carried revision", func(c *fakeCarried, _ *buildinfo.Info) { c.revision = "" }},
		{"no farcast revision (a -X build)", func(_ *fakeCarried, i *buildinfo.Info) { i.Revision = "" }},
		{"carried from a modified tree", func(c *fakeCarried, _ *buildinfo.Info) { c.modified = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			carried, info := newFakeCarried(), releaseBuild()
			tc.apply(carried, &info)
			fb := &fakeBuilder{}
			r := redeployProd(t, output.ModeHuman, fb, nil, func(c *redeployCommand) {
				c.carried = carried
				c.build = func() buildinfo.Info { return info }
			})
			if !errors.Is(r.err, buildinfo.ErrNotRelease) {
				t.Fatalf("err = %v, want a refusal wrapping ErrNotRelease", r.err)
			}
			if len(fb.resolved) != 0 || len(r.fc.applied) != 0 {
				t.Errorf("a refused farcast reached the registry or the cluster")
			}
		})
	}
}

// devBuild is a farcast that carries components and is not a release.
func devBuild() buildinfo.Info { return buildinfo.Info{Version: "dev", Revision: testRevision} }

func TestNonReleaseIsRefusedBeforeAnythingIsAsked(t *testing.T) {
	// A config directory with no record for the instance: the refusal has to
	// be the precheck's, because it runs before the record is read.
	emptyDir := func(t *testing.T) config.Dir {
		dir := config.Dir(t.TempDir())
		if err := os.Chmod(string(dir), 0o700); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	wantPrecheck := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, buildinfo.ErrNotRelease) || errors.Is(err, config.ErrNoInstanceRecord) {
			t.Fatalf("err = %v, want the precheck's refusal, not the missing record", err)
		}
	}
	t.Run("redeploy", func(t *testing.T) {
		fb := &fakeBuilder{}
		c := testRedeploy(&fakeProvider{}, fb)
		c.build = devBuild
		env, _ := testEnv(emptyDir(t), output.ModeHuman)
		wantPrecheck(t, c.Run(context.Background(), env, []string{prodName}))
	})
	t.Run("kernel deploy", func(t *testing.T) {
		c := testKernelDeploy(&fakeCluster{}, &fakeBuilder{})
		c.deployer.build = devBuild
		env, _ := testEnv(emptyDir(t), output.ModeHuman)
		wantPrecheck(t, c.Run(context.Background(), env, []string{prodName}))
	})
	t.Run("storage deploy", func(t *testing.T) {
		c := testStorageDeploy(&fakeProvider{}, &fakeBuilder{})
		c.deployer.build = devBuild
		env, _ := testEnv(emptyDir(t), output.ModeHuman)
		wantPrecheck(t, c.Run(context.Background(), env, []string{prodName}))
	})
	// On connect and redeploy --fatline-image names FatLine's image alone:
	// Shrike is still the carried image, so the refusal stands under it.
	for _, named := range []bool{false, true} {
		what := "connect, not yet connected"
		if named {
			what += ", with --fatline-image"
		}
		t.Run(what, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			installedInstance(t, dir, prodName)
			fp := &fakeProvider{}
			c := testConnect(fp, &fakeBuilder{}) // no --yes: the cost question would be asked
			c.build = devBuild
			if named {
				c.fatlineImage = imageIn("fatline", "c")
			}
			c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
				t.Fatal("dialled")
				return nil, nil
			}
			env, _, errb := testEnvBoth(dir, output.ModeHuman)
			err := c.Run(context.Background(), env, []string{prodName})
			if !errors.Is(err, buildinfo.ErrNotRelease) {
				t.Fatalf("err = %v, want the precheck's refusal", err)
			}
			if len(fp.ensured) != 0 {
				t.Error("the registry was ensured before the refusal")
			}
			if strings.Contains(errb.String(), "[y/N]") || strings.Contains(errb.String(), "load balancer") {
				t.Errorf("something was asked before the refusal:\n%s", errb.String())
			}
			if minted, _ := dir.InstanceMTLSExists(prodName); minted {
				t.Error("an identity was minted before the refusal")
			}
		})
	}
	t.Run("redeploy, with --fatline-image", func(t *testing.T) {
		c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
		c.build = devBuild
		c.fatlineImage = imageIn("fatline", "c")
		env, _ := testEnv(emptyDir(t), output.ModeHuman)
		wantPrecheck(t, c.Run(context.Background(), env, []string{prodName}))
	})
	t.Run("connect, already connected", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		connectedInstance(t, dir, prodName)
		c := testConnect(&fakeProvider{}, &fakeBuilder{})
		c.build = devBuild
		c.newCluster = func(clusterRef) (clusterApplier, error) { return &fakeCluster{}, nil }
		c.dial = connectedDial()
		env, _ := testEnv(dir, output.ModeHuman)
		if err := c.Run(context.Background(), env, []string{prodName}); err != nil {
			t.Fatalf("a reconnect deploys nothing and must not be refused: %v", err)
		}
	})
	t.Run("--source", func(t *testing.T) {
		r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, nil, func(c *redeployCommand) {
			c.build = devBuild
			c.sourceDir = "/checkouts/farcast"
			c.findSource = func(d string) (string, error) { return d, nil }
		})
		noErr(t, r)
	})
	// Kernel deploy and storage deploy deploy one component each, so their
	// image flag names everything they deploy.
	t.Run("the command's own image flag", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		connectedInstance(t, dir, prodName)
		c := testKernelDeploy(&fakeCluster{}, &fakeBuilder{})
		c.deployer.build = devBuild
		c.image = imageIn("technocore", "c")
		env, _ := testEnv(dir, output.ModeHuman)
		if err := c.Run(context.Background(), env, []string{prodName}); err != nil {
			t.Fatalf("a named image is deployed by any farcast: %v", err)
		}
	})
}

func TestSourceBuildIsRecordedAsOperatorBuilt(t *testing.T) {
	const source = "/checkouts/farcast"
	check := func(t *testing.T, meta *config.InstanceMetadata, fb *fakeBuilder, names ...string) {
		t.Helper()
		if len(fb.built) != len(names) {
			t.Fatalf("built %d images, want %d", len(fb.built), len(names))
		}
		for i, name := range names {
			if fb.built[i].Repository != repoOf(name) {
				t.Errorf("built into %q, want the untagged repository %q", fb.built[i].Repository, repoOf(name))
			}
			want := config.SystemImage{Image: pinnedRef(repoOf(name), "b"), Origin: config.OriginOperator, Go: "go1.27.5",
				Farcast: testVersion, BuiltAt: testBuiltAt, Source: source}
			if got := meta.SystemImages[name]; got != want {
				t.Errorf("%s recorded as %+v, want %+v", name, got, want)
			}
		}
	}
	t.Run("connect", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		installedInstance(t, dir, prodName)
		fb := &fakeBuilder{}
		c := testConnect(&fakeProvider{}, fb)
		c.assumeYes, c.sourceDir = true, source
		c.findSource = func(d string) (string, error) { return d, nil }
		c.newCluster = func(clusterRef) (clusterApplier, error) { return &fakeCluster{ip: "203.0.113.1"}, nil }
		c.dial = connectedDial()
		env, _ := testEnv(dir, output.ModeHuman)
		if err := c.Run(context.Background(), env, []string{prodName}); err != nil {
			t.Fatal(err)
		}
		meta, _ := dir.LoadInstanceMetadata(prodName)
		check(t, meta, fb, "fatline", "shrike")
	})
	t.Run("redeploy", func(t *testing.T) {
		fb := &fakeBuilder{}
		r := redeployProd(t, output.ModeHuman, fb, nil, func(c *redeployCommand) {
			c.sourceDir = source
			c.findSource = func(d string) (string, error) { return d, nil }
		})
		noErr(t, r)
		check(t, r.meta, fb, "fatline", "shrike")
	})
	t.Run("kernel deploy", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		connectedInstance(t, dir, prodName)
		fb := &fakeBuilder{}
		c := testKernelDeploy(&fakeCluster{}, fb)
		c.deployer.sourceDir = source
		env, _ := testEnv(dir, output.ModeHuman)
		if err := c.Run(context.Background(), env, []string{prodName}); err != nil {
			t.Fatal(err)
		}
		meta, _ := dir.LoadInstanceMetadata(prodName)
		check(t, meta, fb, "technocore")
		if meta.Kernel.Image != meta.SystemImages["technocore"].Image {
			t.Errorf("the record %q is not the deploy record %q", meta.SystemImages["technocore"].Image, meta.Kernel.Image)
		}
	})
	t.Run("storage deploy", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		deployableInstance(t, dir, prodName)
		fb := &fakeBuilder{}
		c := testStorageDeploy(&fakeProvider{}, fb)
		c.deployer.assumeYes, c.deployer.sourceDir = true, source
		c.deployer.newCluster = func(clusterRef) (clusterApplier, error) { return &fakeCluster{}, nil }
		env, _ := testEnv(dir, output.ModeHuman)
		if err := c.Run(context.Background(), env, []string{prodName}); err != nil {
			t.Fatal(err)
		}
		meta, _ := dir.LoadInstanceMetadata(prodName)
		check(t, meta, fb, "datasphered")
		if meta.Keyholder.Image != meta.SystemImages["datasphered"].Image {
			t.Errorf("the record is not the deploy record")
		}
	})
}

func TestFallbackBuildIsRecordedAsDevelopment(t *testing.T) {
	var asked []string
	fb := &fakeBuilder{}
	r := redeployProd(t, output.ModeHuman, fb, nil, func(c *redeployCommand) {
		asSourceBuild(&c.fatlineDeployer, "v0.0.0-20261113155828-006e479afcf0+dirty")
		c.findSource = func(d string) (string, error) { asked = append(asked, d); return "/work/farcast", nil }
	})
	noErr(t, r)
	want := config.SystemImage{Image: pinnedRef(repoOf("fatline"), "b"), Origin: config.OriginDevelopment, Go: "go1.27.5",
		Farcast: "v0.0.0-20261113155828-006e479afcf0+dirty", BuiltAt: testBuiltAt, Source: "/work/farcast"}
	if got := r.meta.SystemImages["fatline"]; got != want {
		t.Errorf("recorded %+v, want %+v", got, want)
	}
	if len(asked) == 0 || asked[0] != "" {
		t.Errorf("the checkout was looked up as %q, want the auto-detected one", asked)
	}
}

// developmentRecorded is an instance whose FatLine and Shrike are development
// builds from /work/farcast.
func developmentRecorded(meta *config.InstanceMetadata) {
	dev := config.SystemImage{Origin: config.OriginDevelopment, Go: "go1.27.5", Farcast: "dev", BuiltAt: testBuiltAt, Source: "/work/farcast"}
	recordFatLine(meta, imageIn("fatline", "d"), dev)
	dev.Image = imageIn("shrike", "d")
	recordSystemImage(meta, "shrike", dev)
}

func TestSourceFarcastKeepsADevelopmentImage(t *testing.T) {
	fb := &fakeBuilder{}
	r := redeployProd(t, output.ModeHuman, fb, developmentRecorded, func(c *redeployCommand) {
		asSourceBuild(&c.fatlineDeployer, "dev")
		c.findSource = func(string) (string, error) { t.Fatal("looked for a checkout"); return "", nil }
	})
	noErr(t, r)
	if len(fb.built) != 0 || deployedImage(r.meta) != imageIn("fatline", "d") {
		t.Fatalf("built %d, deployed %q; a source build keeps its development image", len(fb.built), deployedImage(r.meta))
	}
	if !slices.Contains(fb.resolved, imageIn("fatline", "d")) {
		t.Errorf("the kept image was not checked: %v", fb.resolved)
	}
	if !strings.Contains(r.stderr, "keeping the development image "+imageIn("fatline", "d")) || !strings.Contains(r.stderr, "Pass --source to rebuild it.") {
		t.Errorf("stderr does not say it kept it:\n%s", r.stderr)
	}
}

func TestReleaseFarcastReplacesADevelopmentImageAndSaysSo(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, developmentRecorded, nil)
	noErr(t, r)
	if deployedImage(r.meta) != carriedRef("fatline") {
		t.Fatalf("deployed %q, want the carried image", deployedImage(r.meta))
	}
	want := "fatline: replacing the development image " + imageIn("fatline", "d") + " (built from /work/farcast) with the image this farcast carries (go1.27.4)."
	if !strings.Contains(r.stderr, want) {
		t.Errorf("stderr does not say %q:\n%s", want, r.stderr)
	}
	if r.meta.SystemImages["fatline"].Origin != config.OriginEmbedded {
		t.Errorf("recorded %+v", r.meta.SystemImages["fatline"])
	}
}

func TestProvenanceOutsideTheInstanceRegistryIsIgnored(t *testing.T) {
	evil := "evil.example/x@" + sha("0")
	fb := &fakeBuilder{}
	r := redeployProd(t, output.ModeHuman, fb, func(meta *config.InstanceMetadata) {
		recordFatLine(meta, evil, config.SystemImage{Origin: config.OriginOperator, Go: "go1.27.5", Farcast: testVersion, Source: "/x"})
	}, nil)
	noErr(t, r)
	for _, ref := range fb.resolved {
		if strings.Contains(ref, "evil.example") {
			t.Errorf("looked %s up, with this instance's credential", ref)
		}
	}
	if !strings.Contains(r.stderr, "ignoring the recorded origin of "+evil) {
		t.Errorf("the record was ignored silently:\n%s", r.stderr)
	}
	if deployedImage(r.meta) != carriedRef("fatline") {
		t.Errorf("deployed %q, want the carried image", deployedImage(r.meta))
	}
}

// embeddedBy records FatLine as the image another farcast version carried.
func embeddedBy(farcast, goVersion string) func(*config.InstanceMetadata) {
	return func(meta *config.InstanceMetadata) {
		recordFatLine(meta, imageIn("fatline", "1"), config.SystemImage{Origin: config.OriginEmbedded, Go: goVersion, Farcast: farcast})
	}
}

func TestEmbeddedOverAnotherVersionNeedsTheFlag(t *testing.T) {
	fb := &fakeBuilder{resolveFn: notFoundForTags}
	r := redeployProd(t, output.ModeHuman, fb, embeddedBy("v0.8.0", "go1.27.3"), nil)
	if kindOf(r.err) != kindVersionSkew {
		t.Fatalf("err = %v (kind %s), want version_skew", r.err, kindOf(r.err))
	}
	for _, want := range []string{"v0.8.0", testVersion, "go1.27.3", carriedGo, "--embedded"} {
		if !strings.Contains(r.err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, r.err)
		}
	}
	if len(fb.embedded) != 0 || len(r.fc.applied) != 0 {
		t.Errorf("pushed %d and applied %d before refusing", len(fb.embedded), len(r.fc.applied))
	}

	fb = &fakeBuilder{resolveFn: notFoundForTags}
	r = redeployProd(t, output.ModeHuman, fb, embeddedBy("v0.8.0", "go1.27.3"), func(c *redeployCommand) { c.embedded = true })
	noErr(t, r)
	if len(fb.embedded) == 0 || deployedImage(r.meta) != carriedRef("fatline") {
		t.Fatalf("--embedded did not push and deploy the carried image: pushed %d, deployed %q", len(fb.embedded), deployedImage(r.meta))
	}
	want := "fatline: replacing " + imageIn("fatline", "1") + ", deployed by farcast v0.8.0 (go1.27.3), with the image this farcast carries (go1.27.4)."
	if !strings.Contains(r.stderr, want) {
		t.Errorf("stderr does not say %q:\n%s", want, r.stderr)
	}

	// kernel deploy and storage deploy, which since ADR 0023 M2.6c decide
	// their image in their plan and realize it after consent: in a --yes
	// run the same guard refuses there, version_skew, before anything is
	// pushed or applied, and --embedded replaces the image, saying so.
	// (Under --confirm the plan is the consent to the replacement:
	// TestConfirmCoversTheReplacementItsPlanListed.)
	//
	// With the version tag foreign too, the refusal says nothing of the tag
	// (review C-F2): the skew was refused before the tag was looked up, and
	// the carried image is not pushed over it. --embedded pushes over it,
	// and says so.
	const foreignWarning = "Pushing the carried image over that tag."
	for _, tc := range []struct {
		component string
		run       func(t *testing.T, dir config.Dir, fb *fakeBuilder, fc *fakeCluster, embedded bool) (string, error)
		record    func(meta *config.InstanceMetadata, img string)
	}{
		{"technocore", func(t *testing.T, dir config.Dir, fb *fakeBuilder, fc *fakeCluster, embedded bool) (string, error) {
			c := testKernelDeploy(fc, fb)
			c.deployer.embedded = embedded
			env, _, errb := testEnvBoth(dir, output.ModeHuman)
			err := c.Run(t.Context(), env, []string{prodName})
			return errb.String(), err
		}, func(meta *config.InstanceMetadata, img string) { meta.Kernel = &config.Kernel{Image: img} }},
		{"datasphered", func(t *testing.T, dir config.Dir, fb *fakeBuilder, fc *fakeCluster, embedded bool) (string, error) {
			c := testStorageDeploy(&fakeProvider{}, fb)
			c.deployer.assumeYes, c.deployer.embedded = true, embedded
			c.deployer.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
			env, _, errb := testEnvBoth(dir, output.ModeHuman)
			err := c.Run(t.Context(), env, []string{prodName})
			return errb.String(), err
		}, func(meta *config.InstanceMetadata, img string) { meta.Keyholder = &config.Keyholder{Image: img} }},
	} {
		for _, tag := range []struct {
			name    string
			resolve func(string) (string, error)
		}{{"its tag missing", notFoundForTags}, {"its tag foreign", foreignForTags}} {
			for _, embedded := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s, %s, --embedded=%v", tc.component, tag.name, embedded), func(t *testing.T) {
					dir := config.Dir(t.TempDir())
					meta := deployableInstance(t, dir, prodName)
					old := imageIn(tc.component, "1")
					tc.record(meta, old)
					recordSystemImage(meta, tc.component, config.SystemImage{Image: old, Origin: config.OriginEmbedded, Go: "go1.27.3", Farcast: "v0.8.0"})
					if err := dir.SaveInstanceMetadata(prodName, meta); err != nil {
						t.Fatal(err)
					}
					fb, fc := &fakeBuilder{resolveFn: tag.resolve}, &fakeCluster{}
					stderr, err := tc.run(t, dir, fb, fc, embedded)
					if !embedded {
						if kindOf(err) != kindVersionSkew || !strings.Contains(err.Error(), tc.component+" runs "+old+", deployed by farcast v0.8.0 (go1.27.3)") ||
							!strings.Contains(err.Error(), "Pass --embedded to replace it.") {
							t.Fatalf("err = %v (kind %s), want version_skew naming %s", err, kindOf(err), old)
						}
						if len(fb.embedded)+len(fb.built)+len(fc.applied) != 0 {
							t.Errorf("pushed %d, built %d and applied %d before refusing", len(fb.embedded), len(fb.built), len(fc.applied))
						}
						if strings.Contains(stderr, foreignWarning) || strings.Contains(stderr, "points at") || strings.Contains(stderr, "replacing") {
							t.Errorf("said what it does not do before refusing the replacement:\n%s", stderr)
						}
						return
					}
					if err != nil {
						t.Fatalf("--embedded: %v", err)
					}
					after, _ := dir.LoadInstanceMetadata(prodName)
					if len(fb.embedded) != 1 || after.SystemImages[tc.component].Image != carriedRef(tc.component) {
						t.Errorf("--embedded pushed %d and recorded %+v; want the carried image", len(fb.embedded), after.SystemImages[tc.component])
					}
					if tag.name == "its tag foreign" && !strings.Contains(stderr, foreignWarning) {
						t.Errorf("--embedded pushed over a foreign tag without saying so:\n%s", stderr)
					}
				})
			}
		}
	}
}

// ADR 0023 decision 4, A23-34 (review M-M26B-MUT-06): an interactive or
// --yes run over another farcast version's image refuses with
// version_skew even when the version tag cannot be looked up, as it did
// when the skew was refused before the lookup: the skew stands in the
// decision, and comes before decide's error. Nothing is ensured, pushed,
// built or applied.
func TestSkewBeatsAFailedTagLookup(t *testing.T) {
	for _, dr := range deployRigs() {
		t.Run(dr.name, func(t *testing.T) {
			r := dr.rig(t, recorded(embeddedBy("v0.8.0", "go1.27.3")))
			r.fb.resolveFn = func(ref string) (string, error) {
				if strings.Contains(ref, "@sha256:") {
					return ref, nil
				}
				return "", errors.New("registry unavailable")
			}
			_, _, err := r.run(t, output.ModeHuman, "--yes")
			if kindOf(err) != kindVersionSkew {
				t.Errorf("%s --yes over another version's image, its tag unreadable = %v (kind %s); want version_skew", dr.name, err, kindOf(err))
			}
			if len(r.fp.ensured)+len(r.fb.embedded)+len(r.fb.built)+len(r.fc.applied) != 0 {
				t.Errorf("ensured %d, pushed %d, built %d, applied %d", len(r.fp.ensured), len(r.fb.embedded), len(r.fb.built), len(r.fc.applied))
			}
		})
	}
}

func TestSkewGuardSaysWhenGoGoesBack(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, embeddedBy("v1.0.0", "go1.28.1"), nil)
	if kindOf(r.err) != kindVersionSkew || !strings.Contains(r.err.Error(), "That replaces go1.28.1 with an older Go, go1.27.4.") {
		t.Fatalf("err = %v, want the skew refusal saying the Go goes back", r.err)
	}
	r = redeployProd(t, output.ModeHuman, &fakeBuilder{}, embeddedBy("v0.8.0", "go1.27.3"), nil)
	if strings.Contains(r.err.Error(), "older Go") {
		t.Errorf("a newer Go was called older: %v", r.err)
	}
}

func TestSameImageFromAnotherVersionIsNotSkew(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, func(meta *config.InstanceMetadata) {
		recordFatLine(meta, carriedRef("fatline"), config.SystemImage{Origin: config.OriginEmbedded, Go: carriedGo, Farcast: "v0.8.0"})
	}, nil)
	noErr(t, r)
	if rec := r.meta.SystemImages["fatline"]; rec.Farcast != testVersion || rec.Image != carriedRef("fatline") {
		t.Errorf("recorded %+v, want this farcast's version over the same image", rec)
	}
}

var namedFatLine = "registry.example/fatline@" + sha("c")

func namedBy(farcast string) func(*config.InstanceMetadata) {
	return func(meta *config.InstanceMetadata) {
		recordFatLine(meta, namedFatLine, config.SystemImage{Origin: config.OriginNamed, Farcast: farcast})
	}
}

func TestNamedImageOverAnotherVersionNeedsTheFlag(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, namedBy("v0.8.0"), nil)
	if kindOf(r.err) != kindVersionSkew || !strings.Contains(r.err.Error(), "its Go is not recorded") {
		t.Fatalf("err = %v, want version_skew saying the named image's Go is not recorded", r.err)
	}
	r = redeployProd(t, output.ModeHuman, &fakeBuilder{}, namedBy("v0.8.0"), func(c *redeployCommand) { c.embedded = true })
	noErr(t, r)
	if deployedImage(r.meta) != carriedRef("fatline") {
		t.Errorf("deployed %q", deployedImage(r.meta))
	}
}

func TestNamedImageReplacementIsSaid(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, namedBy(testVersion), nil)
	noErr(t, r)
	want := "fatline: replacing the named image " + namedFatLine + " with the image this farcast carries."
	if !strings.Contains(r.stderr, want) {
		t.Errorf("stderr does not say %q:\n%s", want, r.stderr)
	}
}

// notPinnedImages are image flag values rule 1 refuses (review finding
// SEC2-2): each would otherwise be written into a workload's YAML as it
// stands. No repository, no host, a space in the host and both newlines pass
// a check of the text after '@' alone (isDigestPinned).
var notPinnedImages = map[string]string{
	"a tag":                       "registry.example/repo/system/x:v1",
	"an uppercase digest":         "registry.example/f@sha256:" + strings.Repeat("A", 64),
	"no repository":               "@" + sha("a"),
	"no registry host":            "fatline@" + sha("a"),
	"a newline in the path":       "r.example/f\n          securityContext: {privileged: true}\n          x: r.example/f@" + sha("a"),
	"a newline in the host":       "r.example\n          securityContext: x/f@" + sha("a"),
	"surrounding space":           " r.example/f@" + sha("a") + "\n",
	"a space in the host":         "r.exa mple/f@" + sha("a"),
	"a digest a parser would cut": "r.example/f@" + sha("a") + "\t",
}

func TestIsPinnedImageRef(t *testing.T) {
	for _, ref := range []string{
		namedFatLine,
		imageIn("fatline", "c"),
		"localhost:5000/a/b@" + sha("1"),
		"registry.example:443/team/fatline:v1@" + sha("2"), // a tag beside the digest, which pins
	} {
		if !isPinnedImageRef(ref) {
			t.Errorf("refused %q", ref)
		}
	}
	for name, ref := range notPinnedImages {
		if isPinnedImageRef(ref) {
			t.Errorf("%s: accepted %q", name, ref)
		}
	}
}

func TestImageFlagsMustBeDigestPinned(t *testing.T) {
	emptyDir := func(t *testing.T) config.Dir { return config.Dir(t.TempDir()) }
	wantUsage := func(t *testing.T, err error, flag string, fb *fakeBuilder) {
		t.Helper()
		var ue *usageError
		if !errors.As(err, &ue) || !strings.Contains(err.Error(), flag) || !strings.Contains(err.Error(), "digest-pinned") {
			t.Fatalf("err = %v, want a usage error requiring %s to be digest-pinned", err, flag)
		}
		if len(fb.resolved) != 0 {
			t.Errorf("resolved %v before refusing", fb.resolved)
		}
	}
	for name, ref := range notPinnedImages {
		t.Run(name, func(t *testing.T) {
			t.Run("connect", func(t *testing.T) {
				fb := &fakeBuilder{}
				c := testConnect(&fakeProvider{}, fb)
				c.fatlineImage = ref
				env, _ := testEnv(emptyDir(t), output.ModeHuman)
				wantUsage(t, c.Run(context.Background(), env, []string{prodName}), "--fatline-image", fb)
			})
			t.Run("redeploy", func(t *testing.T) {
				fb := &fakeBuilder{}
				c := testRedeploy(&fakeProvider{}, fb)
				c.fatlineImage = ref
				env, _ := testEnv(emptyDir(t), output.ModeHuman)
				wantUsage(t, c.Run(context.Background(), env, []string{prodName}), "--fatline-image", fb)
			})
			t.Run("kernel deploy", func(t *testing.T) {
				fb := &fakeBuilder{}
				c := testKernelDeploy(&fakeCluster{}, fb)
				c.image = ref
				env, _ := testEnv(emptyDir(t), output.ModeHuman)
				wantUsage(t, c.Run(context.Background(), env, []string{prodName}), "--technocore-image", fb)
			})
			t.Run("storage deploy", func(t *testing.T) {
				fb := &fakeBuilder{}
				c := testStorageDeploy(&fakeProvider{}, fb)
				c.image = ref
				env, _ := testEnv(emptyDir(t), output.ModeHuman)
				wantUsage(t, c.Run(context.Background(), env, []string{prodName}), "--datasphered-image", fb)
			})
			// Rule 1 again where the image is decided, for a caller that
			// skipped the usage check.
			t.Run("decideImage", func(t *testing.T) {
				fb := &fakeBuilder{}
				c := testRedeploy(&fakeProvider{}, fb)
				c.fatlineImage = ref
				env, _ := testEnv(emptyDir(t), output.ModeHuman)
				got, err := c.decideImage(context.Background(), env, nil, &config.InstanceMetadata{Name: prodName})
				wantUsage(t, err, "--fatline-image", fb)
				if got.action != "" || got.target != "" {
					t.Errorf("decided %q on %q", got.action, got.target)
				}
			})
		})
	}
}

// operatorRecorded is an instance whose FatLine is an operator build.
func operatorRecorded(meta *config.InstanceMetadata) {
	recordFatLine(meta, imageIn("fatline", "a"), config.SystemImage{Origin: config.OriginOperator, Go: "go1.27.5",
		Farcast: "v0.8.0", BuiltAt: testBuiltAt, Source: "/home/op/farcast"})
}

func TestOperatorBuiltImageIsKeptAndReused(t *testing.T) {
	fb := &fakeBuilder{}
	r := redeployProd(t, output.ModeHuman, fb, operatorRecorded, nil)
	noErr(t, r)
	if !slices.Contains(fb.resolved, imageIn("fatline", "a")) {
		t.Errorf("the kept image was not looked up by digest: %v", fb.resolved)
	}
	if len(fb.embedded) != 0 || deployedImage(r.meta) != imageIn("fatline", "a") {
		t.Fatalf("pushed %d, deployed %q; an operator build is kept", len(fb.embedded), deployedImage(r.meta))
	}
	for _, want := range []string{"keeping the operator-built image " + imageIn("fatline", "a"), "go1.27.5", "carries go1.27.4", "--embedded"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr does not name %q:\n%s", want, r.stderr)
		}
	}
	if r.meta.SystemImages["fatline"].Origin != config.OriginOperator {
		t.Errorf("recorded %+v, want the operator build kept", r.meta.SystemImages["fatline"])
	}
}

func TestOperatorBuiltImageMissingIsRefused(t *testing.T) {
	missing := func(ref string) (string, error) {
		if ref == imageIn("fatline", "a") {
			return "", image.ErrNotFound
		}
		return pinnedRef(ref, tagDigest), nil
	}
	fb := &fakeBuilder{resolveFn: missing}
	r := redeployProd(t, output.ModeHuman, fb, operatorRecorded, nil)
	if r.err == nil || !strings.Contains(r.err.Error(), "--source") || !strings.Contains(r.err.Error(), "--embedded") {
		t.Fatalf("err = %v, want a refusal naming --source and --embedded", r.err)
	}
	if len(fb.embedded) != 0 || len(r.fc.applied) != 0 {
		t.Errorf("pushed %d and applied %d", len(fb.embedded), len(r.fc.applied))
	}
}

// A farcast built from source keeps a recorded operator build too, as its
// --help and the README say (rule 4; review finding RCK2-2-1): with no
// --source it builds only what it does not keep — here Shrike, which has no
// record.
func TestSourceFarcastKeepsAnOperatorBuild(t *testing.T) {
	fb := &fakeBuilder{}
	r := redeployProd(t, output.ModeHuman, fb, operatorRecorded, func(c *redeployCommand) {
		asSourceBuild(&c.fatlineDeployer, "dev")
		c.findSource = func(string) (string, error) { return "/work/farcast", nil }
		c.assumeYes = true
	})
	noErr(t, r)
	if deployedImage(r.meta) != imageIn("fatline", "a") {
		t.Fatalf("deployed %q, want the operator build %q kept", deployedImage(r.meta), imageIn("fatline", "a"))
	}
	if !slices.Contains(fb.resolved, imageIn("fatline", "a")) {
		t.Errorf("the kept image was not looked up by digest: %v", fb.resolved)
	}
	var repos []string
	for _, o := range fb.built {
		repos = append(repos, o.Repository)
	}
	if !slices.Equal(repos, []string{repoOf("shrike")}) {
		t.Errorf("built into %q, want Shrike's repository alone: the operator build is kept, not rebuilt", repos)
	}
	if got := r.meta.SystemImages["fatline"].Origin; got != config.OriginOperator {
		t.Errorf("recorded FatLine as %q, want the operator build kept", got)
	}
	for _, want := range []string{"keeping the operator-built image " + imageIn("fatline", "a"), "This farcast carries no components. Pass --source to rebuild it."} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr does not say %q:\n%s", want, r.stderr)
		}
	}
	if strings.Contains(r.stderr, "--embedded") {
		t.Errorf("stderr offers --embedded, which a source farcast refuses:\n%s", r.stderr)
	}
}

// On a farcast built from source a missing operator build names --source
// alone: --embedded is refused there, so naming it would offer a remedy that
// is itself refused (review finding RCK2-2-2).
func TestOperatorBuiltImageMissingOnASourceFarcastNamesOnlySource(t *testing.T) {
	missing := func(ref string) (string, error) {
		if ref == imageIn("fatline", "a") {
			return "", image.ErrNotFound
		}
		return ref, nil
	}
	fb := &fakeBuilder{resolveFn: missing}
	r := redeployProd(t, output.ModeHuman, fb, operatorRecorded, func(c *redeployCommand) {
		asSourceBuild(&c.fatlineDeployer, "dev")
		c.findSource = func(string) (string, error) { return "/work/farcast", nil }
		c.assumeYes = true
	})
	if r.err == nil {
		t.Fatal("a missing operator build was not refused")
	}
	msg := r.err.Error()
	if !strings.Contains(msg, "no longer in its registry") || !strings.Contains(msg, "--source <dir>") {
		t.Errorf("err = %v, want a refusal naming --source", r.err)
	}
	if strings.Contains(msg, "--embedded") {
		t.Errorf("err = %v names --embedded, which this farcast refuses", r.err)
	}
	if len(fb.built) != 0 || len(fb.embedded) != 0 || len(r.fc.applied) != 0 {
		t.Errorf("built %d, pushed %d and applied %d", len(fb.built), len(fb.embedded), len(r.fc.applied))
	}
	if deployedImage(r.meta) != imageIn("fatline", "a") || r.meta.SystemImages["fatline"].Origin != config.OriginOperator {
		t.Errorf("the record changed: deployed %q, %+v", deployedImage(r.meta), r.meta.SystemImages["fatline"])
	}
}

func TestEmbeddedReplacesAnOperatorBuiltImageAndSaysSo(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, operatorRecorded, func(c *redeployCommand) { c.embedded = true })
	noErr(t, r)
	if deployedImage(r.meta) != carriedRef("fatline") {
		t.Fatalf("deployed %q", deployedImage(r.meta))
	}
	want := "fatline: replacing the operator-built image " + imageIn("fatline", "a") + " (go1.27.5) with the image this farcast carries (go1.27.4)."
	if !strings.Contains(r.stderr, want) {
		t.Errorf("stderr does not say %q:\n%s", want, r.stderr)
	}
	if r.meta.SystemImages["fatline"].Origin != config.OriginEmbedded {
		t.Errorf("recorded %+v", r.meta.SystemImages["fatline"])
	}
}

func TestEmbeddedFlagRefusals(t *testing.T) {
	wantUsage := func(t *testing.T, err error, want string) {
		t.Helper()
		var ue *usageError
		if !errors.As(err, &ue) || !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want a usage error saying %q", err, want)
		}
	}
	for _, tc := range []struct {
		name      string
		configure func(*redeployCommand)
		want      string
	}{
		{"with --source", func(c *redeployCommand) { c.embedded, c.sourceDir = true, "/src" }, "--source builds a new one"},
		{"carrying nothing", func(c *redeployCommand) { asSourceBuild(&c.fatlineDeployer, "dev"); c.embedded = true }, "--embedded has nothing to deploy"},
		// Accepting --embedded beside --fatline-image (SEC-2) does not let it
		// past the refusal of a farcast with nothing to deploy.
		{"carrying nothing, beside --fatline-image", func(c *redeployCommand) {
			asSourceBuild(&c.fatlineDeployer, "dev")
			c.embedded, c.fatlineImage = true, namedFatLine
		}, "--embedded has nothing to deploy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, nil, tc.configure)
			wantUsage(t, r.err, tc.want)
			if len(r.fp.ensured) != 0 {
				t.Error("the registry was ensured before the usage error")
			}
		})
	}
	// An image flag that names the command's only component leaves --embedded
	// nothing to govern. On connect and redeploy --fatline-image does not, and
	// the pair is accepted: TestEmbeddedWithFatlineImageGovernsShrikeOnly.
	t.Run("with an image flag on kernel deploy", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		connectedInstance(t, dir, prodName)
		fb := &fakeBuilder{}
		c := testKernelDeploy(&fakeCluster{}, fb)
		opened := false
		c.deployer.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
			opened = true
			return &fakeProvider{}, nil
		}
		c.image, c.deployer.embedded = imageIn("technocore", "c"), true
		env, _ := testEnv(dir, output.ModeHuman)
		wantUsage(t, c.Run(context.Background(), env, []string{prodName}),
			"--embedded deploys the image this farcast carries and --technocore-image deploys an image as given; pass one or the other")
		if opened || len(fb.resolved) != 0 {
			t.Error("the provider was opened or an image looked up before the usage error")
		}
	})
	t.Run("with an image flag on storage deploy", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		connectedInstance(t, dir, prodName)
		fp, fb := &fakeProvider{}, &fakeBuilder{}
		c := testStorageDeploy(fp, fb)
		c.image, c.deployer.embedded = imageIn("datasphered", "c"), true
		env, _ := testEnv(dir, output.ModeHuman)
		wantUsage(t, c.Run(context.Background(), env, []string{prodName}),
			"--embedded deploys the image this farcast carries and --datasphered-image deploys an image as given; pass one or the other")
		if len(fp.ensured) != 0 || len(fb.resolved) != 0 {
			t.Error("the registry was ensured or an image looked up before the usage error")
		}
	})
	t.Run("connect to a connected instance", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		connectedInstance(t, dir, prodName)
		c := testConnect(&fakeProvider{}, &fakeBuilder{})
		c.embedded = true
		c.dial = connectedDial()
		env, _ := testEnv(dir, output.ModeHuman)
		wantUsage(t, c.Run(context.Background(), env, []string{prodName}), "farcast redeploy prod --embedded")
	})
}

// shrikeEmbeddedBy records Shrike as the image another farcast version
// carried. Shrike has no deploy record of its own: this is its only record.
func shrikeEmbeddedBy(farcast, goVersion string) func(*config.InstanceMetadata) {
	return func(meta *config.InstanceMetadata) {
		recordSystemImage(meta, components.Shrike.Name, config.SystemImage{
			Image: imageIn("shrike", "1"), Origin: config.OriginEmbedded, Go: goVersion, Farcast: farcast,
		})
	}
}

// On connect and redeploy --fatline-image names FatLine's image alone, so
// --embedded beside it governs Shrike's (design §1.3.8, review finding SEC-2).
// Before, a Shrike record from another farcast version refused the
// break-glass redeploy with "Pass --embedded to replace it", and --embedded
// was itself refused beside --fatline-image.
func TestEmbeddedWithFatlineImageGovernsShrikeOnly(t *testing.T) {
	given := imageIn("fatline", "c") // repo@sha256:<X>
	oldShrike := imageIn("shrike", "1")
	// Both components were deployed by farcast v0.8.0; FatLine's record is
	// never consulted under --fatline-image.
	setup := func(meta *config.InstanceMetadata) {
		embeddedBy("v0.8.0", "go1.27.3")(meta)
		shrikeEmbeddedBy("v0.8.0", "go1.27.3")(meta)
	}
	applied := func(fc *fakeCluster) string {
		var b strings.Builder
		for _, m := range fc.applied {
			b.Write(m)
		}
		return b.String()
	}
	refused := func(t *testing.T, err error, fb *fakeBuilder, fc *fakeCluster) {
		t.Helper()
		if kindOf(err) != kindVersionSkew {
			t.Fatalf("err = %v (kind %s), want version_skew", err, kindOf(err))
		}
		for _, want := range []string{"shrike runs " + oldShrike, "v0.8.0", testVersion, "go1.27.3", carriedGo, "Pass --embedded to replace it."} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not name %q: %v", want, err)
			}
		}
		if len(fb.embedded) != 0 || len(fb.built) != 0 || len(fc.applied) != 0 {
			t.Errorf("pushed %d, built %d and applied %d before refusing", len(fb.embedded), len(fb.built), len(fc.applied))
		}
	}
	replaced := func(t *testing.T, err error, stderr string, fb *fakeBuilder, fc *fakeCluster, meta *config.InstanceMetadata) {
		t.Helper()
		if err != nil {
			t.Fatalf("--embedded beside --fatline-image: %v\nstderr:\n%s", err, stderr)
		}
		m := applied(fc)
		if !strings.Contains(m, "image: "+given) || strings.Contains(m, carriedRef("fatline")) {
			t.Errorf("FatLine was not rendered with the image given (%s):\n%s", given, m)
		}
		if !strings.Contains(m, "image: "+carriedRef("shrike")) || strings.Contains(m, oldShrike) {
			t.Errorf("Shrike was not rendered with the image this farcast carries:\n%s", m)
		}
		var pushed []string
		for _, o := range fb.embedded {
			pushed = append(pushed, o.Ref)
		}
		if len(pushed) != 1 || pinnedRepository(pushed[0]) != repoOf("shrike") || len(fb.built) != 0 {
			t.Errorf("pushed %v and built %d, want Shrike's carried image pushed alone", pushed, len(fb.built))
		}
		for _, ref := range fb.resolved {
			if strings.Contains(ref, "system/fatline") {
				t.Errorf("looked up %s: FatLine's image is deployed as given", ref)
			}
		}
		want := "shrike: replacing " + oldShrike + ", deployed by farcast v0.8.0 (go1.27.3), with the image this farcast carries (go1.27.4)."
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not say %q:\n%s", want, stderr)
		}
		if strings.Contains(stderr, "fatline: replacing") {
			t.Errorf("the replacement note names FatLine:\n%s", stderr)
		}
		if got, want := meta.SystemImages["fatline"], (config.SystemImage{Image: given, Origin: config.OriginNamed, Farcast: testVersion}); got != want {
			t.Errorf("FatLine recorded %+v, want %+v", got, want)
		}
		if got, want := meta.SystemImages["shrike"], (config.SystemImage{Image: carriedRef("shrike"), Origin: config.OriginEmbedded, Go: carriedGo, Farcast: testVersion}); got != want {
			t.Errorf("Shrike recorded %+v, want %+v", got, want)
		}
	}

	// With no registry, --embedded has nothing to take Shrike's image from:
	// refused before anything is applied or pushed, and no record moves
	// (review findings SEC2-1, CON2-2). Without it, FatLine deploys alone
	// (TestShrikeRecordIsDroppedWhenFatLineDeploysAlone).
	noRegistry := func(t *testing.T, r deployRun) {
		t.Helper()
		if r.err == nil {
			t.Fatalf("--embedded beside --fatline-image with no registry was accepted\nstderr:\n%s", r.stderr)
		}
		for _, want := range []string{"--embedded governs Shrike's image", "drop --embedded to deploy FatLine alone", "permission denied"} {
			if !strings.Contains(r.err.Error(), want) {
				t.Errorf("the refusal does not say %q: %v", want, r.err)
			}
		}
		if len(r.fc.applied) != 0 || len(r.fb.embedded) != 0 || len(r.fb.built) != 0 {
			t.Errorf("applied %d, pushed %d and built %d before refusing", len(r.fc.applied), len(r.fb.embedded), len(r.fb.built))
		}
		if strings.Contains(r.stderr, "deploying FatLine alone") {
			t.Errorf("said it deploys FatLine alone:\n%s", r.stderr)
		}
		want := config.SystemImage{Image: oldShrike, Origin: config.OriginEmbedded, Go: "go1.27.3", Farcast: "v0.8.0"}
		if got := r.meta.SystemImages["shrike"]; got != want {
			t.Errorf("Shrike's record is %+v, want it unchanged: %+v", got, want)
		}
		if got := r.meta.SystemImages["fatline"]; got.Image != imageIn("fatline", "1") || got.Farcast != "v0.8.0" {
			t.Errorf("FatLine's record is %+v, want it unchanged", got)
		}
	}
	permissionDenied := func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return &fakeProvider{ensureErr: errors.New("permission denied")}, nil
	}

	t.Run("redeploy", func(t *testing.T) {
		fb := &fakeBuilder{resolveFn: notFoundForTags}
		r := redeployProd(t, output.ModeHuman, fb, setup, func(c *redeployCommand) { c.fatlineImage = given })
		refused(t, r.err, fb, r.fc)

		fb = &fakeBuilder{resolveFn: notFoundForTags}
		r = redeployProd(t, output.ModeHuman, fb, setup, func(c *redeployCommand) { c.fatlineImage, c.embedded = given, true })
		replaced(t, r.err, r.stderr, fb, r.fc, r.meta)
	})
	t.Run("redeploy with no registry", func(t *testing.T) {
		r := redeployProd(t, output.ModeHuman, &fakeBuilder{resolveFn: notFoundForTags}, setup, func(c *redeployCommand) {
			c.fatlineImage, c.embedded = given, true
			c.openProvider = permissionDenied
		})
		noRegistry(t, r)
		if previous := deployedImage(r.meta); previous != imageIn("fatline", "1") {
			t.Errorf("the deploy record moved to %q", previous)
		}
	})

	// A connect that deploys FatLine: the instance is not connected yet, and
	// holds the records of an earlier deploy, such as a bootstrap that failed
	// after its apply.
	connectProd := func(t *testing.T, embedded bool, fp *fakeProvider) deployRun {
		t.Helper()
		dir := config.Dir(t.TempDir())
		meta := installedInstance(t, dir, prodName)
		setup(meta)
		if err := dir.SaveInstanceMetadata(prodName, meta); err != nil {
			t.Fatal(err)
		}
		fb, fc := &fakeBuilder{resolveFn: notFoundForTags}, &fakeCluster{ip: "203.0.113.1"}
		c := testConnect(fp, fb)
		c.assumeYes = true
		c.fatlineImage, c.embedded = given, embedded
		c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
		c.dial = connectedDial()
		env, out, errb := testEnvBoth(dir, output.ModeHuman)
		err := c.Run(context.Background(), env, []string{prodName})
		after, lerr := dir.LoadInstanceMetadata(prodName)
		if lerr != nil {
			t.Fatal(lerr)
		}
		return deployRun{err: err, fb: fb, fc: fc, fp: fp, stderr: errb.String(), stdout: out.String(), meta: after}
	}
	t.Run("connect", func(t *testing.T) {
		r := connectProd(t, false, &fakeProvider{})
		refused(t, r.err, r.fb, r.fc)
		if r.meta.FatLineDeployed {
			t.Error("a refused connect recorded FatLine as deployed")
		}

		r = connectProd(t, true, &fakeProvider{})
		replaced(t, r.err, r.stderr, r.fb, r.fc, r.meta)
		if !r.meta.FatLineDeployed || deployedImage(r.meta) != given {
			t.Errorf("connect recorded deployed=%v image %q, want %s", r.meta.FatLineDeployed, deployedImage(r.meta), given)
		}
	})
	t.Run("connect with no registry", func(t *testing.T) {
		r := connectProd(t, true, &fakeProvider{ensureErr: errors.New("permission denied")})
		noRegistry(t, r)
		if r.meta.FatLineDeployed || r.meta.Carrier != nil {
			t.Errorf("a refused connect recorded deployed=%v carrier %+v", r.meta.FatLineDeployed, r.meta.Carrier)
		}
	})
	// The belt and braces in decideSidecarImage, for a caller that reached
	// it with no registry. Deciding says nothing: the break-glass lines are
	// the decision's notices, and realizing it deploys no Shrike.
	t.Run("decideSidecarImage", func(t *testing.T) {
		c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
		c.fatlineImage, c.embedded = given, true
		env, out, errb := testEnvBoth(config.Dir(t.TempDir()), output.ModeHuman)
		got, err := c.decideSidecarImage(context.Background(), env, nil, &config.InstanceMetadata{Name: prodName})
		if err == nil || !strings.Contains(err.Error(), "drop --embedded to deploy FatLine alone") || got.action != "" {
			t.Fatalf("decided %q, %v; want the refusal", got.action, err)
		}
		c.embedded = false
		got, err = c.decideSidecarImage(context.Background(), env, nil, &config.InstanceMetadata{Name: prodName})
		if err != nil || got.action != "" || len(got.notices) != 2 || !strings.Contains(got.notices[0], "deploying FatLine alone") {
			t.Fatalf("decided %q with notices %q, %v; want FatLine alone, said", got.action, got.notices, err)
		}
		if out.Len() != 0 || errb.Len() != 0 {
			t.Errorf("deciding printed:\n%s%s", out.String(), errb.String())
		}
		res, err := c.realizeSidecarImage(context.Background(), env, nil, got)
		if err != nil || res != (resolvedImage{}) {
			t.Fatalf("realized %+v, %v; want no Shrike image and no record", res, err)
		}
	})
}

func TestKernelAndStorageRefuseAnImageAndSource(t *testing.T) {
	want := "deploys an image as given and --source builds a new one; pass one or the other"
	kc := testKernelDeploy(&fakeCluster{}, &fakeBuilder{})
	kc.image, kc.deployer.sourceDir = imageIn("technocore", "c"), "/src"
	env, _ := testEnv(config.Dir(t.TempDir()), output.ModeHuman)
	var ue *usageError
	if err := kc.Run(context.Background(), env, []string{prodName}); !errors.As(err, &ue) || !strings.Contains(err.Error(), "--technocore-image "+want) {
		t.Errorf("kernel deploy: %v", err)
	}
	sc := testStorageDeploy(&fakeProvider{}, &fakeBuilder{})
	sc.image, sc.deployer.sourceDir = imageIn("datasphered", "c"), "/src"
	if err := sc.Run(context.Background(), env, []string{prodName}); !errors.As(err, &ue) || !strings.Contains(err.Error(), "--datasphered-image "+want) {
		t.Errorf("storage deploy: %v", err)
	}
}

func TestSourceBuildWithoutCarriedComponentsStillCompiles(t *testing.T) {
	var asked []string
	source := func(c *redeployCommand) {
		asSourceBuild(&c.fatlineDeployer, "dev")
		c.findSource = func(d string) (string, error) { asked = append(asked, d); return "/work/farcast", nil }
	}
	// Without --yes, unattended: the build confirmation is what answers.
	fb := &fakeBuilder{}
	r := redeployProd(t, output.ModeHuman, fb, nil, func(c *redeployCommand) { source(c); c.assumeYes = false })
	var ue *usageError
	if !errors.As(r.err, &ue) || !strings.Contains(r.err.Error(), "/work/farcast") || !strings.Contains(r.err.Error(), "--yes") {
		t.Fatalf("err = %v, want the build confirmation's refusal", r.err)
	}
	if len(fb.built) != 0 {
		t.Error("built without confirmation")
	}
	// With it, the image is compiled from the auto-detected checkout, and no
	// version tag is looked up: a source build's version names no image.
	fb = &fakeBuilder{}
	asked = nil
	r = redeployProd(t, output.ModeHuman, fb, nil, source)
	noErr(t, r)
	if len(fb.built) != 2 || len(asked) == 0 || asked[0] != "" {
		t.Fatalf("built %d from %q, want both from the auto-detected checkout", len(fb.built), asked)
	}
	for _, ref := range fb.resolved {
		if !strings.Contains(ref, "@sha256:") {
			t.Errorf("looked up the tag %s", ref)
		}
	}
}

// The version-skew guard and --embedded belong to a farcast that carries
// components (rule 5). A farcast built from source carries none, so it
// compiles over an image another farcast version deployed, with its build
// confirmation as the only gate (rule 6), which --yes answers. The documents
// say so (review finding DOC2-3); this pins it.
func TestSourceBuildReplacesAReleaseImageAfterItsBuildConfirmation(t *testing.T) {
	setup := func(meta *config.InstanceMetadata) {
		embeddedBy("v0.8.0", "go1.27.3")(meta)
		shrikeEmbeddedBy("v0.8.0", "go1.27.3")(meta)
	}
	source := func(c *redeployCommand) {
		asSourceBuild(&c.fatlineDeployer, "dev")
		c.findSource = func(string) (string, error) { return "/work/farcast", nil }
	}
	fb := &fakeBuilder{}
	r := redeployProd(t, output.ModeHuman, fb, setup, func(c *redeployCommand) { source(c); c.assumeYes = false })
	var ue *usageError
	if !errors.As(r.err, &ue) || !strings.Contains(r.err.Error(), "--yes to build it") || len(fb.built) != 0 {
		t.Fatalf("err = %v, built %d; want the build confirmation's refusal", r.err, len(fb.built))
	}
	fb = &fakeBuilder{}
	r = redeployProd(t, output.ModeHuman, fb, setup, source)
	noErr(t, r)
	if len(fb.built) != 2 || kindOf(r.err) == kindVersionSkew {
		t.Fatalf("built %d; want both compiled over the release's images", len(fb.built))
	}
	for _, name := range []string{"fatline", "shrike"} {
		if got := r.meta.SystemImages[name]; got.Origin != config.OriginDevelopment || got.Image == imageIn(name, "1") {
			t.Errorf("%s recorded %+v, want a development build", name, got)
		}
	}
}

func TestNamedImageIsRecordedAsNamed(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, nil, func(c *redeployCommand) { c.fatlineImage = namedFatLine })
	noErr(t, r)
	want := config.SystemImage{Image: namedFatLine, Origin: config.OriginNamed, Farcast: testVersion}
	if got := r.meta.SystemImages["fatline"]; got != want {
		t.Errorf("recorded %+v, want %+v", got, want)
	}
}

func TestShrikeImageIsRecorded(t *testing.T) {
	want := config.SystemImage{Image: carriedRef("shrike"), Origin: config.OriginEmbedded, Go: carriedGo, Farcast: testVersion}
	t.Run("connect", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		installedInstance(t, dir, prodName)
		fc := &fakeCluster{ip: "203.0.113.1"}
		c := testConnect(&fakeProvider{}, &fakeBuilder{})
		c.assumeYes = true
		c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
		c.dial = connectedDial()
		env, _ := testEnv(dir, output.ModeHuman)
		if err := c.Run(context.Background(), env, []string{prodName}); err != nil {
			t.Fatal(err)
		}
		meta, _ := dir.LoadInstanceMetadata(prodName)
		if got := meta.SystemImages["shrike"]; got != want {
			t.Errorf("recorded %+v, want %+v", got, want)
		}
		if !bytes.Contains(fc.applied[0], []byte(want.Image)) {
			t.Error("the recorded Shrike image is not the one deployed")
		}
	})
	t.Run("redeploy", func(t *testing.T) {
		r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, nil, nil)
		noErr(t, r)
		if got := r.meta.SystemImages["shrike"]; got != want {
			t.Errorf("recorded %+v, want %+v", got, want)
		}
	})
}

func TestShrikeRecordIsDroppedWhenFatLineDeploysAlone(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, func(meta *config.InstanceMetadata) {
		recordSystemImage(meta, "shrike", config.SystemImage{Image: carriedRef("shrike"), Origin: config.OriginEmbedded, Go: carriedGo, Farcast: testVersion})
	}, func(c *redeployCommand) {
		c.fatlineImage = namedFatLine
		c.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
			return &fakeProvider{ensureErr: errors.New("permission denied")}, nil
		}
	})
	noErr(t, r)
	if _, ok := r.meta.SystemImages["shrike"]; ok {
		t.Errorf("FatLine deployed alone, and the Shrike record stayed: %+v", r.meta.SystemImages)
	}
	if strings.Contains(r.applied(), "system/shrike") {
		t.Error("Shrike was deployed")
	}
}

func TestUnknownOriginReplacementIsSaid(t *testing.T) {
	r := redeployProd(t, output.ModeHuman, &fakeBuilder{}, func(meta *config.InstanceMetadata) {
		recordFatLine(meta, imageIn("fatline", "1"), config.SystemImage{})
	}, nil)
	noErr(t, r)
	want := "fatline: replacing " + imageIn("fatline", "1") + " (its origin is not recorded on this machine)."
	if !strings.Contains(r.stderr, want) {
		t.Errorf("stderr does not say %q:\n%s", want, r.stderr)
	}
}

// The decide/realize split (ADR 0023 M2.6, A23-34). Every action of rules
// 1–6 is decided, then realized, against the fake registry, with each phase
// counted apart: deciding mints the registry token and looks up, and never
// pushes, builds or prints; realizing pushes or builds and never looks
// anything up again, and for a named, kept or reused image it makes no
// registry call at all.

// countingRegistry is the fake provider, counting the registry tokens it
// mints.
type countingRegistry struct {
	*fakeProvider
	tokens int
}

func (r *countingRegistry) RegistryToken(ctx context.Context) (planck.RegistryToken, error) {
	r.tokens++
	return r.fakeProvider.RegistryToken(ctx)
}

// imageCalls is what one phase asked of the registry.
type imageCalls struct{ tokens, resolves, pushes, builds int }

func imageCallsOf(fb *fakeBuilder, reg *countingRegistry) imageCalls {
	return imageCalls{tokens: reg.tokens, resolves: len(fb.resolved), pushes: len(fb.embedded), builds: len(fb.built)}
}

func (a imageCalls) minus(b imageCalls) imageCalls {
	return imageCalls{tokens: a.tokens - b.tokens, resolves: a.resolves - b.resolves, pushes: a.pushes - b.pushes, builds: a.builds - b.builds}
}

// fakeToolchain is the Go a source build in these tests compiles with.
func fakeToolchain(context.Context, []string, string) (image.Toolchain, error) {
	return image.Toolchain{Go: "/usr/local/go/bin/go", Version: "go1.27.5"}, nil
}

// noToolchain is a machine with no Go on its PATH.
func noToolchain(context.Context, []string, string) (image.Toolchain, error) {
	return image.Toolchain{}, image.ErrNoGo
}

// prodRegistry is prod's registry in the fake provider, counting its tokens.
func prodRegistry() (*registryAccess, *countingRegistry) {
	cr := &countingRegistry{fakeProvider: &fakeProvider{}}
	return &registryAccess{provider: cr, registry: derivedRegistry(planck.RegistrySpec{Name: prodName, Location: "us-central1"})}, cr
}

func TestDecideAndRealizeEveryImageAction(t *testing.T) {
	const source = "/work/farcast"
	foreignTag := func(ref string) (string, error) {
		if strings.Contains(ref, "@sha256:") {
			return ref, nil
		}
		return pinnedRef(ref, "f"), nil
	}
	missing := func(gone string) func(string) (string, error) {
		return func(ref string) (string, error) {
			if ref == gone {
				return "", image.ErrNotFound
			}
			return pinnedRef(ref, tagDigest), nil
		}
	}
	sourceBuild := func(d *fatlineDeployer) { asSourceBuild(d, "dev") }
	built := func(component, origin, farcast string) config.SystemImage {
		return config.SystemImage{Image: pinnedRef(repoOf(component), "b"), Origin: origin, Go: "go1.27.5", Farcast: farcast, BuiltAt: testBuiltAt, Source: source}
	}
	carried := func(component string) config.SystemImage {
		return config.SystemImage{Image: carriedRef(component), Origin: config.OriginEmbedded, Go: carriedGo, Farcast: testVersion}
	}
	operatorRec := config.SystemImage{Image: imageIn("fatline", "a"), Origin: config.OriginOperator, Go: "go1.27.5",
		Farcast: "v0.8.0", BuiltAt: testBuiltAt, Source: "/home/op/farcast"}
	developmentRec := config.SystemImage{Image: imageIn("fatline", "d"), Origin: config.OriginDevelopment, Go: "go1.27.5",
		Farcast: "dev", BuiltAt: testBuiltAt, Source: "/work/farcast"}
	toolchain := imageSource{dir: source, goPath: "/usr/local/go/bin/go", goVersion: "go1.27.5"}
	lookedUp, minted := imageCalls{tokens: 1, resolves: 1}, imageCalls{tokens: 1}

	for _, row := range []struct {
		name       string
		shrike     bool // decided and realized as connect and redeploy do Shrike's
		setup      func(*config.InstanceMetadata)
		configure  func(*fatlineDeployer)
		resolve    func(string) (string, error)
		noRegistry bool

		decided   imageCalls
		decideErr string // the refusal; the row ends with it
		action    string
		target    string
		tagRef    string
		source    imageSource
		notices   []string
		replacing string
		replaces  bool // rule 5b

		realized imageCalls
		progress string // what realizing says on a verbose run
		record   config.SystemImage
	}{
		{name: "rule 1: named", configure: func(d *fatlineDeployer) { d.fatlineImage = namedFatLine }, noRegistry: true,
			action: plan.ImageNamed, target: namedFatLine,
			record: config.SystemImage{Image: namedFatLine, Origin: config.OriginNamed, Farcast: testVersion}},
		{name: "rule 2: no registry", noRegistry: true,
			decideErr: "no image registry for this instance and no --fatline-image given"},
		{name: "rule 3: build_source", configure: func(d *fatlineDeployer) { d.sourceDir = source },
			decided: minted, action: plan.ImageBuildSource, source: toolchain,
			realized: imageCalls{tokens: 1, builds: 1}, record: built("fatline", config.OriginOperator, testVersion)},
		{name: "rule 4: keep_operator", setup: operatorRecorded,
			decided: lookedUp, action: plan.ImageKeepOperator, target: imageIn("fatline", "a"),
			notices: []string{"fatline: keeping the operator-built image " + imageIn("fatline", "a") +
				" (go1.27.5, built 2026-11-13T12:00:00Z by farcast v0.8.0 from /home/op/farcast). This farcast carries go1.27.4. Pass --embedded to replace it, or --source to rebuild it."},
			record: operatorRec},
		{name: "rule 4: keep_development", setup: developmentRecorded, configure: sourceBuild,
			decided: lookedUp, action: plan.ImageKeepDevelopment, target: imageIn("fatline", "d"),
			notices: []string{"fatline: keeping the development image " + imageIn("fatline", "d") +
				" (go1.27.5, built 2026-11-13T12:00:00Z by farcast dev from /work/farcast). This farcast carries no components. Pass --source to rebuild it."},
			record: developmentRec},
		{name: "rule 4: a missing development build, then rule 6", setup: developmentRecorded, configure: sourceBuild,
			resolve: missing(imageIn("fatline", "d")),
			decided: lookedUp, action: plan.ImageBuildDevelopment, source: toolchain,
			notices:  []string{"fatline: the development image " + imageIn("fatline", "d") + " is no longer in the registry; building it again."},
			realized: imageCalls{tokens: 1, builds: 1}, record: built("fatline", config.OriginDevelopment, "dev")},
		{name: "rule 4: a missing operator build", setup: operatorRecorded, resolve: missing(imageIn("fatline", "a")),
			decided: lookedUp, decideErr: "the operator-built fatline image " + imageIn("fatline", "a") + " recorded for this instance is no longer in its registry"},
		{name: "rule 5: push", resolve: notFoundForTags,
			decided: lookedUp, action: plan.ImagePush, target: carriedRef("fatline"), tagRef: instanceImageRef(prodName),
			realized: imageCalls{tokens: 1, pushes: 1},
			progress: "  fatline: pushing the image this farcast carries (go1.27.4, " + sha(tagDigest) + ")\n", record: carried("fatline")},
		{name: "rule 5: reuse",
			decided: lookedUp, action: plan.ImageReuse, target: carriedRef("fatline"), tagRef: instanceImageRef(prodName),
			progress: "  fatline: " + instanceImageRef(prodName) + " already holds the image this farcast carries\n", record: carried("fatline")},
		{name: "rule 5: push_over_foreign", resolve: foreignTag,
			decided: lookedUp, action: plan.ImagePushOverForeign, target: carriedRef("fatline"), tagRef: instanceImageRef(prodName),
			notices: []string{"warning: " + instanceImageRef(prodName) + " points at " + sha("f") + ", which is not the fatline image this farcast carries (" +
				sha(tagDigest) + "); it will not be deployed. Pushing the carried image over that tag."},
			realized: imageCalls{tokens: 1, pushes: 1},
			progress: "  fatline: pushing the image this farcast carries (go1.27.4, " + sha(tagDigest) + ")\n", record: carried("fatline")},
		{name: "rule 5b: the carried image replaces another version's", setup: embeddedBy("v0.8.0", "go1.27.3"), resolve: notFoundForTags,
			decided: lookedUp, action: plan.ImagePush, target: carriedRef("fatline"), tagRef: instanceImageRef(prodName), replaces: true,
			replacing: "fatline: replacing " + imageIn("fatline", "1") + ", deployed by farcast v0.8.0 (go1.27.3), with the image this farcast carries (go1.27.4).",
			realized:  imageCalls{tokens: 1, pushes: 1},
			progress:  "  fatline: pushing the image this farcast carries (go1.27.4, " + sha(tagDigest) + ")\n", record: carried("fatline")},
		{name: "rule 5: a component this farcast does not carry", configure: func(d *fatlineDeployer) {
			c := newFakeCarried()
			delete(c.arts, "fatline")
			d.carried = c
		}, decided: minted, decideErr: "this farcast carries no fatline component"},
		{name: "rule 6: build_development", configure: sourceBuild,
			decided: minted, action: plan.ImageBuildDevelopment, source: toolchain,
			realized: imageCalls{tokens: 1, builds: 1}, record: built("fatline", config.OriginDevelopment, "dev")},
		{name: "Shrike, rule 5: push", shrike: true, configure: func(d *fatlineDeployer) { d.fatlineImage = namedFatLine },
			resolve: notFoundForTags,
			decided: lookedUp, action: plan.ImagePush, target: carriedRef("shrike"), tagRef: repoOf("shrike") + ":" + testVersion,
			realized: imageCalls{tokens: 1, pushes: 1},
			progress: "  shrike: pushing the image this farcast carries (go1.27.4, " + sha(tagDigest) + ")\n", record: carried("shrike")},
		{name: "Shrike, rule 6: build_development", shrike: true, configure: sourceBuild,
			decided: minted, action: plan.ImageBuildDevelopment, source: toolchain,
			realized: imageCalls{tokens: 1, builds: 1}, record: built("shrike", config.OriginDevelopment, "dev")},
	} {
		t.Run(row.name, func(t *testing.T) {
			fb := &fakeBuilder{resolveFn: row.resolve}
			c := testRedeploy(&fakeProvider{}, fb)
			d := &c.fatlineDeployer
			d.findSource = func(string) (string, error) { return source, nil }
			d.findToolchain = fakeToolchain
			if row.configure != nil {
				row.configure(d)
			}
			d.ensureDefaults()
			meta := &config.InstanceMetadata{Name: prodName, Region: "us-central1"}
			if row.setup != nil {
				row.setup(meta)
			}
			reg, cr := prodRegistry()
			if row.noRegistry {
				reg = nil
			}
			env, out, errb := testEnvBoth(config.Dir(t.TempDir()), output.ModeHuman)
			env.Verbose = true // so that a progress line decide printed would show

			decide, realize := d.decideImage, d.realizeImage
			if row.shrike {
				decide, realize = d.decideSidecarImage, d.realizeSidecarImage
			}
			before := imageCallsOf(fb, cr)
			dec, err := decide(context.Background(), env, reg, meta)
			decided := imageCallsOf(fb, cr).minus(before)
			if decided != row.decided {
				t.Errorf("deciding asked %+v of the registry, want %+v", decided, row.decided)
			}
			if out.Len() != 0 || errb.Len() != 0 {
				t.Errorf("deciding printed:\n%s%s", out.String(), errb.String())
			}
			if row.decideErr != "" {
				if err == nil || !strings.Contains(err.Error(), row.decideErr) {
					t.Fatalf("decide = %v, want the refusal %q", err, row.decideErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("decide: %v", err)
			}
			if dec.action != row.action || dec.target != row.target || dec.tagRef != row.tagRef || dec.source != row.source {
				t.Errorf("decided %q on %q (tag %q, source %+v), want %q on %q (tag %q, source %+v)",
					dec.action, dec.target, dec.tagRef, dec.source, row.action, row.target, row.tagRef, row.source)
			}
			wantComponent := "fatline"
			if row.shrike {
				wantComponent = "shrike"
			}
			if dec.component.Name != wantComponent || (!row.noRegistry && dec.repo != repoOf(wantComponent)) {
				t.Errorf("decided for %q in %q, want %q in %q", dec.component.Name, dec.repo, wantComponent, repoOf(wantComponent))
			}
			if !slices.Equal(dec.notices, row.notices) || dec.replacing != row.replacing {
				t.Errorf("notices %q and replacement %q,\nwant %q and %q", dec.notices, dec.replacing, row.notices, row.replacing)
			}
			refusal := dec.skewRefusal(false)
			if dec.replacesOther != row.replaces || (refusal != nil) != row.replaces || (refusal != nil && kindOf(refusal) != kindVersionSkew) ||
				dec.skewRefusal(true) != nil {
				t.Errorf("replaces another version: %v, refusal %v; want %v, and none with --embedded", dec.replacesOther, refusal, row.replaces)
			}
			if row.replaces && dec.previous != imageIn("fatline", "1") {
				t.Errorf("the replaced image is %q", dec.previous)
			}

			before = imageCallsOf(fb, cr)
			res, err := realize(context.Background(), env, reg, dec)
			if err != nil {
				t.Fatalf("realize: %v", err)
			}
			realized := imageCallsOf(fb, cr).minus(before)
			if realized != row.realized {
				t.Errorf("realizing asked %+v of the registry, want %+v", realized, row.realized)
			}
			if got := errb.String(); got != row.progress || out.Len() != 0 {
				t.Errorf("realizing printed %q on stderr and %q on stdout, want %q", got, out.String(), row.progress)
			}
			wantRef := row.target
			if dec.builds() {
				wantRef = row.record.Image
				if got := fb.built[len(fb.built)-1]; got.SourceDir != source || got.Repository != repoOf(wantComponent) || got.Package != dec.component.Package {
					t.Errorf("built %+v", got)
				}
			}
			if res.Ref != wantRef || res.Record != row.record {
				t.Errorf("realized %q recorded as %+v,\nwant %q recorded as %+v", res.Ref, res.Record, wantRef, row.record)
			}
		})
	}

	// A push the registry answers with another digest is refused: what is
	// deployed is the digest this farcast was released with, never the
	// registry's word for it.
	t.Run("rule 5: a push that lands another image", func(t *testing.T) {
		fb := &fakeBuilder{resolveFn: notFoundForTags, pushedRef: imageIn("fatline", "9")}
		c := testRedeploy(&fakeProvider{}, fb)
		d := &c.fatlineDeployer
		d.ensureDefaults()
		reg, _ := prodRegistry()
		env, _ := testEnv(config.Dir(t.TempDir()), output.ModeHuman)
		dec, err := d.decideImage(context.Background(), env, reg, &config.InstanceMetadata{Name: prodName, Region: "us-central1"})
		if err != nil || dec.action != plan.ImagePush {
			t.Fatalf("decided %q, %v", dec.action, err)
		}
		res, err := d.realizeImage(context.Background(), env, reg, dec)
		want := "pushed " + instanceImageRef(prodName) + " as " + imageIn("fatline", "9") + ", not the " + carriedRef("fatline") + " this farcast carries"
		if err == nil || err.Error() != want || res != (resolvedImage{}) {
			t.Fatalf("realized %q, %v; want %q", res.Ref, err, want)
		}
	})
}

// kernel deploy and storage deploy decide in their plan, and say what the
// resolution always said, in the same order: the decision's notices
// (imageDecision.say), before anything is asked; then, once the cost is
// agreed, the build prompt (buildConsent), the push's progress, and the
// replacement note once the image is in the registry (realizeAndNote).
// (Until ADR 0023 M2.6c storage deploy decided and realized at once,
// through resolveImage, and printed the notices after the cost question.)
func TestDecidedImageSaysItsLinesInTheirOrder(t *testing.T) {
	resolve := func(t *testing.T, mode output.Mode, in io.Reader, fb *fakeBuilder, setup func(*config.InstanceMetadata), configure func(*fatlineDeployer)) (resolvedImage, string, error) {
		t.Helper()
		c := testRedeploy(&fakeProvider{}, fb)
		d := &c.fatlineDeployer
		d.findSource = func(string) (string, error) { return "/work/farcast", nil }
		d.findToolchain = fakeToolchain
		if configure != nil {
			configure(d)
		}
		d.ensureDefaults()
		meta := &config.InstanceMetadata{Name: prodName, Region: "us-central1"}
		setup(meta)
		reg, _ := prodRegistry()
		env, _, errb := testEnvBoth(config.Dir(t.TempDir()), mode)
		env.Verbose = true
		if in != nil {
			env.In = in
		}
		res, err := settledImage(context.Background(), env, d, reg, meta)
		return res, errb.String(), err
	}
	inOrder := func(t *testing.T, stderr string, lines ...string) {
		t.Helper()
		at := -1
		for _, l := range lines {
			i := strings.Index(stderr, l)
			if i <= at {
				t.Fatalf("stderr does not say %q after what came before it:\n%s", l, stderr)
			}
			at = i
		}
	}

	t.Run("an ignored record, the push and the replacement", func(t *testing.T) {
		evil := "evil.example/x@" + sha("0")
		res, stderr, err := resolve(t, output.ModeHuman, nil, &fakeBuilder{resolveFn: notFoundForTags}, func(meta *config.InstanceMetadata) {
			recordFatLine(meta, evil, config.SystemImage{Origin: config.OriginOperator, Go: "go1.27.5", Farcast: testVersion, Source: "/x"})
		}, nil)
		if err != nil || res.Ref != carriedRef("fatline") {
			t.Fatalf("resolved %q, %v", res.Ref, err)
		}
		inOrder(t, stderr,
			"fatline: ignoring the recorded origin of "+evil+": it is not in this instance's registry "+repoOf("fatline")+"\n",
			"  fatline: pushing the image this farcast carries (go1.27.4, "+sha(tagDigest)+")\n",
			"fatline: replacing "+evil+" (its origin is not recorded on this machine).\n")
	})
	t.Run("a foreign tag, the push and the replacement", func(t *testing.T) {
		_, stderr, err := resolve(t, output.ModeJSON, nil, &fakeBuilder{resolveFn: func(ref string) (string, error) {
			if strings.Contains(ref, "@sha256:") {
				return ref, nil
			}
			return pinnedRef(ref, "f"), nil
		}}, namedBy(testVersion), nil)
		if err != nil {
			t.Fatal(err)
		}
		inOrder(t, stderr,
			"warning: "+instanceImageRef(prodName)+" points at "+sha("f"),
			"  fatline: pushing the image this farcast carries",
			"fatline: replacing the named image "+namedFatLine+" with the image this farcast carries.\n")
	})
	t.Run("a reused tag and the replacement", func(t *testing.T) {
		_, stderr, err := resolve(t, output.ModeHuman, nil, &fakeBuilder{}, namedBy(testVersion), nil)
		if err != nil {
			t.Fatal(err)
		}
		inOrder(t, stderr,
			"  fatline: "+instanceImageRef(prodName)+" already holds the image this farcast carries\n",
			"fatline: replacing the named image "+namedFatLine)
	})
	t.Run("a missing development build, then the build prompt", func(t *testing.T) {
		fb := &fakeBuilder{resolveFn: func(ref string) (string, error) { return "", image.ErrNotFound }}
		_, stderr, err := resolve(t, output.ModeHuman, nil, fb, developmentRecorded, func(d *fatlineDeployer) { asSourceBuild(d, "dev") })
		var ue *usageError
		if !errors.As(err, &ue) || err.Error() != "fatline's image would be compiled from /work/farcast with this machine's Go and pushed to "+repoOf("fatline")+":source-…; pass --yes to build it" {
			t.Fatalf("err = %v, want the build confirmation's refusal", err)
		}
		if stderr != "fatline: the development image "+imageIn("fatline", "d")+" is no longer in the registry; building it again.\n" || len(fb.built) != 0 {
			t.Errorf("built %d; stderr:\n%s", len(fb.built), stderr)
		}
	})
	// The build prompt names the checkout and the Go the decision found, or
	// why the Go could not be asked. /dev/null is a terminal to isTerminal,
	// and it answers nothing: the prompt is asked, and its input is closed.
	for _, tc := range []struct {
		name      string
		toolchain func(context.Context, []string, string) (image.Toolchain, error)
		goLine    string
	}{
		{"the Go found", fakeToolchain, "/usr/local/go/bin/go (go1.27.5)"},
		{"no Go", noToolchain, "the Go on PATH, which could not be asked (" + image.ErrNoGo.Error() + ")"},
	} {
		t.Run("the build prompt, "+tc.name, func(t *testing.T) {
			devNull, err := os.Open(os.DevNull) // a character device: a terminal to isTerminal
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = devNull.Close() }()
			fb := &fakeBuilder{}
			_, stderr, err := resolve(t, output.ModeHuman, devNull, fb, func(*config.InstanceMetadata) {}, func(d *fatlineDeployer) {
				asSourceBuild(d, "dev")
				d.findToolchain = tc.toolchain
			})
			if err == nil || err.Error() != "input closed" || len(fb.built) != 0 {
				t.Fatalf("err = %v, built %d; want the prompt's input closed, and nothing built", err, len(fb.built))
			}
			want := "This farcast carries no components (a source build), so fatline's image is compiled here.\n" +
				"fatline's image would be compiled from /work/farcast by " + tc.goLine + ", with no container engine,\n" +
				"pushed to the instance's registry as " + repoOf("fatline") + ":source-…, and recorded as a development build, which a release farcast replaces.\n" +
				"Build and push it now? [y/N]: "
			if stderr != want {
				t.Errorf("stderr:\n%q\nwant\n%q", stderr, want)
			}
		})
	}
}

// settledImage is d's image decided, said, consented to and realized, in
// the order kernel deploy and storage deploy go through them outside a plan,
// the cost question between the saying and the build question aside: the
// skew refusal or the notices (imageDecision.say); decide's error; the build
// question (buildConsent); and the push or build with its replacement note
// (realizeAndNote).
func settledImage(ctx context.Context, env *Env, d *fatlineDeployer, reg *registryAccess, meta *config.InstanceMetadata) (resolvedImage, error) {
	dec, err := d.decideImage(ctx, env, reg, meta)
	if serr := dec.say(env, d.embedded); serr != nil {
		return resolvedImage{}, serr
	}
	if err != nil {
		return resolvedImage{}, err
	}
	if err := d.buildConsent(env, dec); err != nil {
		return resolvedImage{}, err
	}
	return d.realizeAndNote(ctx, env, reg, dec)
}

// The version command.

// versionDigit is the hex digit of each component's manifest in carriedVersion.
var versionDigit = map[string]string{"datasphered": "d", "fatline": "f", "shrike": "5", "technocore": "7"}

func carriedVersion() (bool, string, []components.Artifact) {
	c := newFakeCarried()
	var arts []components.Artifact
	for _, comp := range components.All() {
		a, _ := c.Lookup(comp.Name)
		a.Manifest = sha(versionDigit[comp.Name]) // one digest each, so the order shows
		arts = append(arts, a)
	}
	// Out of order on purpose: the command sorts.
	arts[0], arts[3] = arts[3], arts[0]
	return true, image.BaseImage, arts
}

func versionOf(t *testing.T, mode output.Mode, carried func() (bool, string, []components.Artifact)) string {
	t.Helper()
	env, out := testEnv(config.Dir(t.TempDir()), mode)
	c := versionCommand{info: releaseBuild, carried: carried}
	if err := c.Run(context.Background(), env, nil); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestVersionPrintsCarriedComponents(t *testing.T) {
	var doc struct {
		Version    string `json:"version"`
		Embedded   bool   `json:"embedded"`
		Base       string `json:"base"`
		Components []struct {
			Name, Go, Manifest, Config, Layer string
			DiffID                            string `json:"diff_id"`
			BinarySHA256                      string `json:"binary_sha256"`
		} `json:"components"`
	}
	raw := versionOf(t, output.ModeJSON, carriedVersion)
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	if !doc.Embedded || doc.Base != image.BaseImage || len(doc.Components) != 4 {
		t.Fatalf("version printed %s", raw)
	}
	for i, name := range []string{"datasphered", "fatline", "shrike", "technocore"} {
		c := doc.Components[i]
		if c.Name != name || c.Go != carriedGo || c.Manifest != sha(versionDigit[name]) || c.DiffID == "" || c.Layer == "" || c.Config == "" || len(c.BinarySHA256) != 64 {
			t.Errorf("component %d = %+v, want %s with its Go and digests", i, c, name)
		}
	}

	human := versionOf(t, output.ModeHuman, carriedVersion)
	lines := strings.Split(strings.TrimRight(human, "\n"), "\n")
	tail := lines[len(lines)-5:]
	wantTail := []string{
		"  components (linux/amd64, on " + image.BaseImage + "):",
		"    datasphered  go1.27.4  " + sha("d"),
		"    fatline      go1.27.4  " + sha("f"),
		"    shrike       go1.27.4  " + sha("5"),
		"    technocore   go1.27.4  " + sha("7"),
	}
	if strings.Join(tail, "\n") != strings.Join(wantTail, "\n") {
		t.Errorf("the human form ends\n%s\nwant\n%s", strings.Join(tail, "\n"), strings.Join(wantTail, "\n"))
	}
}

func TestVersionSaysWhenNothingIsCarried(t *testing.T) {
	none := func() (bool, string, []components.Artifact) { return false, "", nil }
	raw := versionOf(t, output.ModeJSON, none)
	if !strings.Contains(raw, `"embedded":false,"base":"","components":[]`) {
		t.Errorf("version printed %s", raw)
	}
	human := versionOf(t, output.ModeHuman, none)
	if !strings.HasSuffix(human, "  components: none carried (a source build: a missing image is compiled from a farcast checkout)\n") {
		t.Errorf("the human form is\n%s", human)
	}
}

// The world document.

func TestWorldComponentGoVersion(t *testing.T) {
	componentsOf := func(t *testing.T, mutate func(*worldInputs)) map[string]worldComponent {
		t.Helper()
		in := healthyInputs(t)
		if mutate != nil {
			mutate(&in)
		}
		out := map[string]worldComponent{}
		for _, c := range buildWorld(in).Instance.Components {
			out[c.Name] = c
		}
		return out
	}
	goOf := func(c worldComponent) string {
		if c.Go == nil {
			return "null"
		}
		return *c.Go
	}

	// Set when the record names the running image.
	got := componentsOf(t, nil)
	for name, want := range map[string]string{"fatline": "go1.27.4", "shrike": "go1.27.4", "technocore": "go1.27.5", "datasphered": "go1.27.4"} {
		if goOf(got[name]) != want {
			t.Errorf("%s go = %s, want %s", name, goOf(got[name]), want)
		}
	}

	// Null when the record names another image, for the monitor too, whose
	// record is its only one.
	got = componentsOf(t, func(in *worldInputs) {
		in.Meta.SystemImages["fatline"] = config.SystemImage{Image: vecRegistry + "/fatline" + digestOf("a"), Go: "go1.27.3"}
		in.Meta.SystemImages["shrike"] = config.SystemImage{Image: vecRegistry + "/shrike" + digestOf("b"), Go: "go1.27.3"}
	})
	if goOf(got["fatline"]) != "null" || goOf(got["shrike"]) != "null" || got["fatline"].Version == nil {
		t.Errorf("an unmatched record gave fatline go %s (version %v) and shrike go %s", goOf(got["fatline"]), got["fatline"].Version, goOf(got["shrike"]))
	}

	// Null when there is no version: the cluster runs something else.
	got = componentsOf(t, func(in *worldInputs) {
		in.Apps.System[1] = cluster.Workload{Kind: "Deployment", Namespace: "farcast-system", Name: "technocore", Ready: 1, Desired: 1,
			Images: []string{vecRegistry + "/technocore" + digestOf("9")}}
	})
	if got["technocore"].Version != nil || goOf(got["technocore"]) != "null" {
		t.Errorf("a component running another image has version %v and go %s", got["technocore"].Version, goOf(got["technocore"]))
	}

	// Null when the record names the image but not its Go.
	got = componentsOf(t, func(in *worldInputs) {
		rec := in.Meta.SystemImages["datasphered"]
		rec.Go = ""
		in.Meta.SystemImages["datasphered"] = rec
	})
	if goOf(got["datasphered"]) != "null" {
		t.Errorf("a record with no Go gave %s", goOf(got["datasphered"]))
	}
}

// ADR 0023 M2.6 (row 75): --confirm executes the decisions it compared,
// never decisions made again. The plan reuses the carried images, whose
// version tags hold them; the recomputed plan compares equal; and then, as
// the writer opens, the tags move to another image. The command looks
// nothing up again and pushes nothing: it deploys and records exactly the
// images it compared.
func TestConfirmExecutesWhatItCompared(t *testing.T) {
	for _, dr := range deployRigs() {
		t.Run(dr.name, func(t *testing.T) {
			r := dr.rig(t)
			moved := false
			r.fb.resolveFn = func(ref string) (string, error) {
				if moved && !strings.Contains(ref, "@sha256:") {
					return pinnedRef(ref, "f"), nil
				}
				return tagOrDigest(ref)
			}
			doc := r.plan(t)
			for _, f := range decodedBound(t, doc).Facts {
				if img, ok := f.(plan.ImageFact); ok && img.Action != plan.ImageReuse {
					t.Fatalf("the plan does not reuse %s's image: %+v", img.Component, img)
				}
			}
			r.onWriter = func() { moved = true }
			before := len(r.fb.resolved)
			if _, errb, err := r.run(t, output.ModeJSON, "--confirm", doc.Digest); err != nil {
				t.Fatalf("--confirm: %v\n%s", err, errb)
			}
			if !moved {
				t.Fatal("the writer never opened, so the tags never moved")
			}
			if got := r.fb.resolved[before:]; len(got) != 2 {
				t.Errorf("--confirm looked up %q; want the recomputation's two lookups and none after the comparison", got)
			}
			if len(r.fb.embedded)+len(r.fb.built) != 0 {
				t.Errorf("pushed %d and built %d images the plan reused", len(r.fb.embedded), len(r.fb.built))
			}
			applied := string(slices.Concat(r.fc.applied...))
			for _, c := range []string{"fatline", "shrike"} {
				if !strings.Contains(applied, "image: "+carriedRef(c)) || r.meta(t).SystemImages[c].Image != carriedRef(c) {
					t.Errorf("%s was not deployed and recorded as compared, %s", c, carriedRef(c))
				}
			}
			if strings.Contains(applied, sha("f")) {
				t.Error("the moved tag's image was deployed")
			}
		})
	}
	// kernel deploy and storage deploy (ADR 0023 M2.6c, A23-38 and A23-43
	// step 4; rows O54 and O55 of the M2.6c review): the same, for the one
	// image each decides in its plan.
	for _, sc := range singleImageCommands() {
		t.Run(sc.name, func(t *testing.T) {
			r := sc.rig(t, nil)
			moved := false
			r.fb.resolveFn = func(ref string) (string, error) {
				if moved && !strings.Contains(ref, "@sha256:") {
					return pinnedRef(ref, "f"), nil
				}
				return tagOrDigest(ref)
			}
			doc := r.plan(t)
			if img := imageFactOf(t, doc, sc.component); img.Action != plan.ImageReuse {
				t.Fatalf("the plan does not reuse %s's image: %+v", sc.component, img)
			}
			r.onWriter(func() { moved = true })
			before := len(r.fb.resolved)
			if _, errb, err := r.run(t, "--confirm", doc.Digest); err != nil {
				t.Fatalf("--confirm: %v\n%s", err, errb)
			}
			if !moved {
				t.Fatal("the writer never opened, so the tag never moved")
			}
			if got := r.fb.resolved[before:]; len(got) != 1 {
				t.Errorf("--confirm looked up %q; want the recomputation's one lookup and none after the comparison", got)
			}
			if len(r.fb.embedded)+len(r.fb.built) != 0 {
				t.Errorf("pushed %d and built %d images the plan reused", len(r.fb.embedded), len(r.fb.built))
			}
			meta := r.meta(t)
			applied, want := string(slices.Concat(r.fc.applied...)), carriedRegistryRef(meta, sc.component)
			if !strings.Contains(applied, "image: "+want) || meta.SystemImages[sc.component].Image != want || strings.Contains(applied, sha("f")) {
				t.Errorf("%s was not deployed and recorded as compared, %s", sc.component, want)
			}
		})
	}
}

// singleImageRig is kernelRig or storageRig as the cross-cutting --confirm
// tests run them: a command that decides one system image in its plan
// (ADR 0023 M2.6c). plan runs --plan with flags, run runs the command with
// flags in JSON mode with no terminal, and onWriter sets what runs as the
// writer opens.
type singleImageRig struct {
	dir      config.Dir
	fp       *fakeProvider
	fb       *fakeBuilder
	fc       *fakeCluster
	plan     func(t *testing.T, flags ...string) plan.Document
	run      func(t *testing.T, flags ...string) (stdout, stderr string, err error)
	onWriter func(func())
}

// meta is the instance's record as the rig's command left it.
func (r singleImageRig) meta(t *testing.T) *config.InstanceMetadata {
	t.Helper()
	meta, err := r.dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

// singleImageCommand is kernel deploy or storage deploy, the component
// whose image it decides, and how a record names that image deployed.
type singleImageCommand struct {
	name, component string
	rig             func(t *testing.T, edit func(*config.InstanceMetadata)) singleImageRig
	deployed        func(meta *config.InstanceMetadata, img string)
}

func singleImageCommands() []singleImageCommand {
	return []singleImageCommand{
		{"kernel deploy", "technocore", func(t *testing.T, edit func(*config.InstanceMetadata)) singleImageRig {
			r := newKernelRig(t, edit)
			return singleImageRig{dir: r.dir, fp: r.fp, fb: r.fb, fc: r.fc, plan: r.plan, run: r.run, onWriter: func(f func()) { r.onWriter = f }}
		}, func(meta *config.InstanceMetadata, img string) { meta.Kernel.Image = img }},
		{"storage deploy", "datasphered", func(t *testing.T, edit func(*config.InstanceMetadata)) singleImageRig {
			r := newStorageRig(t, edit)
			planned := func(t *testing.T, flags ...string) plan.Document {
				t.Helper()
				stdout, stderr, err := r.run(t, append([]string{"--plan"}, flags...)...)
				if err != nil {
					t.Fatalf("storage deploy --plan: %v\n%s", err, stderr)
				}
				return printedDocument(t, []byte(stdout))
			}
			return singleImageRig{dir: r.dir, fp: r.fp, fb: r.fb, fc: r.fc, plan: planned, run: r.run, onWriter: func(f func()) { r.onWriter = f }}
		}, func(meta *config.InstanceMetadata, img string) { meta.Keyholder.Image = img }},
	}
}

// imageFactOf is doc's image fact for component.
func imageFactOf(t *testing.T, doc plan.Document, component string) plan.ImageFact {
	t.Helper()
	for _, f := range decodedBound(t, doc).Facts {
		if img, ok := f.(plan.ImageFact); ok && img.Component == component {
			return img
		}
	}
	t.Fatalf("the plan has no image fact for %s", component)
	return plan.ImageFact{}
}

// ADR 0023 M2.6 (§9.5, row 83): under --confirm, the image fact's
// replaces_other_version is the consent to replacing a component another
// farcast version deployed, with or without --embedded. A plan made without
// --embedded binds the replacement, and differs from the one made with it
// only in that option; confirmed without --embedded, it replaces the image.
func TestConfirmCoversTheReplacementItsPlanListed(t *testing.T) {
	for _, dr := range deployRigs() {
		t.Run(dr.name, func(t *testing.T) {
			r := dr.rig(t, recorded(embeddedBy("v0.8.0", "go1.27.3")))
			r.fb.resolveFn = notFoundForTags
			without := decodedBound(t, r.plan(t))
			var fact plan.ImageFact
			for _, f := range without.Facts {
				if img, ok := f.(plan.ImageFact); ok && img.Component == "fatline" {
					fact = img
				}
			}
			if !fact.ReplacesOtherVersion || fact.Action != plan.ImagePush || fact.Target != carriedRef("fatline") ||
				fact.Current == nil || fact.Current.FarCast != "v0.8.0" || fact.Current.Image != imageIn("fatline", "1") {
				t.Fatalf("the plan binds FatLine as %+v; want the replacement of v0.8.0's image listed", fact)
			}
			with := decodedBound(t, r.plan(t, "--embedded"))
			if !reflect.DeepEqual(with.Facts, without.Facts) {
				t.Errorf("a plan made with --embedded differs in its facts:\n%#v\n%#v", with.Facts, without.Facts)
			}
			var differ []string
			for i, o := range without.Options {
				if with.Options[i] != o {
					differ = append(differ, o.Flag)
				}
			}
			if !slices.Equal(differ, []string{"embedded"}) {
				t.Errorf("the two plans' options differ in %q; want --embedded alone", differ)
			}

			doc := r.plan(t)
			_, errb, err := r.run(t, output.ModeJSON, "--confirm", doc.Digest)
			if err != nil {
				t.Fatalf("--confirm of a plan that lists the replacement: %v\n%s", err, errb)
			}
			if deployedImage(r.meta(t)) != carriedRef("fatline") || len(r.fb.embedded) == 0 {
				t.Errorf("deployed %q after pushing %d images; want the carried image", deployedImage(r.meta(t)), len(r.fb.embedded))
			}
			want := config.SystemImage{Image: carriedRef("fatline"), Origin: config.OriginEmbedded, Go: carriedGo, Farcast: testVersion}
			if got := r.meta(t).SystemImages["fatline"]; got != want {
				t.Errorf("recorded %+v, want %+v", got, want)
			}
			if !strings.Contains(errb, "fatline: replacing "+imageIn("fatline", "1")+", deployed by farcast v0.8.0") {
				t.Errorf("the replacement was not said:\n%s", errb)
			}
		})
	}
	// kernel deploy and storage deploy (ADR 0023 M2.6c; rows O30 and O31 of
	// the M2.6c review): a plan made without --embedded over the image
	// v0.8.0 deployed binds the replacement, and its --confirm, with no
	// --embedded and no terminal, pushes, applies and records the carried
	// image, saying so.
	for _, sc := range singleImageCommands() {
		t.Run(sc.name, func(t *testing.T) {
			var old string
			r := sc.rig(t, func(m *config.InstanceMetadata) {
				old = m.Registry.Prefix + "/system/" + sc.component + "@" + sha("1")
				sc.deployed(m, old)
				recordSystemImage(m, sc.component, config.SystemImage{Image: old, Origin: config.OriginEmbedded, Go: "go1.27.3", Farcast: "v0.8.0"})
			})
			doc := r.plan(t)
			if img := imageFactOf(t, doc, sc.component); !img.ReplacesOtherVersion || img.Action != plan.ImagePush ||
				img.Current == nil || img.Current.FarCast != "v0.8.0" || img.Current.Image != old {
				t.Fatalf("the plan binds %s as %+v; want the replacement of v0.8.0's image listed", sc.component, img)
			}
			_, errb, err := r.run(t, "--confirm", doc.Digest)
			if err != nil {
				t.Fatalf("--confirm of a plan that lists the replacement = %v (kind %s)\n%s", err, kindOf(classified(err)), errb)
			}
			meta := r.meta(t)
			want := carriedRegistryRef(meta, sc.component)
			if len(r.fb.embedded) != 1 || len(r.fc.applied) != 1 || meta.SystemImages[sc.component].Image != want ||
				!strings.Contains(string(slices.Concat(r.fc.applied...)), "image: "+want) {
				t.Errorf("pushed %d, applied %d, recorded %+v; want the carried image %s pushed, applied and recorded",
					len(r.fb.embedded), len(r.fc.applied), meta.SystemImages[sc.component], want)
			}
			if !strings.Contains(errb, sc.component+": replacing "+old+", deployed by farcast v0.8.0") {
				t.Errorf("the replacement was not said:\n%s", errb)
			}
		})
	}
}

// ADR 0023 M2.6 (§9.5): --yes never implies --embedded. A --yes run, and a
// run with no answer and no terminal, refuse to replace a component another
// farcast version deployed, version_skew, before anything is asked, minted,
// ensured, pushed or applied; --yes --embedded replaces it.
func TestYesNeverReplacesAnotherVersionWithoutEmbedded(t *testing.T) {
	// The version tag as the registry answers it. The refusal comes before
	// anything is said or asked (review C-F1): not the replacement note,
	// nor a foreign tag's warning that the carried image will be pushed
	// over it, neither of which happens; as before the decisions were split
	// from the pushes, when the skew was refused before the tag was looked
	// up. The last row refuses through a plan that could not be made,
	// Shrike's tag unreadable after FatLine's skew was decided.
	for _, tag := range []struct {
		name    string
		resolve func(string) (string, error)
	}{
		{"its tag missing", notFoundForTags},
		{"its tag foreign", foreignForTags},
		{"its tag foreign, Shrike's unreadable", func(ref string) (string, error) {
			if strings.Contains(ref, "system/shrike:") {
				return "", errors.New("registry unavailable")
			}
			return foreignForTags(ref)
		}},
	} {
		for _, dr := range deployRigs() {
			for _, flags := range [][]string{{"--yes"}, nil} {
				t.Run(fmt.Sprintf("%s/%s/%q", tag.name, dr.name, flags), func(t *testing.T) {
					r := dr.rig(t, recorded(embeddedBy("v0.8.0", "go1.27.3")))
					r.fb.resolveFn = tag.resolve
					before := r.files(t)
					_, errb, err := r.run(t, output.ModeHuman, flags...)
					if kindOf(err) != kindVersionSkew || !strings.Contains(err.Error(), "Pass --embedded to replace it.") {
						t.Fatalf("%s %q over another version's image = %v (kind %s); want version_skew", dr.name, flags, err, kindOf(err))
					}
					if len(r.fb.embedded)+len(r.fb.built)+len(r.fc.applied)+len(r.fp.ensured)+r.dials != 0 {
						t.Errorf("pushed %d, built %d, applied %d, ensured %d and dialled %d before refusing",
							len(r.fb.embedded), len(r.fb.built), len(r.fc.applied), len(r.fp.ensured), r.dials)
					}
					if errb != "" {
						t.Errorf("said or asked something before refusing the replacement:\n%s", errb)
					}
					sameFiles(t, "a refused replacement", before, r.files(t))
				})
			}
		}
	}
	for _, dr := range deployRigs() {
		t.Run(dr.name+"/--yes --embedded", func(t *testing.T) {
			r := dr.rig(t, recorded(embeddedBy("v0.8.0", "go1.27.3")))
			r.fb.resolveFn = notFoundForTags
			if _, errb, err := r.run(t, output.ModeHuman, "--yes", "--embedded"); err != nil {
				t.Fatalf("--yes --embedded: %v\n%s", err, errb)
			}
			if deployedImage(r.meta(t)) != carriedRef("fatline") {
				t.Errorf("deployed %q, want the carried image", deployedImage(r.meta(t)))
			}
		})
	}
}
