package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	c.newCluster = func(string) clusterApplier { return fc }
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
		c.newCluster = func(string) clusterApplier { return &fakeCluster{} }
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
		c.newCluster = func(string) clusterApplier { return &fakeCluster{ip: "34.0.0.1"} }
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
		c.deployer.newCluster = func(string) clusterApplier { return &fakeCluster{} }
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
			t.Run("resolveImage", func(t *testing.T) {
				fb := &fakeBuilder{}
				c := testRedeploy(&fakeProvider{}, fb)
				c.fatlineImage = ref
				env, _ := testEnv(emptyDir(t), output.ModeHuman)
				got, err := c.resolveImage(context.Background(), env, nil, &config.InstanceMetadata{Name: prodName})
				wantUsage(t, err, "--fatline-image", fb)
				if got.Ref != "" {
					t.Errorf("resolved %q", got.Ref)
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
		fb, fc := &fakeBuilder{resolveFn: notFoundForTags}, &fakeCluster{ip: "34.0.0.1"}
		c := testConnect(fp, fb)
		c.assumeYes = true
		c.fatlineImage, c.embedded = given, embedded
		c.newCluster = func(string) clusterApplier { return fc }
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
	// The belt and braces in resolveSidecarImage, for a caller that reached
	// it with no registry.
	t.Run("resolveSidecarImage", func(t *testing.T) {
		c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
		c.fatlineImage, c.embedded = given, true
		env, _, errb := testEnvBoth(config.Dir(t.TempDir()), output.ModeHuman)
		got, err := c.resolveSidecarImage(context.Background(), env, nil, &config.InstanceMetadata{Name: prodName})
		if err == nil || !strings.Contains(err.Error(), "drop --embedded to deploy FatLine alone") || got.Ref != "" {
			t.Fatalf("got %+v, %v; want the refusal", got, err)
		}
		c.embedded = false
		got, err = c.resolveSidecarImage(context.Background(), env, nil, &config.InstanceMetadata{Name: prodName})
		if err != nil || got.Ref != "" || !strings.Contains(errb.String(), "deploying FatLine alone") {
			t.Fatalf("got %+v, %v; want FatLine alone, said\nstderr:\n%s", got, err, errb.String())
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
		fc := &fakeCluster{ip: "34.0.0.1"}
		c := testConnect(&fakeProvider{}, &fakeBuilder{})
		c.assumeYes = true
		c.newCluster = func(string) clusterApplier { return fc }
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
