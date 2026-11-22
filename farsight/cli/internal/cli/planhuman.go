package cli

import (
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	pfetch "github.com/sofmon/farcast/planck/fetch"
	"github.com/sofmon/farcast/technocore/kernel"
)

// The human rendering of a plan (design §9.6, as A23-7 and A23-27 amend it).
// The operator consents by reading it, so every value the plan binds appears
// in it, each through terminalText: a plan names values from the record, the
// cluster and a manifest nobody has reviewed yet, and none of them may act on
// the terminal that shows the plan.

// planResult is a printed plan. Its JSON is exactly the document, whose bound
// member holds the bytes its digest covers; the typed plan and the confirm
// line are for the human rendering only.
type planResult struct {
	plan.Document
	// typed is the plan the document's bytes were encoded from.
	typed plan.Bound `json:"-"`
	// confirm is the line that confirms the plan (confirmLine).
	confirm string `json:"-"`
}

// Human writes the blocks, the header, the facts in their order, the digest,
// and the confirm line, or for a blocked plan the line saying --confirm would
// refuse it.
func (r planResult) Human(w io.Writer) error {
	b := r.typed
	var lines []string
	for _, bl := range b.Blocked {
		lines = append(lines, fmt.Sprintf("blocked (%s): %s", terminalText(bl.Kind), output.ErrorText(bl.Message)))
	}
	if len(b.Blocked) > 0 {
		lines = append(lines, "")
	}
	lines = append(lines, planHeader(b)...)

	if len(b.Facts) > 0 {
		lines = append(lines, "")
	}
	keys, minted := placeholderKeyLabels(b.Facts)
	for i, f := range b.Facts {
		lines = append(lines, factLines(f, keys, minted[i])...)
	}

	lines = append(lines, "", "digest: "+r.Digest)
	if len(b.Blocked) > 0 {
		lines = append(lines, fmt.Sprintf("blocked: --confirm would refuse this plan (%s)", terminalText(b.Blocked[0].Kind)))
	} else {
		lines = append(lines, r.confirm)
	}
	for _, l := range lines {
		fprintln(w, l)
	}
	return nil
}

// planHeader is the four lines naming everything the plan binds outside its
// facts and blocks: which instance and cluster, which command and options,
// and which farcast and protocol.
func planHeader(b plan.Bound) []string {
	t := b.Target
	uid := terminalText(t.SystemNamespaceUID)
	switch {
	case b.ClusterIdentity == "none":
		uid = "not read"
	case t.SystemNamespaceUID == "":
		uid = "absent"
	}
	stage := b.Stage
	if stage == "" {
		stage = "-"
	}
	opts := "none"
	if len(b.Options) > 0 {
		parts := make([]string, 0, len(b.Options))
		for _, o := range b.Options {
			if o.Value == "" {
				parts = append(parts, "--"+terminalText(o.Flag)+" (not given)")
				continue
			}
			parts = append(parts, "--"+terminalText(o.Flag)+"="+terminalText(o.Value))
		}
		opts = strings.Join(parts, ", ")
	}
	return []string{
		fmt.Sprintf("instance %s: provider %s, project %s, region %s, cluster %s, endpoint %s (recorded %s); farcast-system %s",
			terminalText(b.Instance), terminalText(t.Provider), terminalText(t.Project), terminalText(t.Region),
			terminalText(t.Cluster), terminalText(t.Endpoint), terminalText(t.CreatedAt), uid),
		fmt.Sprintf("farcast %s %s, stage %s, reading the cluster as %s",
			terminalText(b.Command), terminalText(b.Instance), terminalText(stage), terminalText(b.ClusterIdentity)),
		"options: " + opts,
		fmt.Sprintf("farcast %s (commit %s), plan protocol %s",
			terminalText(b.FarCast.Version), terminalText(b.FarCast.Commit), terminalText(b.Protocol)),
	}
}

// factValue is f, with a pointer to a fact read through, so a plan that holds
// facts by pointer renders as one that holds them by value.
func factValue(f plan.Fact) plan.Fact {
	v := reflect.ValueOf(f)
	if v.Kind() == reflect.Pointer && !v.IsNil() {
		if e, ok := v.Elem().Interface().(plan.Fact); ok {
			return e
		}
	}
	return f
}

// factLines is one fact in the command's words: one to three lines, the
// first unindented. keys names the placeholder key ids the plan mints, and
// minted is the name of the key a key mint makes (placeholderKeyLabels).
func factLines(f plan.Fact, keys map[string]string, minted string) []string {
	switch f := factValue(f).(type) {
	case plan.CostFact:
		return costLines(f)
	case plan.ImageFact:
		return imageLines(f)
	case plan.WriteFact:
		return []string{writeLine(f)}
	case plan.MintFact:
		return []string{mintLine(f, minted)}
	case plan.RestartFact:
		return []string{fmt.Sprintf("restart %s: %s", terminalText(f.Component), terminalText(f.Because))}
	case plan.CloudFact:
		return []string{fmt.Sprintf("cloud %s: %s %s", terminalText(f.Service), terminalText(f.Action), terminalText(f.Target))}
	case plan.KernelSettingsFact:
		return kernelSettingsLines(f)
	case plan.MeterFact:
		return meterLines(f)
	case plan.ConfirmationFact:
		return confirmationLines(f)
	case plan.PinFact:
		return pinLines(f, keys)
	case plan.RotationFact:
		return []string{fmt.Sprintf("rotation: %d new key(s), handed to %d keyholder replica(s)", f.NewKeys, f.HandoverReplicas)}
	case plan.FetchFact:
		return []string{fmt.Sprintf("fetch: the manifest %s from %s at %s, read by the Job %s with %s",
			defaulted(f.Manifest, pfetch.DefaultManifest), terminalText(f.Repository), defaulted(f.Ref, fetchDefaultRef),
			terminalText(f.Job), terminalText(f.Fetcher))}
	case plan.RunFact:
		return runLines(f)
	case plan.BuildFact:
		return []string{fmt.Sprintf("build: %s from %s at %s, %s in %s, tagged %s, pushed to %s",
			terminalText(f.App), terminalText(f.Repository), terminalText(f.Ref), terminalText(f.Containerfile),
			terminalText(f.Context), terminalText(f.Tag), terminalText(f.Destination))}
	case plan.ApplicationResetFact:
		return resetLines(f)
	case plan.ReaderFact:
		return []string{fmt.Sprintf("reader: %s (%s), scope %s: %s in %s; the ConfigMaps %s; in farcast-system, the ServiceAccounts %s (their uid)",
			terminalText(f.Email), terminalText(f.IAMRole), terminalText(f.Scope), listText(f.Resources),
			listText(f.Namespaces), listText(f.ConfigMaps), listText(f.ServiceAccounts))}
	case plan.NoticeFact:
		return noticeLines(f)
	case plan.GrantFact:
		return grantLines(f)
	case plan.GitCredentialFact:
		return []string{gitCredentialLine(f)}
	}
	return fallbackLines(f)
}

// defaulted is a flag's value as a fact binds it, given (A28-8): one that
// was not given is bound as "", and reads as the value the command uses in
// its place, said to be the default.
func defaulted(given, def string) string {
	if given == "" {
		return def + " (the default)"
	}
	return terminalText(given)
}

// fallbackLines is a fact this farcast has no words for, shown as its JSON
// so nothing it binds goes unseen. Every fact type of the plan package has
// words (TestEveryBoundFactIsRendered).
func fallbackLines(f plan.Fact) []string {
	b, err := marshalJSON(f)
	if err != nil {
		return []string{fmt.Sprintf("fact %s: (cannot be shown: %v)", terminalText(f.FactType()), err)}
	}
	return []string{fmt.Sprintf("fact %s: %s", terminalText(f.FactType()), terminalText(string(b)))}
}

// money is an amount in cents, exactly: <currency> <units>.<cents>.
func money(currency string, cents int64) string {
	return terminalText(currency) + " " + amount(cents)
}

// amount is cents as <units>.<cents>, with no rounding.
func amount(cents int64) string {
	sign := ""
	if cents < 0 {
		sign, cents = "-", -cents
	}
	return fmt.Sprintf("%s%d.%02d", sign, cents/100, cents%100)
}

// listText is a list, each element through terminalText, or "none".
func listText(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = terminalText(x)
	}
	return strings.Join(out, ", ")
}

func costLines(f plan.CostFact) []string {
	cur := f.Currency
	lines := []string{fmt.Sprintf("cost, against the cost limit %s/%s:", money(cur, f.LimitCents), terminalText(f.Period))}
	for _, s := range f.Standing {
		line := fmt.Sprintf("  standing: %s, %d replica(s) at %dm CPU and %d MiB, %s a month",
			terminalText(s.What), s.Replicas, s.CPUMilli, s.MemMiB, money(cur, s.MonthCents))
		if s.MaxMonthCents != nil {
			line += fmt.Sprintf(", at most %s a month", money(cur, *s.MaxMonthCents))
		}
		lines = append(lines, line)
	}
	for _, o := range f.OneOff {
		lines = append(lines, fmt.Sprintf("  one-off: %s, %d job(s) at %dm CPU and %d MiB, each stopped after %d s",
			terminalText(o.What), o.Jobs, o.CPUMilli, o.MemMiB, o.DeadlineS))
	}
	below := "the cost limit is not below it"
	if f.BelowFloor {
		below = "the cost limit is below it"
	}
	lines = append(lines,
		fmt.Sprintf("  the instance's floor is %s a month; %s", money(cur, f.FloorMonthCents), below),
		fmt.Sprintf("  prices: %s as of %s", terminalText(f.Pricing.Region), terminalText(f.Pricing.AsOf)))
	return lines
}

func imageLines(f plan.ImageFact) []string {
	first := fmt.Sprintf("image %s: %s %s", terminalText(f.Component), terminalText(f.Action), terminalText(f.Target))
	if f.Go != "" {
		first += ", go " + terminalText(f.Go)
	}
	lines := []string{first}
	if c := f.Current; c != nil {
		lines = append(lines, fmt.Sprintf("  today: %s (origin %s, farcast %s, go %s)",
			terminalText(c.Image), terminalText(c.Origin), terminalText(c.FarCast), terminalText(c.Go)))
	} else {
		lines = append(lines, "  today: nothing recorded")
	}
	if f.ReplacesOtherVersion {
		lines = append(lines, "  it replaces a component another farcast version deployed")
	} else {
		lines = append(lines, "  it replaces no component another farcast version deployed")
	}
	if s := f.Source; s != nil {
		lines = append(lines, fmt.Sprintf("  a source build of %s, with %s (%s)",
			terminalText(s.Dir), terminalText(s.GoPath), terminalText(s.GoVersion)))
	}
	return lines
}

// describeObject names one cluster object as an operator reads it: <Kind>
// <namespace>/<name>, or <Kind> <name> for a cluster-scoped one (namespace
// ""), each through terminalText, since the namespace and the name may be the
// server's. A write's object and a Git credential's Secret are named by it.
// A30-13 defined it for migrate's fact, which M2.9a removed (design A37-12).
func describeObject(kind, namespace, name string) string {
	obj := terminalText(name)
	if namespace != "" {
		obj = terminalText(namespace) + "/" + obj
	}
	return terminalText(kind) + " " + obj
}

func writeLine(f plan.WriteFact) string {
	line := fmt.Sprintf("write: %s %s (%s)", terminalText(f.Method), describeObject(f.Kind, f.Namespace, f.Name), terminalText(f.API))
	if f.Method == plan.WriteDelete {
		return deleteLine(line, f)
	}
	switch {
	case f.ResourceVersion != "":
		line += ", at resourceVersion " + terminalText(f.ResourceVersion)
	case f.Method == plan.WriteReplace:
		// A replace with no version of its own is rotate's final pin: its
		// version is the one the hold-stage write produces (A23-45).
		line += ", at the version the hold-stage write produced"
	}
	force := "no"
	if f.Force {
		force = "yes"
	}
	return line + ", force: " + force + ", sha256 " + terminalText(f.SHA256)
}

// deleteLine ends writeLine for a delete, git-credential rm's (ADR 0023
// M2.8, design §33, A33-31): a delete writes no document, so the plan binds
// no sha256 of one, and it is preconditioned on the uid its read finds after
// consent. A resourceVersion or a sha256, which no plan's delete binds,
// would still show.
func deleteLine(line string, f plan.WriteFact) string {
	line += ", on the uid read after consent"
	if f.ResourceVersion != "" {
		line += ", at resourceVersion " + terminalText(f.ResourceVersion)
	}
	force := "no"
	if f.Force {
		force = "yes"
	}
	line += ", force: " + force
	if f.SHA256 != "" {
		line += ", sha256 " + terminalText(f.SHA256)
	}
	return line
}

// gitCredentialLine is the git_credential fact (ADR 0023 M2.8, design §33,
// A33-29): the action and the Secret, which the plan names by its namespace
// and name alone.
func gitCredentialLine(f plan.GitCredentialFact) string {
	line := fmt.Sprintf("git credential: %s %s", terminalText(f.Action), describeObject("Secret", f.Namespace, f.Name))
	switch f.Action {
	case plan.GitCredentialSet:
		line += "; its token is read only after consent, and the plan binds neither the username nor the token"
	case plan.GitCredentialRm:
		line += ", only if it is a Git credential farcast wrote"
	}
	return line
}

func mintLine(f plan.MintFact, minted string) string {
	if f.What == plan.MintKey {
		if f.Subject == "" {
			return "mint key: a new key for the instance key space"
		}
		return "mint key: " + minted
	}
	return fmt.Sprintf("mint %s: %s", terminalText(f.What), terminalText(f.Subject))
}

func kernelSettingsLines(f plan.KernelSettingsFact) []string {
	adapt := "off"
	if f.Adapt {
		adapt = "on"
	}
	lines := []string{fmt.Sprintf("kernel settings: interval %s, adapting %s, adapt cooldown %s; metering %s",
		effective(time.Duration(f.IntervalS)*time.Second, kernel.DefaultInterval), adapt,
		effective(time.Duration(f.AdaptCooldownS)*time.Second, kernel.DefaultCooldown), listText(f.Namespaces))}
	return append(lines, readerBindingLine(f.Reader, f.ReaderBindingsCreated))
}

// readerBindingLine names the reader a stream binds and where, or says it
// binds none.
func readerBindingLine(reader string, namespaces []string) string {
	if reader == "" {
		return "  no reader binding is added"
	}
	return fmt.Sprintf("  the reader %s is bound in: %s", terminalText(reader), listText(namespaces))
}

func meterLines(f plan.MeterFact) []string {
	return []string{
		fmt.Sprintf("meter: start metering %s; stop metering %s; metered afterwards: %s",
			listText(f.Add), listText(f.Remove), listText(f.MeteredAfter)),
		fmt.Sprintf("  the kernel's RoleBinding is created in: %s; left in place in: %s",
			listText(f.BindingsCreated), listText(f.BindingsLeft)),
		readerBindingLine(f.Reader, f.ReaderBindingsCreated),
	}
}

func confirmationLines(f plan.ConfirmationFact) []string {
	windows := make([]string, 0, len(f.WindowsAfter))
	for _, w := range f.WindowsAfter {
		windows = append(windows, fmt.Sprintf("%s..%s %s", terminalText(w.From), terminalText(w.To), amount(w.AmountCents)))
	}
	after := "none"
	if len(windows) > 0 {
		after = strings.Join(windows, ", ")
	}
	return []string{
		fmt.Sprintf("confirmation: the provider charged %s for %s..%s, as of %s",
			amount(f.AmountCents), terminalText(f.From), terminalText(f.To), terminalText(f.AsOfDay)),
		"  confirmed windows afterwards: " + after,
	}
}

func pinLines(f plan.PinFact, keys map[string]string) []string {
	ids := func(xs []string) string {
		if len(xs) == 0 {
			return "none"
		}
		out := make([]string, len(xs))
		for i, x := range xs {
			if l, ok := keys[x]; ok {
				out[i] = l
				continue
			}
			out[i] = terminalText(x)
		}
		return strings.Join(out, ", ")
	}
	lowering := "it lowers nothing"
	if len(f.Lowering) > 0 {
		lowering = "it lowers the pin, dropping " + ids(f.Lowering)
	}
	repairing := "it repairs no unreadable pin"
	if f.Repairing {
		repairing = "it replaces a pin that could not be read"
	}
	return []string{
		fmt.Sprintf("pin: require %s; retired %s", ids(f.Require), ids(f.Retired)),
		"  " + lowering + "; " + repairing,
	}
}

func runLines(f plan.RunFact) []string {
	ns := terminalText(f.Namespace)
	lines := []string{fmt.Sprintf("run: deploy %s from the manifest %s at commit %s, fetched by the plan %s (Job uid %s)",
		ns, terminalText(f.ManifestDigest), terminalText(f.Commit), terminalText(f.FetchPlanDigest), terminalText(f.JobUID))}
	if f.ReplacesRepository != "" {
		lines = append(lines, "  it replaces the repository "+terminalText(f.ReplacesRepository)+" recorded for "+ns)
	} else {
		lines = append(lines, "  it replaces no other repository")
	}
	for _, a := range f.Apps {
		hosts := make([]string, 0, len(a.External))
		for _, h := range a.External {
			hosts = append(hosts, terminalText(h.Host)+" ("+terminalText(h.Reason)+")")
		}
		reach := "reaches nothing outside the instance"
		if len(hosts) > 0 {
			reach = "reaches " + strings.Join(hosts, ", ")
		}
		lines = append(lines, fmt.Sprintf("  app %s: %s in %s; %s",
			terminalText(a.Name), terminalText(a.Containerfile), terminalText(a.Context), reach))
	}
	metering := ns + " is already metered"
	if f.MeteringAdded {
		metering = ns + " is added to what the kernel meters"
	}
	lines = append(lines, fmt.Sprintf("  other deployments kept in %s: %s; %s", ns, listText(f.OtherDeploymentsKept), metering))
	// While the spending reads at its limit the plan says so, in the line
	// the review prints (A28-1): confirming it is the consent to deploying.
	if f.LimitReached {
		return append(lines, "  "+limitLine(terminalText(f.LimitReason)))
	}
	return append(lines, "  the instance's spending is not at its limit")
}

func resetLines(f plan.ApplicationResetFact) []string {
	guard := "not stopped by the cost guard"
	if f.StoppedByCostGuard {
		guard = "stopped by the cost guard"
	}
	limit := "the spending does not read the limit reached"
	if f.LimitReached {
		limit = "the spending reads the limit reached, or cannot be read"
	}
	live := "not read"
	if f.ReplicasLive != nil {
		live = strconv.FormatInt(int64(*f.ReplicasLive), 10)
	}
	liveReq := "not read"
	if r := f.RequestsLive; r != nil {
		liveReq = fmt.Sprintf("%dm CPU and %d MiB", r.CPUMilli, r.MemMiB)
	}
	return []string{
		fmt.Sprintf("reset %s/%s: %s, %s; %s",
			terminalText(f.Namespace), terminalText(f.App), terminalText(f.State), guard, limit),
		fmt.Sprintf("  replicas: %s now, %d after; requests: %s now, %dm CPU and %d MiB after",
			live, f.ReplicasAfter, liveReq, f.RequestsAfter.CPUMilli, f.RequestsAfter.MemMiB),
	}
}

// grantLines is a grant fact (ADR 0023 M2.8, A33-11): the uid principal, the
// ServiceAccount it is, the target and the roles, and the principal's state;
// then the principal every instance in the project shares, and its state;
// then whether this command applies the grant.
func grantLines(f plan.GrantFact) []string {
	lines := []string{
		fmt.Sprintf("grant %s: %s (ServiceAccount %s) on %s as %s: %s",
			terminalText(f.Name), principalText(f.Principal), terminalText(f.ServiceAccount), terminalText(f.Target),
			listText(f.Roles), terminalText(f.State)),
		fmt.Sprintf("  the shared principal %s, which every FarCast instance in the project shares: %s",
			principalText(f.SharedPrincipal), terminalText(f.Shared)),
	}
	switch {
	case f.Apply:
		return append(lines, "  applied: one policy write adds the uid principal to both roles and removes the shared one from them")
	case f.Name == plan.GrantBucket:
		return append(lines, "  not applied: the printed commands do it, or --grant-bucket")
	case f.Name == plan.GrantPush:
		return append(lines, "  not applied: this command never grants push access; the printed commands do it")
	}
	return append(lines, "  not applied")
}

// principalText is a grant's principal as its rendering names it: one that
// carries the uid placeholder is the account this command creates (A33-19),
// and "" is one no project number was known for.
func principalText(principal string) string {
	if principal == "" {
		return "not known (the provider states no project number)"
	}
	if namespace, name, ok := placeholderServiceAccount(principal); ok {
		return "the uid of ServiceAccount " + terminalText(namespace) + "/" + terminalText(name) + ", once this command creates it"
	}
	return terminalText(principal)
}

// noticeLines is a notice in the command's own words. A notice of several
// lines keeps them, each through terminalText.
func noticeLines(f plan.NoticeFact) []string {
	parts := strings.Split(f.Text, "\n")
	lines := make([]string, len(parts))
	for i, p := range parts {
		prefix := "  "
		if i == 0 {
			prefix = "notice: "
		}
		lines[i] = prefix + terminalText(p)
	}
	return lines
}

// placeholderKeyID is the id a plan gives the n-th key-encryption key (from
// 1) a command would mint into scope (design §9.4, A23-32): the first 8 bytes
// of SHA-256 of farcast-placeholder:key:<scope>:<n>. A real id is random, so
// the plan names a fixed one, and its rendering names it by what it is.
func placeholderKeyID(scope string, n int) datasphere.KeyID {
	sum := sha256.Sum256([]byte("farcast-placeholder:key:" + scope + ":" + strconv.Itoa(n)))
	var id datasphere.KeyID
	copy(id[:], sum[:])
	return id
}

// placeholderKeyLabels names the keys the plan's facts mint, "new key <n> of
// <scope>", n counted from 1 per scope in the facts' order: by the
// placeholder id of each, for the pins, and by the index of the key mint
// that makes it, for the mints. A pin rendered with them names a key the
// command would mint by what it is, not by an id it will never have.
func placeholderKeyLabels(facts []plan.Fact) (byID map[string]string, byFact []string) {
	byID, byFact = map[string]string{}, make([]string, len(facts))
	count := map[string]int{}
	for i, f := range facts {
		m, ok := factValue(f).(plan.MintFact)
		if !ok || m.What != plan.MintKey || m.Subject == "" {
			continue
		}
		count[m.Subject]++
		n := count[m.Subject]
		label := fmt.Sprintf("new key %d of %s", n, terminalText(m.Subject))
		byID[placeholderKeyID(m.Subject, n).String()] = label
		byFact[i] = label
	}
	return byID, byFact
}
