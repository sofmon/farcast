package config

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"time"
)

// Route is how one of an instance's roles reaches Google (ADR 0024 D7): the
// certificate route, one of its three fallbacks, or none. A route is
// recorded per role, because fallback 3's writer pairs with a fallback 2
// reader or with no reader at all.
type Route string

// The routes, in D7's order.
const (
	// RouteCertificate is X.509 federation from the device's own anchor and
	// leaf for the role (D1, D2), whose keys are in identity/.
	RouteCertificate Route = "certificate"
	// RoutePublicKey is fallback 1: OIDC, a device key uploaded as the role's
	// single-key JWKS.
	RoutePublicKey Route = "public_key"
	// RouteUploadedKey is fallback 2: a device-made RSA key whose certificate
	// was uploaded to the role's service account.
	RouteUploadedKey Route = "uploaded_key"
	// RouteGoogleMadeKey is fallback 3: a key Google made, which the operator
	// downloaded. It is a provider-made secret, and it does not expire.
	RouteGoogleMadeKey Route = "google_made_key"
	// RouteNone is a role this machine cannot act as.
	RouteNone Route = "none"
)

// valid reports whether r is one of the five routes.
func (r Route) valid() bool {
	switch r {
	case RouteCertificate, RoutePublicKey, RouteUploadedKey, RouteGoogleMadeKey, RouteNone:
		return true
	}
	return false
}

// The two roles a device holds (ADR 0024 D2), as the record names them.
const (
	RoleReader = "reader"
	RoleWriter = "writer"
)

// Identity is an instance's identity on this machine (ADR 0024 D3, D7): the
// IDs drawn for the instance's pool and its three service accounts, the
// project's number, which STS's audience names, the title of the writer's
// storage condition, this device's roles with their routes, and the other
// devices' providers this machine has been told of.
//
// Nothing secret lives here. Every ID and the project's number are
// non-secret coordinates, and each is printed at some point into a block an
// Owner pastes into Cloud Shell, so CheckedIdentity holds each to the one
// alphabet it may be rendered in. The device's keys are in identity/ beside this record
// (InstanceIdentityDir), in devicekey's store.
type Identity struct {
	// ProjectNumber is the project's number, which STS's audience needs and
	// the installer holds no credential to read before verification (D7).
	ProjectNumber string `yaml:"project_number,omitempty"`
	// Pool is the instance's workload identity pool's ID, drawn per instance.
	Pool string `yaml:"pool,omitempty"`
	// ReaderAccount, WriterAccount and NodeAccount are the IDs of the
	// instance's three service accounts, drawn per instance, never their
	// emails: ServiceAccountEmail gives each its email in the project.
	ReaderAccount string `yaml:"reader_account,omitempty"`
	WriterAccount string `yaml:"writer_account,omitempty"`
	NodeAccount   string `yaml:"node_account,omitempty"`
	// ConditionTitle is the title of the IAM condition under which the
	// writer holds its storage grant, drawn per instance (D5, D7).
	ConditionTitle string `yaml:"condition_title,omitempty"`
	// Roles is this device's roles, each at most once. It is merged per role
	// (mergeOntoNewer).
	Roles []DeviceRole `yaml:"roles,omitempty"`
	// Known is the other devices' providers this machine was told of
	// ('device known'), each at most once. It is merged per provider.
	Known []KnownProvider `yaml:"known,omitempty"`
	// EnrolledAt is when this device's enrolment was verified.
	EnrolledAt time.Time `yaml:"enrolled_at,omitzero"`
}

// DeviceRole is one of this device's roles and how it reaches Google.
type DeviceRole struct {
	Role  string `yaml:"role"` // RoleReader or RoleWriter
	Route Route  `yaml:"route"`
	// Provider is the ID of the role's provider in the instance's pool,
	// drawn per device and role: on the certificate route, and on fallback
	// 1's, which has one too. None on the other routes.
	Provider string `yaml:"provider,omitempty"`
	// AnchorNotAfter is the role's anchor's NotAfter, read from its
	// certificate when it was enrolled or renewed, so a warning about its
	// expiry needs no key. The certificate route only.
	AnchorNotAfter time.Time `yaml:"anchor_not_after,omitzero"`
}

// KnownProvider is another device's provider in the instance's pool, and
// the role it serves.
type KnownProvider struct {
	Provider string `yaml:"provider"`
	Role     string `yaml:"role"` // RoleReader or RoleWriter
}

// ErrNoIdentity is a record that names no identity: no route for any role.
var ErrNoIdentity = errors.New("the instance's record names no identity route")

// ErrIdentityRecord is an identity holding a value outside the shape farcast
// writes it in, or a route without what it needs. The error that carries it
// names the field and the shape, never the value.
var ErrIdentityRecord = errors.New("the instance's identity record is not one farcast writes")

// The shapes CheckedIdentity and the pending store check, config's own
// copies (devicekey draws the IDs; config does not import it, and its tests
// hold the two to agree). Go's $ matches only at the end of the text, so no
// trailing newline passes.
var (
	// projectNumberShape is a project's number: 1 to 20 decimal digits.
	projectNumberShape = regexp.MustCompile(`^[0-9]{1,20}$`)
	// longIDShape is a pool's or a provider's drawn ID: a lowercase letter,
	// then 31 lowercase letters and digits.
	longIDShape = regexp.MustCompile(`^[a-z][a-z0-9]{31}$`)
	// shortIDShape is a service account's drawn ID, or a condition's drawn
	// title: a lowercase letter, then 29 lowercase letters and digits.
	shortIDShape = regexp.MustCompile(`^[a-z][a-z0-9]{29}$`)
	// projectIDShape is Google's project-ID shape: 6 to 30 characters,
	// lowercase letters, digits and hyphens, starting with a letter and not
	// ending with a hyphen.
	projectIDShape = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
)

// The shapes, as an error names them.
const (
	shapeNumber  = "1 to 20 digits"
	shapeLongID  = "32 of a-z and 0-9, starting with a letter"
	shapeShortID = "30 of a-z and 0-9, starting with a letter"
	shapeProject = "6 to 30 of a-z, 0-9 and -, starting with a letter and not ending with -"
)

// identityRefused is ErrIdentityRecord, with what is wrong.
func identityRefused(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrIdentityRecord}, a...)...)
}

// shaped is one value, the field it is in, and the shape it must have when
// it is there.
type shaped struct {
	field, value string
	shape        *regexp.Regexp
	what         string
}

// checkShapes refuses the first present value that is not in its shape. An
// empty value is absent; a field that is required checks that apart.
func checkShapes(refuse func(string, ...any) error, values []shaped) error {
	for _, v := range values {
		if v.value != "" && !v.shape.MatchString(v.value) {
			return refuse("%s is not %s", v.field, v.what)
		}
	}
	return nil
}

// CheckedIdentity returns meta's identity once every value in it has its
// shape and every route has what it needs. A record with no identity, or an
// identity that names no role and so no route for any, is ErrNoIdentity;
// anything else it refuses is ErrIdentityRecord, naming the field and never
// its value, because a hand-edited or damaged record can hold anything and
// these values are rendered into an Owner's shell. A role this machine
// cannot act as is named with the route none, never left out.
//
// The shapes, each checked where the value is present:
//   - the project's number, 1 to 20 digits;
//   - the pool's and every provider's ID, 32 of [a-z0-9], a letter first;
//   - each service account's ID and the condition's title, 30 of [a-z0-9],
//     a letter first.
//
// The routes:
//   - certificate needs the role's provider and its anchor's NotAfter, the
//     project's number and the pool, which STS's audience names, and the
//     role's account, which its token impersonates; a writer needs the node
//     account too, which it acts as when it creates the cluster (D4);
//   - public_key (fallback 1) may name a provider, and no anchor;
//   - uploaded_key, google_made_key and none name neither. The fallbacks
//     carry only the route until M3b.14 tightens fallback 3.
//
// It refuses, too, a role named twice or that is neither reader nor writer,
// a route farcast does not know, two roles naming one provider, two of the
// three accounts sharing an ID, and a known provider that is named twice,
// that names no role, or that is one of this device's own: each would make
// one name stand for two things a later check tells apart.
func CheckedIdentity(meta *InstanceMetadata) (*Identity, error) {
	if meta == nil || meta.Identity == nil || len(meta.Identity.Roles) == 0 {
		return nil, ErrNoIdentity
	}
	if err := checkIdentity(meta.Identity); err != nil {
		return nil, err
	}
	return meta.Identity, nil
}

// checkIdentity is CheckedIdentity's checks of one identity.
func checkIdentity(id *Identity) error {
	if err := checkShapes(identityRefused, []shaped{
		{"identity.project_number", id.ProjectNumber, projectNumberShape, shapeNumber},
		{"identity.pool", id.Pool, longIDShape, shapeLongID},
		{"identity.reader_account", id.ReaderAccount, shortIDShape, shapeShortID},
		{"identity.writer_account", id.WriterAccount, shortIDShape, shapeShortID},
		{"identity.node_account", id.NodeAccount, shortIDShape, shapeShortID},
		{"identity.condition_title", id.ConditionTitle, shortIDShape, shapeShortID},
	}); err != nil {
		return err
	}
	if err := distinctAccounts(identityRefused, "identity", id.ReaderAccount, id.WriterAccount, id.NodeAccount); err != nil {
		return err
	}
	own := map[string]bool{}
	roles := map[string]bool{}
	for i, r := range id.Roles {
		field := fmt.Sprintf("identity.roles[%d]", i)
		if r.Role != RoleReader && r.Role != RoleWriter {
			return identityRefused("%s.role is neither %s nor %s", field, RoleReader, RoleWriter)
		}
		if roles[r.Role] {
			return identityRefused("identity.roles names the %s role twice", r.Role)
		}
		roles[r.Role] = true
		if !r.Route.valid() {
			return identityRefused("%s.route is not a route farcast knows", field)
		}
		if r.Provider != "" {
			if !longIDShape.MatchString(r.Provider) {
				return identityRefused("%s.provider is not %s", field, shapeLongID)
			}
			if own[r.Provider] {
				return identityRefused("identity.roles names one provider for two roles")
			}
			own[r.Provider] = true
		}
		if err := checkRoute(id, field, r); err != nil {
			return err
		}
	}
	known := map[string]bool{}
	for i, k := range id.Known {
		field := fmt.Sprintf("identity.known[%d]", i)
		switch {
		case !longIDShape.MatchString(k.Provider):
			return identityRefused("%s.provider is not %s", field, shapeLongID)
		case k.Role != RoleReader && k.Role != RoleWriter:
			return identityRefused("%s.role is neither %s nor %s", field, RoleReader, RoleWriter)
		case known[k.Provider]:
			return identityRefused("identity.known names one provider twice")
		case own[k.Provider]:
			return identityRefused("%s.provider is one of this device's own", field)
		}
		known[k.Provider] = true
	}
	return nil
}

// checkRoute refuses a role whose route lacks what it needs, or carries what
// it cannot have.
func checkRoute(id *Identity, field string, r DeviceRole) error {
	if r.Route != RouteCertificate && !r.AnchorNotAfter.IsZero() {
		return identityRefused("%s names an anchor, which only the %s route has", field, RouteCertificate)
	}
	switch r.Route {
	case RouteCertificate:
		account, accountField := id.ReaderAccount, "identity.reader_account"
		if r.Role == RoleWriter {
			account, accountField = id.WriterAccount, "identity.writer_account"
		}
		for _, need := range []struct{ field, value string }{
			{field + ".provider", r.Provider},
			{"identity.project_number", id.ProjectNumber},
			{"identity.pool", id.Pool},
			{accountField, account},
		} {
			if need.value == "" {
				return identityRefused("the %s route of %s needs %s", RouteCertificate, field, need.field)
			}
		}
		if r.AnchorNotAfter.IsZero() {
			return identityRefused("the %s route of %s needs %s.anchor_not_after", RouteCertificate, field, field)
		}
		if r.Role == RoleWriter && id.NodeAccount == "" {
			return identityRefused("the writer's %s route needs identity.node_account", RouteCertificate)
		}
	case RoutePublicKey:
		// Fallback 1's provider is optional until M3b.18 builds it.
	default:
		if r.Provider != "" {
			return identityRefused("%s names a provider, which the %s route has none of", field, r.Route)
		}
	}
	return nil
}

// distinctAccounts refuses two of the three accounts sharing an ID: a
// reader whose account is the writer's would read as the writer.
func distinctAccounts(refuse func(string, ...any) error, prefix, reader, writer, node string) error {
	switch {
	case reader != "" && (reader == writer || reader == node):
		return refuse("%s names the reader's account for another role's too", prefix)
	case writer != "" && writer == node:
		return refuse("%s names the writer's account for the nodes' too", prefix)
	}
	return nil
}

// ServiceAccountEmail is the email of the service account id in project:
// <id>@<project>.iam.gserviceaccount.com. It refuses an id that is not a
// drawn account ID (30 of [a-z0-9], a letter first) and a project that is
// not Google's project-ID shape, naming which and never the value, so an
// email it gives holds nothing a shell or a URL would read as more than a
// name.
func ServiceAccountEmail(id, project string) (string, error) {
	if !shortIDShape.MatchString(id) {
		return "", fmt.Errorf("a service account's ID is not %s", shapeShortID)
	}
	if !projectIDShape.MatchString(project) {
		return "", fmt.Errorf("a project's ID is not %s", shapeProject)
	}
	return id + "@" + project + ".iam.gserviceaccount.com", nil
}

// mergeIdentity is mergeOntoNewer's three-way rule applied to Identity field
// by field, with Roles merged per role and Known per provider, as
// SystemImages is merged per component. A nil Identity reads as an empty
// one, so a machine that recorded none and one that recorded some merge as
// any two values do. Nothing left is no Identity.
func mergeIdentity(base, mine, newer *Identity) (*Identity, error) {
	var b, m, n Identity
	if base != nil {
		b = *base
	}
	if mine != nil {
		m = *mine
	}
	if newer != nil {
		n = *newer
	}
	out := n
	bv, mv, ov := reflect.ValueOf(b), reflect.ValueOf(m), reflect.ValueOf(&out).Elem()
	t := ov.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		switch f.Name {
		case "Roles":
			roles, err := mergeKeyed("Identity.Roles", b.Roles, m.Roles, n.Roles, func(r DeviceRole) string { return r.Role }, sameRole)
			if err != nil {
				return nil, err
			}
			out.Roles = roles
			continue
		case "Known":
			known, err := mergeKeyed("Identity.Known", b.Known, m.Known, n.Known, func(k KnownProvider) string { return k.Provider },
				func(x, y KnownProvider) bool { return x == y })
			if err != nil {
				return nil, err
			}
			out.Known = known
			continue
		}
		baseF, mineF, newerF := bv.Field(i), mv.Field(i), ov.Field(i)
		switch {
		case sameField(mineF, baseF):
			// Untouched here; whatever is on disk stands.
		case sameField(newerF, baseF), sameField(newerF, mineF):
			ov.Field(i).Set(mineF)
		default:
			return nil, fmt.Errorf("%w: field Identity.%s was changed by this command and by something else at the same time", ErrMetadataConflict, f.Name)
		}
	}
	if reflect.ValueOf(out).IsZero() {
		return nil, nil
	}
	return &out, nil
}

// sameField compares two of Identity's scalar fields: a time by its instant,
// as a time read from the record and one set in memory may differ only in
// their location; anything else by its value.
func sameField(x, y reflect.Value) bool {
	if tx, ok := x.Interface().(time.Time); ok {
		return tx.Equal(y.Interface().(time.Time))
	}
	return reflect.DeepEqual(x.Interface(), y.Interface())
}

// sameRole compares two roles, the anchor's NotAfter by its instant.
func sameRole(x, y DeviceRole) bool {
	return x.Role == y.Role && x.Route == y.Route && x.Provider == y.Provider && x.AnchorNotAfter.Equal(y.AnchorNotAfter)
}

// mergeKeyed is the three-way rule applied to each key of a list whose
// entries each have a key of their own. A key absent on one side is a value
// like any other, so an entry one side added and the other never touched
// survives, and one only the caller removed is removed. A list that names a
// key twice is refused: which of the two entries is meant cannot be told. The
// result is in the keys' order; an empty result is nil, as a record that
// never had the field reads.
func mergeKeyed[T any](field string, base, mine, newer []T, key func(T) string, same func(T, T) bool) ([]T, error) {
	index := func(list []T) (map[string]T, error) {
		out := make(map[string]T, len(list))
		for _, e := range list {
			k := key(e)
			if _, dup := out[k]; dup {
				return nil, fmt.Errorf("%s names %q twice; the record cannot be merged", field, k)
			}
			out[k] = e
		}
		return out, nil
	}
	bm, err := index(base)
	if err != nil {
		return nil, err
	}
	mm, err := index(mine)
	if err != nil {
		return nil, err
	}
	nm, err := index(newer)
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for _, m := range []map[string]T{bm, mm, nm} {
		for k := range m {
			keys[k] = true
		}
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)

	eq := func(x T, xok bool, y T, yok bool) bool { return xok == yok && (!xok || same(x, y)) }
	var out []T
	for _, k := range names {
		b, bok := bm[k]
		m, mok := mm[k]
		n, nok := nm[k]
		take, tok := n, nok
		switch {
		case eq(m, mok, b, bok):
			// Untouched here; whatever is on disk stands.
		case eq(n, nok, b, bok), eq(n, nok, m, mok):
			take, tok = m, mok
		default:
			return nil, fmt.Errorf("%w: field %s[%q] was changed by this command and by something else at the same time", ErrMetadataConflict, field, k)
		}
		if tok {
			out = append(out, take)
		}
	}
	return out, nil
}
