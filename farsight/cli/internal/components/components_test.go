package components

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// releaseTable is a well-formed table, as farcast-release writes one.
func releaseTable() Table {
	d := func(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }
	t := Table{
		Format:   1,
		Go:       "go1.27.4",
		Base:     "gcr.io/distroless/static:nonroot@" + d('b'),
		Platform: "linux/amd64",
		Revision: strings.Repeat("0", 40),
	}
	for _, c := range All() {
		t.Components = append(t.Components, Entry{
			Name:         c.Name,
			Package:      c.Package,
			BinaryPath:   c.BinaryPath,
			Go:           "go1.27.4",
			BinarySHA256: strings.Repeat("a", 64),
			BinarySize:   7_000_000,
			Layer:        d('1'),
			LayerSize:    3_000_000,
			DiffID:       d('2'),
			Config:       d('3'),
			Manifest:     d('4'),
		})
	}
	return t
}

func encode(t *testing.T, table Table) []byte {
	t.Helper()
	data, err := EncodeTable(table)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseTableAcceptsAReleaseTable(t *testing.T) {
	want := releaseTable()
	got, err := ParseTable(encode(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if got.Go != want.Go || got.Base != want.Base || got.Revision != want.Revision || len(got.Components) != 4 {
		t.Fatalf("ParseTable = %+v", got)
	}
	for _, rev := range []string{"", strings.Repeat("f", 64)} {
		table := releaseTable()
		table.Revision = rev
		if _, err := ParseTable(encode(t, table)); err != nil {
			t.Fatalf("revision %q (the layers subcommand's, or a SHA-256 repository's) was refused: %v", rev, err)
		}
	}
	table := releaseTable()
	table.Modified = true
	if got, err := ParseTable(encode(t, table)); err != nil || !got.Modified {
		t.Fatalf("a modified table = %+v, %v; want it read as modified", got, err)
	}
}

func TestParseTableRefuses(t *testing.T) {
	entry := func(name string, edit func(*Entry)) func(*Table) {
		return func(t *Table) {
			for i := range t.Components {
				if t.Components[i].Name == name {
					edit(&t.Components[i])
				}
			}
		}
	}
	cases := map[string]struct {
		edit func(*Table)
		raw  func([]byte) []byte // applied to the encoding instead, when set
	}{
		"an unknown field": {raw: func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"format": 1,`), []byte(`"format": 1, "signed": true,`), 1)
		}},
		"an unknown entry field": {raw: func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"name": "fatline",`), []byte(`"name": "fatline", "extra": 1,`), 1)
		}},
		"trailing data":         {raw: func(b []byte) []byte { return append(b, []byte("{}")...) }},
		"a second object":       {raw: func(b []byte) []byte { return append(b, b...) }},
		"format 2":              {edit: func(t *Table) { t.Format = 2 }},
		"another platform":      {edit: func(t *Table) { t.Platform = "linux/arm64" }},
		"an empty go":           {edit: func(t *Table) { t.Go = "" }},
		"an empty base":         {edit: func(t *Table) { t.Base = "" }},
		"a short revision":      {edit: func(t *Table) { t.Revision = "006e479" }},
		"an uppercase revision": {edit: func(t *Table) { t.Revision = strings.Repeat("A", 40) }},
		"a revision of 41":      {edit: func(t *Table) { t.Revision = strings.Repeat("0", 41) }},
		"three components":      {edit: func(t *Table) { t.Components = t.Components[:3] }},
		"a fifth component": {edit: func(t *Table) {
			t.Components = append(t.Components, Entry{Name: "keeper"})
		}},
		"a component twice": {edit: func(t *Table) { t.Components[3] = t.Components[0] }},
		"an unknown name":   {edit: entry("shrike", func(e *Entry) { e.Name = "shrike2" })},
		"another package":   {edit: entry("fatline", func(e *Entry) { e.Package = "./evil/cmd/fatline" })},
		"another binary path": {edit: entry("technocore", func(e *Entry) {
			e.BinaryPath = "/bin/technocore"
		})},
		"an entry built with another go": {edit: entry("datasphered", func(e *Entry) { e.Go = "go1.27.3" })},
		"a layer digest that is not sha256": {edit: entry("fatline", func(e *Entry) {
			e.Layer = "sha512:" + strings.Repeat("1", 64)
		})},
		"a short diff_id":     {edit: entry("fatline", func(e *Entry) { e.DiffID = "sha256:abc" })},
		"an uppercase config": {edit: entry("fatline", func(e *Entry) { e.Config = "sha256:" + strings.Repeat("A", 64) })},
		"an empty manifest":   {edit: entry("fatline", func(e *Entry) { e.Manifest = "" })},
		"a short binary hash": {edit: entry("shrike", func(e *Entry) { e.BinarySHA256 = "abc" })},
		"a prefixed binary hash": {edit: entry("shrike", func(e *Entry) {
			e.BinarySHA256 = "sha256:" + strings.Repeat("a", 64)
		})},
		"a zero binary size":    {edit: entry("shrike", func(e *Entry) { e.BinarySize = 0 })},
		"a negative layer size": {edit: entry("shrike", func(e *Entry) { e.LayerSize = -1 })},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			table := releaseTable()
			if c.edit != nil {
				c.edit(&table)
			}
			data := encode(t, table)
			if c.raw != nil {
				data = c.raw(encode(t, releaseTable()))
			}
			if got, err := ParseTable(data); err == nil {
				t.Fatalf("ParseTable accepted %+v", got)
			}
		})
	}
}

func TestEncodeTableIsByteStable(t *testing.T) {
	table := releaseTable()
	// Out of order on the way in: the encoding sorts by name.
	table.Components[0], table.Components[3] = table.Components[3], table.Components[0]
	first := encode(t, table)
	if table.Components[0].Name != "technocore" {
		t.Fatal("EncodeTable reordered its input")
	}
	parsed, err := ParseTable(first)
	if err != nil {
		t.Fatal(err)
	}
	second := encode(t, parsed)
	if !bytes.Equal(first, second) {
		t.Fatalf("encode, parse, encode changed the bytes:\n%s\n---\n%s", first, second)
	}
	if !bytes.HasSuffix(first, []byte("}\n")) || bytes.Contains(first, []byte("\r")) {
		t.Fatal("the table does not end in one LF")
	}
	names := []string{}
	for _, e := range parsed.Components {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "datasphered,fatline,shrike,technocore" {
		t.Fatalf("components encoded as %v, want sorted by name", names)
	}
}

func TestUntaggedBuildCarriesNothing(t *testing.T) {
	if Embedded() {
		t.Skip("this build carries the components (farcast_embedded)")
	}
	if Artifacts() != nil {
		t.Fatal("Artifacts is not nil")
	}
	for _, c := range All() {
		if _, ok := Lookup(c.Name); ok {
			t.Fatalf("Lookup(%s) found something", c.Name)
		}
		if _, err := Layer(c.Name); !errors.Is(err, ErrNotEmbedded) {
			t.Fatalf("Layer(%s) = %v, want ErrNotEmbedded", c.Name, err)
		}
	}
	if Base() != "" || Revision() != "" || Modified() {
		t.Fatal("a source build reports a base, a revision or a modified tree")
	}
}

func TestComponentsAreTheFour(t *testing.T) {
	want := map[string]Component{
		"datasphered": {Name: "datasphered", ImagePath: "system/datasphered", Package: "./datasphere/cmd/datasphere", BinaryPath: "/datasphere"},
		"fatline":     {Name: "fatline", ImagePath: "system/fatline", Package: "./fatline/cmd/fatline", BinaryPath: "/fatline"},
		"shrike":      {Name: "shrike", ImagePath: "system/shrike", Package: "./shrike/cmd/shrike", BinaryPath: "/shrike"},
		"technocore":  {Name: "technocore", ImagePath: "system/technocore", Package: "./technocore/cmd/technocore", BinaryPath: "/technocore"},
	}
	all := All()
	if len(all) != 4 {
		t.Fatalf("All() = %v", all)
	}
	for i, c := range all {
		if i > 0 && all[i-1].Name >= c.Name {
			t.Fatalf("All() is not sorted by name: %v", all)
		}
		if want[c.Name] != c {
			t.Fatalf("%s = %+v, want %+v", c.Name, c, want[c.Name])
		}
		if got, ok := ByName(c.Name); !ok || got != c {
			t.Fatalf("ByName(%s) = %+v, %v", c.Name, got, ok)
		}
	}
	if _, ok := ByName("keeper"); ok {
		t.Fatal("ByName found a fifth component")
	}
}
