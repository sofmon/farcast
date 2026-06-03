// Package providers registers the bundled Planck cloud adapters as a
// side-effect of import. Blank-import it from a composition root (the
// cmd/planck harness, the farcast CLI) so the adapters are available to
// planck.Open:
//
//	import _ "github.com/sofmon/farcast/planck/providers"
//
// Adding a cloud = one new internal/providers/<cloud> package plus one
// blank-import line here.
package providers

import _ "github.com/sofmon/farcast/planck/internal/providers/gke"
