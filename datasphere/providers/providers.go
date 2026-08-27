// Package providers registers the bundled DataSphere cloud adapters as a
// side-effect of import. Blank-import it from a composition root (the
// cmd/datasphere harness, the farcast CLI, the in-cluster service) so the
// adapters are available to datasphere.Open:
//
//	import _ "github.com/sofmon/farcast/datasphere/providers"
//
// Adding a cloud = one new internal/providers/<cloud> package plus one
// blank-import line here. Nothing about the encryption changes, because no
// adapter has ever seen a plaintext byte to begin with.
package providers

import _ "github.com/sofmon/farcast/datasphere/internal/providers/gcs"
