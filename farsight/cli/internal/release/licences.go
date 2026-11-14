package release

// moduleLicences is the SPDX identifier of every vendored module's licence,
// classified by reading each module's licence file. Notices refuses a module in
// vendor/modules.txt that is missing here, and an entry here that is not in
// vendor/modules.txt, so a vendor change cannot leave it stale.
var moduleLicences = map[string]string{
	"cloud.google.com/go/auth":                           "Apache-2.0",
	"cloud.google.com/go/auth/oauth2adapt":               "Apache-2.0",
	"cloud.google.com/go/compute/metadata":               "Apache-2.0",
	"cloud.google.com/go/container":                      "Apache-2.0",
	"github.com/cespare/xxhash/v2":                       "MIT",
	"github.com/felixge/httpsnoop":                       "MIT",
	"github.com/go-logr/logr":                            "Apache-2.0",
	"github.com/go-logr/stdr":                            "Apache-2.0",
	"github.com/goccy/go-yaml":                           "MIT",
	"github.com/google/s2a-go":                           "Apache-2.0",
	"github.com/googleapis/enterprise-certificate-proxy": "Apache-2.0",
	"github.com/googleapis/gax-go/v2":                    "BSD-3-Clause",
	"go.opentelemetry.io/auto/sdk":                       "Apache-2.0",
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc": "Apache-2.0",
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp":               "Apache-2.0",
	"go.opentelemetry.io/otel":                  "Apache-2.0",
	"go.opentelemetry.io/otel/metric":           "Apache-2.0",
	"go.opentelemetry.io/otel/trace":            "Apache-2.0",
	"golang.org/x/crypto":                       "BSD-3-Clause",
	"golang.org/x/net":                          "BSD-3-Clause",
	"golang.org/x/oauth2":                       "BSD-3-Clause",
	"golang.org/x/sync":                         "BSD-3-Clause",
	"golang.org/x/sys":                          "BSD-3-Clause",
	"golang.org/x/text":                         "BSD-3-Clause",
	"golang.org/x/time":                         "BSD-3-Clause",
	"google.golang.org/api":                     "BSD-3-Clause",
	"google.golang.org/genproto":                "Apache-2.0",
	"google.golang.org/genproto/googleapis/api": "Apache-2.0",
	"google.golang.org/genproto/googleapis/rpc": "Apache-2.0",
	"google.golang.org/grpc":                    "Apache-2.0",
	"google.golang.org/protobuf":                "BSD-3-Clause",
}
