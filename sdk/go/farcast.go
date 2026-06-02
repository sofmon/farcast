// Package farcast is the Go SDK for applications running on a FarCast
// instance. It is the syscall surface between an application and the
// FarCast environment: instead of calling cloud APIs directly, an
// application calls farcast.Log, farcast.Storage, farcast.Net, and so on,
// and the FarCast modules broker the underlying cloud.
//
// Each capability is reached through a zero-ceremony accessor that returns
// an interface configured from the environment on first use:
//
//	log := farcast.Log()
//	log.Info(ctx, "service starting", "version", "1.4.2")
//
// Naming: where an interface would collide with its accessor it takes an
// "API" suffix — Storage returns StorageAPI, Config returns ConfigAPI, and
// so on — because Go does not allow a function and a type to share a name,
// and the ergonomic call surface takes priority. Logging keeps the
// idiomatic name Logger.
//
// As of phases 0.2 and 0.3 of the build plan, logging (farcast.Log) is the
// only implemented capability. The Config, Storage, Net, and AI accessors
// return stubs whose methods yield ErrNotImplemented until their respective
// phases land, so applications can compile against the full surface early.
//
// See README.md in this directory for the full specification.
package farcast
