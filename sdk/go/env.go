package farcast

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Environment variables read by the SDK. The platform sets these when it
// runs an application inside an instance; off-instance they fall back to
// safe defaults so nothing needs configuring for local development.
const (
	envInstanceID = "FARCAST_INSTANCE_ID"
	envAppName    = "FARCAST_APP_NAME"
	envLogLevel   = "FARCAST_LOG_LEVEL"
	envLogSource  = "FARCAST_LOG_SOURCE"
)

// instanceID returns the instance identity, defaulting to "local" when run
// outside a FarCast instance.
func instanceID() string {
	if v := os.Getenv(envInstanceID); v != "" {
		return v
	}
	return "local"
}

// appName returns the application name, defaulting to the executable's base
// name (or "unknown") when FARCAST_APP_NAME is not set.
func appName() string {
	if v := os.Getenv(envAppName); v != "" {
		return v
	}
	if len(os.Args) > 0 && os.Args[0] != "" {
		return filepath.Base(os.Args[0])
	}
	return "unknown"
}

// parseLevel maps FARCAST_LOG_LEVEL to a slog.Level. Unrecognised or empty
// values default to info.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// parseBool reports whether s is a truthy value (per strconv.ParseBool).
// Unparseable values are false.
func parseBool(s string) bool {
	b, _ := strconv.ParseBool(strings.TrimSpace(s))
	return b
}
