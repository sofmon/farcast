package farcast

import (
	"context"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Logger is FarCast's structured logging capability. Each call emits one
// JSON object per line to stdout, carrying the ambient instance and app
// identity and, when present, the request ID from the context.
//
// args are alternating key/value pairs, following the same convention as
// the standard library's log/slog:
//
//	log.Info(ctx, "request handled", "method", "GET", "status", 200)
type Logger interface {
	Debug(ctx context.Context, msg string, args ...any)
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)

	// With returns a child logger that adds the given key/value pairs to
	// every record it emits. Children inherit their parent's fields.
	With(args ...any) Logger
}

// Reserved record keys owned by the SDK. Applications should not pass these
// as custom args.
const (
	keyInstance  = "instance"
	keyApp       = "app"
	keyRequestID = "request_id"
)

// logger is the slog-backed implementation of Logger.
type logger struct {
	sl *slog.Logger
}

var _ Logger = logger{}

var (
	logOnce   sync.Once
	logBase   logger
	logWriter *syncWriter
)

// Log returns the process-wide structured logger. It is always safe to call
// and never returns nil; outside a FarCast instance it writes to stdout
// with best-effort identity.
func Log() Logger {
	logOnce.Do(initLog)
	return logBase
}

func initLog() {
	logWriter = &syncWriter{w: os.Stdout}
	logBase = newLogger(
		logWriter,
		parseLevel(os.Getenv(envLogLevel)),
		parseBool(os.Getenv(envLogSource)),
		instanceID(),
		appName(),
	)
}

// newLogger builds a logger writing JSON records to w. It is the seam the
// singleton and the tests share, so test loggers exercise the exact code
// path used in production.
func newLogger(w io.Writer, level slog.Level, addSource bool, instance, app string) logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       level,
		AddSource:   addSource,
		ReplaceAttr: replaceAttr,
	})
	sl := slog.New(h).With(
		slog.String(keyInstance, instance),
		slog.String(keyApp, app),
	)
	return logger{sl: sl}
}

func (l logger) Debug(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelDebug, msg, args)
}

func (l logger) Info(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelInfo, msg, args)
}

func (l logger) Warn(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelWarn, msg, args)
}

func (l logger) Error(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelError, msg, args)
}

func (l logger) With(args ...any) Logger {
	return logger{sl: l.sl.With(args...)}
}

// log builds and dispatches one record. It mirrors the standard library's
// own slog.Logger.log so that the reported source location (when enabled)
// points at the application's call site rather than this wrapper.
func (l logger) log(ctx context.Context, level slog.Level, msg string, args []any) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !l.sl.Enabled(ctx, level) {
		return
	}
	var pcs [1]uintptr
	// Skip runtime.Callers, this function, and the exported level method.
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	if id := RequestID(ctx); id != "" {
		r.Add(keyRequestID, id)
	}
	r.Add(args...)
	_ = l.sl.Handler().Handle(ctx, r)
}

// replaceAttr normalises the built-in record fields to FarCast's documented
// shape: a UTC RFC3339 nanosecond timestamp, a lowercase level, and a
// "file:line" source string.
func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) != 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		if a.Value.Kind() == slog.KindTime {
			return slog.String(slog.TimeKey, a.Value.Time().UTC().Format(time.RFC3339Nano))
		}
	case slog.LevelKey:
		if lvl, ok := a.Value.Any().(slog.Level); ok {
			return slog.String(slog.LevelKey, strings.ToLower(lvl.String()))
		}
	case slog.SourceKey:
		if src, ok := a.Value.Any().(*slog.Source); ok {
			return slog.String(slog.SourceKey, src.File+":"+strconv.Itoa(src.Line))
		}
	}
	return a
}

// SetLogWriter redirects log output to w and returns a function that
// restores the previous writer. It is intended for tests; the production
// default is os.Stdout. Safe to call concurrently with logging.
func SetLogWriter(w io.Writer) (restore func()) {
	Log() // ensure the singleton (and its writer) are initialised
	prev := logWriter.swap(w)
	var once sync.Once
	return func() { once.Do(func() { logWriter.swap(prev) }) }
}

// syncWriter is an io.Writer whose target can be swapped atomically. The
// mutex makes both the swap and every write race-free, which matters
// because the logger is a process-wide singleton reached from many
// goroutines while a test may redirect its output.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func (s *syncWriter) swap(w io.Writer) io.Writer {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.w
	s.w = w
	return prev
}
