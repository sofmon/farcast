package cli

import (
	"context"
	"flag"
	"fmt"
)

// Command is one farcast subcommand.
type Command interface {
	Name() string              // e.g. "version"
	Synopsis() string          // one line, shown in `help`
	Usage() string             // full usage, shown in `help <command>`
	SetFlags(fs *flag.FlagSet) // register command-specific flags
	Run(ctx context.Context, env *Env, args []string) error
}

// Registry holds the available commands in registration order.
type Registry struct {
	order  []string
	byName map[string]Command
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Command)}
}

// Register adds c. It panics on a duplicate name (a programmer error).
func (r *Registry) Register(c Command) {
	if _, dup := r.byName[c.Name()]; dup {
		panic("cli: duplicate command " + c.Name())
	}
	r.byName[c.Name()] = c
	r.order = append(r.order, c.Name())
}

// Lookup returns the command with the given name.
func (r *Registry) Lookup(name string) (Command, bool) {
	c, ok := r.byName[name]
	return c, ok
}

// Commands returns the registered commands in registration order.
func (r *Registry) Commands() []Command {
	out := make([]Command, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.byName[n])
	}
	return out
}

// usageError marks an error as misuse (bad arguments), mapping to exit code 2
// rather than the generic runtime failure code 1.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// stubCommand is a registered-but-unimplemented command. It keeps the whole
// command surface visible in help while a feature is pending.
type stubCommand struct {
	name     string
	synopsis string
	phase    string
}

func newStub(name, synopsis, phase string) *stubCommand {
	return &stubCommand{name: name, synopsis: synopsis, phase: phase}
}

func (s *stubCommand) Name() string { return s.name }

func (s *stubCommand) Synopsis() string {
	return fmt.Sprintf("%s   (not yet implemented — phase %s)", s.synopsis, s.phase)
}

func (s *stubCommand) Usage() string {
	return fmt.Sprintf("Usage: farcast %s\n\n%s\n\nNot yet implemented — planned for phase %s.",
		s.name, s.synopsis, s.phase)
}

func (s *stubCommand) SetFlags(*flag.FlagSet) {}

func (s *stubCommand) Run(context.Context, *Env, []string) error {
	return fmt.Errorf("%s is not yet implemented (planned for phase %s)", s.name, s.phase)
}
