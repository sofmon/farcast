package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"golang.org/x/sys/unix"
)

// gitTokenNoCTTYChild marks the child run of
// TestGitCredentialReadTakesNoControllingTerminal.
const gitTokenNoCTTYChild = "FARCAST_TEST_GITTOKEN_NOCTTY_CHILD"

// openPseudoTerminal opens a pseudo-terminal's master, O_NOCTTY, and names
// its other end as macOS's own ptsname does: by the master's minor device
// number. The master's ioctls go through SyscallConn, not Fd, so the master
// stays non-blocking and a write to it can be given a deadline. It is closed
// when the test ends.
func openPseudoTerminal(t *testing.T) (*os.File, string) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open a pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	var terminal string
	ptyControl(t, master, "open a pseudo-terminal", func(fd int) error {
		if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
			return fmt.Errorf("grant it: %w", err)
		}
		if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
			return fmt.Errorf("unlock it: %w", err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return fmt.Errorf("examine it: %w", err)
		}
		terminal = fmt.Sprintf("/dev/ttys%03d", unix.Minor(uint64(st.Rdev)))
		return nil
	})
	return master, terminal
}

// ptyControl runs do on file's descriptor through SyscallConn, and fails the
// test with what when either fails.
func ptyControl(t *testing.T, file *os.File, what string, do func(fd int) error) {
	t.Helper()
	conn, err := file.SyscallConn()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	var doErr error
	if err := conn.Control(func(fd uintptr) { doErr = do(int(fd)) }); err != nil || doErr != nil {
		t.Fatalf("%s: %v, %v", what, err, doErr)
	}
}

// hasControllingTerminal says /dev/tty opens. It names the process's
// controlling terminal, and opens only when the process has one.
func hasControllingTerminal() bool {
	f, err := os.OpenFile("/dev/tty", os.O_RDONLY|unix.O_NOCTTY, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// ADR 0023 M2.8 (design §33, A33-30 step 12; review FT-MFC-3): readGitToken
// refuses a terminal it opened before it reads a byte of it, which
// /dev/null, empty at once, cannot show. A line is typed at a
// pseudo-terminal whose master stays open, so a read of its other end would
// return that line and then wait for more; readGitToken answers with its
// refusal at once instead, and the typed line is still there to be read
// afterwards. macOS only: its pseudo-terminal is opened through macOS's own
// ioctls and naming.
func TestGitCredentialReadRefusesATerminalBeforeReadingIt(t *testing.T) {
	master, terminal := openPseudoTerminal(t)
	// The other end is opened, and held open, before anything is typed, for
	// two reasons. A write to the master waits while its other end has never
	// been opened, so typing first would hang; the write's deadline below
	// makes that a failure instead. And while the other end is held,
	// readGitToken's close of it is not the last close, which would discard
	// the typed line.
	held, err := os.OpenFile(terminal, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open the pseudo-terminal's other end: %v", err)
	}
	defer func() { _ = held.Close() }()
	// It is this pseudo-terminal's other end, not another terminal's: a
	// window size set on the master shows there. Nothing is read from it or
	// written to it before that holds.
	ptyControl(t, master, "size the pseudo-terminal", func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 4321, Col: 1234})
	})
	var size *unix.Winsize
	ptyControl(t, held, "read "+terminal+"'s window size", func(fd int) (err error) {
		size, err = unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
		return err
	})
	if size.Row != 4321 || size.Col != 1234 {
		t.Fatalf("%s is not the pseudo-terminal's other end: its window size is %dx%d", terminal, size.Row, size.Col)
	}
	if err := master.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set a deadline on the pseudo-terminal's master: %v", err)
	}
	if _, err := master.Write([]byte("typed\n")); err != nil {
		t.Fatalf("type a line: %v", err)
	}

	env, _, _ := testEnvBoth(config.Dir(t.TempDir()), output.ModeJSON)
	type answer struct {
		raw []byte
		err error
	}
	got := make(chan answer, 1)
	go func() {
		raw, err := readGitToken(env, terminal)
		got <- answer{raw, err}
	}()
	select {
	case a := <-got:
		if want := terminal + " is a device, such as a terminal, which would show the token as it is typed"; a.err == nil || a.err.Error() != want || a.raw != nil {
			t.Fatalf("readGitToken(a terminal) = %d bytes, %v; want %q, nothing read", len(a.raw), a.err, want)
		}
	case <-time.After(10 * time.Second):
		// Closing the terminal ends the read, so the goroutine returns.
		_ = master.Close()
		<-got
		t.Fatal("readGitToken waited on a terminal for 10 s: it read from it")
	}

	// The typed line is still unread.
	if err := held.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline on the pseudo-terminal: %v", err)
	}
	buf := make([]byte, 64)
	n, err := held.Read(buf)
	if err != nil || string(buf[:n]) != "typed\n" {
		t.Errorf("the terminal holds %q, %v after the refusal; want the typed line, unread", buf[:n], err)
	}
}

// TestGitCredentialReadTakesNoControllingTerminal (ADR 0023 M2.8, design §36
// A36-2; final check K-FA-1): readGitToken opens its path with O_NOCTTY. A
// process that leads its own session and has no controlling terminal, as one
// started by setsid or launchd, takes a terminal it opens without that flag
// as its controlling terminal, and readGitToken's open of a terminal it then
// refuses must not do that. go test never runs a test binary as a session
// leader, so the test runs itself again as a child in a session of its own.
// macOS only, for its pseudo-terminal's naming.
func TestGitCredentialReadTakesNoControllingTerminal(t *testing.T) {
	if os.Getenv(gitTokenNoCTTYChild) == "1" {
		readTakesNoControllingTerminalChild(t)
		return
	}
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, gitTokenNoCTTYChild+"=") })
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestGitCredentialReadTakesNoControllingTerminal$", "-test.count=1", "-test.v", "-test.timeout=2m")
	cmd.Env = append(env, gitTokenNoCTTYChild+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil || !strings.Contains(out.String(), "--- PASS: TestGitCredentialReadTakesNoControllingTerminal") {
		t.Fatalf("the child, in a session of its own, did not pass: %v\n%s", err, out.String())
	}
}

// readTakesNoControllingTerminalChild is the child's half. It leads a new
// session with no controlling terminal, opens a pseudo-terminal and holds its
// other end, both O_NOCTTY, and has readGitToken refuse that other end.
// /dev/tty must still not open afterwards.
func readTakesNoControllingTerminalChild(t *testing.T) {
	// Were the terminal to become the child's, closing its master would send
	// the child a hangup, which would end it before it reports.
	signal.Ignore(syscall.SIGHUP)
	if sid, err := unix.Getsid(0); err != nil || sid != os.Getpid() {
		t.Fatalf("the child leads no session of its own: its session is %d (%v), its pid %d", sid, err, os.Getpid())
	}
	if hasControllingTerminal() {
		t.Fatal("the child, in a new session, already has a controlling terminal")
	}
	master, terminal := openPseudoTerminal(t)
	held, err := os.OpenFile(terminal, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open the pseudo-terminal's other end: %v", err)
	}
	defer func() { _ = held.Close() }()
	if hasControllingTerminal() {
		t.Fatalf("an O_NOCTTY open of %s gave the child a controlling terminal", terminal)
	}
	env, _, _ := testEnvBoth(config.Dir(t.TempDir()), output.ModeJSON)
	type answer struct {
		raw []byte
		err error
	}
	got := make(chan answer, 1)
	go func() {
		raw, err := readGitToken(env, terminal)
		got <- answer{raw, err}
	}()
	var a answer
	select {
	case a = <-got:
	case <-time.After(10 * time.Second):
		// Closing the terminal ends the read, so the goroutine returns.
		_ = master.Close()
		<-got
		t.Fatal("readGitToken waited on a terminal for 10 s: it read from it")
	}
	if want := terminal + " is a device, such as a terminal, which would show the token as it is typed"; a.err == nil || a.err.Error() != want || a.raw != nil {
		t.Fatalf("readGitToken(a terminal) = %d bytes, %v; want %q, nothing read", len(a.raw), a.err, want)
	}
	if hasControllingTerminal() {
		t.Fatalf("readGitToken's open of %s made it the child's controlling terminal", terminal)
	}
}
