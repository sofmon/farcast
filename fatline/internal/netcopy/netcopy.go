// Package netcopy carries bytes between two halves of a tunnelled connection.
//
// It is deliberately tiny and deliberately shared. FatLine relays two kinds of
// stream — an application's outbound CONNECT and the operator's inbound stream
// to an in-instance service — and both must be relayed the same way: copied,
// never parsed. Keeping one implementation means there is one place to audit
// for the property that matters, which is that FatLine has no code path that
// interprets what it is carrying.
package netcopy

import "io"

// Duplex copies in both directions until each finishes, and reports the bytes
// moved each way.
//
// It half-closes the upstream write side when the client side ends, so a
// well-behaved peer sees a clean EOF rather than waiting for a timeout. Copy
// errors are deliberately not returned: either side closing is the normal end
// of a relayed stream, and there is nothing this layer could do with the
// distinction that would not amount to interpreting the traffic.
func Duplex(upstream io.ReadWriter, clientDst io.Writer, clientSrc io.Reader) (up, down int64) {
	done := make(chan struct{}, 2)
	go func() {
		up, _ = io.Copy(upstream, clientSrc)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		down, _ = io.Copy(clientDst, upstream)
		done <- struct{}{}
	}()
	<-done
	<-done
	return up, down
}
