package terminator

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"quic-terminator/debug"
)

// streamBufPool provides reusable 32KB buffers for stream copying.
var streamBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// session represents a bridged connection between client and server.
type session struct {
	clientConn  *quic.Conn
	serverConn  *quic.Conn
	ctx         context.Context
	cancel      context.CancelFunc
	closed      atomic.Bool
	wg          sync.WaitGroup
	packetLimit int // Debug: max packets to log per stream (0 = unlimited)

	// For packet handler support
	term *Terminator // Parent terminator (for handler access)
	dcid string      // DCID of this session
}

func newSession(client, server *quic.Conn, packetLimit int, term *Terminator, dcid string) *session {
	ctx, cancel := context.WithCancel(context.Background())
	return &session{
		clientConn:  client,
		serverConn:  server,
		ctx:         ctx,
		cancel:      cancel,
		packetLimit: packetLimit,
		term:        term,
		dcid:        dcid,
	}
}

func (s *session) bridge() {
	// Monitor for connection close from either side
	go func() {
		select {
		case <-s.clientConn.Context().Done():
		case <-s.serverConn.Context().Done():
		}
		s.Close()
	}()

	// 4 goroutines for all stream types
	s.wg.Add(4)
	go s.bridgeBidi(s.clientConn, s.serverConn, true)  // Client-initiated
	go s.bridgeBidi(s.serverConn, s.clientConn, false) // Server-initiated
	go s.bridgeUni(s.clientConn, s.serverConn, true)   // Client → Server
	go s.bridgeUni(s.serverConn, s.clientConn, false)  // Server → Client

	s.wg.Wait()
}

func (s *session) bridgeBidi(src, dst *quic.Conn, srcIsClient bool) {
	defer s.wg.Done()

	for {
		srcStream, err := src.AcceptStream(s.ctx)
		if err != nil {
			return
		}

		dstStream, err := dst.OpenStream()
		if err != nil {
			srcStream.Close()
			return
		}

		s.wg.Add(1)
		go s.copyBidiStream(srcStream, dstStream, srcIsClient)
	}
}

func (s *session) copyBidiStream(src, dst *quic.Stream, srcIsClient bool) {
	defer s.wg.Done()
	defer src.Close()
	defer dst.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// src → dst
	go func() {
		defer wg.Done()
		if s.term.HasPacketHandlers() {
			s.copyStreamWithHandlers(dst, src, srcIsClient)
		} else if debug.IsEnabled() {
			s.copyStreamParsed(dst, src, srcIsClient)
		} else {
			s.copyStream(dst, src)
		}
		dst.Close() // Send FIN
	}()

	// dst → src (responses)
	go func() {
		defer wg.Done()
		if s.term.HasPacketHandlers() {
			s.copyStreamWithHandlers(src, dst, !srcIsClient)
		} else if debug.IsEnabled() {
			s.copyStreamParsed(src, dst, !srcIsClient)
		} else {
			s.copyStream(src, dst)
		}
		src.Close()
	}()

	// Wait for BOTH (important for correct cleanup)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Both finished
	case <-s.ctx.Done():
		// Session closed - defer handles cleanup
	}
}

func (s *session) bridgeUni(src, dst *quic.Conn, srcIsClient bool) {
	defer s.wg.Done()

	for {
		srcStream, err := src.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}

		dstStream, err := dst.OpenUniStream()
		if err != nil {
			srcStream.CancelRead(0) // Important: cancel source!
			return
		}

		s.wg.Add(1)
		go s.copyUniStream(srcStream, dstStream, srcIsClient)
	}
}

func (s *session) copyUniStream(src *quic.ReceiveStream, dst *quic.SendStream, srcIsClient bool) {
	defer s.wg.Done()
	defer src.CancelRead(0) // Cancel source when done
	defer dst.Close()

	if s.term.HasPacketHandlers() {
		s.copyStreamWithHandlers(dst, src, srcIsClient)
	} else if debug.IsEnabled() {
		s.copyStreamParsed(dst, src, srcIsClient)
	} else {
		s.copyStream(dst, src)
	}
}

// copyStream copies data with buffer pooling.
func (s *session) copyStream(dst io.Writer, src io.Reader) (int64, error) {
	buf := streamBufPool.Get().(*[]byte)
	defer streamBufPool.Put(buf)

	var total int64
	for {
		n, err := src.Read(*buf)
		if n > 0 {
			nw, werr := dst.Write((*buf)[:n])
			total += int64(nw)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

// Close closes the session and both connections.
func (s *session) Close() {
	if !s.closed.Swap(true) {
		s.cancel()
		s.clientConn.CloseWithError(0, "session closed")
		s.serverConn.CloseWithError(0, "session closed")
	}
}
