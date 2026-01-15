package terminator

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"quic-terminator/debug"
)

// Config holds configuration for the Terminator.
type Config struct {
	// Listen address (":5521" or "localhost:0" for ephemeral port)
	Listen string

	// TLS Certificate and Key paths
	CertFile string
	KeyFile  string

	// Use same cert as client cert for backend mTLS
	BackendMTLS bool

	// Debug enables debug logging
	Debug bool

	// Logging config per direction
	LogClientChunks  int // Number of client chunks to log (0 = disabled)
	LogServerChunks  int // Number of server chunks to log (0 = disabled)
	SkipClientChunks int // Client chunks to skip before logging
	SkipServerChunks int // Server chunks to skip before logging
	MaxChunkSize     int // Skip chunks larger than this (0 = no limit, default 1MB)
}

// Terminator terminates QUIC connections and bridges them to backends.
// It runs an internal QUIC listener that accepts connections forwarded by a proxy.
type Terminator struct {
	config     Config
	transport  *quic.Transport
	listener   *quic.Listener
	tracker    *dcidTracker
	clientCert *tls.Certificate // Client certificate for backend mTLS

	// InternalAddr is the address of the internal listener.
	// The proxy forwarder should send packets here.
	InternalAddr string

	// DCID → backend mapping (set by RegisterBackend, read by handleConnection)
	backends sync.Map // dcid (hex string) → backend address (string)

	// Session tracking
	sessionCount atomic.Int64
	sessions     sync.Map // sessionID → *session

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new Terminator with the given configuration.
func New(cfg Config) (*Terminator, error) {
	// Enable debug mode if configured
	if cfg.Debug {
		debug.SetEnabled(true)
	}

	t := &Terminator{config: cfg}
	t.ctx, t.cancel = context.WithCancel(context.Background())

	// Load certificate
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	// Store certificate for backend mTLS if enabled
	if cfg.BackendMTLS {
		t.clientCert = &cert
		log.Printf("[terminator] backend mTLS enabled")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Accept any ALPN protocol the client offers
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   chi.SupportedProtos, // Mirror client's offered protocols
			}, nil
		},
	}

	// Setup internal listener address
	addr := cfg.Listen
	if addr == "auto" || addr == "" {
		addr = "localhost:0" // Ephemeral port
	}

	// Create UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	// Wrap with DCID tracker
	t.tracker = newDCIDTracker(udpConn)

	// Create QUIC transport with our tracked connection
	t.transport = &quic.Transport{Conn: t.tracker}

	// Start QUIC listener on transport
	listener, err := t.transport.Listen(tlsConfig, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		t.tracker.Close()
		return nil, err
	}

	t.listener = listener
	t.InternalAddr = udpConn.LocalAddr().String()

	log.Printf("[terminator] internal listener on %s", t.InternalAddr)

	// Start accept loop in goroutine
	t.wg.Add(1)
	go t.acceptLoop()

	return t, nil
}

// RegisterBackend stores the backend address for a DCID.
// Call this when a new connection arrives at the proxy.
func (t *Terminator) RegisterBackend(dcid, backend string) {
	t.backends.Store(dcid, backend)

	dcidShort := dcid
	if len(dcid) > 8 {
		dcidShort = dcid[:8]
	}
	debug.Printf("[terminator] registered backend for dcid=%s → %s", dcidShort, backend)
}

// UnregisterBackend removes the backend mapping for a DCID.
// Call this if the connection is dropped before reaching the terminator.
func (t *Terminator) UnregisterBackend(dcid string) {
	t.backends.Delete(dcid)
}

// acceptLoop accepts connections on the internal listener.
func (t *Terminator) acceptLoop() {
	defer t.wg.Done()

	log.Printf("[terminator] accept loop started")

	for {
		debug.Printf("[terminator] calling Accept()...")
		conn, err := t.listener.Accept(t.ctx)
		if err != nil {
			log.Printf("[terminator] accept loop ended: %v", err)
			return
		}

		debug.Printf("[terminator] accepted connection from %s", conn.RemoteAddr())
		t.wg.Add(1)
		go t.handleConnection(conn)
	}
}

// handleConnection handles a single client connection.
func (t *Terminator) handleConnection(clientConn *quic.Conn) {
	defer t.wg.Done()

	// Get DCID from tracker using remote address
	remoteAddr := clientConn.RemoteAddr().String()
	dcid := t.tracker.GetDCID(remoteAddr)
	if dcid == "" {
		log.Printf("[terminator] no DCID mapping for %s", remoteAddr)
		clientConn.CloseWithError(0x01, "no dcid mapping")
		return
	}

	// Lookup backend by DCID
	entry, ok := t.backends.Load(dcid)
	if !ok {
		dcidShort := dcid
		if len(dcid) > 8 {
			dcidShort = dcid[:8]
		}
		log.Printf("[terminator] no backend for DCID %s", dcidShort)
		clientConn.CloseWithError(0x01, "no backend")
		t.tracker.Delete(remoteAddr)
		return
	}
	backend := entry.(string)

	// Cleanup mappings (one-time use)
	t.tracker.Delete(remoteAddr)
	t.backends.Delete(dcid)

	// Get SNI and ALPN from TLS state for backend connection
	tlsState := clientConn.ConnectionState().TLS
	sni := tlsState.ServerName
	alpn := tlsState.NegotiatedProtocol

	// Dial backend with timeout
	dialCtx, cancel := context.WithTimeout(t.ctx, 10*time.Second)
	defer cancel()

	backendTLS := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni, // Pass through SNI
	}
	if alpn != "" {
		backendTLS.NextProtos = []string{alpn}
	}
	// Add client certificate for mTLS if configured
	if t.clientCert != nil {
		backendTLS.Certificates = []tls.Certificate{*t.clientCert}
	}

	serverConn, err := quic.DialAddr(dialCtx, backend, backendTLS, &quic.Config{
		MaxIdleTimeout:       30 * time.Second,
		HandshakeIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		log.Printf("[terminator] dial backend %s failed: %v", backend, err)
		clientConn.CloseWithError(0x02, "backend unreachable")
		return
	}

	// Check if client is still connected
	select {
	case <-clientConn.Context().Done():
		serverConn.CloseWithError(0, "client gone")
		return
	default:
	}

	// Create session and start bridging
	sess := newSession(clientConn, serverConn, &t.config)
	sessionID := t.sessionCount.Add(1)
	t.sessions.Store(sessionID, sess)
	defer t.sessions.Delete(sessionID)

	log.Printf("[terminator] session %d: %s ↔ %s (ALPN=%s)", sessionID, sni, backend, alpn)

	// Bridge streams (blocks until session ends)
	sess.bridge()

	log.Printf("[terminator] session %d closed", sessionID)
}

// Close gracefully shuts down the terminator.
func (t *Terminator) Close() error {
	// Cancel context (stops accept loop)
	t.cancel()

	// Close listener
	t.listener.Close()

	// Close transport (and underlying tracker/conn)
	t.transport.Close()

	// Close all sessions
	t.sessions.Range(func(key, val any) bool {
		val.(*session).Close()
		return true
	})

	// Wait for all goroutines with timeout
	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return context.DeadlineExceeded
	}
}
