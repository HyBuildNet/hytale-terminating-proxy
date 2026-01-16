package terminator

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"protohytale"
	"quic-terminator/debug"
)

// PacketAction determines what happens after a handler processes a packet.
type PacketAction int

const (
	PacketContinue PacketAction = iota // Pass to next handler, then forward
	PacketDrop                         // Don't forward the packet
)

// PacketHandler processes a decrypted Hytale protocol packet.
// Return (modifiedData, action). If modifiedData != nil, it replaces pkt.Data.
type PacketHandler func(dcid string, pkt *protohytale.Packet, fromClient bool) (modifiedData []byte, action PacketAction)

// TargetConfig holds TLS config for a specific backend target.
type TargetConfig struct {
	CertFile    string `json:"cert"`
	KeyFile     string `json:"key"`
	BackendMTLS *bool  `json:"backend_mtls,omitempty"` // default: true
}

// Config holds configuration for the Terminator.
type Config struct {
	// Listen address (":5521" or "localhost:0" for ephemeral port)
	Listen string

	// Target-specific TLS configs (backend address → config)
	Targets map[string]*TargetConfig

	// Default TLS config (fallback if no target match)
	Default *TargetConfig

	// Debug enables debug logging and packet parsing
	Debug bool

	// DebugPacketLimit limits packets logged per stream (0 = unlimited)
	DebugPacketLimit int
}

// loadedTarget holds a loaded certificate and its config.
type loadedTarget struct {
	cert        *tls.Certificate
	backendMTLS bool
}

// Terminator terminates QUIC connections and bridges them to backends.
// It runs an internal QUIC listener that accepts connections forwarded by a proxy.
type Terminator struct {
	config    Config
	transport *quic.Transport
	listener  *quic.Listener
	tracker   *dcidTracker

	// InternalAddr is the address of the internal listener.
	// The proxy forwarder should send packets here.
	InternalAddr string

	// Target → loaded certificate + config
	targetCerts map[string]*loadedTarget
	defaultCert *loadedTarget

	// DCID → backend mapping (set by RegisterBackend, read by handleConnection)
	backends sync.Map // dcid (hex string) → backend address (string)

	// Session tracking
	sessionCount atomic.Int64
	sessions     sync.Map // sessionID → *session

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Packet handlers (sequential execution)
	packetHandlers   []PacketHandler
	packetHandlersMu sync.RWMutex
}

// New creates a new Terminator with the given configuration.
func New(cfg Config) (*Terminator, error) {
	// Enable debug mode if configured
	if cfg.Debug {
		debug.SetEnabled(true)
	}

	t := &Terminator{
		config:      cfg,
		targetCerts: make(map[string]*loadedTarget),
	}
	t.ctx, t.cancel = context.WithCancel(context.Background())

	// Load default cert if configured
	if cfg.Default != nil {
		cert, err := tls.LoadX509KeyPair(cfg.Default.CertFile, cfg.Default.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("default cert: %w", err)
		}
		t.defaultCert = &loadedTarget{
			cert:        &cert,
			backendMTLS: cfg.Default.BackendMTLS == nil || *cfg.Default.BackendMTLS,
		}
		log.Printf("[terminator] loaded default certificate")
	}

	// Load target-specific certs
	for target, tcfg := range cfg.Targets {
		cert, err := tls.LoadX509KeyPair(tcfg.CertFile, tcfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("cert for %s: %w", target, err)
		}
		t.targetCerts[target] = &loadedTarget{
			cert:        &cert,
			backendMTLS: tcfg.BackendMTLS == nil || *tcfg.BackendMTLS,
		}
		log.Printf("[terminator] loaded certificate for target %s", target)
	}

	// Validate: need at least default or one target
	if t.defaultCert == nil && len(t.targetCerts) == 0 {
		return nil, errors.New("no certificates configured (need default or targets)")
	}

	// TLS config with dynamic cert selection
	tlsConfig := &tls.Config{
		GetConfigForClient: t.getConfigForClient,
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

// getConfigForClient selects the TLS certificate based on backend target.
// Called during TLS handshake - looks up: RemoteAddr → DCID → Backend → Cert
func (t *Terminator) getConfigForClient(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	var cert *tls.Certificate

	// Try to find target-specific cert
	if chi.Conn != nil {
		addr := chi.Conn.RemoteAddr().String()
		dcid := t.tracker.GetDCID(addr)

		if dcid != "" {
			if entry, ok := t.backends.Load(dcid); ok {
				backend := entry.(string)
				if target, ok := t.targetCerts[backend]; ok {
					cert = target.cert
					debug.Printf("[terminator] using cert for target %s", backend)
				}
			}
		}
	}

	// Fallback to default
	if cert == nil && t.defaultCert != nil {
		cert = t.defaultCert.cert
		debug.Printf("[terminator] using default cert")
	}

	if cert == nil {
		return nil, errors.New("no certificate available for connection")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   chi.SupportedProtos, // Mirror client's offered protocols
	}, nil
}

// getTargetConfig returns the loaded target config for a backend address.
func (t *Terminator) getTargetConfig(backend string) *loadedTarget {
	if target, ok := t.targetCerts[backend]; ok {
		return target
	}
	return t.defaultCert
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

// AddPacketHandler adds a handler for decrypted packets.
// Handlers are executed in the order they are added.
func (t *Terminator) AddPacketHandler(h PacketHandler) {
	t.packetHandlersMu.Lock()
	t.packetHandlers = append(t.packetHandlers, h)
	t.packetHandlersMu.Unlock()
}

// HasPacketHandlers returns true if any handlers are registered.
func (t *Terminator) HasPacketHandlers() bool {
	t.packetHandlersMu.RLock()
	defer t.packetHandlersMu.RUnlock()
	return len(t.packetHandlers) > 0
}

// runPacketHandlers executes all handlers sequentially.
// Returns (finalData, shouldDrop).
func (t *Terminator) runPacketHandlers(dcid string, pkt *protohytale.Packet, fromClient bool) ([]byte, bool) {
	t.packetHandlersMu.RLock()
	handlers := t.packetHandlers
	t.packetHandlersMu.RUnlock()

	var currentData []byte
	for _, h := range handlers {
		modData, action := h(dcid, pkt, fromClient)
		if action == PacketDrop {
			return nil, true
		}
		if modData != nil {
			currentData = modData
			pkt.Data = modData // For next handler
		}
	}
	return currentData, false
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

	// Get target config for mTLS
	targetCfg := t.getTargetConfig(backend)

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
	// Add client certificate for mTLS if configured for this target
	if targetCfg != nil && targetCfg.backendMTLS && targetCfg.cert != nil {
		backendTLS.Certificates = []tls.Certificate{*targetCfg.cert}
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
	sess := newSession(clientConn, serverConn, t.config.DebugPacketLimit, t, dcid)
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
