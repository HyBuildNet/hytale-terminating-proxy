package terminator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// createTestCert generates a self-signed test certificate
func createTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	// Generate key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "example.com"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Write cert PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	// Write key PEM
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatal(err)
	}

	return certFile, keyFile
}

func TestNew(t *testing.T) {
	certFile, keyFile := createTestCert(t)

	term, err := New(Config{
		Listen: "localhost:0",
		Default: &TargetConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer term.Close()

	if term.InternalAddr == "" {
		t.Error("InternalAddr should not be empty")
	}
}

func TestNew_InvalidCert(t *testing.T) {
	_, err := New(Config{
		Listen: "localhost:0",
		Default: &TargetConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
	})
	if err == nil {
		t.Error("Expected error for invalid cert paths")
	}
}

func TestNew_NoCerts(t *testing.T) {
	_, err := New(Config{
		Listen: "localhost:0",
	})
	if err == nil {
		t.Error("Expected error when no certificates configured")
	}
}

func TestRegisterBackend(t *testing.T) {
	certFile, keyFile := createTestCert(t)

	term, err := New(Config{
		Listen: "localhost:0",
		Default: &TargetConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer term.Close()

	// Register a backend
	term.RegisterBackend("aabbccdd", "backend.example.com:5521")

	// Verify it's stored
	entry, ok := term.backends.Load("aabbccdd")
	if !ok {
		t.Error("Backend should be registered")
	}
	if entry.(string) != "backend.example.com:5521" {
		t.Errorf("Backend mismatch: got %s", entry)
	}

	// Unregister
	term.UnregisterBackend("aabbccdd")

	_, ok = term.backends.Load("aabbccdd")
	if ok {
		t.Error("Backend should be unregistered")
	}
}

func TestClose(t *testing.T) {
	certFile, keyFile := createTestCert(t)

	term, err := New(Config{
		Listen: "localhost:0",
		Default: &TargetConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Close should complete without error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- term.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}
	case <-ctx.Done():
		t.Error("Close timed out")
	}
}

func TestNew_WithTargets(t *testing.T) {
	certFile, keyFile := createTestCert(t)
	cert2File, key2File := createTestCert(t)

	term, err := New(Config{
		Listen: "localhost:0",
		Targets: map[string]*TargetConfig{
			"server1:5521": {
				CertFile: certFile,
				KeyFile:  keyFile,
			},
			"server2:5521": {
				CertFile: cert2File,
				KeyFile:  key2File,
			},
		},
		Default: &TargetConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer term.Close()

	// Verify target certs loaded
	if len(term.targetCerts) != 2 {
		t.Errorf("Expected 2 target certs, got %d", len(term.targetCerts))
	}
	if term.defaultCert == nil {
		t.Error("Default cert should be loaded")
	}
}

func TestParseQUICDCID(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   string
	}{
		{
			name: "valid Initial packet",
			// Long header (0xc0), version (4 bytes), DCID len (4), DCID (01020304)
			packet: []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x02, 0x03, 0x04},
			want:   "01020304",
		},
		{
			name: "empty DCID",
			// Long header, version, DCID len = 0
			packet: []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x00},
			want:   "",
		},
		{
			name: "short header (no DCID)",
			// Short header (first bit = 0)
			packet: []byte{0x40, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x02, 0x03, 0x04},
			want:   "",
		},
		{
			name:   "packet too short",
			packet: []byte{0xc0, 0x00, 0x00},
			want:   "",
		},
		{
			name:   "nil packet",
			packet: nil,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseQUICDCID(tt.packet)
			if got != tt.want {
				t.Errorf("ParseQUICDCID() = %q, want %q", got, tt.want)
			}
		})
	}
}
