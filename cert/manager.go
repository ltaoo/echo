package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// Manager handles certificate generation and caching
type Manager struct {
	caCert       *x509.Certificate
	caKey        crypto.PrivateKey
	certCache    sync.Map // map[string]*tls.Certificate
	serverKey    *rsa.PrivateKey
	serverKeyPEM []byte
}

// NewManager creates a new certificate manager
func NewManager(caCert *x509.Certificate, caKey crypto.PrivateKey) (*Manager, error) {
	// Generate a single RSA key pair for all certificates (for performance)
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})

	return &Manager{
		caCert:       caCert,
		caKey:        caKey,
		serverKey:    serverKey,
		serverKeyPEM: serverKeyPEM,
	}, nil
}

// GetCertificate returns a certificate for the given hostname, generating it if necessary
func (m *Manager) GetCertificate(hostname string) (*tls.Certificate, error) {
	// Check cache
	if cached, ok := m.certCache.Load(hostname); ok {
		return cached.(*tls.Certificate), nil
	}

	// Generate new certificate
	cert, err := m.generateCert(hostname)
	if err != nil {
		return nil, err
	}

	// Cache it
	m.certCache.Store(hostname, cert)
	return cert, nil
}

// GetCertificateFunc returns a function suitable for tls.Config.GetCertificate
func (m *Manager) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return m.GetCertificate(hello.ServerName)
	}
}

// generateCert generates a new certificate for the given hostname
func (m *Manager) generateCert(hostname string) (*tls.Certificate, error) {
	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Mini Whistle Proxy"},
			Country:      []string{"US"},
			Province:     []string{"Virginia"},
			Locality:     []string{"Blacksburg"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Add SAN (Subject Alternative Name)
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	// Sign the certificate with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &m.serverKey.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Create tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEM, m.serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return &tlsCert, nil
}
