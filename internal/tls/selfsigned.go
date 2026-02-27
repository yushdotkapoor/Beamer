package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// CertPaths holds all file paths for the mTLS certificate chain.
type CertPaths struct {
	CACert     string
	CAKey      string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
	ClientP12  string
	Hosts      []string
}

// EnsureMTLSCerts generates the full certificate chain if any pieces are missing:
// CA → server cert (signed by CA) → client cert (signed by CA) → client .p12 export.
func EnsureMTLSCerts(paths CertPaths) error {
	// 1. CA
	if !fileExists(paths.CACert) || !fileExists(paths.CAKey) {
		slog.Info("generating CA certificate")
		if err := generateCA(paths.CACert, paths.CAKey); err != nil {
			return fmt.Errorf("generating CA: %w", err)
		}
	} else {
		slog.Info("using existing CA certificate", "cert", paths.CACert)
	}

	// 2. Server cert signed by CA
	if !fileExists(paths.ServerCert) || !fileExists(paths.ServerKey) {
		slog.Info("generating server certificate signed by CA")
		if err := generateServerCert(paths.ServerCert, paths.ServerKey, paths.CACert, paths.CAKey, paths.Hosts); err != nil {
			return fmt.Errorf("generating server cert: %w", err)
		}
	} else {
		slog.Info("using existing server certificate", "cert", paths.ServerCert)
	}

	// 3. Client cert signed by CA + .p12 export
	if !fileExists(paths.ClientCert) || !fileExists(paths.ClientKey) {
		slog.Info("generating client certificate signed by CA")
		if err := generateClientCert(paths.ClientCert, paths.ClientKey, paths.CACert, paths.CAKey); err != nil {
			return fmt.Errorf("generating client cert: %w", err)
		}
		if err := exportClientP12(paths.ClientCert, paths.ClientKey, paths.CACert, paths.ClientP12); err != nil {
			return fmt.Errorf("exporting client .p12: %w", err)
		}
		slog.Info("client .p12 exported — copy this to your iOS project", "path", paths.ClientP12)
	} else {
		slog.Info("using existing client certificate", "cert", paths.ClientCert)
	}

	return nil
}

// LoadMTLSConfig loads the server certificate and configures TLS to require
// and verify client certificates signed by the CA.
func LoadMTLSConfig(serverCertPath, serverKeyPath, caCertPath string) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading server TLS key pair: %w", err)
	}

	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}, nil
}

// CertFingerprint returns the SHA-256 fingerprint of the certificate at certPath
// in colon-separated hex format (e.g., "AB:CD:EF:...").
func CertFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("reading certificate: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM block found in %s", certPath)
	}

	fingerprint := sha256.Sum256(block.Bytes)
	parts := make([]string, len(fingerprint))
	for i, b := range fingerprint {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":"), nil
}

// generateCA creates a self-signed root CA certificate (100-year validity).
func generateCA(caCertPath, caKeyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := randSerial()
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Beamer CA",
			Organization: []string{"Beamer"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("creating CA certificate: %w", err)
	}

	if err := writePEM(caCertPath, "CERTIFICATE", certDER); err != nil {
		return err
	}
	if err := writeECKey(caKeyPath, key); err != nil {
		return err
	}

	slog.Info("CA certificate generated", "cert", caCertPath)
	return nil
}

// generateServerCert creates a server certificate signed by the CA.
func generateServerCert(certPath, keyPath, caCertPath, caKeyPath string, hosts []string) error {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating server key: %w", err)
	}

	serial, err := randSerial()
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Beamer Media Server",
			Organization: []string{"Beamer"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating server certificate: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return err
	}
	if err := writeECKey(keyPath, key); err != nil {
		return err
	}

	fp := sha256.Sum256(certDER)
	parts := make([]string, len(fp))
	for i, b := range fp {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	slog.Info("server certificate generated",
		"cert", certPath,
		"fingerprint", "SHA-256:"+strings.Join(parts, ":"),
		"hosts", hosts,
	)
	return nil
}

// generateClientCert creates a client certificate signed by the CA.
func generateClientCert(certPath, keyPath, caCertPath, caKeyPath string) error {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating client key: %w", err)
	}

	serial, err := randSerial()
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "PhotoSwap Client",
			Organization: []string{"Beamer"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating client certificate: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return err
	}
	if err := writeECKey(keyPath, key); err != nil {
		return err
	}

	slog.Info("client certificate generated", "cert", certPath)
	return nil
}

// exportClientP12 bundles the client cert + key + CA cert into a PKCS#12 file
// for import on iOS via SecPKCS12Import.
func exportClientP12(clientCertPath, clientKeyPath, caCertPath, p12Path string) error {
	// Load client cert
	clientCertPEM, err := os.ReadFile(clientCertPath)
	if err != nil {
		return fmt.Errorf("reading client cert: %w", err)
	}
	block, _ := pem.Decode(clientCertPEM)
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing client cert: %w", err)
	}

	// Load client key
	clientKeyPEM, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return fmt.Errorf("reading client key: %w", err)
	}
	keyBlock, _ := pem.Decode(clientKeyPEM)
	clientKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parsing client key: %w", err)
	}

	// Load CA cert
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CA cert: %w", err)
	}

	p12Data, err := pkcs12.LegacyRC2.Encode(clientKey, clientCert, []*x509.Certificate{caCert}, "beamer")
	if err != nil {
		return fmt.Errorf("encoding PKCS#12: %w", err)
	}

	if err := os.WriteFile(p12Path, p12Data, 0600); err != nil {
		return fmt.Errorf("writing .p12: %w", err)
	}

	return nil
}

// --- helpers ---

func loadCA(caCertPath, caKeyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA key: %w", err)
	}

	return cert, key, nil
}

func randSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	return serial, nil
}

func writePEM(path, blockType string, der []byte) error {
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func writeECKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling EC key: %w", err)
	}
	return writePEM(path, "EC PRIVATE KEY", der)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
