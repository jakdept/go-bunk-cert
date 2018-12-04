// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.
// Lifted from crypto/ssl/generate_cert.go.

package selfCert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// GenerateRsa generates an RSA x509 key and certificate, for use as a self signed SSL.
func GenerateRsa(host string, rsaBits int, validFor time.Duration) (cert []byte, key []byte, err error) {

	if host == "" {
		host, err = os.Hostname()
		if err != nil {
			return []byte{}, []byte{}, fmt.Errorf(
				"no hostname given and failed to retrieve local: %v", err)
		}
	}

	if rsaBits == 0 {
		rsaBits = 4096
	}
	if rsaBits != 1024 && rsaBits != 2048 && rsaBits != 3072 && rsaBits != 4096 {
		return []byte{}, []byte{}, fmt.Errorf(
			"invalid rsa key size - %d", rsaBits)
	}

	if validFor == time.Duration(0) {
		validFor = time.Hour * 24 * 365
	}
	notBefore := time.Now()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf(
			"failed to generate serial number: %v", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf(
			"failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Acme Co"}},
		DNSNames:     []string{host},

		NotBefore: notBefore,
		NotAfter:  notBefore.Add(validFor),

		IsCA:                  true,
		BasicConstraintsValid: true,

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	pubKeyBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.PublicKey, priv)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf(
			"failed to create certificate: %v", err)
	}

	cert = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pubKeyBytes,
	})
	key = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	return cert, key, nil
}
