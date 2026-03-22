package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

type CertificateManager struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
}

func NewCertificateManager(issuerDomain string) (*CertificateManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   issuerDomain,
			Organization: []string{issuerDomain},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return &CertificateManager{
		PrivateKey:  privateKey,
		Certificate: cert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

func (c *CertificateManager) CertBase64DER() []byte {
	block, _ := pem.Decode(c.CertPEM)
	if block == nil {
		return nil
	}
	return block.Bytes
}
