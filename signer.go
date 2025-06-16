package aws_credential_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"io"
)

type Signer struct {
	cert *x509.Certificate
	pkey *ecdsa.PrivateKey
}

// NewSigner creates a new Signer instance with the provided certificate and private key.
// Currently only supporting ECDSA keys however this will change.
func NewSigner(cert *x509.Certificate, pkey *ecdsa.PrivateKey) Signer {
	return Signer{
		cert: cert,
		pkey: pkey,
	}
}

func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.pkey == nil {
		return nil, errors.New("signer is not initialized")
	}
	return s.pkey.Sign(rand, digest, opts)
}
