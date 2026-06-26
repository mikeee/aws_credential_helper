package aws_credential_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxX509ChainDepth is the maximum number of intermediate certificates IAM
// Roles Anywhere accepts in the X-Amz-X509-Chain header.
const maxX509ChainDepth = 5

type Signer struct {
	cert  *x509.Certificate
	chain []*x509.Certificate
	pkey  *ecdsa.PrivateKey
}

// NewSigner creates a new Signer from a leaf certificate and its private key.
// Currently only supporting ECDSA keys however this will change.
func NewSigner(cert *x509.Certificate, pkey *ecdsa.PrivateKey) Signer {
	return Signer{
		cert: cert,
		pkey: pkey,
	}
}

// NewSignerWithChain creates a Signer that, in addition to the leaf
// certificate, presents the intermediate CA certificates to IAM Roles Anywhere
// via the X-Amz-X509-Chain header. This lets the leaf be validated against a
// trust anchor registered higher in the chain (e.g. the root) rather than the
// immediate issuer.
func NewSignerWithChain(cert *x509.Certificate, chain []*x509.Certificate, pkey *ecdsa.PrivateKey) Signer {
	return Signer{
		cert:  cert,
		chain: chain,
		pkey:  pkey,
	}
}

func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.pkey == nil {
		return nil, errors.New("signer is not initialized")
	}
	return s.pkey.Sign(rand, digest, opts)
}

// chainHeader returns the value for the X-Amz-X509-Chain header: the
// intermediate certificates as comma-delimited, base64-encoded DER. Returns an
// empty string when the signer carries no chain.
func (s Signer) chainHeader() (string, error) {
	if len(s.chain) == 0 {
		return "", nil
	}
	if len(s.chain) > maxX509ChainDepth {
		return "", fmt.Errorf("certificate chain depth %d exceeds maximum of %d", len(s.chain), maxX509ChainDepth)
	}
	parts := make([]string, len(s.chain))
	for i, c := range s.chain {
		parts[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return strings.Join(parts, ","), nil
}
