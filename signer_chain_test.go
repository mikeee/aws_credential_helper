package aws_credential_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCert(t *testing.T, key crypto.Signer, cn string) *x509.Certificate {
	t.Helper()
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func validSessionReq() *CreateSessionRequest {
	mockTime := "20211103T120000Z"
	return &CreateSessionRequest{
		ProfileArn:     "p",
		RoleArn:        "r",
		TrustAnchorArn: "t",
		region:         "us-east-1",
		mockTime:       &mockTime,
	}
}

func TestCreateCanonicalRequest_WithChain(t *testing.T) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leaf := testCert(t, leafKey, "leaf")
	inter := testCert(t, interKey, "intermediate")

	signer := NewSignerWithChain(leaf, []*x509.Certificate{inter}, leafKey)
	req, err := createCanonicalRequest(validSessionReq(), signer)
	require.NoError(t, err)

	// the intermediate is presented via X-Amz-X509-Chain and included in the
	// signed headers
	assert.Equal(t, base64.StdEncoding.EncodeToString(inter.Raw), req.Header.Get("X-Amz-X509-Chain"))
	assert.Contains(t, req.Header.Get("Authorization"), "x-amz-x509-chain")
}

func TestCreateCanonicalRequest_NoChain(t *testing.T) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := testCert(t, leafKey, "leaf")

	signer := NewSigner(leaf, leafKey)
	req, err := createCanonicalRequest(validSessionReq(), signer)
	require.NoError(t, err)

	// no chain header, and signed headers omit x-amz-x509-chain (backwards compatible)
	assert.Empty(t, req.Header.Get("X-Amz-X509-Chain"))
	assert.NotContains(t, req.Header.Get("Authorization"), "x-amz-x509-chain")
}

func TestChainHeader_ExceedsMaxDepth(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := testCert(t, key, "c")

	chain := make([]*x509.Certificate, maxX509ChainDepth+1)
	for i := range chain {
		chain[i] = cert
	}
	signer := NewSignerWithChain(cert, chain, key)
	_, err = signer.chainHeader()
	require.Error(t, err)
}

func TestChainHeader_NilOrEmptyCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := testCert(t, key, "leaf")

	// nil chain entry must error, not panic
	_, err = NewSignerWithChain(cert, []*x509.Certificate{nil}, key).chainHeader()
	require.Error(t, err)

	// chain entry with no DER bytes must error, not panic
	_, err = NewSignerWithChain(cert, []*x509.Certificate{{}}, key).chainHeader()
	require.Error(t, err)
}
