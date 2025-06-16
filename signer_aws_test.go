package aws_credential_helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
	"time"
)

func TestCreateCanonicalRequest(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		ecdsaPrivate, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err, "failed to generate ECDSA key")

		serialNumber, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
		require.NoError(t, err)
		now := time.Now()
		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName:   "dapr-test",
				Country:      []string{"GB"},
				Organization: []string{"dapr-org"},
				Province:     []string{"London"},
			},
			Issuer: pkix.Name{
				CommonName:   "dapr-test",
				Country:      []string{"GB"},
				Organization: []string{"dapr-org"},
				Province:     []string{"London"},
			},
			NotBefore:          now,
			NotAfter:           now.AddDate(10, 0, 0),
			PublicKeyAlgorithm: x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &ecdsaPrivate.PublicKey, ecdsaPrivate)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(derBytes)
		require.NoError(t, err)

		signer := NewSigner(cert, ecdsaPrivate)

		mockTime := "20211103T120000Z"
		request, err := createCanonicalRequest(&CreateSessionRequest{
			DurationSeconds: 0,
			ProfileArn:      "testarn",
			RoleArn:         "testrole",
			TrustAnchorArn:  "trust",
			RoleSessionName: "session",
			region:          "aws-east-1",
			mockTime:        &mockTime,
		}, signer)
		require.NoError(t, err)
		assert.NotEmpty(t, request)
		// TODO: Re-implement this test to check the canonical request string
		//var lines []string
		//scanner := bufio.NewScanner(strings.NewReader(canonicalRequestString))
		//for scanner.Scan() {
		//	lines = append(lines, scanner.Text())
		//}
		//assert.Equal(t, "POST", lines[0])
		//assert.Equal(t, "/sessions", lines[1])
		//assert.Equal(t, "", lines[2])
		//assert.Equal(t, "content-type:application/json", lines[3])
		//assert.Equal(t, "host:rolesanywhere.aws-east-1.amazonaws.com", lines[4])
		//assert.Equal(t, "x-amz-date:20211103T120000Z", lines[5])
		//assert.Equal(t, "x-amz-x509:"+base64.StdEncoding.EncodeToString(derBytes), lines[6])
		//assert.Equal(t, "", lines[7])
		//assert.Equal(t, "content-type;host;x-amz-date;x-amz-x509", lines[8])
		//assert.Equal(t, "e1e53a1bd678f67fc9193384d54a32e1083fac28b6b407eb2d0ef66876bd0c07", lines[9])

	})
}

func TestCreateStringToSign(t *testing.T) {
	validAlgorithm := "AWS4-X509-ECDSA-SHA256"
	validRequestDateTime := "20250609T120000Z"
	validCredentialScope := "20250609/us-east-1/rolesanywhere/aws4_request"
	validCanonicalRequest := "POST\n/sessions\n\ncontent-type:application/json\nhost:rolesanywhere.us-east-1.amazonaws.com\nx-amz-date:20211103T120000Z\nx-amz-x509:{base64-encoded DER data}\n\ncontent-type;host;x-amz-date;x-amz-x509\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	validCanonicalRequestHash := "6c7968c182ec60df96d27a9a9b302b79eace5e3972bacc3cf1aadc10b8d7afb4"
	t.Run("Algorithm", func(t *testing.T) {

		tests := []struct {
			Algorithm     string
			Expected      string
			ErrorExpected error
		}{
			{
				Algorithm:     "AWS4-X509",
				Expected:      "",
				ErrorExpected: errors.New(""),
			},
			{
				Algorithm:     "AWS4-X509-ECDSA-SHA256",
				Expected:      fmt.Sprintf("%s\n%s\n%s\n%s", validAlgorithm, validRequestDateTime, validCredentialScope, validCanonicalRequestHash),
				ErrorExpected: nil,
			},
		}

		for _, test := range tests {
			t.Run(test.Algorithm, func(t *testing.T) {
				result, err := CreateStringToSign(test.Algorithm, validRequestDateTime, validCredentialScope,
					validCanonicalRequest)
				if test.ErrorExpected != nil {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				assert.Equal(t, test.Expected, result)
			})
		}
	})

	t.Run("RequestDateTime", func(t *testing.T) {
		_ = validAlgorithm
		t.Skip("unimplemented")
	})
	t.Run("valid", func(t *testing.T) {
		// TODO: Add test that asserts newlines between the request date time, credential scope,
		// and the canonical request but not at the end
		t.Skip("unimplemented")
	})
}

func TestCalculateSignature(t *testing.T) {
	//t.Run("invalid rsa signer", func(t *testing.T) {
	//	rsaSigner, err := rsa.GenerateKey(rand.Reader, 1024)
	//	require.NoError(t, err, "expected no error setting up a signer")
	//	tests := []struct {
	//		stringToSign  string
	//		signer        Signer
	//		expected      string
	//		errorExpected error
	//	}{
	//		{
	//			stringToSign:  "test",
	//			signer:        *NewSigner(rsaSigner, nil),
	//			expected:      "",
	//			errorExpected: errors.New(""),
	//		},
	//	}
	//
	//	for _, test := range tests {
	//		t.Run(test.stringToSign, func(t *testing.T) {
	//			result, err := CalculateSignature(test.stringToSign, test.signer)
	//			if test.errorExpected != nil {
	//				require.Error(t, err)
	//			} else {
	//				require.NoError(t, err)
	//			}
	//			assert.Equal(t, test.expected, result)
	//		})
	//	}
	//})
	t.Skip("not implemeneted")
}

func TestBuildAuthorizationHeader(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Skip("unimplemented")
	})
}
