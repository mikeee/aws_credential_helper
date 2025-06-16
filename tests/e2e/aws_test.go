//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/mikeee/aws_credential_helper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func TestE2E(t *testing.T) {
	cert := os.Getenv("E2E_CERT")
	pkey := os.Getenv("E2E_KEY")

	trustProfileArn := os.Getenv("E2E_TRUST_PROFILE_ARN")
	trustAnchorArn := os.Getenv("E2E_TRUST_ANCHOR_ARN")
	assumeRoleArn := os.Getenv("E2E_ASSUME_ROLE_ARN")

	t.Run("Connect to AWSRA", func(t *testing.T) {
		if cert == "" || pkey == "" || trustProfileArn == "" || trustAnchorArn == "" || assumeRoleArn == "" {
			t.Error("E2E test failure: E2E_CERT, E2E_KEY, E2E_TRUST_PROFILE_ARN, E2E_TRUST_ANCHOR_ARN, and E2E_ASSUME_ROLE_ARN environment variables must be set")
		}

		blockCert, rest := pem.Decode([]byte(cert))
		require.NotNil(t, blockCert, "expected certificate PEM block to be non-nil")
		assert.Empty(t, rest, "expected no remaining data after decoding certificate PEM block")

		parsedCert, err := x509.ParseCertificate(blockCert.Bytes)

		blockPkey, rest := pem.Decode([]byte(pkey))
		assert.Empty(t, rest, "expected no remaining data after decoding private key PEM block")
		require.NotNil(t, blockPkey, "expected private key PEM block to be non-nil")
		parsedPKEY, err := x509.ParsePKCS8PrivateKey(blockPkey.Bytes)
		require.NoError(t, err, "expected no error when parsing private key")
		key := parsedPKEY.(*ecdsa.PrivateKey)
		signer := aws_credential_helper.NewSigner(parsedCert, key)
		require.NotNil(t, signer)
		signerOut, err := signer.Sign(rand.Reader, []byte("test"), crypto.SHA256)
		require.NoError(t, err, "expected no error when signing a test string with the signer")
		assert.NotEmpty(t, signerOut)

		// Credential Provider
		credentialProviderInput := aws_credential_helper.CredentialProviderInput{
			Region:          "us-east-1",
			TrustProfileArn: trustProfileArn,
			TrustAnchorArn:  trustAnchorArn,
			AssumeRoleArn:   assumeRoleArn,

			Signer: signer,
		}
		credentialProvider, err := aws_credential_helper.NewCredentialProvider(context.Background(), credentialProviderInput)
		require.NoError(t, err, "expected no error when creating a credential provider")
		assert.NotNil(t, credentialProvider, "expected credential provider to be created")

		// credentialprovider definition
		cfg, err := config.LoadDefaultConfig(
			context.Background(),
			config.WithRegion("us-east-1"),
			config.WithCredentialsProvider(credentialProvider),
		)
		require.NoError(t, err, "expected no error when creating a config with the credential provider specified.")
		assert.NotNil(t, cfg)

		t.Run("Credential Test", func(t *testing.T) {
			start := time.Now()
			creds, err := cfg.Credentials.Retrieve(context.Background())
			require.NoError(t, err, "expected no error when retrieving credentials from the config")
			assert.NotEmpty(t, creds.AccessKeyID, "expected non-empty AccessKeyID from the credentials")

			// assert the expiration is around 60 minutes
			assert.Greater(t, creds.Expires.Sub(start), time.Hour-10*time.Minute, "expected credentials to expire in more than 50 minutes")
		})

		t.Run("S3 List Buckets", func(t *testing.T) {
			// S3
			svc := s3.NewFromConfig(cfg)
			assert.NotNil(t, svc, "expected S3 service client to be created")

			input := s3.ListBucketsInput{}
			out, err := svc.ListBuckets(context.Background(), &input)
			require.NoError(t, err, "required no error when listing buckets")
			var bucketsFound []string
			for _, o := range out.Buckets {
				bucketsFound = append(bucketsFound, *o.Name)
			}
			assert.Contains(t, bucketsFound, "dapr-ra-test-do-not-delete",
				"expected bucket 'aws-sdk-test' to be in the list of buckets")

		})
	})
}
