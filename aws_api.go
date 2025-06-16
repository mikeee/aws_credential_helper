package aws_credential_helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"io"
	"net/http"
	"time"
)

var ErrInvalidKeyType = errors.New("invalid key type, expected an ECDSA public key")

type CreateSessionRequest struct {
	DurationSeconds int    `json:"durationSeconds,omitempty"`
	ProfileArn      string `json:"profileArn"`
	RoleArn         string `json:"roleArn"`
	TrustAnchorArn  string `json:"trustAnchorArn"`
	RoleSessionName string `json:"roleSessionName,omitempty"`

	// Unexported fields
	region string

	mockTime *string // Used for testing purposes only
}

// TODO: Marshal ARNs?
type CreateSessionResponse struct {
	CredentialSet []CredentialSetItem `json:"credentialSet"`
	SubjectArn    string              `json:"subjectArn"`
}

type CredentialSetItem struct {
	AssumedRoleUser  AssumedRoleUser `json:"assumedRoleUser"`
	Credentials      CredentialsItem `json:"credentials"`
	PackedPolicySize int             `json:"packedPolicySize"`
	RoleArn          string          `json:"roleArn"`
	SourceIdentity   string          `json:"sourceIdentity"`
}

type CredentialsItem struct {
	AccessKeyId     string    `json:"accessKeyId"`
	Expiration      time.Time `json:"expiration"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
}

type AssumedRoleUser struct {
	Arn           string `json:"arn"`
	AssumedRoleId string `json:"assumedRoleId"`
}

func CreateSession(
	ctx context.Context,
	client *retryablehttp.Client,
	region string,
	request *CreateSessionRequest,
	signer Signer,
) (*CreateSessionResponse, error) {
	if client == nil {
		return nil, fmt.Errorf("retryablehttp client cannot be nil")
	}

	if region == "" {
		return nil, fmt.Errorf("region cannot be empty")
	}

	if signer.pkey == nil {
		return nil, fmt.Errorf("signer pkey cannot be nil or uninitialized")
	}

	if signer.cert == nil {
		return nil, fmt.Errorf("signer certificate cannot be nil or uninitialized")
	}

	// TODO: Refactor this
	req, err := createCanonicalRequest(request, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create canonical request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	var createSessionResponse CreateSessionResponse
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("unexpected status code: %d and failed to read response body: %w",
				resp.StatusCode, err)
		}

		return nil, fmt.Errorf("unexpected status code: %d body %s", resp.StatusCode, respBody)
	}

	// Parse response and return CreateSessionResponse
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if err := json.Unmarshal(respBytes, &createSessionResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(createSessionResponse.CredentialSet) != 1 {
		return nil, fmt.Errorf("expected exactly one credential set, got %d", len(createSessionResponse.CredentialSet))
	}

	return &createSessionResponse, nil
}
