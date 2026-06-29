package aws_credential_helper

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/hashicorp/go-retryablehttp"
)

// accountIDFromARN extracts the account ID from an ARN of the form
// arn:partition:service:region:account-id:resource (field index 4). It returns
// "" unless the input is a well-formed ARN whose account-id field is a 12-digit
// AWS account number; returning "" makes the AWS SDK fall back to the standard
// regional endpoint rather than account-based endpoint routing (better than
// populating aws.Credentials.AccountID with an invalid value).
func accountIDFromARN(arn string) string {
	const accountIDField = 4
	if !strings.HasPrefix(arn, "arn:") {
		return ""
	}
	parts := strings.Split(arn, ":")
	if len(parts) <= accountIDField {
		return ""
	}
	accountID := parts[accountIDField]
	if len(accountID) != 12 {
		return ""
	}
	for _, r := range accountID {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return accountID
}

type CredentialProvider struct {
	httpClient *retryablehttp.Client

	mutex sync.RWMutex

	signer Signer

	region          string
	trustProfileArn string
	trustAnchorArn  string
	assumeRoleArn   string
	sessionName     string // unused
}
type CredentialProviderInput struct {
	Region string

	TrustProfileArn string
	TrustAnchorArn  string
	AssumeRoleArn   string

	Signer Signer
}

func checkCredentialProviderInput(credentialProviderInput CredentialProviderInput) error {
	switch {
	case credentialProviderInput.AssumeRoleArn == "":
		return errors.New("AssumeRoleArn is required")
	case credentialProviderInput.TrustAnchorArn == "":
		return errors.New("TrustAnchorArn is required")
	case credentialProviderInput.TrustProfileArn == "":
		return errors.New("TrustProfileArn is required")
	}
	return nil
}

func NewCredentialProvider(ctx context.Context, authInput CredentialProviderInput) (*CredentialProvider, error) {
	if err := checkCredentialProviderInput(authInput); err != nil {
		return nil, err
	}

	// Init a new client
	httpClient := retryablehttp.NewClient()
	httpClient.Logger = nil // Disable Logging for now
	httpClient.RetryMax = 50

	return &CredentialProvider{
		httpClient: httpClient,

		region:          authInput.Region,
		trustProfileArn: authInput.TrustProfileArn,
		trustAnchorArn:  authInput.TrustAnchorArn,
		assumeRoleArn:   authInput.AssumeRoleArn,

		signer: authInput.Signer,
	}, nil
}

func (c *CredentialProvider) ChangeSigner(signer Signer) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// TODO: implement assertions here
	c.signer = signer
	return nil
}

func (c *CredentialProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	createSessionRequest := &CreateSessionRequest{
		DurationSeconds: 0,
		ProfileArn:      c.trustProfileArn,
		RoleArn:         c.assumeRoleArn,
		TrustAnchorArn:  c.trustAnchorArn,
		RoleSessionName: c.sessionName,
		region:          c.region,
		mockTime:        nil,
	}

	createSessionResponse, err := CreateSession(ctx, c.httpClient, c.region, createSessionRequest, c.signer)
	if err != nil {
		return aws.Credentials{}, err
	}

	return aws.Credentials{
		AccessKeyID: createSessionResponse.CredentialSet[0].Credentials.AccessKeyId,
		// credentialset.credentials.accessKeyId
		SecretAccessKey: createSessionResponse.CredentialSet[0].Credentials.SecretAccessKey,
		// credentialset.credentials.secretAccessKey
		SessionToken: createSessionResponse.CredentialSet[0].Credentials.SessionToken,
		// credentialset.credentials.sessionToken
		Source:    createSessionResponse.CredentialSet[0].SourceIdentity, // credentialset.sourceIdentity
		CanExpire: true,                                                  // always wil expire
		Expires:   createSessionResponse.CredentialSet[0].Credentials.Expiration,
		// Should be in the form of a timestamp / credentialset.
		// credentials.
		// expiration
		// Account ID parsed from the assumed-role ARN
		// (credentialSet.assumedRoleUser.arn) so the SDK's account-based
		// endpoint routing (e.g. DynamoDB) works.
		AccountID: accountIDFromARN(createSessionResponse.CredentialSet[0].AssumedRoleUser.Arn),
	}, nil
}
