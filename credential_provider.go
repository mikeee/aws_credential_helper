package aws_credential_helper

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/hashicorp/go-retryablehttp"
	"sync"
)

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
		AccountID: createSessionResponse.CredentialSet[0].AssumedRoleUser.Arn, // TODO: get the account id - not arn
		// credentialset.assumedRoleUser.arn ?? TODO: Confirm this
	}, nil
}
