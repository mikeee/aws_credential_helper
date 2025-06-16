package aws_credential_helper

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mikeee/aws_credential_helper/internal"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func createSessionRequestURL(region string) (*url.URL, error) {
	if region == "" {
		return nil, fmt.Errorf("region cannot be empty")
	}

	return &url.URL{
		Scheme: "https",
		Host:   "rolesanywhere." + region + ".amazonaws.com",
		Path:   "/sessions",
	}, nil
}

func createCanonicalRequest(input *CreateSessionRequest, signer Signer) (*retryablehttp.Request, error) {
	// Validate the input
	switch {
	case input == nil:
		return nil, fmt.Errorf("input cannot be nil")
	case input.region == "":
		return nil, fmt.Errorf("region cannot be empty")
	}
	// TODO: Add assertions for other fields

	requestPayloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request payload: %w", err)
	}

	// Create a URL object to use for the request
	createSessionUrl, err := createSessionRequestURL(input.region)
	if err != nil {
		return nil, fmt.Errorf("failed to create session request URL: %w", err)
	}

	// Task 1

	// Step 1 - HttpRequestMethod as a verb that is an uppercase string e.g. POST
	method := http.MethodPost // TODO: Assert that this is an uppercase method

	// Step 2 - CanonicalUri creation which is the path before the query string delimiter
	canonicalUri := createSessionUrl.Path

	// Step 3 - CanonicalQueryString which is the query string part of the URL
	// Since the request does not have any query strings, use an empty string to create a blank line.
	canonicalQueryString := ""

	// Step 4 - CanonicalHeaders
	headers := []string{
		"content-type",
		"host",
		"x-amz-date",
		"x-amz-x509",
	}

	// Step 5 - SignedHeaders which is a list of headers that are included in the signature
	signedHeaders := strings.Join(headers, ";")

	// Step 6 - Hash of the request payload
	requestPayloadBytesHash := sha256.Sum256(requestPayloadBytes)

	// Step 7 - Construct the finished canonical request - combining everything as a string.
	// + Step 8 - Create a hash of the canonical request (UTF-8 encoded) using SHA256,
	// TODO: Propagate context
	request, err := retryablehttp.NewRequest(method, createSessionUrl.String(), bytes.NewReader(requestPayloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	// Set the headers
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Host", createSessionUrl.Host)
	amzTime := internal.AwsTimeFromTime(time.Now().UTC())
	if input.mockTime != nil {
		amzTime = *input.mockTime
	}
	request.Header.Set("X-Amz-Date", amzTime)
	request.Header.Set("X-Amz-X509", base64.StdEncoding.EncodeToString(signer.cert.Raw))

	/*

	   POST
	   /sessions

	   content-type:application/json
	   host:rolesanywhere.us-east-1.amazonaws.com
	   x-amz-date:20211103T120000Z
	   x-amz-x509:{base64-encoded DER data}

	   content-type;host;x-amz-date;x-amz-x509
	   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

	*/
	canonicalRequest := fmt.Sprintf(`%s
%s
%s
content-type:%s
host:%s
x-amz-date:%s
x-amz-x509:%s

%s
%x`,
		request.Method,
		canonicalUri,
		canonicalQueryString,
		request.Header.Get("Content-Type"),
		request.Header.Get("Host"),
		request.Header.Get("X-Amz-Date"),
		request.Header.Get("X-Amz-X509"),
		signedHeaders,
		requestPayloadBytesHash[:], // hex encoded in the final string (lowercase)
	)

	alg := aws4_x509_ecdsa_sha256 // TODO: Replace with actual algorithm from signer
	// TODO: Refactor this
	credentialScope := fmt.Sprintf("%s/%s/rolesanywhere/aws4_request", amzTime[:8], input.region)

	stringToSign, err := CreateStringToSign(alg, amzTime, credentialScope, canonicalRequest)
	if err != nil {
		return nil, err
	}

	// Calculate the signature using the string to sign and the signer
	signature, err := CalculateSignature(stringToSign, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate signature: %w", err)
	}

	authHeader := BuildAuthorizationHeader(alg, signer.cert.SerialNumber.String(), credentialScope, signedHeaders, signature)

	request.Header.Set("Authorization", authHeader)
	return request, nil
}

func CreateStringToSign(algorithm, requestDateTime, credentialSCope, canonicalRequest string) (string, error) {
	// Task 2

	// Assert Algorithm is in the format AWS4-X509-[ALGORITHM]-SHA256
	// We only use SHA256 for now, so the algorithm will be AWS4-X509-[ALGORITHM]-SHA256
	matchedAlg, err := regexp.Match("AWS4-X509-[\\w]+-SHA256", []byte(algorithm))
	if err != nil {
		return "", fmt.Errorf("error matching algorithm regex: %v", err)
	} else if !matchedAlg {
		return "", fmt.Errorf("algorithm does not match expected format: %s", algorithm)
	}

	// Assert RequestDateTime is in the format YYYYMMDD'T'HHMMSS'Z'
	// TODO: Improve this assertion
	matchedRDT, err := regexp.Match("[\\d]+T[\\d]+Z", []byte(requestDateTime))
	if err != nil {
		return "", fmt.Errorf("error matching RequestDateTime regex: %v", err)
	} else if !matchedRDT {
		return "", fmt.Errorf("RequestDateTime does not match expected format: %s", requestDateTime)
	}

	// Assert CredentialScope is in the format YYYYMMDD/[REGION]/rolesanywhere/aws4_request
	matchedCS, err := regexp.Match("[\\d]+\\/[^/]+\\/rolesanywhere\\/aws4_request", []byte(credentialSCope))
	if err != nil {
		return "", fmt.Errorf("error matching CredentialScope regex: %v", err)
	} else if !matchedCS {
		return "", fmt.Errorf("CredentialScope does not match expected format: %s", credentialSCope)
	}

	canonicalHash := sha256.Sum256([]byte(canonicalRequest))
	hashedCanonical := hex.EncodeToString(canonicalHash[:])
	return strings.Join([]string{
		algorithm,
		requestDateTime,
		credentialSCope,
		hashedCanonical,
	}, "\n"), nil
}

func CalculateSignature(stringToSign string, signer Signer) (string, error) {
	// Task 3

	// Generate a signature
	signatureHash := sha256.Sum256([]byte(stringToSign))

	// Assert the signer is a ecdsa key type
	if _, ok := signer.pkey.Public().(*ecdsa.PublicKey); !ok {
		return "", ErrInvalidKeyType
	}

	// Sign the string to sign using the provided signer
	signedSignature, err := signer.pkey.Sign(rand.Reader, signatureHash[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to sign string to sign: %w", err)
	}

	// Return the signature as a hex-encoded string
	return hex.EncodeToString(signedSignature), nil
}

func BuildAuthorizationHeader(algorithm, serialNumber, scope, signedHeaders, signature string) string {
	// Task 4

	return algorithm + " " +
		"Credential=" + serialNumber + "/" + scope + ", " +
		"SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature
}
