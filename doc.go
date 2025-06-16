// Package aws_credential_helper provides a helper for managing AWS credentials.
//
// It includes functionality for creating sessions, managing credential providers,
// and signing requests using AWS's Roles Anywhere service.
//
// This package is CGO-less :)
//
// This package heavily relies on the steps outlined in the AWS Roles Anywhere documentation.
// https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html

package aws_credential_helper
