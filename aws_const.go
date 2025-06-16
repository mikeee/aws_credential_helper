package aws_credential_helper

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
const (
	aws4_x509_rsa_sha256   = "AWS4-X509-RSA-SHA256"   // https://github.com/aws/rolesanywhere-credential-helper/blob/6942d888fa4edffd85591fbe155db67f006bf31b/aws_signing_helper/signer.go#L118
	aws4_x509_ecdsa_sha256 = "AWS4-X509-ECDSA-SHA256" // https://github.com/aws/rolesanywhere-credential-helper/blob/6942d888fa4edffd85591fbe155db67f006bf31b/aws_signing_helper/signer.go#L119
	x_amz_date             = "X-Amz-Date"             // https://github.com/aws/rolesanywhere-credential-helper/blob/6942d888fa4edffd85591fbe155db67f006bf31b/aws_signing_helper/signer.go#L122
	x_amz_x509             = "X-Amz-X509"             // https://github.com/aws/rolesanywhere-credential-helper/blob/6942d888fa4edffd85591fbe155db67f006bf31b/aws_signing_helper/signer.go#L123
	x_amz_x509_chain       = "X-Amz-X509-Chain"       // https://github.com/aws/rolesanywhere-credential-helper/blob/6942d888fa4edffd85591fbe155db67f006bf31b/aws_signing_helper/signer.go#L124
	x_amz_content_sha256   = "X-Amz-Content-Sha256"   // https://github.com/aws/rolesanywhere-credential-helper/blob/6942d888fa4edffd85591fbe155db67f006bf31b/aws_signing_helper/signer.go#L125
)
