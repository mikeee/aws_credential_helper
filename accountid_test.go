package aws_credential_helper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccountIDFromARN(t *testing.T) {
	tests := map[string]struct {
		arn  string
		want string
	}{
		"sts assumed-role ARN":        {"arn:aws:sts::123456789012:assumed-role/MyRole/session", "123456789012"},
		"iam role ARN":                {"arn:aws:iam::123456789012:role/MyRole", "123456789012"},
		"non-default partition":       {"arn:aws-us-gov:sts::210987654321:assumed-role/MyRole/s", "210987654321"},
		"resource segment has colons": {"arn:aws:sts::123456789012:assumed-role/MyRole/s:e:c", "123456789012"},
		"empty string":                {"", ""},
		"too few segments":            {"arn:aws:sts", ""},
		"not an ARN":                  {"garbage", ""},
		"non-ARN with enough fields":  {"garbage:1:2:3:4", ""},
		"account not 12 digits":       {"arn:aws:sts::123:assumed-role/MyRole/s", ""},
		"account non-numeric":         {"arn:aws:sts::12345678901x:role/MyRole", ""},
		"empty account segment":       {"arn:aws:sts:::assumed-role/MyRole/s", ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, accountIDFromARN(tc.arn))
		})
	}
}
