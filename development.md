# Tests

The E2E tests use valid certificates and keys, stored as secrets accessible to the actions runners.
In GitHub Actions, E2E tests run daily at 06:00 UTC on the default branch and can also be run manually from the `E2E Tests` workflow with a pull request number.
Manual runs check out the PR merge ref and expose E2E secrets, so only dispatch them for reviewed PRs.
E2E tests can be run locally with the following ENV Vars set:

```
E2E_CERT=
E2E_KEY=

E2E_TRUST_PROFILE_ARN=
E2E_TRUST_ANCHOR_ARN=
E2E_ASSUME_ROLE_ARN=
```

The account must also contain a s3 bucket named `dapr-ra-test-do-not-delete` as part of the assertions.