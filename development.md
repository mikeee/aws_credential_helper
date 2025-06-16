# Tests

The E2E tests use valid certificates and keys, stored as secrets accessible to the actions runners.
E2E tests can be run locally with the following ENV Vars set:

```
E2E_CERT=
E2E_KEY=

E2E_TRUST_PROFILE_ARN=
E2E_TRUST_ANCHOR_ARN=
E2E_ASSUME_ROLE_ARN=
```

The account must also contain a s3 bucket named `dapr-ra-test-do-not-delete` as part of the assertions.