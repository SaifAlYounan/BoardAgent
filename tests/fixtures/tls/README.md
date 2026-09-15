# Synthetic TLS test fixtures

The certificates and private keys in this directory are synthetic test material. They
were generated for the automated test suite only, are self-signed for the fake host names
`cimd-fixture.test` and `BoardAgent-Client-Matrix-Test`, and have never protected any
real service. They are committed deliberately so that the tests are reproducible.

Do not use them anywhere else, and do not report them as leaked credentials.
