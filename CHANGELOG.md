# v1.0.7

- Add the challenge password to the CSR as described in RFC 7030 section 3.5.
- Add a signing key for signing the CSR when a challenge password is included, and support it in the estclient CLI.
- Return an error instead of panicking when parsing a malformed certificate.
- Stop requiring the Content-Transfer-Encoding header, per RFC 8951.
- Make all HTTP requests from the same HTTP client.
- estclient cacerts: support flexible output filtering and writing every CA certificate to a separate file.
- Update go-tpm from v0.3 to v0.9.
- Update golang.org/x/crypto to v0.35.0.
- Remove the sample from the repository.

# v1.0.6

- Windows build capability.

# v1.0.5

- Update go-tpm package version.

# v1.0.4

- Update client error processing.

# v1.0.3

- Break all HTTP messages with a base64 Content-Transfer-Encoding into lines.

# v1.0.2

- Minor bug fixes and quality enhancements.

# v1.0.1

- Travis CI integration

# v1.0.0

- Initial release
