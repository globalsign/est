# Changelog

## [Unreleased]
### Changed
- Report the version the Go toolchain records from the module's git tag, instead
  of a hardcoded string, in the `estclient` and `estserver` version output, the
  client's `User-Agent` header and the server's `Server` header.

## [1.0.7] - 2025-11-19
### Added
- Challenge password in the CSR as described in RFC 7030 section 3.5.
- Signing key for signing the CSR when a challenge password is included, with
  support in the `estclient` CLI.
- `estclient cacerts`: flexible output filtering and writing every CA
  certificate to a separate file.
### Changed
- Stop requiring the Content-Transfer-Encoding header, per RFC 8951.
- Make all HTTP requests from the same HTTP client.
- Update go-tpm from v0.3 to v0.9.
- Update golang.org/x/crypto to v0.35.0.
### Fixed
- Return an error instead of panicking when parsing a malformed certificate.
### Removed
- The sample from the repository.

## [1.0.6] - 2021-02-21
### Added
- Windows build capability.

## [1.0.5] - 2021-02-19
### Changed
- Update go-tpm package version.

## [1.0.4] - 2020-09-08
### Changed
- Update client error processing.

## [1.0.3] - 2020-08-10
### Changed
- Break all HTTP messages with a base64 Content-Transfer-Encoding into lines.

## [1.0.2] - 2020-06-03
### Changed
- Minor bug fixes and quality enhancements.

## [1.0.1] - 2020-06-02
### Added
- Travis CI integration

## [1.0.0] - 2020-05-28
### Added
- Initial release

[Unreleased]: https://github.com/globalsign/est/compare/v1.0.7...HEAD
[1.0.7]: https://github.com/globalsign/est/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/globalsign/est/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/globalsign/est/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/globalsign/est/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/globalsign/est/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/globalsign/est/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/globalsign/est/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/globalsign/est/releases/tag/v1.0.0
