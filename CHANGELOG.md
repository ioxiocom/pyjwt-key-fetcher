# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2023-06-26

### Fixed

- In rare conditions the cache used by a `Provider` could return old data from another
  no longer existing `Provider`. This was seen in some unit tests that created a lot of
  `AsyncKeyFetcher` instances which created a lot of `Provider` instances. The main
  reason to the problem was that the `aiocache` library would create the cache key using
  a string like `<pyjwt_key_fetcher.provider.Provider object at 0x120e9a070>` that then
  got reused by a new instance occupying the same memory address later. This is now
  fixed by ensuring each provider instance gets a UUID and it's used in the cache key.
  An [issue was opened in aiocache](https://github.com/aio-libs/aiocache/issues/734)
  regarding this. This issue would likely not have affected any real world use cases.

### Changed

- Updated `PyJWT`, `cachetools` and `aiocache`.

## [0.4.0] - 2023-02-21

### Changed

- Refactored internals of the `MockHTTPClient` so it can be used with custom paths for
  the config and jwks more easily. The `OPENID_CONFIG_PATH` and `JWKS_URL` were removed
  and replaced with instance variables `config_path` and `jwks_path`.
- The `create_token` in `MockProvider` can now be give extra headers to include in the
  token.
- Updated cryptography and aiohttp.

## [0.3.0] - 2023-02-07

### Changed

- BREAKING CHANGES: Removed all explicit references to OpenID Connect in names of
  methods, classes and exceptions. The most important changes:
  - `get_openid_configuration` -> `get_configuration`
  - `JWTOpenIDConnectError` -> `JWTProviderConfigError` and `JWTProviderJWKSError`
  - `OpenIDProvider` -> `Provider`
- Updated all dependencies and pre-commit hooks to the latest versions.

### Added

- Functionality to override the path from which the (OpenID or other) configuration is
  loaded.

## [0.2.0] - 2022-08-05

### Changed

- Update dependencies. Especially noteworthy:
  - pyjwt to 2.4.0 which fixes CVE-2022-29217.
  - pycares to 4.2.1; version 4.2.0 fixed CVE-2021-3672.
- Switch from Travis CI to GitHub actions.
- Update pre-commit hooks.
- Update configurations for prettier.
- Update links to GitHub repo due to organization rename.

## [0.1.1] - 2021-06-21

### Fixed

- Allow `alg` to not be specified for a key. PR #2 by @danmichaelo.

## [0.1.0] - 2021-05-24

### Added

- Everything for the initial release

[unreleased]: https://github.com/ioxiocom/pyjwt-key-fetcher/compare/0.5.0...HEAD
[0.5.0]: https://github.com/ioxiocom/pyjwt-key-fetcher/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/ioxiocom/pyjwt-key-fetcher/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/ioxiocom/pyjwt-key-fetcher/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/ioxiocom/pyjwt-key-fetcher/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/ioxiocom/pyjwt-key-fetcher/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/ioxiocom/pyjwt-key-fetcher/releases/tag/0.1.0
