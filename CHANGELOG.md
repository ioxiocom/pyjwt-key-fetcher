# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[unreleased]: https://github.com/ioxiocom/pyjwt-key-fetcher/compare/0.2.0...HEAD
[0.2.0]: https://github.com/ioxiocom/pyjwt-key-fetcher/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/ioxiocom/pyjwt-key-fetcher/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/ioxiocom/pyjwt-key-fetcher/releases/tag/0.1.0
