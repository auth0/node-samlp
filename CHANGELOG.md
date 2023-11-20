# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [7.1.1](https://github.com/auth0/node-samlp/compare/v7.1.0...v7.1.1) (2023-11-20)


### Bug Fixes

* support signed logout response sent via POST ([#140](https://github.com/auth0/node-samlp/issues/140)) ([5274d62](https://github.com/auth0/node-samlp/commit/5274d622b1f4cca04790dcf2acf83840c0b592c6))

## [7.1.0](https://github.com/auth0/node-samlp/compare/v7.0.2...v7.1.0) (2023-07-24)


### Features

* add support for per-participant bindings during SLO ([9f21610](https://github.com/auth0/node-samlp/commit/9f21610d18c685765d4cd5ac11deca39938d31ac))

### [7.0.2](https://github.com/auth0/node-samlp/compare/v7.0.1...v7.0.2) (2022-06-09)


### Bug Fixes

* Update saml and ejs dependencies ([#132](https://github.com/auth0/node-samlp/issues/132)) ([26b8cbd](https://github.com/auth0/node-samlp/commit/26b8cbd50bde051e68bcb32fce61421641276b72))

### [7.0.1](https://github.com/auth0/node-samlp/compare/v7.0.0...v7.0.1) (2022-05-19)


### Bug Fixes

* install updated saml to address issue with malformed pem ([#129](https://github.com/auth0/node-samlp/issues/129)) ([ce5cb5c](https://github.com/auth0/node-samlp/commit/ce5cb5ceaa627596ae114ab81a50464da982ffd4))

## [7.0.0](https://github.com/auth0/node-samlp/compare/v6.0.2...v7.0.0) (2022-02-09)


### ⚠ BREAKING CHANGES

* Requires NodeJS >= 12

See https://github.com/auth0/node-saml/releases/tag/v2.0.0

### Bug Fixes

* remove vulnerable node-saml dependency ([#126](https://github.com/auth0/node-samlp/issues/126)) ([bab5bd0](https://github.com/auth0/node-samlp/commit/bab5bd0468d1234d1fcea52fdb9ebafc3e6032e2))

### [6.0.2](https://github.com/auth0/node-samlp/compare/v6.0.1...v6.0.2) (2021-06-07)

### [6.0.1](https://github.com/auth0/node-samlp/compare/v6.0.0...v6.0.1) (2021-03-02)

- Use @auth0/xmldom ([#119](https://github.com/auth0/node-samlp/commit/e0524290ea7127f72429fd887cb66a8933f0f662))

## [6.0.0](https://github.com/auth0/node-samlp/compare/v5.0.1...v6.0.0) (2021-02-23)

### ⚠ BREAKING CHANGES

- The expected signature of `SessionParticipants.get` has been changed to `SessionParticipants.get(issuer, sessionIndices, nameId, cb)` where `sessionIndices` is an array of `SessionIndex` values from the `LogoutRequest`. Previously, this was called with only a single value: the value of first `SessionIndex` element from the `LogoutRequest`. The effect is that any matching `SessionIndex` specified in a `LogoutRequest` may be used to identify a matching `SessionParticipant` when processing the logout request. ([ef9a056](https://github.com/auth0/node-samlp/commit/ef9a056517456eb7a1b90d46ed9182088bb6f1d8)).

### [5.0.1](https://github.com/auth0/node-samlp/compare/v5.0.0...v5.0.1) (2021-02-10)

### Bug Fixes

- build fix from merge ([24fa8be](https://github.com/auth0/node-samlp/commit/24fa8bee116379d95053fd4d74ad24dfdfc4ad42))

## [5.0.0-rc.1](https://github.com/auth0/node-samlp/compare/v4.0.1...v5.0.0-rc.1) (2021-01-22)

## [5.0.0-rc.0](https://github.com/auth0/node-samlp/compare/v4.0.0...v5.0.0-rc.0) (2021-01-22)

### ⚠ BREAKING CHANGES

- fix npm audit and library upgrades
- remove ci for node v4, 6, 8, add 14

- fix npm audit and library upgrades ([a2688c7](https://github.com/auth0/node-samlp/commit/a2688c702792fba90db4e7c72c463b223498c127))
- remove ci for node v4, 6, 8, add 14 ([3019b74](https://github.com/auth0/node-samlp/commit/3019b747a0b46f571d4b6a1b3227dec56e7a71d8))

## [5.0.0](https://github.com/auth0/node-samlp/compare/v4.0.1...v5.0.0) (2021-02-09)

### ⚠ BREAKING CHANGES

- Fix dependency security issues (#114)

- Fix dependency security issues ([#114](https://github.com/auth0/node-samlp/issues/114)) ([26bb934](https://github.com/auth0/node-samlp/commit/26bb9343b1e4893135f467709074a027ea69015a))
