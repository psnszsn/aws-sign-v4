# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added 

- Support for sigv4 `service` attributes beyond "s3" (e.g. "execute-api") in `AwsSign` struct
- Support for "body" attribute beyond "s3" in `AwsSign` struct
- More documentation

### Changed

- Upgrage Rust Edition to 2021
- Upgrade dependencies
- License from MIT to BSD 2-Clause (like MIT, but "don't blame me if things go wrong")

## [0.1.1] - 2019-12-30

- First working version with a README: https://crates.io/crates/aws-sign-v4/0.1.1