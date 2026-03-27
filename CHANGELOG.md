# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-03-27

### Documentation

- Document intentional protocol permissiveness decisions ([#27](https://github.com/joshrotenberg/resp-rs/pull/27))

### Fixed

- Harden parsers and add edge-case tests ([#22](https://github.com/joshrotenberg/resp-rs/pull/22))

### Performance

- Extract heavy RESP3 match arms to reduce icache pressure ([#29](https://github.com/joshrotenberg/resp-rs/pull/29))



## [0.1.3] - 2026-03-27



## [0.1.2] - 2026-03-26

### Documentation

- Polish Cargo.toml metadata, rustdoc, and README ([#6](https://github.com/joshrotenberg/resp-rs/pull/6))



## [0.1.1] - 2026-03-26

### Added

- Add examples (parse demo and breadis server) ([#5](https://github.com/joshrotenberg/resp-rs/pull/5))

### Miscellaneous

- Set up release-plz with git-cliff ([#2](https://github.com/joshrotenberg/resp-rs/pull/2))

### Testing

- Add proptest property tests for RESP2 and RESP3 ([#4](https://github.com/joshrotenberg/resp-rs/pull/4))


