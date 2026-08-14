# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-14

### Fixed

- Bound aggregate nesting depth in RESP2 and RESP3 parsers ([#48](https://github.com/joshrotenberg/resp-rs/pull/48))
- Bound collection pre-allocation by available input and nesting depth ([#52](https://github.com/joshrotenberg/resp-rs/pull/52))
- Accept explicit plus sign on integers and classify trailing junk correctly ([#56](https://github.com/joshrotenberg/resp-rs/pull/56))
- RESP3 attributes must not consume an aggregate element slot ([#66](https://github.com/joshrotenberg/resp-rs/pull/66))
- *(resp3)* Scalar conformance for null, terminator, big number, and streamed strings ([#67](https://github.com/joshrotenberg/resp-rs/pull/67))
- *(unsafe-internals)* Find_cr must agree with find_crlf on a bare CR ([#68](https://github.com/joshrotenberg/resp-rs/pull/68))
- *(test)* Update artifacts left stale by the attribute and terminator fixes ([#70](https://github.com/joshrotenberg/resp-rs/pull/70))
- Cap CRLF-terminated line length ([#69](https://github.com/joshrotenberg/resp-rs/pull/69))
- Apply the line ceiling to terminated lines too ([#71](https://github.com/joshrotenberg/resp-rs/pull/71))
- Add checked serialization and wire it into the codec encode path ([#72](https://github.com/joshrotenberg/resp-rs/pull/72))
- Anchor the build.rs gitignore pattern ([#75](https://github.com/joshrotenberg/resp-rs/pull/75))

### Performance

- Drain the parser buffer without copying the tail ([#73](https://github.com/joshrotenberg/resp-rs/pull/73))
- Decode without cloning the read buffer on every call ([#74](https://github.com/joshrotenberg/resp-rs/pull/74))



## [0.1.8] - 2026-03-27



## [0.1.7] - 2026-03-27

### Miscellaneous

- Update README and CI for new features ([#42](https://github.com/joshrotenberg/resp-rs/pull/42))



## [0.1.6] - 2026-03-27

### Added

- Add Frame convenience methods for type extraction ([#39](https://github.com/joshrotenberg/resp-rs/pull/39))
- Add no_std support ([#41](https://github.com/joshrotenberg/resp-rs/pull/41))



## [0.1.5] - 2026-03-27

### Added

- Add opt-in unsafe parser behind `unsafe-internals` feature ([#30](https://github.com/joshrotenberg/resp-rs/pull/30))



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


