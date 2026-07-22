# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/djvcom/opentelemetry-configuration/compare/v0.3.2...v0.4.0) - 2026-07-22

### Added

- [**breaking**] add configurable metric export temporality
- [**breaking**] update OpenTelemetry dependencies to 0.32

### Other

- *(deps)* bump dependabot/fetch-metadata in the actions group
- *(deps)* bump tokio in the rust-minor-patch group ([#24](https://github.com/djvcom/opentelemetry-configuration/pull/24))
- *(deps)* bump mock-collector in the rust-minor-patch group ([#23](https://github.com/djvcom/opentelemetry-configuration/pull/23))
- *(deps)* bump tokio in the rust-minor-patch group ([#22](https://github.com/djvcom/opentelemetry-configuration/pull/22))
- *(deps)* bump tokio in the rust-minor-patch group ([#20](https://github.com/djvcom/opentelemetry-configuration/pull/20))
- *(deps)* bump mock-collector in the rust-minor-patch group ([#19](https://github.com/djvcom/opentelemetry-configuration/pull/19))
- *(deps)* bump tokio in the rust-minor-patch group ([#18](https://github.com/djvcom/opentelemetry-configuration/pull/18))
- *(deps)* bump opentelemetry-otlp ([#17](https://github.com/djvcom/opentelemetry-configuration/pull/17))
- *(deps)* bump tracing-subscriber in the rust-minor-patch group ([#16](https://github.com/djvcom/opentelemetry-configuration/pull/16))
- *(deps)* bump tempfile in the rust-minor-patch group ([#15](https://github.com/djvcom/opentelemetry-configuration/pull/15))
- *(deps)* bump tokio in the rust-minor-patch group ([#14](https://github.com/djvcom/opentelemetry-configuration/pull/14))
- *(deps)* bump tempfile in the rust-minor-patch group ([#13](https://github.com/djvcom/opentelemetry-configuration/pull/13))
- *(deps)* bump serial_test in the rust-minor-patch group ([#12](https://github.com/djvcom/opentelemetry-configuration/pull/12))
- *(deps)* bump tonic in the rust-minor-patch group ([#11](https://github.com/djvcom/opentelemetry-configuration/pull/11))
- *(deps)* bump mock-collector in the rust-minor-patch group ([#10](https://github.com/djvcom/opentelemetry-configuration/pull/10))
- *(deps)* bump tonic in the rust-minor-patch group ([#9](https://github.com/djvcom/opentelemetry-configuration/pull/9))
- *(deps)* bump tempfile in the rust-minor-patch group ([#8](https://github.com/djvcom/opentelemetry-configuration/pull/8))

## [0.3.2](https://github.com/djvcom/opentelemetry-configuration/compare/v0.3.1...v0.3.2) - 2026-01-06

### Other

- *(ci)* remove macOS test job

## [0.3.1](https://github.com/djvcom/opentelemetry-configuration/compare/v0.3.0...v0.3.1) - 2026-01-06

### Added

- re-export tracing_opentelemetry for context propagation

## [0.3.0](https://github.com/djvcom/opentelemetry-configuration/compare/v0.2.0...v0.3.0) - 2026-01-06

### Added

- re-export core crates for version compatibility

### Other

- *(builder)* add coverage for with_env, header, and scope name
- improve test suite quality and fix clippy pedantic warnings
- remove dead code and improve code quality
- improve documentation and add guard tests
- *(guard)* extract tonic metadata helper and use tracing for errors
- update MSRV to 1.92

## [0.2.0](https://github.com/djvcom/opentelemetry-configuration/releases/tag/v0.2.0) - 2025-12-24

### Added

- Add compute environment detection and Rust resource detector

## [0.1.2](https://github.com/djvcom/opentelemetry-configuration/releases/tag/v0.1.2) - 2025-12-23

### Added

- Set W3C trace context and baggage propagators

## [0.1.1](https://github.com/djvcom/opentelemetry-configuration/releases/tag/v0.1.1) - 2025-12-07

### Added

- Complete high-priority improvements

### Other

- Remove inline comments
- Use let-chains for clippy

## [0.1.0](https://github.com/djvcom/opentelemetry-configuration/releases/tag/v0.1.0) - 2025-12-03

### Added

- Opinionated OpenTelemetry SDK setup with `OtelSdkBuilder`
- Layered configuration using figment
  - Sensible defaults (localhost:4318 for HTTP OTLP)
  - File-based configuration (TOML)
  - Environment variable overrides (`OTEL_*` prefix)
- Drop-based lifecycle management via `OtelGuard`
  - Automatic flush on drop
  - Graceful shutdown with configurable timeout
- Tracer, meter, and logger provider setup
- Integration with `tracing` via `tracing-opentelemetry`
- Log bridging from `log` and `tracing` to OpenTelemetry logs
- Support for HTTP and gRPC OTLP exporters

### Features

- `http` (default) - HTTP OTLP exporter
- `grpc` - gRPC OTLP exporter via tonic
