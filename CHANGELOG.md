# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Known Limitations

- Fallback export feature defined but not yet wired into pipeline
