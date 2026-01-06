//! Opinionated OpenTelemetry SDK configuration and lifecycle management.
//!
//! Wires together the OpenTelemetry SDK, OTLP exporters, and `tracing` into a
//! cohesive configuration system with automatic lifecycle management.
//!
//! # Example
//!
//! ```no_run
//! use opentelemetry_configuration::{OtelSdkBuilder, SdkError};
//!
//! fn main() -> Result<(), SdkError> {
//!     let _guard = OtelSdkBuilder::new()
//!         .service_name("my-service")
//!         .build()?;
//!
//!     tracing::info!("Application running");
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod builder;
mod config;
mod error;
mod guard;
mod rust_detector;

pub use builder::{OtelSdkBuilder, ResourceConfigBuilder};
pub use config::{
    BatchConfig, ComputeEnvironment, EndpointConfig, OtelSdkConfig, Protocol, ResourceConfig,
    SignalConfig,
};
pub use error::SdkError;
pub use guard::OtelGuard;
pub use rust_detector::{RustBuildInfo, RustResourceDetector, emit_rustc_env};

/// Re-exported for version compatibility with this crate's dependencies.
pub use opentelemetry;
/// Re-exported for version compatibility with this crate's dependencies.
pub use opentelemetry_sdk;
/// Re-exported for version compatibility with this crate's dependencies.
pub use tracing;

/// Re-exported for users who want to construct custom configuration providers.
pub use figment;

/// Captures Rust build-time information as resource attributes.
///
/// This macro reads environment variables set by [`emit_rustc_env`] in build.rs.
/// Use it with [`OtelSdkBuilder::with_rust_build_info`] to add rustc version
/// and channel information to your telemetry resource attributes.
///
/// # Example
///
/// ```ignore
/// // In build.rs:
/// fn main() {
///     opentelemetry_configuration::emit_rustc_env();
/// }
///
/// // In main.rs:
/// use opentelemetry_configuration::{OtelSdkBuilder, capture_rust_build_info};
///
/// let _guard = OtelSdkBuilder::new()
///     .service_name("my-service")
///     .with_rust_build_info(capture_rust_build_info!())
///     .build()?;
/// ```
///
/// # Attributes Added
///
/// When combined with [`emit_rustc_env`] in build.rs, this adds:
/// - `process.runtime.version` - rustc version (e.g., "1.84.0")
/// - `process.runtime.description` - full version string
/// - `rust.channel` - release channel ("stable", "beta", or "nightly")
#[macro_export]
macro_rules! capture_rust_build_info {
    () => {
        $crate::RustBuildInfo {
            rustc_version: option_env!("RUSTC_VERSION"),
            rust_channel: option_env!("RUST_CHANNEL"),
            rustc_version_full: option_env!("RUSTC_VERSION_FULL"),
        }
    };
}
