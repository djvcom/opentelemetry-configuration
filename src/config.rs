//! Configuration types for the OpenTelemetry SDK.
//!
//! These types are designed to be deserialised from multiple sources using
//! figment, supporting layered configuration from defaults, files, and
//! environment variables.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Compute environment for resource attribute detection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComputeEnvironment {
    /// Automatically detect the compute environment.
    /// Runs generic detectors (host, OS, process) and probes for Lambda/K8s.
    #[default]
    Auto,
    /// AWS Lambda - generic detectors + Lambda-specific attributes (faas.*)
    Lambda,
    /// Kubernetes - generic detectors + K8s-specific attributes
    Kubernetes,
    /// No automatic detection - only use explicitly configured attributes.
    None,
}

/// OTLP export protocol.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// gRPC protocol (default port 4317).
    Grpc,
    /// HTTP with Protocol Buffers encoding (default port 4318).
    #[default]
    #[serde(alias = "http_binary", alias = "http-binary")]
    HttpBinary,
    /// HTTP with JSON encoding (default port 4318).
    #[serde(alias = "http_json", alias = "http-json")]
    HttpJson,
}

impl Protocol {
    /// Returns the default endpoint for this protocol.
    #[must_use]
    pub fn default_endpoint(&self) -> &'static str {
        match self {
            Protocol::Grpc => "http://localhost:4317",
            Protocol::HttpBinary | Protocol::HttpJson => "http://localhost:4318",
        }
    }

    /// Returns the default port for this protocol.
    #[must_use]
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Grpc => 4317,
            Protocol::HttpBinary | Protocol::HttpJson => 4318,
        }
    }
}

/// Complete OpenTelemetry SDK configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OtelSdkConfig {
    /// Endpoint configuration.
    pub endpoint: EndpointConfig,

    /// Resource configuration.
    pub resource: ResourceConfig,

    /// Traces configuration.
    pub traces: SignalConfig,

    /// Metrics configuration.
    pub metrics: SignalConfig,

    /// Logs configuration.
    pub logs: SignalConfig,

    /// Whether to initialise the tracing subscriber.
    pub init_tracing_subscriber: bool,

    /// Name for the instrumentation scope (otel.library.name).
    /// Defaults to `service_name` if set, otherwise "opentelemetry-configuration".
    pub instrumentation_scope_name: Option<String>,
}

impl Default for OtelSdkConfig {
    fn default() -> Self {
        Self {
            endpoint: EndpointConfig::default(),
            resource: ResourceConfig::default(),
            traces: SignalConfig::default_enabled(),
            metrics: SignalConfig::default_enabled(),
            logs: SignalConfig::default_enabled(),
            init_tracing_subscriber: true,
            instrumentation_scope_name: None,
        }
    }
}

impl OtelSdkConfig {
    /// Returns the effective endpoint URL, using protocol defaults if not specified.
    #[must_use]
    pub fn effective_endpoint(&self) -> String {
        self.endpoint
            .url
            .clone()
            .unwrap_or_else(|| self.endpoint.protocol.default_endpoint().to_string())
    }

    /// Returns the endpoint URL for a specific signal type.
    #[must_use]
    pub fn signal_endpoint(&self, signal_path: &str) -> String {
        let base = self.effective_endpoint();
        let base = base.trim_end_matches('/');

        match self.endpoint.protocol {
            Protocol::Grpc => base.to_string(),
            Protocol::HttpBinary | Protocol::HttpJson => {
                format!("{base}{signal_path}")
            }
        }
    }
}

/// Endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EndpointConfig {
    /// OTLP endpoint URL.
    ///
    /// If not specified, uses the protocol's default:
    /// - gRPC: `http://localhost:4317`
    /// - HTTP: `http://localhost:4318`
    pub url: Option<String>,

    /// Export protocol.
    pub protocol: Protocol,

    /// Request timeout.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,

    /// HTTP headers for authentication or customisation.
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            url: None,
            protocol: Protocol::default(),
            timeout: Duration::from_secs(10),
            headers: HashMap::new(),
        }
    }
}

/// Resource configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceConfig {
    /// Service name.
    pub service_name: Option<String>,

    /// Service version.
    pub service_version: Option<String>,

    /// Deployment environment (e.g., "production", "staging").
    pub deployment_environment: Option<String>,

    /// Additional resource attributes.
    #[serde(default)]
    pub attributes: HashMap<String, String>,

    /// Compute environment for automatic resource detection.
    #[serde(default)]
    pub compute_environment: ComputeEnvironment,
}

impl ResourceConfig {
    /// Creates a new resource config with a service name.
    pub fn with_service_name(name: impl Into<String>) -> Self {
        Self {
            service_name: Some(name.into()),
            ..Default::default()
        }
    }
}

/// Configuration for an individual signal type (traces, metrics, logs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SignalConfig {
    /// Whether this signal is enabled.
    pub enabled: bool,

    /// Batch export configuration.
    pub batch: BatchConfig,
}

impl SignalConfig {
    /// Creates a default config with the signal enabled.
    #[must_use]
    pub fn default_enabled() -> Self {
        Self {
            enabled: true,
            batch: BatchConfig::default(),
        }
    }
}

/// Batch exporter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BatchConfig {
    /// Maximum queue size.
    pub max_queue_size: usize,

    /// Maximum batch size for export.
    pub max_export_batch_size: usize,

    /// Scheduled delay between exports.
    #[serde(with = "humantime_serde")]
    pub scheduled_delay: Duration,

    /// Maximum time to wait for export to complete.
    #[serde(with = "humantime_serde")]
    pub export_timeout: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 2048,
            max_export_batch_size: 512,
            scheduled_delay: Duration::from_secs(5),
            export_timeout: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_default_endpoint() {
        assert_eq!(Protocol::Grpc.default_endpoint(), "http://localhost:4317");
        assert_eq!(
            Protocol::HttpBinary.default_endpoint(),
            "http://localhost:4318"
        );
        assert_eq!(
            Protocol::HttpJson.default_endpoint(),
            "http://localhost:4318"
        );
    }

    #[test]
    fn test_otel_sdk_config_effective_endpoint() {
        let config = OtelSdkConfig::default();
        assert_eq!(config.effective_endpoint(), "http://localhost:4318");

        let mut config = OtelSdkConfig::default();
        config.endpoint.protocol = Protocol::Grpc;
        assert_eq!(config.effective_endpoint(), "http://localhost:4317");

        let mut config = OtelSdkConfig::default();
        config.endpoint.url = Some("http://collector:4318".to_string());
        assert_eq!(config.effective_endpoint(), "http://collector:4318");
    }

    #[test]
    fn signal_endpoint_appends_path_for_http_protocols() {
        let config = OtelSdkConfig::default();
        assert_eq!(
            config.signal_endpoint("/v1/traces"),
            "http://localhost:4318/v1/traces"
        );
    }

    #[test]
    fn signal_endpoint_strips_trailing_slash_before_appending() {
        let mut config = OtelSdkConfig::default();
        config.endpoint.url = Some("http://collector:4318/".to_string());
        assert_eq!(
            config.signal_endpoint("/v1/traces"),
            "http://collector:4318/v1/traces"
        );
    }

    #[test]
    fn signal_endpoint_returns_base_only_for_grpc() {
        let mut config = OtelSdkConfig::default();
        config.endpoint.protocol = Protocol::Grpc;
        assert_eq!(
            config.signal_endpoint("/v1/traces"),
            "http://localhost:4317"
        );
    }

    #[test]
    fn test_resource_config_with_service_name() {
        let config = ResourceConfig::with_service_name("my-service");
        assert_eq!(config.service_name, Some("my-service".to_string()));
    }

    #[test]
    fn test_batch_config_defaults() {
        let config = BatchConfig::default();
        assert_eq!(config.max_queue_size, 2048);
        assert_eq!(config.max_export_batch_size, 512);
        assert_eq!(config.scheduled_delay, Duration::from_secs(5));
        assert_eq!(config.export_timeout, Duration::from_secs(30));
    }
}
