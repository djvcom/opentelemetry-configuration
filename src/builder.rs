//! Builder for OpenTelemetry SDK configuration.
//!
//! Supports layered configuration: defaults → files → env vars → programmatic.

use crate::SdkError;
use crate::config::{ComputeEnvironment, OtelSdkConfig, Protocol, ResourceConfig};
use crate::guard::OtelGuard;
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use opentelemetry_sdk::Resource;
use std::path::Path;

/// Builder for configuring and initialising the OpenTelemetry SDK.
///
/// # Example
///
/// ```no_run
/// use opentelemetry_configuration::{OtelSdkBuilder, SdkError};
///
/// let _guard = OtelSdkBuilder::new()
///     .service_name("my-service")
///     .build()?;
/// # Ok::<(), SdkError>(())
/// ```
#[must_use = "builders do nothing unless .build() is called"]
pub struct OtelSdkBuilder {
    figment: Figment,
    custom_resource: Option<Resource>,
    resource_attributes: std::collections::HashMap<String, String>,
}

impl OtelSdkBuilder {
    /// Creates a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            figment: Figment::from(Serialized::defaults(OtelSdkConfig::default())),
            custom_resource: None,
            resource_attributes: std::collections::HashMap::new(),
        }
    }

    /// Creates a builder from an existing figment for complex configuration chains.
    pub fn from_figment(figment: Figment) -> Self {
        Self {
            figment,
            custom_resource: None,
            resource_attributes: std::collections::HashMap::new(),
        }
    }

    /// Merges configuration from a TOML file. Missing files are silently skipped.
    pub fn with_file<P: AsRef<Path>>(mut self, path: P) -> Self {
        let path = path.as_ref();
        if path.exists() {
            self.figment = self.figment.merge(Toml::file(path));
        }
        self
    }

    /// Merges configuration from environment variables with the given prefix.
    ///
    /// Variables are split on underscores: `PREFIX_FOO_BAR` → `foo.bar`.
    pub fn with_env(mut self, prefix: &str) -> Self {
        self.figment = self.figment.merge(Env::prefixed(prefix).split("_"));
        self
    }

    /// Merges standard `OTEL_*` environment variables per OpenTelemetry spec.
    pub fn with_standard_env(mut self) -> Self {
        if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
            self.figment = self
                .figment
                .merge(Serialized::default("endpoint.url", endpoint));
        }

        if let Ok(protocol) = std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL") {
            let protocol = match protocol.as_str() {
                "grpc" => "grpc",
                "http/json" => "httpjson",
                // "http/protobuf" and unknown values default to httpbinary
                _ => "httpbinary",
            };
            self.figment = self
                .figment
                .merge(Serialized::default("endpoint.protocol", protocol));
        }

        if let Ok(service_name) = std::env::var("OTEL_SERVICE_NAME") {
            self.figment = self
                .figment
                .merge(Serialized::default("resource.service_name", service_name));
        }

        if let Ok(exporter) = std::env::var("OTEL_TRACES_EXPORTER") {
            let enabled = exporter != "none";
            self.figment = self
                .figment
                .merge(Serialized::default("traces.enabled", enabled));
        }

        if let Ok(exporter) = std::env::var("OTEL_METRICS_EXPORTER") {
            let enabled = exporter != "none";
            self.figment = self
                .figment
                .merge(Serialized::default("metrics.enabled", enabled));
        }

        if let Ok(exporter) = std::env::var("OTEL_LOGS_EXPORTER") {
            let enabled = exporter != "none";
            self.figment = self
                .figment
                .merge(Serialized::default("logs.enabled", enabled));
        }

        self
    }

    /// Sets the OTLP endpoint URL. For HTTP, signal paths are appended automatically.
    pub fn endpoint(mut self, url: impl Into<String>) -> Self {
        self.figment = self
            .figment
            .merge(Serialized::default("endpoint.url", url.into()));
        self
    }

    /// Sets the export protocol.
    ///
    /// This overrides any configuration from files or environment variables.
    ///
    /// The default endpoint changes based on protocol:
    /// - `Protocol::Grpc` → `http://localhost:4317`
    /// - `Protocol::HttpBinary` → `http://localhost:4318`
    /// - `Protocol::HttpJson` → `http://localhost:4318`
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        let protocol_str = match protocol {
            Protocol::Grpc => "grpc",
            Protocol::HttpBinary => "httpbinary",
            Protocol::HttpJson => "httpjson",
        };
        self.figment = self
            .figment
            .merge(Serialized::default("endpoint.protocol", protocol_str));
        self
    }

    /// Sets the service name resource attribute.
    ///
    /// This is the most commonly configured resource attribute and identifies
    /// your service in the telemetry backend.
    pub fn service_name(mut self, name: impl Into<String>) -> Self {
        self.figment = self
            .figment
            .merge(Serialized::default("resource.service_name", name.into()));
        self
    }

    /// Sets the service version resource attribute.
    pub fn service_version(mut self, version: impl Into<String>) -> Self {
        self.figment = self.figment.merge(Serialized::default(
            "resource.service_version",
            version.into(),
        ));
        self
    }

    /// Sets the deployment environment resource attribute.
    pub fn deployment_environment(mut self, env: impl Into<String>) -> Self {
        self.figment = self.figment.merge(Serialized::default(
            "resource.deployment_environment",
            env.into(),
        ));
        self
    }

    /// Adds a custom resource attribute.
    ///
    /// Resource attributes describe the entity producing telemetry. Use this for
    /// application-specific metadata not covered by standard semantic conventions.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), opentelemetry_configuration::SdkError> {
    /// use opentelemetry_configuration::OtelSdkBuilder;
    ///
    /// let _guard = OtelSdkBuilder::new()
    ///     .service_name("my-service")
    ///     .resource_attribute("git.commit", "abc123")
    ///     .resource_attribute("feature.flags", "new-ui,beta-api")
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn resource_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.resource_attributes.insert(key.into(), value.into());
        self
    }

    /// Provides a pre-built OpenTelemetry Resource.
    ///
    /// This takes precedence over individual resource configuration.
    /// Use this when you need fine-grained control over resource construction.
    pub fn with_resource(mut self, resource: Resource) -> Self {
        self.custom_resource = Some(resource);
        self
    }

    /// Configures the resource using a builder function.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use opentelemetry_configuration::{OtelSdkBuilder, SdkError};
    ///
    /// let _guard = OtelSdkBuilder::new()
    ///     .resource(|r| r
    ///         .service_name("my-lambda")
    ///         .service_version(env!("CARGO_PKG_VERSION"))
    ///         .deployment_environment("production"))
    ///     .build()?;
    /// # Ok::<(), SdkError>(())
    /// ```
    pub fn resource<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ResourceConfigBuilder) -> ResourceConfigBuilder,
    {
        let builder = f(ResourceConfigBuilder::new());
        let config = builder.build();

        if let Some(name) = &config.service_name {
            self.figment = self
                .figment
                .merge(Serialized::default("resource.service_name", name.clone()));
        }
        if let Some(version) = &config.service_version {
            self.figment = self.figment.merge(Serialized::default(
                "resource.service_version",
                version.clone(),
            ));
        }
        if let Some(env) = &config.deployment_environment {
            self.figment = self.figment.merge(Serialized::default(
                "resource.deployment_environment",
                env.clone(),
            ));
        }
        if config.compute_environment != ComputeEnvironment::default() {
            let env_str = match config.compute_environment {
                ComputeEnvironment::Auto => "auto",
                ComputeEnvironment::Lambda => "lambda",
                ComputeEnvironment::Kubernetes => "kubernetes",
                ComputeEnvironment::None => "none",
            };
            self.figment = self
                .figment
                .merge(Serialized::default("resource.compute_environment", env_str));
        }
        for (key, value) in config.attributes {
            self.resource_attributes.insert(key, value);
        }

        self
    }

    /// Enables or disables trace collection.
    ///
    /// Default: enabled
    pub fn traces(mut self, enabled: bool) -> Self {
        self.figment = self
            .figment
            .merge(Serialized::default("traces.enabled", enabled));
        self
    }

    /// Enables or disables metrics collection.
    ///
    /// Default: enabled
    pub fn metrics(mut self, enabled: bool) -> Self {
        self.figment = self
            .figment
            .merge(Serialized::default("metrics.enabled", enabled));
        self
    }

    /// Enables or disables log collection.
    ///
    /// Default: enabled
    pub fn logs(mut self, enabled: bool) -> Self {
        self.figment = self
            .figment
            .merge(Serialized::default("logs.enabled", enabled));
        self
    }

    /// Disables automatic tracing subscriber initialisation.
    ///
    /// By default, the SDK sets up a `tracing-subscriber` with
    /// `tracing-opentelemetry` and `opentelemetry-appender-tracing` integration.
    /// Disable this if you want to configure the subscriber yourself.
    pub fn without_tracing_subscriber(mut self) -> Self {
        self.figment = self
            .figment
            .merge(Serialized::default("init_tracing_subscriber", false));
        self
    }

    /// Adds an HTTP header to all export requests.
    ///
    /// Headers are applied to trace, metric, and log exporters. Common uses include
    /// authentication tokens and custom routing metadata.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), opentelemetry_configuration::SdkError> {
    /// use opentelemetry_configuration::OtelSdkBuilder;
    ///
    /// let api_token = std::env::var("API_TOKEN").unwrap_or_default();
    /// let _guard = OtelSdkBuilder::new()
    ///     .service_name("my-service")
    ///     .header("Authorization", format!("Bearer {api_token}"))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let header_key = format!("endpoint.headers.{}", key.into());
        self.figment = self
            .figment
            .merge(Serialized::default(&header_key, value.into()));
        self
    }

    /// Sets the instrumentation scope name (otel.library.name).
    ///
    /// If not set, defaults to the service name, then "opentelemetry-configuration".
    pub fn instrumentation_scope_name(mut self, name: impl Into<String>) -> Self {
        self.figment = self.figment.merge(Serialized::default(
            "instrumentation_scope_name",
            name.into(),
        ));
        self
    }

    /// Sets the compute environment for resource detection.
    ///
    /// Controls which resource detectors are run automatically:
    /// - `Auto` (default): Runs generic detectors and probes for Lambda/K8s
    /// - `Lambda`: Runs generic detectors + Lambda-specific attributes
    /// - `Kubernetes`: Runs generic detectors + K8s detector
    /// - `None`: No automatic detection, only explicit configuration
    pub fn compute_environment(mut self, env: ComputeEnvironment) -> Self {
        let env_str = match env {
            ComputeEnvironment::Auto => "auto",
            ComputeEnvironment::Lambda => "lambda",
            ComputeEnvironment::Kubernetes => "kubernetes",
            ComputeEnvironment::None => "none",
        };
        self.figment = self
            .figment
            .merge(Serialized::default("resource.compute_environment", env_str));
        self
    }

    /// Adds Rust build-time information as resource attributes.
    ///
    /// Use with the [`capture_rust_build_info!`](crate::capture_rust_build_info) macro
    /// to add rustc version and channel information to telemetry.
    ///
    /// Requires [`emit_rustc_env`](crate::emit_rustc_env) to be called in your build.rs.
    ///
    /// # Example
    ///
    /// In build.rs:
    ///
    /// ```
    /// opentelemetry_configuration::emit_rustc_env();
    /// ```
    ///
    /// In main.rs:
    ///
    /// ```no_run
    /// # fn main() -> Result<(), opentelemetry_configuration::SdkError> {
    /// use opentelemetry_configuration::{OtelSdkBuilder, capture_rust_build_info};
    ///
    /// let _guard = OtelSdkBuilder::new()
    ///     .service_name("my-service")
    ///     .with_rust_build_info(capture_rust_build_info!())
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Attributes Added
    ///
    /// - `process.runtime.version` - rustc version (e.g., "1.84.0")
    /// - `process.runtime.description` - full version string
    /// - `rust.channel` - release channel ("stable", "beta", or "nightly")
    pub fn with_rust_build_info(mut self, info: crate::RustBuildInfo) -> Self {
        for kv in info.to_key_values() {
            let key = kv.key.as_str().to_string();
            let value = kv.value.as_str().to_string();
            self.resource_attributes.insert(key, value);
        }
        self
    }

    /// Extracts the configuration for inspection or debugging.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration extraction fails or if the endpoint
    /// URL is invalid.
    pub fn extract_config(&self) -> Result<OtelSdkConfig, SdkError> {
        let mut config: OtelSdkConfig = self
            .figment
            .extract()
            .map_err(|e| SdkError::Config(Box::new(e)))?;

        config
            .resource
            .attributes
            .extend(self.resource_attributes.clone());

        if let Some(ref url) = config.endpoint.url
            && !url.starts_with("http://")
            && !url.starts_with("https://")
        {
            return Err(SdkError::InvalidEndpoint { url: url.clone() });
        }

        Ok(config)
    }

    /// Builds and initialises the OpenTelemetry SDK.
    ///
    /// Returns an [`OtelGuard`] that manages provider lifecycle. When the
    /// guard is dropped, all providers are flushed and shut down.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Configuration extraction fails
    /// - Provider initialisation fails
    /// - Tracing subscriber initialisation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use opentelemetry_configuration::{OtelSdkBuilder, SdkError};
    ///
    /// fn main() -> Result<(), SdkError> {
    ///     let _guard = OtelSdkBuilder::new()
    ///         .with_env("OTEL_")
    ///         .service_name("my-lambda")
    ///         .build()?;
    ///
    ///     tracing::info!("Application started");
    ///
    ///     // Guard automatically shuts down providers on drop
    ///     Ok(())
    /// }
    /// ```
    pub fn build(self) -> Result<OtelGuard, SdkError> {
        let mut config: OtelSdkConfig = self
            .figment
            .extract()
            .map_err(|e| SdkError::Config(Box::new(e)))?;

        config.resource.attributes.extend(self.resource_attributes);

        if let Some(ref url) = config.endpoint.url
            && !url.starts_with("http://")
            && !url.starts_with("https://")
        {
            return Err(SdkError::InvalidEndpoint { url: url.clone() });
        }

        OtelGuard::from_config(&config, self.custom_resource)
    }
}

impl Default for OtelSdkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for resource configuration.
///
/// Used with [`OtelSdkBuilder::resource`] for fluent configuration.
#[derive(Default)]
#[must_use = "builders do nothing unless .build() is called"]
pub struct ResourceConfigBuilder {
    config: ResourceConfig,
}

impl ResourceConfigBuilder {
    /// Creates a new resource config builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the service name.
    pub fn service_name(mut self, name: impl Into<String>) -> Self {
        self.config.service_name = Some(name.into());
        self
    }

    /// Sets the service version.
    pub fn service_version(mut self, version: impl Into<String>) -> Self {
        self.config.service_version = Some(version.into());
        self
    }

    /// Sets the deployment environment.
    pub fn deployment_environment(mut self, env: impl Into<String>) -> Self {
        self.config.deployment_environment = Some(env.into());
        self
    }

    /// Adds a resource attribute.
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.attributes.insert(key.into(), value.into());
        self
    }

    /// Sets the compute environment for resource detection.
    pub fn compute_environment(mut self, env: ComputeEnvironment) -> Self {
        self.config.compute_environment = env;
        self
    }

    /// Builds the resource configuration.
    #[must_use]
    pub fn build(self) -> ResourceConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_builder_enables_all_signals_with_http_binary_protocol() {
        let builder = OtelSdkBuilder::new();
        let config = builder.extract_config().unwrap();

        assert!(config.traces.enabled);
        assert!(config.metrics.enabled);
        assert!(config.logs.enabled);
        assert!(config.init_tracing_subscriber);
        assert_eq!(config.endpoint.protocol, Protocol::HttpBinary);
    }

    #[test]
    fn builder_methods_can_disable_individual_signals() {
        let builder = OtelSdkBuilder::new()
            .traces(false)
            .metrics(false)
            .logs(false);
        let config = builder.extract_config().unwrap();

        assert!(!config.traces.enabled);
        assert!(!config.metrics.enabled);
        assert!(!config.logs.enabled);
    }

    #[test]
    fn test_builder_resource_fluent() {
        let builder = OtelSdkBuilder::new().resource(|r| {
            r.service_name("my-service")
                .service_version("1.0.0")
                .deployment_environment("production")
                .attribute("custom.key", "custom.value")
        });
        let config = builder.extract_config().unwrap();

        assert_eq!(config.resource.service_name, Some("my-service".to_string()));
        assert_eq!(config.resource.service_version, Some("1.0.0".to_string()));
        assert_eq!(
            config.resource.deployment_environment,
            Some("production".to_string())
        );
        assert_eq!(
            config.resource.attributes.get("custom.key"),
            Some(&"custom.value".to_string())
        );
    }

    #[test]
    fn test_builder_without_tracing_subscriber() {
        let builder = OtelSdkBuilder::new().without_tracing_subscriber();
        let config = builder.extract_config().unwrap();

        assert!(!config.init_tracing_subscriber);
    }

    #[test]
    fn test_with_standard_env_service_name() {
        temp_env::with_var("OTEL_SERVICE_NAME", Some("test-service"), || {
            let builder = OtelSdkBuilder::new().with_standard_env();
            let config = builder.extract_config().unwrap();
            assert_eq!(
                config.resource.service_name,
                Some("test-service".to_string())
            );
        });
    }

    #[test]
    fn test_with_standard_env_multiple_vars() {
        temp_env::with_vars(
            [
                ("OTEL_EXPORTER_OTLP_ENDPOINT", Some("http://collector:4317")),
                ("OTEL_EXPORTER_OTLP_PROTOCOL", Some("grpc")),
                ("OTEL_SERVICE_NAME", Some("multi-test")),
                ("OTEL_TRACES_EXPORTER", Some("otlp")),
            ],
            || {
                let builder = OtelSdkBuilder::new().with_standard_env();
                let config = builder.extract_config().unwrap();

                assert_eq!(
                    config.endpoint.url,
                    Some("http://collector:4317".to_string())
                );
                assert_eq!(config.endpoint.protocol, Protocol::Grpc);
                assert_eq!(config.resource.service_name, Some("multi-test".to_string()));
                assert!(config.traces.enabled);
            },
        );
    }

    #[test]
    fn test_programmatic_overrides_env() {
        temp_env::with_vars(
            [
                ("OTEL_EXPORTER_OTLP_ENDPOINT", Some("http://env:4318")),
                ("OTEL_SERVICE_NAME", Some("env-service")),
            ],
            || {
                let builder = OtelSdkBuilder::new()
                    .with_standard_env()
                    .endpoint("http://programmatic:4318")
                    .service_name("programmatic-service");
                let config = builder.extract_config().unwrap();

                assert_eq!(
                    config.endpoint.url,
                    Some("http://programmatic:4318".to_string())
                );
                assert_eq!(
                    config.resource.service_name,
                    Some("programmatic-service".to_string())
                );
            },
        );
    }

    #[test]
    fn test_invalid_endpoint_url_rejected() {
        let builder = OtelSdkBuilder::new().endpoint("not-a-valid-url");
        let result = builder.extract_config();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SdkError::InvalidEndpoint { ref url } if url == "not-a-valid-url"),
            "Expected InvalidEndpoint error, got: {err:?}"
        );
    }

    #[test]
    fn test_valid_http_endpoint_accepted() {
        let builder = OtelSdkBuilder::new().endpoint("http://localhost:4318");
        let config = builder.extract_config().unwrap();
        assert_eq!(
            config.endpoint.url,
            Some("http://localhost:4318".to_string())
        );
    }

    #[test]
    fn test_valid_https_endpoint_accepted() {
        let builder = OtelSdkBuilder::new().endpoint("https://collector.example.com:4318");
        let config = builder.extract_config().unwrap();
        assert_eq!(
            config.endpoint.url,
            Some("https://collector.example.com:4318".to_string())
        );
    }

    #[test]
    fn extract_config_rejects_endpoint_with_ftp_scheme() {
        let builder = OtelSdkBuilder::new().endpoint("ftp://collector:21");
        let result = builder.extract_config();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SdkError::InvalidEndpoint { ref url } if url == "ftp://collector:21"),
            "Expected InvalidEndpoint error for ftp scheme, got: {err:?}"
        );
    }

    #[test]
    fn with_standard_env_maps_unknown_protocol_to_default() {
        temp_env::with_var(
            "OTEL_EXPORTER_OTLP_PROTOCOL",
            Some("unknown-protocol"),
            || {
                let builder = OtelSdkBuilder::new().with_standard_env();
                let config = builder.extract_config().unwrap();
                assert_eq!(
                    config.endpoint.protocol,
                    Protocol::HttpBinary,
                    "Unknown protocol should fall back to HttpBinary"
                );
            },
        );
    }

    #[test]
    fn configuration_layering_follows_correct_precedence() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[resource]
service_name = "file-service"

[endpoint]
url = "http://file-collector:4318"
"#
        )
        .unwrap();

        temp_env::with_vars(
            [
                ("OTEL_SERVICE_NAME", Some("env-service")),
                (
                    "OTEL_EXPORTER_OTLP_ENDPOINT",
                    Some("http://env-collector:4318"),
                ),
            ],
            || {
                let builder = OtelSdkBuilder::new()
                    .with_file(file.path())
                    .with_standard_env()
                    .service_name("programmatic-service");
                let config = builder.extract_config().unwrap();

                assert_eq!(
                    config.resource.service_name,
                    Some("programmatic-service".to_string()),
                    "Programmatic config should override env and file"
                );
                assert_eq!(
                    config.endpoint.url,
                    Some("http://env-collector:4318".to_string()),
                    "Env config should override file config"
                );
            },
        );
    }

    #[test]
    fn with_file_merges_toml_config() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[resource]
service_name = "toml-service"
service_version = "2.0.0"

[endpoint]
url = "http://toml-collector:4318"
protocol = "grpc"

[traces]
enabled = false
"#
        )
        .unwrap();

        let builder = OtelSdkBuilder::new().with_file(file.path());
        let config = builder.extract_config().unwrap();

        assert_eq!(
            config.resource.service_name,
            Some("toml-service".to_string())
        );
        assert_eq!(config.resource.service_version, Some("2.0.0".to_string()));
        assert_eq!(
            config.endpoint.url,
            Some("http://toml-collector:4318".to_string())
        );
        assert_eq!(config.endpoint.protocol, Protocol::Grpc);
        assert!(!config.traces.enabled);
    }

    #[test]
    fn with_env_reads_prefixed_environment_variables() {
        temp_env::with_var("MYAPP_ENDPOINT_URL", Some("http://custom:4318"), || {
            let builder = OtelSdkBuilder::new().with_env("MYAPP_");
            let config = builder.extract_config().unwrap();
            assert_eq!(config.endpoint.url, Some("http://custom:4318".to_string()));
        });
    }

    #[test]
    fn header_adds_to_endpoint_headers() {
        let builder = OtelSdkBuilder::new()
            .header("X-Custom", "value1")
            .header("X-Another", "value2");
        let config = builder.extract_config().unwrap();

        assert_eq!(
            config.endpoint.headers.get("X-Custom"),
            Some(&"value1".to_string())
        );
        assert_eq!(
            config.endpoint.headers.get("X-Another"),
            Some(&"value2".to_string())
        );
    }

    #[test]
    fn instrumentation_scope_name_overrides_default() {
        let builder = OtelSdkBuilder::new().instrumentation_scope_name("custom-scope");
        let config = builder.extract_config().unwrap();

        assert_eq!(
            config.instrumentation_scope_name,
            Some("custom-scope".to_string())
        );
    }
}
