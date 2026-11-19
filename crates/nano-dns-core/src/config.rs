//! Strict, fully validated JSON configuration for NanoDNS.
//!
//! Unknown fields are rejected so that a typo can never silently produce a
//! partially valid or insecure configuration. Semantic validation is performed
//! in [`Config::validate`], which is called by [`load`].

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, ConfigResult};

/// Default configuration file name.
pub const DEFAULT_CONFIG_FILE: &str = "nano-dns.json";

/// Mode used to resolve queries that are not answered locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum ResolverMode {
    /// Forward queries to one or more upstream resolvers.
    Forward,
    /// Perform full iterative resolution from the root zone.
    Recursive,
}

/// Blocking response returned to clients for denied queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE", deny_unknown_fields)]
pub enum BlockResponse {
    /// Respond with NXDOMAIN (default).
    Nxdomain,
    /// Respond with NOERROR and no answers.
    Nodata,
    /// Respond with an address pointing to a sinkhole.
    Sinkhole,
}

impl Default for BlockResponse {
    fn default() -> Self {
        Self::Nxdomain
    }
}

/// Address family selection for listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum IpVersion {
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
    /// Both families.
    Both,
}

/// General process settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct General {
    /// Human-readable instance name.
    pub instance_name: String,
    /// Daemonize / detach on Unix (reserved for a later phase).
    pub daemon: bool,
    /// Minimum log level: `trace`, `debug`, `info`, `warn` or `error`.
    pub log_level: String,
}

impl Default for General {
    fn default() -> Self {
        Self {
            instance_name: "NanoDNS".to_owned(),
            daemon: false,
            log_level: "info".to_owned(),
        }
    }
}

/// A single DNS listening socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Address to bind to.
    pub address: IpAddr,
    /// UDP port. `0` disables UDP for this listener.
    pub port_udp: u16,
    /// TCP port. `0` disables TCP for this listener.
    pub port_tcp: u16,
    /// Whether this listener accepts DNS over TLS (Fase 11).
    pub dot: bool,
    /// Whether this listener accepts DNS over HTTPS (Fase 11).
    pub doh: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port_udp: 53,
            port_tcp: 53,
            dot: false,
            doh: false,
        }
    }
}

/// Listener and transport settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listeners {
    /// Address family policy.
    pub ip_version: IpVersion,
    /// Explicit listeners. An empty list uses the default loopback listener.
    pub entries: Vec<ListenerConfig>,
    /// Maximum DNS message size accepted from clients.
    pub max_packet_bytes: usize,
    /// Maximum concurrent in-flight queries (global).
    pub max_concurrent_queries: usize,
    /// Networks allowed to query this resolver. Empty means loopback only.
    pub allowed_networks: Vec<IpNet>,
}

impl Default for Listeners {
    fn default() -> Self {
        Self {
            ip_version: IpVersion::V4,
            entries: Vec::new(),
            max_packet_bytes: 1232,
            max_concurrent_queries: 1024,
            allowed_networks: Vec::new(),
        }
    }
}

/// A single upstream DNS resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// Upstream IP address.
    pub address: IpAddr,
    /// Upstream port.
    pub port: u16,
    /// Prefer TCP for this upstream.
    pub tcp: bool,
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            port: 53,
            tcp: false,
        }
    }
}

/// Resolution engine settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverConfig {
    /// Resolution mode.
    pub mode: ResolverMode,
    /// Upstream resolvers used in forward mode.
    pub upstreams: Vec<Upstream>,
    /// Query timeout in milliseconds.
    pub timeout_ms: u64,
    /// Number of retries per query.
    pub retries: u8,
    /// Validate DNSSEC responses.
    pub dnssec: bool,
    /// Optional trust anchor file (DNSKEY presentation format) used for validation.
    #[serde(default)]
    pub dnssec_trust_anchor: Option<PathBuf>,
    /// Root hints used in recursive mode.
    pub root_hints: Vec<IpAddr>,
    /// UDP/TCP port used for root hint servers.
    #[serde(default = "default_root_port")]
    pub root_port: u16,
}

const fn default_root_port() -> u16 {
    53
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            mode: ResolverMode::Forward,
            upstreams: vec![Upstream::default()],
            timeout_ms: 2_000,
            retries: 2,
            dnssec: false,
            dnssec_trust_anchor: None,
            root_hints: Vec::new(),
            root_port: default_root_port(),
        }
    }
}

/// DNS response cache settings (Fase 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsCacheConfig {
    /// Whether the DNS cache is enabled.
    pub enabled: bool,
    /// Maximum number of cached responses.
    pub max_entries: usize,
    /// Soft memory limit in bytes.
    pub max_bytes: usize,
    /// Cap applied to response TTLs, in seconds.
    pub max_ttl_secs: u32,
    /// TTL used for negative responses, in seconds.
    pub negative_ttl_secs: u32,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 4_096,
            max_bytes: 16 * 1024 * 1024,
            max_ttl_secs: 86_400,
            negative_ttl_secs: 60,
        }
    }
}

/// Filtering decision cache settings (Fase 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCacheConfig {
    /// Whether the policy cache is enabled.
    pub enabled: bool,
    /// Maximum number of cached decisions.
    pub max_entries: usize,
}

impl Default for PolicyCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 8_192,
        }
    }
}

/// Categories that can be blocked globally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum BlockCategory {
    /// Advertising.
    Advertising,
    /// Trackers.
    Trackers,
    /// Analytics.
    Analytics,
    /// Malware.
    Malware,
    /// Phishing.
    Phishing,
    /// User-provided lists.
    Custom,
}

/// A remote or local block list source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListSource {
    /// Unique list identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Category assigned to entries from this list.
    pub category: BlockCategory,
    /// File path or URL.
    pub source: String,
    /// Whether the list is enabled.
    pub enabled: bool,
    /// Refresh interval in seconds; `0` disables automatic refresh.
    pub refresh_secs: u64,
}

/// Blocking engine configuration (Fase 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockerConfig {
    /// Whether blocking is enabled.
    pub enabled: bool,
    /// Response returned for blocked queries.
    pub block_response: BlockResponse,
    /// Enabled categories.
    pub categories: Vec<BlockCategory>,
    /// Installed lists.
    pub lists: Vec<ListSource>,
    /// Globally allowed domains.
    pub allowlist: Vec<String>,
    /// Globally denied domains.
    pub denylist: Vec<String>,
    /// Directory containing list files.
    pub lists_dir: PathBuf,
    /// Sinkhole IPv4 address used when `block_response` is `SINKHOLE`.
    pub sinkhole_v4: Ipv4Addr,
    /// Sinkhole IPv6 address used when `block_response` is `SINKHOLE`.
    pub sinkhole_v6: Ipv6Addr,
}

impl Default for BlockerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_response: BlockResponse::Nxdomain,
            categories: vec![
                BlockCategory::Advertising,
                BlockCategory::Trackers,
                BlockCategory::Malware,
                BlockCategory::Phishing,
            ],
            lists: Vec::new(),
            allowlist: Vec::new(),
            denylist: Vec::new(),
            lists_dir: PathBuf::from("data/lists"),
            sinkhole_v4: Ipv4Addr::UNSPECIFIED,
            sinkhole_v6: Ipv6Addr::UNSPECIFIED,
        }
    }
}

/// A client with device-specific rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Stable client identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Networks or addresses that identify this device.
    pub networks: Vec<IpNet>,
    /// Domains allowed for this client.
    pub allowlist: Vec<String>,
    /// Domains blocked for this client.
    pub denylist: Vec<String>,
}

/// Optional SQLite persistence (Fase 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Whether persistence is enabled.
    pub enabled: bool,
    /// Database path.
    pub path: PathBuf,
    /// Store full DNS history (disabled by default).
    pub history: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: PathBuf::from("data/database/nano-dns.sqlite3"),
            history: false,
        }
    }
}

/// Optional statistics (Fase 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsConfig {
    /// Whether statistics collection is enabled.
    pub enabled: bool,
    /// How long to retain in-memory counters, in seconds.
    pub retention_secs: u64,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_secs: 86_400,
        }
    }
}

/// Optional REST API (Fase 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Whether the API is enabled.
    pub enabled: bool,
    /// Bind address. Never exposed publicly by default.
    pub listen: IpAddr,
    /// TCP port.
    pub port: u16,
    /// Shared secret token required in the `Authorization` header.
    pub token: Option<String>,
    /// Networks allowed to call the API. Empty means loopback only.
    pub allowed_networks: Vec<IpNet>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            token: None,
            allowed_networks: Vec::new(),
        }
    }
}

/// Optional server-rendered web interface (Fase 10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    /// Whether the web interface is enabled.
    pub enabled: bool,
    /// Bind address. Never exposed publicly by default.
    pub listen: IpAddr,
    /// TCP port.
    pub port: u16,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8081,
        }
    }
}

/// DNS over TLS settings (Fase 11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DotConfig {
    /// Whether DoT is enabled at runtime.
    pub enabled: bool,
    /// TCP port used by every listener that opts into DoT.
    pub port: u16,
    /// Path to the PEM certificate chain.
    pub cert_path: Option<PathBuf>,
    /// Path to the PEM private key.
    pub key_path: Option<PathBuf>,
}

impl Default for DotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 853,
            cert_path: None,
            key_path: None,
        }
    }
}

/// DNS over HTTPS settings (Fase 11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DohConfig {
    /// Whether DoH is enabled at runtime.
    pub enabled: bool,
    /// TCP port used by every listener that opts into DoH.
    pub port: u16,
    /// HTTPS path used for DNS queries.
    pub path: String,
    /// Path to the PEM certificate chain.
    pub cert_path: Option<PathBuf>,
    /// Path to the PEM private key.
    pub key_path: Option<PathBuf>,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 443,
            path: "/dns-query".to_owned(),
            cert_path: None,
            key_path: None,
        }
    }
}

/// Complete NanoDNS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema version. Only version 1 is currently accepted.
    pub version: u32,
    /// General settings.
    pub general: General,
    /// Listener settings.
    pub listeners: Listeners,
    /// Resolver settings.
    pub resolver: ResolverConfig,
    /// DNS cache settings.
    pub dns_cache: DnsCacheConfig,
    /// Policy cache settings.
    pub policy_cache: PolicyCacheConfig,
    /// Blocking settings.
    pub blocker: BlockerConfig,
    /// Per-device rules, keyed by client id.
    pub clients: BTreeMap<String, ClientConfig>,
    /// SQLite persistence settings.
    pub storage: StorageConfig,
    /// Statistics settings.
    pub stats: StatsConfig,
    /// REST API settings.
    pub api: ApiConfig,
    /// Web interface settings.
    pub web: WebConfig,
    /// DNS over TLS settings.
    pub dot: DotConfig,
    /// DNS over HTTPS settings.
    pub doh: DohConfig,
}

impl Default for Config {
    fn default() -> Self {
        let loopback_v6 = IpNet::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128)
            .expect("the IPv6 loopback prefix is always valid");
        let mut allowed_networks = Vec::new();
        allowed_networks.push(loopback_v6);

        let mut listeners = Listeners::default();
        listeners.entries.push(ListenerConfig::default());
        listeners.allowed_networks = allowed_networks.clone();

        let mut api = ApiConfig::default();
        api.allowed_networks = allowed_networks;

        Self {
            version: 1,
            general: General::default(),
            listeners,
            resolver: ResolverConfig::default(),
            dns_cache: DnsCacheConfig::default(),
            policy_cache: PolicyCacheConfig::default(),
            blocker: BlockerConfig::default(),
            clients: BTreeMap::new(),
            storage: StorageConfig::default(),
            stats: StatsConfig::default(),
            api,
            web: WebConfig::default(),
            dot: DotConfig::default(),
            doh: DohConfig::default(),
        }
    }
}

impl Config {
    /// Validate all semantic invariants of the configuration.
    ///
    /// Every error returned here leaves the previous configuration untouched,
    /// so a hot reload can never apply a partially valid state.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.version != 1 {
            return Err(ConfigError::Validation(format!(
                "unsupported config version {}, expected 1",
                self.version
            )));
        }

        if !matches!(
            self.general.log_level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error"
        ) {
            return Err(ConfigError::Validation(format!(
                "invalid general.log_level '{}'",
                self.general.log_level
            )));
        }

        if self.listeners.entries.is_empty() {
            return Err(ConfigError::Validation(
                "listeners.entries must contain at least one listener".to_owned(),
            ));
        }

        for (index, listener) in self.listeners.entries.iter().enumerate() {
            if listener.port_udp == 0 && listener.port_tcp == 0 {
                return Err(ConfigError::Validation(format!(
                    "listeners.entries[{index}] disables both UDP and TCP"
                )));
            }
            match self.listeners.ip_version {
                IpVersion::V4 if listener.address.is_ipv6() => {
                    return Err(ConfigError::Validation(format!(
                        "listeners.entries[{index}] is IPv6 but ip_version is v4"
                    )));
                }
                IpVersion::V6 if listener.address.is_ipv4() => {
                    return Err(ConfigError::Validation(format!(
                        "listeners.entries[{index}] is IPv4 but ip_version is v6"
                    )));
                }
                IpVersion::Both | IpVersion::V4 | IpVersion::V6 => {}
            }
            if listener.dot && !self.dot.enabled {
                return Err(ConfigError::Validation(format!(
                    "listeners.entries[{index}] requests DoT but dot.enabled is false"
                )));
            }
            if listener.doh && !self.doh.enabled {
                return Err(ConfigError::Validation(format!(
                    "listeners.entries[{index}] requests DoH but doh.enabled is false"
                )));
            }
        }

        if self.listeners.max_packet_bytes < 512 || self.listeners.max_packet_bytes > 65_535 {
            return Err(ConfigError::Validation(
                "listeners.max_packet_bytes must be between 512 and 65535".to_owned(),
            ));
        }
        if self.listeners.max_concurrent_queries == 0 {
            return Err(ConfigError::Validation(
                "listeners.max_concurrent_queries must be greater than zero".to_owned(),
            ));
        }

        match self.resolver.mode {
            ResolverMode::Forward => {
                if self.resolver.upstreams.is_empty() {
                    return Err(ConfigError::Validation(
                        "resolver.upstreams cannot be empty in forward mode".to_owned(),
                    ));
                }
                if self.resolver.upstreams.iter().any(|u| u.port == 0) {
                    return Err(ConfigError::Validation(
                        "resolver.upstreams contains an invalid port".to_owned(),
                    ));
                }
            }
            ResolverMode::Recursive => {
                if self.resolver.root_hints.is_empty() {
                    return Err(ConfigError::Validation(
                        "resolver.root_hints cannot be empty in recursive mode".to_owned(),
                    ));
                }
                if self.resolver.root_port == 0 {
                    return Err(ConfigError::Validation(
                        "resolver.root_port must be greater than zero".to_owned(),
                    ));
                }
            }
        }

        if self.resolver.dnssec && self.resolver.mode != ResolverMode::Forward {
            return Err(ConfigError::Validation(
                "DNSSEC validation requires resolver.mode = \"forward\"".to_owned(),
            ));
        }
        if self.resolver.dnssec_trust_anchor.is_some() && !self.resolver.dnssec {
            return Err(ConfigError::Validation(
                "resolver.dnssec_trust_anchor requires resolver.dnssec to be enabled".to_owned(),
            ));
        }

        if !self.blocker.enabled && !self.blocker.allowlist.is_empty() {
            return Err(ConfigError::Validation(
                "blocker.allowlist is non-empty while blocking is disabled".to_owned(),
            ));
        }
        if !self.blocker.enabled && !self.blocker.denylist.is_empty() {
            return Err(ConfigError::Validation(
                "blocker.denylist is non-empty while blocking is disabled".to_owned(),
            ));
        }

        if self.dns_cache.enabled
            && (self.dns_cache.max_entries == 0 || self.dns_cache.max_bytes == 0)
        {
            return Err(ConfigError::Validation(
                "dns_cache limits must be greater than zero when the cache is enabled".to_owned(),
            ));
        }
        if self.policy_cache.enabled && self.policy_cache.max_entries == 0 {
            return Err(ConfigError::Validation(
                "policy_cache.max_entries must be greater than zero when enabled".to_owned(),
            ));
        }

        if !self.storage.enabled && self.storage.history {
            return Err(ConfigError::Validation(
                "storage.history cannot be enabled while storage is disabled".to_owned(),
            ));
        }
        if self.storage.enabled && self.storage.path.as_os_str().is_empty() {
            return Err(ConfigError::Validation(
                "storage.path cannot be empty when storage is enabled".to_owned(),
            ));
        }
        if self.stats.enabled && self.stats.retention_secs == 0 {
            return Err(ConfigError::Validation(
                "stats.retention_secs must be greater than zero when enabled".to_owned(),
            ));
        }
        if self.api.enabled
            && self
                .api
                .token
                .as_ref()
                .is_some_and(|token| token.is_empty())
        {
            return Err(ConfigError::Validation(
                "api.token cannot be empty when configured".to_owned(),
            ));
        }
        if self.dot.enabled {
            if self.dot.cert_path.is_none() || self.dot.key_path.is_none() {
                return Err(ConfigError::Validation(
                    "DoT requires both cert_path and key_path".to_owned(),
                ));
            }
            if self.dot.port == 0 {
                return Err(ConfigError::Validation(
                    "dot.port must be greater than zero".to_owned(),
                ));
            }
            if !self.listeners.entries.iter().any(|entry| entry.dot) {
                return Err(ConfigError::Validation(
                    "dot.enabled requires at least one listener with dot = true".to_owned(),
                ));
            }
        }
        if self.doh.enabled {
            if self.doh.cert_path.is_none() || self.doh.key_path.is_none() {
                return Err(ConfigError::Validation(
                    "DoH requires both cert_path and key_path".to_owned(),
                ));
            }
            if self.doh.port == 0 {
                return Err(ConfigError::Validation(
                    "doh.port must be greater than zero".to_owned(),
                ));
            }
            if !self.listeners.entries.iter().any(|entry| entry.doh) {
                return Err(ConfigError::Validation(
                    "doh.enabled requires at least one listener with doh = true".to_owned(),
                ));
            }
        }
        if !self.doh.path.starts_with('/') || self.doh.path.len() < 2 {
            return Err(ConfigError::Validation(
                "doh.path must be an absolute HTTP path".to_owned(),
            ));
        }

        let mut ids = BTreeMap::<&str, ()>::new();
        for (key, client) in &self.clients {
            if *key != client.id {
                return Err(ConfigError::Validation(format!(
                    "client key '{key}' does not match id '{}'",
                    client.id
                )));
            }
            if client.networks.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "client '{}' must define at least one network",
                    client.id
                )));
            }
            if ids.insert(&client.id, ()).is_some() {
                return Err(ConfigError::Validation(format!(
                    "duplicated client id '{}'",
                    client.id
                )));
            }
        }

        let mut list_ids = BTreeMap::<&str, ()>::new();
        for list in &self.blocker.lists {
            if list.id.is_empty() || list.source.is_empty() {
                return Err(ConfigError::Validation(
                    "block lists require a non-empty id and source".to_owned(),
                ));
            }
            if list_ids.insert(&list.id, ()).is_some() {
                return Err(ConfigError::Validation(format!(
                    "duplicated block list id '{}'",
                    list.id
                )));
            }
        }

        Ok(())
    }
}

/// Load and validate a JSON configuration file.
pub fn load(path: &Path) -> ConfigResult<Config> {
    let content = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let config: Config = serde_json::from_str(&content).map_err(|source| ConfigError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    config.validate()?;
    Ok(config)
}

/// Parse a configuration from a JSON string.
pub fn from_str(input: &str) -> ConfigResult<Config> {
    let config: Config = serde_json::from_str(input).map_err(|source| ConfigError::Json {
        path: PathBuf::from("<string>"),
        source,
    })?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        Config::default()
            .validate()
            .expect("defaults must be valid");
    }

    #[test]
    fn default_config_roundtrips_through_json() {
        let config = Config::default();
        let json = serde_json::to_string(&config).expect("serialization must succeed");
        let restored = from_str(&json).expect("deserialization must succeed");
        assert_eq!(config, restored);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = r#"{"version":1,"unexpected":true}"#;
        assert!(from_str(json).is_err());
    }

    #[test]
    fn recursive_mode_requires_root_hints() {
        let mut config = Config::default();
        config.resolver.mode = ResolverMode::Recursive;
        assert!(config.validate().is_err());

        config
            .resolver
            .root_hints
            .push(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)));
        config
            .validate()
            .expect("recursive configuration must be valid");

        config.resolver.root_port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn dnssec_requires_forward_mode_and_consistent_trust_anchor() {
        let mut config = Config::default();
        config.resolver.dnssec = true;
        config.validate().expect("DNSSEC forward mode is valid");

        config.resolver.mode = ResolverMode::Recursive;
        config
            .resolver
            .root_hints
            .push(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(config.validate().is_err());

        config.resolver.mode = ResolverMode::Forward;
        config.resolver.dnssec_trust_anchor = Some(PathBuf::from("anchors/dnskey.txt"));
        config.validate().expect("custom trust anchor is valid");

        config.resolver.dnssec = false;
        assert!(config.validate().is_err());

        config.resolver.dnssec = true;
        config.validate().expect("custom anchor implies DNSSEC");
    }

    #[test]
    fn storage_requires_consistent_options() {
        let mut config = Config::default();
        config.storage.enabled = true;
        config
            .validate()
            .expect("persistence is fully available at runtime");

        config.storage.enabled = false;
        config.storage.history = true;
        assert!(config.validate().is_err());

        config.storage.enabled = true;
        config.storage.path = PathBuf::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn stats_require_positive_retention() {
        let mut config = Config::default();
        config.stats.enabled = true;
        config.stats.retention_secs = 0;
        assert!(config.validate().is_err());

        config.stats.retention_secs = 60;
        config.validate().expect("positive retention is valid");
    }

    #[test]
    fn listener_validation_rejects_both_transports_disabled() {
        let mut config = Config::default();
        config.listeners.entries.push(ListenerConfig {
            port_udp: 0,
            port_tcp: 0,
            ..ListenerConfig::default()
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn client_ids_must_be_consistent() {
        let mut config = Config::default();
        config.clients.insert(
            "phone".to_owned(),
            ClientConfig {
                id: "tablet".to_owned(),
                name: "Tablet".to_owned(),
                networks: vec![
                    IpNet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32).expect("valid prefix"),
                ],
                allowlist: Vec::new(),
                denylist: Vec::new(),
            },
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn dot_requires_paths_and_opt_in() {
        let mut config = Config::default();
        config.dot.enabled = true;
        config.dot.cert_path = Some(PathBuf::from("cert.pem"));
        config.dot.key_path = Some(PathBuf::from("cert.key"));
        // No listener opts into DoT yet.
        assert!(config.validate().is_err());

        config.listeners.entries[0].dot = true;
        config.validate().expect("valid DoT configuration");

        // Missing paths are rejected.
        config.dot.key_path = None;
        assert!(config.validate().is_err());

        // A zero port is invalid.
        config.dot.key_path = Some(PathBuf::from("cert.key"));
        config.dot.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn doh_requires_paths_opt_in_and_absolute_path() {
        let mut config = Config::default();
        config.doh.enabled = true;
        config.doh.cert_path = Some(PathBuf::from("cert.pem"));
        config.doh.key_path = Some(PathBuf::from("cert.key"));
        assert!(config.validate().is_err());

        config.listeners.entries[0].doh = true;
        config.validate().expect("valid DoH configuration");

        config.doh.path = "dns-query".to_owned();
        assert!(config.validate().is_err());

        config.doh.path = "/dns-query".to_owned();
        config.doh.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn listener_cannot_request_disabled_transports() {
        let mut config = Config::default();
        config.listeners.entries[0].dot = true;
        assert!(config.validate().is_err());

        config.listeners.entries[0].dot = false;
        config.listeners.entries[0].doh = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn every_runtime_service_can_be_enabled_at_once() {
        let mut config = Config::default();
        config.blocker.enabled = true;
        config.storage.enabled = true;
        config.stats.enabled = true;
        config.api.enabled = true;
        config.web.enabled = true;
        config.resolver.dnssec = true;
        config.dot.enabled = true;
        config.dot.cert_path = Some(PathBuf::from("cert.pem"));
        config.dot.key_path = Some(PathBuf::from("cert.key"));
        config.doh.enabled = true;
        config.doh.cert_path = Some(PathBuf::from("cert.pem"));
        config.doh.key_path = Some(PathBuf::from("cert.key"));
        config.listeners.entries[0].dot = true;
        config.listeners.entries[0].doh = true;

        config
            .validate()
            .expect("JSON must be able to enable every service");
    }

    #[test]
    fn load_reports_io_errors_with_path() {
        let error = load(Path::new("definitely-missing-nano-dns.json"))
            .expect_err("missing file must fail");
        assert!(matches!(error, ConfigError::Read { .. }));
    }
}
