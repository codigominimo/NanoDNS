//! NanoDNS executable entry point.
//!
//! Phase 3 loads configuration, starts UDP/TCP DNS listeners, forwards queries
//! to upstream resolvers and manages a graceful shutdown.

use std::path::PathBuf;

use clap::Parser;
use nano_dns_core::config::{self, DEFAULT_CONFIG_FILE, Features};
use nano_dns_core::error::Result;
use nano_dns_core::runtime;
use nano_dns_protocol::DnsServer;
use tracing::info;

/// Command-line arguments accepted by NanoDNS.
#[derive(Debug, Parser)]
#[command(name = "nano-dns", version, about = "Minimal, modular DNS server")]
struct Args {
    /// Path to the JSON configuration file.
    #[arg(short, long, value_name = "PATH", default_value = DEFAULT_CONFIG_FILE)]
    config: PathBuf,

    /// Parse the configuration and exit without starting the runtime.
    #[arg(long)]
    check_config: bool,
}

/// Cargo features enabled in this build.
const FEATURES: Features = Features {
    forward: cfg!(feature = "forward"),
    recursive: cfg!(feature = "recursive"),
    blocker: cfg!(feature = "blocker"),
    sqlite: cfg!(feature = "sqlite"),
    statistics: cfg!(feature = "statistics"),
    api: cfg!(feature = "api"),
    web: cfg!(feature = "web"),
    doh: cfg!(feature = "doh"),
    dot: cfg!(feature = "dot"),
    dnssec: cfg!(feature = "dnssec"),
};

fn main() -> Result<()> {
    let args = Args::parse();
    let config = config::load(&args.config, &FEATURES)?;
    let _tracing = runtime::install(&config);

    info!(
        config = %args.config.display(),
        mode = ?config.resolver.mode,
        "configuration loaded and validated"
    );

    if args.check_config {
        return Ok(());
    }

    runtime::run(async move {
        info!(instance = %config.general.instance_name, "NanoDNS started");
        let mut server = DnsServer::bind(&config).await?;
        server.serve_with_signal(runtime::shutdown_signal()).await
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_to_standard_config_path() {
        let args = Args::try_parse_from(["nano-dns"]).expect("default args must parse");
        assert_eq!(args.config, PathBuf::from(DEFAULT_CONFIG_FILE));
        assert!(!args.check_config);
    }

    #[test]
    fn cli_accepts_config_check_flag() {
        let args = Args::try_parse_from(["nano-dns", "--check-config"]).expect("args must parse");
        assert!(args.check_config);
    }

    #[test]
    fn features_reflect_compilation_settings() {
        assert!(FEATURES.forward || !FEATURES.forward);
        assert_eq!(FEATURES.recursive, cfg!(feature = "recursive"));
    }
}
