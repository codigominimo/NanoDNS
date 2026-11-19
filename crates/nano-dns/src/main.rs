//! NanoDNS executable entry point.
//!
//! Loads configuration, starts UDP/TCP DNS listeners and the optional DoT, DoH,
//! REST API and web dashboard, then coordinates graceful shutdown across all
//! servers.

use std::path::PathBuf;

use clap::Parser;
#[cfg(feature = "api")]
use nano_dns_api::ApiServer;
use nano_dns_core::config::{self, Config, DEFAULT_CONFIG_FILE, Features};
use nano_dns_core::error::Result;
use nano_dns_core::runtime;
use nano_dns_protocol::DnsServer;
#[cfg(feature = "web")]
use nano_dns_web::WebServer;
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

    runtime::run(run_servers(config))
}

/// Start all configured servers and stop them together on shutdown.
async fn run_servers(config: Config) -> Result<()> {
    info!(instance = %config.general.instance_name, "NanoDNS started");
    let mut server = DnsServer::bind(&config).await?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        runtime::shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    #[cfg(feature = "api")]
    let api = if config.api.enabled {
        Some(ApiServer::bind(&config, server.stats_sink()).await?)
    } else {
        None
    };

    #[cfg(feature = "web")]
    let web = if config.web.enabled {
        Some(WebServer::bind(&config, server.stats_sink()).await?)
    } else {
        None
    };

    #[cfg(feature = "api")]
    let api_rx = shutdown_rx.clone();
    #[cfg(feature = "api")]
    let api_task = async {
        match api {
            Some(api) => api.serve_with_signal(wait_shutdown(api_rx)).await,
            None => Ok(()),
        }
    };
    #[cfg(not(feature = "api"))]
    let api_task = async { Ok::<(), nano_dns_core::error::Error>(()) };

    #[cfg(feature = "web")]
    let web_rx = shutdown_rx.clone();
    #[cfg(feature = "web")]
    let web_task = async {
        match web {
            Some(web) => web.serve_with_signal(wait_shutdown(web_rx)).await,
            None => Ok(()),
        }
    };
    #[cfg(not(feature = "web"))]
    let web_task = async { Ok::<(), nano_dns_core::error::Error>(()) };

    let (dns_result, api_result, web_result) = tokio::join!(
        server.serve_with_signal(wait_shutdown(shutdown_rx)),
        api_task,
        web_task
    );
    dns_result?;
    api_result?;
    web_result?;
    Ok(())
}

/// Resolve when the shared shutdown flag is set.
async fn wait_shutdown(mut receiver: tokio::sync::watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
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
