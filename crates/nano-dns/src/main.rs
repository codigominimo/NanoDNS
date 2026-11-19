//! NanoDNS executable entry point.
//!
//! Loads configuration, starts UDP/TCP DNS listeners and the configured DoT,
//! DoH, REST API and web dashboard, then coordinates graceful shutdown across
//! all servers. Every capability is compiled in; the JSON configuration alone
//! decides which ones run.

use std::path::PathBuf;

use clap::Parser;
use nano_dns_api::ApiServer;
use nano_dns_core::config::{self, Config, DEFAULT_CONFIG_FILE};
use nano_dns_core::error::Result;
use nano_dns_core::runtime;
use nano_dns_protocol::DnsServer;
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

fn main() -> Result<()> {
    let args = Args::parse();
    let config = config::load(&args.config)?;
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

    let api = if config.api.enabled {
        Some(ApiServer::bind(&config, server.stats_sink()).await?)
    } else {
        None
    };

    let web = if config.web.enabled {
        Some(
            WebServer::bind_with_blocker(&config, server.stats_sink(), server.blocker_control())
                .await?,
        )
    } else {
        None
    };

    let api_rx = shutdown_rx.clone();
    let api_task = async {
        match api {
            Some(api) => api.serve_with_signal(wait_shutdown(api_rx)).await,
            None => Ok(()),
        }
    };

    let web_rx = shutdown_rx.clone();
    let web_task = async {
        match web {
            Some(web) => web.serve_with_signal(wait_shutdown(web_rx)).await,
            None => Ok(()),
        }
    };

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
}
