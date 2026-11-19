//! NanoDNS executable entry point.
//!
//! Loads configuration, starts UDP/TCP DNS listeners and the configured DoT,
//! DoH, REST API and web dashboard, then coordinates graceful shutdown across
//! all servers. Every capability is compiled in; the JSON configuration alone
//! decides which ones run. The same binary can also install and manage itself
//! as a Windows or systemd service.

mod service;

use std::future::Future;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
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
    #[arg(short, long, value_name = "PATH", default_value = DEFAULT_CONFIG_FILE, global = true)]
    config: PathBuf,

    /// Parse the configuration and exit without starting the runtime.
    #[arg(long)]
    check_config: bool,

    /// Internal flag used by the Windows service control manager.
    #[arg(long, hide = true)]
    service: bool,

    /// Service management command. Without one, NanoDNS runs in the console.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Service lifecycle subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Install NanoDNS as a Windows or systemd service.
    InstallService,
    /// Remove the NanoDNS service.
    UninstallService {
        /// Also delete the configuration and data directories.
        #[arg(long)]
        purge: bool,
    },
    /// Start the installed service.
    Start,
    /// Stop the installed service.
    Stop,
    /// Show the installed service status.
    Status,
    /// Print the systemd unit without installing anything.
    #[cfg(unix)]
    PrintUnit,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.service {
        return service::run_service_mode(&args.config);
    }

    if let Some(command) = &args.command {
        return match command {
            Command::InstallService => service::install(&args.config),
            Command::UninstallService { purge } => service::uninstall(*purge),
            Command::Start => service::start(),
            Command::Stop => service::stop(),
            Command::Status => service::status(),
            #[cfg(unix)]
            Command::PrintUnit => service::print_unit(&args.config),
        };
    }

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

    runtime::run(run_servers(config, runtime::shutdown_signal()))
}

/// Start all configured servers and stop them together on shutdown.
pub(crate) async fn run_servers<S>(config: Config, shutdown: S) -> Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    info!(instance = %config.general.instance_name, "NanoDNS started");
    let mut server = DnsServer::bind(&config).await?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
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
    use clap::CommandFactory;

    #[test]
    fn cli_defaults_to_standard_config_path() {
        let args = Args::try_parse_from(["nano-dns"]).expect("default args must parse");
        assert_eq!(args.config, PathBuf::from(DEFAULT_CONFIG_FILE));
        assert!(!args.check_config);
        assert!(!args.service);
        assert!(args.command.is_none());
    }

    #[test]
    fn cli_accepts_config_check_flag() {
        let args = Args::try_parse_from(["nano-dns", "--check-config"]).expect("args must parse");
        assert!(args.check_config);
    }

    #[test]
    fn cli_parses_every_service_subcommand() {
        for (input, expected) in [
            ("install-service", "InstallService"),
            ("uninstall-service", "UninstallService"),
            ("start", "Start"),
            ("stop", "Stop"),
            ("status", "Status"),
        ] {
            let args = Args::try_parse_from(["nano-dns", input])
                .unwrap_or_else(|error| panic!("{input} must parse: {error}"));
            let name = match args.command.expect("subcommand") {
                Command::InstallService => "InstallService",
                Command::UninstallService { .. } => "UninstallService",
                Command::Start => "Start",
                Command::Stop => "Stop",
                Command::Status => "Status",
                #[cfg(unix)]
                Command::PrintUnit => "PrintUnit",
            };
            assert_eq!(name, expected);
        }
    }

    #[test]
    fn cli_accepts_global_config_before_and_after_subcommand() {
        let before = Args::try_parse_from(["nano-dns", "--config", "a.json", "status"])
            .expect("config before subcommand must parse");
        let after = Args::try_parse_from(["nano-dns", "status", "--config", "b.json"])
            .expect("config after subcommand must parse");
        assert_eq!(before.config, PathBuf::from("a.json"));
        assert_eq!(after.config, PathBuf::from("b.json"));
    }

    #[test]
    fn cli_accepts_purge_on_uninstall() {
        let args = Args::try_parse_from(["nano-dns", "uninstall-service", "--purge"])
            .expect("purge must parse");
        assert!(matches!(
            args.command,
            Some(Command::UninstallService { purge: true })
        ));
    }

    #[test]
    fn cli_hides_but_parses_the_internal_service_flag() {
        let args =
            Args::try_parse_from(["nano-dns", "--service"]).expect("service flag must parse");
        assert!(args.service);
        assert!(
            !Args::command()
                .render_help()
                .to_string()
                .contains("--service")
        );
    }
}
