//! Async runtime setup and graceful shutdown support.

use std::future::Future;

use tokio::signal;
use tracing::info;

use crate::config::Config;
use crate::error::{Error, Result};

/// Guard returned by [`install`]. Dropping it stops the tracing subscriber.
pub struct TracingGuard {
    _guard: tracing::subscriber::DefaultGuard,
}

/// Install a global-compatible tracing subscriber for the process.
///
/// The returned guard must be kept alive for the whole application lifetime.
pub fn install(config: &Config) -> TracingGuard {
    let subscriber = tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&config.general.log_level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    info!(instance = %config.general.instance_name, "NanoDNS runtime initialized");
    TracingGuard { _guard: guard }
}

/// Wait for a shutdown request from the operating system.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "cannot install SIGTERM handler; using Ctrl+C only");
                let _ = signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = signal::ctrl_c() => info!("shutdown requested via Ctrl+C"),
            _ = sigterm.recv() => info!("shutdown requested via SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
        info!("shutdown requested via Ctrl+C");
    }
}

/// Run a future on a multi-thread Tokio runtime.
///
/// Long-lived components own their shutdown logic and call
/// [`shutdown_signal`] when they need to react to operating system signals.
pub fn run<F>(future: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_name("nano-dns-worker")
        .enable_all()
        .build()
        .map_err(|error| Error::Runtime(format!("cannot create Tokio runtime: {error}")))?;

    runtime.block_on(future)
}
