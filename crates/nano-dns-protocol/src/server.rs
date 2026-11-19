//! UDP/TCP DNS server lifecycle.

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::pin::Pin;
use std::sync::Arc;

use hickory_server::Server;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use nano_dns_blocker::DomainBlocker;
use nano_dns_cache::{CachingResolver, MemoryCache};
use nano_dns_core::blocker::BlockerControl;
use nano_dns_core::config::{Config, ListenerConfig, ResolverMode};
use nano_dns_core::error::Result;
use nano_dns_core::error::Result as CoreResult;
use nano_dns_core::model::StatsSnapshot;
use nano_dns_core::model::{DnsQuery, Response as CoreResponse};
use nano_dns_core::traits::{Policy, Resolver, StatsSink, Storage};
use nano_dns_resolver::ForwardResolver;
use nano_dns_resolver::RecursiveResolver;
use nano_dns_stats::StatsCollector;
use nano_dns_storage::SqliteStorage;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};

use crate::error::ProtocolError;
use crate::handler::{BlockSettings, NanoRequestHandler, RequestLimits};

/// TCP connection inactivity timeout.
const TCP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// TLS handshake budget for DoT and DoH connections.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Outgoing response slots reserved per TCP connection.
const TCP_RESPONSE_BUFFER: usize = 128;

/// Upstream resolver selected by the configured resolution mode.
pub enum UpstreamResolver {
    /// Forward mode.
    Forward(ForwardResolver),
    /// Recursive mode.
    Recursive(RecursiveResolver),
    /// DNSSEC-validating forward mode.
    Dnssec(nano_dns_resolver::DnssecResolver),
}

impl Resolver for UpstreamResolver {
    type Query = DnsQuery;
    type Future<'a> = Pin<Box<dyn Future<Output = CoreResult<CoreResponse>> + Send + 'a>>;

    fn resolve(
        &self,
        query: DnsQuery,
        context: &nano_dns_core::model::QueryContext,
    ) -> Self::Future<'_> {
        match self {
            Self::Forward(resolver) => resolver.resolve(query, context),
            Self::Recursive(resolver) => resolver.resolve(query, context),
            Self::Dnssec(resolver) => resolver.resolve(query, context),
        }
    }
}

/// Resolver type installed in the production server.
pub type PipelineResolver = CachingResolver<UpstreamResolver, MemoryCache>;

/// Owns all configured UDP/TCP DNS listeners.
pub struct DnsServer<R>
where
    R: Resolver<Query = DnsQuery> + 'static,
{
    server: Server<NanoRequestHandler<R>>,
    storage: Option<Arc<dyn Storage>>,
    stats: Option<Arc<dyn StatsSink>>,
    blocker: Option<Arc<dyn BlockerControl>>,
}

impl DnsServer<PipelineResolver> {
    /// Bind and register every configured UDP/TCP listener.
    pub async fn bind(config: &Config) -> Result<Self> {
        if config.resolver.dnssec && config.resolver.mode != ResolverMode::Forward {
            return Err(ProtocolError::Server(
                "DNSSEC validation requires resolver.mode = \"forward\"".to_owned(),
            )
            .into());
        }

        let clients: Vec<_> = config.clients.values().cloned().collect();
        let limits = RequestLimits::from_config(&config.listeners);
        let upstream = if config.resolver.dnssec {
            UpstreamResolver::Dnssec(nano_dns_resolver::DnssecResolver::new(&config.resolver)?)
        } else if config.resolver.mode == ResolverMode::Recursive {
            UpstreamResolver::Recursive(RecursiveResolver::new(&config.resolver)?)
        } else {
            UpstreamResolver::Forward(ForwardResolver::new(&config.resolver)?)
        };
        let resolver = if config.dns_cache.enabled {
            CachingResolver::new(upstream, MemoryCache::new(&config.dns_cache))
        } else {
            CachingResolver::passthrough(upstream)
        };

        // The runtime control can enable filtering later, so the policy always
        // exists. `blocker.enabled` is its initial state, not a build switch.
        let blocker = Arc::new(DomainBlocker::new(
            &config.blocker,
            &clients,
            config.policy_cache.enabled.then_some(&config.policy_cache),
        )?);
        let policy: Option<Arc<dyn Policy<Query = DnsQuery>>> = Some(blocker.clone());
        let blocker_control: Option<Arc<dyn BlockerControl>> = Some(blocker);
        let block = BlockSettings::from_config(&config.blocker);

        let storage: Option<Arc<dyn Storage>> = if config.storage.enabled {
            Some(Arc::new(SqliteStorage::open(&config.storage)?) as Arc<dyn Storage>)
        } else {
            None
        };

        let stats: Option<Arc<dyn StatsSink>> = if config.stats.enabled {
            Some(Arc::new(StatsCollector::new(&config.stats)) as Arc<dyn StatsSink>)
        } else {
            None
        };

        let mut server = Server::with_access(
            NanoRequestHandler::with_sinks(
                limits,
                clients,
                resolver,
                policy,
                block,
                storage.clone(),
                stats.clone(),
            ),
            [],
            allowed_networks(config),
        );

        let mut registered = 0usize;
        for listener in &config.listeners.entries {
            registered += Self::bind_listener(&mut server, listener).await?;
        }
        registered += Self::bind_dot_listeners(&mut server, config).await?;
        registered += Self::bind_doh_listeners(&mut server, config).await?;

        if registered == 0 {
            return Err(ProtocolError::Server("no listeners were registered".to_owned()).into());
        }

        Ok(Self {
            server,
            storage,
            stats,
            blocker: blocker_control,
        })
    }

    /// Register TLS listeners for every entry that opts into DoT.
    async fn bind_dot_listeners(
        server: &mut Server<NanoRequestHandler<PipelineResolver>>,
        config: &Config,
    ) -> Result<usize> {
        if !config.dot.enabled {
            return Ok(0);
        }
        let (Some(cert_path), Some(key_path)) = (
            config.dot.cert_path.as_deref(),
            config.dot.key_path.as_deref(),
        ) else {
            return Err(
                ProtocolError::Tls("DoT requires cert_path and key_path".to_owned()).into(),
            );
        };
        let resolver = crate::tls::cert_resolver(cert_path, key_path)?;
        let tls_config = Arc::new(
            hickory_server::server::default_tls_server_config(b"dot", resolver)
                .map_err(|error| ProtocolError::Tls(error.to_string()))?,
        );

        let mut registered = 0usize;
        for listener in &config.listeners.entries {
            if listener.dot {
                let address = SocketAddr::new(listener.address, config.dot.port);
                let tcp_listener = TcpListener::bind(address)
                    .await
                    .map_err(|source| ProtocolError::Bind { address, source })?;
                info!(%address, transport = "dot", "DNS listener bound");
                server
                    .register_tls_listener_with_tls_config(
                        tcp_listener,
                        TLS_HANDSHAKE_TIMEOUT,
                        Arc::clone(&tls_config),
                    )
                    .map_err(|error| ProtocolError::Tls(error.to_string()))?;
                registered += 1;
            }
        }
        Ok(registered)
    }

    /// Register HTTP/2 TLS listeners for every entry that opts into DoH.
    async fn bind_doh_listeners(
        server: &mut Server<NanoRequestHandler<PipelineResolver>>,
        config: &Config,
    ) -> Result<usize> {
        if !config.doh.enabled {
            return Ok(0);
        }
        let (Some(cert_path), Some(key_path)) = (
            config.doh.cert_path.as_deref(),
            config.doh.key_path.as_deref(),
        ) else {
            return Err(
                ProtocolError::Tls("DoH requires cert_path and key_path".to_owned()).into(),
            );
        };
        let resolver = crate::tls::cert_resolver(cert_path, key_path)?;

        let mut registered = 0usize;
        for listener in &config.listeners.entries {
            if listener.doh {
                let address = SocketAddr::new(listener.address, config.doh.port);
                let tcp_listener = TcpListener::bind(address)
                    .await
                    .map_err(|source| ProtocolError::Bind { address, source })?;
                info!(%address, transport = "doh", "DNS listener bound");
                server
                    .register_https_listener(
                        tcp_listener,
                        TLS_HANDSHAKE_TIMEOUT,
                        Arc::clone(&resolver),
                        None,
                        config.doh.path.clone(),
                    )
                    .map_err(|error| ProtocolError::Tls(error.to_string()))?;
                registered += 1;
            }
        }
        Ok(registered)
    }
}

impl<R> DnsServer<R>
where
    R: Resolver<Query = DnsQuery> + 'static,
{
    async fn bind_listener(
        server: &mut Server<NanoRequestHandler<R>>,
        listener: &ListenerConfig,
    ) -> Result<usize> {
        let mut registered = 0usize;

        if listener.port_udp != 0 {
            let address = SocketAddr::new(listener.address, listener.port_udp);
            let socket = StdUdpSocket::bind(address)
                .map_err(|source| ProtocolError::Bind { address, source })?;
            socket
                .set_nonblocking(true)
                .map_err(|source| ProtocolError::Bind { address, source })?;
            let socket = UdpSocket::from_std(socket)
                .map_err(|source| ProtocolError::Bind { address, source })?;
            info!(%address, transport = "udp", "DNS listener bound");
            server.register_socket(socket);
            registered += 1;
        }

        if listener.port_tcp != 0 {
            let address = SocketAddr::new(listener.address, listener.port_tcp);
            let tcp_listener = TcpListener::bind(address)
                .await
                .map_err(|source| ProtocolError::Bind { address, source })?;
            info!(%address, transport = "tcp", "DNS listener bound");
            server.register_listener(tcp_listener, TCP_TIMEOUT, TCP_RESPONSE_BUFFER);
            registered += 1;
        }

        Ok(registered)
    }

    /// Shared statistics sink, when statistics collection is enabled.
    pub fn stats_sink(&self) -> Option<Arc<dyn StatsSink>> {
        self.stats.clone()
    }

    /// Current statistics snapshot, when statistics collection is enabled.
    pub fn stats_snapshot(&self) -> Option<StatsSnapshot> {
        self.stats.as_ref().map(|stats| stats.snapshot())
    }

    /// Shared runtime blocker control.
    pub fn blocker_control(&self) -> Option<Arc<dyn BlockerControl>> {
        self.blocker.clone()
    }

    /// Run until every listener task finishes.
    pub async fn run(&mut self) -> Result<()> {
        self.server
            .block_until_done()
            .await
            .map_err(|error| ProtocolError::Server(error.to_string()).into())
    }

    /// Serve queries until an external shutdown signal arrives, then stop
    /// accepting new queries and wait for in-flight work to finish.
    pub async fn serve_with_signal<S>(&mut self, signal: S) -> Result<()>
    where
        S: Future<Output = ()>,
    {
        enum Reason {
            ListenersDone,
            ServerToken,
            ExternalSignal,
        }

        let server_token = self.server.shutdown_token().clone();
        let reason = tokio::select! {
            result = self.server.block_until_done() => {
                result.map_err(|error| ProtocolError::Server(error.to_string()))?;
                Reason::ListenersDone
            }
            _ = server_token.cancelled() => Reason::ServerToken,
            _ = signal => Reason::ExternalSignal,
        };

        match reason {
            Reason::ListenersDone => Ok(()),
            Reason::ServerToken | Reason::ExternalSignal => self.shutdown().await,
        }
    }

    /// Stop accepting new queries, flush persistence and wait for listeners.
    pub async fn shutdown(&mut self) -> Result<()> {
        let shutdown = self.server.shutdown_gracefully().await;

        if let Some(storage) = &self.storage {
            let storage = Arc::clone(storage);
            match tokio::task::spawn_blocking(move || storage.flush()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "cannot flush query history on shutdown"),
                Err(error) => warn!(%error, "persistence flush task failed"),
            }
        }

        if let Err(error) = shutdown {
            warn!(%error, "DNS server did not shut down cleanly");
            return Err(ProtocolError::Shutdown(error.to_string()).into());
        }
        Ok(())
    }
}

/// Return the configured allow-list, defaulting to loopback only.
fn allowed_networks(config: &Config) -> Vec<IpNet> {
    if config.listeners.allowed_networks.is_empty() {
        vec![
            IpNet::V4(Ipv4Net::from(Ipv4Addr::LOCALHOST)),
            IpNet::V6(Ipv6Net::from(Ipv6Addr::LOCALHOST)),
        ]
    } else {
        config.listeners.allowed_networks.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn empty_allow_list_defaults_to_loopback() {
        let mut config = Config::default();
        config.listeners.allowed_networks.clear();
        config.validate().expect("config must validate");

        let networks = allowed_networks(&config);
        assert_eq!(networks.len(), 2);
        assert!(
            networks
                .iter()
                .any(|network| network.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)))
        );
        assert!(
            networks
                .iter()
                .any(|network| network.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)))
        );
    }

    #[test]
    fn configured_allow_list_is_preserved() {
        let mut config = Config::default();
        let network = IpNet::V4(Ipv4Net::from(Ipv4Addr::new(192, 168, 1, 0)));
        config.listeners.allowed_networks = vec![network];
        assert_eq!(allowed_networks(&config), vec![network]);
    }
}
