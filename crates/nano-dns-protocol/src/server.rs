//! UDP/TCP DNS server lifecycle.

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};

use hickory_server::Server;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use nano_dns_core::config::{Config, ListenerConfig, ResolverMode};
use nano_dns_core::error::Result;
use nano_dns_core::model::DnsQuery;
use nano_dns_core::traits::Resolver;
use nano_dns_resolver::ForwardResolver;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};

use crate::error::ProtocolError;
use crate::handler::{NanoRequestHandler, RequestLimits};

/// TCP connection inactivity timeout.
const TCP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Outgoing response slots reserved per TCP connection.
const TCP_RESPONSE_BUFFER: usize = 128;

/// Owns all configured UDP/TCP DNS listeners.
pub struct DnsServer<R>
where
    R: Resolver<Query = DnsQuery> + 'static,
{
    server: Server<NanoRequestHandler<R>>,
}

impl DnsServer<ForwardResolver> {
    /// Bind and register every configured UDP/TCP listener.
    pub async fn bind(config: &Config) -> Result<Self> {
        if config.resolver.mode == ResolverMode::Recursive {
            return Err(ProtocolError::Server(
                "recursive mode is not implemented until Phase 6".to_owned(),
            )
            .into());
        }

        let clients = config.clients.values().cloned().collect();
        let limits = RequestLimits::from_config(&config.listeners);
        let resolver = ForwardResolver::new(&config.resolver)?;

        let mut server = Server::with_access(
            NanoRequestHandler::new(limits, clients, resolver),
            [],
            allowed_networks(config),
        );

        let mut registered = 0usize;
        for listener in &config.listeners.entries {
            registered += Self::bind_listener(&mut server, listener).await?;
        }

        if registered == 0 {
            return Err(ProtocolError::Server("no listeners were registered".to_owned()).into());
        }

        Ok(Self { server })
    }

    async fn bind_listener(
        server: &mut Server<NanoRequestHandler<ForwardResolver>>,
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
}

impl<R> DnsServer<R>
where
    R: Resolver<Query = DnsQuery> + 'static,
{
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

    /// Stop accepting new queries and wait for listener tasks to finish.
    pub async fn shutdown(&mut self) -> Result<()> {
        if let Err(error) = self.server.shutdown_gracefully().await {
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

    use nano_dns_core::config::Features;

    fn features() -> Features {
        Features {
            forward: true,
            recursive: false,
            blocker: true,
            sqlite: false,
            statistics: false,
            api: false,
            web: false,
            doh: false,
            dot: false,
            dnssec: false,
        }
    }

    #[test]
    fn empty_allow_list_defaults_to_loopback() {
        let mut config = Config::default();
        config.listeners.allowed_networks.clear();
        config.validate(&features()).expect("config must validate");

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
