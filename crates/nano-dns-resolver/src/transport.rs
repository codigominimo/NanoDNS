//! Shared UDP/TCP DNS exchange helpers.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::error::ResolverError;

/// Send one UDP query and decode the answer.
pub(crate) async fn exchange_udp(
    query_bytes: &[u8],
    address: SocketAddr,
    deadline: Duration,
    udp_payload: usize,
) -> Result<Message, ResolverError> {
    let bind_address = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_address)
        .await
        .map_err(|source| ResolverError::Io { address, source })?;
    socket
        .connect(address)
        .await
        .map_err(|source| ResolverError::Io { address, source })?;
    socket
        .send(query_bytes)
        .await
        .map_err(|source| ResolverError::Io { address, source })?;

    let mut buffer = vec![0u8; udp_payload];
    let len = timeout(deadline, socket.recv(&mut buffer))
        .await
        .map_err(|_| ResolverError::Timeout {
            address,
            timeout: deadline,
        })?
        .map_err(|source| ResolverError::Io { address, source })?;

    Message::from_vec(&buffer[..len]).map_err(|error| ResolverError::InvalidResponse {
        address,
        reason: error.to_string(),
    })
}

/// Send one length-prefixed TCP query and decode the answer.
pub(crate) async fn exchange_tcp(
    query_bytes: &[u8],
    address: SocketAddr,
    deadline: Duration,
) -> Result<Message, ResolverError> {
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|source| ResolverError::Io { address, source })?;

    let length = u16::try_from(query_bytes.len()).map_err(|_| ResolverError::InvalidResponse {
        address,
        reason: "query exceeds DNS TCP length prefix".to_owned(),
    })?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|source| ResolverError::Io { address, source })?;
    stream
        .write_all(query_bytes)
        .await
        .map_err(|source| ResolverError::Io { address, source })?;

    let mut length_buffer = [0u8; 2];
    timeout(deadline, stream.read_exact(&mut length_buffer))
        .await
        .map_err(|_| ResolverError::Timeout {
            address,
            timeout: deadline,
        })?
        .map_err(|source| ResolverError::Io { address, source })?;

    let mut buffer = vec![0u8; usize::from(u16::from_be_bytes(length_buffer))];
    timeout(deadline, stream.read_exact(&mut buffer))
        .await
        .map_err(|_| ResolverError::Timeout {
            address,
            timeout: deadline,
        })?
        .map_err(|source| ResolverError::Io { address, source })?;

    Message::from_vec(&buffer).map_err(|error| ResolverError::InvalidResponse {
        address,
        reason: error.to_string(),
    })
}

/// Exchange a query over UDP, retrying over TCP when the answer is truncated.
pub(crate) async fn exchange_with_truncation(
    query_bytes: &[u8],
    address: SocketAddr,
    deadline: Duration,
    udp_payload: usize,
) -> Result<Message, ResolverError> {
    match exchange_udp(query_bytes, address, deadline, udp_payload).await {
        Ok(message) if message.metadata.truncation => {
            tracing::debug!(%address, "UDP response truncated; retrying over TCP");
            exchange_tcp(query_bytes, address, deadline).await
        }
        result => result,
    }
}
