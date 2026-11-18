//! Generic, dependency-light HTTP/1.1 server for local management interfaces.
//!
//! One request per connection, `GET`-friendly, no body parsing and no
//! streaming. Handlers are plain functions over shared state, so callers own
//! routing, authentication and response construction.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info};

use crate::error::HttpError;

/// Maximum bytes accepted for the request head (request line plus headers).
const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Maximum time spent waiting for the complete request head.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum number of header lines accepted.
const MAX_HEADERS: usize = 32;

/// A parsed HTTP request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// HTTP method, upper case as sent by the client.
    pub method: String,
    /// Request target, usually a path with an optional query string.
    pub path: String,
    headers: HashMap<String, String>,
}

impl Request {
    /// Build a request with no headers, useful for handler tests.
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: HashMap::new(),
        }
    }

    /// Look up a header by its case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// Path component without the query string.
    pub fn route_path(&self) -> &str {
        self.path.split('?').next().unwrap_or_default()
    }
}

/// An HTTP response with an arbitrary byte body.
#[derive(Debug, Clone)]
pub struct Response {
    /// Numeric status code.
    pub status: u16,
    /// Value of the `Content-Type` header.
    pub content_type: &'static str,
    /// Raw response body.
    pub body: Vec<u8>,
    /// Additional headers appended before the blank line.
    pub extra_headers: Vec<(&'static str, &'static str)>,
}

impl Response {
    /// Build a JSON response from any serializable value.
    pub fn json<T: serde::Serialize>(status: u16, value: T) -> Result<Self, HttpError> {
        let body = serde_json::to_vec(&value).map_err(HttpError::Encode)?;
        Ok(Self {
            status,
            content_type: "application/json; charset=utf-8",
            body,
            extra_headers: Vec::new(),
        })
    }

    /// Build an HTML response from a UTF-8 string.
    pub fn html(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/html; charset=utf-8",
            body: body.into().into_bytes(),
            extra_headers: Vec::new(),
        }
    }

    /// Build a plain-text response.
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into().into_bytes(),
            extra_headers: Vec::new(),
        }
    }

    /// Append an extra response header.
    pub fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.extra_headers.push((name, value));
        self
    }

    fn reason(&self) -> &'static str {
        match self.status {
            200 => "OK",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }
}

/// Handler invoked for every parsed request.
///
/// `peer` is the accepted socket address; callers must derive client identity
/// from it rather than from request headers.
pub type Handler<S> = dyn Fn(&Request, IpAddr, &S) -> Response + Send + Sync + 'static;

/// A bound HTTP listener dispatching to a shared handler and state.
pub struct HttpServer<S> {
    listener: TcpListener,
    state: Arc<S>,
    handler: Arc<Handler<S>>,
    label: &'static str,
}

impl<S> HttpServer<S>
where
    S: Send + Sync + 'static,
{
    /// Bind an address and install a handler.
    pub async fn bind(
        address: SocketAddr,
        state: Arc<S>,
        handler: impl Fn(&Request, IpAddr, &S) -> Response + Send + Sync + 'static,
        label: &'static str,
    ) -> Result<Self, HttpError> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|source| HttpError::Bind { address, source })?;
        let local = listener
            .local_addr()
            .map_err(|source| HttpError::Bind { address, source })?;
        info!(%local, label, "HTTP listener bound");
        Ok(Self {
            listener,
            state,
            handler: Arc::new(handler),
            label,
        })
    }

    /// Accept connections until a shutdown signal resolves.
    pub async fn serve_with_signal<F>(self, signal: F) -> Result<(), HttpError>
    where
        F: Future<Output = ()>,
    {
        tokio::select! {
            result = self.serve() => result,
            _ = signal => {
                info!(label = self.label, "HTTP server shutting down");
                Ok(())
            }
        }
    }

    /// Bound local address, useful for tests and diagnostics.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept and handle connections indefinitely.
    async fn serve(&self) -> Result<(), HttpError> {
        loop {
            let (stream, peer) = self.listener.accept().await.map_err(HttpError::Accept)?;
            let state = Arc::clone(&self.state);
            let handler = Arc::clone(&self.handler);
            tokio::spawn(async move {
                if let Err(error) = handle_connection(stream, peer, state, handler).await {
                    debug!(%peer, %error, "HTTP connection ended with an error");
                }
            });
        }
    }
}

/// Read one request, dispatch to the handler and write the response.
async fn handle_connection<S>(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<S>,
    handler: Arc<Handler<S>>,
) -> Result<(), HttpError> {
    let request = match read_request(&mut stream).await {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(error) => {
            debug!(%peer, %error, "malformed HTTP request");
            let response = Response::text(400, "Bad Request").with_header("Connection", "close");
            return write_response(&mut stream, &response).await;
        }
    };

    let response = handler(&request, peer.ip(), &state);
    write_response(&mut stream, &response).await
}

/// Read and parse one request head.
async fn read_request(stream: &mut TcpStream) -> Result<Option<Request>, HttpError> {
    let head = read_head(stream).await?;
    let Some(head) = head else {
        return Ok(None);
    };
    parse_request(&head).map(Some)
}

/// Read bytes until the header terminator or the size limit is reached.
async fn read_head(stream: &mut TcpStream) -> Result<Option<Vec<u8>>, HttpError> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        let read = timeout(READ_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| HttpError::InvalidRequest("read timed out"))?
            .map_err(HttpError::Read)?;
        if read == 0 {
            return if buffer.is_empty() {
                Ok(None)
            } else {
                Ok(Some(buffer))
            };
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_HEAD_BYTES {
            return Err(HttpError::InvalidRequest("request head too large"));
        }
        if find_subslice(&buffer, b"\r\n\r\n").is_some() {
            return Ok(Some(buffer));
        }
    }
}

/// Parse a request head into its method, path and headers.
fn parse_request(head: &[u8]) -> Result<Request, HttpError> {
    let text = std::str::from_utf8(head)
        .map_err(|_| HttpError::InvalidRequest("request head is not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(HttpError::InvalidRequest("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(HttpError::InvalidRequest("missing method"))?;
    let path = parts
        .next()
        .ok_or(HttpError::InvalidRequest("missing path"))?;
    let version = parts
        .next()
        .ok_or(HttpError::InvalidRequest("missing HTTP version"))?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpError::InvalidRequest("unsupported HTTP version"));
    }
    if parts.next().is_some() {
        return Err(HttpError::InvalidRequest("malformed request line"));
    }

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(HttpError::InvalidRequest("too many headers"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(HttpError::InvalidRequest("malformed header"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }

    Ok(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
    })
}

/// Write one response and close the connection.
pub async fn write_response(stream: &mut TcpStream, response: &Response) -> Result<(), HttpError> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n",
        response.status,
        response.reason(),
        response.content_type,
        response.body.len()
    );
    for (name, value) in &response.extra_headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(HttpError::Write)?;
    stream
        .write_all(&response.body)
        .await
        .map_err(HttpError::Write)?;
    stream.flush().await.map_err(HttpError::Write)?;
    Ok(())
}

/// Return the byte offset of `needle` in `haystack`, if present.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_request_with_headers() {
        let head = b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n";
        let request = parse_request(head).expect("request must parse");
        assert_eq!(request.method, "GET");
        assert_eq!(request.route_path(), "/api/v1/status");
        assert_eq!(request.header("authorization"), Some("Bearer secret"));
        assert_eq!(request.header("HOST"), None);
    }

    #[test]
    fn route_path_drops_query_string() {
        let head = b"GET /status?verbose=1 HTTP/1.1\r\n\r\n";
        let request = parse_request(head).expect("request must parse");
        assert_eq!(request.route_path(), "/status");
    }

    #[test]
    fn rejects_unsupported_version() {
        let head = b"GET / HTTP/2.0\r\n\r\n";
        assert!(parse_request(head).is_err());
    }

    #[test]
    fn finds_header_terminator() {
        let bytes = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nsome-body";
        assert_eq!(find_subslice(bytes, b"\r\n\r\n"), Some(23));
        assert_eq!(find_subslice(b"no terminator", b"\r\n\r\n"), None);
    }

    #[test]
    fn builds_json_and_html_responses() {
        let json = Response::json(200, serde_json::json!({"ok": true})).expect("json body");
        assert_eq!(json.content_type, "application/json; charset=utf-8");
        let html = Response::html(200, "<h1>NanoDNS</h1>");
        assert_eq!(html.content_type, "text/html; charset=utf-8");
        assert_eq!(html.body, b"<h1>NanoDNS</h1>");
    }
}
