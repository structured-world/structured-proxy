//! Running a [`ProxyService`] on a TCP listener: HTTP/1.1 and HTTP/2 on one
//! port, optionally behind TLS, with an optional cap on open connections.

use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tonic::transport::server::Connected;

use crate::service::{ConnectionInfo, ProxyService};
use crate::upstream::Upstream;

/// How long a client has to finish its TLS handshake before the connection is
/// dropped, so a stalled client holds neither a task nor a connection slot.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How [`serve_with`] runs its listener.
///
/// # Examples
///
/// ```
/// use structured_proxy::ServeOptions;
///
/// let options = ServeOptions::new().max_connections(10_000);
/// # let _ = options;
/// ```
#[derive(Clone, Debug, Default)]
pub struct ServeOptions {
    max_connections: Option<usize>,
    tls: Option<Arc<rustls::ServerConfig>>,
}

impl ServeOptions {
    /// Cleartext, with no limit on connections.
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve at most `max` connections at once: past it, the next connection
    /// is accepted when one closes, and waits in the listen backlog until then.
    ///
    /// # Panics
    ///
    /// `max` is zero, which would never accept a connection.
    #[must_use]
    pub fn max_connections(mut self, max: usize) -> Self {
        assert!(max > 0, "max_connections must be at least 1");
        self.max_connections = Some(max.min(Semaphore::MAX_PERMITS));
        self
    }

    /// Terminate TLS with `config`. Set its `alpn_protocols` to `h2` and
    /// `http/1.1` for gRPC clients to get HTTP/2; an empty list is filled in
    /// with those two. A client certificate the config verifies reaches a
    /// tonic upstream as `Request::peer_certs`.
    #[must_use]
    pub fn tls(mut self, mut config: rustls::ServerConfig) -> Self {
        if config.alpn_protocols.is_empty() {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        self.tls = Some(Arc::new(config));
        self
    }
}

/// Serve `service` on `listener` until the listener fails: cleartext HTTP/1.1
/// and HTTP/2 on the same port, so REST clients and native gRPC clients share
/// it. [`serve_with`] adds TLS and a connection limit.
///
/// # Errors
///
/// None so far: a failed accept is logged and retried, as a full file
/// descriptor table recovers when connections close.
///
/// # Examples
///
/// ```no_run
/// use structured_proxy::ProxyServer;
///
/// # async fn run() -> anyhow::Result<()> {
/// let grpc = tonic::service::Routes::default();
/// let service = ProxyServer::from_yaml_str("service:\n  name: demo\n")?.service(grpc)?;
/// let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
/// structured_proxy::serve(listener, service).await?;
/// # Ok(())
/// # }
/// ```
pub async fn serve<U: Upstream>(
    listener: TcpListener,
    service: ProxyService<U>,
) -> std::io::Result<()> {
    serve_with(listener, service, ServeOptions::new()).await
}

/// [`serve`] with `options`: TLS termination (mTLS when the config verifies
/// client certificates) and a cap on open connections. Each connection's
/// service gets its peer, and behind TLS its client certificates, through
/// [`ProxyService::for_connection`]. The TLS handshake runs in the
/// connection's own task, so a slow client does not hold up the others.
///
/// # Errors
///
/// See [`serve`].
///
/// # Examples
///
/// ```no_run
/// use structured_proxy::{ProxyServer, ServeOptions};
///
/// # async fn run(tls: rustls::ServerConfig) -> anyhow::Result<()> {
/// let service = ProxyServer::from_yaml_str("service:\n  name: demo\n")?
///     .service(tonic::service::Routes::default())?;
/// let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
/// let options = ServeOptions::new().tls(tls).max_connections(10_000);
/// structured_proxy::serve_with(listener, service, options).await?;
/// # Ok(())
/// # }
/// ```
pub async fn serve_with<U: Upstream>(
    listener: TcpListener,
    service: ProxyService<U>,
    options: ServeOptions,
) -> std::io::Result<()> {
    let slots = options
        .max_connections
        .map(|max| Arc::new(Semaphore::new(max)));
    let acceptor = options.tls.map(tokio_rustls::TlsAcceptor::from);
    loop {
        // The slot is taken before the accept, so a full server leaves new
        // connections in the kernel's backlog instead of accepting and
        // dropping them.
        let slot = match &slots {
            Some(slots) => Some(
                slots
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("the connection semaphore is never closed"),
            ),
            None => None,
        };
        let tcp = match listener.accept().await {
            Ok((tcp, _)) => tcp,
            Err(error) => {
                accept_failed(error).await;
                continue;
            }
        };
        let service = service.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            // Held for the connection's life.
            let _slot = slot;
            // Small gRPC frames and REST answers are latency-bound.
            if let Err(error) = tcp.set_nodelay(true) {
                tracing::debug!(%error, "cannot set TCP_NODELAY");
            }
            match acceptor {
                None => {
                    let service = service.for_connection(tcp.connect_info());
                    serve_connection(tcp, service).await;
                }
                Some(acceptor) => {
                    let stream =
                        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
                            .await
                        {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(error)) => {
                                tracing::debug!(%error, "TLS handshake failed");
                                return;
                            }
                            Err(_) => {
                                tracing::debug!("TLS handshake timed out");
                                return;
                            }
                        };
                    let service =
                        service.for_connection(ConnectionInfo::tls(stream.connect_info()));
                    serve_connection(stream, service).await;
                }
            }
        });
    }
}

/// HTTP/1.1 or HTTP/2, whichever the client speaks, on one connection.
async fn serve_connection<U, I>(io: I, service: ProxyService<U>)
where
    U: Upstream,
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let served = Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(io), TowerToHyperService::new(service))
        .await;
    if let Err(error) = served {
        tracing::debug!(%error, "connection ended");
    }
}

/// A failed accept: a connection the client gave up on is skipped; anything
/// else (a full file descriptor table) is logged and retried a second later,
/// the pause that lets open connections close.
async fn accept_failed(error: std::io::Error) {
    use std::io::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::error!(%error, "accepting a connection failed; retrying in 1s");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[cfg(test)]
mod tests;
