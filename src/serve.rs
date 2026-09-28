//! Running a [`ProxyService`] on a TCP listener: HTTP/1.1 and HTTP/2 on one
//! port, optionally behind TLS, with an optional cap on open connections and
//! a graceful shutdown.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulConnection;
use hyper_util::service::TowerToHyperService;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tonic::transport::server::Connected;

use crate::service::{ConnectionInfo, ProxyService};
use crate::upstream::Upstream;

mod idle;

/// How [`serve_with`] runs its listener.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use structured_proxy::ServeOptions;
///
/// let options = ServeOptions::new()
///     .max_connections(10_000)
///     .idle_timeout(Some(Duration::from_secs(120)));
/// # let _ = options;
/// ```
#[derive(Clone, Debug)]
pub struct ServeOptions {
    max_connections: Option<usize>,
    tls: Option<Arc<rustls::ServerConfig>>,
    idle_timeout: Option<Duration>,
    header_read_timeout: Duration,
    tls_handshake_timeout: Duration,
    drain_timeout: Option<Duration>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            max_connections: None,
            tls: None,
            idle_timeout: Some(Duration::from_secs(60)),
            header_read_timeout: Duration::from_secs(30),
            tls_handshake_timeout: Duration::from_secs(10),
            // Below the 30 s a Kubernetes pod gets after SIGTERM by default,
            // so the drain ends before the kill.
            drain_timeout: Some(Duration::from_secs(25)),
        }
    }
}

impl ServeOptions {
    /// Cleartext, with no limit on connections; a connection idle for 60 s is
    /// closed, a client gets 30 s to send the headers of an HTTP/1.1 request
    /// and 10 s to finish a TLS handshake, and a shutdown waits at most 25 s
    /// for open connections.
    pub fn new() -> Self {
        Self::default()
    }

    /// How long a shutdown ([`serve_with_shutdown`]) waits for the
    /// connections still open to finish what they serve; the ones open after
    /// it are closed. `None` waits for all of them.
    #[must_use]
    pub fn drain_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Close a connection that has had no request in flight for `timeout`
    /// (gracefully: HTTP/2 gets a GOAWAY); `None` keeps idle connections
    /// open. A request counts until its response body ends, so a stream keeps
    /// its connection. Without it an idle client holds a
    /// [`max_connections`](Self::max_connections) slot for as long as it likes.
    /// A connection upgraded to another protocol (a WebSocket in a fallback)
    /// leaves HTTP and this timeout with it; it keeps its slot until it
    /// closes.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// How long an HTTP/1.1 client has to send a request's headers, so a
    /// client that trickles them in holds no connection for long.
    #[must_use]
    pub fn header_read_timeout(mut self, timeout: Duration) -> Self {
        self.header_read_timeout = timeout;
        self
    }

    /// How long a client has to finish its TLS handshake before the
    /// connection is dropped, so a stalled client holds neither a task nor a
    /// connection slot.
    #[must_use]
    pub fn tls_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.tls_handshake_timeout = timeout;
        self
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

/// Serve `service` on `listener`: cleartext HTTP/1.1 and HTTP/2 on the same
/// port, so REST clients and native gRPC clients share it. It runs until the
/// future is dropped, which closes every connection; [`serve_with_shutdown`]
/// stops gracefully, and [`serve_with`] adds TLS and a connection limit.
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
    serve_with_shutdown(listener, service, options, std::future::pending()).await
}

/// [`serve_with`], until `signal` resolves; then a graceful shutdown. The
/// listening socket closes, so new connections are refused; a connection
/// still in its TLS handshake or waiting for its `max_connections` slot is
/// dropped; every open connection is asked to wind down (HTTP/2 gets a GOAWAY,
/// so its client opens no new streams; HTTP/1.1 closes after the response in
/// progress), and requests and streams in flight finish. The future resolves
/// once every connection has closed, or after
/// [`drain_timeout`](ServeOptions::drain_timeout), closing the ones still
/// open. Dropping it closes every connection at once.
///
/// A connection a fallback upgraded (a WebSocket) belongs to the fallback's
/// own task once upgraded, and closes when that task lets it go.
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
/// # async fn run() -> anyhow::Result<()> {
/// let service = ProxyServer::from_yaml_str("service:\n  name: demo\n")?
///     .service(tonic::service::Routes::default())?;
/// let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
/// let shutdown = async {
///     tokio::signal::ctrl_c().await.expect("the signal handler installs");
/// };
/// structured_proxy::serve_with_shutdown(listener, service, ServeOptions::new(), shutdown).await?;
/// # Ok(())
/// # }
/// ```
pub async fn serve_with_shutdown<U, F>(
    listener: TcpListener,
    service: ProxyService<U>,
    options: ServeOptions,
    signal: F,
) -> std::io::Result<()>
where
    U: Upstream,
    F: Future<Output = ()>,
{
    let slots = options
        .max_connections
        .map(|max| Arc::new(Semaphore::new(max)));
    let acceptor = options.tls.map(tokio_rustls::TlsAcceptor::from);
    let handshake_timeout = options.tls_handshake_timeout;
    let limits = ConnectionLimits {
        idle_timeout: options.idle_timeout,
        header_read_timeout: options.header_read_timeout,
    };
    // Tells every connection to wind down. The connections are this future's
    // own tasks, so dropping it ends them too.
    let (stop, stopping) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(signal);
    loop {
        // Finished connections leave the set, which holds only open ones.
        while connections.try_join_next().is_some() {}
        // The slot is taken before the accept, so a full server leaves new
        // connections in the kernel's backlog instead of accepting and
        // dropping them.
        let slot = tokio::select! {
            biased;
            () = &mut signal => break,
            slot = take_slot(slots.as_ref()) => slot,
        };
        let tcp = tokio::select! {
            biased;
            () = &mut signal => break,
            accepted = listener.accept() => match accepted {
                Ok((tcp, _)) => tcp,
                Err(error) => {
                    tokio::select! {
                        biased;
                        () = &mut signal => break,
                        () = accept_failed(error) => continue,
                    }
                }
            },
        };
        let service = service.clone();
        let acceptor = acceptor.clone();
        let stopping = stopping.clone();
        connections.spawn(async move {
            // Small gRPC frames and REST answers are latency-bound.
            if let Err(error) = tcp.set_nodelay(true) {
                tracing::debug!(%error, "cannot set TCP_NODELAY");
            }
            match acceptor {
                None => {
                    let service = service.for_connection(tcp.connect_info());
                    serve_connection(SlotIo { io: tcp, slot }, service, limits, stopping).await;
                }
                Some(acceptor) => {
                    // The slot is held through the handshake, then by the
                    // stream. A handshake still running at shutdown is not
                    // finished: the connection would only be closed again.
                    let handshake = tokio::time::timeout(handshake_timeout, acceptor.accept(tcp));
                    let stream = tokio::select! {
                        handshake = handshake => match handshake {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(error)) => {
                                tracing::debug!(%error, "TLS handshake failed");
                                return;
                            }
                            Err(_) => {
                                tracing::debug!("TLS handshake timed out");
                                return;
                            }
                        },
                        () = stopped(stopping.clone()) => return,
                    };
                    let service =
                        service.for_connection(ConnectionInfo::tls(stream.connect_info()));
                    serve_connection(SlotIo { io: stream, slot }, service, limits, stopping).await;
                }
            }
        });
    }
    // No new connections from here: the listening socket closes, then the
    // open connections wind down.
    drop(listener);
    stop.send_replace(true);
    let drained = async { while connections.join_next().await.is_some() {} };
    match options.drain_timeout {
        None => drained.await,
        Some(timeout) => {
            if tokio::time::timeout(timeout, drained).await.is_err() {
                tracing::warn!(
                    open = connections.len(),
                    "shutdown drain timed out; closing the connections still open"
                );
                connections.shutdown().await;
            }
        }
    }
    Ok(())
}

/// A `max_connections` slot, or none without a limit.
async fn take_slot(slots: Option<&Arc<Semaphore>>) -> Option<OwnedSemaphorePermit> {
    match slots {
        Some(slots) => Some(
            Arc::clone(slots)
                .acquire_owned()
                .await
                .expect("the connection semaphore is never closed"),
        ),
        None => None,
    }
}

/// Resolves once the server shuts down.
async fn stopped(mut stopping: watch::Receiver<bool>) {
    // A closed channel means the serve future is gone: stop as well.
    stopping.wait_for(|stop| *stop).await.ok();
}

pin_project! {
    /// A connection's IO holding its `max_connections` slot for as long as
    /// the socket is open. hyper hands the IO of an upgraded connection (a
    /// WebSocket in a fallback) to the upgrading service and finishes the
    /// connection future, so the slot has to live with the IO, not the task.
    struct SlotIo<I> {
        #[pin]
        io: I,
        slot: Option<OwnedSemaphorePermit>,
    }
}

impl<I: AsyncRead> AsyncRead for SlotIo<I> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().io.poll_read(cx, buf)
    }
}

impl<I: AsyncWrite> AsyncWrite for SlotIo<I> {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.project().io.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().io.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().io.poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        self.project().io.poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

/// The timeouts every connection is served under.
#[derive(Clone, Copy, Debug)]
struct ConnectionLimits {
    idle_timeout: Option<Duration>,
    header_read_timeout: Duration,
}

/// HTTP/1.1 or HTTP/2, whichever the client speaks, on one connection, until
/// it closes, idles out or the server shuts down.
async fn serve_connection<U, I>(
    io: I,
    service: ProxyService<U>,
    limits: ConnectionLimits,
    stopping: watch::Receiver<bool>,
) where
    U: Upstream,
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = Builder::new(TokioExecutor::new());
    // hyper times nothing without a timer: its own default header read
    // timeout is dropped with a warning.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);
    builder.http2().timer(TokioTimer::new());
    let served = match limits.idle_timeout {
        None => {
            let connection = builder.serve_connection_with_upgrades(
                TokioIo::new(io),
                TowerToHyperService::new(service),
            );
            drive(connection, std::future::pending(), stopping).await
        }
        Some(timeout) => {
            let activity = Arc::new(idle::Activity::default());
            let service = idle::Tracked {
                inner: service,
                activity: Arc::clone(&activity),
            };
            let connection = builder.serve_connection_with_upgrades(
                TokioIo::new(io),
                TowerToHyperService::new(service),
            );
            drive(connection, activity.idle_for(timeout), stopping).await
        }
    };
    if let Err(error) = served {
        tracing::debug!(%error, "connection ended");
    }
}

/// Serve `connection` until it ends; when `idle` resolves or the server
/// shuts down first, it is asked to wind down (HTTP/2 gets a GOAWAY, HTTP/1.1
/// closes after the request in progress) and served until it has.
async fn drive<C: GracefulConnection>(
    connection: C,
    idle: impl Future<Output = ()>,
    stopping: watch::Receiver<bool>,
) -> Result<(), C::Error> {
    tokio::pin!(connection);
    tokio::select! {
        served = connection.as_mut() => served,
        () = idle => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
        () = stopped(stopping) => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
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
