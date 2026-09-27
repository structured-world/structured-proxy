//! The proxy as one tower service: native gRPC to the upstream, everything
//! else to the proxy's routes, and what no route answers to a fallback.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::extract::connect_info::ConnectInfo;
use axum::response::IntoResponse;
use axum::routing::future::RouteFuture;
use axum::serve::IncomingStream;
use bytes::Bytes;
use pin_project_lite::pin_project;
use tonic::transport::server::TcpConnectInfo;
use tower::Service;

use crate::upstream::{is_grpc, BoxError, PassThrough, Upstream};

/// The proxy as a tower service, built by
/// [`ProxyServer::service`](crate::ProxyServer::service).
///
/// A request with a gRPC or gRPC-Web content type goes to the upstream as it
/// arrived, so one listener carries REST and native gRPC. Every other request
/// goes to the proxy's routes (transcoded RPCs, health, metrics, OpenAPI, OIDC,
/// forward-auth, extra routes) behind the proxy's middleware. A request no
/// route matches is answered `404`, or handed to the service set with
/// [`with_fallback`](Self::with_fallback), untouched by that middleware.
///
/// Serve it with [`serve`], or hand it to any server that takes
/// a tower service of `http` types. Native gRPC needs HTTP/2 on that server.
///
/// # Examples
///
/// ```
/// use structured_proxy::ProxyServer;
///
/// # fn build() -> anyhow::Result<()> {
/// // The embedder's own tonic services, called in process.
/// let grpc = tonic::service::Routes::default();
/// let service = ProxyServer::from_yaml_str("service:\n  name: demo\n")?.service(grpc)?;
/// # let _ = service;
/// # Ok(())
/// # }
/// # build().unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct ProxyService<U> {
    upstream: U,
    routes: axum::Router,
    /// The connection a served request arrived on, set by [`serve`].
    connection: Option<Connection>,
}

/// The two ends of an accepted connection.
#[derive(Clone, Copy, Debug)]
struct Connection {
    local: Option<SocketAddr>,
    remote: SocketAddr,
}

impl<U: Upstream> ProxyService<U> {
    pub(crate) fn new(upstream: U, routes: axum::Router) -> Self {
        Self {
            upstream,
            routes,
            connection: None,
        }
    }

    /// Hand the requests no route matches to `fallback` instead of answering
    /// `404`: an embedder's own REST routes, a static site, anything that is a
    /// tower service. The proxy's middleware does not see them.
    ///
    /// A request whose path a route answers but not with its method stays with
    /// the proxy (`405`), as does every gRPC request.
    #[must_use]
    pub fn with_fallback<F>(mut self, fallback: F) -> Self
    where
        F: Service<axum::extract::Request, Error = Infallible> + Clone + Send + Sync + 'static,
        F::Response: IntoResponse,
        F::Future: Send + 'static,
    {
        self.routes = self.routes.fallback_service(fallback);
        self
    }

    fn on_connection(&self, connection: Connection) -> Self {
        Self {
            upstream: self.upstream.clone(),
            routes: self.routes.clone(),
            connection: Some(connection),
        }
    }
}

impl<U, B> Service<http::Request<B>> for ProxyService<U>
where
    U: Upstream,
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Response = http::Response<axum::body::Body>;
    type Error = Infallible;
    type Future = ResponseFuture<U>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Readiness of the upstream is waited for per request, on its clone.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        if let Some(connection) = self.connection {
            // What axum extractors and a tonic handler read the peer from; a
            // server that set them already (an embedder's own axum app) keeps
            // its values.
            let extensions = request.extensions_mut();
            if extensions.get::<ConnectInfo<SocketAddr>>().is_none() {
                extensions.insert(ConnectInfo(connection.remote));
            }
            if extensions.get::<TcpConnectInfo>().is_none() {
                extensions.insert(TcpConnectInfo {
                    local_addr: connection.local,
                    remote_addr: Some(connection.remote),
                });
            }
        }
        let inner = if is_grpc(request.headers()) {
            Inner::Grpc {
                call: PassThrough::new(self.upstream.clone(), request.map(tonic::body::Body::new)),
            }
        } else {
            Inner::Routes {
                future: self.routes.call(request),
            }
        };
        ResponseFuture { inner }
    }
}

pin_project! {
    /// The response future of [`ProxyService`].
    pub struct ResponseFuture<U: Upstream> {
        #[pin]
        inner: Inner<U>,
    }
}

pin_project! {
    #[project = InnerProj]
    enum Inner<U: Upstream> {
        Routes {
            #[pin]
            future: RouteFuture<Infallible>,
        },
        Grpc {
            #[pin]
            call: PassThrough<U>,
        },
    }
}

impl<U: Upstream> Future for ResponseFuture<U> {
    type Output = Result<http::Response<axum::body::Body>, Infallible>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().inner.project() {
            InnerProj::Routes { future } => future.poll(cx),
            InnerProj::Grpc { call } => call.poll(cx),
        }
    }
}

/// Serve `service` on `listener` until the listener fails: HTTP/1.1 and
/// HTTP/2 (with or without TLS in front, cleartext here) on the same port, so
/// REST clients and native gRPC clients share it. Each request carries the
/// connection's peer, for the proxy's own middleware (`ConnectInfo`) and for a
/// tonic handler upstream (`Request::remote_addr`).
///
/// # Errors
///
/// The listener's own I/O failure.
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
    listener: tokio::net::TcpListener,
    service: ProxyService<U>,
) -> std::io::Result<()> {
    axum::serve(listener, PerConnection(service)).await
}

/// Makes the [`ProxyService`] of each accepted connection.
struct PerConnection<U>(ProxyService<U>);

impl<U: Upstream> Service<IncomingStream<'_, tokio::net::TcpListener>> for PerConnection<U> {
    type Response = ProxyService<U>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<ProxyService<U>, Infallible>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, stream: IncomingStream<'_, tokio::net::TcpListener>) -> Self::Future {
        std::future::ready(Ok(self.0.on_connection(Connection {
            local: stream.io().local_addr().ok(),
            remote: *stream.remote_addr(),
        })))
    }
}

#[cfg(test)]
mod tests;
