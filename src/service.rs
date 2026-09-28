//! The proxy as one tower service: native gRPC to the upstream, everything
//! else to the proxy's routes, and what no route answers to a fallback.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::connect_info::ConnectInfo;
use axum::response::IntoResponse;
use axum::routing::future::RouteFuture;
use axum::serve::IncomingStream;
use bytes::Bytes;
use pin_project_lite::pin_project;
use rustls::pki_types::CertificateDer;
use tonic::transport::server::{Connected, TcpConnectInfo};
use tower::{Layer, Service};
use tower_http::cors::{Cors, CorsLayer};

/// tonic's `TlsConnectInfo<TcpConnectInfo>`, the record its TLS server puts on
/// a request and `Request::peer_certs` reads. tonic exports the name only with
/// a TLS backend feature, so it is reached through the stream it describes.
pub type TlsConnectInfo =
    <tokio_rustls::server::TlsStream<tokio::net::TcpStream> as Connected>::ConnectInfo;

use crate::upstream::{
    grpc_protocol, is_grpc_web_preflight, BoxError, GrpcProtocol, PassThrough, Upstream,
};

/// The proxy as a tower service, built by
/// [`ProxyServer::service`](crate::ProxyServer::service).
///
/// A request with a gRPC or gRPC-Web content type goes to the upstream as it
/// arrived, so one listener carries REST and native gRPC; gRPC-Web is the
/// upstream's to translate (tonic-web's `GrpcWebLayer` around its services),
/// the proxy passes protocols through rather than converting them. A gRPC-Web
/// answer gets the proxy's CORS policy (`cors.grpc_web`), since the proxy
/// answers the browser's preflight for it. Every other request goes to the
/// proxy's routes (transcoded RPCs, health, metrics, OpenAPI, OIDC,
/// forward-auth, extra routes) behind the proxy's middleware. A request no
/// route matches is answered `404`, or handed to the service set with
/// [`with_fallback`](Self::with_fallback), untouched by that middleware.
///
/// Serve it with [`serve`], or hand it to any server that takes a tower
/// service of `http` types: your own TLS, a Unix socket, an existing hyper or
/// axum server. Native gRPC needs HTTP/2 on that server (ALPN `h2` next to
/// `http/1.1` behind TLS). Such a server tells the proxy which connection a
/// request came on with [`for_connection`](Self::for_connection).
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
    /// Binary and text gRPC-Web to the upstream under the CORS policy, each
    /// built once; `None` when the upstream owns CORS for gRPC-Web.
    grpc_web: Option<GrpcWebCors<U>>,
    /// The connection the requests arrive on, set per connection by the
    /// server.
    connection: Option<ConnectionInfo>,
}

/// gRPC-Web pass-through, one CORS-wrapped path per encoding.
#[derive(Clone, Debug)]
struct GrpcWebCors<U> {
    web: Cors<Forward<U>>,
    web_text: Cors<Forward<U>>,
}

/// Hands a request to the upstream in a known protocol, as a tower service so
/// a layer can wrap it.
#[derive(Clone, Debug)]
struct Forward<U> {
    upstream: U,
    protocol: GrpcProtocol,
}

impl<U: Upstream> Service<http::Request<tonic::body::Body>> for Forward<U> {
    type Response = http::Response<axum::body::Body>;
    type Error = Infallible;
    type Future = PassThrough<U>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // The upstream's readiness is waited for per request, on its clone.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        PassThrough::new(self.upstream.clone(), request, self.protocol)
    }
}

/// The connection requests arrive on, in the form a tonic server records it:
/// the TCP ends, and behind TLS the client's certificate chain.
///
/// Built from what [`Connected::connect_info`] returns for a
/// `tokio::net::TcpStream` (`ConnectionInfo::from`) or a
/// `tokio_rustls::server::TlsStream<TcpStream>` ([`ConnectionInfo::tls`]), so a
/// tonic handler behind the proxy reads it as it would behind tonic's own
/// server: `Request::remote_addr`, and `Request::peer_certs` for mTLS.
///
/// [`Connected::connect_info`]: tonic::transport::server::Connected::connect_info
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    tcp: TcpConnectInfo,
    tls: Option<TlsConnectInfo>,
}

impl ConnectionInfo {
    /// The client's address.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.tcp.remote_addr
    }

    /// The certificate chain the client presented over TLS, if it did.
    pub fn peer_certs(&self) -> Option<Arc<Vec<CertificateDer<'static>>>> {
        self.tls.as_ref().and_then(|tls| tls.peer_certs())
    }

    /// Put the connection where tonic reads it: [`TcpConnectInfo`] for
    /// `Request::remote_addr` and, behind TLS, [`TlsConnectInfo`] for
    /// `Request::peer_certs`.
    pub(crate) fn into_tonic_extensions(self, extensions: &mut http::Extensions) {
        extensions.insert(self.tcp);
        if let Some(tls) = self.tls {
            extensions.insert(tls);
        }
    }
}

impl From<TcpConnectInfo> for ConnectionInfo {
    fn from(tcp: TcpConnectInfo) -> Self {
        Self { tcp, tls: None }
    }
}

impl ConnectionInfo {
    /// A TLS connection, from what `connect_info` reports for a
    /// `tokio_rustls::server::TlsStream<TcpStream>`: the TCP ends and the
    /// client's certificate chain.
    pub fn tls(tls: TlsConnectInfo) -> Self {
        Self {
            tcp: tls.get_ref().clone(),
            tls: Some(tls),
        }
    }
}

impl<U: Upstream> ProxyService<U> {
    /// The service over `upstream` and `routes`; gRPC-Web answers carry
    /// `grpc_web_cors` when set.
    pub(crate) fn new(upstream: U, routes: axum::Router, grpc_web_cors: Option<CorsLayer>) -> Self {
        let grpc_web = grpc_web_cors.map(|cors| {
            let forward = |protocol| Forward {
                upstream: upstream.clone(),
                protocol,
            };
            GrpcWebCors {
                web: cors.layer(forward(GrpcProtocol::Web)),
                web_text: cors.layer(forward(GrpcProtocol::WebText)),
            }
        });
        Self {
            upstream,
            routes,
            grpc_web,
            connection: None,
        }
    }

    /// Hand the requests no route matches to `fallback` instead of answering
    /// `404`: an embedder's own REST routes, a static site, anything that is a
    /// tower service. The proxy's middleware does not see them.
    ///
    /// A request whose path a route answers but not with its method stays with
    /// the proxy (`405`), as does every gRPC request and every browser
    /// preflight for a gRPC-Web call, which follows the call it announces.
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

    /// This service for the requests of one connection: the proxy's
    /// middleware sees its client's address (rate limits by IP, the auth
    /// decider), and a tonic upstream in process reads it with
    /// `Request::remote_addr`, and its TLS client certificates with
    /// `Request::peer_certs`, for native and transcoded calls alike.
    ///
    /// A server of your own calls it once per accepted connection, with what
    /// tonic's [`Connected`] trait
    /// reports for the stream. [`serve`] does this itself.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use structured_proxy::ProxyServer;
    /// use tonic::transport::server::Connected;
    ///
    /// # async fn run() -> anyhow::Result<()> {
    /// let proxy = ProxyServer::from_yaml_str("service:\n  name: demo\n")?
    ///     .service(tonic::service::Routes::default())?;
    /// let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    /// let (tcp, _) = listener.accept().await?;
    /// // After a TLS handshake, the `TlsStream` reports the client's certificates too.
    /// let service = proxy.for_connection(tcp.connect_info());
    /// # let _ = service;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Without it, a request's peer comes from the `ConnectInfo` an outer
    /// axum server recorded, when there is one.
    #[must_use]
    pub fn for_connection(&self, connection: impl Into<ConnectionInfo>) -> Self {
        Self {
            upstream: self.upstream.clone(),
            routes: self.routes.clone(),
            grpc_web: self.grpc_web.clone(),
            connection: Some(connection.into()),
        }
    }

    /// The connection `request` came on: the one given to
    /// [`for_connection`](Self::for_connection), else the peer an outer axum
    /// server recorded as `ConnectInfo`, so the upstream sees the same client
    /// the proxy's middleware does.
    fn connection_of<B>(&self, request: &http::Request<B>) -> Option<ConnectionInfo> {
        if let Some(connection) = &self.connection {
            return Some(connection.clone());
        }
        let ConnectInfo(remote) = request.extensions().get::<ConnectInfo<SocketAddr>>()?;
        Some(ConnectionInfo::from(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(*remote),
        }))
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
        // A gRPC-Web preflight goes where the call it announces goes, so both
        // get one CORS policy: the proxy's, or the upstream's when it owns
        // CORS. A fallback in between would answer it with neither.
        let protocol = grpc_protocol(request.headers()).or_else(|| {
            is_grpc_web_preflight(request.method(), request.headers()).then_some(GrpcProtocol::Web)
        });
        let inner = if let Some(protocol) = protocol {
            // A native call carries its connection the way tonic's server
            // hands it to a handler.
            if let Some(connection) = self.connection_of(&request) {
                connection.into_tonic_extensions(request.extensions_mut());
            }
            let request = request.map(tonic::body::Body::new);
            // A browser only speaks gRPC-Web, and the routes answered its
            // preflight: its call gets the same CORS policy.
            let cors = match (&mut self.grpc_web, protocol) {
                (Some(cors), GrpcProtocol::Web) => Some(&mut cors.web),
                (Some(cors), GrpcProtocol::WebText) => Some(&mut cors.web_text),
                _ => None,
            };
            match cors {
                // `Forward` is always ready, and so is CORS around it.
                Some(cors) => Inner::GrpcWeb {
                    future: cors.call(request),
                },
                None => Inner::Grpc {
                    call: PassThrough::new(self.upstream.clone(), request, protocol),
                },
            }
        } else {
            // The middleware reads the peer as axum's `ConnectInfo`; the
            // transcoder passes the whole connection on to the upstream.
            if let Some(connection) = &self.connection {
                let extensions = request.extensions_mut();
                if let Some(remote) = connection.remote_addr() {
                    extensions.insert(ConnectInfo(remote));
                }
                extensions.insert(connection.clone());
            } else if let Some(connection) = self.connection_of(&request) {
                request.extensions_mut().insert(connection);
            }
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
        GrpcWeb {
            #[pin]
            future: tower_http::cors::ResponseFuture<PassThrough<U>>,
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
            InnerProj::GrpcWeb { future } => future.poll(cx),
        }
    }
}

/// Serve `service` on `listener` until the listener fails: cleartext HTTP/1.1
/// and HTTP/2 on the same port, so REST clients and native gRPC clients share
/// it. Each connection's service gets its peer through
/// [`ProxyService::for_connection`]. For TLS, run the service on a server of
/// your own (see [`ProxyService`]).
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
        std::future::ready(Ok(self.0.for_connection(stream.io().connect_info())))
    }
}

#[cfg(test)]
mod tests;
