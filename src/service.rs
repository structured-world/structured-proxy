//! The proxy as one tower service: native gRPC to the upstream, everything
//! else to the proxy's routes, and what no route answers to a fallback.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::cors::{Cors, CorsFuture, CorsLayer};
use axum::extract::connect_info::ConnectInfo;
use axum::response::IntoResponse;
use axum::routing::future::RouteFuture;
use bytes::Bytes;
use pin_project_lite::pin_project;
use rustls::pki_types::CertificateDer;
use tonic::transport::server::{Connected, TcpConnectInfo};
use tower::{Layer, Service, ServiceExt};

use crate::client_address::ClientAddressLayer;
use crate::guard::{BoxedService, Class, GrpcRejections, Guards};
use crate::transcode::{Chooser, Direct};

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
/// arrived, so one listener carries REST and native gRPC. gRPC-Web is the
/// upstream's to translate (tonic-web's `GrpcWebLayer` around its services),
/// or the proxy's with `grpc_web.translate` for an upstream that speaks only
/// gRPC. A gRPC-Web
/// answer gets the proxy's CORS policy (`cors.grpc_web`), since the proxy
/// answers the browser's preflight for it. Every other request goes to the
/// proxy's routes (transcoded RPCs, health, metrics, OpenAPI, OIDC,
/// forward-auth, extra routes) behind the proxy's middleware. A request no
/// route matches is answered `404`, or handed to the service set with
/// [`with_fallback`](Self::with_fallback). Native gRPC and the fallback pass
/// only the guards whose scope names them (`grpc`, `fallback`); a guard's
/// rejection of a gRPC call is a gRPC status.
///
/// Serve it with [`serve`](crate::serve()) or
/// [`serve_with`](crate::serve_with) (TLS, a connection limit), or hand it to
/// any server that takes a tower service of `http` types: a Unix socket, an
/// existing hyper or axum server. Native gRPC needs HTTP/2 on that server
/// (ALPN `h2` next to `http/1.1` behind TLS). Such a server tells the proxy
/// which connection a request came on with
/// [`for_connection`](Self::for_connection).
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
#[derive(Clone)]
pub struct ProxyService<U> {
    /// Shared by every clone: a server clones the service for each request
    /// and only one path serves it.
    shared: Arc<Shared<U>>,
    /// The connection the requests arrive on, set per connection by the
    /// server.
    connection: Option<ConnectionInfo>,
}

/// What every request of a [`ProxyService`] may take a path through.
#[derive(Clone)]
struct Shared<U> {
    upstream: U,
    /// Where the requests that are not gRPC go.
    routing: Routing,
    /// Binary and text gRPC-Web to the upstream under the CORS policy, each
    /// built once; `None` when the upstream owns CORS for gRPC-Web.
    grpc_web: Option<GrpcWebCors<U>>,
    /// The gRPC paths behind guards or through gRPC-Web translation; a
    /// protocol that needs neither passes through with nothing in between.
    boxed: BoxedGrpc,
    /// The guards, for the fallback an embedder sets later.
    guards: Arc<Guards>,
}

impl<U> std::fmt::Debug for ProxyService<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyService")
            .field("boxed_grpc", &self.shared.boxed.grpc.is_some())
            .field("boxed_grpc_web", &self.shared.boxed.web.is_some())
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

/// How the requests that are not gRPC reach the proxy's routes.
#[derive(Clone)]
pub(crate) enum Routing {
    /// The transcoded routes are matched by the proxy and served past any
    /// router; the other routes by theirs.
    Direct {
        direct: Direct,
        others: axum::Router,
    },
    /// Every route by one router, which `chooser` (with transcoded routes)
    /// chooses a binding after; `served` is the router with it.
    Routed {
        router: axum::Router,
        chooser: Option<Chooser>,
        served: axum::Router,
    },
}

impl Routing {
    /// Every route by `router`, choosing among its transcoded bindings with
    /// `chooser`.
    pub(crate) fn routed(router: axum::Router, chooser: Option<Chooser>) -> Self {
        let served = match &chooser {
            Some(chooser) => chooser.clone().layer(router.clone()),
            None => router.clone(),
        };
        Self::Routed {
            router,
            chooser,
            served,
        }
    }

    /// These routes, with `fallback` answering what none does.
    fn with_fallback(self, fallback: BoxedService) -> Self {
        match self {
            Self::Direct { direct, others } => Self::Direct {
                direct,
                others: others.fallback_service(fallback),
            },
            Self::Routed {
                router, chooser, ..
            } => Self::routed(
                router.fallback_service(fallback.clone()),
                chooser.map(|chooser| chooser.with_fallback(fallback)),
            ),
        }
    }
}

/// The gRPC paths that need more than a pass-through (guards, gRPC-Web
/// translation), each protocol's stack built once; `None` for a protocol that
/// passes through as it is.
#[derive(Clone, Default)]
struct BoxedGrpc {
    grpc: Option<BoxedService>,
    web: Option<BoxedService>,
    web_text: Option<BoxedService>,
}

/// Hands a gRPC-Web call, translated to gRPC by tonic-web, to an upstream
/// that speaks only gRPC.
#[derive(Clone, Debug)]
struct Translated<U> {
    upstream: U,
}

impl<U: Upstream> Service<http::Request<tonic::body::Body>> for Translated<U> {
    type Response = http::Response<axum::body::Body>;
    type Error = Infallible;
    type Future = PassThrough<U>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let (mut parts, body) = request.into_parts();
        // A browser's call arrives over HTTP/1.1; as gRPC it is an HTTP/2
        // request (gRPC PROTOCOL-HTTP2).
        parts.version = http::Version::HTTP_2;
        // tonic-web reports the size of the base64 text body for the decoded
        // one, and an HTTP/2 client would announce that as its length; the
        // gRPC body goes without one.
        let body = tonic::body::Body::new(Unsized { body });
        PassThrough::new(
            self.upstream.clone(),
            http::Request::from_parts(parts, body),
            GrpcProtocol::Grpc,
        )
    }
}

pin_project! {
    /// `body` without its size hint.
    struct Unsized {
        #[pin]
        body: tonic::body::Body,
    }
}

impl http_body::Body for Unsized {
    type Data = Bytes;
    type Error = tonic::Status;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, tonic::Status>>> {
        self.project().body.poll_frame(cx)
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
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

/// The guarded path's end: the guards run on axum's request type.
impl<U: Upstream> Service<axum::extract::Request> for Forward<U> {
    type Response = http::Response<axum::body::Body>;
    type Error = Infallible;
    type Future = PassThrough<U>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: axum::extract::Request) -> Self::Future {
        let request = request.map(tonic::body::Body::new);
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
    /// The service over `upstream` and the routes of `routing`; gRPC-Web
    /// answers carry `grpc_web_cors` when set, and gRPC-Web calls are
    /// translated to gRPC when `translate_grpc_web`.
    pub(crate) fn new(
        upstream: U,
        routing: Routing,
        grpc_web_cors: Option<CorsLayer>,
        guards: Arc<Guards>,
        translate_grpc_web: bool,
    ) -> Self {
        let forward = |protocol| Forward {
            upstream: upstream.clone(),
            protocol,
        };
        let guard_grpc = guards.cover(Class::Grpc);
        let stack = |protocol: GrpcProtocol| {
            let web = protocol != GrpcProtocol::Grpc;
            let mut service = if web && translate_grpc_web {
                let translator = tonic_web::GrpcWebLayer::new().layer(Translated {
                    upstream: upstream.clone(),
                });
                BoxedService::new(ServiceExt::<axum::extract::Request>::map_response(
                    translator,
                    |response| response.map(axum::body::Body::new),
                ))
            } else {
                BoxedService::new(forward(protocol))
            };
            if guard_grpc {
                service = BoxedService::new(GrpcRejections {
                    inner: guards.service(service, Class::Grpc),
                    protocol,
                });
            }
            // CORS outermost, so a rejected gRPC-Web call still carries it.
            match &grpc_web_cors {
                Some(cors) if web => BoxedService::new(cors.layer(service)),
                _ => service,
            }
        };
        let boxed_web = guard_grpc || translate_grpc_web;
        let boxed = BoxedGrpc {
            grpc: guard_grpc.then(|| stack(GrpcProtocol::Grpc)),
            web: boxed_web.then(|| stack(GrpcProtocol::Web)),
            web_text: boxed_web.then(|| stack(GrpcProtocol::WebText)),
        };
        // The pass-through of gRPC-Web, and the answer to its preflights.
        let grpc_web = grpc_web_cors.map(|cors| GrpcWebCors {
            web: cors.layer(forward(GrpcProtocol::Web)),
            web_text: cors.layer(forward(GrpcProtocol::WebText)),
        });
        Self {
            shared: Arc::new(Shared {
                upstream,
                routing,
                grpc_web,
                boxed,
                guards,
            }),
            connection: None,
        }
    }

    /// Hand the requests no route matches to `fallback` instead of answering
    /// `404`: an embedder's own REST routes, a static site, anything that is a
    /// tower service. Only the guards whose scope names `fallback` traffic see
    /// them; CORS and tracing are the fallback's own.
    ///
    /// A URL whose path a transcoded template's route matches, but which no
    /// binding answers (its field template or custom verb does not fit), is
    /// the fallback's too. A request whose path a route answers but not with
    /// its method stays with the proxy (`405`), as do every gRPC request and
    /// every browser preflight for a gRPC-Web call, which follows the call it
    /// announces.
    #[must_use]
    pub fn with_fallback<F>(mut self, fallback: F) -> Self
    where
        F: Service<axum::extract::Request, Error = Infallible> + Clone + Send + Sync + 'static,
        F::Response: IntoResponse,
        F::Future: Send + 'static,
    {
        let shared = Arc::make_mut(&mut self.shared);
        let fallback = BoxedService::new(fallback.map_response(IntoResponse::into_response));
        let guarded = if shared.guards.cover(Class::Fallback) {
            shared.guards.service(fallback, Class::Fallback)
        } else {
            fallback
        };
        // The routes' own layers do not reach a fallback set after them, so
        // it gets the client-address resolution of its own, around its guards.
        // A URL no transcoded binding answers goes to the other routes, which
        // hand what they do not answer to the same fallback.
        let resolve = ClientAddressLayer::with(shared.guards.client_address.clone());
        let fallback = BoxedService::new(resolve.layer(guarded));
        shared.routing = shared.routing.clone().with_fallback(fallback);
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
    /// reports for the stream. [`serve_with`](crate::serve_with) does this
    /// itself.
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
            shared: self.shared.clone(),
            connection: Some(connection.into()),
        }
    }
}

/// The connection `request` came on: `connection`, the one given to
/// [`ProxyService::for_connection`], else the peer an outer axum server
/// recorded as `ConnectInfo`, so the upstream sees the same client the proxy's
/// middleware does. A free function, so the caller keeps its other fields.
fn connection_of<B>(
    connection: Option<&ConnectionInfo>,
    request: &http::Request<B>,
) -> Option<ConnectionInfo> {
    if let Some(connection) = connection {
        return Some(connection.clone());
    }
    let ConnectInfo(remote) = request.extensions().get::<ConnectInfo<SocketAddr>>()?;
    Some(ConnectionInfo::from(TcpConnectInfo {
        local_addr: None,
        remote_addr: Some(*remote),
    }))
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
        let call = grpc_protocol(request.headers());
        let protocol = call.or_else(|| {
            is_grpc_web_preflight(request.method(), request.headers()).then_some(GrpcProtocol::Web)
        });
        // Only the path the request takes is cloned for it.
        let shared = &*self.shared;
        // A preflight is not a call: it skips the guards and the translation.
        let boxed = match call {
            Some(GrpcProtocol::Grpc) => shared.boxed.grpc.as_ref(),
            Some(GrpcProtocol::Web) => shared.boxed.web.as_ref(),
            Some(GrpcProtocol::WebText) => shared.boxed.web_text.as_ref(),
            None => None,
        };
        let inner = if let Some(protocol) = protocol {
            // Whatever goes the upstream's way, guarded or not: its client
            // address is resolved and its forwarding headers rewritten here,
            // once, for the guards and the upstream alike. The call carries
            // its connection the way tonic's server hands it to a handler.
            let connection = connection_of(self.connection.as_ref(), &request);
            let peer = connection.as_ref().and_then(ConnectionInfo::remote_addr);
            shared.guards.client_address.apply(&mut request, peer);
            if let Some(connection) = connection {
                connection.into_tonic_extensions(request.extensions_mut());
            }
            match boxed {
                // Every service on these paths is ready at once: guards and
                // the translator are middleware, and `Forward` waits for the
                // upstream per request.
                Some(service) => Inner::Boxed {
                    future: service.clone().call(request.map(axum::body::Body::new)),
                },
                None => {
                    let request = request.map(tonic::body::Body::new);
                    // A browser only speaks gRPC-Web, and the routes answered
                    // its preflight: its call gets the same CORS policy.
                    let cors = match (&shared.grpc_web, protocol) {
                        (Some(cors), GrpcProtocol::Web) => Some(&cors.web),
                        (Some(cors), GrpcProtocol::WebText) => Some(&cors.web_text),
                        _ => None,
                    };
                    match cors {
                        // `Forward` is always ready, and so is CORS around it.
                        Some(cors) => Inner::GrpcWeb {
                            future: cors.clone().call(request),
                        },
                        None => Inner::Grpc {
                            call: PassThrough::new(shared.upstream.clone(), request, protocol),
                        },
                    }
                }
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
            } else if let Some(connection) = connection_of(None, &request) {
                request.extensions_mut().insert(connection);
            }
            // A router and the transcoded routes' layers are always ready.
            // A router is a reference count.
            match &shared.routing {
                Routing::Direct { direct, others } => {
                    if direct.takes(&mut request) {
                        Inner::Boxed {
                            future: direct
                                .service()
                                .clone()
                                .call(request.map(axum::body::Body::new)),
                        }
                    } else {
                        Inner::Routes {
                            future: others.clone().call(request),
                        }
                    }
                }
                Routing::Routed { served, .. } => Inner::Routes {
                    future: served.clone().call(request),
                },
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
            future: CorsFuture<PassThrough<U>, axum::body::Body>,
        },
        Boxed {
            #[pin]
            future: <BoxedService as Service<axum::extract::Request>>::Future,
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
            InnerProj::Boxed { future } => future.poll(cx),
        }
    }
}

#[cfg(test)]
mod tests;
