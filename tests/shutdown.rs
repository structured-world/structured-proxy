//! Graceful shutdown of the built-in listener (`serve_with_shutdown`): after
//! the signal new connections are refused, requests and streams in flight
//! finish, idle connections are closed, and dropping the serve future closes
//! everything at once. Each case runs in cleartext, behind TLS and under a
//! connection limit.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt as _;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use structured_proxy::{ProxyServer, ServeOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tower::ServiceExt as _;

const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tls/testdata");
const CA: &str = include_str!("../src/tls/testdata/ca.pem");
/// How long a test waits for what should happen right away; far below the
/// drain timeout, so no case passes by running into it.
const PROMPT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
struct Setup {
    tls: bool,
    max_connections: Option<usize>,
}

const SETUPS: [Setup; 3] = [
    Setup {
        tls: false,
        max_connections: None,
    },
    Setup {
        tls: true,
        max_connections: None,
    },
    // One slot: the one connection a case opens holds it, so the accept loop
    // sits waiting for a slot when the signal comes.
    Setup {
        tls: false,
        max_connections: Some(1),
    },
];

trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// Tells the test a handler future was dropped.
struct OnDrop(mpsc::UnboundedSender<()>);

impl Drop for OnDrop {
    fn drop(&mut self) {
        // The test may have stopped listening; nothing to report then.
        self.0.send(()).ok();
    }
}

/// Routes whose answers the test holds: `/slow` answers once released,
/// `/stream` sends a first chunk and the last one once released, `/hang`
/// never answers and reports when its handler is dropped. Each reports on
/// `entered` once its handler runs.
fn held_routes(
    entered: &mpsc::UnboundedSender<()>,
    release: &watch::Receiver<bool>,
    dropped: &mpsc::UnboundedSender<()>,
) -> axum::Router {
    use axum::routing::get;
    let slow = {
        let (entered, release) = (entered.clone(), release.clone());
        move || {
            let (entered, mut release) = (entered.clone(), release.clone());
            async move {
                entered.send(()).unwrap();
                release.wait_for(|go| *go).await.unwrap();
                "done"
            }
        }
    };
    let stream = {
        let (entered, release) = (entered.clone(), release.clone());
        move || {
            let (entered, mut release) = (entered.clone(), release.clone());
            async move {
                entered.send(()).unwrap();
                let first = futures::stream::once(async { Ok::<_, std::io::Error>("first\n") });
                let last = futures::stream::once(async move {
                    release.wait_for(|go| *go).await.unwrap();
                    Ok("last\n")
                });
                axum::body::Body::from_stream(futures::StreamExt::chain(first, last))
            }
        }
    };
    let hang = {
        let (entered, dropped) = (entered.clone(), dropped.clone());
        move || {
            let (entered, dropped) = (entered.clone(), dropped.clone());
            async move {
                let _dropped = OnDrop(dropped);
                entered.send(()).unwrap();
                std::future::pending::<&'static str>().await
            }
        }
    };
    axum::Router::new()
        .route("/slow", get(slow))
        .route("/stream", get(stream))
        .route("/hang", get(hang))
}

/// The proxy serving [`held_routes`] until the test stops it.
struct Proxy {
    addr: SocketAddr,
    setup: Setup,
    entered: mpsc::UnboundedReceiver<()>,
    release: watch::Sender<bool>,
    dropped: mpsc::UnboundedReceiver<()>,
    stop: Option<oneshot::Sender<()>>,
    served: JoinHandle<std::io::Result<()>>,
}

impl Proxy {
    /// Serve with the options `listen:` gives for `setup`, changed by
    /// `configure`. Idle connections stay open, so what closes one in a case
    /// is the shutdown.
    async fn start(setup: Setup, configure: impl FnOnce(ServeOptions) -> ServeOptions) -> Self {
        let mut listen = String::from("listen:\n  idle_timeout_secs: 0\n");
        if let Some(max) = setup.max_connections {
            listen.push_str(&format!("  max_connections: {max}\n"));
        }
        if setup.tls {
            install_provider();
            listen.push_str(&format!(
                "  tls:\n    cert_file: {TESTDATA}/ecdsa.pem\n    key_file: {TESTDATA}/ecdsa.key.pem\n"
            ));
        }
        let server = ProxyServer::from_yaml_str(&listen).unwrap();
        let options = configure(server.serve_options().unwrap());
        let (entered_tx, entered) = mpsc::unbounded_channel();
        let (release, release_rx) = watch::channel(false);
        let (dropped_tx, dropped) = mpsc::unbounded_channel();
        let service = server
            .service(tonic::service::Routes::default())
            .unwrap()
            .with_fallback(held_routes(&entered_tx, &release_rx, &dropped_tx));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, signal) = oneshot::channel::<()>();
        let served = tokio::spawn(structured_proxy::serve_with_shutdown(
            listener,
            service,
            options,
            async {
                signal.await.unwrap();
            },
        ));
        Self {
            addr,
            setup,
            entered,
            release,
            dropped,
            stop: Some(stop),
            served,
        }
    }

    /// A connection negotiating `alpn` behind TLS.
    async fn connect(&self, alpn: &[u8]) -> Box<dyn Io> {
        connect(self.addr, self.setup.tls, alpn).await
    }

    /// A tonic channel: an HTTP/2 client with a connection of its own.
    async fn channel(&self) -> tonic::transport::Channel {
        let (addr, tls) = (self.addr, self.setup.tls);
        let connector = tower::service_fn(move |_: http::Uri| async move {
            Ok::<_, std::io::Error>(TokioIo::new(connect(addr, tls, b"h2").await))
        });
        tonic::transport::Endpoint::from_static("http://localhost")
            .connect_with_connector(connector)
            .await
            .unwrap()
    }

    /// Wait until `count` handlers have started.
    async fn entered(&mut self, count: usize) {
        for _ in 0..count {
            tokio::time::timeout(PROMPT, self.entered.recv())
                .await
                .expect("the request reaches its handler")
                .unwrap();
        }
    }

    /// Wait until `count` handler futures have been dropped.
    async fn dropped(&mut self, count: usize) {
        for _ in 0..count {
            tokio::time::timeout(PROMPT, self.dropped.recv())
                .await
                .expect("the handler is dropped")
                .unwrap();
        }
    }

    fn signal(&mut self) {
        self.stop.take().unwrap().send(()).unwrap();
    }

    fn release(&self) {
        self.release.send_replace(true);
    }

    /// Wait until the listening socket is closed.
    async fn refuses_connections(&self) {
        tokio::time::timeout(PROMPT, async {
            while TcpStream::connect(self.addr).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("new connections are refused after the signal");
    }

    /// Wait for the serve future to resolve.
    async fn served(&mut self) {
        tokio::time::timeout(PROMPT, &mut self.served)
            .await
            .expect("the serve future resolves")
            .unwrap()
            .unwrap();
    }
}

fn install_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider())
            .expect("each test runs in its own process");
    }
}

async fn connect(addr: SocketAddr, tls: bool, alpn: &[u8]) -> Box<dyn Io> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    if !tls {
        return Box::new(tcp);
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(CA.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    Box::new(stream)
}

/// Read until the server closes the connection; returns what it sent.
async fn read_until_closed(io: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut received = Vec::new();
    let read = tokio::time::timeout(PROMPT, io.read_to_end(&mut received))
        .await
        .expect("the server closes the connection");
    // An end of stream, a reset, or TLS closed without close_notify: the
    // server let go either way.
    if let Err(error) = read {
        use std::io::ErrorKind;
        assert!(
            matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof
            ),
            "{error}"
        );
    }
    received
}

async fn get(channel: &tonic::transport::Channel, path: &str) -> http::Response<tonic::body::Body> {
    send(channel, path).await.unwrap()
}

/// A call the server is expected to cut off: its outcome is left to the case.
async fn send(
    channel: &tonic::transport::Channel,
    path: &str,
) -> Result<http::Response<tonic::body::Body>, tonic::transport::Error> {
    let request = http::Request::get(path)
        .body(tonic::body::Body::empty())
        .unwrap();
    channel.clone().oneshot(request).await
}

#[tokio::test]
async fn an_http1_request_in_flight_completes_and_new_connections_are_refused() {
    for setup in SETUPS {
        let mut proxy = Proxy::start(setup, |options| options).await;
        let mut client = proxy.connect(b"http/1.1").await;
        client
            .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        proxy.entered(1).await;

        proxy.signal();
        proxy.refuses_connections().await;
        assert!(
            !proxy.served.is_finished(),
            "{setup:?}: a request is in flight"
        );

        proxy.release();
        let response = String::from_utf8(read_until_closed(&mut client).await).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{setup:?}: {response}"
        );
        assert!(response.ends_with("done"), "{setup:?}: {response}");
        proxy.served().await;
    }
}

#[tokio::test]
async fn http2_calls_and_streams_in_flight_complete() {
    for setup in SETUPS {
        let mut proxy = Proxy::start(setup, |options| options).await;
        let channel = proxy.channel().await;
        let unary = tokio::spawn({
            let channel = channel.clone();
            async move {
                let body = get(&channel, "/slow").await.into_body();
                body.collect().await.unwrap().to_bytes()
            }
        });
        let mut stream = get(&channel, "/stream").await.into_body();
        proxy.entered(2).await;
        let first = stream.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first, "first\n", "{setup:?}");

        proxy.signal();
        proxy.refuses_connections().await;
        assert!(!proxy.served.is_finished(), "{setup:?}: streams are open");

        proxy.release();
        let rest = stream.collect().await.unwrap().to_bytes();
        assert_eq!(rest, "last\n", "{setup:?}");
        assert_eq!(unary.await.unwrap(), "done", "{setup:?}");
        proxy.served().await;
    }
}

#[tokio::test]
async fn an_idle_http2_client_gets_a_goaway() {
    for setup in SETUPS {
        let mut proxy = Proxy::start(setup, |options| options).await;
        let io = proxy.connect(b"h2").await;
        let (sender, connection) = h2::client::handshake(io).await.unwrap();
        let connection = tokio::spawn(connection);
        let mut sender = sender.ready().await.unwrap();
        let (response, _) = sender
            .send_request(
                http::Request::get("http://localhost/health/live")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(response.await.unwrap().status(), 200, "{setup:?}");

        // The client keeps its connection; the server closes it.
        proxy.signal();
        proxy.served().await;
        let ended = tokio::time::timeout(PROMPT, connection)
            .await
            .expect("the client's connection ends")
            .unwrap();
        assert!(ended.is_ok(), "{setup:?}: {ended:?}");
        let refused = sender
            .send_request(
                http::Request::get("http://localhost/health/live")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap_err();
        assert!(refused.is_go_away(), "{setup:?}: {refused}");
        assert_eq!(refused.reason(), Some(h2::Reason::NO_ERROR), "{setup:?}");
    }
}

#[tokio::test]
async fn a_connection_that_sent_nothing_is_closed() {
    // Behind TLS it is still in its handshake; in cleartext hyper has not
    // seen which HTTP version it speaks.
    for setup in SETUPS {
        let mut proxy = Proxy::start(setup, |options| options).await;
        let mut silent = TcpStream::connect(proxy.addr).await.unwrap();
        // Let the server accept it before the signal.
        tokio::time::sleep(Duration::from_millis(100)).await;

        proxy.signal();
        proxy.served().await;
        assert_eq!(read_until_closed(&mut silent).await, b"", "{setup:?}");
    }
}

#[tokio::test]
async fn a_connection_waiting_for_a_slot_is_closed() {
    let setup = Setup {
        tls: false,
        max_connections: Some(1),
    };
    let mut proxy = Proxy::start(setup, |options| options).await;
    let mut first = proxy.connect(b"http/1.1").await;
    first
        .write_all(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut head = [0; 12];
    first.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200");
    // The first connection holds the one slot: the kernel completes this one,
    // but the proxy never accepts it.
    let mut waiting = TcpStream::connect(proxy.addr).await.unwrap();
    waiting
        .write_all(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    proxy.signal();
    proxy.served().await;
    assert_eq!(read_until_closed(&mut waiting).await, b"");
    read_until_closed(&mut first).await;
}

#[tokio::test]
async fn the_drain_timeout_closes_connections_still_busy() {
    for setup in SETUPS {
        let mut proxy = Proxy::start(setup, |options| {
            options.drain_timeout(Some(Duration::from_millis(300)))
        })
        .await;
        let mut client = proxy.connect(b"http/1.1").await;
        client
            .write_all(b"GET /hang HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        proxy.entered(1).await;

        proxy.signal();
        proxy.served().await;
        proxy.dropped(1).await;
        assert_eq!(read_until_closed(&mut client).await, b"", "{setup:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_drain_timeout_ends_http2_handlers_before_returning() {
    // HTTP/2 serves each stream in a task of its own: when the serve future
    // resolves, those have ended too, not only their connections.
    for setup in SETUPS {
        let mut proxy = Proxy::start(setup, |options| {
            options.drain_timeout(Some(Duration::from_millis(300)))
        })
        .await;
        let channel = proxy.channel().await;
        let call = tokio::spawn(async move { send(&channel, "/hang").await });
        proxy.entered(1).await;

        proxy.signal();
        proxy.served().await;
        assert!(
            proxy.dropped.try_recv().is_ok(),
            "{setup:?}: a handler outlived serve_with_shutdown"
        );
        call.abort();
    }
}

#[tokio::test]
async fn dropping_the_serve_future_ends_every_connection_and_handler() {
    // Unlimited: this case opens two connections.
    for setup in &SETUPS[..2] {
        let mut proxy = Proxy::start(*setup, |options| options).await;
        let mut http1 = proxy.connect(b"http/1.1").await;
        http1
            .write_all(b"GET /hang HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let channel = proxy.channel().await;
        let http2 = tokio::spawn(async move { send(&channel, "/hang").await });
        proxy.entered(2).await;

        proxy.served.abort();
        // HTTP/2 serves each stream in a task of its own; that one ends too.
        proxy.dropped(2).await;
        assert_eq!(read_until_closed(&mut http1).await, b"", "{setup:?}");
        let refused = tokio::time::timeout(PROMPT, TcpStream::connect(proxy.addr))
            .await
            .expect("connecting completes");
        assert!(refused.is_err(), "{setup:?}: the listener is closed");
        http2.abort();
    }
}
