//! What the listener keeps of a connection after it closes. A test binary of
//! its own: it counts every allocation of the process.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use structured_proxy::{ProxyServer, ServeOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The system allocator, keeping count of the bytes live.
struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every call goes to `System` unchanged; the counter only observes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE.fetch_add(
                new_size as isize - layout.size() as isize,
                Ordering::Relaxed,
            );
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// A keep-alive connection that has had one `GET /health/live` answered.
async fn served(addr: std::net::SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    // The status line is all the case needs; the rest stays unread.
    let mut status = [0; 12];
    stream.read_exact(&mut status).await.unwrap();
    assert_eq!(&status, b"HTTP/1.1 200");
    stream
}

#[tokio::test]
async fn closed_connections_are_released_while_the_listener_waits() {
    // After a burst the server sits in accept with no new client; what the
    // closed connections held must be freed then, not at the next accept.
    let service = ProxyServer::from_yaml_str("service:\n  name: demo\n")
        .unwrap()
        .service(tonic::service::Routes::default())
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(structured_proxy::serve_with(
        listener,
        service,
        ServeOptions::new(),
    ));
    // Lazily built state (the router, runtime buffers) is in place after one.
    drop(served(addr).await);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let before = LIVE.load(Ordering::Relaxed);

    // Held open together, then closed together: they end while the server
    // waits for a client that does not come. Few enough for the default
    // file descriptor limit of macOS (256).
    const BURST: isize = 100;
    let mut open = Vec::new();
    for _ in 0..BURST {
        open.push(served(addr).await);
    }
    drop(open);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let kept = LIVE.load(Ordering::Relaxed) - before;
    // A closed connection's task keeps about 190 bytes until it is reaped;
    // the bound leaves room for allocator noise, not for the tasks.
    assert!(
        kept < 64 * BURST,
        "{kept} bytes kept for {BURST} closed connections"
    );
}
