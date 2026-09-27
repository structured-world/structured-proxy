//! The installed `structured-proxy` binary: it reads `--config`, refuses a
//! config it cannot load, and serves once started.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_structured-proxy");

/// Kills the proxy when the test ends, pass or fail.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        // Reported, not unwrapped: a panic here while a failed test unwinds
        // would abort and hide that test's own message.
        if let Err(e) = self.0.kill() {
            eprintln!("could not kill the proxy: {e}");
        }
        if let Err(e) = self.0.wait() {
            eprintln!("could not reap the proxy: {e}");
        }
    }
}

#[test]
fn version_names_the_binary_and_the_package_version() {
    let out = Command::new(BIN).arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        format!("structured-proxy {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn a_missing_config_fails_and_names_the_file() {
    let path = std::env::temp_dir().join("structured-proxy-cli-test-missing.yaml");
    let out = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains(&*path.to_string_lossy()), "{stderr}");
}

#[test]
fn an_invalid_config_fails_before_listening() {
    let path = std::env::temp_dir().join(format!(
        "structured-proxy-cli-test-invalid-{}.yaml",
        std::process::id()
    ));
    std::fs::write(&path, "listen: [not, a, map]\n").unwrap();
    let out = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(!out.status.success());
}

#[test]
fn a_valid_config_starts_the_proxy() {
    // A port that was free a moment ago; the proxy binds it itself.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = std::env::temp_dir().join(format!(
        "structured-proxy-cli-test-{}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        format!(
            "listen:\n  http: \"127.0.0.1:{port}\"\n\
             upstream:\n  default: \"http://127.0.0.1:9\"\n\
             descriptors: []\n"
        ),
    )
    .unwrap();
    let _proxy = Running(
        Command::new(BIN)
            .arg("--config")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    // Liveness does not depend on the upstream, so it answers as soon as the
    // listener is up.
    let deadline = Instant::now() + Duration::from_secs(20);
    let response = loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream
                .write_all(
                    b"GET /health/live HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            break response;
        }
        assert!(Instant::now() < deadline, "the proxy never listened");
        std::thread::sleep(Duration::from_millis(50));
    };
    std::fs::remove_file(&path).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}
