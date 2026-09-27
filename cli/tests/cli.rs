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
    // Inside a directory named for this run and never created, so no file can
    // be there: a config that existed would start the proxy instead.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir()
        .join(format!(
            "structured-proxy-cli-test-missing-{}-{nanos}",
            std::process::id()
        ))
        .join("config.yaml");
    assert!(!path.exists());
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

/// A config file for this test process holding `yaml`, removed on drop.
struct ConfigFile(std::path::PathBuf);

impl ConfigFile {
    fn new(name: &str, yaml: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "structured-proxy-cli-test-{name}-{}.yaml",
            std::process::id()
        ));
        std::fs::write(&path, yaml).unwrap();
        Self(path)
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.0) {
            eprintln!("could not remove {}: {e}", self.0.display());
        }
    }
}

#[test]
fn configured_worker_threads_run_the_proxy_and_are_logged() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = ConfigFile::new(
        "workers",
        &format!(
            "listen:\n  http: \"127.0.0.1:{port}\"\n\
             upstream:\n  default: \"http://127.0.0.1:9\"\n\
             descriptors: []\n\
             runtime:\n  worker_threads: 2\n"
        ),
    );
    let mut child = Command::new(BIN)
        .arg("--config")
        .arg(&config.0)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let _proxy = Running(child);

    // Read the log on its own thread, so a proxy that never logs fails the
    // test at the deadline instead of blocking it.
    let (lines, logged) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let start = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let line = logged
            .recv_timeout(left)
            .expect("the proxy never logged its start");
        if line.contains("Starting structured-proxy") {
            break line;
        }
    };
    assert!(start.contains("worker_threads=2"), "{start}");
    assert!(
        start.contains("worker_threads_from=runtime.worker_threads"),
        "{start}"
    );
}

#[test]
fn a_bad_runtime_section_fails_at_startup_and_names_the_key() {
    for (name, runtime, key) in [
        ("zero", "worker_threads: 0", "runtime.worker_threads"),
        ("text", "worker_threads: two", "runtime.worker_threads"),
        ("unknown", "worker_thread: 2", "worker_thread"),
    ] {
        let config = ConfigFile::new(
            name,
            &format!("upstream:\n  default: \"http://127.0.0.1:9\"\nruntime:\n  {runtime}\n"),
        );
        let out = Command::new(BIN)
            .arg("--config")
            .arg(&config.0)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{name}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains(key), "{name}: {stderr}");
    }
}
