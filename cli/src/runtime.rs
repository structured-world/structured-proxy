//! The `runtime:` section of the config file: the async runtime the binary
//! runs the proxy on. Only the binary reads it; the library runs on whatever
//! runtime its embedder provides.

use std::ffi::OsStr;
use std::fmt;
use std::num::NonZeroUsize;

use serde::Deserialize;

/// The variable tokio reads for its default worker count.
const WORKER_THREADS_ENV: &str = "TOKIO_WORKER_THREADS";

/// The keys of the config file this binary reads itself; the library reads
/// the rest and ignores these.
#[derive(Debug, Default, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub runtime: RuntimeConfig,
}

/// `runtime:`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Worker threads of the async runtime, so the CPU cores the proxy keeps
    /// busy. Left out: tokio's default. Present, it must be a positive
    /// integer: an explicit null or empty value is refused, not taken for
    /// "left out".
    #[serde(default, deserialize_with = "present_count")]
    pub worker_threads: Option<NonZeroUsize>,
}

/// A key that is present holds a count; only an absent one (`default`) is
/// `None`.
fn present_count<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<NonZeroUsize>, D::Error> {
    NonZeroUsize::deserialize(de).map(Some)
}

/// Where the worker count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerSource {
    /// `runtime.worker_threads`.
    Config,
    /// The `TOKIO_WORKER_THREADS` environment variable.
    Environment,
    /// The available parallelism (on Linux, the cgroup CPU quota).
    AvailableParallelism,
}

impl fmt::Display for WorkerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Config => "runtime.worker_threads",
            Self::Environment => WORKER_THREADS_ENV,
            Self::AvailableParallelism => "available parallelism",
        })
    }
}

impl FileConfig {
    /// The binary's own settings in a config file.
    ///
    /// # Errors
    ///
    /// A `runtime:` section that is not a map, holds an unknown key, or sets
    /// `worker_threads` to anything but a positive integer; the message names
    /// the key.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }
}

impl RuntimeConfig {
    /// A multi-thread runtime with the configured worker count, or tokio's
    /// default, and where that count came from.
    ///
    /// # Errors
    ///
    /// The runtime cannot be created, or `TOKIO_WORKER_THREADS` is used and
    /// is not a positive integer: tokio would panic on it, so it is read here
    /// and refused with its name.
    pub fn build(&self) -> std::io::Result<(tokio::runtime::Runtime, WorkerSource)> {
        self.build_with(std::env::var_os(WORKER_THREADS_ENV).as_deref())
    }

    /// [`build`](Self::build) with the value of `TOKIO_WORKER_THREADS` given
    /// rather than read, so the count depends on the arguments alone.
    fn build_with(
        &self,
        env: Option<&OsStr>,
    ) -> std::io::Result<(tokio::runtime::Runtime, WorkerSource)> {
        let (workers, source) = match (self.worker_threads, env) {
            (Some(n), _) => (n.get(), WorkerSource::Config),
            (None, Some(raw)) => {
                let n = raw
                    .to_str()
                    .and_then(|s| s.trim().parse::<NonZeroUsize>().ok())
                    .ok_or_else(|| {
                        std::io::Error::other(format!(
                            "{WORKER_THREADS_ENV} must be a positive integer, got {raw:?}"
                        ))
                    })?;
                (n.get(), WorkerSource::Environment)
            }
            // What tokio falls back to itself; set here so tokio does not
            // read the variable a second time.
            (None, None) => (
                std::thread::available_parallelism().map_or(1, NonZeroUsize::get),
                WorkerSource::AvailableParallelism,
            ),
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()?;
        Ok((runtime, source))
    }
}

#[cfg(test)]
mod tests;
