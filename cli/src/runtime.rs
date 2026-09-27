//! The `runtime:` section of the config file: the async runtime the binary
//! runs the proxy on. Only the binary reads it; the library runs on whatever
//! runtime its embedder provides.

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
    /// busy. Unset: tokio's default.
    #[serde(default)]
    pub worker_threads: Option<NonZeroUsize>,
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
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all();
        let source = match self.worker_threads {
            Some(n) => {
                builder.worker_threads(n.get());
                WorkerSource::Config
            }
            None => match std::env::var_os(WORKER_THREADS_ENV) {
                Some(raw) => {
                    let n = raw
                        .to_str()
                        .and_then(|s| s.trim().parse::<NonZeroUsize>().ok())
                        .ok_or_else(|| {
                            std::io::Error::other(format!(
                                "{WORKER_THREADS_ENV} must be a positive integer, got {raw:?}"
                            ))
                        })?;
                    builder.worker_threads(n.get());
                    WorkerSource::Environment
                }
                None => WorkerSource::AvailableParallelism,
            },
        };
        Ok((builder.build()?, source))
    }
}

#[cfg(test)]
mod tests;
