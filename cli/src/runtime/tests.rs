use super::*;

/// The `runtime:` settings of `yaml`, or the error they fail with.
fn runtime(yaml: &str) -> Result<RuntimeConfig, String> {
    FileConfig::from_yaml_str(yaml)
        .map(|file| file.runtime)
        .map_err(|e| e.to_string())
}

// The tests pass the value of TOKIO_WORKER_THREADS to `build_with` instead of
// setting the process-wide variable, so they can run in parallel in one
// process.

#[test]
fn configured_worker_threads_start_exactly_that_many_workers() {
    let config = runtime("runtime:\n  worker_threads: 3\n").unwrap();
    let (rt, source) = config.build_with(None).unwrap();
    assert_eq!(rt.metrics().num_workers(), 3);
    assert_eq!(source, WorkerSource::Config);
}

#[test]
fn without_the_key_the_environment_decides() {
    let config = runtime("upstream:\n  default: \"http://x:1\"\n").unwrap();
    let (rt, source) = config.build_with(Some(OsStr::new("2"))).unwrap();
    assert_eq!(rt.metrics().num_workers(), 2);
    assert_eq!(source, WorkerSource::Environment);
}

#[test]
fn without_the_key_or_the_variable_the_available_parallelism_decides() {
    let (rt, source) = RuntimeConfig::default().build_with(None).unwrap();
    let parallelism = std::thread::available_parallelism().unwrap().get();
    assert_eq!(rt.metrics().num_workers(), parallelism);
    assert_eq!(source, WorkerSource::AvailableParallelism);
}

#[test]
fn the_config_wins_over_the_environment() {
    let (rt, source) = runtime("runtime:\n  worker_threads: 1\n")
        .unwrap()
        .build_with(Some(OsStr::new("5")))
        .unwrap();
    assert_eq!(rt.metrics().num_workers(), 1);
    assert_eq!(source, WorkerSource::Config);
}

#[test]
fn an_invalid_worker_count_names_the_key() {
    // An explicit null or empty value is a mistake to report, not the same
    // as leaving the key out.
    for value in ["0", "-1", "two", "1.5", "[]", "null", "~", ""] {
        let err = runtime(&format!("runtime:\n  worker_threads: {value}\n")).unwrap_err();
        assert!(err.contains("runtime.worker_threads"), "{value}: {err}");
    }
}

#[test]
fn an_unknown_runtime_key_names_it() {
    let err = runtime("runtime:\n  worker_thread: 2\n").unwrap_err();
    assert!(err.contains("worker_thread"), "{err}");
    assert!(err.starts_with("runtime"), "{err}");
}

#[test]
fn an_invalid_environment_value_is_refused_by_name() {
    for value in ["0", "many", "", "-2"] {
        let err = RuntimeConfig::default()
            .build_with(Some(OsStr::new(value)))
            .unwrap_err()
            .to_string();
        assert!(err.contains(WORKER_THREADS_ENV), "{value:?}: {err}");
    }
}

#[test]
fn the_source_is_named_for_the_startup_log() {
    assert_eq!(WorkerSource::Config.to_string(), "runtime.worker_threads");
    assert_eq!(
        WorkerSource::Environment.to_string(),
        "TOKIO_WORKER_THREADS"
    );
    assert_eq!(
        WorkerSource::AvailableParallelism.to_string(),
        "available parallelism"
    );
}
