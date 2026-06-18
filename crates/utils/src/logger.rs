use std::{
    fs::{OpenOptions, create_dir_all},
    io::Write,
    path::Path,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use env_logger::{Builder, Target};
use log::LevelFilter;
use serde_json::json;

static LOGGER_INIT_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoggerInitStatus {
    Initialized,
    AlreadyInitialized,
}

pub fn init_logger(log_level: &str, log_enabled: bool, log_file: &str, json: bool) {
    let _ = try_init_logger(log_level, log_enabled, log_file, json);
}

pub fn try_init_logger(
    log_level: &str,
    log_enabled: bool,
    log_file: &str,
    json: bool,
) -> LoggerInitStatus {
    let mutex = LOGGER_INIT_MUTEX.get_or_init(|| Mutex::new(()));
    let _guard = mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if LOGGER_INITIALIZED.load(Ordering::Acquire) {
        return LoggerInitStatus::AlreadyInitialized;
    }

    let status = configure_and_init_logger(log_level, log_enabled, log_file, json);
    LOGGER_INITIALIZED.store(true, Ordering::Release);
    status
}

fn configure_and_init_logger(
    log_level: &str,
    log_enabled: bool,
    log_file: &str,
    json: bool,
) -> LoggerInitStatus {
    let level = match log_level.to_lowercase().as_str() {
        "whisper" => LevelFilter::Trace,
        "haunt" => LevelFilter::Debug,
        "spooky" => LevelFilter::Info,
        "scream" => LevelFilter::Warn,
        "poltergeist" => LevelFilter::Error,
        "silence" => LevelFilter::Off,

        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,

        _ => {
            eprintln!(
                "Invalid log level '{}', defaulting to 'spooky' (info)",
                log_level
            );
            LevelFilter::Info
        }
    };

    let mut builder = Builder::new();
    builder.filter_level(level);

    if json {
        builder.format(|buf, record| {
            let message = record.args().to_string();
            let payload = build_json_payload(
                &buf.timestamp_seconds().to_string(),
                &record.level().as_str().to_ascii_lowercase(),
                record.target(),
                &message,
            );

            writeln!(buf, "{payload}")
        });
    } else {
        builder.format_timestamp_secs();
    }

    // only write to file if enabled
    if log_enabled {
        if let Some(parent) = Path::new(log_file).parent()
            && let Err(err) = create_dir_all(parent)
        {
            eprintln!(
                "{}",
                build_create_log_dir_error(log_file, parent, &err)
            );
            return try_init_builder(builder);
        }

        let file = match OpenOptions::new().create(true).append(true).open(log_file) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("{}", build_open_log_file_error(log_file, &err));
                return try_init_builder(builder);
            }
        };

        builder.target(Target::Pipe(Box::new(file)));
    }
    // else → default (stderr)

    try_init_builder(builder)
}

fn try_init_builder(mut builder: Builder) -> LoggerInitStatus {
    match builder.try_init() {
        Ok(()) => LoggerInitStatus::Initialized,
        Err(_) => LoggerInitStatus::AlreadyInitialized,
    }
}

fn build_create_log_dir_error(log_file: &str, parent: &Path, err: &std::io::Error) -> String {
    format!(
        "Failed to create log directory '{}' for log file '{}': {}. Falling back to stderr logging.",
        parent.display(),
        log_file,
        err
    )
}

fn build_open_log_file_error(log_file: &str, err: &std::io::Error) -> String {
    format!(
        "Failed to open log file '{}': {}. Falling back to stderr logging.",
        log_file,
        err
    )
}

fn build_json_payload(ts: &str, level: &str, target: &str, message: &str) -> serde_json::Value {
    json!({
        "ts": ts,
        "level": level,
        "target": target,
        "msg": message,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        LoggerInitStatus, build_create_log_dir_error, build_json_payload,
        build_open_log_file_error, try_init_logger,
    };
    use serde_json::json;
    use std::io;
    use std::path::Path;

    #[test]
    fn logger_init_is_idempotent() {
        let _first = try_init_logger("info", false, "", false);

        let second = try_init_logger("debug", true, "/tmp/ignored.log", true);
        assert_eq!(second, LoggerInitStatus::AlreadyInitialized);
    }

    #[test]
    fn create_log_dir_error_includes_directory_and_file_path() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "permission denied");
        let msg = build_create_log_dir_error(
            "/var/log/spooky/spooky.log",
            Path::new("/var/log/spooky"),
            &err,
        );

        assert!(msg.contains("/var/log/spooky"));
        assert!(msg.contains("/var/log/spooky/spooky.log"));
        assert!(msg.contains("permission denied"));
    }

    #[test]
    fn open_log_file_error_includes_file_path() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "permission denied");
        let msg = build_open_log_file_error("/var/log/spooky/spooky.log", &err);

        assert!(msg.contains("/var/log/spooky/spooky.log"));
        assert!(msg.contains("permission denied"));
    }

    #[test]
    fn json_payload_preserves_plain_message_verbatim() {
        let payload = build_json_payload("123", "info", "spooky", "request_id=42 status=200");

        assert_eq!(
            payload,
            json!({
                "ts": "123",
                "level": "info",
                "target": "spooky",
                "msg": "request_id=42 status=200",
            })
        );
    }

    #[test]
    fn json_payload_preserves_malformed_kv_like_message_verbatim() {
        let payload = build_json_payload(
            "123",
            "warn",
            "spooky_edge",
            r#"request_id= status="" path=, trace_id==broken"#,
        );

        assert_eq!(
            payload,
            json!({
                "ts": "123",
                "level": "warn",
                "target": "spooky_edge",
                "msg": r#"request_id= status="" path=, trace_id==broken"#,
            })
        );
    }

    #[test]
    fn json_payload_preserves_embedded_quotes_and_whitespace() {
        let payload = build_json_payload(
            "123",
            "error",
            "spooky_edge::quic_listener::forwarding",
            r#"msg="backend failed" path="/api v1" detail="x=y, z""#,
        );

        assert_eq!(
            payload,
            json!({
                "ts": "123",
                "level": "error",
                "target": "spooky_edge::quic_listener::forwarding",
                "msg": r#"msg="backend failed" path="/api v1" detail="x=y, z""#,
            })
        );
    }
}
