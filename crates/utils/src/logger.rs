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
    let _guard = mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

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
            let payload = json!({
                "ts": buf.timestamp_seconds().to_string(),
                "level": record.level().as_str().to_ascii_lowercase(),
                "target": record.target(),
                "msg": message,
            });

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
                "Failed to create log directory '{}': {}. Falling back to stderr logging.",
                parent.display(),
                err
            );
            return try_init_builder(builder);
        }

        let file = match OpenOptions::new().create(true).append(true).open(log_file) {
            Ok(file) => file,
            Err(err) => {
                eprintln!(
                    "Failed to open log file '{}': {}. Falling back to stderr logging.",
                    log_file, err
                );
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

#[cfg(test)]
mod tests {
    use super::{LoggerInitStatus, try_init_logger};

    #[test]
    fn logger_init_is_idempotent() {
        let _first = try_init_logger("info", false, "", false);

        let second = try_init_logger("debug", true, "/tmp/ignored.log", true);
        assert_eq!(second, LoggerInitStatus::AlreadyInitialized);
    }
}
