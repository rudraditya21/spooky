use crate::logger::errors::{build_create_log_dir_error, build_open_log_file_error};
use crate::logger::formatter::build_json_payload;
use env_logger::{Builder, Target};
use log::LevelFilter;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

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
            eprintln!("{}", build_create_log_dir_error(log_file, parent, &err));
            return try_init_builder(builder);
        }

        // Restrict newly-created log files (0o640, not world-readable) and
        // refuse to follow a symlinked path — the log is opened as root before
        // privilege drop, so a symlink there would be a root-write primitive.
        let file = match OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .custom_flags(libc::O_NOFOLLOW)
            .open(log_file)
        {
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
