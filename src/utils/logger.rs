use env_logger;
use log::LevelFilter;

pub fn init_logger(log_level: &str) {
    let level = match log_level.to_lowercase().as_str() {
        // Spooky levels
        "whisper" => LevelFilter::Trace,
        "haunt" => LevelFilter::Debug,
        "spooky" => LevelFilter::Info,
        "scream" => LevelFilter::Warn,
        "poltergeist" => LevelFilter::Error,
        "silence" => LevelFilter::Off,

        // Standard levels (still supported)
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

    env_logger::Builder::from_default_env()
        .filter_level(level)
        .format_timestamp_secs()
        .init();
}
