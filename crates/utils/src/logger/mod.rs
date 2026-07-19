pub mod errors;
pub mod formatter;
pub mod init;

pub use init::{LogLevelError, LoggerInitStatus, init_logger, set_log_level, try_init_logger};
