use std::path::Path;

pub fn build_create_log_dir_error(log_file: &str, parent: &Path, err: &std::io::Error) -> String {
    format!(
        "Failed to create log directory '{}' for log file '{}': {}. Falling back to stderr logging.",
        parent.display(),
        log_file,
        err
    )
}

pub fn build_open_log_file_error(log_file: &str, err: &std::io::Error) -> String {
    format!(
        "Failed to open log file '{}': {}. Falling back to stderr logging.",
        log_file, err
    )
}
