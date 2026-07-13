use std::{io, path::Path};

use serde_json::json;
use spooky_utils::logger::{
    errors::{build_create_log_dir_error, build_open_log_file_error},
    formatter::build_json_payload,
    init::{LoggerInitStatus, try_init_logger},
};

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
