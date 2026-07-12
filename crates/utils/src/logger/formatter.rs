use serde_json::json;

pub fn build_json_payload(ts: &str, level: &str, target: &str, message: &str) -> serde_json::Value {
    json!({
        "ts": ts,
        "level": level,
        "target": target,
        "msg": message,
    })
}
