// SPDX-License-Identifier: AGPL-3.0-or-later
use bloch_indexer::rpcprobe::{decode_response, extract_string_field, Probe};

fn response(body: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}

#[test]
fn probe_requires_matching_successful_rpc_envelope() {
    let valid = r#"{"jsonrpc":"2.0","id":7,"result":{"balance_sat":"9007199254740993"}}"#;
    assert_eq!(decode_response(&response(valid), 7).unwrap()["balance_sat"], "9007199254740993");
    assert!(decode_response(&response(valid), 8).is_err());
    for invalid in [
        r#"{"id":7,"result":{"balance_sat":"1"}}"#,
        r#"{"jsonrpc":"2.0","id":7,"error":{"balance_sat":"1"}}"#,
        r#"{"jsonrpc":"2.0","id":7,"error":{"code":-1},"result":{"balance_sat":"1"}}"#,
        r#"{"jsonrpc":"2.0","id":7,"result":null}"#,
        r#"{"jsonrpc":"2.0","id":7,"result":{}} trailing"#,
    ] { assert!(decode_response(&response(invalid), 7).is_err()); }
    assert_eq!(extract_string_field(r#"{"nested":{"balance_sat":"1"}}"#, "balance_sat"), None);
    assert!(Probe::new("127.0.0.1:1", 0).is_err());
}

#[test]
fn probe_refuses_status_framing_and_body_budget_errors() {
    let body = r#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
    for bad in [
        format!("HTTP/1.1 500 Error\r\n\r\n{body}"),
        format!("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{body}"),
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Length: {}\r\n\r\n{body}", body.len(), body.len()),
        format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body}"),
        format!("HTTP/1.1 200 OK\r\nX-Padding: {}\r\n\r\n{body}", "x".repeat(16 * 1024)),
    ] { assert!(decode_response(bad.as_bytes(), 7).is_err()); }
    let oversized = vec![b'x'; 1024 * 1024 + 1];
    assert!(decode_response(&oversized, 7).is_err());
}
