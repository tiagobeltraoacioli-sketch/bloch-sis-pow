//! Bounded synchronous HTTP/1 RPC transport for the retained CLI callers.
//! HTTP only; this is not a TLS transport or a complete G4 wallet adapter.
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use serde_json::Value;

const MAX_RESPONSE: usize = 64 * 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;

fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
        .ok_or_else(|| "RPC deadline exceeded".into())
}

/// HTTP endpoint must be an authority (host:port), with no credentials or path.
/// DNS resolution shares the deadline; an OS resolver worker may outlive timeout.
pub fn call(authority: &str, method: &str, params: &Value, api_key: Option<&str>) -> Result<Value, String> {
    call_with_limits(authority, method, params, api_key, MAX_RESPONSE, Duration::from_secs(30))
}

fn call_with_limits(authority: &str, method: &str, params: &Value, api_key: Option<&str>, cap: usize, timeout: Duration) -> Result<Value, String> {
    if authority.is_empty() || authority.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '@' | '?' | '#')) {
        return Err("invalid RPC authority".into());
    }
    if api_key.is_some_and(|key| key.chars().any(|c| c.is_control())) { return Err("RPC API key contains control characters".into()); }
    let deadline = Instant::now().checked_add(timeout).ok_or("invalid RPC timeout")?;
    let owned = authority.to_owned();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new().name("wallet-rpc-dns".into()).spawn(move || {
        let resolved = owned.to_socket_addrs().map(|addresses| addresses.take(32).collect::<Vec<_>>());
        let _ = send.send(resolved);
    }).map_err(|_| "RPC DNS worker unavailable")?;
    let addresses = receive.recv_timeout(remaining(deadline)?).map_err(|_| "RPC DNS deadline exceeded")?
        .map_err(|_| "RPC DNS resolution failed")?;
    let mut connected = None;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, remaining(deadline)?) { connected = Some(stream); break; }
    }
    let mut stream = connected.ok_or("RPC connection failed")?;
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let auth = api_key.map(|key| format!("x-api-key: {key}\r\n")).unwrap_or_default();
    let request = format!("POST / HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let mut pending = request.as_bytes();
    while !pending.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?)).map_err(|_| "RPC socket configuration failed")?;
        let count = stream.write(pending).map_err(|_| "RPC write failed or deadline exceeded")?;
        if count == 0 { return Err("RPC connection closed during write".into()); }
        pending = &pending[count..];
    }
    let response = read_response(&mut stream, deadline, cap)?;
    let body = decode_response(&response, cap)?;
    let response: Value = serde_json::from_slice(&body).map_err(|_| "invalid JSON RPC response")?;
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || response.get("id").and_then(Value::as_u64) != Some(1) {
        return Err("RPC envelope version or ID mismatch".into());
    }
    if let Some(error) = response.get("error").filter(|error| !error.is_null()) {
        if response.get("result").is_some() { return Err("RPC response contains result and error".into()); }
        let code = error.get("code").and_then(Value::as_i64).ok_or("malformed RPC error")?;
        if error.get("message").and_then(Value::as_str).is_none() { return Err("malformed RPC error".into()); }
        return Err(format!("RPC error code {code}"));
    }
    response.get("result").cloned().ok_or_else(|| "RPC response missing result".into())
}

fn read_response(stream: &mut TcpStream, deadline: Instant, cap: usize) -> Result<Vec<u8>, String> {
    let limit = cap.checked_add(MAX_HEADERS).ok_or("invalid RPC response cap")?;
    let mut response = Vec::new();
    let mut headers_complete = false;
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?)).map_err(|_| "RPC socket configuration failed")?;
        let mut chunk = [0u8; 8192];
        let count = stream.read(&mut chunk).map_err(|_| "RPC read failed or deadline exceeded")?;
        remaining(deadline)?;
        if count == 0 { return Ok(response); }
        if response.len().checked_add(count).ok_or("RPC response length overflow")? > limit { return Err("RPC response exceeds byte limit".into()); }
        response.extend_from_slice(&chunk[..count]);
        if !headers_complete {
            if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                if end > MAX_HEADERS { return Err("RPC headers exceed byte limit".into()); }
                headers_complete = true;
            } else if response.len() > MAX_HEADERS { return Err("RPC headers exceed byte limit".into()); }
        }
    }
}

fn decode_response(response: &[u8], cap: usize) -> Result<Vec<u8>, String> {
    let header_end = response.windows(4).position(|w| w == b"\r\n\r\n").ok_or("missing HTTP headers")?;
    if header_end > MAX_HEADERS { return Err("RPC headers exceed byte limit".into()); }
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|_| "invalid HTTP headers")?;
    let mut lines = headers.split("\r\n");
    let mut status = lines.next().ok_or("missing HTTP status")?.split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) { return Err("invalid HTTP version".into()); }
    let code = status.next().ok_or("missing HTTP status")?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) { return Err("invalid HTTP status".into()); }
    let code: u16 = code.parse().map_err(|_| "invalid HTTP status")?;
    if !(200..300).contains(&code) { return Err(format!("HTTP status {code}")); }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid HTTP header")?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
            return Err("invalid HTTP header".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() { return Err("duplicate HTTP length".into()); }
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) { return Err("invalid HTTP length".into()); }
            length = Some(value.parse::<usize>().map_err(|_| "invalid HTTP length")?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.trim().eq_ignore_ascii_case("chunked") { return Err("unsupported HTTP transfer encoding".into()); }
            chunked = true;
        }
    }
    if chunked && length.is_some() { return Err("ambiguous HTTP framing".into()); }
    let body_start = header_end.checked_add(4).ok_or("HTTP offset overflow")?;
    let body = &response[body_start..];
    if chunked { return decode_chunks(body, cap); }
    if length.is_some_and(|length| length != body.len()) { return Err("HTTP content length mismatch".into()); }
    if body.len() > cap { return Err("RPC response exceeds byte limit".into()); }
    Ok(body.to_vec())
}

fn decode_chunks(mut body: &[u8], cap: usize) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    loop {
        let end = body.windows(2).position(|w| w == b"\r\n").ok_or("missing chunk size delimiter")?;
        let size = std::str::from_utf8(&body[..end]).map_err(|_| "invalid chunk size")?;
        if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("invalid chunk size".into()); }
        let size = usize::from_str_radix(size, 16).map_err(|_| "chunk size overflow")?;
        body = &body[end.checked_add(2).ok_or("chunk offset overflow")?..];
        if size == 0 {
            if body != b"\r\n" { return Err("unsupported chunk trailers or trailing bytes".into()); }
            return Ok(decoded);
        }
        if decoded.len().checked_add(size).ok_or("chunk size overflow")? > cap { return Err("RPC response exceeds byte limit".into()); }
        let framed_size = size.checked_add(2).ok_or("chunk size overflow")?;
        if body.len() < framed_size || &body[size..framed_size] != b"\r\n" { return Err("truncated or malformed chunk".into()); }
        decoded.extend_from_slice(&body[..size]);
        body = &body[framed_size..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_are_bytes_and_utf8_is_decoded_only_after_reassembly() {
        assert_eq!(decode_chunks(b"1\r\n\xc3\r\n1\r\n\xa9\r\n0\r\n\r\n", 2).unwrap(), "é".as_bytes());
        for malformed in [b"1\r\n\xc3\xa9\r\n0\r\n\r\n".as_slice(), b"ffffffffffffffffffffffff\r\n", b"2\r\na\r\n0\r\n\r\n", b"+1\r\na\r\n0\r\n\r\n", b"0\r\n\r\nextra", b"1\r\na\r\n"] {
            assert!(decode_chunks(malformed, 8).is_err());
        }
        assert!(decode_chunks(b"2\r\nab\r\n0\r\n\r\n", 1).is_err());
    }

    #[test]
    fn rejects_ambiguous_lengths_truncation_and_body_reflection() {
        for response in [
            b"HTTP/1.1 +200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 0200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 999999999999999999999999\r\n\r\n",
        ] { assert!(decode_response(response, 8).is_err()); }
        let error = decode_response(b"HTTP/1.1 500 Failure\r\n\r\nprivate-peer-marker", 64).unwrap_err();
        assert_eq!(error, "HTTP status 500");
        assert_eq!(decode_response(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nab", 2).unwrap(), b"ab");
    }

    fn server(chunks: Vec<Vec<u8>>, interval: Duration) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut reader = std::io::BufReader::new(&mut stream);
            let mut body_len = 0;
            loop {
                let mut line = String::new();
                assert!(std::io::BufRead::read_line(&mut reader, &mut line).unwrap() > 0);
                if line == "\r\n" { break; }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    body_len = value.trim().parse::<usize>().unwrap();
                }
            }
            assert!(body_len < 4096);
            let mut request_body = vec![0; body_len];
            reader.read_exact(&mut request_body).unwrap();
            drop(reader);
            for chunk in chunks {
                if stream.write_all(&chunk).is_err() { break; }
                std::thread::sleep(interval);
            }
        });
        (address, worker)
    }

    #[test]
    fn actual_reads_are_capped_and_slow_drip_cannot_reset_absolute_deadline() {
        let mut oversized = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        oversized.extend(vec![b'x'; MAX_HEADERS.saturating_add(1024)]);
        let (address, worker) = server(vec![oversized], Duration::ZERO);
        assert!(call_with_limits(&address, "test", &Value::Null, None, 8, Duration::from_secs(2)).is_err());
        worker.join().unwrap();
        let mut chunks = vec![b"HTTP/1.1 200 OK\r\n\r\n".to_vec()];
        chunks.extend((0..15).map(|_| vec![b' ']));
        let (address, worker) = server(chunks, Duration::from_millis(10));
        let start = Instant::now();
        let error = call_with_limits(&address, "test", &Value::Null, None, 1024, Duration::from_millis(50)).unwrap_err();
        assert!(error.contains("deadline"));
        assert!(start.elapsed() < Duration::from_secs(1));
        worker.join().unwrap();
    }

    #[test]
    fn real_chunked_json_preserves_split_utf8_and_api_key_controls_are_refused() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":""#;
        let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for chunk in [body.as_slice(), b"\xc3", b"\xa9", b"\"}"] {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let (address, worker) = server(vec![wire], Duration::ZERO);
        assert_eq!(call_with_limits(&address, "test", &Value::Null, None, 4096, Duration::from_secs(2)).unwrap(), "é");
        worker.join().unwrap();
        assert!(call("127.0.0.1:1", "test", &Value::Null, Some("key\r\ninjected")).unwrap_err().contains("control"));
    }

    #[test]
    fn real_json_errors_do_not_echo_peer_content() {
        for body in ["private-peer-marker", r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"private-peer-marker"}}"#] {
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            let (address, worker) = server(vec![response.into_bytes()], Duration::ZERO);
            let error = call_with_limits(&address, "test", &Value::Null, None, 4096, Duration::from_secs(2)).unwrap_err();
            assert!(!error.contains("private-peer-marker"));
            worker.join().unwrap();
        }
    }
}
