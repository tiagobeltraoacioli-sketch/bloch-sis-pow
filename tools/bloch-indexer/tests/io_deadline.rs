// SPDX-License-Identifier: AGPL-3.0-or-later
#[path = "../src/io_deadline.rs"]
mod io_deadline;

use io_deadline::DeadlineStream;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = listener.accept().unwrap().0;
    (client, server)
}

#[test]
fn trickling_bytes_does_not_renew_read_deadline() {
    let (mut client, server) = sockets();
    let writer = std::thread::spawn(move || {
        for _ in 0..100 {
            if client.write_all(b"x").is_err() { break; }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let started = Instant::now();
    let mut stream = DeadlineStream::new(&server, started + Duration::from_millis(150));
    let mut received = 0;
    loop {
        match stream.read(&mut [0; 1]) {
            Ok(1) => received += 1,
            Err(error) => {
                assert!(matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock));
                break;
            }
            other => panic!("unexpected read: {other:?}"),
        }
    }
    assert!(received > 0 && received < 100);
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(server);
    writer.join().unwrap();
}

#[test]
fn nonreading_client_cannot_hold_a_writer_indefinitely() {
    let (_client, server) = sockets();
    let started = Instant::now();
    let mut stream = DeadlineStream::new(&server, started + Duration::from_millis(150));
    let chunk = [0; 64 * 1024];
    loop {
        if let Err(error) = stream.write_all(&chunk) {
            assert!(matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock));
            break;
        }
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    let mut expired = DeadlineStream::new(&server, Instant::now());
    assert_eq!(expired.flush().unwrap_err().kind(), std::io::ErrorKind::TimedOut);
}
