// SPDX-License-Identifier: AGPL-3.0-or-later
//! Audit L1N-04: a mesh reader's buffer grows with the bytes a connection
//! delivered, not with the length it announced.
use super::*;
use std::io::Write as _;

/// A deterministic payload, so a misplaced chunk shows.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8).collect()
}

/// Announcing the largest frame costs nothing; each step of buffer is paid
/// for with the bytes of the step before it.
#[test]
fn the_buffer_follows_the_bytes_received_not_the_announcement() {
    let len = crate::codec::MAX_FIELD_LEN;
    let source = pattern(len);
    let mut frame = AnnouncedFrame::new(len);
    assert_eq!(frame.capacity(), 0, "four bytes of length prefix buy no buffer");
    let mut delivered = 0usize;
    let mut steps = 0usize;
    loop {
        // What the reader holds while it waits for the next chunk.
        let Some(chunk) = frame.next_chunk() else { break };
        let take = chunk.len();
        assert!(take > 0 && take <= FRAME_READ_STEP, "a chunk is at most one step ({take})");
        chunk.copy_from_slice(&source[delivered..delivered + take]);
        let waiting_for = delivered + take;
        delivered = waiting_for;
        steps += 1;
        let capacity = frame.capacity();
        assert!(capacity <= len, "never more than was announced");
        assert!(
            capacity <= (2 * waiting_for).max(FRAME_READ_STEP),
            "step {steps}: {capacity} bytes of buffer for {waiting_for} bytes received or being received",
        );
    }
    assert_eq!(steps, len.div_ceil(FRAME_READ_STEP));
    assert_eq!(delivered, len);
    assert!(frame.next_chunk().is_none());
    assert!(frame.finish() == source, "the frame is the bytes, in order");
}

/// A connection that announces the largest frame and sends one step of it:
/// the reader holds one step, not eight mebibytes.
#[test]
fn an_announced_frame_that_never_arrives_holds_one_step() {
    let mut frame = AnnouncedFrame::new(crate::codec::MAX_FIELD_LEN);
    let first = frame.next_chunk().expect("the first chunk").len();
    assert_eq!(first, FRAME_READ_STEP);
    assert_eq!(frame.capacity(), FRAME_READ_STEP);
    // The second chunk is only asked for once the first was filled.
    let _ = frame.next_chunk().expect("the second chunk");
    assert_eq!(frame.capacity(), 2 * FRAME_READ_STEP);
}

/// Wire compatibility: frames of every size around a step boundary are read
/// back byte for byte through the real reader, and a bad length is refused
/// as before.
#[test]
fn frames_are_read_back_unchanged_across_step_boundaries() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut writer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut reader, _) = listener.accept().unwrap();
    let sizes = [1, 9, FRAME_READ_STEP - 1, FRAME_READ_STEP, FRAME_READ_STEP + 1, 3 * FRAME_READ_STEP + 17];
    let frames: Vec<Vec<u8>> = sizes.iter().map(|len| pattern(*len)).collect();
    let sent = frames.clone();
    let sender = thread::spawn(move || {
        for frame in &sent {
            write_frame(&mut writer, frame).unwrap();
        }
        // Then a length past the ceiling, and a zero length.
        writer.write_all(&((crate::codec::MAX_FIELD_LEN as u32) + 1).to_le_bytes()).unwrap();
        writer
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    for (n, frame) in frames.iter().enumerate() {
        let read = read_frame_until(&mut reader, deadline).unwrap();
        assert!(read == *frame, "frame {n} ({} bytes) differs", frame.len());
        assert_eq!(read.capacity(), frame.len(), "frame {n}: no slack is kept beyond the frame");
    }
    let refused = read_frame_until(&mut reader, deadline).unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData);
    drop(sender.join().unwrap());
}

/// An incomplete frame is still an error under the frame's one deadline.
#[test]
fn an_incomplete_frame_times_out_under_one_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut writer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut reader, _) = listener.accept().unwrap();
    writer.write_all(&(crate::codec::MAX_FIELD_LEN as u32).to_le_bytes()).unwrap();
    writer.write_all(&pattern(FRAME_READ_STEP + 5)).unwrap();
    let started = Instant::now();
    let refused = read_frame_until(&mut reader, started + Duration::from_millis(400)).unwrap_err();
    assert!(matches!(refused.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock), "{refused:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}
