//! Sprint A1 — Post-Quantum Transport Primitives Tests
//!
//! Covers:
//!   - Full authenticated handshake round-trip
//!   - Session keys derivation (both sides derive the same keys)
//!   - Stream cipher roundtrip + tamper detection + replay/reorder rejection
//!   - Frame protocol roundtrip + incomplete frame handling
//!   - Signature verification failure cases
//!   - MITM resistance (attacker swaps identity without valid signature)
//!   - Version gating
//!   - Nonce freshness per handshake
//!   - Confirmation MAC constant-time behavior (structural)

#[cfg(test)]
mod sprint_a1_tests {
    use bloch::transport::*;
    use bloch::crypto;

    fn make_identity() -> (Vec<u8>, Vec<u8>) {
        // crypto::generate_keypair returns (pk, sk)
        crypto::generate_keypair()
    }

    /// Run a full mutual-authenticated handshake including both confirmation
    /// messages. Returns the session keys on both sides.
    fn full_handshake() -> (SessionKeys, SessionKeys) {
        let (i_pk, i_sk) = make_identity();
        let (r_pk, r_sk) = make_identity();

        // 1. Initiator begins.
        let (init_state, init_msg) = Initiator::begin(&i_sk, &i_pk).unwrap();

        // 2. Responder processes init.
        let (pending_r, resp_msg) = PendingResponder::respond(&init_msg, &r_sk, &r_pk).unwrap();

        // 3. Initiator finishes — derives keys, produces confirmation.
        let completed = init_state.finish(&resp_msg, None).unwrap();

        // 4. Responder verifies initiator confirm, returns its own.
        let (r_keys, r_confirm) = pending_r.accept_confirmation(&completed.my_confirm).unwrap();

        // 5. Initiator verifies responder confirm.
        SessionKeys::verify_responder_confirmation(
            &completed.confirm_key,
            &completed.t2,
            &r_confirm,
        ).unwrap();

        (completed.keys, r_keys)
    }

    // ── Handshake correctness ─────────────────────────────────────────────

    #[test]
    fn handshake_produces_matching_stream_keys() {
        let (i, r) = full_handshake();
        assert_eq!(i.tx_key, r.rx_key, "initiator tx == responder rx");
        assert_eq!(i.rx_key, r.tx_key, "initiator rx == responder tx");
        assert_ne!(i.tx_key, i.rx_key, "directions must use different keys");
        assert!(i.is_initiator);
        assert!(!r.is_initiator);
    }

    #[test]
    fn handshake_with_correct_pin_succeeds() {
        let (i_pk, i_sk) = make_identity();
        let (r_pk, r_sk) = make_identity();

        let (init_state, init_msg) = Initiator::begin(&i_sk, &i_pk).unwrap();
        let (_, resp_msg) = PendingResponder::respond(&init_msg, &r_sk, &r_pk).unwrap();

        // Pin the actual responder identity → succeeds.
        let result = init_state.finish(&resp_msg, Some(&r_pk));
        assert!(result.is_ok());
    }

    #[test]
    fn handshake_with_wrong_pin_fails() {
        let (i_pk, i_sk) = make_identity();
        let (r_pk, r_sk) = make_identity();
        let (wrong_pk, _) = make_identity();

        let (init_state, init_msg) = Initiator::begin(&i_sk, &i_pk).unwrap();
        let (_, resp_msg) = PendingResponder::respond(&init_msg, &r_sk, &r_pk).unwrap();

        // Pin to someone else — must fail.
        assert!(matches!(init_state.finish(&resp_msg, Some(&wrong_pk)), Err(TransportError::IdentityMismatch)));
    }

    #[test]
    fn handshake_nonces_are_fresh() {
        let (pk, sk) = make_identity();
        let (_, msg1) = Initiator::begin(&sk, &pk).unwrap();
        let (_, msg2) = Initiator::begin(&sk, &pk).unwrap();
        assert_ne!(msg1.nonce, msg2.nonce);
    }

    // ── Signature verification ────────────────────────────────────────────

    #[test]
    fn bad_initiator_signature_rejected() {
        let (i_pk, i_sk) = make_identity();
        let (r_pk, r_sk) = make_identity();

        let (_, mut init_msg) = Initiator::begin(&i_sk, &i_pk).unwrap();
        init_msg.signature[0] ^= 0xff;

        assert!(matches!(PendingResponder::respond(&init_msg, &r_sk, &r_pk), Err(TransportError::BadInitiatorSignature)));
    }

    #[test]
    fn bad_responder_signature_rejected() {
        let (i_pk, i_sk) = make_identity();
        let (r_pk, r_sk) = make_identity();

        let (init_state, init_msg) = Initiator::begin(&i_sk, &i_pk).unwrap();
        let (_, mut resp_msg) = PendingResponder::respond(&init_msg, &r_sk, &r_pk).unwrap();
        resp_msg.signature[0] ^= 0xff;

        assert!(matches!(init_state.finish(&resp_msg, None), Err(TransportError::BadResponderSignature)));
    }

    #[test]
    fn mitm_without_valid_signature_fails() {
        // Attacker intercepts init, tries to replace identity_pk with their
        // own pubkey but doesn't have the initiator's sk to re-sign.
        // Responder's signature check must fail.
        let (i_pk, i_sk) = make_identity();
        let (attacker_pk, _attacker_sk) = make_identity();
        let (r_pk, r_sk) = make_identity();

        let (_, mut init_msg) = Initiator::begin(&i_sk, &i_pk).unwrap();

        // Attacker swaps identity_pk but keeps victim's signature.
        init_msg.identity_pk = attacker_pk;
        assert!(matches!(PendingResponder::respond(&init_msg, &r_sk, &r_pk), Err(TransportError::BadInitiatorSignature)));
    }

    #[test]
    fn version_mismatch_rejected() {
        let (i_pk, i_sk) = make_identity();
        let (r_pk, r_sk) = make_identity();

        let (_, mut init_msg) = Initiator::begin(&i_sk, &i_pk).unwrap();
        init_msg.version = 99;

        assert!(matches!(PendingResponder::respond(&init_msg, &r_sk, &r_pk), Err(TransportError::UnsupportedVersion(99))));
    }

    // ── Confirmation MAC ──────────────────────────────────────────────────

    #[test]
    fn bad_initiator_confirmation_rejected() {
        let (i_pk, i_sk) = make_identity();
        let (r_pk, r_sk) = make_identity();

        let (init_state, init_msg) = Initiator::begin(&i_sk, &i_pk).unwrap();
        let (pending_r, resp_msg) = PendingResponder::respond(&init_msg, &r_sk, &r_pk).unwrap();
        let completed = init_state.finish(&resp_msg, None).unwrap();

        // Tamper initiator's confirmation MAC.
        let mut bad_confirm = completed.my_confirm.clone();
        bad_confirm.mac[0] ^= 0xff;

        assert!(matches!(pending_r.accept_confirmation(&bad_confirm), Err(TransportError::BadConfirmation)));
    }

    #[test]
    fn bad_responder_confirmation_rejected_by_initiator() {
        let (i_pk, i_sk) = make_identity();
        let (r_pk, r_sk) = make_identity();

        let (init_state, init_msg) = Initiator::begin(&i_sk, &i_pk).unwrap();
        let (pending_r, resp_msg) = PendingResponder::respond(&init_msg, &r_sk, &r_pk).unwrap();
        let completed = init_state.finish(&resp_msg, None).unwrap();
        let (_, mut r_confirm) = pending_r.accept_confirmation(&completed.my_confirm).unwrap();

        // Tamper responder's confirmation.
        r_confirm.mac[0] ^= 0xff;

        let err = SessionKeys::verify_responder_confirmation(
            &completed.confirm_key,
            &completed.t2,
            &r_confirm,
        );
        assert!(matches!(err, Err(TransportError::BadConfirmation)));
    }

    // ── Stream cipher ─────────────────────────────────────────────────────

    #[test]
    fn stream_roundtrip_in_order() {
        let (i, r) = full_handshake();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        for n in 0..10 {
            let pt = format!("message {}", n);
            let ct = tx.seal(pt.as_bytes(), b"").unwrap();
            let decrypted = rx.open(&ct, b"").unwrap();
            assert_eq!(decrypted, pt.as_bytes());
        }
        assert_eq!(tx.counter(), 10);
        assert_eq!(rx.counter(), 10);
    }

    #[test]
    fn stream_rejects_replay() {
        let (i, r) = full_handshake();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        let ct1 = tx.seal(b"one", b"").unwrap();
        let ct2 = tx.seal(b"two", b"").unwrap();

        assert_eq!(rx.open(&ct1, b"").unwrap(), b"one");
        // Replay of ct1 now fails (counter advanced).
        assert!(rx.open(&ct1, b"").is_err());
        // Next-in-order still works.
        assert_eq!(rx.open(&ct2, b"").unwrap(), b"two");
    }

    #[test]
    fn stream_rejects_reorder() {
        let (i, r) = full_handshake();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        let _ct1 = tx.seal(b"one", b"").unwrap();
        let ct2 = tx.seal(b"two", b"").unwrap();

        // ct2 before ct1 → counter mismatch, AEAD fails.
        assert!(rx.open(&ct2, b"").is_err());
    }

    #[test]
    fn stream_rejects_tamper() {
        let (i, r) = full_handshake();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        let mut ct = tx.seal(b"hello", b"").unwrap();
        ct[0] ^= 0x01;
        assert!(rx.open(&ct, b"").is_err());
    }

    #[test]
    fn stream_aad_bound_into_tag() {
        let (i, r) = full_handshake();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx1 = RxStream::new(r.rx_key);
        let mut rx2 = RxStream::new(r.rx_key);

        let ct = tx.seal(b"msg", b"AAD-value").unwrap();

        // Right AAD decrypts.
        assert_eq!(rx1.open(&ct, b"AAD-value").unwrap(), b"msg");
        // Wrong AAD fails.
        assert!(rx2.open(&ct, b"different-AAD").is_err());
    }

    #[test]
    fn stream_wrong_key_fails() {
        let (i, _r) = full_handshake();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx_wrong = RxStream::new([42u8; STREAM_KEY_SIZE]);

        let ct = tx.seal(b"secret", b"").unwrap();
        assert!(rx_wrong.open(&ct, b"").is_err());
    }

    // ── Framing ───────────────────────────────────────────────────────────

    #[test]
    fn frame_roundtrip() {
        let (i, r) = full_handshake();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        let framed = frame_seal(&mut tx, b"framed payload").unwrap();
        assert!(framed.len() >= 4 + TAG_SIZE);

        let (consumed, pt) = frame_open(&mut rx, &framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(pt, b"framed payload");
    }

    #[test]
    fn frame_incomplete_buffer_returns_error() {
        let (i, _) = full_handshake();
        let mut tx = TxStream::new(i.tx_key);
        let framed = frame_seal(&mut tx, b"payload").unwrap();

        let mut rx = RxStream::new([0u8; STREAM_KEY_SIZE]);

        // Only 2 bytes: length prefix incomplete.
        assert!(matches!(frame_open(&mut rx, &framed[..2]), Err(TransportError::IncompleteFrame)));

        // Length complete but ciphertext truncated.
        assert!(matches!(frame_open(&mut rx, &framed[..6]), Err(TransportError::IncompleteFrame)));
    }

    #[test]
    fn frame_truncation_attack_fails() {
        // Attacker strips off the last byte of a framed message, leaving
        // length prefix intact. We arrive with ct_len bytes but the AEAD
        // tag check must catch the missing byte.
        let (i, r) = full_handshake();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        let mut framed = frame_seal(&mut tx, b"hello").unwrap();
        let original_len = framed.len();

        // Simulate attacker: rewrite length prefix to pretend the frame
        // is shorter than it is.
        let ct_len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        let new_ct_len = ct_len - 1;
        framed[..4].copy_from_slice(&(new_ct_len as u32).to_be_bytes());
        framed.truncate(4 + new_ct_len);
        assert_ne!(framed.len(), original_len);

        // Decryption must fail — AAD binding will mismatch.
        let result = frame_open(&mut rx, &framed);
        assert!(result.is_err());
    }

    // ── Multiple sequential handshakes ────────────────────────────────────

    #[test]
    fn independent_sessions_have_independent_keys() {
        let (i1, r1) = full_handshake();
        let (i2, r2) = full_handshake();

        assert_ne!(i1.tx_key, i2.tx_key, "fresh session must produce fresh keys");
        assert_ne!(r1.tx_key, r2.tx_key);

        // Cross-session keys don't work: ciphertext from session 1 can't
        // be decrypted by session 2's keys.
        let mut tx1 = TxStream::new(i1.tx_key);
        let mut rx2 = RxStream::new(r2.rx_key);
        let ct = tx1.seal(b"s1 msg", b"").unwrap();
        assert!(rx2.open(&ct, b"").is_err());
    }
}
