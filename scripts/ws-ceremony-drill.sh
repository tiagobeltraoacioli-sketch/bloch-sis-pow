#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ws-ceremony-drill.sh — rehearse the weak-subjectivity signing ceremony end
# to end with DISPOSABLE keys, then prove the refusals.
#
# "The ceremony works" is a claim about EXISTENCE. What an operator needs
# before convening three humans is a claim about VIGENCE: that THIS binary,
# today, produces an artifact that verifies AND refuses every artifact it must
# refuse. So the drill does both, and the refusals are the larger half.
#
# Two gates are exercised separately, because they are separate defences:
#   - the ASSEMBLER gate: `ws-envelope` runs ws::verify_envelope before it
#     writes anything, so a bad envelope never becomes a file here;
#   - the VERIFIER gate: `ws-verify` refuses an envelope forged outside this
#     toolchain. Every dishonest envelope below is therefore FORGED BY BYTE
#     SURGERY, not built by the tool — otherwise the drill would only be
#     testing that the tool refuses to hurt itself.
#
#   ./scripts/ws-ceremony-drill.sh /path/to/bloch-pos [workdir]
#
# NEVER run this with production key material. Every key it touches is
# generated inside the workdir. It reads two archival RPCs and writes nothing
# outside the workdir.

set -u

BIN="${1:?usage: ws-ceremony-drill.sh <bloch-pos binary> [workdir]}"
WORK="${2:-$(mktemp -d "${TMPDIR:-/tmp}/ws-drill.XXXXXX")}"
mkdir -p "$WORK"
MANIFEST="${MANIFEST:-genesis/mainnet.manifest}"
CP_BIN="${CP_BIN:-checkpoints/wscheckpoint-1536.bin}"
RPCS="${WS_RPC:-139.180.166.5:8080,139.180.173.231:8080}"

pass=0; fail=0
say() { printf '\n──────── %s\n' "$*"; }

expect_ok() { # expect_ok <label> -- <cmd...>
  local label="$1"; shift; [ "${1:-}" = "--" ] && shift
  local out rc; out="$("$@" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    pass=$((pass+1)); printf 'PASS  %s\n' "$label"
    printf '%s\n' "$out" | sed 's/^/      | /'
  else
    fail=$((fail+1)); printf 'FAIL  %s (expected success, rc=%d)\n' "$label" $rc
    printf '%s\n' "$out" | sed 's/^/      | /'
  fi
}

expect_refusal() { # expect_refusal <label> <substring> -- <cmd...>
  # A refusal must be BOTH a non-zero exit AND the named reason. Failing for
  # some other reason is not a demonstration, it is only a failure.
  local label="$1" want="$2"; shift 2; [ "${1:-}" = "--" ] && shift
  local out rc; out="$("$@" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    fail=$((fail+1)); printf 'FAIL  %s — ACCEPTED what it must refuse\n' "$label"
    printf '%s\n' "$out" | sed 's/^/      | /'
  elif printf '%s' "$out" | grep -q -- "$want"; then
    pass=$((pass+1))
    printf 'PASS  %s\n' "$label"
    printf '%s' "$out" | grep -- "$want" | head -2 | sed 's/^/      refused: /'
  else
    fail=$((fail+1)); printf 'FAIL  %s — refused, but not for `%s`\n' "$label" "$want"
    printf '%s\n' "$out" | sed 's/^/      | /'
  fi
}

# ── byte-level forgery helpers ─────────────────────────────────────────────
# Envelope file  = "BPOSWSE1" ‖ checkpoint[154] ‖ u32 count ‖ (u8 idx ‖ u32 len ‖ sig)*
# Checkpoint[154]= version u16 @0 ‖ network u32 @2 ‖ genesis_root @6 ‖ epoch u64 @38
#                  ‖ block_root @46 ‖ state_root @78 ‖ validator_set_root @110
#                  ‖ issued_at u64 @142 ‖ signer_set_id u32 @150
forge() { # forge <out> <cp.bin> <idx:sigfile>...
  python3 - "$@" <<'PY'
import sys, struct
out, cp = sys.argv[1], sys.argv[2]
b = bytearray(b"BPOSWSE1") + open(cp,'rb').read()
sigs = sys.argv[3:]
b += struct.pack('<I', len(sigs))
for s in sigs:
    idx, path = s.split(':', 1)
    blob = open(path, 'rb').read()
    if blob[:8] == b"BPOSWSP1":
        # BPOSWSP1 ‖ digest[32] ‖ idx u8 ‖ u32 len ‖ sig
        n = struct.unpack('<I', blob[41:45])[0]
        raw = blob[45:45+n]
    else:
        raw = bytes.fromhex(blob.decode().strip())
    b += bytes([int(idx)]) + struct.pack('<I', len(raw)) + raw
open(out,'wb').write(bytes(b))
PY
}

tweak() { # tweak <in.bin> <out.bin> <offset> <hexbytes> — patch a checkpoint
  python3 - "$@" <<'PY'
import sys
src, dst, off, hexb = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
b = bytearray(open(src,'rb').read()); v = bytes.fromhex(hexb)
b[off:off+len(v)] = v
open(dst,'wb').write(bytes(b))
PY
}

say "0. what is under test"
"$BIN" --version
# Two copies of ws_tool.rs exist in this repository's history. The hardened
# one makes `ws-envelope` require --signer-set and refuse to WRITE an envelope
# a node would reject; the older one is a file concatenator. The drill adapts,
# and says which it found, because a green run means different things.
if "$BIN" ws-envelope --checkpoint "$CP_BIN" --out /dev/null 2>&1 \
     | grep -q -- "--signer-set is required"; then
  HARDENED=1; echo "ws_tool  : HARDENED (ws-envelope gates on ws::verify_envelope)"
else
  HARDENED=0
  echo "ws_tool  : UNHARDENED (ws-envelope writes whatever it is given)"
  echo "           section 3 is SKIPPED — this build has no assembler gate."
  echo "           Use the copy on branch converge/ws-tool for the real ceremony."
fi
echo "binary   : $BIN"
echo "workdir  : $WORK"
echo "manifest : $MANIFEST"
echo "artifact : $CP_BIN"

# ═══════════════════════════════════════════════════════════════════════════
say "1. THE ARTIFACT — is the committed epoch-1536 checkpoint still the chain's?"
# Read-only, against two independently reachable archivals. --issued-at is
# pinned to the published value so the bytes are comparable at all; every
# other field is re-derived from the chain.
ISSUED="$(python3 -c "import json;print(json.load(open('${CP_BIN%.bin}.json'))['issued_at'])" 2>/dev/null || echo 1788185511)"
expect_ok "re-mint epoch 1536 from two archivals" -- \
  "$BIN" ws-checkpoint --genesis "$MANIFEST" --rpc "$RPCS" \
    --epoch 1536 --signer-set-id 1 --issued-at "$ISSUED" --out "$WORK/remint"
if cmp -s "$WORK/remint.bin" "$CP_BIN"; then
  pass=$((pass+1)); printf 'PASS  re-minted bytes are IDENTICAL to the committed artifact\n'
else
  fail=$((fail+1)); printf 'FAIL  re-minted bytes DIFFER from the committed artifact\n'
  cmp -l "$WORK/remint.bin" "$CP_BIN" | head | sed 's/^/      | /'
fi

# ═══════════════════════════════════════════════════════════════════════════
say "2. THE HAPPY PATH — three disposable signers, Phase A shape"
# In the real ceremony these three run on three DIFFERENT air-gapped machines
# and only the .pk travels. Running all three here is what makes this a drill.
for i in 0 1 2; do "$BIN" ws-keygen --out "$WORK/s$i" >/dev/null || exit 1; done
echo "three disposable keypairs: s0 internal, s1 internal, s2 external"

expect_ok "assemble the Phase A arrangement (2-of-3, >=1 external)" -- \
  "$BIN" ws-signer-set --id 1 --threshold 2 --min-external 1 --adopted-epoch 0 --current-epoch 1771 \
    --signer "$WORK/s0.pk:internal" --signer "$WORK/s1.pk:internal" \
    --signer "$WORK/s2.pk:external" --out "$WORK/set1.bin"

for i in 0 1 2; do
  "$BIN" ws-sign --key "$WORK/s$i.sk" --pubkey "$WORK/s$i.pk" \
    --checkpoint "$CP_BIN" --signer-index "$i" --out "$WORK/sig$i" >/dev/null || exit 1
done
echo "three signatures over the epoch-1536 ws digest"

if [ "$HARDENED" = 1 ]; then
  expect_ok "assemble the envelope (signer 0 + external signer 2)" -- \
    "$BIN" ws-envelope --checkpoint "$CP_BIN" --signer-set "$WORK/set1.bin" \
      --genesis "$MANIFEST" --sig "0:$WORK/sig0" --sig "2:$WORK/sig2" \
      --out "$WORK/env.bin"
else
  expect_ok "assemble the envelope (signer 0 + external signer 2)" -- \
    "$BIN" ws-envelope --checkpoint "$CP_BIN" \
      --sig "0:$WORK/sig0" --sig "2:$WORK/sig2" --out "$WORK/env.bin"
fi

expect_ok "VERIFY exactly as a booting node does" -- \
  "$BIN" ws-verify --envelope "$WORK/env.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST" --rpc "${RPCS%%,*}"

# ═══════════════════════════════════════════════════════════════════════════
if [ "$HARDENED" = 1 ]; then
say "3. THE ASSEMBLER GATE — the tool refuses to WRITE what a node would reject"

expect_refusal "assembling with one signature short" "QuorumNotReached" -- \
  "$BIN" ws-envelope --checkpoint "$CP_BIN" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST" --sig "2:$WORK/sig2" --out "$WORK/x1.bin"

expect_refusal "assembling a quorum of internal keys only" "ExternalQuorumNotReached" -- \
  "$BIN" ws-envelope --checkpoint "$CP_BIN" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST" --sig "0:$WORK/sig0" --sig "1:$WORK/sig1" \
    --out "$WORK/x2.bin"

# The partial carries the index it was signed as, so a mispairing is caught by
# the file disagreeing with the flag — before any cryptography, and with the
# slip named rather than reported as a bad signature.
expect_refusal "assembling with a mispaired signer index" "signed as signer index" -- \
  "$BIN" ws-envelope --checkpoint "$CP_BIN" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST" --sig "1:$WORK/sig0" --sig "2:$WORK/sig2" \
    --out "$WORK/x3.bin"

for f in "$WORK/x1.bin" "$WORK/x2.bin" "$WORK/x3.bin"; do
  if [ -e "$f" ]; then fail=$((fail+1)); printf 'FAIL  %s was written despite the refusal\n' "$f"
  else pass=$((pass+1)); printf 'PASS  %s does not exist — refused BEFORE touching disk\n' "$(basename "$f")"; fi
done

fi

# ═══════════════════════════════════════════════════════════════════════════
say "4. THE VERIFIER GATE — envelopes FORGED outside the toolchain"
# Everything below is assembled by the python forger above, exactly as an
# attacker with the published files would do it. The assembler's refusals are
# irrelevant here; only ws::verify_envelope stands between these and a node.

# (a) wrong block root — the identity the signers attested.
tweak "$CP_BIN" "$WORK/cp-badroot.bin" 46 "deadbeef"
forge "$WORK/f-badroot.bin" "$WORK/cp-badroot.bin" "0:$WORK/sig0" "2:$WORK/sig2"
expect_refusal "wrong block_root, signatures reused" "BadSignature" -- \
  "$BIN" ws-verify --envelope "$WORK/f-badroot.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (b) wrong state root, ONE byte — what checkpoint-sync verifies downloads against.
tweak "$CP_BIN" "$WORK/cp-badstate.bin" 78 "00"
forge "$WORK/f-badstate.bin" "$WORK/cp-badstate.bin" "0:$WORK/sig0" "2:$WORK/sig2"
expect_refusal "wrong state_root (a single byte)" "BadSignature" -- \
  "$BIN" ws-verify --envelope "$WORK/f-badstate.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (c) wrong epoch — 1536 relabelled 1792 without re-signing.
tweak "$CP_BIN" "$WORK/cp-badepoch.bin" 38 "0007000000000000"
forge "$WORK/f-badepoch.bin" "$WORK/cp-badepoch.bin" "0:$WORK/sig0" "2:$WORK/sig2"
expect_refusal "wrong epoch (1536 relabelled 1792)" "BadSignature" -- \
  "$BIN" ws-verify --envelope "$WORK/f-badepoch.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (d) one signature short.
forge "$WORK/f-one.bin" "$CP_BIN" "2:$WORK/sig2"
expect_refusal "one signature short of the threshold" "QuorumNotReached" -- \
  "$BIN" ws-verify --envelope "$WORK/f-one.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (e) a full quorum of internal keys — rule 4, the whole point of Phase A.
forge "$WORK/f-internal.bin" "$CP_BIN" "0:$WORK/sig0" "1:$WORK/sig1"
expect_refusal "2-of-3 with NO external signature" "ExternalQuorumNotReached" -- \
  "$BIN" ws-verify --envelope "$WORK/f-internal.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (f) a signature from a key that is not in the set at all.
"$BIN" ws-keygen --out "$WORK/outsider" >/dev/null
"$BIN" ws-sign --key "$WORK/outsider.sk" --pubkey "$WORK/outsider.pk" \
  --checkpoint "$CP_BIN" --signer-index 0 --out "$WORK/sig-out" >/dev/null
forge "$WORK/f-outsider.bin" "$CP_BIN" "0:$WORK/sig-out" "2:$WORK/sig2"
expect_refusal "a signature from a key NOT in the set" "BadSignature" -- \
  "$BIN" ws-verify --envelope "$WORK/f-outsider.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (g) the external signer counted twice to manufacture a quorum.
forge "$WORK/f-dup.bin" "$CP_BIN" "2:$WORK/sig2" "2:$WORK/sig2"
expect_refusal "the external signer counted twice" "DuplicateSigner" -- \
  "$BIN" ws-verify --envelope "$WORK/f-dup.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (h) a signer index outside the arrangement.
forge "$WORK/f-idx.bin" "$CP_BIN" "2:$WORK/sig2" "7:$WORK/sig0"
expect_refusal "a signer index outside the set" "UnknownSignerIndex" -- \
  "$BIN" ws-verify --envelope "$WORK/f-idx.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (i) a valid envelope verified against a different arrangement.
"$BIN" ws-signer-set --id 2 --threshold 2 --min-external 1 --adopted-epoch 0 --current-epoch 1771 \
  --signer "$WORK/s0.pk:internal" --signer "$WORK/s1.pk:internal" \
  --signer "$WORK/s2.pk:external" --out "$WORK/set2.bin" >/dev/null
expect_refusal "verified against the WRONG arrangement" "WrongSignerSet" -- \
  "$BIN" ws-verify --envelope "$WORK/env.bin" --signer-set "$WORK/set2.bin" \
    --genesis "$MANIFEST"

# (j) cross-chain replay: the reserved genesis arrangement id.
tweak "$CP_BIN" "$WORK/cp-ss0.bin" 150 "00000000"
forge "$WORK/f-ss0.bin" "$WORK/cp-ss0.bin" "0:$WORK/sig0" "2:$WORK/sig2"
expect_refusal "an envelope claiming the reserved genesis set id" "ReservedSignerSet" -- \
  "$BIN" ws-verify --envelope "$WORK/f-ss0.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (k) the reserved id cannot even be minted into an arrangement.
expect_refusal "minting signer-set id 0" "reserved" -- \
  "$BIN" ws-signer-set --id 0 --threshold 2 --min-external 1 --adopted-epoch 0 --current-epoch 1771 \
    --signer "$WORK/s0.pk:internal" --signer "$WORK/s1.pk:internal" \
    --signer "$WORK/s2.pk:external" --out "$WORK/set0.bin"

# (l) THE DEAD-MAN'S SWITCH. Adopted at epoch 0, an arrangement hard-stops at
#     41040 (365 days + 91 days of 16-minute epochs). A checkpoint beyond it is
#     refused even with a perfect quorum — because nobody reviewed the
#     arrangement. This is what --adopted-epoch actually controls.
tweak "$CP_BIN" "$WORK/cp-far.bin" 38 "50a0000000000000"   # epoch 41040
tweak "$WORK/cp-far.bin" "$WORK/cp-far1.bin" 38 "51a0000000000000"  # epoch 41041
for i in 0 2; do
  "$BIN" ws-sign --key "$WORK/s$i.sk" --pubkey "$WORK/s$i.pk" \
    --checkpoint "$WORK/cp-far.bin" --signer-index "$i" --out "$WORK/sigfar$i" >/dev/null
  "$BIN" ws-sign --key "$WORK/s$i.sk" --pubkey "$WORK/s$i.pk" \
    --checkpoint "$WORK/cp-far1.bin" --signer-index "$i" --out "$WORK/sigfar1$i" >/dev/null
done
forge "$WORK/f-at-hardstop.bin" "$WORK/cp-far.bin" "0:$WORK/sigfar0" "2:$WORK/sigfar2"
expect_ok "epoch 41040 — the last epoch the arrangement may sign" -- \
  "$BIN" ws-verify --envelope "$WORK/f-at-hardstop.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"
forge "$WORK/f-past-hardstop.bin" "$WORK/cp-far1.bin" "0:$WORK/sigfar10" "2:$WORK/sigfar12"
expect_refusal "epoch 41041 — one epoch past the hard stop, perfect quorum" "ArrangementExpired" -- \
  "$BIN" ws-verify --envelope "$WORK/f-past-hardstop.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (m) an epoch the chain has not finalized may never become an artifact.
expect_refusal "minting a checkpoint at an UNFINALIZED epoch" "NOT finalized" -- \
  "$BIN" ws-checkpoint --genesis "$MANIFEST" --rpc "$RPCS" \
    --epoch 99999 --signer-set-id 1 --out "$WORK/cp-future"

# (n) TRUNCATION and EXTENSION of the envelope file. Neither is a signature
#     forgery: the framing decoder is the gate, and it is strict at both ends
#     because a decoder that accepts `encode(x) ‖ junk` breaks the
#     encode→hash injectivity every digest comparison in this mechanism
#     depends on. Two artifacts that decode to the same envelope but have
#     different file bytes would make "compare the file across channels"
#     meaningless.
python3 - "$WORK/env.bin" "$WORK/f-truncated.bin" <<'PY'
import sys
b = open(sys.argv[1],'rb').read()
open(sys.argv[2],'wb').write(b[:-1])          # one byte short
PY
expect_refusal "an envelope truncated by one byte" "truncated" -- \
  "$BIN" ws-verify --envelope "$WORK/f-truncated.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

python3 - "$WORK/env.bin" "$WORK/f-extended.bin" <<'PY'
import sys
b = open(sys.argv[1],'rb').read()
open(sys.argv[2],'wb').write(b + b"\x00")     # one byte long
PY
expect_refusal "an envelope with one trailing byte appended" "trailing" -- \
  "$BIN" ws-verify --envelope "$WORK/f-extended.bin" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST"

# (o) A PARTIAL OVER A DIFFERENT ROOT. The signature is perfectly valid — it
#     attests a different block_root. Without the digest binding this reaches
#     the coordinator as `BadSignature`, which reads like a corrupt file; with
#     it, `ws::combine` names the signer who was shown the wrong artifact,
#     before any cryptography runs.
tweak "$CP_BIN" "$WORK/cp-otherroot.bin" 46 "cafebabe"
"$BIN" ws-sign --key "$WORK/s0.sk" --pubkey "$WORK/s0.pk" \
  --checkpoint "$WORK/cp-otherroot.bin" --signer-index 0 --out "$WORK/sig-otherroot" >/dev/null
expect_refusal "a partial signed over a DIFFERENT block_root" "DigestMismatch" -- \
  "$BIN" ws-envelope --checkpoint "$CP_BIN" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST" --sig "0:$WORK/sig-otherroot" --sig "2:$WORK/sig2" \
    --out "$WORK/x4.bin"

# (p) A PARTIAL FOR A DIFFERENT EPOCH — the recycling attack the every-256-epoch
#     cadence invites: last ceremony's signature, this ceremony's checkpoint.
tweak "$CP_BIN" "$WORK/cp-1280.bin" 38 "0005000000000000"   # epoch 1280
"$BIN" ws-sign --key "$WORK/s2.sk" --pubkey "$WORK/s2.pk" \
  --checkpoint "$WORK/cp-1280.bin" --signer-index 2 --out "$WORK/sig-1280" >/dev/null
expect_refusal "the external signer's partial from the PREVIOUS epoch" "DigestMismatch" -- \
  "$BIN" ws-envelope --checkpoint "$CP_BIN" --signer-set "$WORK/set1.bin" \
    --genesis "$MANIFEST" --sig "0:$WORK/sig0" --sig "2:$WORK/sig-1280" \
    --out "$WORK/x5.bin"

# (q1) THE 10^12 CASE — no arithmetic overflows, and the switch is still off.
#      10^12 epochs is ~30 million years of 16-minute epochs, so hard_stop()
#      is a perfectly ordinary number no checkpoint will ever exceed. This is
#      the shape the release lineage actually invites, because there is no
#      --adopted-epoch flag there at all: the field arrives in an
#      operator-supplied signer-set file with nothing checking it. What
#      refuses it is the arrangement window's LOWER bound.
python3 - "$WORK/set1.bin" "$WORK/set-far.bin" <<'PY'
import sys
b = bytearray(open(sys.argv[1],'rb').read())
b[20:28] = (10**12).to_bytes(8, 'little')      # adopted_epoch = 10^12
open(sys.argv[2],'wb').write(bytes(b))
PY
expect_refusal "a signer-set adopted at epoch 10^12 (nothing overflows)" "OutsideArrangementWindow" -- \
  "$BIN" ws-envelope --checkpoint "$CP_BIN" --signer-set "$WORK/set-far.bin" \
    --genesis "$MANIFEST" --sig "0:$WORK/sig0" --sig "2:$WORK/sig2" \
    --out "$WORK/x6.bin"

# (q) THE --adopted-epoch HAZARD. `hard_stop()` saturating_adds, so a value
#     near u64::MAX clamps BOTH the review deadline and the hard stop to
#     u64::MAX: the §6.3 dead-man's switch and the 12-month warning both
#     become unreachable comparisons, for the life of the arrangement, with
#     nothing about the resulting envelope looking any different. One
#     mistyped flag. Refused at three layers — the builder, the file decoder,
#     and ws::verify_envelope.
expect_refusal "--adopted-epoch u64::MAX (the mistyped flag)" "in the future" -- \
  "$BIN" ws-signer-set --id 1 --threshold 2 --min-external 1 \
    --adopted-epoch 18446744073709551615 --current-epoch 1771 \
    --signer "$WORK/s0.pk:internal" --signer "$WORK/s1.pk:internal" \
    --signer "$WORK/s2.pk:external" --out "$WORK/set-sat.bin"
expect_refusal "--adopted-epoch in the future" "future" -- \
  "$BIN" ws-signer-set --id 1 --threshold 2 --min-external 1 \
    --adopted-epoch 999999 --current-epoch 1771 \
    --signer "$WORK/s0.pk:internal" --signer "$WORK/s1.pk:internal" \
    --signer "$WORK/s2.pk:external" --out "$WORK/set-future.bin"
# Forged outside the toolchain: patch adopted_epoch to u64::MAX in a set file
# the builder already wrote. Signer-set file = "BPOSWSS1" ‖ id u32 @8 ‖
# threshold u32 @12 ‖ min_external u32 @16 ‖ adopted_epoch u64 @20.
python3 - "$WORK/set1.bin" "$WORK/set-sat-forged.bin" <<'PY'
import sys
b = bytearray(open(sys.argv[1],'rb').read())
b[20:28] = (2**64 - 1).to_bytes(8, 'little')
open(sys.argv[2],'wb').write(bytes(b))
PY
expect_refusal "a FORGED signer-set whose adopted_epoch saturates" "saturates" -- \
  "$BIN" ws-verify --envelope "$WORK/env.bin" --signer-set "$WORK/set-sat-forged.bin" \
    --genesis "$MANIFEST"

# (r) ONE KEY IN TWO SLOTS — the arrangement that is a 1-of-3 wearing a
#     2-of-3's clothes. `verify_envelope` counts distinct INDICES, not
#     distinct KEYS, so its holder signs once, lists the identical signature
#     at both indices, and every counting rule passes. The consensus rule
#     that closes it ships INERT (ws::WS_DISTINCT_KEYS_ENFORCED_FROM_EPOCH =
#     u64::MAX); what refuses it today is the tooling, at the point where an
#     arrangement is born.
expect_refusal "an arrangement seating ONE key in TWO slots" "SAME public key" -- \
  "$BIN" ws-signer-set --id 1 --threshold 2 --min-external 1 \
    --adopted-epoch 0 --current-epoch 1771 \
    --signer "$WORK/s0.pk:internal" --signer "$WORK/s1.pk:internal" \
    --signer "$WORK/s0.pk:external" --out "$WORK/set-dup.bin"

for f in "$WORK/x4.bin" "$WORK/x5.bin" "$WORK/x6.bin" "$WORK/set-sat.bin" "$WORK/set-future.bin" "$WORK/set-dup.bin"; do
  if [ -e "$f" ]; then fail=$((fail+1)); printf 'FAIL  %s was written despite the refusal\n' "$f"
  else pass=$((pass+1)); printf 'PASS  %s does not exist — refused BEFORE touching disk\n' "$(basename "$f")"; fi
done

# (s) a checkpoint older than the window. This is NOT an envelope rule — the
#     verifier has no clock and says so. The refusal lives at the boot gate,
#     and the freshness line is where a human is told before it bites.
say "5. STALENESS — refused at boot, not at verification"
echo "ws-verify has no clock of its own; --rpc/--now-epoch is what gives it one."
"$BIN" ws-verify --envelope "$WORK/env.bin" --signer-set "$WORK/set1.bin" \
  --genesis "$MANIFEST" --now-epoch 3600 2>&1 | grep -i "freshness\|VERDICT" | sed 's/^/      | /'
echo "the corresponding boot refusal is proven by:"
echo "      cargo test -p bloch-pos-node ws_boot -- --nocapture"
echo "      (genesis_anchor_expires_at_epoch_2016_and_a_1536_checkpoint_moves_it_to_3552)"

printf '\n──────── %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
