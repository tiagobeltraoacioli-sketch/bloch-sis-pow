# Runtime hardening (Bloch-SIS-Linux L2)

L2 shrinks the node's attack surface. It has two tiers; this directory covers
the **container tier** (deliverable + testable today). The **OS tier**
(dm-verity immutable rootfs, measured boot) needs the bootable image build and
lands with the Nix/apko migration — see `docs/specs/BLOCH-SIS-LINUX.md §2.2`.

## Baked into the image (`Dockerfile`)

| Hardening | How |
|---|---|
| **Non-root** | Runs as uid/gid `10001` (`USER 10001:10001`); owns `/bloch-data` |
| **No core dumps** | Entrypoint runs `ulimit -c 0` before exec — a core dump can leak secret key material mid-execution (`docs/THREAT_MODEL.md`) |
| **No shell needed** | Distroless-ish `debian-slim`; only the node + CA certs |

These apply everywhere the image runs — Docker, Akash, Fly.

## Applied at runtime

Capabilities, privilege-escalation, and rootfs read-only-ness are set by the
**runtime**, not the image. Use the hardened compose file:

```bash
docker compose -f deploy/hardening/docker-compose.hardened.yml up -d
```

or an equivalent `docker run`:

```bash
docker run -d --name bloch \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp \
  --ulimit core=0 \
  -v bloch_data:/bloch-data \
  -p 16110:16110 -p 16210:16210 \
  bloch:local --mine
```

| Flag | Effect |
|---|---|
| `--cap-drop ALL` | Node binds ports > 1024, so it needs **zero** Linux capabilities |
| `--security-opt no-new-privileges` | Process can never gain privileges via setuid/fscaps |
| `--read-only --tmpfs /tmp` | Immutable rootfs; only the data volume + `/tmp` are writable |
| `--ulimit core=0` | Belt-and-suspenders core-dump block (also done at entrypoint) |
| (default) seccomp | Docker's default profile blocks ~44 dangerous syscalls |

## seccomp

Docker/containerd apply their **default seccomp profile** automatically — a
well-tested allowlist that already blocks the dangerous syscalls. A *custom*
tighter profile is deliberately **not** shipped by default: an over-tight
allowlist breaks RocksDB / tokio / libp2p and is a foot-gun. If you build one,
test it against a mining + syncing node before pinning it via
`--security-opt seccomp=<file>`.

## Akash / Fly

The **image-tier** hardening (non-root, no-core-dumps) applies automatically on
Akash and Fly. The **runtime-tier** flags (`cap_drop`, `no-new-privileges`,
read-only rootfs) are Docker/Compose features those platforms don't all expose;
the platforms provide their own isolation (Firecracker microVM on Fly, the
provider's k8s on Akash). Full control of the runtime hardening is a reason to
prefer the self-hosted / confidential-compute path (`BLOCH-SIS-LINUX.md`).

## Not covered here (OS tier, later)

dm-verity, measured boot, encrypted data volume, and attestation (L3) require
the bootable OS image and are tracked in `docs/specs/BLOCH-SIS-LINUX.md`.
