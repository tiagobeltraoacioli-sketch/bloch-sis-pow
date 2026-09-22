# Coherence SP1 prover candidate

This is an experimental off-chain proving service and Linux/amd64 build recipe.
It has not been qualified in a Linux container or on a GPU in this audit session.
The shared V1 spend statement does not prove recipient authorization: read
[the activation blocker](../../crates/coherence-prover/AUTHORIZATION-BLOCKER.md).
Do not accept funded shielded deposits or treat a successful proof as repairing
that statement. Rebuilding changes the guest artifact and requires separately
reviewed verifier identity and activation handling.

## Build inputs

The recipe pins Rust, CUDA base images, SP1 CLI 4.2.1 and the compatible
`succinct-1.85.0` guest toolchain. The downloaded guest toolchain is checked
against a committed SHA256 before extraction. There are no downloaded shell
installers. An explicit source/context allowlist excludes host-generated ELFs,
keys and unrelated repository content. See [input provenance](BUILD-INPUTS.md).

The guest is a standalone workspace with its own committed lockfile. Its build
names the ELF path consumed by the service and verifies that the lockfile did
not change. The service is another standalone workspace; its manifest and output
directory are passed explicitly. The root workspace excludes it.

```sh
# Run on an appropriately provisioned isolated build host; not validated here.
docker build --platform linux/amd64 \
  -f deploy/sp1-prover/Dockerfile \
  --build-arg PROVER_BACKEND=cuda \
  -t coherence-prover-candidate .
```

`PROVER_BACKEND=cpu` builds the CPU backend using the same pinned CUDA base
images. It does not silently replace the compiler/base images or qualify CPU
performance. Other backend values fail. The old `CUDA_FEATURE` argument is no
longer used; build automation must select the explicit backend argument.

## Operational boundaries

The service exposes `/health`, `/prove` and `/verify`. `/prove` receives the
complete private witness, and a valid proof only establishes the statement
implemented by the pinned guest. Proving infrastructure therefore sees witness
secrets even though a verifier should receive only proof/public inputs.

Release builds require the configured bearer token and refuse debug auth/TLS
bypasses. The `x-forwarded-proto` check is meaningful only behind a trusted TLS
proxy with the origin inaccessible directly; it is not TLS inside the process.
Both `/prove` and `/verify` check the existing bearer/TLS policy before parsing
JSON; `/health` remains public. Native prove/verify jobs run behind worker slots retained until
the work finishes, even when the HTTP request times out. A timeout does not kill
native work and shutdown can wait for it. Proof encoding and decoding share the
existing fixed-integer wire format and a 16 MiB serialized-proof budget; trailing
bytes are refused. Body/proof byte limits do not bound total memory or CPU use.

The runtime uses UID/GID 10001 and `/data` as HOME, with `/data/.sp1` for tool
artifacts. A mounted volume must be provisioned writable for that identity;
mounting a root-owned volume hides the image's ownership settings. Existing
Fly configuration is a candidate configuration, not a claim of deployed GPU
availability, cost, cold-start time or end-to-end qualification.

Before deployment, independently qualify the container build, ELF/verifier
identity, real proof/verification paths, resource behavior, private-origin TLS,
authentication and volume ownership. The funded-statement blocker must be
resolved through a reviewed versioned upgrade. This change publishes nothing.
