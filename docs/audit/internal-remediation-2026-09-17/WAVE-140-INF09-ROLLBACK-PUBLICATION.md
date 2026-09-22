# Wave 140 — INF-09 rollback publication cleanup

Date: 2026-09-19
Comparison base: `3b408c57`

## Reproduced gap

Wave 137 moved tar creation and digest validation into private work storage,
but publication still moved the final tarball into the requested output
directory before copying its adjacent public key. A copy failure therefore
left an apparently complete tarball without the key operators need beside it.
Both final names could also overwrite an earlier rollback publication.

The assembler had no cleanup trap for those outputs or its private work
directory. An ordinary command failure between the two publication operations
could therefore leave ambiguous local evidence even though no invalid package
bytes or signature had been accepted.

## Correction

After signing, self-verification and private tarball digest validation, the
assembler now:

- refuses either pre-existing final tarball or public-key name, including a
  symlink;
- copies both inputs into exclusive `mktemp` names inside the output
  filesystem;
- hard-links the public key to its final name first and the tarball last,
  making the tarball the completion artifact while each `ln` atomically
  refuses an existing destination; and
- tracks only the temporary/final paths created by this invocation and removes
  a final name on failure only when `-ef` proves it still names the same inode
  as this invocation's temporary file.

The same cleanup trap removes the private work directory. On success it leaves
both final outputs untouched. Filenames, tarball bytes, adjacent public-key
bytes, signed manifest, trusted comment and verification flow are unchanged.

## Adversarial coverage

The disposable-key selftest places a delegating `ln` shim first on `PATH` and
injects failure exactly when the final tarball would be linked, after the
public key has reached its final name. The assembler must return nonzero and
leave the output directory empty, proving cleanup covers the final public key
and both temporary names.

A race fixture creates an unrelated final tarball immediately before that
same `ln`. Atomic no-overwrite publication must fail; inode-checked cleanup
must preserve the concurrent sentinel while removing the owned public key and
both temporary files.

Two independent collision fixtures pre-create the final tarball or public-key
name with sentinel bytes. Assembly must refuse each collision, preserve the
sentinel exactly and create no additional output. The complete SHA contract,
signature/tamper, wrong-key, pasted-signature, self-mutating input and
verify-only matrix remains active.

## Validation

```text
bash -n deploy/rollback/make-rollback-package.sh
bash -n deploy/rollback/make-rollback-package.selftest.sh
# passed

bash deploy/rollback/make-rollback-package.selftest.sh
# not run end to end locally: minisign is absent and the selftest fails closed
# before key generation

# A temporary non-signing minisign shim was used only to reach the publication
# fixtures. The injected final-tarball failure left OUTDIR empty; the raced
# final tarball survived unchanged as the only output; and both pre-existing
# collision cases preserved their sole sentinel without additional output.
# The later authentication matrix predictably fails under that shim; this is
# not claimed as a substitute for the complete disposable-key selftest above.
```

## Residual boundary

This is bounded cleanup for failures observed by the shell, not an atomic
multi-file transaction. `SIGKILL`, host power loss, kernel failure or a
filesystem that violates link/write guarantees can still leave a temporary
or public-key-only residue. A concurrent actor can also race after the
collision preflight, but final-name creation is no-overwrite and cleanup will
not remove a different inode. Operators must treat the final tarball as the
completion artifact and discard any other residue. Filesystems that do not
support hard links fail closed instead of publishing the pair.

This does not authenticate the assembler host, checksum/minisign executables,
source binary, signing key or artifact store. Release-key custody,
scratch-systemd rehearsal, staged N-1 availability, rollback execution and
fleet state remain external release gates. INF-09 remains `PARTIAL`.
