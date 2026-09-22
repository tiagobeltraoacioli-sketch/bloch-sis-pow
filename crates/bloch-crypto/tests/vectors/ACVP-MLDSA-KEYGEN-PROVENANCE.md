# Official NIST ACVP ML-DSA-65 key-pair sample

Source: NIST's ACVP-Server repository, commit
`975de31eb83d87039ec88934fdc47d8c312b892d`:

- [`prompt.json`](https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-keyGen-FIPS204/prompt.json),
  10,062 bytes,
  SHA-256 `43e81ad820e495dbcad086fe27c1008393a8c32100bbbff77c558c3f06dcefef`.
- [`expectedResults.json`](https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json),
  873,632 bytes, SHA-256
  `361f47ca19d592adcc66ff2cb591686ad785fea157b295648738bed6921a68df`.

The checked-in fixture selects only group 2 (`ML-DSA-65`) test case 26 and
retains its 32-byte seed plus expected public and secret keys. Its SHA-256 is
`d062ba074dda6ddf44b545e3612f82c36c231fe1f95cc5e5fc8c29a28f63b4f4`.

The regression parses the official key encodings, signs a repository-chosen
message through the compiled production ML-DSA backend, and verifies that
fresh signature through Bloch's empty-context wrapper. The signature is
randomized and is not an official expected value.

This evidence is deliberately limited. The test does **not** feed the official
seed into the backend's key generator and compare outputs, does not reproduce
a NIST sigGen signature, and is not a keygen or signing KAT. It demonstrates
interoperability between an official ACVP key pair and the production signing
and verification path. It is not ACVP certification or FIPS validation.
