# Public record for a controlled mainnet validator test

Use a separately designated test identity. Do not exit an existing fleet
validator as a substitute. The funding owner selects the public inputs and
approves the deposit before the custodians sign privately.

Copy this template to `public-record.json` and replace every placeholder.
Only public metadata belongs here. Never include private keys, passwords,
sealed keystore contents or RANDAO seeds.

```json
{
  "network_domain": "f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966",
  "funding_pubkey": "FULL_LOWERCASE_SUITE_1_PUBLIC_KEY_HEX",
  "validator_pubkey": "FULL_LOWERCASE_SUITE_1_PUBLIC_KEY_HEX",
  "randao_commitment": "LOWERCASE_HEX32_PUBLIC_COMMITMENT",
  "withdrawal_script": "LOWERCASE_HEX32_WITHDRAWAL_CREDENTIAL",
  "change_script": "LOWERCASE_HEX32_APPROVED_CHANGE_SCRIPT",
  "stake_sat": "2500000000000",
  "fee_cap_sat": "OWNER_APPROVED_POSITIVE_DECIMAL_LIMIT",
  "inputs": [
    {
      "txid": "LOWERCASE_HEX32_FUNDING_TRANSACTION_ID",
      "vout": 0,
      "value_sat": "OBSERVED_POSITIVE_DECIMAL_VALUE",
      "script_hash": "FULL_SHA3_256_OF_FUNDING_PUBLIC_KEY"
    }
  ]
}
```

Run `python3 scripts/check-admission-public-record.py public-record.json`.
The checker rejects missing/unknown fields, duplicate JSON keys and funding
outpoints, incorrect network, malformed suite envelopes, zero commitments,
incorrect funding scripts and totals below stake plus the approved fee cap.
It prints a summary and the input file hash only after structural validation.
The fee cap is an owner-supplied upper bound, not a fee estimate.

This check neither validates public-key cryptography nor establishes funds,
ownership, maturity, registry uniqueness or admission. It makes no RPC requests
and cannot sign or submit. Confirm every outpoint on synchronized nodes,
verify the new validator identity is not already registered, and prepare and
inspect the deposit using the official offline CLI. Custodians must approve
all outputs, fee limits, expiry and genesis before signing. Retain subsequent
inclusion, finality, activation and duty evidence separately.

Run the synthetic tests with
`python3 scripts/test-admission-public-record.py`. The test public-key bytes
are deliberately synthetic; passing structural checks is not a cryptographic
qualification or permission to use a key in production.
