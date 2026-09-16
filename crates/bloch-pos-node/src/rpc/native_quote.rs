use super::*;
use bloch_pos_committee::transition::native_dex::lab_quote::{Operation, Query};
pub(super) fn parse(params: Option<&Json>) -> Result<([u8; 32], Query), RpcError> {
    let Some(Json::Arr(args)) = params else {
        return Err(RpcError::invalid_params("expected one quote object"));
    };
    let [Json::Obj(fields)] = args.as_slice() else {
        return Err(RpcError::invalid_params("expected one quote object"));
    };
    let object = &args[0];
    let string = |name: &str| {
        object
            .get(name)
            .and_then(Json::as_str)
            .ok_or_else(|| RpcError::invalid_params(format!("missing string {name}")))
    };
    let number = |name: &str| -> Result<u64, RpcError> {
        let raw = string(name)?;
        if raw.is_empty()
            || !raw.bytes().all(|b| b.is_ascii_digit())
            || (raw.len() > 1 && raw.starts_with('0'))
        {
            return Err(RpcError::invalid_params(format!("invalid decimal {name}")));
        }
        raw.parse()
            .map_err(|_| RpcError::invalid_params(format!("overflow {name}")))
    };
    let hash = |name: &str| {
        hex32_from(string(name)?)
            .ok_or_else(|| RpcError::invalid_params(format!("invalid hash {name}")))
    };
    let operation = string("operation")?;
    let extras: &[&str] = match operation {
        "create-pair" => &["asset", "seed", "blchAmount", "nativeAmount"],
        "initialize" => &["reserve", "feeBps", "minimumLp"],
        "swap" => &["pool", "inputAsset", "amount", "minimumOut"],
        "withdraw" => {
            return Err(RpcError::invalid_params(
                "withdrawal requires independently authorized committee approvals",
            ))
        }
        _ => {
            return Err(RpcError::invalid_params(
                "unsupported laboratory builder operation",
            ))
        }
    };
    let mut seen = std::collections::BTreeSet::new();
    for (name, _) in fields {
        if !seen.insert(name)
            || (![
                "operation",
                "ownerPublicKeyHex",
                "expectedHead",
                "validUntil",
            ]
            .contains(&name.as_str())
                && !extras.contains(&name.as_str()))
        {
            return Err(RpcError::invalid_params("unknown or duplicate quote field"));
        }
    }
    let owner_hex = string("ownerPublicKeyHex")?;
    if owner_hex.len() > 16384 {
        return Err(RpcError::invalid_params("owner key exceeds limit"));
    }
    let owner = from_hex(owner_hex)
        .filter(|k| bloch_crypto::crypto::valid_native_hybrid_key(k))
        .ok_or_else(|| RpcError::invalid_params("invalid hybrid owner key"))?;
    let query = Query {
        owner,
        valid_until: number("validUntil")?,
        operation: match operation {
            "create-pair" => Operation::CreatePair {
                asset: hash("asset")?,
                seed: hash("seed")?,
                blch_amount: number("blchAmount")?,
                native_amount: number("nativeAmount")?,
            },
            "initialize" => Operation::Initialize {
                reserve: hash("reserve")?,
                fee_bps: u16::try_from(number("feeBps")?)
                    .map_err(|_| RpcError::invalid_params("feeBps overflow"))?,
                minimum_lp: number("minimumLp")?,
            },
            "swap" => Operation::Swap {
                pool: hash("pool")?,
                input_asset: hash("inputAsset")?,
                amount: number("amount")?,
                minimum_out: number("minimumOut")?,
            },
            _ => unreachable!(),
        },
    };
    Ok((hash("expectedHead")?, query))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn laboratory_quote_params_require_typed_decimal_fields_and_exact_object() {
        let (key, _) = bloch_crypto::crypto::generate_keypair_from_seed(&[7; 32]).unwrap();
        let mut fields = vec![
            ("operation", Json::s("create-pair")),
            ("ownerPublicKeyHex", Json::s(crate::codec::hex(&key))),
            ("expectedHead", Json::hex(&[1; 32])),
            ("validUntil", Json::s("100")),
            ("asset", Json::hex(&[2; 32])),
            ("seed", Json::hex(&[3; 32])),
            ("blchAmount", Json::s("1000000")),
            ("nativeAmount", Json::s("60")),
        ];
        assert!(matches!(
            parse(Some(&Json::Arr(vec![Json::obj(fields.clone())]))),
            Ok((_, Query { .. }))
        ));
        assert!(parse(Some(&Json::obj(fields.clone()))).is_err());
        fields.push(("unexpected", Json::Bool(true)));
        assert!(parse(Some(&Json::Arr(vec![Json::obj(fields.clone())]))).is_err());
        fields.pop();
        fields[3].1 = Json::s("01");
        assert!(parse(Some(&Json::Arr(vec![Json::obj(fields.clone())]))).is_err());
        fields[3].1 = Json::Num("100".into());
        assert!(parse(Some(&Json::Arr(vec![Json::obj(fields.clone())]))).is_err());
        fields[0].1 = Json::s("withdraw");
        assert!(parse(Some(&Json::Arr(vec![Json::obj(fields)])))
            .unwrap_err()
            .message
            .contains("committee"));
    }
}

pub(super) fn parse_withdrawal(
    params: Option<&Json>,
) -> Result<
    (
        [u8; 32],
        bloch_pos_committee::transition::native_dex::lab_withdrawal::Query,
    ),
    RpcError,
> {
    use bloch_pos_committee::transition::native_dex::lab_withdrawal::Query;
    let Some(Json::Arr(args)) = params else {
        return Err(RpcError::invalid_params("expected one withdrawal object"));
    };
    let [Json::Obj(fields)] = args.as_slice() else {
        return Err(RpcError::invalid_params("expected one withdrawal object"));
    };
    let value = &args[0];
    let mut seen = std::collections::BTreeSet::new();
    for (name, _) in fields {
        if !seen.insert(name)
            || ![
                "ownerPublicKeyHex",
                "expectedHead",
                "route",
                "amount",
                "recipientHex20",
                "nonce",
                "validUntil",
            ]
            .contains(&name.as_str())
        {
            return Err(RpcError::invalid_params(
                "unknown or duplicate withdrawal field",
            ));
        }
    }
    let text = |name: &str| {
        value
            .get(name)
            .and_then(Json::as_str)
            .ok_or_else(|| RpcError::invalid_params(format!("missing string {name}")))
    };
    let number = |name: &str| -> Result<u64, RpcError> {
        let s = text(name)?;
        if s.is_empty()
            || !s.bytes().all(|b| b.is_ascii_digit())
            || (s.len() > 1 && s.starts_with('0'))
        {
            return Err(RpcError::invalid_params(format!("invalid decimal {name}")));
        }
        s.parse()
            .map_err(|_| RpcError::invalid_params(format!("overflow {name}")))
    };
    let hash = |name: &str| {
        hex32_from(text(name)?)
            .ok_or_else(|| RpcError::invalid_params(format!("invalid hash {name}")))
    };
    let owner = text("ownerPublicKeyHex")?;
    if owner.len() > 16384 {
        return Err(RpcError::invalid_params("owner exceeds limit"));
    }
    let owner = from_hex(owner)
        .filter(|k| bloch_crypto::crypto::valid_native_hybrid_key(k))
        .ok_or_else(|| RpcError::invalid_params("invalid hybrid owner key"))?;
    let recipient = text("recipientHex20")?;
    if recipient.len() != 40 {
        return Err(RpcError::invalid_params(
            "recipientHex20 must be exactly 20 bytes",
        ));
    }
    let recipient: [u8; 20] = from_hex(recipient)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| RpcError::invalid_params("invalid recipientHex20"))?;
    Ok((
        hash("expectedHead")?,
        Query {
            owner,
            route: hash("route")?,
            amount: number("amount")?,
            recipient,
            nonce: number("nonce")?,
            valid_until: number("validUntil")?,
        },
    ))
}
#[cfg(test)]
mod withdrawal_tests {
    use super::*;
    #[test]
    fn laboratory_withdrawal_requires_explicit_nonce_recipient_and_typed_amount() {
        let (key, _) = bloch_crypto::crypto::generate_keypair_from_seed(&[7; 32]).unwrap();
        let mut fields = vec![
            ("ownerPublicKeyHex", Json::s(crate::codec::hex(&key))),
            ("expectedHead", Json::hex(&[1; 32])),
            ("route", Json::hex(&[2; 32])),
            ("amount", Json::s("40")),
            ("recipientHex20", Json::s("0f".repeat(20))),
            ("nonce", Json::s("1")),
            ("validUntil", Json::s("100")),
        ];
        let (_, query) =
            parse_withdrawal(Some(&Json::Arr(vec![Json::obj(fields.clone())]))).unwrap();
        assert_eq!(
            (query.amount, query.nonce, query.recipient),
            (40, 1, [15; 20])
        );
        fields[4].1 = Json::s("0f".repeat(19));
        assert!(parse_withdrawal(Some(&Json::Arr(vec![Json::obj(fields.clone())]))).is_err());
        fields[4].1 = Json::s("0f".repeat(20));
        fields[3].1 = Json::Num("40".into());
        assert!(parse_withdrawal(Some(&Json::Arr(vec![Json::obj(fields.clone())]))).is_err());
        fields[3].1 = Json::s("40");
        fields.push(("nonce", Json::s("2")));
        assert!(parse_withdrawal(Some(&Json::Arr(vec![Json::obj(fields)]))).is_err());
    }
}
