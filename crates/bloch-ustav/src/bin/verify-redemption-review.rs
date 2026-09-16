//! Bounded, versioned stdin protocol for the source observer. No signing or RPC.
use bloch_euvm::ustav::gateway::{Release, Route};
use bloch_ustav::dex_journal::{
    verify_exported_review, Checkpoint, ReviewCertificate, ReviewTrust,
};
use std::io::{self, Read};

const MAX_REQUEST: usize = 65_536;
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], ()> {
        let value = self.0.get(..n).ok_or(())?;
        self.0 = &self.0[n..];
        Ok(value)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ()> {
        self.bytes(N)?.try_into().map_err(|_| ())
    }
    fn number(&mut self) -> Result<u64, ()> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn blob(&mut self) -> Result<&'a [u8], ()> {
        let n = u32::from_be_bytes(self.fixed()?) as usize;
        self.bytes(n)
    }
}
fn verify(input: &[u8]) -> Result<[u8; 32], ()> {
    let mut r = Reader(input.strip_prefix(b"BLOCH-REVIEW-VERIFY-v1\0").ok_or(())?);
    let checkpoint = Checkpoint {
        height: r.number()?,
        root: r.fixed()?,
    };
    let current_height = r.number()?;
    let valid_until = r.number()?;
    let route = Route {
        source_domain: r.fixed()?,
        native_domain: r.fixed()?,
        native_asset: r.fixed()?,
        token: r.fixed()?,
        vault: r.fixed()?,
        decimals: 6,
        cap: r.number()?,
        vault_code_hash: [0; 32],
    };
    let release = Release {
        route: route.id(),
        nonce: r.number()?,
        recipient: r.fixed()?,
        amount: r.number()?,
        native_burn: r.fixed()?,
    };
    let authority = r.blob()?;
    let signature = r.blob()?;
    let preimage = r.blob()?;
    if !r.0.is_empty() {
        return Err(());
    }
    verify_exported_review(
        preimage,
        ReviewTrust {
            checkpoint,
            authority,
            current_height,
        },
        ReviewCertificate {
            valid_until,
            signature,
        },
        &route,
        &release,
    )
    .map_err(|_| ())
}
fn main() {
    let mut input = Vec::new();
    let result = io::stdin()
        .take((MAX_REQUEST + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| ())
        .and_then(|_| {
            if input.len() > MAX_REQUEST {
                Err(())
            } else {
                verify(&input)
            }
        });
    match result {
        Ok(commitment) => println!(
            "{}",
            commitment
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        Err(()) => {
            eprintln!("review-verification-refused");
            std::process::exit(1);
        }
    }
}
