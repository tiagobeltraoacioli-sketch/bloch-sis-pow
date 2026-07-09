// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stratum V2 Pool role static keypair (secp256k1 for NOISE_NX handshake).

use secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use super::Sv2Error;

#[derive(Debug)]
pub struct Sv2StaticKeypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

#[derive(Serialize, Deserialize)]
struct StoredKeypair {
    version:         u32,
    secret_hex:      String,
    public_hex:      String,
    fingerprint_hex: String,
    created_unix:    u64,
}

const STORED_KEYPAIR_VERSION: u32 = 1;

impl Sv2StaticKeypair {
    pub fn load_or_generate(path: &Path) -> Result<Self, Sv2Error> {
        if path.exists() {
            Self::load(path)
        } else {
            let kp = Self::generate()?;
            kp.save(path)?;
            Ok(kp)
        }
    }

    fn generate() -> Result<Self, Sv2Error> {
        let secp = Secp256k1::new();
        let (secret, public) = secp.generate_keypair(&mut rand::thread_rng());
        Ok(Self { secret, public })
    }

    fn load(path: &Path) -> Result<Self, Sv2Error> {
        let bytes = fs::read(path)
            .map_err(|e| Sv2Error::Keypair(format!("read {:?}: {}", path, e)))?;
        let stored: StoredKeypair = serde_json::from_slice(&bytes)
            .map_err(|e| Sv2Error::Keypair(format!("parse {:?}: {}", path, e)))?;
        if stored.version != STORED_KEYPAIR_VERSION {
            return Err(Sv2Error::Keypair(format!(
                "unsupported keypair version {} (expected {})",
                stored.version, STORED_KEYPAIR_VERSION
            )));
        }
        let secret_bytes = hex::decode(&stored.secret_hex)
            .map_err(|e| Sv2Error::Keypair(format!("secret hex: {}", e)))?;
        let secret = SecretKey::from_slice(&secret_bytes)
            .map_err(|e| Sv2Error::Keypair(format!("secret key: {}", e)))?;
        let secp = Secp256k1::new();
        let public = PublicKey::from_secret_key(&secp, &secret);
        Ok(Self { secret, public })
    }

    fn save(&self, path: &Path) -> Result<(), Sv2Error> {
        let stored = StoredKeypair {
            version:         STORED_KEYPAIR_VERSION,
            secret_hex:      hex::encode(self.secret.as_ref()),
            public_hex:      hex::encode(self.public.serialize()),
            fingerprint_hex: self.fingerprint_hex(),
            created_unix:    std::time::SystemTime::now()
                                 .duration_since(std::time::UNIX_EPOCH)
                                 .map(|d| d.as_secs())
                                 .unwrap_or(0),
        };
        let json = serde_json::to_vec_pretty(&stored)
            .map_err(|e| Sv2Error::Keypair(format!("serialize: {}", e)))?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| Sv2Error::Keypair(format!("mkdir {:?}: {}", parent, e)))?;
        }
        fs::write(path, json)
            .map_err(|e| Sv2Error::Keypair(format!("write {:?}: {}", path, e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
                log::warn!(
                    "stratum_v2: could not set 0600 on {:?}: {} (secure manually)",
                    path, e
                );
            }
        }
        Ok(())
    }

    pub fn fingerprint_hex(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.public.serialize());
        let digest = h.finalize();
        hex::encode(&digest[..8])
    }
}
