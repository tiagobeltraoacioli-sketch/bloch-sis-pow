//! Durable candidate replay for an explicitly enabled local DEX host.
//! No live block integration or authority to derive checkpoints from this log.
use crate::{BlochVerifier, Verifier};
use bloch_euvm::ustav::gateway::{self, Release};
use bloch_pos_committee::{
    transition::native_dex::{pool_batch, pool_candidate, State},
    SignatureVerifier,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const MAGIC: &[u8; 8] = b"BLCHDJ01";
const BOUND_MAGIC: &[u8; 8] = b"BLCHDJ02";
const HEADER_BYTES: u64 = 48; // magic, anchor height, anchor combined state root
pub const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RECORDS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub root: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailRecovery {
    Reject,
    DiscardIncomplete,
}
#[derive(Debug)]
pub enum Error {
    BaseRootsRequired,
    Io(io::Error),
    Locked,
    InvalidFile,
    InvalidHeader,
    WrongAnchor,
    WrongHead,
    UnknownRelease,
    InvalidLength,
    ResourceLimit,
    NonIncreasingHeight,
    Poisoned,
    StorageChanged,
    Incomplete { offset: u64 },
    Candidate(pool_candidate::Error),
    Gateway(gateway::Error),
}

/// One page from a healthy local journal at an exact checkpoint. Records are
/// borrowed, preventing journal mutation until the page's last use.
/// This is not consensus finality or an external payout authorization.
pub struct ReleasePage<'a> {
    checkpoint: Checkpoint,
    route: [u8; 32],
    records: Vec<&'a Release>,
}

/// A committed native release and asset accounting from the same local head.
/// The checkpoint must be independently trusted; this is not consensus proof.
pub struct RedemptionReview<'a> {
    checkpoint: Checkpoint,
    release: &'a Release,
    liabilities: gateway::AssetLiabilities,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewCertificateError {
    InvalidReview,
    WrongCheckpoint,
    InvalidAuthority,
    InvalidValidity,
    InvalidSignature,
}

/// Trust inputs must come from the operator's authenticated configuration/state,
/// never from the exported review or its certificate.
pub struct ReviewTrust<'a> {
    pub checkpoint: Checkpoint,
    pub authority: &'a [u8],
    pub current_height: u64,
}
pub struct ReviewCertificate<'a> {
    pub valid_until: u64,
    pub signature: &'a [u8],
}

/// Verify a bounded canonical export without access to the originating journal.
/// Returns the authenticated attestation commitment, not a finality/payment proof.
pub fn verify_exported_review(
    preimage: &[u8],
    trust: ReviewTrust<'_>,
    certificate: ReviewCertificate<'_>,
    expected_route: &gateway::Route,
    expected_release: &Release,
) -> Result<[u8; 32], ReviewCertificateError> {
    use ReviewCertificateError::InvalidReview;
    const TAG: &[u8] = b"BLOCH-REDEMPTION-REVIEW-v1\0";
    const FIXED: usize = TAG.len() + 8 + 32 + 32 + 32 + 8 + 16 + 16 + 32 + 4;
    const ROUTE_BYTES: usize = 32 + 32 + 20 + 20 + 16 + 16 + 8 + 8;
    if preimage.len() > FIXED + gateway::MAX_ROUTES * ROUTE_BYTES {
        return Err(InvalidReview);
    }
    struct Reader<'a>(&'a [u8]);
    impl Reader<'_> {
        fn take<const N: usize>(&mut self) -> Result<[u8; N], ReviewCertificateError> {
            let value = self
                .0
                .get(..N)
                .ok_or(InvalidReview)?
                .try_into()
                .map_err(|_| InvalidReview)?;
            self.0 = &self.0[N..];
            Ok(value)
        }
    }
    let mut reader = Reader(preimage.strip_prefix(TAG).ok_or(InvalidReview)?);
    let checkpoint = Checkpoint {
        height: u64::from_be_bytes(reader.take()?),
        root: reader.take()?,
    };
    if checkpoint != trust.checkpoint {
        return Err(ReviewCertificateError::WrongCheckpoint);
    }
    let native_domain = reader.take()?;
    let native_asset = reader.take()?;
    let native_supply = u64::from_be_bytes(reader.take()?);
    let imported = u128::from_be_bytes(reader.take()?);
    let burned = u128::from_be_bytes(reader.take()?);
    let release_id: [u8; 32] = reader.take()?;
    let count = u32::from_be_bytes(reader.take()?) as usize;
    if count == 0
        || count > gateway::MAX_ROUTES
        || reader.0.len() != count * ROUTE_BYTES
        || native_domain != expected_route.native_domain
        || native_asset != expected_route.native_asset
        || expected_route.decimals != 6
        || expected_route.cap == 0
        || expected_release.route != expected_route.id()
        || expected_release.id() != release_id
        || expected_release.amount == 0
        || expected_release.amount > expected_route.cap
        || expected_release.nonce == u64::MAX
        || expected_release.native_burn == [0; 32]
        || expected_release.recipient == [0; 20]
        || expected_release.recipient == expected_route.vault
        || expected_release.recipient == expected_route.token
    {
        return Err(InvalidReview);
    }
    let mut routes = Vec::with_capacity(count);
    let (mut imports, mut burns, mut supply) = (0u128, 0u128, 0u128);
    let mut previous = None;
    let mut matched = false;
    for _ in 0..count {
        let entry = gateway::RouteLiabilities {
            route: reader.take()?,
            source_domain: reader.take()?,
            token: reader.take()?,
            vault: reader.take()?,
            imported: u128::from_be_bytes(reader.take()?),
            burned: u128::from_be_bytes(reader.take()?),
            outstanding: u64::from_be_bytes(reader.take()?),
            release_count: u64::from_be_bytes(reader.take()?),
        };
        if previous.is_some_and(|id| entry.route <= id)
            || entry.imported.checked_sub(entry.burned) != Some(u128::from(entry.outstanding))
        {
            return Err(InvalidReview);
        }
        previous = Some(entry.route);
        imports = imports.checked_add(entry.imported).ok_or(InvalidReview)?;
        burns = burns.checked_add(entry.burned).ok_or(InvalidReview)?;
        supply = supply
            .checked_add(u128::from(entry.outstanding))
            .ok_or(InvalidReview)?;
        if entry.route == expected_release.route {
            if entry.source_domain != expected_route.source_domain
                || entry.token != expected_route.token
                || entry.vault != expected_route.vault
                || entry.outstanding > expected_route.cap
                || entry.burned < u128::from(expected_release.amount)
                || entry.release_count <= expected_release.nonce
            {
                return Err(InvalidReview);
            }
            matched = true;
        }
        routes.push(entry);
    }
    if !matched
        || imports != imported
        || burns != burned
        || supply != u128::from(native_supply)
        || imported.checked_sub(burned) != Some(supply)
    {
        return Err(InvalidReview);
    }
    let review = RedemptionReview {
        checkpoint,
        release: expected_release,
        liabilities: gateway::AssetLiabilities {
            native_domain,
            native_asset,
            native_supply,
            imported,
            burned,
            routes,
        },
    };
    if review.commitment_preimage() != preimage {
        return Err(InvalidReview);
    }
    review.verify_certificate(
        trust.checkpoint,
        trust.authority,
        trust.current_height,
        certificate.valid_until,
        certificate.signature,
    )?;
    Ok(review.commitment())
}

impl RedemptionReview<'_> {
    /// Message for an independently configured attestation authority to sign.
    /// No key is selected, generated or trusted by this method.
    pub fn certificate_message(
        &self,
        authority: &[u8],
        valid_until: u64,
    ) -> Result<[u8; 32], ReviewCertificateError> {
        use sha3::{Digest, Sha3_256};
        if !BlochVerifier.valid_pq_key(authority) {
            return Err(ReviewCertificateError::InvalidAuthority);
        }
        if valid_until < self.checkpoint.height {
            return Err(ReviewCertificateError::InvalidValidity);
        }
        let mut hash = Sha3_256::new();
        hash.update(b"BLOCH-REDEMPTION-ATTESTATION-v1\0");
        hash.update(self.commitment());
        hash.update(Sha3_256::digest(authority));
        hash.update(valid_until.to_be_bytes());
        Ok(hash.finalize().into())
    }

    /// Verify a review attestation against external trust inputs, not a key or
    /// checkpoint embedded in an untrusted certificate. The host supplies the
    /// current native height; validity is inclusive and never before the review.
    /// Success authenticates this attestation only, NOT finality or payment.
    pub fn verify_certificate(
        &self,
        trusted_checkpoint: Checkpoint,
        trusted_authority: &[u8],
        current_height: u64,
        valid_until: u64,
        signature: &[u8],
    ) -> Result<(), ReviewCertificateError> {
        if self.checkpoint != trusted_checkpoint {
            return Err(ReviewCertificateError::WrongCheckpoint);
        }
        if current_height < self.checkpoint.height || current_height > valid_until {
            return Err(ReviewCertificateError::InvalidValidity);
        }
        let message = self.certificate_message(trusted_authority, valid_until)?;
        if !BlochVerifier.verify_pq(&message, trusted_authority, signature) {
            return Err(ReviewCertificateError::InvalidSignature);
        }
        Ok(())
    }

    /// Canonical versioned bytes for independent commitment verification.
    /// This is an integrity identifier, not a certificate or payout permission.
    pub fn commitment_preimage(&self) -> Vec<u8> {
        let mut bytes = b"BLOCH-REDEMPTION-REVIEW-v1\0".to_vec();
        bytes.extend_from_slice(&self.checkpoint.height.to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint.root);
        bytes.extend_from_slice(&self.liabilities.native_domain);
        bytes.extend_from_slice(&self.liabilities.native_asset);
        bytes.extend_from_slice(&self.liabilities.native_supply.to_be_bytes());
        bytes.extend_from_slice(&self.liabilities.imported.to_be_bytes());
        bytes.extend_from_slice(&self.liabilities.burned.to_be_bytes());
        bytes.extend_from_slice(&self.release.id());
        // Only the journal constructs reviews; liabilities bounds this to MAX_ROUTES.
        bytes.extend_from_slice(&(self.liabilities.routes.len() as u32).to_be_bytes());
        for route in &self.liabilities.routes {
            bytes.extend_from_slice(&route.route);
            bytes.extend_from_slice(&route.source_domain);
            bytes.extend_from_slice(&route.token);
            bytes.extend_from_slice(&route.vault);
            bytes.extend_from_slice(&route.imported.to_be_bytes());
            bytes.extend_from_slice(&route.burned.to_be_bytes());
            bytes.extend_from_slice(&route.outstanding.to_be_bytes());
            bytes.extend_from_slice(&route.release_count.to_be_bytes());
        }
        bytes
    }
    /// SHA3-256 of commitment_preimage; distinct from the source release's SHA-256 ID.
    pub fn commitment(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        Sha3_256::digest(self.commitment_preimage()).into()
    }

    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }
    pub fn release(&self) -> &Release {
        self.release
    }
    pub fn liabilities(&self) -> &gateway::AssetLiabilities {
        &self.liabilities
    }
    /// Exact input schema for inspect-stablecoin-release.py. The exported JSON
    /// alone is NOT authenticated and contains no permission to settle a claim.
    /// u64 values remain decimal strings for lossless transport through browsers.
    pub fn observer_request_json(&self) -> String {
        fn hex(bytes: &[u8]) -> String {
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            let mut result = String::with_capacity(2 + bytes.len() * 2);
            result.push_str("0x");
            for byte in bytes {
                result.push(DIGITS[usize::from(byte >> 4)] as char);
                result.push(DIGITS[usize::from(byte & 15)] as char);
            }
            result
        }
        format!(
            "{{\"native_domain\":\"{}\",\"native_asset\":\"{}\",\"route_id\":\"{}\",\"nonce\":\"{}\",\"recipient\":\"{}\",\"amount\":\"{}\",\"native_burn\":\"{}\"}}",
            hex(&self.liabilities.native_domain), hex(&self.liabilities.native_asset),
            hex(&self.release.route), self.release.nonce, hex(&self.release.recipient),
            self.release.amount, hex(&self.release.native_burn),
        )
    }
}
impl ReleasePage<'_> {
    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }
    pub fn route(&self) -> &[u8; 32] {
        &self.route
    }
    pub fn records(&self) -> &[&Release] {
        &self.records
    }
    /// Use this exclusive cursor with the SAME checkpoint for the next page.
    /// None means this page is empty; a nonempty last page may require one final
    /// empty query to establish that traversal is complete at this checkpoint.
    pub fn next_after(&self) -> Option<u64> {
        self.records.last().map(|r| r.nonce)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub(super) struct BaseVerifier;
impl SignatureVerifier for BaseVerifier {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        BlochVerifier.verify_pq(root, key, signature)
    }
}

/// Owns the exclusive file lock and the only mutable host state.
/// File paths/directories must be controlled by the operator, not RPC clients.
pub struct Journal {
    file: File,
    header: [u8; HEADER_BYTES as usize],
    state: State,
    head: Checkpoint,
    length: u64,
    records: usize,
    poisoned: bool,
    require_base_roots: bool,
    recovered_tail_bytes: u64,
}
impl Journal {
    /// Create a new log from an independently authenticated anchor.
    pub fn create(path: &Path, state: State, height: u64) -> Result<Self, Error> {
        Self::create_with_policy(path, state, height, false)
    }

    /// Create a new journal that durably requires host BLCH root expectations.
    /// Existing files are never migrated or overwritten by this constructor.
    pub fn create_requiring_base_roots(
        path: &Path,
        state: State,
        height: u64,
    ) -> Result<Self, Error> {
        Self::create_with_policy(path, state, height, true)
    }

    fn create_with_policy(
        path: &Path,
        state: State,
        height: u64,
        require_base_roots: bool,
    ) -> Result<Self, Error> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.try_lock().map_err(|_| Error::Locked)?;
        let head = Checkpoint {
            height,
            root: state.state_root(),
        };
        let mut header = [0; HEADER_BYTES as usize];
        header[..8].copy_from_slice(if require_base_roots {
            BOUND_MAGIC
        } else {
            MAGIC
        });
        header[8..16].copy_from_slice(&height.to_le_bytes());
        header[16..].copy_from_slice(&head.root);
        file.write_all(&header)?;
        file.sync_all()?;
        // Persist creation of the directory entry as well as the file contents.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(Self {
            file,
            header,
            state,
            head,
            length: HEADER_BYTES,
            records: 0,
            poisoned: false,
            require_base_roots,
            recovered_tail_bytes: 0,
        })
    }

    /// Replay with real PQ verification and require an independently trusted tip.
    /// Recovery may discard only a physically incomplete final record, and only
    /// after the complete replayed prefix matches the trusted expected head.
    pub fn open(
        path: &Path,
        anchor: State,
        anchor_height: u64,
        expected_head: Checkpoint,
        recovery: TailRecovery,
    ) -> Result<Self, Error> {
        Self::open_with_policy(path, anchor, anchor_height, expected_head, recovery, false)
    }

    /// Require the bound format from independent host configuration, before any
    /// replay or tail recovery. Never silently accept a legacy/unbound journal.
    pub fn open_requiring_base_roots(
        path: &Path,
        anchor: State,
        anchor_height: u64,
        expected_head: Checkpoint,
        recovery: TailRecovery,
    ) -> Result<Self, Error> {
        Self::open_with_policy(path, anchor, anchor_height, expected_head, recovery, true)
    }

    fn open_with_policy(
        path: &Path,
        anchor: State,
        anchor_height: u64,
        expected_head: Checkpoint,
        recovery: TailRecovery,
        host_requires_base_roots: bool,
    ) -> Result<Self, Error> {
        if !std::fs::symlink_metadata(path)?.file_type().is_file() {
            return Err(Error::InvalidFile);
        }
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.try_lock().map_err(|_| Error::Locked)?;
        let length = file.metadata()?.len();
        if length > MAX_JOURNAL_BYTES {
            return Err(Error::ResourceLimit);
        }
        if length < HEADER_BYTES {
            return Err(Error::InvalidHeader);
        }
        let mut header = [0; HEADER_BYTES as usize];
        file.read_exact(&mut header)?;
        let require_base_roots = if &header[..8] == BOUND_MAGIC {
            true
        } else if &header[..8] == MAGIC {
            false
        } else {
            return Err(Error::InvalidHeader);
        };
        if host_requires_base_roots && !require_base_roots {
            return Err(Error::BaseRootsRequired);
        }
        if header[8..16] != anchor_height.to_le_bytes() || header[16..48] != anchor.state_root() {
            return Err(Error::WrongAnchor);
        }
        let mut journal = Self {
            file,
            header,
            head: Checkpoint {
                height: anchor_height,
                root: anchor.state_root(),
            },
            state: anchor,
            length: HEADER_BYTES,
            records: 0,
            poisoned: false,
            require_base_roots,
            recovered_tail_bytes: 0,
        };
        let mut incomplete = false;
        while journal.length < length {
            if journal.records == MAX_RECORDS {
                return Err(Error::ResourceLimit);
            }
            let remaining = length - journal.length;
            if remaining < 4 {
                incomplete = true;
                break;
            }
            let mut encoded_length = [0; 4];
            journal.file.read_exact(&mut encoded_length)?;
            let count = u32::from_le_bytes(encoded_length) as usize;
            if count == 0 || count > pool_candidate::MAX_ENCODED_BYTES {
                return Err(Error::InvalidLength);
            }
            if count as u64 > remaining - 4 {
                incomplete = true;
                break;
            }
            let mut candidate = vec![0; count];
            journal.file.read_exact(&mut candidate)?;
            let height = candidate_height(&candidate)?;
            if height <= journal.head.height {
                return Err(Error::NonIncreasingHeight);
            }
            let result = pool_candidate::apply(
                &mut journal.state,
                &candidate,
                height,
                &BaseVerifier,
                &BlochVerifier,
            )
            .map_err(Error::Candidate)?;
            journal.head = Checkpoint {
                height,
                root: result.post_root,
            };
            journal.length += 4 + count as u64;
            journal.records += 1;
        }
        if incomplete && recovery == TailRecovery::Reject {
            return Err(Error::Incomplete {
                offset: journal.length,
            });
        }
        if journal.head != expected_head {
            return Err(Error::WrongHead);
        }
        if incomplete {
            journal.file.set_len(journal.length)?;
            journal.file.sync_all()?;
            journal.recovered_tail_bytes = length - journal.length;
        }
        journal.file.seek(SeekFrom::Start(journal.length))?;
        Ok(journal)
    }

    pub(super) fn ensure_healthy(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Bytes removed by successful incomplete-tail recovery during this open.
    /// Zero for a new/clean journal; this is a local diagnostic, not finality.
    pub fn recovered_tail_bytes(&self) -> u64 {
        self.recovered_tail_bytes
    }

    /// Persisted admission policy, not proof that the file was authenticated.
    pub fn requires_base_roots(&self) -> bool {
        self.require_base_roots
    }

    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn checkpoint(&self) -> Checkpoint {
        self.head
    }

    /// Query persisted local releases only at the caller's pinned checkpoint.
    /// A changed height OR root requires restarting traversal. Failed writes
    /// disable this API until reopen/reconciliation, even though state() remains
    /// available for diagnostics.
    /// ```compile_fail
    /// use bloch_ustav::dex_journal::{Checkpoint, Journal};
    /// fn mutate(journal: &mut Journal, head: Checkpoint, route: &[u8; 32]) {
    ///     let page = journal.release_page(head, route, None, 1).unwrap();
    ///     journal.append(&[], head.height + 1);
    ///     println!("{}", page.records().len());
    /// }
    /// ```
    pub fn release_page(
        &self,
        expected: Checkpoint,
        route: &[u8; 32],
        after: Option<u64>,
        limit: usize,
    ) -> Result<ReleasePage<'_>, Error> {
        self.ensure_healthy()?;
        if self.head != expected {
            return Err(Error::WrongHead);
        }
        let records = self
            .state
            .native()
            .gateway()
            .releases_after(route, after, limit)
            .map_err(Error::Gateway)?;
        Ok(ReleasePage {
            checkpoint: self.head,
            route: *route,
            records,
        })
    }

    /// Return one committed release and all of its asset's route liabilities
    /// at the SAME expected head. Pending admission previews are not consulted.
    /// The borrowed review prevents mutation of this journal while in use.
    /// ```compile_fail
    /// use bloch_ustav::dex_journal::Journal;
    /// fn mutate(journal: &mut Journal, route: &[u8; 32], frame: &[u8]) {
    ///     let head = journal.checkpoint();
    ///     let review = journal.redemption_review(head, route, 0).unwrap();
    ///     journal.append(frame, head.height + 1).unwrap();
    ///     println!("{}", review.observer_request_json());
    /// }
    /// ```
    pub fn redemption_review(
        &self,
        expected: Checkpoint,
        route: &[u8; 32],
        nonce: u64,
    ) -> Result<RedemptionReview<'_>, Error> {
        self.ensure_healthy()?;
        if self.head != expected {
            return Err(Error::WrongHead);
        }
        let view = self.state.native().gateway();
        let asset = view
            .route(route)
            .ok_or(Error::Gateway(gateway::Error::UnknownRoute))?
            .config
            .route
            .native_asset;
        let release = view
            .release_record(route, nonce)
            .ok_or(Error::UnknownRelease)?;
        let liabilities = view.liabilities(&asset).map_err(Error::Gateway)?;
        Ok(RedemptionReview {
            checkpoint: self.head,
            release,
            liabilities,
        })
    }

    /// The host supplies the authenticated candidate height. Successful return
    /// follows fsync; any write/fsync failure poisons this handle until reopen.
    pub fn append(&mut self, candidate: &[u8], height: u64) -> Result<pool_batch::Outcome, Error> {
        self.append_checked(candidate, height, None)
    }

    /// Persist only after the candidate matches both independently supplied BLCH
    /// roots. The journal format is unchanged: replay authenticates the complete
    /// joint tip, not historical host root expectations. No consensus activation.
    pub fn append_with_base_roots(
        &mut self,
        candidate: &[u8],
        height: u64,
        roots: pool_candidate::BaseRoots,
    ) -> Result<pool_batch::Outcome, Error> {
        self.append_checked(candidate, height, Some(roots))
    }

    fn append_checked(
        &mut self,
        candidate: &[u8],
        height: u64,
        roots: Option<pool_candidate::BaseRoots>,
    ) -> Result<pool_batch::Outcome, Error> {
        self.ensure_healthy()?;
        if self.require_base_roots && roots.is_none() {
            return Err(Error::BaseRootsRequired);
        }
        if height <= self.head.height {
            return Err(Error::NonIncreasingHeight);
        }
        if candidate.len() > pool_candidate::MAX_ENCODED_BYTES || self.records == MAX_RECORDS {
            return Err(Error::ResourceLimit);
        }
        let next_length = self
            .length
            .checked_add(4 + candidate.len() as u64)
            .filter(|n| *n <= MAX_JOURNAL_BYTES)
            .ok_or(Error::ResourceLimit)?;
        check_storage_identity(
            &mut self.file,
            self.length,
            &self.header,
            &mut self.poisoned,
        )?;
        let prepared = match roots {
            Some(roots) => pool_candidate::prepare_with_base_roots(
                &mut self.state,
                candidate,
                height,
                roots,
                &BaseVerifier,
                &BlochVerifier,
            ),
            None => pool_candidate::prepare(
                &mut self.state,
                candidate,
                height,
                &BaseVerifier,
                &BlochVerifier,
            ),
        }
        .map_err(Error::Candidate)?;
        // Recheck after potentially expensive PQ verification as well.
        check_storage_identity(
            &mut self.file,
            self.length,
            &self.header,
            &mut self.poisoned,
        )?;
        persist_record(&mut self.file, prepared.candidate(), &mut self.poisoned)?;
        let result = prepared.commit();
        self.head = Checkpoint {
            height,
            root: result.post_root,
        };
        self.length = next_length;
        self.records += 1;
        Ok(result)
    }
}

// The candidate decoder rechecks magic, version, domain, context and all roots.
// The replayed final height/root must match the separately trusted checkpoint.
fn candidate_height(bytes: &[u8]) -> Result<u64, Error> {
    let value = bytes.get(74..82).ok_or(Error::InvalidLength)?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| Error::InvalidLength)?,
    ))
}

// Advisory locks cannot stop an uncooperative writer. Compare the fixed header
// and extent; same-length payload edits and concurrent races still need replay.
fn check_storage_identity(
    file: &mut File,
    expected: u64,
    expected_header: &[u8; HEADER_BYTES as usize],
    poisoned: &mut bool,
) -> Result<(), Error> {
    let observed = (|| -> io::Result<bool> {
        if file.metadata()?.len() != expected || file.stream_position()? != expected {
            return Ok(false);
        }
        let mut header = [0; HEADER_BYTES as usize];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header)?;
        file.seek(SeekFrom::Start(expected))?;
        Ok(&header == expected_header)
    })();
    match observed {
        Ok(true) => Ok(()),
        Ok(false) => {
            *poisoned = true;
            Err(Error::StorageChanged)
        }
        Err(error) => {
            *poisoned = true;
            Err(Error::Io(error))
        }
    }
}

trait Durable: Write {
    fn sync(&mut self) -> io::Result<()>;
}
impl Durable for File {
    fn sync(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}
fn persist_record(
    writer: &mut impl Durable,
    candidate: &[u8],
    poisoned: &mut bool,
) -> Result<(), Error> {
    if *poisoned {
        return Err(Error::Poisoned);
    }
    let write = (|| -> io::Result<()> {
        writer.write_all(&(candidate.len() as u32).to_le_bytes())?;
        writer.write_all(candidate)?;
        writer.sync()
    })();
    if let Err(error) = write {
        *poisoned = true;
        return Err(Error::Io(error));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn commitment_fixture(release: &Release) -> RedemptionReview<'_> {
        RedemptionReview {
            checkpoint: Checkpoint {
                height: 10,
                root: [4; 32],
            },
            release,
            liabilities: gateway::AssetLiabilities {
                native_domain: [5; 32],
                native_asset: [6; 32],
                native_supply: 20,
                imported: 120,
                burned: 100,
                routes: vec![gateway::RouteLiabilities {
                    route: [1; 32],
                    source_domain: [7; 32],
                    token: [8; 20],
                    vault: [9; 20],
                    imported: 120,
                    burned: 100,
                    outstanding: 20,
                    release_count: 1,
                }],
            },
        }
    }
    #[test]
    fn hybrid_review_certificate_requires_trust_context_validity_and_both_signatures() {
        use bloch_crypto::crypto;
        use ReviewCertificateError::*;
        let release = Release {
            route: [1; 32],
            nonce: 7,
            recipient: [2; 20],
            amount: 100,
            native_burn: [3; 32],
        };
        let review = commitment_fixture(&release);
        let (public, secret) = crypto::generate_keypair_from_seed(&[241; 32]).unwrap();
        let (other, _) = crypto::generate_keypair_from_seed(&[242; 32]).unwrap();
        let message = review.certificate_message(&public, 20).unwrap();
        let signature = crypto::sign(&secret, &message).unwrap();
        for height in [10, 15, 20] {
            assert_eq!(
                review.verify_certificate(review.checkpoint(), &public, height, 20, &signature),
                Ok(())
            );
        }
        for height in [0, 9, 21, u64::MAX] {
            assert_eq!(
                review.verify_certificate(review.checkpoint(), &public, height, 20, &signature),
                Err(InvalidValidity)
            );
        }
        assert_eq!(review.certificate_message(&public, 9), Err(InvalidValidity));
        assert_eq!(review.certificate_message(&[], 20), Err(InvalidAuthority));
        assert_eq!(
            review.verify_certificate(review.checkpoint(), &[], 15, 20, &signature),
            Err(InvalidAuthority)
        );
        assert_eq!(
            review.verify_certificate(review.checkpoint(), &other, 15, 20, &signature),
            Err(InvalidSignature)
        );
        assert_eq!(
            review.verify_certificate(review.checkpoint(), &public, 15, 21, &signature),
            Err(InvalidSignature)
        );
        for checkpoint in [
            Checkpoint {
                height: 11,
                ..review.checkpoint()
            },
            Checkpoint {
                root: [0; 32],
                ..review.checkpoint()
            },
        ] {
            assert_eq!(
                review.verify_certificate(checkpoint, &public, 15, 20, &signature),
                Err(WrongCheckpoint)
            );
        }
        for offset in [
            crypto::SUITE_HEADER_LEN,
            crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
        ] {
            let mut damaged = signature.clone();
            damaged[offset] ^= 1;
            assert_eq!(
                review.verify_certificate(review.checkpoint(), &public, 15, 20, &damaged),
                Err(InvalidSignature)
            );
        }
        for damaged in [
            vec![],
            vec![0; crate::MAX_SIGNATURE_BYTES + 1],
            crypto::sign(&secret, &review.commitment()).unwrap(),
        ] {
            assert_eq!(
                review.verify_certificate(review.checkpoint(), &public, 15, 20, &damaged),
                Err(InvalidSignature)
            );
        }
        let changed_release = Release {
            amount: 101,
            ..release.clone()
        };
        let mut changed = commitment_fixture(&changed_release);
        assert_eq!(
            changed.verify_certificate(changed.checkpoint(), &public, 15, 20, &signature),
            Err(InvalidSignature)
        );
        changed = commitment_fixture(&release);
        changed.liabilities.burned += 1;
        assert_eq!(
            changed.verify_certificate(changed.checkpoint(), &public, 15, 20, &signature),
            Err(InvalidSignature)
        );
    }
    #[test]
    fn redemption_commitment_matches_independent_python_sha3_vector() {
        let release = Release {
            route: [1; 32],
            nonce: 7,
            recipient: [2; 20],
            amount: 100,
            native_burn: [3; 32],
        };
        let review = commitment_fixture(&release);
        assert_eq!(review.commitment_preimage().len(), 359);
        let hex = review
            .commitment()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            "4634b37856f26dcb28826e93b5a34010532e752cd3d3ef8a5c7efc077b38103f"
        );
        assert_eq!(
            review.commitment(),
            commitment_fixture(&release).commitment()
        );
    }
    #[test]
    fn redemption_commitment_binds_checkpoint_release_and_all_accounting_fields() {
        let release = Release {
            route: [1; 32],
            nonce: 7,
            recipient: [2; 20],
            amount: 100,
            native_burn: [3; 32],
        };
        let baseline = commitment_fixture(&release).commitment();
        let changes: &[fn(&mut RedemptionReview<'_>)] = &[
            |r| r.checkpoint.height += 1,
            |r| r.checkpoint.root[0] ^= 1,
            |r| r.liabilities.native_domain[0] ^= 1,
            |r| r.liabilities.native_asset[0] ^= 1,
            |r| r.liabilities.native_supply += 1,
            |r| r.liabilities.imported += 1,
            |r| r.liabilities.burned += 1,
            |r| r.liabilities.routes.clear(),
            |r| r.liabilities.routes[0].route[0] ^= 1,
            |r| r.liabilities.routes[0].source_domain[0] ^= 1,
            |r| r.liabilities.routes[0].token[0] ^= 1,
            |r| r.liabilities.routes[0].vault[0] ^= 1,
            |r| r.liabilities.routes[0].imported += 1,
            |r| r.liabilities.routes[0].burned += 1,
            |r| r.liabilities.routes[0].outstanding += 1,
            |r| r.liabilities.routes[0].release_count += 1,
        ];
        for change in changes {
            let mut changed = commitment_fixture(&release);
            change(&mut changed);
            assert_ne!(changed.commitment(), baseline);
        }
        for changed in [
            Release {
                route: [10; 32],
                ..release.clone()
            },
            Release {
                nonce: 8,
                ..release.clone()
            },
            Release {
                recipient: [10; 20],
                ..release.clone()
            },
            Release {
                amount: 101,
                ..release.clone()
            },
            Release {
                native_burn: [10; 32],
                ..release.clone()
            },
        ] {
            assert_ne!(commitment_fixture(&changed).commitment(), baseline);
        }
    }
    #[test]
    fn observer_export_keeps_large_uint64_values_as_exact_decimal_strings() {
        let release = Release {
            route: [1; 32],
            nonce: u64::MAX - 1,
            recipient: [2; 20],
            amount: u64::MAX,
            native_burn: [3; 32],
        };
        let review = RedemptionReview {
            checkpoint: Checkpoint {
                height: 10,
                root: [4; 32],
            },
            release: &release,
            liabilities: gateway::AssetLiabilities {
                native_domain: [5; 32],
                native_asset: [6; 32],
                native_supply: 0,
                imported: u128::from(u64::MAX),
                burned: u128::from(u64::MAX),
                routes: vec![],
            },
        };
        let value: serde_json::Value =
            serde_json::from_str(&review.observer_request_json()).unwrap();
        assert_eq!(value["nonce"].as_str(), Some("18446744073709551614"));
        assert_eq!(value["amount"].as_str(), Some("18446744073709551615"));
        assert_eq!(value.as_object().unwrap().len(), 7);
        assert!(value.get("redemption_settled").is_none());
    }
    struct FaultyWriter {
        bytes: Vec<u8>,
        remaining: usize,
        fail_sync: bool,
    }
    impl Write for FaultyWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("injected write failure"));
            }
            let count = bytes.len().min(self.remaining);
            self.bytes.extend_from_slice(&bytes[..count]);
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Durable for FaultyWriter {
        fn sync(&mut self) -> io::Result<()> {
            if self.fail_sync {
                Err(io::Error::other("injected sync failure"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn every_partial_write_failure_poisons_and_prevents_further_appends() {
        let payload = [42; 16];
        for remaining in 0..20 {
            let mut writer = FaultyWriter {
                bytes: vec![],
                remaining,
                fail_sync: false,
            };
            let mut poisoned = false;
            assert!(matches!(
                persist_record(&mut writer, &payload, &mut poisoned),
                Err(Error::Io(_))
            ));
            assert!(poisoned);
            let before = writer.bytes.clone();
            writer.remaining = 100;
            assert!(matches!(
                persist_record(&mut writer, &payload, &mut poisoned),
                Err(Error::Poisoned)
            ));
            assert_eq!(writer.bytes, before);
        }
    }
    #[test]
    fn complete_write_followed_by_sync_failure_remains_unconfirmed_and_poisoned() {
        let mut writer = FaultyWriter {
            bytes: vec![],
            remaining: 100,
            fail_sync: true,
        };
        let mut poisoned = false;
        assert!(matches!(
            persist_record(&mut writer, &[7; 8], &mut poisoned),
            Err(Error::Io(_))
        ));
        assert_eq!(writer.bytes.len(), 12);
        assert!(poisoned);
    }
    #[test]
    fn durable_record_has_exact_length_prefix_and_payload() {
        let mut writer = FaultyWriter {
            bytes: vec![],
            remaining: 100,
            fail_sync: false,
        };
        let mut poisoned = false;
        persist_record(&mut writer, &[1, 2, 3], &mut poisoned).unwrap();
        assert_eq!(writer.bytes, [3, 0, 0, 0, 1, 2, 3]);
        assert!(!poisoned);
    }
}
