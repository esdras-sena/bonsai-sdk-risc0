use wasm_bindgen::prelude::*;
use bincode;

use serde::Serialize;
use serde_json;

use anyhow::{bail, Result};

use serde::de::{self,Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;
use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, PodCastError, Zeroable};
use std::borrow::Borrow;

extern crate alloc;
use alloc::{collections::VecDeque, vec::Vec};
use std::ops::{Deref, DerefMut};
use derive_more;

pub const DIGEST_WORDS: usize = 8;

#[derive(
    Copy,
    Clone,
    Eq,
    Ord,
    PartialOrd,
    PartialEq,
    Hash,
    Pod,
    Debug,
    Zeroable,
    Serialize,
   serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[repr(transparent)]
pub struct Digest([u32; DIGEST_WORDS]);

impl AsRef<[u8; DIGEST_BYTES]> for Digest {
    fn as_ref(&self) -> &[u8; DIGEST_BYTES] {
        bytemuck::cast_ref(&self.0)
    }
}


#[derive(Debug, Copy, Clone)]
pub struct InvalidExitCodeError(pub u32, pub u32);

#[derive(
    Clone, Copy, Debug, Serialize,serde::Deserialize, PartialEq, BorshSerialize, BorshDeserialize,
)]
pub enum ExitCode {
    Halted(u32),
    Paused(u32),
    SystemSplit,
    SessionLimit,
}

impl ExitCode {
    /// Convert this [ExitCode] into a pair representation, where the first number is the "system"
    /// part, and the second is the "user" part. E.g. Halted(255) -> (0, 255)
    pub fn into_pair(self) -> (u32, u32) {
        match self {
            ExitCode::Halted(user_exit) => (0, user_exit),
            ExitCode::Paused(user_exit) => (1, user_exit),
            ExitCode::SystemSplit => (2, 0),
            ExitCode::SessionLimit => (2, 2),
        }
    }

    /// Convert this [ExitCode] from its pair representation, where the first number is the "system"
    /// part, and the second is the "user" part. E.g. (0, 255) -> Halted(255)
    pub fn from_pair(sys_exit: u32, user_exit: u32) -> Result<ExitCode, InvalidExitCodeError> {
        match sys_exit {
            0 => Ok(ExitCode::Halted(user_exit)),
            1 => Ok(ExitCode::Paused(user_exit)),
            2 => Ok(ExitCode::SystemSplit),
            _ => Err(InvalidExitCodeError(sys_exit, user_exit)),
        }
    }

    /// Whether the verifier should expect a non-empty output field. Exit codes Halted and Paused
    /// produce can produce a non-empty outputs, whereas system initiated exits like SystemSplit do
    /// not.
    pub fn expects_output(&self) -> bool {
        match self {
            ExitCode::Halted(_) | ExitCode::Paused(_) => true,
            ExitCode::SystemSplit | ExitCode::SessionLimit => false,
        }
    }

    /// True if the exit code is Halted(0), indicating the program guest exited with an ok status.
    pub fn is_ok(&self) -> bool {
        matches!(self, ExitCode::Halted(0))
    }
}

#[derive(Clone, Serialize, derive_more::with_trait::Debug,serde::Deserialize, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SystemState {
    /// The program counter.
    pub pc: u32,

    /// The root hash of a merkle tree which confirms the
    /// integrity of the memory image.
    pub merkle_root: Digest,
}

impl risc0_binfmt_Digestible for SystemState {
    /// Hash the [crate::SystemState] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>("risc0.SystemState", &[self.merkle_root], &[self.pc])
    }
}


#[derive(Clone, Debug, Serialize,serde::Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Unknown {}

impl risc0_binfmt_Digestible for Unknown {
    fn digest<S: Sha256>(&self) -> Digest {
        match *self { /* unreachable  */ }
    }
}

#[derive(Clone, Debug, Serialize,serde::Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Input {
    // Private field to ensure this type cannot be constructed.
    // By making this type uninhabited, it can be populated later without breaking backwards
    // compatibility.
    pub(crate) x: Unknown,
}

impl risc0_binfmt_Digestible for Input {
    /// Hash the [Input] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        match self.x { /* unreachable  */ }
    }
}

#[derive(
    Clone, Debug, Serialize,serde::Deserialize, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize,
)]
pub struct Assumption {
    pub claim: Digest,
    pub control_root: Digest,
}

impl risc0_binfmt_Digestible for Assumption {
    /// Hash the [Assumption] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>("risc0.Assumption", &[self.claim, self.control_root], &[])
    }
}


#[derive(Clone, Default, Debug, Serialize,serde::Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Assumptions(pub Vec<MaybePruned<Assumption>>);
impl risc0_binfmt_Digestible for Assumptions {
    /// Hash the [Assumptions] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_list::<S>(
            "risc0.Assumptions",
            &self.0.iter().map(|a| a.digest::<S>()).collect::<Vec<_>>(),
        )
    }
}

pub fn tagged_list<S: Sha256>(tag: &str, list: &[impl Borrow<Digest>]) -> Digest {
    tagged_iter::<S>(tag, list.iter().map(|x| x.borrow()))
}
pub fn tagged_iter<S: Sha256>(
    tag: &str,
    iter: impl DoubleEndedIterator<Item = impl Borrow<Digest>>,
) -> Digest {
    iter.rfold(Digest::ZERO, |list_digest, elem| {
        tagged_list_cons::<S>(tag, elem.borrow(), &list_digest)
    })
}

pub fn tagged_list_cons<S: Sha256>(tag: &str, head: &Digest, tail: &Digest) -> Digest {
    tagged_struct::<S>(tag, &[head, tail], &[])
}



#[derive(Clone, derive_more::with_trait::Debug, Serialize,serde::Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Output {
    /// The journal committed to by the guest execution.
    #[debug("{}", fmt_debug_journal(journal))]
    pub journal: MaybePruned<Vec<u8>>,

    /// An ordered list of [ReceiptClaim] digests corresponding to the
    /// calls to `env::verify` and `env::verify_integrity`.
    ///
    /// Verifying the integrity of a [crate::Receipt] corresponding to a [ReceiptClaim] with a
    /// non-empty assumptions list does not guarantee unconditionally any of the claims over the
    /// guest execution (i.e. if the assumptions list is non-empty, then the journal digest cannot
    /// be trusted to correspond to a genuine execution). The claims can be checked by additional
    /// verifying a [crate::Receipt] for every digest in the assumptions list.
    pub assumptions: MaybePruned<Assumptions>,
}

impl risc0_binfmt_Digestible for Output {
    /// Hash the [Output] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>(
            "risc0.Output",
            &[self.journal.digest::<S>(), self.assumptions.digest::<S>()],
            &[],
        )
    }
}


#[derive(Clone,serde::Deserialize, derive_more::with_trait::Debug, Serialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum MaybePruned<T>
where
    T: Clone + Serialize,
{
    /// Unpruned value.
    Value(T),

    /// Pruned value, which is a hash [Digest] of the value.
    Pruned(Digest),
}

impl<T> risc0_binfmt_Digestible for MaybePruned<T>
where
    T: risc0_binfmt_Digestible + Clone + Serialize,
{
    fn digest<S: Sha256>(&self) -> Digest {
        match self {
            MaybePruned::Value(ref val) => val.digest::<S>(),
            MaybePruned::Pruned(digest) => *digest,
        }
    }
}



#[derive(Clone, Debug,serde::Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ReceiptClaim {
    /// The [SystemState] just before execution has begun.
    pub pre: MaybePruned<SystemState>,

    /// The [SystemState] just after execution has completed.
    pub post: MaybePruned<SystemState>,

    /// The exit code for the execution.
    pub exit_code: ExitCode,

    /// Input to the guest.
    pub input: MaybePruned<Option<Input>>,

    /// [Output] of the guest, including the journal and assumptions set during execution.
    pub output: MaybePruned<Option<Output>>,
}

impl risc0_binfmt_Digestible for ReceiptClaim {
    /// Hash the [ReceiptClaim] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        let (sys_exit, user_exit) = self.exit_code.into_pair();
        tagged_struct::<S>(
            "risc0.ReceiptClaim",
            &[
                self.input.digest::<S>(),
                self.pre.digest::<S>(),
                self.post.digest::<S>(),
                self.output.digest::<S>(),
            ],
            &[sys_exit, user_exit],
        )
    }
}

pub fn tagged_struct<S: Sha256>(tag: &str, down: &[impl Borrow<Digest>], data: &[u32]) -> Digest {
    let tag_digest: Digest = *S::hash_bytes(tag.as_bytes());
    #[allow(clippy::manual_slice_size_calculation)]
    let mut all = Vec::<u8>::with_capacity(
        DIGEST_BYTES * (down.len() + 1) + size_of::<u32>() * data.len() + size_of::<u16>(),
    );
    all.extend_from_slice(tag_digest.as_bytes());
    for digest in down {
        all.extend_from_slice(digest.borrow().as_ref());
    }
    for word in data.iter().copied() {
        all.extend_from_slice(&word.to_le_bytes());
    }
    let down_count: u16 = down
        .len()
        .try_into()
        .expect("struct defined with more than 2^16 fields");
    all.extend_from_slice(&down_count.to_le_bytes());
    *S::hash_bytes(&all)
}

#[derive(Clone, derive_more::with_trait::Debug,serde::Deserialize, Serialize)]
#[non_exhaustive]
#[cfg_attr(test, derive(PartialEq))]
pub struct SegmentReceipt {
    /// The cryptographic data attesting to the validity of the code execution.
    ///
    /// This data is used by the ZKP Verifier (as called by
    /// [SegmentReceipt::verify_integrity_with_context]) to cryptographically prove that this
    /// Segment was faithfully executed. It is largely opaque cryptographic data, but contains a
    /// non-opaque claim component, which can be conveniently accessed with
    /// [SegmentReceipt::claim].
    #[debug("{} bytes", self.get_seal_bytes().len())]
    pub seal: Vec<u32>,

    /// Segment index within the [Receipt](crate::Receipt)
    pub index: u32,

    /// Name of the hash function used to create this receipt.
    pub hashfn: String,

    /// A digest of the verifier parameters that can be used to verify this receipt.
    ///
    /// Acts as a fingerprint to identity differing proof system or circuit versions between a
    /// prover and a verifier. Is not intended to contain the full verifier parameters, which must
    /// be provided by a trusted source (e.g. packaged with the verifier code).
    pub verifier_parameters: Digest,

    /// [ReceiptClaim] containing information about the execution that this receipt proves.
    pub claim: ReceiptClaim,
}


impl SegmentReceipt {
    /// Verify the integrity of this receipt, ensuring the claim is attested
    /// to by the seal.

    /// Return the seal for this receipt, as a vector of bytes.
    pub fn get_seal_bytes(&self) -> Vec<u8> {
        self.seal.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    /// Number of bytes used by the seal for this receipt.
    pub fn seal_size(&self) -> usize {
        core::mem::size_of_val(self.seal.as_slice())
    }
}


#[derive(Clone, Debug,serde::Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub enum InnerAssumptionReceipt {
    /// A non-succinct [CompositeReceipt], made up of one inner receipt per segment and assumption.
    Composite(CompositeReceipt),

    /// A [SuccinctReceipt], proving arbitrarily the claim with a single STARK.
    Succinct(SuccinctReceipt<Unknown>),

    /// A [Groth16Receipt], proving arbitrarily the claim with a single Groth16 SNARK.
    Groth16(Groth16Receipt<Unknown>),

    /// A [FakeReceipt], with no cryptographic integrity, used only for development.
    Fake(FakeReceipt<Unknown>),
}

#[derive(Clone, Debug,serde::Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct CompositeReceipt {
    /// Segment receipts forming the proof of an execution with continuations.
    pub segments: Vec<SegmentReceipt>,

    /// An ordered list of assumptions, either proven or unresolved, made within
    /// the continuation represented by the segment receipts. If any
    /// assumptions are unresolved, this receipt is only _conditionally_
    /// valid.
    // TODO(#982): Allow for unresolved assumptions in this list.
    pub assumption_receipts: Vec<InnerAssumptionReceipt>,

    /// A digest of the verifier parameters that can be used to verify this receipt.
    ///
    /// Acts as a fingerprint to identity differing proof system or circuit versions between a
    /// prover and a verifier. Is not intended to contain the full verifier parameters, which must
    /// be provided by a trusted source (e.g. packaged with the verifier code).
    pub verifier_parameters: Digest,
}

#[derive(Clone, Debug,serde::Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
pub struct Journal {
    /// The raw bytes of the journal.
    pub bytes: Vec<u8>,
}

#[non_exhaustive]
#[derive(Clone, Debug, Serialize,serde::Deserialize, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct MerkleProof {
    /// Index of the leaf for which inclusion is being proven.
    pub index: u32,

    /// Sibling digests on the path from the root to the leaf.
    /// Does not include the root of the leaf.
    pub digests: Vec<Digest>,
}


#[derive(Clone, derive_more::with_trait::Debug, Serialize,serde::Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub struct SuccinctReceipt<Claim>
where
    Claim: risc0_binfmt_Digestible + core::fmt::Debug + Clone + Serialize,
{
    #[debug("{} bytes", self.get_seal_bytes().len())]
    pub seal: Vec<u32>,
    pub control_id: Digest,
    pub claim: MaybePruned<Claim>,
    pub hashfn: String,
    pub verifier_parameters: Digest,
    pub control_inclusion_proof: MerkleProof,
}

impl<Claim> SuccinctReceipt<Claim>
where
    Claim: risc0_binfmt_Digestible + core::fmt::Debug + Clone + Serialize,
{
    

    /// Return the seal for this receipt, as a vector of bytes.
    pub fn get_seal_bytes(&self) -> Vec<u8> {
        self.seal.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    /// Number of bytes used by the seal for this receipt.
    pub fn seal_size(&self) -> usize {
        core::mem::size_of_val(self.seal.as_slice())
    }

    #[cfg(feature = "prove")]
    pub(crate) fn control_root(&self) -> anyhow::Result<Digest> {
        let hash_suite = hash_suite_from_name(&self.hashfn)
            .ok_or_else(|| anyhow::anyhow!("unsupported hash function: {}", self.hashfn))?;
        Ok(self
            .control_inclusion_proof
            .root(&self.control_id, hash_suite.hashfn.as_ref()))
    }

}


#[derive(Clone, derive_more::with_trait::Debug,serde::Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub struct Groth16Receipt<Claim>
where
    Claim: risc0_binfmt_Digestible + core::fmt::Debug + Clone + Serialize,
{
    /// A Groth16 proof of a zkVM execution with the associated claim.
    #[debug("{} bytes", seal.len())]
    pub seal: Vec<u8>,

    /// [ReceiptClaim][crate::ReceiptClaim] containing information about the execution that this
    /// receipt proves.
    pub claim: MaybePruned<Claim>,

    /// A digest of the verifier parameters that can be used to verify this receipt.
    ///
    /// Acts as a fingerprint to identity differing proof system or circuit versions between a
    /// prover and a verifier. Is not intended to contain the full verifier parameters, which must
    /// be provided by a trusted source (e.g. packaged with the verifier code).
    pub verifier_parameters: Digest,
}

pub trait risc0_binfmt_Digestible {
    /// Calculate a collision resistant hash for the typed and structured data.
    fn digest<S: Sha256>(&self) -> Digest;
}

impl risc0_binfmt_Digestible for [u8] {
    fn digest<S: Sha256>(&self) -> Digest {
        *S::hash_bytes(self)
    }
}

impl risc0_binfmt_Digestible for Vec<u8> {
    fn digest<S: Sha256>(&self) -> Digest {
        *S::hash_bytes(self)
    }
}

impl<D: risc0_binfmt_Digestible> risc0_binfmt_Digestible for [D] {
    /// A default incremental hashing algorithm for a slice of Digestible elements.
    ///
    /// This hashing routine may not be appropriate for add use cases. In particular, it is not a
    /// PRF and cannot be used as a MAC. Given a digest of a list, anyone can compute the digest of
    /// that list with additional elements appended to the front of the list. It also does not
    /// domain separate typed data, and the digest of an empty slice is the zero digest.
    fn digest<S: Sha256>(&self) -> Digest {
        self.iter().rfold(Digest::ZERO, |accum, item| {
            *S::hash_bytes(&[accum.as_bytes(), item.digest::<S>().as_bytes()].concat())
        })
    }
}

impl<T: risc0_binfmt_Digestible> risc0_binfmt_Digestible for Option<T> {
    fn digest<S: Sha256>(&self) -> Digest {
        match self {
            Some(val) => val.digest::<S>(),
            None => Digest::ZERO,
        }
    }
}

#[derive(Clone, Debug, Serialize,serde::Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub struct FakeReceipt<Claim>
where
    Claim: risc0_binfmt_Digestible + derive_more::with_trait::Debug + Clone + Serialize,
{
    /// Claim containing information about the computation that this receipt pretends to prove.
    ///
    /// The standard claim type is [ReceiptClaim], which represents a RISC-V zkVM execution.
    pub claim: MaybePruned<Claim>,
}

#[derive(Clone, Debug,serde::Deserialize, Serialize)]
pub enum InnerReceipt {
    /// A non-succinct [CompositeReceipt], made up of one inner receipt per segment.
    Composite(CompositeReceipt),

    /// A [SuccinctReceipt], proving arbitrarily long zkVM computions with a single STARK.
    Succinct(SuccinctReceipt<ReceiptClaim>),

    /// A [Groth16Receipt], proving arbitrarily long zkVM computions with a single Groth16 SNARK.
    Groth16(Groth16Receipt<ReceiptClaim>),

    /// A [FakeReceipt], with no cryptographic integrity, used only for development.
    Fake(FakeReceipt<ReceiptClaim>),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[non_exhaustive]
pub struct ReceiptMetadata {
    /// Information which can be used to decide whether a given verifier is compatible with this
    /// receipt (i.e. that it may be able to verify it).
    ///
    /// It is intended to be used when there are multiple verifier implementations (e.g.
    /// corresponding to multiple versions of a proof system or circuit) and it is ambiguous which
    /// one should be used to attempt verification of a receipt.
    pub verifier_parameters: Digest,
}

#[derive(Clone, Debug, serde::Deserialize, Serialize)]
pub struct Receipt {
    pub inner: InnerReceipt,
    pub journal: Journal,
    pub metadata: ReceiptMetadata,
}




#[allow(dead_code)]
fn fmt_debug_journal(journal: &MaybePruned<Vec<u8>>) -> alloc::string::String {
    match journal {
        MaybePruned::Value(bytes) => alloc::format!("{} bytes", bytes.len()),
        MaybePruned::Pruned(_) => alloc::format!("{journal:?}"),
    }
}

pub const DIGEST_BYTES: usize = DIGEST_WORDS * WORD_SIZE;
pub const WORD_SIZE: usize = 4;

impl Digest {
    /// Digest of all zeroes.
    pub const ZERO: Self = Self::new([0u32; DIGEST_WORDS]);

    /// Constant constructor
    pub const fn new(data: [u32; DIGEST_WORDS]) -> Self {
        Self(data)
    }

    /// Construct a digest from a array of bytes in a const context.
    /// Outside of const context, `Digest::from` is recommended.
    pub const fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        let mut digest: Digest = Digest::ZERO;
        let mut i: usize = 0;
        while i < DIGEST_WORDS {
            let mut j = 0;
            let mut word = 0u32;
            while j < WORD_SIZE {
                word <<= 8;
                word |= bytes[i * WORD_SIZE + j] as u32;
                j += 1;
            }
            word = u32::from_be(word);
            digest.0[i] = word;
            i += 1;
        }
        digest
    }

    /// Returns a reference to the [Digest] as a slice of words.
    pub fn as_words(&self) -> &[u32] {
        &self.0
    }

    /// Returns a reference to the [Digest] as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::cast_slice(&self.0)
    }

    /// Returns a mutable slice of words.
    pub fn as_mut_words(&mut self) -> &mut [u32] {
        &mut self.0
    }

    /// Returns a mutable slice of bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        bytemuck::cast_slice_mut(&mut self.0)
    }
}

pub const SHA256_INIT: Digest = Digest::new([
    0x6a09e667_u32.to_be(),
    0xbb67ae85_u32.to_be(),
    0x3c6ef372_u32.to_be(),
    0xa54ff53a_u32.to_be(),
    0x510e527f_u32.to_be(),
    0x9b05688c_u32.to_be(),
    0x1f83d9ab_u32.to_be(),
    0x5be0cd19_u32.to_be(),
]);

pub const BLOCK_WORDS: usize = DIGEST_WORDS * 2;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Pod, Zeroable, Serialize,serde::Deserialize)]
#[repr(transparent)]
pub struct Block([u32; BLOCK_WORDS]);

pub trait Sha256 {
    /// A pointer to the digest created as the result of a hashing operation.
    ///
    /// This may either be a `Box<Digest>` or some other pointer in case the
    /// implementation wants to manage its own memory. Semantically, holding the
    /// `DigestPtr` denotes ownership of the underlying value. (e.g. `DigestPtr`
    /// does not implement `Copy` and the owner of `DigestPtr` can create a
    /// mutable reference to the underlying digest).
    type DigestPtr: DerefMut<Target = Digest> + derive_more::with_trait::Debug;

    /// Generate a SHA-256 hash from a slice of bytes, padding to block size
    /// and adding the SHA-256 hash trailer, as specified in FIPS 180-4.
    fn hash_bytes(bytes: &[u8]) -> Self::DigestPtr;

    /// Generate a SHA-256 hash from a slice of words, padding to block size
    /// and adding the SHA-256 hash trailer, as specified in FIPS 180-4.
    fn hash_words(words: &[u32]) -> Self::DigestPtr {
        Self::hash_bytes(bytemuck::cast_slice(words))
    }

    /// Generate a hash from a pair of [Digest] using the SHA-256 compression
    /// function. Note that the result is not a standard-compliant hash of any
    /// known preimage.
    fn hash_pair(a: &Digest, b: &Digest) -> Self::DigestPtr {
        Self::compress(&SHA256_INIT, a, b)
    }

    /// Execute the SHA-256 compression function on a single block given as
    /// two half-blocks and return a pointer to the result.
    ///
    /// NOTE: The half blocks do not need to be adjacent.
    ///
    /// DANGER: This is the low-level SHA-256 compression function. It is a
    /// primitive used to construct SHA-256, but it is NOT the full
    /// algorithm and should be used directly only with extreme caution.
    fn compress(state: &Digest, block_half1: &Digest, block_half2: &Digest) -> Self::DigestPtr;

    /// Execute the SHA-256 compression function on a slice of blocks following
    /// the [Merkle–Damgård] construction and return a pointer to the result.
    ///
    /// DANGER: This is the low-level SHA-256 compression function. It is a
    /// primitive used to construct SHA-256, but it is NOT the full
    /// algorithm and should be used directly only with extreme caution.
    ///
    /// [Merkle–Damgård]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction
    fn compress_slice(state: &Digest, blocks: &[Block]) -> Self::DigestPtr;

    /// Generate a hash from a slice of anything that can be represented as
    /// a slice of bytes. Pads up to the SHA-256 block boundary, but does not
    /// add the standard SHA-256 trailer and so is not a standards compliant
    /// hash.
    fn hash_raw_data_slice<T: bytemuck::NoUninit>(data: &[T]) -> Self::DigestPtr;
}

pub fn encode_seal(receipt: &Receipt) -> Result<Vec<u8>> {
    let seal = match receipt.inner.clone() {
        // InnerReceipt::Fake(receipt) => {
        //     let seal = receipt.claim.digest().as_bytes().to_vec();
        //     let selector = &[0u8; 4];
        //     // Create a new vector with the capacity to hold both selector and seal
        //     let mut selector_seal = Vec::with_capacity(selector.len() + seal.len());
        //     selector_seal.extend_from_slice(selector);
        //     selector_seal.extend_from_slice(&seal);
        //     selector_seal
        // }
        InnerReceipt::Groth16(receipt) => {
            let selector = &receipt.verifier_parameters.as_bytes()[..4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + receipt.seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(receipt.seal.as_ref());
            selector_seal
        }
        _ => bail!("Unsupported receipt type"),
        // TODO(victor): Add set verifier seal here.
    };
    Ok(seal)
}

#[wasm_bindgen]
pub struct ProofData {
    seal: Vec<u8>,
    journal: Vec<u8>,
}

#[wasm_bindgen]
impl ProofData {
    // Provide getter methods for each field.
    #[wasm_bindgen(getter)]
    pub fn seal(&self) -> Vec<u8> {
        self.seal.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn journal(&self) -> Vec<u8> {
        self.journal.clone()
    }
}

#[wasm_bindgen]
pub fn convert(bincode: Vec<u8>)  -> ProofData{
    let receipt: Receipt = bincode::deserialize(&bincode).unwrap();
    let seal: Vec<u8> = encode_seal(&receipt).unwrap();
    
    return ProofData{seal: seal, journal: receipt.journal.bytes};

}