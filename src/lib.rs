//! The `shred` module defines data structures and methods to pull MTU sized data frames from the
//! network. There are two types of shreds: data and coding. Data shreds contain entry information
//! while coding shreds provide redundancy to protect against dropped network packets (erasures).
//!
//! +---------------------------------------------------------------------------------------------+
//! | Data Shred                                                                                  |
//! +---------------------------------------------------------------------------------------------+
//! | common       | data       | payload                                                         |
//! | header       | header     |                                                                 |
//! |+---+---+---  |+---+---+---|+----------------------------------------------------------+----+|
//! || s | s | .   || p | f | s || data (ie ledger entries)                                 | r  ||
//! || i | h | .   || a | l | i ||                                                          | e  ||
//! || g | r | .   || r | a | z || See notes immediately after shred diagrams for an        | s  ||
//! || n | e |     || e | g | e || explanation of the "restricted" section in this payload  | t  ||
//! || a | d |     || n | s |   ||                                                          | r  ||
//! || t |   |     || t |   |   ||                                                          | i  ||
//! || u | t |     ||   |   |   ||                                                          | c  ||
//! || r | y |     || o |   |   ||                                                          | t  ||
//! || e | p |     || f |   |   ||                                                          | e  ||
//! ||   | e |     || f |   |   ||                                                          | d  ||
//! |+---+---+---  |+---+---+---+|----------------------------------------------------------+----+|
//! +---------------------------------------------------------------------------------------------+
//!
//! +---------------------------------------------------------------------------------------------+
//! | Coding Shred                                                                                |
//! +---------------------------------------------------------------------------------------------+
//! | common       | coding     | payload                                                         |
//! | header       | header     |                                                                 |
//! |+---+---+---  |+---+---+---+----------------------------------------------------------------+|
//! || s | s | .   || n | n | p || data (encoded data shred data)                                ||
//! || i | h | .   || u | u | o ||                                                               ||
//! || g | r | .   || m | m | s ||                                                               ||
//! || n | e |     ||   |   | i ||                                                               ||
//! || a | d |     || d | c | t ||                                                               ||
//! || t |   |     ||   |   | i ||                                                               ||
//! || u | t |     || s | s | o ||                                                               ||
//! || r | y |     || h | h | n ||                                                               ||
//! || e | p |     || r | r |   ||                                                               ||
//! ||   | e |     || e | e |   ||                                                               ||
//! ||   |   |     || d | d |   ||                                                               ||
//! |+---+---+---  |+---+---+---+|+--------------------------------------------------------------+|
//! +---------------------------------------------------------------------------------------------+
//!
//! Notes:
//! a) Coding shreds encode entire data shreds: both of the headers AND the payload.
//! b) Coding shreds require their own headers for identification and etc.
//! c) The erasure algorithm requires data shred and coding shred bytestreams to be equal in length.
//!
//! So, given a) - c), we must restrict data shred's payload length such that the entire coding
//! payload can fit into one coding shred / packet.

#![allow(dead_code)]

pub use self::merkle_tree::PROOF_ENTRIES_FOR_32_32_BATCH;
use {
    self::traits::{Shred as _, ShredData as _},
    assert_matches::debug_assert_matches,
    bitflags::bitflags,
    num_enum::{IntoPrimitive, TryFromPrimitive},
    serde::{Deserialize, Serialize},
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_sha256_hasher::hashv,
    solana_signature::{SIGNATURE_BYTES, Signature},
    static_assertions::const_assert_eq,
    std::{fmt::Debug, mem::MaybeUninit},
    thiserror::Error,
    wincode::{
        SchemaRead, SchemaWrite, TypeMeta,
        io::{Reader, Writer},
    },
};
pub use {
    self::{
        merkle::{ShredCode, ShredData},
        payload::Payload,
        stats::{ProcessShredsStats, ShredFetchStats},
    },
};

/// Slot is just u64 -- vendored to avoid pulling in solana_clock.
pub type Slot = u64;

/// PACKET_DATA_SIZE from solana_packet -- vendored as a const.
pub const PACKET_DATA_SIZE: usize = 1232;

mod common;
pub mod merkle;
pub mod merkle_tree;
mod payload;
mod shred_code;
pub(crate) mod shred_data;
mod stats;
mod traits;
pub mod wire;
pub mod blockstore_meta;

// Alias for shred::wire::* for the old code.
// New code should use shred::wire::*.
pub mod layout {
    pub use super::wire::*;
}

pub type Nonce = u32;
const_assert_eq!(SIZE_OF_NONCE, 4);
pub const SIZE_OF_NONCE: usize = std::mem::size_of::<Nonce>();

/// The following constants are computed by hand, and hardcoded.
const SIZE_OF_COMMON_SHRED_HEADER: usize = 83;
pub const SIZE_OF_DATA_SHRED_HEADERS: usize = 88;
const SIZE_OF_CODING_SHRED_HEADERS: usize = 89;
const SIZE_OF_SIGNATURE: usize = SIGNATURE_BYTES;

// Shreds are uniformly split into erasure batches with a "target" number of
// data shreds per each batch as below.
pub const DATA_SHREDS_PER_FEC_BLOCK: usize = 32;
pub const CODING_SHREDS_PER_FEC_BLOCK: usize = 32;
pub const SHREDS_PER_FEC_BLOCK: usize = DATA_SHREDS_PER_FEC_BLOCK + CODING_SHREDS_PER_FEC_BLOCK;

/// An upper bound on maximum number of data shreds we can handle in a slot
/// 32K shreds would allow ~320K peak TPS
/// (32K shreds per slot * 4 TX per shred * 2.5 slots per sec)
pub const MAX_DATA_SHREDS_PER_SLOT: usize = 32_768;
pub const MAX_CODE_SHREDS_PER_SLOT: usize = MAX_DATA_SHREDS_PER_SLOT;

pub const MAX_FEC_SETS_PER_SLOT: u32 =
    MAX_DATA_SHREDS_PER_SLOT as u32 / DATA_SHREDS_PER_FEC_BLOCK as u32;

// Statically compute the typical data batch size assuming:
// 1. 32:32 erasure coding batch
// 2. Merkles are chained
// 3. No retransmit signature (only included for last batch)
pub const fn get_data_shred_bytes_per_batch_typical() -> u64 {
    let capacity = match merkle::ShredData::const_capacity(PROOF_ENTRIES_FOR_32_32_BATCH, false) {
        Ok(v) => v,
        Err(_proof_size) => {
            panic!("this is unreachable");
        }
    };
    (DATA_SHREDS_PER_FEC_BLOCK * capacity) as u64
}

// LAST_SHRED_IN_SLOT also implies DATA_COMPLETE_SHRED.
// So it cannot be LAST_SHRED_IN_SLOT if not also DATA_COMPLETE_SHRED.
bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
    pub struct ShredFlags:u8 {
        const SHRED_TICK_REFERENCE_MASK = 0b0011_1111;
        const DATA_COMPLETE_SHRED       = 0b0100_0000;
        const LAST_SHRED_IN_SLOT        = 0b1100_0000;
    }
}

impl ShredFlags {
    pub(crate) fn from_reference_tick(reference_tick: u8) -> Self {
        Self::from_bits_retain(Self::SHRED_TICK_REFERENCE_MASK.bits().min(reference_tick))
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    WincodeRead(#[from] wincode::ReadError),
    #[error(transparent)]
    WincodeWrite(#[from] wincode::WriteError),
    #[error(transparent)]
    Erasure(#[from] reed_solomon_erasure::Error),
    #[error("Invalid data size: {size}, payload: {payload}")]
    InvalidDataSize { size: u16, payload: usize },
    #[error("Invalid deshred set")]
    InvalidDeshredSet,
    #[error("Invalid erasure config")]
    InvalidErasureConfig,
    #[error("Invalid erasure shard index: {0:?}")]
    InvalidErasureShardIndex(/*headers:*/ Box<dyn Debug + Send>),
    #[error("Invalid merkle proof")]
    InvalidMerkleProof,
    #[error("Invalid Merkle root")]
    InvalidMerkleRoot,
    #[error("Invalid num coding shreds: {0}")]
    InvalidNumCodingShreds(u16),
    #[error("Invalid parent_offset: {parent_offset}, slot: {slot}")]
    InvalidParentOffset { slot: Slot, parent_offset: u16 },
    #[error("Invalid parent slot: {parent_slot}, slot: {slot}")]
    InvalidParentSlot { slot: Slot, parent_slot: Slot },
    #[error("Invalid payload size: {0}")]
    InvalidPayloadSize(/*payload size:*/ usize),
    #[error("Invalid proof size: {0}")]
    InvalidProofSize(/*proof_size:*/ u8),
    #[error("Invalid recovered shred")]
    InvalidRecoveredShred,
    #[error("Invalid shard size: {0}")]
    InvalidShardSize(/*shard_size:*/ usize),
    #[error("Invalid shred flags: {0}")]
    InvalidShredFlags(u8),
    #[error("Invalid {0:?} shred index: {1}")]
    InvalidShredIndex(ShredType, /*shred index:*/ u32),
    #[error("Invalid shred type")]
    InvalidShredType,
    #[error("Invalid shred variant")]
    InvalidShredVariant,
    #[error("Invalid packet size, could not get the shred")]
    InvalidPacketSize,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Unknown proof size")]
    UnknownProofSize,
    #[error("Empty shreds list")]
    EmptyIterator,
}

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    PartialEq,
    Deserialize,
    IntoPrimitive,
    Serialize,
    TryFromPrimitive,
    SchemaWrite,
    SchemaRead,
)]
#[serde(into = "u8", try_from = "u8")]
#[wincode(tag_encoding = "u8")]
pub enum ShredType {
    #[wincode(tag = 0b1010_0101)]
    Data = 0b1010_0101,
    #[wincode(tag = 0b0101_1010)]
    Code = 0b0101_1010,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ShredVariant {
    MerkleCode { proof_size: u8, resigned: bool }, // 0b01??_????
    MerkleData { proof_size: u8, resigned: bool }, // 0b10??_????
}

wincode::pod_wrapper! {
    unsafe struct PodShredFlags(ShredFlags);
}

/// A common header that is present in data and code shred headers
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
struct ShredCommonHeader {
    signature: Signature,
    shred_variant: ShredVariant,
    slot: Slot,
    index: u32,
    version: u16,
    fec_set_index: u32,
}

/// The data shred header has parent offset and flags
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
struct DataShredHeader {
    parent_offset: u16,
    #[wincode(with = "PodShredFlags")]
    flags: ShredFlags,
    size: u16, // common shred header + data shred header + data
}

/// The coding shred header has FEC information
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
struct CodingShredHeader {
    num_data_shreds: u16,
    num_coding_shreds: u16,
    position: u16, // [0..num_coding_shreds)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shred {
    ShredCode(ShredCode),
    ShredData(merkle::ShredData),
}

/// Tuple which uniquely identifies a shred should it exists.
#[derive(Clone, Copy, Eq, Debug, Hash, PartialEq)]
pub struct ShredId(Slot, /*shred index:*/ u32, ShredType);

impl ShredId {
    #[inline]
    pub fn new(slot: Slot, index: u32, shred_type: ShredType) -> ShredId {
        ShredId(slot, index, shred_type)
    }

    #[inline]
    pub fn slot(&self) -> Slot {
        self.0
    }

    #[inline]
    pub fn index(&self) -> u32 {
        self.1
    }

    #[inline]
    pub fn shred_type(&self) -> ShredType {
        self.2
    }

    #[inline]
    pub(crate) fn unpack(&self) -> (Slot, /*shred index:*/ u32, ShredType) {
        (self.0, self.1, self.2)
    }

    pub fn seed(&self, leader: &Pubkey) -> [u8; 32] {
        let ShredId(slot, index, shred_type) = self;
        hashv(&[
            &slot.to_le_bytes(),
            &u8::from(*shred_type).to_le_bytes(),
            &index.to_le_bytes(),
            AsRef::<[u8]>::as_ref(leader),
        ])
        .to_bytes()
    }
}

/// Tuple which identifies erasure coding set that the shred belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub(crate) struct ErasureSetId(Slot, /*fec_set_index:*/ u32);

impl ErasureSetId {
    pub(crate) fn new(slot: Slot, fec_set_index: u32) -> Self {
        Self(slot, fec_set_index)
    }

    pub(crate) fn slot(&self) -> Slot {
        self.0
    }

    pub(crate) fn fec_set_index(&self) -> u32 {
        self.1
    }

    // Storage key for ErasureMeta and MerkleRootMeta in blockstore db.
    pub(crate) fn store_key(&self) -> (Slot, /*fec_set_index:*/ u32) {
        (self.0, self.1)
    }
}

/// To be used with the [`Shred`] enum.
macro_rules! dispatch {
    ($vis:vis fn $name:ident(&self $(, $arg:ident : $ty:ty)?) $(-> $out:ty)?) => {
        #[inline]
        $vis fn $name(&self $(, $arg:$ty)?) $(-> $out)? {
            match self {
                Self::ShredCode(shred) => shred.$name($($arg, )?),
                Self::ShredData(shred) => shred.$name($($arg, )?),
            }
        }
    };
    ($vis:vis fn $name:ident(self $(, $arg:ident : $ty:ty)?) $(-> $out:ty)?) => {
        #[inline]
        $vis fn $name(self $(, $arg:$ty)?) $(-> $out)? {
            match self {
                Self::ShredCode(shred) => shred.$name($($arg, )?),
                Self::ShredData(shred) => shred.$name($($arg, )?),
            }
        }
    };
    ($vis:vis fn $name:ident(&mut self $(, $arg:ident : $ty:ty)?) $(-> $out:ty)?) => {
        #[inline]
        $vis fn $name(&mut self $(, $arg:$ty)?) $(-> $out)? {
            match self {
                Self::ShredCode(shred) => shred.$name($($arg, )?),
                Self::ShredData(shred) => shred.$name($($arg, )?),
            }
        }
    }
}

use {dispatch, wincode::config::ConfigCore};

impl Shred {
    dispatch!(fn common_header(&self) -> &ShredCommonHeader);
    dispatch!(fn set_signature(&mut self, signature: Signature));
    dispatch!(fn signed_data(&self) -> Result<Hash, Error>);

    dispatch!(pub fn chained_merkle_root(&self) -> Result<Hash, Error>);
    dispatch!(pub(crate) fn retransmitter_signature(&self) -> Result<Signature, Error>);
    dispatch!(pub fn retransmitter_signature_offset(&self) -> Result<usize, Error>);

    dispatch!(pub fn into_payload(self) -> Payload);
    dispatch!(pub fn merkle_root(&self) -> Result<Hash, Error>);
    dispatch!(pub fn payload(&self) -> &Payload);
    dispatch!(pub fn sanitize(&self) -> Result<(), Error>);

    pub fn new_from_serialized_shred<T>(shred: T) -> Result<Self, Error>
    where
        T: AsRef<[u8]> + Into<Payload>,
        Payload: From<T>,
    {
        Ok(match layout::get_shred_variant(shred.as_ref())? {
            ShredVariant::MerkleCode { .. } => {
                let shred = merkle::ShredCode::from_payload(shred)?;
                Self::ShredCode(shred)
            }
            ShredVariant::MerkleData { .. } => {
                let shred = merkle::ShredData::from_payload(shred)?;
                Self::ShredData(shred)
            }
        })
    }

    /// Unique identifier for each shred.
    pub fn id(&self) -> ShredId {
        ShredId(self.slot(), self.index(), self.shred_type())
    }

    pub fn slot(&self) -> Slot {
        self.common_header().slot
    }

    pub fn parent(&self) -> Result<Slot, Error> {
        match self {
            Self::ShredCode(_) => Err(Error::InvalidShredType),
            Self::ShredData(shred) => shred.parent(),
        }
    }

    pub fn index(&self) -> u32 {
        self.common_header().index
    }

    pub fn fec_set_index(&self) -> u32 {
        self.common_header().fec_set_index
    }

    pub(crate) fn first_coding_index(&self) -> Option<u32> {
        match self {
            Self::ShredCode(shred) => shred.first_coding_index(),
            Self::ShredData(_) => None,
        }
    }

    pub fn version(&self) -> u16 {
        self.common_header().version
    }

    // Identifier for the erasure coding set that the shred belongs to.
    pub(crate) fn erasure_set(&self) -> ErasureSetId {
        ErasureSetId(self.slot(), self.fec_set_index())
    }

    pub fn signature(&self) -> &Signature {
        &self.common_header().signature
    }

    #[inline]
    pub fn shred_type(&self) -> ShredType {
        ShredType::from(self.common_header().shred_variant)
    }

    #[inline]
    pub fn is_data(&self) -> bool {
        self.shred_type() == ShredType::Data
    }

    #[inline]
    pub fn is_code(&self) -> bool {
        self.shred_type() == ShredType::Code
    }

    pub fn last_in_slot(&self) -> bool {
        match self {
            Self::ShredCode(_) => false,
            Self::ShredData(shred) => shred.last_in_slot(),
        }
    }

    pub fn data_complete(&self) -> bool {
        match self {
            Self::ShredCode(_) => false,
            Self::ShredData(shred) => shred.data_complete(),
        }
    }

    pub(crate) fn reference_tick(&self) -> u8 {
        match self {
            Self::ShredCode(_) => ShredFlags::SHRED_TICK_REFERENCE_MASK.bits(),
            Self::ShredData(shred) => shred.reference_tick(),
        }
    }

    #[must_use]
    pub fn verify(&self, pubkey: &Pubkey) -> bool {
        match self.signed_data() {
            Ok(data) => self.signature().verify(pubkey.as_ref(), data.as_ref()),
            Err(_) => false,
        }
    }

    // Returns true if the erasure coding of the two shreds mismatch.
    pub(crate) fn erasure_mismatch(&self, other: &Self) -> Result<bool, Error> {
        match (self, other) {
            (Self::ShredCode(shred), Self::ShredCode(other)) => Ok(shred.erasure_mismatch(other)),
            _ => Err(Error::InvalidShredType),
        }
    }

    pub(crate) fn num_data_shreds(&self) -> Result<u16, Error> {
        match self {
            Self::ShredCode(shred) => Ok(shred.num_data_shreds()),
            Self::ShredData(_) => Err(Error::InvalidShredType),
        }
    }

    pub(crate) fn num_coding_shreds(&self) -> Result<u16, Error> {
        match self {
            Self::ShredCode(shred) => Ok(shred.num_coding_shreds()),
            Self::ShredData(_) => Err(Error::InvalidShredType),
        }
    }

    /// Returns true if the other shred has the same ShredId but different payload.
    pub fn is_shred_duplicate(&self, other: &Shred) -> bool {
        if self.id() != other.id() {
            return false;
        }
        fn get_payload(shred: &Shred) -> &[u8] {
            let Ok(offset) = shred.retransmitter_signature_offset() else {
                return shred.payload();
            };
            debug_assert_eq!(offset + SIZE_OF_SIGNATURE, shred.payload().len());
            shred
                .payload()
                .get(..offset)
                .unwrap_or_else(|| shred.payload())
        }
        get_payload(self) != get_payload(other)
    }
}

impl From<merkle::Shred> for Shred {
    fn from(shred: merkle::Shred) -> Self {
        match shred {
            merkle::Shred::ShredCode(shred) => Self::ShredCode(shred),
            merkle::Shred::ShredData(shred) => Self::ShredData(shred),
        }
    }
}

impl TryFrom<Shred> for merkle::Shred {
    type Error = Error;

    fn try_from(shred: Shred) -> Result<Self, Self::Error> {
        match shred {
            Shred::ShredCode(shred) => Ok(Self::ShredCode(shred)),
            Shred::ShredData(shred) => Ok(Self::ShredData(shred)),
        }
    }
}

impl From<ShredVariant> for ShredType {
    #[inline]
    fn from(shred_variant: ShredVariant) -> Self {
        match shred_variant {
            ShredVariant::MerkleCode { .. } => ShredType::Code,
            ShredVariant::MerkleData { .. } => ShredType::Data,
        }
    }
}

impl From<ShredVariant> for u8 {
    #[inline]
    fn from(shred_variant: ShredVariant) -> u8 {
        match shred_variant {
            ShredVariant::MerkleCode {
                proof_size,
                resigned: false,
            } => proof_size | 0x60,
            ShredVariant::MerkleCode {
                proof_size,
                resigned: true,
            } => proof_size | 0x70,
            ShredVariant::MerkleData {
                proof_size,
                resigned: false,
            } => proof_size | 0x90,
            ShredVariant::MerkleData {
                proof_size,
                resigned: true,
            } => proof_size | 0xb0,
        }
    }
}

impl TryFrom<u8> for ShredVariant {
    type Error = Error;
    #[inline]
    fn try_from(shred_variant: u8) -> Result<Self, Self::Error> {
        if shred_variant == u8::from(ShredType::Code) || shred_variant == u8::from(ShredType::Data)
        {
            Err(Error::InvalidShredVariant)
        } else {
            let proof_size = shred_variant & 0x0F;
            match shred_variant & 0xF0 {
                0x60 => Ok(ShredVariant::MerkleCode {
                    proof_size,
                    resigned: false,
                }),
                0x70 => Ok(ShredVariant::MerkleCode {
                    proof_size,
                    resigned: true,
                }),
                0x90 => Ok(ShredVariant::MerkleData {
                    proof_size,
                    resigned: false,
                }),
                0xb0 => Ok(ShredVariant::MerkleData {
                    proof_size,
                    resigned: true,
                }),
                _ => Err(Error::InvalidShredVariant),
            }
        }
    }
}

unsafe impl<C: ConfigCore> SchemaWrite<C> for ShredVariant {
    type Src = Self;
    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: 1,
        zero_copy: false,
    };

    fn size_of(_src: &Self::Src) -> wincode::WriteResult<usize> {
        Ok(1)
    }

    fn write(writer: impl Writer, src: &Self::Src) -> wincode::WriteResult<()> {
        let repr: u8 = (*src).into();
        <u8 as SchemaWrite<C>>::write(writer, &repr)
    }
}

unsafe impl<'a, C: ConfigCore> SchemaRead<'a, C> for ShredVariant {
    type Dst = Self;
    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: 1,
        zero_copy: false,
    };

    fn read(reader: impl Reader<'a>, dst: &mut MaybeUninit<Self::Dst>) -> wincode::ReadResult<()> {
        let repr = <u8 as SchemaRead<C>>::get(reader)?;
        let value = Self::try_from(repr)
            .map_err(|_| wincode::ReadError::InvalidTagEncoding(repr as usize))?;
        dst.write(value);
        Ok(())
    }
}

// ---- ReedSolomonCache (vendored from shredder.rs) ----

use {
    lazy_lru::LruCache,
    reed_solomon_erasure::galois_8::ReedSolomon,
    std::sync::{Arc, OnceLock, RwLock},
};

// Arc<...> wrapper so that cache entries can be initialized without locking
// the entire cache.
type LruCacheOnce<K, V> = RwLock<LruCache<K, Arc<OnceLock<V>>>>;

pub struct ReedSolomonCache(
    LruCacheOnce<
        (usize, usize), // number of {data,parity} shards
        Result<Arc<ReedSolomon>, reed_solomon_erasure::Error>,
    >,
);

impl ReedSolomonCache {
    const CAPACITY: usize = 4 * DATA_SHREDS_PER_FEC_BLOCK;

    pub(crate) fn get(
        &self,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<Arc<ReedSolomon>, reed_solomon_erasure::Error> {
        let key = (data_shards, parity_shards);
        // Read from the cache with a shared lock.
        let entry = self.0.read().unwrap().get(&key).cloned();
        // Fall back to exclusive lock if there is a cache miss.
        let entry: Arc<OnceLock<Result<_, _>>> = entry.unwrap_or_else(|| {
            let mut cache = self.0.write().unwrap();
            cache.get(&key).cloned().unwrap_or_else(|| {
                let entry = Arc::<OnceLock<Result<_, _>>>::default();
                cache.put(key, Arc::clone(&entry));
                entry
            })
        });
        // Initialize if needed by only a single thread outside locks.
        entry
            .get_or_init(|| ReedSolomon::new(data_shards, parity_shards).map(Arc::new))
            .clone()
    }
}

impl Default for ReedSolomonCache {
    fn default() -> Self {
        Self(RwLock::new(LruCache::new(Self::CAPACITY)))
    }
}

// ---- recover ----

pub fn recover<T: IntoIterator<Item = Shred>>(
    shreds: T,
    reed_solomon_cache: &ReedSolomonCache,
) -> Result<impl Iterator<Item = Result<Shred, Error>> + use<T>, Error> {
    let shreds = shreds
        .into_iter()
        .map(|shred| {
            debug_assert_matches!(
                shred.common_header().shred_variant,
                ShredVariant::MerkleCode { .. } | ShredVariant::MerkleData { .. }
            );
            merkle::Shred::try_from(shred)
        })
        .collect::<Result<_, _>>()?;
    let shreds = merkle::recover(shreds, reed_solomon_cache)?;
    Ok(shreds.map(|shred| shred.map(Shred::from)))
}

/// Fast recovery — RS reconstruct only, skips merkle tree/proof/root verification.
/// Returns only recovered DATA shreds with parsed headers.
///
/// Use this when you only need the data payloads (e.g. transaction parsing)
/// and don't need merkle-valid shreds for retransmission.
pub fn recover_data_only<T: IntoIterator<Item = Shred>>(
    shreds: T,
    reed_solomon_cache: &ReedSolomonCache,
) -> Result<Vec<Shred>, Error> {
    let shreds = shreds
        .into_iter()
        .map(|shred| merkle::Shred::try_from(shred))
        .collect::<Result<_, _>>()?;
    let recovered = merkle::recover_data_only(shreds, reed_solomon_cache)?;
    Ok(recovered.into_iter().map(Shred::from).collect())
}

/// Inline replacement for crate::blockstore::verify_shred_slots
fn verify_shred_slots(slot: Slot, parent: Slot, root: Slot) -> bool {
    if slot == 0 && parent == 0 && root == 0 {
        return true;
    }
    root <= parent && parent < slot
}

// Accepts shreds in the slot range [root + 1, max_slot].
#[must_use]
pub fn should_discard_shred(
    shred: &[u8],
    root: Slot,
    max_slot: Slot,
    shred_version: u16,
    discard_unexpected_data_complete_shreds: impl Fn(Slot) -> bool,
    stats: &mut ShredFetchStats,
) -> bool {
    debug_assert!(root < max_slot);
    let Some(shred) = layout::get_shred_from_buf(shred) else {
        stats.index_overrun += 1;
        return true;
    };
    match layout::get_version(shred) {
        None => {
            stats.index_overrun += 1;
            return true;
        }
        Some(version) => {
            if version != shred_version {
                stats.shred_version_mismatch += 1;
                return true;
            }
        }
    }
    let Ok(shred_variant) = layout::get_shred_variant(shred) else {
        stats.bad_shred_type += 1;
        return true;
    };
    let slot = match layout::get_slot(shred) {
        Some(slot) => {
            if slot > max_slot {
                stats.slot_out_of_range += 1;
                return true;
            }
            slot
        }
        None => {
            stats.slot_bad_deserialize += 1;
            return true;
        }
    };
    let Some(index) = layout::get_index(shred) else {
        stats.index_bad_deserialize += 1;
        return true;
    };
    let Some(fec_set_index) = layout::get_fec_set_index(shred) else {
        stats.fec_set_index_bad_deserialize += 1;
        return true;
    };

    match ShredType::from(shred_variant) {
        ShredType::Code => {
            if index >= MAX_CODE_SHREDS_PER_SLOT as u32 {
                stats.index_out_of_bounds += 1;
                return true;
            }
            if slot <= root {
                stats.slot_out_of_range += 1;
                return true;
            }

            let Ok(erasure_config) = layout::get_erasure_config(shred) else {
                stats.erasure_config_bad_deserialize += 1;
                return true;
            };

            if !erasure_config.is_fixed() {
                stats.misaligned_erasure_config += 1;
                return true;
            }
        }
        ShredType::Data => {
            if index >= MAX_DATA_SHREDS_PER_SLOT as u32 {
                stats.index_out_of_bounds += 1;
                return true;
            }
            let Some(parent_offset) = layout::get_parent_offset(shred) else {
                stats.bad_parent_offset += 1;
                return true;
            };
            let Some(parent) = slot.checked_sub(Slot::from(parent_offset)) else {
                stats.bad_parent_offset += 1;
                return true;
            };
            if !verify_shred_slots(slot, parent, root) {
                stats.slot_out_of_range += 1;
                return true;
            }

            let Ok(shred_flags) = layout::get_flags(shred) else {
                stats.shred_flags_bad_deserialize += 1;
                return true;
            };

            let expected_data_complete_index = fec_set_index
                .checked_add(DATA_SHREDS_PER_FEC_BLOCK as u32)
                .and_then(|index| index.checked_sub(1));
            if shred_flags.contains(ShredFlags::DATA_COMPLETE_SHRED)
                && (expected_data_complete_index != Some(index))
            {
                stats.unexpected_data_complete_shred += 1;

                if discard_unexpected_data_complete_shreds(slot) {
                    return true;
                }
            }

            if shred_flags.contains(ShredFlags::LAST_SHRED_IN_SLOT)
                && !check_last_data_shred_index(index)
            {
                stats.misaligned_last_data_index += 1;
                return true;
            }
        }
    }

    if !check_fixed_fec_set(index, fec_set_index) {
        stats.misaligned_fec_set += 1;
        return true;
    }

    match shred_variant {
        ShredVariant::MerkleCode { .. } => {
            stats.num_shreds_merkle_code_chained =
                stats.num_shreds_merkle_code_chained.saturating_add(1);
        }
        ShredVariant::MerkleData { .. } => {
            stats.num_shreds_merkle_data_chained =
                stats.num_shreds_merkle_data_chained.saturating_add(1);
        }
    }
    false
}

/// Returns true if `index` and `fec_set_index` are valid under the assumption that
/// all erasure sets contain exactly `DATA_SHREDS_PER_FEC_BLOCK` data and coding shreds:
/// - `index` is between `fec_set_index` and `fec_set_index + DATA_SHREDS_PER_FEC_BLOCK`
/// - `fec_set_index` is a multiple of `DATA_SHREDS_PER_FEC_BLOCK`
fn check_fixed_fec_set(index: u32, fec_set_index: u32) -> bool {
    let Some(fec_set_end_exclusive) = fec_set_index.checked_add(DATA_SHREDS_PER_FEC_BLOCK as u32)
    else {
        return false;
    };
    index >= fec_set_index
        && index < fec_set_end_exclusive
        && fec_set_index.is_multiple_of(DATA_SHREDS_PER_FEC_BLOCK as u32)
}

/// Returns true if `index` of the last data shred is valid under the assumption that
/// all erasure sets contain exactly `DATA_SHREDS_PER_FEC_BLOCK` data and coding shreds:
/// - `index + 1` must be a multiple of `DATA_SHREDS_PER_FEC_BLOCK`
///
/// Note: this check is critical to verify that the last fec set is sufficiently sized.
fn check_last_data_shred_index(index: u32) -> bool {
    (index + 1).is_multiple_of(DATA_SHREDS_PER_FEC_BLOCK as u32)
}
