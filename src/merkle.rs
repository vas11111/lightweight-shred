#![allow(dead_code)]
use {
    super::{
        CodingShredHeader,
        DataShredHeader, Error,
        SIZE_OF_CODING_SHRED_HEADERS, SIZE_OF_DATA_SHRED_HEADERS, SIZE_OF_NONCE,
        SIZE_OF_SIGNATURE, ShredCommonHeader, ShredFlags, ShredVariant,
        common::impl_shred_common,
        dispatch,
        merkle_tree::*,
        payload::{Payload, PayloadMutGuard},
        shred_code, shred_data,
        traits::{
            Shred as ShredTrait, ShredCode as ShredCodeTrait, ShredData as ShredDataTrait,
        },
        ReedSolomonCache,
        PACKET_DATA_SIZE,
    },
    assert_matches::debug_assert_matches,
    itertools::{Either, Itertools},
    reed_solomon_erasure::Error::{InvalidIndex, TooFewParityShards},
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_sha256_hasher::hashv,
    solana_signature::Signature,
    static_assertions::const_assert_eq,
    std::{
        cmp::Ordering,
        io::{Cursor, Write},
        ops::Range,
    },
};

const_assert_eq!(ShredData::SIZE_OF_PAYLOAD, 1203);
const_assert_eq!(ShredCode::SIZE_OF_PAYLOAD, 1228);

// Layout: {common, data} headers | data buffer
//     | [Merkle root of the previous erasure batch if chained]
//     | Merkle proof
//     | [Retransmitter's signature if resigned]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShredData {
    common_header: ShredCommonHeader,
    data_header: DataShredHeader,
    payload: Payload,
}

// Layout: {common, coding} headers | erasure coded shard
//     | [Merkle root of the previous erasure batch if chained]
//     | Merkle proof
//     | [Retransmitter's signature if resigned]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShredCode {
    common_header: ShredCommonHeader,
    coding_header: CodingShredHeader,
    payload: Payload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Shred {
    ShredCode(ShredCode),
    ShredData(ShredData),
}

impl Shred {
    dispatch!(fn erasure_shard_index(&self) -> Result<usize, Error>);
    dispatch!(fn erasure_shard_mut(&mut self) -> Result<PayloadMutGuard<'_, Range<usize>>, Error>);
    dispatch!(fn merkle_node(&self) -> Result<Hash, Error>);
    dispatch!(fn sanitize(&self) -> Result<(), Error>);
    dispatch!(fn set_chained_merkle_root(&mut self, chained_merkle_root: &Hash) -> Result<(), Error>);
    dispatch!(fn set_signature(&mut self, signature: Signature));
    dispatch!(fn signed_data(&self) -> Result<Hash, Error>);
    dispatch!(pub(super) fn common_header(&self) -> &ShredCommonHeader);
    dispatch!(pub(super) fn payload(&self) -> &Payload);
    dispatch!(pub(super) fn set_retransmitter_signature(&mut self, signature: &Signature) -> Result<(), Error>);

    #[inline]
    fn fec_set_index(&self) -> u32 {
        self.common_header().fec_set_index
    }

    #[inline]
    fn merkle_proof(&self) -> Result<impl Iterator<Item = &MerkleProofEntry>, Error> {
        match self {
            Self::ShredCode(shred) => shred.merkle_proof().map(Either::Left),
            Self::ShredData(shred) => shred.merkle_proof().map(Either::Right),
        }
    }

    #[inline]
    fn set_merkle_proof<'a, I>(&mut self, proof: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = Result<&'a MerkleProofEntry, Error>>,
    {
        match self {
            Self::ShredCode(shred) => shred.set_merkle_proof(proof),
            Self::ShredData(shred) => shred.set_merkle_proof(proof),
        }
    }

    #[must_use]
    fn verify(&self, pubkey: &Pubkey) -> bool {
        match self.signed_data() {
            Ok(data) => self.signature().verify(pubkey.as_ref(), data.as_ref()),
            Err(_) => false,
        }
    }

    #[inline]
    fn signature(&self) -> &Signature {
        &self.common_header().signature
    }

    pub(super) fn from_payload<T: AsRef<[u8]>>(shred: T) -> Result<Self, Error>
    where
        Payload: From<T>,
    {
        match super::layout::get_shred_variant(shred.as_ref())? {
            ShredVariant::MerkleCode { .. } => Ok(Self::ShredCode(ShredCode::from_payload(shred)?)),
            ShredVariant::MerkleData { .. } => Ok(Self::ShredData(ShredData::from_payload(shred)?)),
        }
    }
}

impl ShredData {
    impl_merkle_shred!(MerkleData);

    // Offset into the payload where the erasure coded slice begins.
    const ERASURE_SHARD_START_OFFSET: usize = SIZE_OF_SIGNATURE;

    /// Parse headers only — skip sanitize/merkle proof validation.
    pub(super) fn from_payload_unchecked<T>(payload: T) -> Result<Self, Error>
    where
        Payload: From<T>,
    {
        let mut payload = Payload::from(payload);
        if payload.len() < Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(payload.len()));
        }
        payload.truncate(Self::SIZE_OF_PAYLOAD);
        let (common_header, data_header) = wincode::deserialize(&payload[..])?;
        Ok(Self { common_header, data_header, payload })
    }

    pub(super) fn get_data(
        shred: &[u8],
        proof_size: u8,
        resigned: bool,
        size: u16,
    ) -> Result<&[u8], Error> {
        let size = usize::from(size);
        let data_buffer_size = Self::capacity(proof_size, resigned)?;
        (Self::SIZE_OF_HEADERS..=Self::SIZE_OF_HEADERS + data_buffer_size)
            .contains(&size)
            .then(|| shred.get(Self::SIZE_OF_HEADERS..size))
            .flatten()
            .ok_or_else(|| Error::InvalidDataSize {
                size: size as u16,
                payload: shred.len(),
            })
    }

    pub(super) fn get_merkle_root(shred: &[u8], proof_size: u8, resigned: bool) -> Option<Hash> {
        debug_assert_eq!(
            super::layout::get_shred_variant(shred).unwrap(),
            ShredVariant::MerkleData {
                proof_size,
                resigned,
            },
        );
        let index = {
            let fec_set_index = super::layout::get_fec_set_index(shred)?;
            super::layout::get_index(shred)?
                .checked_sub(fec_set_index)
                .map(usize::try_from)?
                .ok()?
        };
        let proof_offset = Self::get_proof_offset(proof_size, resigned).ok()?;
        let proof = get_merkle_proof(shred, proof_offset, proof_size).ok()?;
        let node = get_merkle_node(shred, SIZE_OF_SIGNATURE..proof_offset).ok()?;
        get_merkle_root(index, node, proof).ok()
    }

    pub(crate) const fn const_capacity(proof_size: u8, resigned: bool) -> Result<usize, u8> {
        match Self::SIZE_OF_PAYLOAD.checked_sub(
            Self::SIZE_OF_HEADERS
                + SIZE_OF_MERKLE_ROOT
                + (proof_size as usize) * SIZE_OF_MERKLE_PROOF_ENTRY
                + if resigned { SIZE_OF_SIGNATURE } else { 0 },
        ) {
            Some(v) => Ok(v),
            None => Err(proof_size),
        }
    }

    pub(super) fn last_in_slot(&self) -> bool {
        self.data_header
            .flags
            .contains(ShredFlags::LAST_SHRED_IN_SLOT)
    }

    pub(super) fn data_complete(&self) -> bool {
        self.data_header
            .flags
            .contains(ShredFlags::DATA_COMPLETE_SHRED)
    }

    pub(super) fn reference_tick(&self) -> u8 {
        (self.data_header.flags & ShredFlags::SHRED_TICK_REFERENCE_MASK).bits()
    }
}

impl ShredCode {
    impl_merkle_shred!(MerkleCode);

    // Offset into the payload where the erasure coded slice begins.
    const ERASURE_SHARD_START_OFFSET: usize = Self::SIZE_OF_HEADERS;

    /// Parse headers only — skip sanitize/merkle proof validation.
    pub(super) fn from_payload_unchecked<T>(payload: T) -> Result<Self, Error>
    where
        Payload: From<T>,
    {
        let mut payload = Payload::from(payload);
        let (common_header, coding_header) = wincode::deserialize(&payload[..])?;
        if payload.len() < Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(payload.len()));
        }
        payload.truncate(Self::SIZE_OF_PAYLOAD);
        Ok(Self { common_header, coding_header, payload })
    }

    pub(super) fn get_merkle_root(shred: &[u8], proof_size: u8, resigned: bool) -> Option<Hash> {
        debug_assert_eq!(
            super::layout::get_shred_variant(shred).unwrap(),
            ShredVariant::MerkleCode {
                proof_size,
                resigned,
            },
        );
        let index = {
            let num_data_shreds = <[u8; 2]>::try_from(shred.get(83..85)?)
                .map(u16::from_le_bytes)
                .map(usize::from)
                .ok()?;
            let position = <[u8; 2]>::try_from(shred.get(87..89)?)
                .map(u16::from_le_bytes)
                .map(usize::from)
                .ok()?;
            num_data_shreds.checked_add(position)?
        };
        let proof_offset = Self::get_proof_offset(proof_size, resigned).ok()?;
        let proof = get_merkle_proof(shred, proof_offset, proof_size).ok()?;
        let node = get_merkle_node(shred, SIZE_OF_SIGNATURE..proof_offset).ok()?;
        get_merkle_root(index, node, proof).ok()
    }

    pub(super) fn first_coding_index(&self) -> Option<u32> {
        let position = u32::from(self.coding_header.position);
        self.common_header.index.checked_sub(position)
    }

    pub(super) fn num_data_shreds(&self) -> u16 {
        self.coding_header.num_data_shreds
    }

    pub(super) fn num_coding_shreds(&self) -> u16 {
        self.coding_header.num_coding_shreds
    }

    pub(super) fn erasure_mismatch(&self, other: &ShredCode) -> bool {
        let CodingShredHeader {
            num_data_shreds,
            num_coding_shreds,
            position: _,
        } = &self.coding_header;
        num_coding_shreds != &other.coding_header.num_coding_shreds
            || num_data_shreds != &other.coding_header.num_data_shreds
            || self.first_coding_index() != other.first_coding_index()
            || self.common_header.signature != other.common_header.signature
    }
}

macro_rules! impl_merkle_shred {
    ($variant:ident) => {
        #[inline]
        fn proof_size(&self) -> Result<u8, Error> {
            match self.common_header.shred_variant {
                ShredVariant::$variant { proof_size, .. } => Ok(proof_size),
                _ => Err(Error::InvalidShredVariant),
            }
        }

        pub fn capacity(proof_size: u8, resigned: bool) -> Result<usize, Error> {
            Self::SIZE_OF_PAYLOAD
                .checked_sub(
                    Self::SIZE_OF_HEADERS
                        + SIZE_OF_MERKLE_ROOT
                        + usize::from(proof_size) * SIZE_OF_MERKLE_PROOF_ENTRY
                        + if resigned { SIZE_OF_SIGNATURE } else { 0 },
                )
                .ok_or(Error::InvalidProofSize(proof_size))
        }

        fn proof_offset(&self) -> Result<usize, Error> {
            let ShredVariant::$variant {
                proof_size,
                resigned,
            } = self.common_header.shred_variant
            else {
                return Err(Error::InvalidShredVariant);
            };
            Self::get_proof_offset(proof_size, resigned)
        }

        fn get_proof_offset(proof_size: u8, resigned: bool) -> Result<usize, Error> {
            Ok(Self::SIZE_OF_HEADERS + Self::capacity(proof_size, resigned)? + SIZE_OF_MERKLE_ROOT)
        }

        fn chained_merkle_root_offset(&self) -> Result<usize, Error> {
            let ShredVariant::$variant {
                proof_size,
                resigned,
            } = self.common_header.shred_variant
            else {
                return Err(Error::InvalidShredVariant);
            };
            Self::get_chained_merkle_root_offset(proof_size, resigned)
        }

        pub(super) fn get_chained_merkle_root_offset(
            proof_size: u8,
            resigned: bool,
        ) -> Result<usize, Error> {
            Ok(Self::SIZE_OF_HEADERS + Self::capacity(proof_size, resigned)?)
        }

        pub(super) fn chained_merkle_root(&self) -> Result<Hash, Error> {
            let offset = self.chained_merkle_root_offset()?;
            self.payload
                .get(offset..offset + SIZE_OF_MERKLE_ROOT)
                .map(|chained_merkle_root| {
                    <[u8; SIZE_OF_MERKLE_ROOT]>::try_from(chained_merkle_root)
                        .map(Hash::new_from_array)
                        .unwrap()
                })
                .ok_or(Error::InvalidPayloadSize(self.payload.len()))
        }

        fn set_chained_merkle_root(&mut self, chained_merkle_root: &Hash) -> Result<(), Error> {
            let offset = self.chained_merkle_root_offset()?;
            let Some(mut buffer) = self.payload.get_mut(offset..offset + SIZE_OF_MERKLE_ROOT)
            else {
                return Err(Error::InvalidPayloadSize(self.payload.len()));
            };
            buffer.copy_from_slice(chained_merkle_root.as_ref());
            Ok(())
        }

        pub(super) fn merkle_root(&self) -> Result<Hash, Error> {
            let proof_size = self.proof_size()?;
            let index = self.erasure_shard_index()?;
            let proof_offset = self.proof_offset()?;
            let proof = get_merkle_proof(&self.payload, proof_offset, proof_size)?;
            let node = get_merkle_node(&self.payload, SIZE_OF_SIGNATURE..proof_offset)?;
            get_merkle_root(index, node, proof)
        }

        fn merkle_proof(&self) -> Result<impl Iterator<Item = &MerkleProofEntry>, Error> {
            let proof_size = self.proof_size()?;
            let proof_offset = self.proof_offset()?;
            get_merkle_proof(&self.payload, proof_offset, proof_size)
        }

        fn merkle_node(&self) -> Result<Hash, Error> {
            let proof_offset = self.proof_offset()?;
            get_merkle_node(&self.payload, SIZE_OF_SIGNATURE..proof_offset)
        }

        fn set_merkle_proof<'a, I>(&mut self, proof: I) -> Result<(), Error>
        where
            I: IntoIterator<Item = Result<&'a MerkleProofEntry, Error>>,
        {
            let proof_size = self.proof_size()?;
            let proof_offset = self.proof_offset()?;
            let mut slice = self
                .payload
                .get_mut(proof_offset..)
                .ok_or(Error::InvalidProofSize(proof_size))?;
            let mut cursor = Cursor::new(slice.as_mut());
            let proof_size = usize::from(proof_size);
            proof.into_iter().enumerate().try_for_each(|(k, entry)| {
                if k >= proof_size {
                    return Err(Error::InvalidMerkleProof);
                }
                Ok(cursor.write_all(&entry?[..])?)
            })?;
            if cursor.position() as usize != proof_size * SIZE_OF_MERKLE_PROOF_ENTRY {
                return Err(Error::InvalidMerkleProof);
            }
            Ok(())
        }

        pub(super) fn retransmitter_signature(&self) -> Result<Signature, Error> {
            let offset = self.retransmitter_signature_offset()?;
            self.payload
                .get(offset..offset + SIZE_OF_SIGNATURE)
                .map(|bytes| <[u8; SIZE_OF_SIGNATURE]>::try_from(bytes).unwrap())
                .map(Signature::from)
                .ok_or(Error::InvalidPayloadSize(self.payload.len()))
        }

        fn set_retransmitter_signature(&mut self, signature: &Signature) -> Result<(), Error> {
            let offset = self.retransmitter_signature_offset()?;
            let Some(mut buffer) = self.payload.get_mut(offset..offset + SIZE_OF_SIGNATURE) else {
                return Err(Error::InvalidPayloadSize(self.payload.len()));
            };
            buffer.copy_from_slice(signature.as_ref());
            Ok(())
        }

        pub(super) fn retransmitter_signature_offset(&self) -> Result<usize, Error> {
            let ShredVariant::$variant {
                proof_size,
                resigned,
            } = self.common_header.shred_variant
            else {
                return Err(Error::InvalidShredVariant);
            };
            Self::get_retransmitter_signature_offset(proof_size, resigned)
        }

        pub(super) fn get_retransmitter_signature_offset(
            proof_size: u8,
            resigned: bool,
        ) -> Result<usize, Error> {
            if !resigned {
                return Err(Error::InvalidShredVariant);
            }
            let proof_offset = Self::get_proof_offset(proof_size, resigned)?;
            Ok(proof_offset + usize::from(proof_size) * SIZE_OF_MERKLE_PROOF_ENTRY)
        }

        fn erasure_shard_offsets(&self) -> Result<Range<usize>, Error> {
            if self.payload.len() != Self::SIZE_OF_PAYLOAD {
                return Err(Error::InvalidPayloadSize(self.payload.len()));
            }
            let ShredVariant::$variant {
                proof_size,
                resigned,
            } = self.common_header.shred_variant
            else {
                return Err(Error::InvalidShredVariant);
            };
            let offset = Self::SIZE_OF_HEADERS + Self::capacity(proof_size, resigned)?;
            Ok(Self::ERASURE_SHARD_START_OFFSET..offset)
        }

        fn erasure_shard(&self) -> Result<&[u8], Error> {
            self.payload
                .get(self.erasure_shard_offsets()?)
                .ok_or(Error::InvalidPayloadSize(self.payload.len()))
        }

        fn erasure_shard_mut(&mut self) -> Result<PayloadMutGuard<'_, Range<usize>>, Error> {
            let offsets = self.erasure_shard_offsets()?;
            let payload_size = self.payload.len();
            self.payload
                .get_mut(offsets)
                .ok_or(Error::InvalidPayloadSize(payload_size))
        }
    };
}

use impl_merkle_shred;

impl<'a> ShredTrait<'a> for ShredData {
    type SignedData = Hash;

    impl_shred_common!();

    const SIZE_OF_PAYLOAD: usize =
        ShredCode::SIZE_OF_PAYLOAD - ShredCode::SIZE_OF_HEADERS + SIZE_OF_SIGNATURE;
    const SIZE_OF_HEADERS: usize = SIZE_OF_DATA_SHRED_HEADERS;

    fn from_payload<T>(payload: T) -> Result<Self, Error>
    where
        Payload: From<T>,
    {
        let mut payload = Payload::from(payload);
        if payload.len() < Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(payload.len()));
        }
        payload.truncate(Self::SIZE_OF_PAYLOAD);
        let (common_header, data_header): (ShredCommonHeader, _) =
            wincode::deserialize(&payload[..])?;
        if !matches!(common_header.shred_variant, ShredVariant::MerkleData { .. }) {
            return Err(Error::InvalidShredVariant);
        }
        let shred = Self {
            common_header,
            data_header,
            payload,
        };
        shred.sanitize()?;
        Ok(shred)
    }

    fn erasure_shard_index(&self) -> Result<usize, Error> {
        shred_data::erasure_shard_index(self).ok_or_else(|| {
            let headers = Box::new((self.common_header, self.data_header));
            Error::InvalidErasureShardIndex(headers)
        })
    }

    fn erasure_shard(&self) -> Result<&[u8], Error> {
        Self::erasure_shard(self)
    }

    fn sanitize(&self) -> Result<(), Error> {
        let shred_variant = self.common_header.shred_variant;
        if !matches!(shred_variant, ShredVariant::MerkleData { .. }) {
            return Err(Error::InvalidShredVariant);
        }
        let _ = self.merkle_proof()?;
        shred_data::sanitize(self)
    }

    fn signed_data(&'a self) -> Result<Self::SignedData, Error> {
        self.merkle_root()
    }
}

impl<'a> ShredTrait<'a> for ShredCode {
    type SignedData = Hash;

    impl_shred_common!();
    const SIZE_OF_PAYLOAD: usize = PACKET_DATA_SIZE - SIZE_OF_NONCE;
    const SIZE_OF_HEADERS: usize = SIZE_OF_CODING_SHRED_HEADERS;

    fn from_payload<T>(payload: T) -> Result<Self, Error>
    where
        Payload: From<T>,
    {
        let mut payload = Payload::from(payload);
        let (common_header, coding_header): (ShredCommonHeader, _) =
            wincode::deserialize(&payload[..])?;
        if !matches!(common_header.shred_variant, ShredVariant::MerkleCode { .. }) {
            return Err(Error::InvalidShredVariant);
        }
        if payload.len() < Self::SIZE_OF_PAYLOAD {
            return Err(Error::InvalidPayloadSize(payload.len()));
        }
        payload.truncate(Self::SIZE_OF_PAYLOAD);
        let shred = Self {
            common_header,
            coding_header,
            payload,
        };
        shred.sanitize()?;
        Ok(shred)
    }

    fn erasure_shard_index(&self) -> Result<usize, Error> {
        shred_code::erasure_shard_index(self).ok_or_else(|| {
            let headers = Box::new((self.common_header, self.coding_header));
            Error::InvalidErasureShardIndex(headers)
        })
    }

    fn erasure_shard(&self) -> Result<&[u8], Error> {
        Self::erasure_shard(self)
    }

    fn sanitize(&self) -> Result<(), Error> {
        let shred_variant = self.common_header.shred_variant;
        if !matches!(shred_variant, ShredVariant::MerkleCode { .. }) {
            return Err(Error::InvalidShredVariant);
        }
        let _ = self.merkle_proof()?;
        shred_code::sanitize(self)
    }

    fn signed_data(&'a self) -> Result<Self::SignedData, Error> {
        self.merkle_root()
    }
}

impl ShredDataTrait for ShredData {
    #[inline]
    fn data_header(&self) -> &DataShredHeader {
        &self.data_header
    }

    #[inline]
    fn data(&self) -> Result<&[u8], Error> {
        let ShredVariant::MerkleData {
            proof_size,
            resigned,
        } = self.common_header.shred_variant
        else {
            return Err(Error::InvalidShredVariant);
        };
        Self::get_data(&self.payload, proof_size, resigned, self.data_header.size)
    }
}

impl ShredCodeTrait for ShredCode {
    #[inline]
    fn coding_header(&self) -> &CodingShredHeader {
        &self.coding_header
    }
}

fn get_merkle_proof(
    shred: &[u8],
    proof_offset: usize,
    proof_size: u8,
) -> Result<impl Iterator<Item = &MerkleProofEntry>, Error> {
    let proof_size = usize::from(proof_size) * SIZE_OF_MERKLE_PROOF_ENTRY;
    Ok(shred
        .get(proof_offset..proof_offset + proof_size)
        .ok_or(Error::InvalidPayloadSize(shred.len()))?
        .chunks(SIZE_OF_MERKLE_PROOF_ENTRY)
        .map(<&MerkleProofEntry>::try_from)
        .map(Result::unwrap))
}

fn get_merkle_node(shred: &[u8], offsets: Range<usize>) -> Result<Hash, Error> {
    let node = shred
        .get(offsets)
        .ok_or(Error::InvalidPayloadSize(shred.len()))?;
    Ok(hashv(&[MERKLE_HASH_PREFIX_LEAF, node]))
}

pub(super) fn recover(
    mut shreds: Vec<Shred>,
    reed_solomon_cache: &ReedSolomonCache,
) -> Result<impl Iterator<Item = Result<Shred, Error>> + use<>, Error> {
    // Sort shreds by their erasure shard index.
    let is_sorted = |(a, b)| cmp_shred_erasure_shard_index(a, b).is_le();
    if !shreds.iter().tuple_windows().all(is_sorted) {
        shreds.sort_unstable_by(cmp_shred_erasure_shard_index);
    }
    let (common_header, coding_header, merkle_root, chained_merkle_root, retransmitter_signature) = {
        let Some(Shred::ShredCode(shred)) = shreds.last() else {
            return Err(Error::from(TooFewParityShards));
        };
        let position = u32::from(shred.coding_header.position);
        let index = shred.common_header.index.checked_sub(position);
        let common_header = ShredCommonHeader {
            index: index.ok_or(Error::from(InvalidIndex))?,
            ..shred.common_header
        };
        let coding_header = CodingShredHeader {
            position: 0u16,
            ..shred.coding_header
        };
        (
            common_header,
            coding_header,
            shred.merkle_root()?,
            shred.chained_merkle_root().ok(),
            shred.retransmitter_signature().ok(),
        )
    };
    debug_assert_matches!(common_header.shred_variant, ShredVariant::MerkleCode { .. });
    let (proof_size, resigned) = match common_header.shred_variant {
        ShredVariant::MerkleCode {
            proof_size,
            resigned,
        } => (proof_size, resigned),
        ShredVariant::MerkleData { .. } => {
            return Err(Error::InvalidShredVariant);
        }
    };
    debug_assert!(!resigned || retransmitter_signature.is_some());
    debug_assert!(shreds.iter().all(|shred| {
        let ShredCommonHeader {
            signature: _,
            shred_variant,
            slot,
            index: _,
            version,
            fec_set_index,
        } = shred.common_header();
        slot == &common_header.slot
            && version == &common_header.version
            && fec_set_index == &common_header.fec_set_index
            && match shred {
                Shred::ShredData(_) => {
                    shred_variant
                        == &ShredVariant::MerkleData {
                            proof_size,
                            resigned,
                        }
                }
                Shred::ShredCode(shred) => {
                    let CodingShredHeader {
                        num_data_shreds,
                        num_coding_shreds,
                        position: _,
                    } = shred.coding_header;
                    shred_variant
                        == &ShredVariant::MerkleCode {
                            proof_size,
                            resigned,
                        }
                        && num_data_shreds == coding_header.num_data_shreds
                        && num_coding_shreds == coding_header.num_coding_shreds
                }
            }
    }));
    let num_data_shreds = usize::from(coding_header.num_data_shreds);
    let num_coding_shreds = usize::from(coding_header.num_coding_shreds);
    let num_shards = num_data_shreds + num_coding_shreds;
    let mut mask = vec![false; num_shards];
    let mut shreds = {
        let make_stub_shred = |erasure_shard_index| {
            make_stub_shred(
                erasure_shard_index,
                &common_header,
                &coding_header,
                &chained_merkle_root,
                &retransmitter_signature,
            )
        };
        let mut batch = Vec::with_capacity(num_shards);
        for shred in shreds {
            if shred.signature() != &common_header.signature {
                return Err(Error::InvalidMerkleRoot);
            }
            let erasure_shard_index = shred.erasure_shard_index()?;
            if !(batch.len()..num_shards).contains(&erasure_shard_index) {
                return Err(Error::from(InvalidIndex));
            }
            while batch.len() < erasure_shard_index {
                batch.push(make_stub_shred(batch.len())?);
            }
            mask[erasure_shard_index] = true;
            batch.push(shred);
        }
        while batch.len() < num_shards {
            batch.push(make_stub_shred(batch.len())?);
        }
        batch
    };
    let mut shards = shreds
        .iter_mut()
        .zip(&mask)
        .map(|(shred, &mask)| Ok((shred.erasure_shard_mut()?, mask)))
        .collect::<Result<Vec<_>, Error>>()?;
    reed_solomon_cache
        .get(num_data_shreds, num_coding_shreds)?
        .reconstruct(&mut shards)?;
    drop(shards);
    let nodes = shreds
        .iter_mut()
        .zip(&mask)
        .enumerate()
        .map(|(index, (shred, mask))| {
            if !mask {
                if index < num_data_shreds {
                    let Shred::ShredData(shred) = shred else {
                        return Err(Error::InvalidRecoveredShred);
                    };
                    let (common_header, data_header) = wincode::deserialize(&shred.payload[..])?;
                    if shred.common_header != common_header {
                        return Err(Error::InvalidRecoveredShred);
                    }
                    shred.data_header = data_header;
                } else if !matches!(shred, Shred::ShredCode(_)) {
                    return Err(Error::InvalidRecoveredShred);
                }
                shred.sanitize()?;
            }
            shred.merkle_node()
        });
    let tree = MerkleTree::try_new(nodes)?;
    if tree.root() != &merkle_root {
        return Err(Error::InvalidMerkleRoot);
    }
    let set_merkle_proof = move |(index, (mut shred, mask)): (_, (Shred, _))| {
        if mask {
            debug_assert!({
                let proof = tree.make_merkle_proof(index, num_shards);
                shred.merkle_proof()?.map(Some).eq(proof.map(Result::ok))
            });
            Ok(None)
        } else {
            let proof = tree.make_merkle_proof(index, num_shards);
            shred.set_merkle_proof(proof)?;
            debug_assert_matches!(shred.sanitize(), Ok(()));
            debug_assert_eq!(shred, {
                let shred = shred.payload().clone();
                Shred::from_payload(shred).unwrap()
            });
            Ok(Some(shred))
        }
    };
    Ok(shreds
        .into_iter()
        .zip(mask)
        .enumerate()
        .map(set_merkle_proof)
        .filter_map(Result::transpose))
}

/// Fast recovery — RS reconstruct + header parse, skips merkle tree/proof/root verification.
/// Returns only the newly recovered DATA shreds (not coding, not originals).
///
/// Saves ~30-40% vs full `recover()` by skipping:
///   - SHA256 merkle node computation for every shard
///   - Merkle tree construction
///   - Root verification
///   - Proof generation + serialization into recovered shred payloads
pub(super) fn recover_data_only(
    mut shreds: Vec<Shred>,
    reed_solomon_cache: &ReedSolomonCache,
) -> Result<Vec<Shred>, Error> {
    let is_sorted = |(a, b)| cmp_shred_erasure_shard_index(a, b).is_le();
    if !shreds.iter().tuple_windows().all(is_sorted) {
        shreds.sort_unstable_by(cmp_shred_erasure_shard_index);
    }

    let (common_header, coding_header, chained_merkle_root, retransmitter_signature) = {
        let Some(Shred::ShredCode(shred)) = shreds.last() else {
            return Err(Error::from(TooFewParityShards));
        };
        let position = u32::from(shred.coding_header.position);
        let index = shred.common_header.index.checked_sub(position)
            .ok_or(Error::from(InvalidIndex))?;
        (
            ShredCommonHeader { index, ..shred.common_header },
            CodingShredHeader { position: 0u16, ..shred.coding_header },
            shred.chained_merkle_root().ok(),
            shred.retransmitter_signature().ok(),
        )
    };

    let num_data_shreds = usize::from(coding_header.num_data_shreds);
    let num_coding_shreds = usize::from(coding_header.num_coding_shreds);
    let num_shards = num_data_shreds + num_coding_shreds;

    // Track which positions had original shreds vs stubs
    let mut mask = vec![false; num_shards];
    let mut num_missing_data: usize = 0;

    let mut shreds = {
        let make_stub = |i| make_stub_shred(i, &common_header, &coding_header, &chained_merkle_root, &retransmitter_signature);
        let mut batch = Vec::with_capacity(num_shards);
        for shred in shreds {
            if shred.signature() != &common_header.signature {
                return Err(Error::InvalidMerkleRoot);
            }
            let idx = shred.erasure_shard_index()?;
            if !(batch.len()..num_shards).contains(&idx) {
                return Err(Error::from(InvalidIndex));
            }
            while batch.len() < idx {
                if batch.len() < num_data_shreds { num_missing_data += 1; }
                batch.push(make_stub(batch.len())?);
            }
            mask[idx] = true;
            batch.push(shred);
        }
        while batch.len() < num_shards {
            if batch.len() < num_data_shreds { num_missing_data += 1; }
            batch.push(make_stub(batch.len())?);
        }
        batch
    };

    // RS reconstruct — the hot path
    let mut shards = shreds.iter_mut()
        .zip(&mask)
        .map(|(shred, &present)| Ok((shred.erasure_shard_mut()?, present)))
        .collect::<Result<Vec<_>, Error>>()?;
    reed_solomon_cache
        .get(num_data_shreds, num_coding_shreds)?
        .reconstruct(&mut shards)?;
    drop(shards);

    // Extract only recovered data shreds — no merkle, no proofs
    let mut recovered = Vec::with_capacity(num_missing_data);
    for (index, (mut shred, was_present)) in shreds.into_iter().zip(mask).enumerate() {
        if was_present || index >= num_data_shreds { continue; }
        let Shred::ShredData(ref mut data_shred) = shred else { continue };
        if let Ok((hdr, data_hdr)) = wincode::deserialize::<(ShredCommonHeader, DataShredHeader)>(&data_shred.payload[..]) {
            if data_shred.common_header == hdr {
                data_shred.data_header = data_hdr;
                recovered.push(shred);
            }
        }
    }

    Ok(recovered)
}

#[inline]
fn cmp_shred_erasure_shard_index(a: &Shred, b: &Shred) -> Ordering {
    debug_assert_eq!(
        a.common_header().fec_set_index,
        b.common_header().fec_set_index
    );
    match (a, b) {
        (Shred::ShredCode(_), Shred::ShredData(_)) => Ordering::Greater,
        (Shred::ShredData(_), Shred::ShredCode(_)) => Ordering::Less,
        (Shred::ShredCode(a), Shred::ShredCode(b)) => {
            a.common_header.index.cmp(&b.common_header.index)
        }
        (Shred::ShredData(a), Shred::ShredData(b)) => {
            a.common_header.index.cmp(&b.common_header.index)
        }
    }
}

fn make_stub_shred(
    erasure_shard_index: usize,
    common_header: &ShredCommonHeader,
    coding_header: &CodingShredHeader,
    chained_merkle_root: &Option<Hash>,
    retransmitter_signature: &Option<Signature>,
) -> Result<Shred, Error> {
    let num_data_shreds = usize::from(coding_header.num_data_shreds);
    let mut shred = if let Some(position) = erasure_shard_index.checked_sub(num_data_shreds) {
        let position = u16::try_from(position).map_err(|_| Error::from(InvalidIndex))?;
        let common_header = ShredCommonHeader {
            index: common_header.index + u32::from(position),
            ..*common_header
        };
        let coding_header = CodingShredHeader {
            position,
            ..*coding_header
        };
        let mut payload = vec![0u8; ShredCode::SIZE_OF_PAYLOAD];
        wincode::serialize_into(&mut payload[..], &(&common_header, &coding_header))?;
        Shred::ShredCode(ShredCode {
            common_header,
            coding_header,
            payload: Payload::from(payload),
        })
    } else {
        let ShredVariant::MerkleCode { proof_size, .. } = common_header.shred_variant else {
            return Err(Error::InvalidShredVariant);
        };
        let shred_variant = ShredVariant::MerkleData {
            proof_size,
            resigned: retransmitter_signature.is_some(),
        };
        let index = common_header.fec_set_index
            + u32::try_from(erasure_shard_index).map_err(|_| InvalidIndex)?;
        let common_header = ShredCommonHeader {
            shred_variant,
            index,
            ..*common_header
        };
        let data_header = DataShredHeader {
            parent_offset: 0u16,
            flags: ShredFlags::empty(),
            size: 0u16,
        };
        let mut payload = vec![0u8; ShredData::SIZE_OF_PAYLOAD];
        payload[..SIZE_OF_SIGNATURE].copy_from_slice(common_header.signature.as_ref());
        Shred::ShredData(ShredData {
            common_header,
            data_header,
            payload: Payload::from(payload),
        })
    };
    if let Some(chained_merkle_root) = chained_merkle_root {
        shred.set_chained_merkle_root(chained_merkle_root)?;
    }
    if let Some(signature) = retransmitter_signature {
        shred.set_retransmitter_signature(signature)?;
    }
    Ok(shred)
}
