// Helper methods to extract pieces of the shred from the payload without
// deserializing the entire payload.
#![deny(clippy::indexing_slicing)]
#![allow(dead_code)]
use {
    super::{
        blockstore_meta::ErasureConfig,
        Error, SIZE_OF_COMMON_SHRED_HEADER, ShredFlags, ShredId, ShredType,
        ShredVariant, merkle_tree::SIZE_OF_MERKLE_ROOT, traits::Shred,
        Slot,
    },
    solana_hash::Hash,
    solana_signature::{SIGNATURE_BYTES, Signature},
};

#[inline]
fn get_shred_size(shred: &[u8]) -> Option<usize> {
    match get_shred_variant(shred).ok()? {
        ShredVariant::MerkleCode { .. } => Some(super::merkle::ShredCode::SIZE_OF_PAYLOAD),
        ShredVariant::MerkleData { .. } => Some(super::merkle::ShredData::SIZE_OF_PAYLOAD),
    }
}

/// Get a shred slice from a raw buffer (no packet abstraction needed).
#[inline]
pub fn get_shred_from_buf(buf: &[u8]) -> Option<&[u8]> {
    buf.get(..get_shred_size(buf)?)
}

#[inline]
pub fn get_shred_mut(buffer: &mut [u8]) -> Option<&mut [u8]> {
    buffer.get_mut(..get_shred_size(buffer)?)
}

#[inline]
pub fn get_common_header_bytes(shred: &[u8]) -> Option<&[u8]> {
    shred.get(..SIZE_OF_COMMON_SHRED_HEADER)
}

#[inline]
pub(crate) fn get_signature(shred: &[u8]) -> Option<Signature> {
    let bytes = <[u8; 64]>::try_from(shred.get(..64)?).unwrap();
    Some(Signature::from(bytes))
}

#[inline]
pub(super) fn get_shred_variant(shred: &[u8]) -> Result<ShredVariant, Error> {
    let Some(&shred_variant) = shred.get(64) else {
        return Err(Error::InvalidPayloadSize(shred.len()));
    };
    ShredVariant::try_from(shred_variant).map_err(|_| Error::InvalidShredVariant)
}

#[inline]
pub fn get_shred_type(shred: &[u8]) -> Result<ShredType, Error> {
    get_shred_variant(shred).map(ShredType::from)
}

#[inline]
pub fn get_slot(shred: &[u8]) -> Option<Slot> {
    let bytes = <[u8; 8]>::try_from(shred.get(65..65 + 8)?).unwrap();
    Some(Slot::from_le_bytes(bytes))
}

#[inline]
pub fn get_index(shred: &[u8]) -> Option<u32> {
    let bytes = <[u8; 4]>::try_from(shred.get(73..73 + 4)?).unwrap();
    Some(u32::from_le_bytes(bytes))
}

#[inline]
pub(super) fn get_version(shred: &[u8]) -> Option<u16> {
    let bytes = <[u8; 2]>::try_from(shred.get(77..77 + 2)?).unwrap();
    Some(u16::from_le_bytes(bytes))
}

#[inline]
pub fn get_fec_set_index(shred: &[u8]) -> Option<u32> {
    let bytes = <[u8; 4]>::try_from(shred.get(79..79 + 4)?).unwrap();
    Some(u32::from_le_bytes(bytes))
}

// The caller should verify first that the shred is data and not code!
#[inline]
pub(super) fn get_parent_offset(shred: &[u8]) -> Option<u16> {
    debug_assert_eq!(get_shred_type(shred).unwrap(), ShredType::Data);
    let bytes = <[u8; 2]>::try_from(shred.get(83..83 + 2)?).unwrap();
    Some(u16::from_le_bytes(bytes))
}

// Returns DataShredHeader.flags if the shred is data.
// Returns Error::InvalidShredType for coding shreds.
#[inline]
pub fn get_flags(shred: &[u8]) -> Result<ShredFlags, Error> {
    match get_shred_type(shred)? {
        ShredType::Code => Err(Error::InvalidShredType),
        ShredType::Data => {
            let Some(flags) = shred.get(85).copied() else {
                return Err(Error::InvalidPayloadSize(shred.len()));
            };
            ShredFlags::from_bits(flags).ok_or(Error::InvalidShredFlags(flags))
        }
    }
}

// Returns DataShredHeader.size for data shreds.
#[inline]
fn get_data_size(shred: &[u8]) -> Result<u16, Error> {
    debug_assert_eq!(get_shred_type(shred).unwrap(), ShredType::Data);
    let Some(bytes) = shred.get(86..86 + 2) else {
        return Err(Error::InvalidPayloadSize(shred.len()));
    };
    let bytes = <[u8; 2]>::try_from(bytes).unwrap();
    Ok(u16::from_le_bytes(bytes))
}

#[inline]
pub(crate) fn get_data(shred: &[u8]) -> Result<&[u8], Error> {
    match get_shred_variant(shred)? {
        ShredVariant::MerkleCode { .. } => Err(Error::InvalidShredType),
        ShredVariant::MerkleData {
            proof_size,
            resigned,
        } => super::merkle::ShredData::get_data(shred, proof_size, resigned, get_data_size(shred)?),
    }
}

/// Returns the ErasureConfig specified by the coding shred, or an Error if
/// the shred is a data shred
#[inline]
pub(crate) fn get_erasure_config(shred: &[u8]) -> Result<ErasureConfig, Error> {
    if !matches!(get_shred_type(shred).unwrap(), ShredType::Code) {
        return Err(Error::InvalidShredType);
    }
    let Some(num_data_bytes) = shred.get(83..83 + 2) else {
        return Err(Error::InvalidPayloadSize(shred.len()));
    };
    let Some(num_coding_bytes) = shred.get(85..85 + 2) else {
        return Err(Error::InvalidPayloadSize(shred.len()));
    };
    let num_data = <[u8; 2]>::try_from(num_data_bytes)
        .map(u16::from_le_bytes)
        .map(usize::from)
        .map_err(|_| Error::InvalidErasureConfig)?;
    let num_coding = <[u8; 2]>::try_from(num_coding_bytes)
        .map(u16::from_le_bytes)
        .map(usize::from)
        .map_err(|_| Error::InvalidErasureConfig)?;

    Ok(ErasureConfig {
        num_data,
        num_coding,
    })
}

#[inline]
pub fn get_shred_id(shred: &[u8]) -> Option<ShredId> {
    Some(ShredId(
        get_slot(shred)?,
        get_index(shred)?,
        get_shred_type(shred).ok()?,
    ))
}

pub fn get_reference_tick(shred: &[u8]) -> Result<u8, Error> {
    if get_shred_type(shred)? != ShredType::Data {
        return Err(Error::InvalidShredType);
    }
    let Some(flags) = shred.get(85) else {
        return Err(Error::InvalidPayloadSize(shred.len()));
    };
    Ok(flags & ShredFlags::SHRED_TICK_REFERENCE_MASK.bits())
}

pub fn get_merkle_root(shred: &[u8]) -> Option<Hash> {
    match get_shred_variant(shred).ok()? {
        ShredVariant::MerkleCode {
            proof_size,
            resigned,
        } => super::merkle::ShredCode::get_merkle_root(shred, proof_size, resigned),
        ShredVariant::MerkleData {
            proof_size,
            resigned,
        } => super::merkle::ShredData::get_merkle_root(shred, proof_size, resigned),
    }
}

pub(crate) fn get_chained_merkle_root(shred: &[u8]) -> Option<Hash> {
    let offset = match get_shred_variant(shred).ok()? {
        ShredVariant::MerkleCode {
            proof_size,
            resigned,
        } => super::merkle::ShredCode::get_chained_merkle_root_offset(proof_size, resigned),
        ShredVariant::MerkleData {
            proof_size,
            resigned,
        } => super::merkle::ShredData::get_chained_merkle_root_offset(proof_size, resigned),
    }
    .ok()?;
    let merkle_root = shred.get(offset..offset + SIZE_OF_MERKLE_ROOT)?;
    Some(Hash::from(
        <[u8; SIZE_OF_MERKLE_ROOT]>::try_from(merkle_root).unwrap(),
    ))
}

fn get_retransmitter_signature_offset(shred: &[u8]) -> Result<usize, Error> {
    match get_shred_variant(shred)? {
        ShredVariant::MerkleCode {
            proof_size,
            resigned,
        } => super::merkle::ShredCode::get_retransmitter_signature_offset(proof_size, resigned),
        ShredVariant::MerkleData {
            proof_size,
            resigned,
        } => super::merkle::ShredData::get_retransmitter_signature_offset(proof_size, resigned),
    }
}

pub fn get_retransmitter_signature(shred: &[u8]) -> Result<Signature, Error> {
    let offset = get_retransmitter_signature_offset(shred)?;
    let Some(bytes) = shred.get(offset..offset + 64) else {
        return Err(Error::InvalidPayloadSize(shred.len()));
    };
    Ok(Signature::from(<[u8; 64]>::try_from(bytes).unwrap()))
}

pub fn is_retransmitter_signed_variant(shred: &[u8]) -> Result<bool, Error> {
    match get_shred_variant(shred)? {
        ShredVariant::MerkleCode {
            proof_size: _,
            resigned,
        } => Ok(resigned),
        ShredVariant::MerkleData {
            proof_size: _,
            resigned,
        } => Ok(resigned),
    }
}

pub fn set_retransmitter_signature(shred: &mut [u8], signature: &Signature) -> Result<(), Error> {
    let offset = get_retransmitter_signature_offset(shred)?;
    let Some(buffer) = shred.get_mut(offset..offset + SIGNATURE_BYTES) else {
        return Err(Error::InvalidPayloadSize(shred.len()));
    };
    buffer.copy_from_slice(signature.as_ref());
    Ok(())
}
