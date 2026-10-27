// SPDX-License-Identifier: Apache-2.0
use crate::error::{malformed, Error};
use crate::types::{
    Address, Checkpoint, CheckpointSignature, Hash, SignedCheckpoint, Validator, ValidatorSet,
};

/// Prefix of every checkpoint sign-bytes (spec section 4). Proposed for reservation.
pub const CHECKPOINT_SIGN_DOMAIN: &str = "qorechain-pqlc-checkpoint-v1|";
/// Prefix hashed in front of an encoded validator set (spec section 5).
pub const VALIDATOR_SET_HASH_DOMAIN: &str = "qorechain-pqlc-valset-v1|";
/// Version byte of every encoding in this specification.
pub const ENCODING_VERSION: u8 = 1;
/// ML-DSA-87 public key size.
pub const PUBLIC_KEY_SIZE: usize = 2592;
/// ML-DSA-87 signature size.
pub const SIGNATURE_SIZE: usize = 4627;
/// Validator address size.
pub const ADDRESS_SIZE: usize = 20;
/// Hash size.
pub const HASH_SIZE: usize = 32;
/// Longest chain id.
pub const MAX_CHAIN_ID_LENGTH: usize = 64;
/// Largest validator set, and most signatures on a checkpoint.
pub const MAX_VALIDATORS: usize = 256;
/// The consensus engine's bound on total power, (2^63 - 1) / 8.
pub const MAX_TOTAL_POWER: u64 = (1 << 60) - 1;

// ---------------------------------------------------------------------------
// structural validation (spec section 6)

fn validate_chain_id(id: &str) -> Result<(), Error> {
    if id.is_empty() || id.len() > MAX_CHAIN_ID_LENGTH {
        return Err(malformed("chain id must be 1 to 64 characters"));
    }
    if !id.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(malformed("chain id must be printable ASCII without spaces"));
    }
    Ok(())
}

pub(crate) fn validate_checkpoint(c: &Checkpoint) -> Result<(), Error> {
    validate_chain_id(&c.chain_id)
}

pub(crate) fn validate_validator_set(s: &ValidatorSet) -> Result<(), Error> {
    let vs = &s.validators;
    if vs.is_empty() || vs.len() > MAX_VALIDATORS {
        return Err(malformed("a validator set has 1 to 256 validators"));
    }
    let mut total: u64 = 0;
    for (i, v) in vs.iter().enumerate() {
        if v.public_key.len() != PUBLIC_KEY_SIZE {
            return Err(malformed("validator public key must be 2592 bytes"));
        }
        if v.power < 1 {
            return Err(malformed("validator power must be at least 1"));
        }
        if i > 0 && vs[i - 1].address >= v.address {
            return Err(malformed(
                "validators must be sorted by address, without duplicates",
            ));
        }
        if v.power > MAX_TOTAL_POWER - total {
            return Err(malformed("total power exceeds the maximum"));
        }
        total += v.power;
    }
    Ok(())
}

pub(crate) fn validate_signatures(sigs: &[CheckpointSignature]) -> Result<(), Error> {
    if sigs.len() > MAX_VALIDATORS {
        return Err(malformed("at most 256 signatures"));
    }
    for (i, s) in sigs.iter().enumerate() {
        if s.signature.len() != SIGNATURE_SIZE {
            return Err(malformed("signature must be 4627 bytes"));
        }
        if i > 0 && sigs[i - 1].validator_address >= s.validator_address {
            return Err(malformed(
                "signatures must be sorted by address, without duplicates",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_signed_checkpoint(sc: &SignedCheckpoint) -> Result<(), Error> {
    validate_checkpoint(&sc.checkpoint)?;
    validate_signatures(&sc.signatures)?;
    let changes = sc.checkpoint.validator_set_hash != sc.checkpoint.next_validator_set_hash;
    match (&sc.next_validator_set, changes) {
        (None, true) => Err(malformed(
            "the next validator set is required when it changes",
        )),
        (Some(_), false) => Err(malformed(
            "the next validator set must be omitted when it does not change",
        )),
        (Some(s), true) => validate_validator_set(s),
        (None, false) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// encoders

fn put_checkpoint(out: &mut Vec<u8>, c: &Checkpoint) {
    out.push(ENCODING_VERSION);
    out.push(c.chain_id.len() as u8);
    out.extend_from_slice(c.chain_id.as_bytes());
    out.extend_from_slice(&c.epoch.to_be_bytes());
    out.extend_from_slice(&c.height.to_be_bytes());
    out.extend_from_slice(&c.time.to_be_bytes());
    out.extend_from_slice(&c.header_hash);
    out.extend_from_slice(&c.app_hash);
    out.extend_from_slice(&c.validator_set_hash);
    out.extend_from_slice(&c.next_validator_set_hash);
}

fn put_validator_set(out: &mut Vec<u8>, s: &ValidatorSet) {
    out.push(ENCODING_VERSION);
    out.extend_from_slice(&(s.validators.len() as u16).to_be_bytes());
    for v in &s.validators {
        out.extend_from_slice(&v.address);
        out.extend_from_slice(&v.power.to_be_bytes());
        out.extend_from_slice(&v.public_key);
    }
}

/// Canonical checkpoint encoding (spec section 3).
pub fn encode_checkpoint(c: &Checkpoint) -> Result<Vec<u8>, Error> {
    validate_checkpoint(c)?;
    let mut out = Vec::with_capacity(154 + c.chain_id.len());
    put_checkpoint(&mut out, c);
    Ok(out)
}

/// The bytes each validator signs: [`CHECKPOINT_SIGN_DOMAIN`] followed by the
/// checkpoint encoding.
pub fn encode_checkpoint_sign_bytes(c: &Checkpoint) -> Result<Vec<u8>, Error> {
    validate_checkpoint(c)?;
    let mut out = Vec::with_capacity(CHECKPOINT_SIGN_DOMAIN.len() + 154 + c.chain_id.len());
    out.extend_from_slice(CHECKPOINT_SIGN_DOMAIN.as_bytes());
    put_checkpoint(&mut out, c);
    Ok(out)
}

/// Canonical validator set encoding (spec section 5).
pub fn encode_validator_set(s: &ValidatorSet) -> Result<Vec<u8>, Error> {
    validate_validator_set(s)?;
    let mut out = Vec::with_capacity(3 + s.validators.len() * (ADDRESS_SIZE + 8 + PUBLIC_KEY_SIZE));
    put_validator_set(&mut out, s);
    Ok(out)
}

/// SHAKE-256 over [`VALIDATOR_SET_HASH_DOMAIN`] and the set encoding, 32 bytes.
pub fn hash_validator_set(s: &ValidatorSet) -> Result<Hash, Error> {
    let mut data = VALIDATOR_SET_HASH_DOMAIN.as_bytes().to_vec();
    data.extend_from_slice(&encode_validator_set(s)?);
    Ok(qorechain_pqc::shake256(&data))
}

/// Canonical signed checkpoint encoding.
pub fn encode_signed_checkpoint(sc: &SignedCheckpoint) -> Result<Vec<u8>, Error> {
    validate_signed_checkpoint(sc)?;
    let mut out = vec![ENCODING_VERSION];
    put_checkpoint(&mut out, &sc.checkpoint);
    out.extend_from_slice(&(sc.signatures.len() as u16).to_be_bytes());
    for s in &sc.signatures {
        out.extend_from_slice(&s.validator_address);
        out.extend_from_slice(&s.signature);
    }
    match &sc.next_validator_set {
        None => out.push(0),
        Some(s) => {
            out.push(1);
            put_validator_set(&mut out, s);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// decoders (strict: any deviation from the canonical encoding is MALFORMED)

struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], Error> {
        if self.buf.len() - self.off < n {
            return Err(Error::Malformed(format!("truncated {what}")));
        }
        let b = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(b)
    }

    fn u8(&mut self, what: &str) -> Result<u8, Error> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &str) -> Result<usize, Error> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
    }

    fn u64(&mut self, what: &str) -> Result<u64, Error> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8, what)?);
        Ok(u64::from_be_bytes(a))
    }

    fn hash(&mut self, what: &str) -> Result<Hash, Error> {
        let mut a = [0u8; HASH_SIZE];
        a.copy_from_slice(self.take(HASH_SIZE, what)?);
        Ok(a)
    }

    fn address(&mut self, what: &str) -> Result<Address, Error> {
        let mut a = [0u8; ADDRESS_SIZE];
        a.copy_from_slice(self.take(ADDRESS_SIZE, what)?);
        Ok(a)
    }

    fn version(&mut self, what: &str) -> Result<(), Error> {
        if self.u8(what)? != ENCODING_VERSION {
            return Err(Error::Malformed(format!("unknown {what}")));
        }
        Ok(())
    }

    fn end(&self) -> Result<(), Error> {
        if self.off != self.buf.len() {
            return Err(malformed("trailing bytes"));
        }
        Ok(())
    }

    fn checkpoint(&mut self) -> Result<Checkpoint, Error> {
        self.version("checkpoint version")?;
        let n = self.u8("chain id length")? as usize;
        if !(1..=MAX_CHAIN_ID_LENGTH).contains(&n) {
            return Err(malformed("chain id must be 1 to 64 characters"));
        }
        let id = self.take(n, "chain id")?;
        if !id.iter().all(|b| (0x21..=0x7e).contains(b)) {
            return Err(malformed("chain id must be printable ASCII without spaces"));
        }
        // Printable ASCII is valid UTF-8.
        let chain_id = String::from_utf8(id.to_vec()).map_err(|_| malformed("chain id"))?;
        Ok(Checkpoint {
            chain_id,
            epoch: self.u64("epoch")?,
            height: self.u64("height")?,
            time: self.u64("time")?,
            header_hash: self.hash("header hash")?,
            app_hash: self.hash("app hash")?,
            validator_set_hash: self.hash("validator set hash")?,
            next_validator_set_hash: self.hash("next validator set hash")?,
        })
    }

    fn validator_set(&mut self) -> Result<ValidatorSet, Error> {
        self.version("validator set version")?;
        let count = self.u16("validator count")?;
        if !(1..=MAX_VALIDATORS).contains(&count) {
            return Err(malformed("a validator set has 1 to 256 validators"));
        }
        let mut validators = Vec::with_capacity(count);
        for _ in 0..count {
            validators.push(Validator {
                address: self.address("validator address")?,
                power: self.u64("validator power")?,
                public_key: self.take(PUBLIC_KEY_SIZE, "validator public key")?.to_vec(),
            });
        }
        let s = ValidatorSet { validators };
        validate_validator_set(&s)?;
        Ok(s)
    }
}

/// Parses a canonical checkpoint encoding.
pub fn decode_checkpoint(bytes: &[u8]) -> Result<Checkpoint, Error> {
    let mut r = Reader { buf: bytes, off: 0 };
    let c = r.checkpoint()?;
    r.end()?;
    Ok(c)
}

/// Parses a canonical validator set encoding.
pub fn decode_validator_set(bytes: &[u8]) -> Result<ValidatorSet, Error> {
    let mut r = Reader { buf: bytes, off: 0 };
    let s = r.validator_set()?;
    r.end()?;
    Ok(s)
}

/// Parses a canonical signed checkpoint encoding.
pub fn decode_signed_checkpoint(bytes: &[u8]) -> Result<SignedCheckpoint, Error> {
    let mut r = Reader { buf: bytes, off: 0 };
    r.version("signed checkpoint version")?;
    let checkpoint = r.checkpoint()?;
    let count = r.u16("signature count")?;
    if count > MAX_VALIDATORS {
        return Err(malformed("at most 256 signatures"));
    }
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        signatures.push(CheckpointSignature {
            validator_address: r.address("signer address")?,
            signature: r.take(SIGNATURE_SIZE, "signature")?.to_vec(),
        });
    }
    let next_validator_set = match r.u8("next validator set flag")? {
        0 => None,
        1 => Some(r.validator_set()?),
        _ => return Err(malformed("next validator set flag must be 0 or 1")),
    };
    r.end()?;
    let sc = SignedCheckpoint {
        checkpoint,
        signatures,
        next_validator_set,
    };
    validate_signed_checkpoint(&sc)?;
    Ok(sc)
}
