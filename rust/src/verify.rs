// SPDX-License-Identifier: Apache-2.0
use crate::encoding::{
    encode_checkpoint_sign_bytes, hash_validator_set, validate_checkpoint, validate_signatures,
    validate_signed_checkpoint, validate_validator_set,
};
use crate::error::{malformed, Error};
use crate::types::{
    Address, Checkpoint, CheckpointSignature, Misbehaviour, SignedCheckpoint, TrustedState,
    Validator, ValidatorSet,
};
use qorechain_pqc::mldsa::ml_dsa_87;
use std::collections::BTreeMap;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn members(s: &ValidatorSet) -> BTreeMap<Address, &Validator> {
    s.validators.iter().map(|v| (v.address, v)).collect()
}

fn total_power(s: &ValidatorSet) -> u64 {
    s.validators.iter().map(|v| v.power).sum()
}

/// Spec section 8.2: signatures are checked in order; the first unknown signer
/// or invalid signature rejects the checkpoint, then the signed power must
/// exceed two thirds of the set's total power.
fn check_quorum(
    c: &Checkpoint,
    sigs: &[CheckpointSignature],
    set: &ValidatorSet,
) -> Result<(), Error> {
    if hash_validator_set(set)? != c.validator_set_hash {
        return Err(Error::SetMismatch(
            "the checkpoint names a different validator set".into(),
        ));
    }
    let msg = encode_checkpoint_sign_bytes(c)?;
    let m = members(set);
    let mut signed: u64 = 0;
    for s in sigs {
        let v = m.get(&s.validator_address).ok_or_else(|| {
            Error::UnknownValidator(format!(
                "signer {} is not in the set",
                hex(&s.validator_address)
            ))
        })?;
        if !ml_dsa_87::verify(&v.public_key, &msg, &s.signature) {
            return Err(Error::BadSignature(format!(
                "invalid signature from {}",
                hex(&s.validator_address)
            )));
        }
        signed += v.power;
    }
    // Total power is at most 2^60 - 1, so neither product overflows.
    if signed * 3 <= total_power(set) * 2 {
        return Err(Error::InsufficientPower);
    }
    Ok(())
}

fn build_misbehaviour(
    set: &ValidatorSet,
    a: &SignedCheckpoint,
    b: &SignedCheckpoint,
) -> Result<Misbehaviour, Error> {
    let a_bytes = encode_checkpoint_sign_bytes(&a.checkpoint)?;
    let b_bytes = encode_checkpoint_sign_bytes(&b.checkpoint)?;
    let (first, first_bytes, second, second_bytes) = if a_bytes <= b_bytes {
        (a, a_bytes, b, b_bytes)
    } else {
        (b, b_bytes, a, a_bytes)
    };
    let m = members(set);
    let other: BTreeMap<Address, &Vec<u8>> = second
        .signatures
        .iter()
        .map(|s| (s.validator_address, &s.signature))
        .collect();
    let mut double_signers = Vec::new();
    let mut double_signed_power = 0u64;
    for s in &first.signatures {
        if let (Some(v), Some(o)) = (m.get(&s.validator_address), other.get(&s.validator_address)) {
            if ml_dsa_87::verify(&v.public_key, &first_bytes, &s.signature)
                && ml_dsa_87::verify(&v.public_key, &second_bytes, o)
            {
                double_signers.push(v.address);
                double_signed_power += v.power;
            }
        }
    }
    Ok(Misbehaviour {
        chain_id: first.checkpoint.chain_id.clone(),
        epoch: first.checkpoint.epoch,
        first: first.clone(),
        second: second.clone(),
        double_signers,
        double_signed_power,
    })
}

/// Builds a trust root (spec section 7.1). The caller obtains the checkpoint
/// and both sets out of band; signatures, if given, are kept for evidence but
/// not verified here.
pub fn new_trusted_state(
    checkpoint: Checkpoint,
    signatures: Vec<CheckpointSignature>,
    validator_set: ValidatorSet,
    next_validator_set: ValidatorSet,
    trusting_period: u64,
    max_clock_drift: u64,
) -> Result<TrustedState, Error> {
    validate_checkpoint(&checkpoint)?;
    validate_signatures(&signatures)?;
    validate_validator_set(&validator_set)?;
    validate_validator_set(&next_validator_set)?;
    if trusting_period < 1 {
        return Err(malformed("trusting period must be at least one second"));
    }
    if hash_validator_set(&validator_set)? != checkpoint.validator_set_hash {
        return Err(Error::SetMismatch(
            "validator set does not match the checkpoint".into(),
        ));
    }
    if hash_validator_set(&next_validator_set)? != checkpoint.next_validator_set_hash {
        return Err(Error::SetMismatch(
            "next validator set does not match the checkpoint".into(),
        ));
    }
    Ok(TrustedState {
        checkpoint,
        signatures,
        validator_set,
        next_validator_set,
        trusting_period,
        max_clock_drift,
    })
}

/// Verifies `signed` against `trusted` at time `now` (Unix seconds) and returns
/// the new trusted state. The checks run in the order of spec section 8.1.
pub fn verify_checkpoint(
    trusted: &TrustedState,
    signed: &SignedCheckpoint,
    now: u64,
) -> Result<TrustedState, Error> {
    validate_signed_checkpoint(signed)?;
    let c = &signed.checkpoint;
    let t = &trusted.checkpoint;

    if c.chain_id != t.chain_id {
        return Err(Error::ChainIdMismatch(format!(
            "expected {}, got {}",
            t.chain_id, c.chain_id
        )));
    }
    if now >= t.time && now - t.time >= trusted.trusting_period {
        return Err(Error::TrustExpired);
    }
    if c.time > now && c.time - now > trusted.max_clock_drift {
        return Err(Error::FutureCheckpoint);
    }

    if c.epoch == t.epoch {
        if encode_checkpoint_sign_bytes(c)? == encode_checkpoint_sign_bytes(t)? {
            return Err(Error::NotNewer);
        }
        check_quorum(c, &signed.signatures, &trusted.validator_set)?;
        let trusted_signed = SignedCheckpoint {
            checkpoint: t.clone(),
            signatures: trusted.signatures.clone(),
            next_validator_set: (t.validator_set_hash != t.next_validator_set_hash)
                .then(|| trusted.next_validator_set.clone()),
        };
        let evidence = build_misbehaviour(&trusted.validator_set, &trusted_signed, signed)?;
        return Err(Error::ConflictingCheckpoint(Box::new(evidence)));
    }

    if c.epoch < t.epoch || c.height <= t.height || c.time <= t.time {
        return Err(Error::NotNewer);
    }
    if c.validator_set_hash != t.next_validator_set_hash {
        return Err(Error::SetMismatch(
            "the checkpoint is not signed by the set the trusted state names".into(),
        ));
    }
    let next = match &signed.next_validator_set {
        Some(s) => {
            if hash_validator_set(s)? != c.next_validator_set_hash {
                return Err(Error::SetMismatch(
                    "the next validator set does not match its hash".into(),
                ));
            }
            s.clone()
        }
        None => trusted.next_validator_set.clone(),
    };
    check_quorum(c, &signed.signatures, &trusted.next_validator_set)?;
    Ok(TrustedState {
        checkpoint: c.clone(),
        signatures: signed.signatures.clone(),
        validator_set: trusted.next_validator_set.clone(),
        next_validator_set: next,
        trusting_period: trusted.trusting_period,
        max_clock_drift: trusted.max_clock_drift,
    })
}

/// Returns evidence when `a` and `b` are two different checkpoints for the
/// same chain and epoch, each carrying more than two thirds of `set` (spec
/// section 9). Returns `None` otherwise, including for malformed input.
pub fn detect_misbehaviour(
    set: &ValidatorSet,
    a: &SignedCheckpoint,
    b: &SignedCheckpoint,
) -> Option<Misbehaviour> {
    validate_validator_set(set).ok()?;
    validate_signed_checkpoint(a).ok()?;
    validate_signed_checkpoint(b).ok()?;
    if a.checkpoint.chain_id != b.checkpoint.chain_id || a.checkpoint.epoch != b.checkpoint.epoch {
        return None;
    }
    if encode_checkpoint_sign_bytes(&a.checkpoint).ok()?
        == encode_checkpoint_sign_bytes(&b.checkpoint).ok()?
    {
        return None;
    }
    check_quorum(&a.checkpoint, &a.signatures, set).ok()?;
    check_quorum(&b.checkpoint, &b.signatures, set).ok()?;
    build_misbehaviour(set, a, b).ok()
}

/// Signs a checkpoint with an ML-DSA-87 checkpoint secret key (deterministic
/// FIPS 204 signing). For simulators and tests; validators would sign inside
/// the node once the chain supports checkpoints.
pub fn sign_checkpoint(secret_key: &[u8], checkpoint: &Checkpoint) -> Result<Vec<u8>, Error> {
    let msg = encode_checkpoint_sign_bytes(checkpoint)?;
    ml_dsa_87::sign(secret_key, &msg).map_err(|e| Error::Malformed(e.to_string()))
}
