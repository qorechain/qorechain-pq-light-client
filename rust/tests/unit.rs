// SPDX-License-Identifier: Apache-2.0
use qorechain_pq_light_client::*;
use qorechain_pqc::mldsa::ml_dsa_87;

struct Key {
    secret: Vec<u8>,
    address: Address,
}

fn fixture() -> (Vec<Key>, ValidatorSet) {
    let mut keys = Vec::new();
    let mut validators = Vec::new();
    for i in 0..3u8 {
        let (public_key, secret) =
            ml_dsa_87::keygen_from_seed(&qorechain_pqc::shake256(&[b'u', i]));
        let address = qorechain_pqc::pubkey_hash20(&[b'a', i]);
        validators.push(Validator {
            address,
            power: 10,
            public_key,
        });
        keys.push(Key { secret, address });
    }
    validators.sort_by_key(|v| v.address);
    keys.sort_by_key(|k| k.address);
    (keys, ValidatorSet { validators })
}

fn checkpoint(set: &ValidatorSet, epoch: u64) -> Checkpoint {
    let h = hash_validator_set(set).unwrap();
    Checkpoint {
        chain_id: "unit-chain".into(),
        epoch,
        height: 100 * (epoch + 1),
        time: 1000 + 60 * epoch,
        header_hash: [1; 32],
        app_hash: [epoch as u8; 32],
        validator_set_hash: h,
        next_validator_set_hash: h,
    }
}

fn sign_all(keys: &[Key], c: &Checkpoint) -> SignedCheckpoint {
    SignedCheckpoint {
        checkpoint: c.clone(),
        signatures: keys
            .iter()
            .map(|k| CheckpointSignature {
                validator_address: k.address,
                signature: sign_checkpoint(&k.secret, c).unwrap(),
            })
            .collect(),
        next_validator_set: None,
    }
}

#[test]
fn sign_bytes_layout() {
    let (_, set) = fixture();
    let c = checkpoint(&set, 1);
    let sb = encode_checkpoint_sign_bytes(&c).unwrap();
    let enc = encode_checkpoint(&c).unwrap();
    assert!(sb.starts_with(CHECKPOINT_SIGN_DOMAIN.as_bytes()));
    assert_eq!(&sb[CHECKPOINT_SIGN_DOMAIN.len()..], &enc[..]);
    assert_eq!(enc.len(), 154 + c.chain_id.len());
}

#[test]
fn quorum_and_typed_errors() {
    let (keys, set) = fixture();
    let root = new_trusted_state(
        checkpoint(&set, 0),
        vec![],
        set.clone(),
        set.clone(),
        3600,
        5,
    )
    .unwrap();
    let c1 = checkpoint(&set, 1);
    let err = verify_checkpoint(&root, &sign_all(&keys[..2], &c1), 1061).unwrap_err();
    assert_eq!(err, Error::InsufficientPower);
    let next = verify_checkpoint(&root, &sign_all(&keys, &c1), 1061).unwrap();
    assert_eq!(next.checkpoint.epoch, 1);

    let mut bad = sign_all(&keys, &c1);
    bad.signatures[0].signature.push(0);
    assert_eq!(
        encode_signed_checkpoint(&bad).unwrap_err().code(),
        "MALFORMED"
    );
}

/// Controlled failure for every live-chain function: QoreChain does not
/// produce checkpoints, so they fail with REQUIRES_CHAIN_SUPPORT and make no
/// request.
#[test]
fn requires_chain_support_not_scheduled() {
    let err = fetch_checkpoint("https://rpc.example.invalid", "unit-chain", 1).unwrap_err();
    assert_eq!(err, Error::RequiresChainSupport);
    assert_eq!(
        err.to_string(),
        "REQUIRES_CHAIN_SUPPORT: requires chain support (not scheduled)"
    );
    let src = ChainCheckpointSource {
        endpoint: "https://rpc.example.invalid".into(),
    };
    assert_eq!(
        src.fetch_checkpoint("unit-chain", 1).unwrap_err().code(),
        "REQUIRES_CHAIN_SUPPORT"
    );
}
