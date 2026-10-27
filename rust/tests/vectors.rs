// SPDX-License-Identifier: Apache-2.0
use qorechain_pq_light_client::*;
use serde_json::Value;
use std::collections::BTreeMap;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn tohex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn u(v: &Value) -> u64 {
    s(v).parse().unwrap()
}

fn check_evidence(name: &str, m: &Misbehaviour, want: &Value) {
    if let Some(id) = want.get("chainId") {
        assert_eq!(m.chain_id, s(id), "{name}");
        assert_eq!(m.epoch, u(&want["epoch"]), "{name}");
    }
    assert_eq!(
        tohex(&encode_checkpoint_sign_bytes(&m.first.checkpoint).unwrap()),
        s(&want["firstSignBytes"]),
        "{name}"
    );
    assert_eq!(
        tohex(&encode_checkpoint_sign_bytes(&m.second.checkpoint).unwrap()),
        s(&want["secondSignBytes"]),
        "{name}"
    );
    let signers: Vec<String> = m.double_signers.iter().map(|a| tohex(a)).collect();
    let want_signers: Vec<String> = want["doubleSigners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| s(x).to_string())
        .collect();
    assert_eq!(signers, want_signers, "{name}");
    assert_eq!(
        m.double_signed_power,
        u(&want["doubleSignedPower"]),
        "{name}"
    );
}

#[test]
fn shared_vectors() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vectors/pq-light-client-v1.json"
    ))
    .expect("vectors/pq-light-client-v1.json");
    let v: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        s(&v["constants"]["checkpointSignDomain"]),
        CHECKPOINT_SIGN_DOMAIN
    );
    assert_eq!(
        s(&v["constants"]["validatorSetHashDomain"]),
        VALIDATOR_SET_HASH_DOMAIN
    );

    let mut sets = BTreeMap::new();
    for (id, e) in v["validatorSets"].as_object().unwrap() {
        let set = decode_validator_set(&unhex(s(&e["encoded"]))).unwrap();
        assert_eq!(
            tohex(&encode_validator_set(&set).unwrap()),
            s(&e["encoded"]),
            "{id}"
        );
        assert_eq!(
            tohex(&hash_validator_set(&set).unwrap()),
            s(&e["hash"]),
            "{id}"
        );
        sets.insert(id.clone(), set);
    }
    let signed = |id: &str| {
        decode_signed_checkpoint(&unhex(s(&v["signedCheckpoints"][id]["encoded"])))
            .unwrap_or_else(|e| panic!("{id}: {e}"))
    };
    for (id, e) in v["signedCheckpoints"].as_object().unwrap() {
        let sc = signed(id);
        assert_eq!(
            tohex(&encode_signed_checkpoint(&sc).unwrap()),
            s(&e["encoded"]),
            "{id}"
        );
        assert_eq!(
            tohex(&encode_checkpoint_sign_bytes(&sc.checkpoint).unwrap()),
            s(&e["signBytes"]),
            "{id}"
        );
    }

    let mut ran = 0;
    for tc in v["cases"].as_array().unwrap() {
        let name = format!("{}: {}", s(&tc["type"]), s(&tc["name"]));
        match s(&tc["type"]) {
            "chain" => {
                let r = &v["trustRoots"][s(&tc["trustRoot"])];
                let root = signed(s(&r["checkpoint"]));
                let mut state = new_trusted_state(
                    root.checkpoint,
                    root.signatures,
                    sets[s(&r["validatorSet"])].clone(),
                    sets[s(&r["nextValidatorSet"])].clone(),
                    u(&r["trustingPeriod"]),
                    u(&r["maxClockDrift"]),
                )
                .unwrap();
                for step in tc["steps"].as_array().unwrap() {
                    let res =
                        verify_checkpoint(&state, &signed(s(&step["checkpoint"])), u(&step["now"]));
                    let exp = &step["expect"];
                    if exp["ok"].as_bool().unwrap() {
                        let next = res.unwrap_or_else(|e| panic!("{name}: {e}"));
                        assert_eq!(next.checkpoint.epoch, u(&exp["epoch"]), "{name}");
                        assert_eq!(next.checkpoint.height, u(&exp["height"]), "{name}");
                        assert_eq!(
                            tohex(&hash_validator_set(&next.validator_set).unwrap()),
                            s(&exp["validatorSetHash"]),
                            "{name}"
                        );
                        assert_eq!(
                            tohex(&hash_validator_set(&next.next_validator_set).unwrap()),
                            s(&exp["nextValidatorSetHash"]),
                            "{name}"
                        );
                        state = next;
                    } else {
                        let err = res.expect_err(&name);
                        assert_eq!(err.code(), s(&exp["error"]), "{name}: {err}");
                        if let Some(m) = exp.get("misbehaviour") {
                            check_evidence(&name, err.misbehaviour().expect(&name), m);
                        }
                    }
                }
            }
            "misbehaviour" => {
                let m = detect_misbehaviour(
                    &sets[s(&tc["validatorSet"])],
                    &signed(s(&tc["a"])),
                    &signed(s(&tc["b"])),
                );
                if tc["expect"]["found"].as_bool().unwrap() {
                    check_evidence(&name, m.as_ref().expect(&name), &tc["expect"]);
                } else {
                    assert!(m.is_none(), "{name}");
                }
            }
            "decode" => {
                let b = unhex(s(&tc["encoded"]));
                let res = match s(&tc["object"]) {
                    "checkpoint" => decode_checkpoint(&b).and_then(|c| encode_checkpoint(&c)),
                    "validatorSet" => {
                        decode_validator_set(&b).and_then(|x| encode_validator_set(&x))
                    }
                    "signedCheckpoint" => {
                        decode_signed_checkpoint(&b).and_then(|x| encode_signed_checkpoint(&x))
                    }
                    o => panic!("unknown object {o}"),
                };
                if tc["expect"]["ok"].as_bool().unwrap() {
                    assert_eq!(res.unwrap(), b, "{name}");
                } else {
                    assert_eq!(res.unwrap_err().code(), "MALFORMED", "{name}");
                }
            }
            t => panic!("unknown case type {t}"),
        }
        ran += 1;
    }
    assert_eq!(ran, v["cases"].as_array().unwrap().len());
}
