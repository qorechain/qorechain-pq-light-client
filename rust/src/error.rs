// SPDX-License-Identifier: Apache-2.0
use crate::types::Misbehaviour;
use std::fmt;

/// The message carried by every function that needs the chain to produce checkpoints.
pub const REQUIRES_CHAIN_SUPPORT_MESSAGE: &str = "requires chain support (not scheduled)";

/// Errors with stable codes, identical in the Go, Rust and TypeScript verifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input is not a canonical encoding or breaks a structural rule.
    Malformed(String),
    /// The checkpoint is for another chain.
    ChainIdMismatch(String),
    /// The trusted checkpoint is older than the trusting period.
    TrustExpired,
    /// The checkpoint time is ahead of the local clock by more than the allowed drift.
    FutureCheckpoint,
    /// Epoch, height or time does not increase, or the checkpoint is already trusted.
    NotNewer,
    /// A validator set does not match the hash it must match.
    SetMismatch(String),
    /// A signer is not a member of the set.
    UnknownValidator(String),
    /// A signature does not verify.
    BadSignature(String),
    /// The signed power does not exceed two thirds of the set.
    InsufficientPower,
    /// Two checkpoints for one epoch both carry more than two thirds of the power.
    ConflictingCheckpoint(Box<Misbehaviour>),
    /// The function needs the chain to produce checkpoints, which is not scheduled.
    RequiresChainSupport,
}

impl Error {
    /// The stable code: MALFORMED, CHAIN_ID_MISMATCH, TRUST_EXPIRED, ...
    pub fn code(&self) -> &'static str {
        match self {
            Error::Malformed(_) => "MALFORMED",
            Error::ChainIdMismatch(_) => "CHAIN_ID_MISMATCH",
            Error::TrustExpired => "TRUST_EXPIRED",
            Error::FutureCheckpoint => "FUTURE_CHECKPOINT",
            Error::NotNewer => "NOT_NEWER",
            Error::SetMismatch(_) => "SET_MISMATCH",
            Error::UnknownValidator(_) => "UNKNOWN_VALIDATOR",
            Error::BadSignature(_) => "BAD_SIGNATURE",
            Error::InsufficientPower => "INSUFFICIENT_POWER",
            Error::ConflictingCheckpoint(_) => "CONFLICTING_CHECKPOINT",
            Error::RequiresChainSupport => "REQUIRES_CHAIN_SUPPORT",
        }
    }

    /// The evidence, when this is `ConflictingCheckpoint`.
    pub fn misbehaviour(&self) -> Option<&Misbehaviour> {
        match self {
            Error::ConflictingCheckpoint(m) => Some(m),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = match self {
            Error::Malformed(d)
            | Error::ChainIdMismatch(d)
            | Error::SetMismatch(d)
            | Error::UnknownValidator(d)
            | Error::BadSignature(d) => d.as_str(),
            Error::TrustExpired => "the trusted checkpoint is older than the trusting period",
            Error::FutureCheckpoint => {
                "checkpoint time is ahead of the local clock by more than the allowed drift"
            }
            Error::NotNewer => "epoch, height and time must all increase",
            Error::InsufficientPower => "signed power does not exceed two thirds of the set",
            Error::ConflictingCheckpoint(_) => {
                "two checkpoints for one epoch carry more than two thirds of the power"
            }
            Error::RequiresChainSupport => REQUIRES_CHAIN_SUPPORT_MESSAGE,
        };
        write!(f, "{}: {}", self.code(), detail)
    }
}

impl std::error::Error for Error {}

pub(crate) fn malformed(d: &str) -> Error {
    Error::Malformed(d.to_string())
}
