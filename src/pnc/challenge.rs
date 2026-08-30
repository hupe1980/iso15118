//! `GenChallenge` — the nonce that ties a contract signature to *this* session.
//!
//! A Plug & Charge signature that verifies proves that the contract's private
//! key signed those bytes. On its own it does not prove *when*, and a signature
//! that could have been made last week is a signature an eavesdropper can
//! replay. What closes that gap is a nonce the station picks and the vehicle
//! signs back:
//!
//! ```text
//!  ISO 15118-2                          ISO 15118-20
//!  SECC  PaymentDetailsRes              SECC  AuthorizationSetupRes
//!          GenChallenge = <16 random>            GenChallenge = <16 random>
//!  EVCC  AuthorizationReq               EVCC  AuthorizationReq
//!          GenChallenge = <the same>             PnC_AReqAuthorizationMode
//!          ds:Signature over this                  GenChallenge = <the same>
//!                                                ds:Signature over that
//! ```
//!
//! Both halves have to hold, and it is the *second* one implementations forget:
//! the signature is checked, the echoed challenge is not, and the check that
//! was supposed to bind the signature to the session binds it to nothing. So
//! [`iso2::verify_authorization`](super::iso2::verify_authorization) and
//! [`iso20::verify_authorization`](super::iso20::verify_authorization) do both
//! in one call, and there is no way to ask them for only the first.
//!
//! # What it still does not prove
//!
//! That the vehicle is plugged into *this* station. The challenge is the only
//! thing the vehicle signs — no station identity, no timestamp — so a relay
//! between a victim's vehicle and a distant charger passes every check the
//! protocol defines. That is a gap in the standard rather than in an
//! implementation; see the crate's roadmap.

use core::fmt;

use super::PncError;

/// The 16 random bytes a station challenges a contract with.
///
/// Both generations type it as `genChallengeType`, `base64Binary` with
/// `length = 16` — an exact length, not a maximum, so a shorter or longer one
/// is a schema violation rather than a padding question.
///
/// ```
/// # use iso15118::pnc::GenChallenge;
/// // A station's own randomness. This crate has no RNG.
/// let challenge = GenChallenge::new([0x5A; GenChallenge::LEN]);
///
/// // What came back from the vehicle, as bytes off the wire.
/// assert!(challenge.matches(&[0x5A; 16]));
/// assert!(!challenge.matches(&[0x5A; 15]), "a prefix is not a match");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GenChallenge([u8; Self::LEN]);

impl GenChallenge {
    /// Length of a `GenChallenge` in bytes, per `genChallengeType`.
    pub const LEN: usize = 16;

    /// Wraps sixteen caller-supplied random bytes.
    ///
    /// They must be unpredictable: a challenge a peer can guess is a challenge
    /// a peer can have answered in advance, which is the whole of what this
    /// value is for. This crate has no RNG, so the bytes are the caller's.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Reads a challenge off the wire.
    ///
    /// The length is exact. A short one is not zero-extended, because unlike a
    /// `SessionID` there is no sense in which a truncated nonce is the same
    /// nonce.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, PncError> {
        match <[u8; Self::LEN]>::try_from(bytes) {
            Ok(bytes) => Ok(Self(bytes)),
            Err(_) => Err(PncError::BadChallengeLength { len: bytes.len() }),
        }
    }

    /// The bytes, as they travel.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// True when `echoed` is this challenge.
    ///
    /// Compared without an early return, for the same reason a digest is: this
    /// runs on a value a peer chose, and a comparison that stops at the first
    /// wrong byte tells that peer how much of a guess was right. A charging
    /// session offers plenty of retries.
    #[must_use]
    pub fn matches(&self, echoed: &[u8]) -> bool {
        super::digests_equal(&self.0, echoed)
    }
}

/// Hex, because a challenge that ends up in a log is being compared by eye.
impl fmt::Debug for GenChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GenChallenge(")?;
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_is_exactly_sixteen_bytes() {
        assert!(GenChallenge::from_slice(&[0; 16]).is_ok());
        assert_eq!(
            GenChallenge::from_slice(&[0; 15]),
            Err(PncError::BadChallengeLength { len: 15 })
        );
        assert_eq!(
            GenChallenge::from_slice(&[0; 17]),
            Err(PncError::BadChallengeLength { len: 17 })
        );
    }

    #[test]
    fn matching_is_by_value_and_by_length() {
        let c = GenChallenge::new([7; 16]);
        assert!(c.matches(&[7; 16]));
        assert!(!c.matches(&[7; 17]));
        assert!(!c.matches(&[]));
        let mut off_by_one = [7u8; 16];
        off_by_one[15] = 8;
        assert!(!c.matches(&off_by_one));
    }

    #[test]
    fn debug_is_hex_so_two_challenges_can_be_told_apart() {
        extern crate alloc;
        use alloc::format;
        let c = GenChallenge::new([0xAB; 16]);
        assert_eq!(format!("{c:?}"), "GenChallenge(ABABABABABABABABABABABABABABABAB)");
    }
}
