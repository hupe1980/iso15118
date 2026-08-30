//! The crate-level error type.

use core::fmt;

use crate::exi::ExiError;
use crate::v2gtp::V2gtpError;

/// Result alias used across the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Anything that can go wrong below the state machines.
///
/// Session-level failures — a peer that answers out of sequence, a timer that
/// expires, a response code that says no — are *not* errors here. They are
/// modelled by the protocol modules, because the spec prescribes what to send
/// next and that decision belongs in the state machine, not in a `?`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// EXI encoding or decoding failed.
    Exi(ExiError),
    /// V2GTP framing failed.
    V2gtp(V2gtpError),
    /// SECC discovery failed.
    #[cfg(feature = "sdp")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sdp")))]
    Sdp(crate::sdp::SdpError),
    /// A field held a value the schema forbids.
    ///
    /// Carries the field name so a log line says *which* one.
    InvalidValue(&'static str),
    /// A message carried more repetitions of an element than the schema allows.
    TooManyItems {
        /// The repeated element.
        field: &'static str,
        /// Number present.
        count: usize,
        /// Maximum the schema permits.
        max: usize,
    },
    /// A message carried fewer repetitions than the schema requires.
    TooFewItems {
        /// The repeated element.
        field: &'static str,
        /// Number present.
        count: usize,
        /// Minimum the schema requires.
        min: usize,
    },
}

impl From<ExiError> for Error {
    fn from(e: ExiError) -> Self {
        Self::Exi(e)
    }
}

impl From<V2gtpError> for Error {
    fn from(e: V2gtpError) -> Self {
        Self::V2gtp(e)
    }
}

#[cfg(feature = "sdp")]
impl From<crate::sdp::SdpError> for Error {
    fn from(e: crate::sdp::SdpError) -> Self {
        Self::Sdp(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exi(e) => write!(f, "EXI: {e}"),
            Self::V2gtp(e) => write!(f, "V2GTP: {e}"),
            #[cfg(feature = "sdp")]
            Self::Sdp(e) => write!(f, "SDP: {e}"),
            Self::InvalidValue(field) => write!(f, "invalid value for {field}"),
            Self::TooManyItems { field, count, max } => {
                write!(f, "{field} has {count} entries, the schema allows at most {max}")
            }
            Self::TooFewItems { field, count, min } => {
                write!(f, "{field} has {count} entries, the schema requires at least {min}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Exi(e) => Some(e),
            Self::V2gtp(e) => Some(e),
            #[cfg(feature = "sdp")]
            Self::Sdp(e) => Some(e),
            _ => None,
        }
    }
}
