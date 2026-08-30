//! Structured protocol tracing, behind the `tracing` feature.
//!
//! A charging session that fails in the field fails once, in a car park, and
//! the only thing anyone has afterwards is the log. These macros put the facts
//! that matter into it — which message, in which phase, under which protocol,
//! and which timer ran out — and compile to nothing when the feature is off, so
//! an ECU pays no size for them.
//!
//! Deliberately no payload values: a `SessionID` identifies a charging session
//! and a contract certificate identifies a person, and neither belongs in a log
//! by default.

// A build with no role driver has no call sites for these, and that is fine:
// they are a facility, not a requirement.
#![allow(unused_macros, unused_imports)]

/// A protocol event worth a line in the log.
///
/// With `tracing` off this expands to nothing, so any binding that exists only
/// to be traced becomes unused and the build warns — and CI treats warnings as
/// errors. The macro cannot consume them itself, because its arguments are
/// `tracing`'s own field syntax rather than expressions. A call site whose
/// bindings have no other reader therefore carries
/// `#[allow(unused_variables, reason = "...")]`; see `slac::matching::decoded`.
macro_rules! trace_event {
    ($($arg:tt)*) => {
        #[cfg(feature = "tracing")]
        {
            ::tracing::debug!(target: "iso15118", $($arg)*);
        }
    };
}

/// Something that ended a session.
macro_rules! trace_close {
    ($($arg:tt)*) => {
        #[cfg(feature = "tracing")]
        {
            ::tracing::info!(target: "iso15118", $($arg)*);
        }
    };
}

pub(crate) use {trace_close, trace_event};
