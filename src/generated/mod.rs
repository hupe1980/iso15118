//! Message types generated from the V2G XSD schemas.
//!
//! Nothing here is written by hand. `iso15118-codegen` derives every event-code
//! width, enumeration index and field bound from the schemas, cross-checks the
//! result against the EXI reference implementation, and writes these files;
//! `scripts/verify-grammars.sh` re-runs that comparison.
//!
//! To regenerate:
//!
//! ```sh
//! scripts/fetch-schemas.sh
//! scripts/generate.sh
//! ```

#[cfg(feature = "iso2")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso2")))]
/// ISO 15118-2 message set: one `V2G_Message` root over a body choice of
/// thirty-four messages.
pub mod iso2;

#[cfg(feature = "iso20-common")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso20-common")))]
/// ISO 15118-20 message sets, one module per schema.
pub mod iso20;
