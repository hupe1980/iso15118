//! Schema-informed EXI codec — the layer every V2G message rides on.
//!
//! # Which EXI, exactly
//!
//! "EXI" is a large specification with many switches, and ISO 15118 pins all of
//! them out of band. Getting a single one wrong produces a stream that looks
//! plausible and decodes to nonsense, so the exact profile is worth stating:
//!
//! | Option | Value |
//! |---|---|
//! | Grammars | schema-informed, from the V2G XSDs |
//! | Alignment | `bit-packed` |
//! | Compression | off |
//! | Fidelity | **default — `strict` is _false_** |
//! | Options document | absent (header is the single byte `0x80`) |
//! | `preserve.*`, `selfContained` | all off |
//! | `valueMaxLength`, `valuePartitionCapacity` | unbounded |
//!
//! The `strict = false` row is the one implementations get wrong. Non-strict
//! grammars carry extra productions for content the schema does not declare;
//! those productions live at the *second* event-code level, so they cost no
//! bits of their own — but their mere existence widens first-level event codes.
//! A grammar state with one declared production needs **one** bit under
//! non-strict rules and **zero** under strict ones. Every element in every
//! message is affected.
//!
//! This crate's reading of the profile is pinned by golden vectors captured
//! from independent implementations; see `tests/golden`.
//!
//! # Layout
//!
//! * [`BitWriter`] / [`BitReader`] — bit-level I/O over caller-owned slices.
//! * [`primitives`] — the built-in datatype representations (§7.1).
//! * [`string_table`] — the value string table (§7.3.3).
//! * [`Encoder`] / [`Decoder`] — the two types message codecs are written
//!   against, pairing a bit stream with document-scoped state.
//!
//! # Not zero-copy, deliberately
//!
//! In bit-packed EXI a string is a run of Unsigned-Integer code points and a
//! `hexBinary` is a run of bit-shifted bytes; neither is contiguous in the
//! input unless it happens to land byte-aligned. Borrowing from the input
//! buffer is therefore not possible, and decoded values are owned. What the
//! decoder does guarantee is that every length is bounded by its schema facet
//! *before* anything is allocated.

mod bitstream;
mod codec;
mod error;
mod header;
pub mod primitives;
pub mod seq;
pub mod string_table;

pub use bitstream::{BitReader, BitWriter};
pub use codec::{Decoder, Encoder, ExiDocument, Lengths, MAX_DEPTH, encode_growing};
pub use error::{ExiError, ExiResult};
pub use header::{Header, read_header, write_header};
pub use primitives::{DateTime, Decimal, Float, Fraction, bit_width};
pub use seq::{SeqReader, SeqWriter, Shape, Step};
pub use string_table::{ExiOptions, ValueCtx, ValueTable};
