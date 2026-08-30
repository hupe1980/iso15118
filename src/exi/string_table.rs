//! EXI value string table (EXI 1.0 §7.3.3).
//!
//! Every string *value* an EXI stream carries is offered to a two-level table
//! first: a partition local to the element or attribute the value belongs to,
//! and a partition global to the whole document. A repeat of a string already
//! in a partition costs a couple of bits instead of its characters, which is
//! why a V2G certificate chain sent twice in one session is nearly free the
//! second time.
//!
//! Getting this wrong is not a size regression, it is a wire incompatibility:
//! the reader and writer must add entries in exactly the same order or every
//! subsequent index desynchronises.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::primitives::bit_width;

/// Identifies the local string table partition a value belongs to.
///
/// One id per `(namespace, local-name)` pair that can carry a string value.
/// Generated code assigns these; hand-written codecs declare them as constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueCtx(pub u32);

/// Tuning knobs from the EXI options document.
///
/// ISO 15118 transmits no options document, so the defaults apply — which is
/// exactly what [`Default`] produces here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExiOptions {
    /// Values longer than this (in characters) are coded literally and never
    /// enter the table. `None` is the EXI default, `unbounded`.
    pub value_max_length: Option<usize>,
    /// Maximum number of entries in the value partitions. `None` is the EXI
    /// default, `unbounded`; `Some(0)` disables the table entirely.
    ///
    /// Other finite capacities require the spec's round-robin eviction, which
    /// this codec does not implement — no ISO 15118 profile asks for one, and a
    /// silently wrong eviction order would corrupt every later index.
    pub value_partition_capacity: Option<usize>,
}

impl ExiOptions {
    /// The options ISO 15118 uses: schema-informed, bit-packed, no options
    /// document, everything at its default.
    pub const ISO15118: Self = Self { value_max_length: None, value_partition_capacity: None };

    /// True when values may be stored in (and matched against) the table.
    #[must_use]
    pub const fn table_enabled(&self) -> bool {
        !matches!(self.value_partition_capacity, Some(0))
    }

    /// True when a value of `char_len` characters is eligible for the table.
    #[must_use]
    pub const fn admits(&self, char_len: usize) -> bool {
        match self.value_max_length {
            Some(max) => char_len <= max,
            None => true,
        }
    }
}

/// Where a string was found when the encoder looked it up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hit {
    /// Present in the local partition for this `ValueCtx`, at this index.
    Local(u64),
    /// Present only in the global partition, at this index.
    Global(u64),
    /// Not in the table.
    Miss,
}

#[derive(Debug, Default)]
struct Partition {
    /// Global ids of this partition's entries, in insertion order.
    ///
    /// A `usize` rather than a narrower id: the value that would have to be
    /// truncated cannot occur — a partition holds at most one entry per value in
    /// the document, and the document is bounded long before four billion — but
    /// "cannot occur" is a claim about a caller's limit, not about this type,
    /// and the two bytes it saves are not worth depending on it.
    entries: Vec<usize>,
    /// Value to local index.
    lookup: BTreeMap<String, u64>,
}

/// The document-scoped value string table.
#[derive(Debug, Default)]
pub struct ValueTable {
    /// Every value seen, in insertion order; the index is the global compact
    /// id.
    globals: Vec<String>,
    global_lookup: BTreeMap<String, u64>,
    locals: BTreeMap<ValueCtx, Partition>,
}

impl ValueTable {
    /// Creates an empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self { globals: Vec::new(), global_lookup: BTreeMap::new(), locals: BTreeMap::new() }
    }

    /// Number of bits an index into the local partition of `ctx` occupies.
    #[must_use]
    pub(crate) fn local_index_width(&self, ctx: ValueCtx) -> u32 {
        bit_width(self.local_len(ctx))
    }

    /// Number of bits an index into the global partition occupies.
    #[must_use]
    pub(crate) fn global_index_width(&self) -> u32 {
        bit_width(self.globals.len() as u64)
    }

    fn local_len(&self, ctx: ValueCtx) -> u64 {
        self.locals.get(&ctx).map_or(0, |p| p.entries.len() as u64)
    }

    /// Looks `value` up for the encoder.
    pub(crate) fn find(&self, ctx: ValueCtx, value: &str) -> Hit {
        if let Some(p) = self.locals.get(&ctx)
            && let Some(&idx) = p.lookup.get(value)
        {
            return Hit::Local(idx);
        }
        if let Some(&idx) = self.global_lookup.get(value) {
            return Hit::Global(idx);
        }
        Hit::Miss
    }

    /// Resolves a local-partition index for the decoder.
    pub(crate) fn local(&self, ctx: ValueCtx, index: u64) -> Option<&str> {
        let p = self.locals.get(&ctx)?;
        let global_id = *p.entries.get(usize::try_from(index).ok()?)?;
        self.globals.get(global_id).map(String::as_str)
    }

    /// Resolves a global-partition index for the decoder.
    pub(crate) fn global(&self, index: u64) -> Option<&str> {
        self.globals.get(usize::try_from(index).ok()?).map(String::as_str)
    }

    /// Adds a newly seen value to both partitions.
    ///
    /// Encoder and decoder must call this at the same points in the stream; a
    /// value that misses the table is always added by both sides.
    pub(crate) fn insert(&mut self, ctx: ValueCtx, value: &str) {
        // A local miss that is a global hit reuses the existing global id
        // rather than storing the value twice.
        let global_id = if let Some(&id) = self.global_lookup.get(value) {
            id
        } else {
            let id = self.globals.len() as u64;
            self.globals.push(String::from(value));
            self.global_lookup.insert(String::from(value), id);
            id
        };
        let Ok(global_id) = usize::try_from(global_id) else { return };
        let p = self.locals.entry(ctx).or_default();
        if !p.lookup.contains_key(value) {
            let local_idx = p.entries.len() as u64;
            p.entries.push(global_id);
            p.lookup.insert(String::from(value), local_idx);
        }
    }

    /// Total number of distinct values recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.globals.len()
    }

    /// True when nothing has been recorded yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.globals.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ValueCtx = ValueCtx(1);
    const B: ValueCtx = ValueCtx(2);

    #[test]
    fn first_sighting_misses() {
        let t = ValueTable::new();
        assert_eq!(t.find(A, "x"), Hit::Miss);
    }

    #[test]
    fn repeat_in_same_context_hits_locally() {
        let mut t = ValueTable::new();
        t.insert(A, "x");
        assert_eq!(t.find(A, "x"), Hit::Local(0));
    }

    #[test]
    fn repeat_in_another_context_hits_globally() {
        let mut t = ValueTable::new();
        t.insert(A, "x");
        assert_eq!(t.find(B, "x"), Hit::Global(0));
    }

    #[test]
    fn a_global_hit_stored_locally_reuses_the_global_id() {
        let mut t = ValueTable::new();
        t.insert(A, "x");
        t.insert(B, "x");
        assert_eq!(t.len(), 1, "the value is global only once");
        assert_eq!(t.find(B, "x"), Hit::Local(0));
        assert_eq!(t.local(B, 0), Some("x"));
    }

    #[test]
    fn index_widths_grow_with_the_partitions() {
        let mut t = ValueTable::new();
        assert_eq!(t.local_index_width(A), 0);
        t.insert(A, "one");
        assert_eq!(t.local_index_width(A), 0, "one entry needs no bits");
        t.insert(A, "two");
        assert_eq!(t.local_index_width(A), 1);
        t.insert(A, "three");
        assert_eq!(t.local_index_width(A), 2);
    }

    #[test]
    fn out_of_range_indices_resolve_to_nothing() {
        let mut t = ValueTable::new();
        t.insert(A, "x");
        assert_eq!(t.local(A, 1), None);
        assert_eq!(t.global(9), None);
    }

    #[test]
    fn iso15118_options_enable_an_unbounded_table() {
        let o = ExiOptions::ISO15118;
        assert!(o.table_enabled());
        assert!(o.admits(usize::MAX));
    }

    #[test]
    fn zero_capacity_disables_the_table() {
        let o = ExiOptions { value_partition_capacity: Some(0), ..ExiOptions::default() };
        assert!(!o.table_enabled());
    }
}
