//! Event-code arithmetic for a content model, shared by all generated codecs.
//!
//! A schema-informed EXI grammar is a state machine, but for the content models
//! ISO 15118 uses it is a very regular one, and the whole of it fits in a few
//! integer arrays per type. Generated code carries a [`Shape`] of those arrays
//! and drives [`SeqWriter`] / [`SeqReader`], instead of embedding a state table.
//!
//! That matters for size: the equivalent unrolled state machine for a
//! `maxOccurs="2048"` particle is 2049 states, and ISO 15118-20 has several.
//! Here such a particle costs one extra `u32`.
//!
//! # The model
//!
//! A content model is a list of *items* — an attribute, a child element, a
//! choice of child elements, or the character data of a simple-content type.
//! At position `i`:
//!
//! * the items that may come next are `i` onward up to and including the first
//!   required one, and their event codes are `0, 1, 2, …` in that order;
//! * `EE` is possible exactly when every item from `i` on is optional, and its
//!   code is then the total production count minus what is behind us;
//! * after an occurrence of a repeatable item, that item is offered again at
//!   code 0 and everything else shifts up by one — the `base` below.

use super::{Decoder, Encoder, ExiError, ExiResult};

/// Event-code width while a repetition is still below its `minOccurs`.
///
/// Nothing but another occurrence is permitted, so there is one declared
/// production plus the non-strict second level — *provided* the repeating item
/// is a single element rather than a choice. A choice with `minOccurs >= 2`
/// would offer one production per branch and need a wider code; no V2G schema
/// has one, and [`Shape::assert_below_min_is_narrow`] is what says so out loud
/// rather than leaving it as a coincidence the arithmetic silently depends on.
pub const BELOW_MIN_WIDTH: u32 = 1;

/// Event-code width of a simple-typed child element's `CH`, and of the `EE`
/// that follows it. One production either way.
pub const SIMPLE_WIDTH: u32 = 1;

/// The static event-code arithmetic of one content model.
///
/// Generated code builds these; hand-written code can too. All slices are
/// indexed by item position, and the first three have one more entry than there
/// are items, for the position past the end.
#[derive(Debug, Clone, Copy)]
pub struct Shape {
    /// `prod_before[i]` — event codes occupied by items `0..i`. The last entry
    /// is the total, which is also `EE`'s code wherever `EE` is allowed.
    pub prod_before: &'static [u64],
    /// `width[i]` — event-code width at position `i`.
    pub width: &'static [u32],
    /// `repeat_width[j]` — width after an occurrence of item `j` once its
    /// minimum is met and more are permitted. Zero when item `j` cannot repeat.
    pub repeat_width: &'static [u32],
    /// `min[j]` — minimum occurrences of item `j`.
    pub min: &'static [u32],
    /// `max[j]` — maximum occurrences of item `j`.
    pub max: &'static [u32],
}

impl Shape {
    /// Number of items.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.min.len()
    }

    /// True when the content model is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.min.is_empty()
    }

    /// Total number of event codes the items occupy.
    fn total(&self) -> u64 {
        self.prod_before[self.prod_before.len() - 1]
    }

    /// How many event codes item `j` occupies — more than one for a choice.
    const fn branches(&self, j: usize) -> u64 {
        self.prod_before[j + 1] - self.prod_before[j]
    }

    /// Checks the assumption [`BELOW_MIN_WIDTH`] rests on.
    ///
    /// An item with `minOccurs >= 2` spends part of its life in a state where
    /// another occurrence is the only legal event. That state is one bit wide
    /// only if "another occurrence" is one production — true for an element,
    /// false for a choice, which offers one per branch.
    ///
    /// No V2G schema has a repeated choice with a minimum above one, so this
    /// holds everywhere today. It is asserted rather than assumed because the
    /// failure mode if a future schema breaks it is not a compile error or a
    /// panic: it is a stream that encodes at the wrong width and decodes to
    /// something else.
    ///
    /// The generator refuses to emit such a shape, so this is the second of two
    /// checks rather than the only one; it exists because a `Shape` can also be
    /// written by hand.
    ///
    /// # Panics
    ///
    /// If a shape violates it. Debug builds only.
    pub fn assert_below_min_is_narrow(&self) {
        for j in 0..self.len() {
            assert!(
                self.min[j] < 2 || self.branches(j) == 1,
                "item {j} has minOccurs={} over {} branches; BELOW_MIN_WIDTH is one bit",
                self.min[j],
                self.branches(j),
            );
        }
    }
}

/// Tracks position while writing a content model.
#[derive(Debug)]
pub struct SeqWriter {
    shape: Shape,
    /// Index of the next item not yet passed.
    pos: usize,
    /// Codes occupied ahead of the current first set by an open repetition.
    base: u64,
    /// Event-code width in the current state.
    width: u32,
}

impl SeqWriter {
    /// Starts writing a content model.
    #[must_use]
    pub fn new(shape: Shape) -> Self {
        let width = shape.width[0];
        #[cfg(debug_assertions)]
        shape.assert_below_min_is_narrow();
        Self { shape, pos: 0, base: 0, width }
    }

    /// Writes the event that introduces occurrence `c` (zero-based) of item `j`.
    ///
    /// Skipped optional items are simply never passed here; their codes fall
    /// out of the arithmetic because `pos` has not advanced past them.
    pub fn start(&mut self, e: &mut Encoder<'_>, j: usize, c: u32) -> ExiResult<()> {
        self.start_branch(e, j, c, 0)
    }

    /// Writes the event for occurrence `c` of *branch* `branch` of the choice at
    /// item `j`. A choice occupies one event code per alternative, so its
    /// branches sit at consecutive codes starting where the item does.
    pub fn start_branch(
        &mut self,
        e: &mut Encoder<'_>,
        j: usize,
        c: u32,
        branch: u64,
    ) -> ExiResult<()> {
        let (code, width) = if c == 0 {
            let code =
                self.base + self.shape.prod_before[j] - self.shape.prod_before[self.pos] + branch;
            (code, self.width)
        } else if c < self.shape.min[j] {
            // Still below the minimum: only another occurrence is possible.
            (branch, BELOW_MIN_WIDTH)
        } else {
            (branch, self.shape.repeat_width[j])
        };
        e.event(code, width)
    }

    /// Records that item `j` is complete after `count` occurrences.
    ///
    /// Call only when `count >= 1`; an absent optional item is not finished.
    pub fn finish(&mut self, j: usize, count: u32) {
        self.pos = j + 1;
        if count < self.shape.max[j] {
            // More occurrences would still be legal, so the grammar is in that
            // item's repeat state and every later code shifts up by one.
            self.base = 1;
            self.width = if count < self.shape.min[j] {
                BELOW_MIN_WIDTH
            } else {
                self.shape.repeat_width[j]
            };
        } else {
            self.base = 0;
            self.width = self.shape.width[self.pos];
        }
    }

    /// Writes the `EE` that ends the element.
    pub fn end(&mut self, e: &mut Encoder<'_>) -> ExiResult<()> {
        let code = self.base + self.shape.total() - self.shape.prod_before[self.pos];
        e.event(code, self.width)
    }
}

/// What [`SeqReader::next`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// An occurrence of item `index`.
    Item {
        /// Position of the item in the content model.
        index: usize,
        /// Which alternative of a choice this is; always zero for an element or
        /// attribute item.
        branch: u64,
        /// True for the first occurrence.
        first: bool,
    },
    /// The element ended.
    End,
}

/// Tracks position while reading a content model.
#[derive(Debug)]
pub struct SeqReader {
    shape: Shape,
    pos: usize,
    base: u64,
    width: u32,
    /// The item currently repeating, when `base` is non-zero.
    repeating: usize,
    /// Occurrences of `repeating` seen so far.
    count: u32,
    /// How many event codes `repeating` occupies — more than one for a choice.
    repeating_branches: u64,
    /// True while `repeating` is still short of its `minOccurs`, when the only
    /// legal event is another occurrence of it.
    below_min: bool,
}

impl SeqReader {
    /// Starts reading a content model.
    #[must_use]
    pub fn new(shape: Shape) -> Self {
        let width = shape.width[0];
        #[cfg(debug_assertions)]
        shape.assert_below_min_is_narrow();
        Self {
            shape,
            pos: 0,
            base: 0,
            width,
            repeating: 0,
            count: 0,
            repeating_branches: 1,
            below_min: false,
        }
    }

    /// Reads the next event.
    ///
    /// Rejects any code that names an item beyond the next required one, which
    /// would otherwise let a peer silently omit a mandatory child.
    pub fn next(&mut self, d: &mut Decoder<'_>) -> ExiResult<Step> {
        let code = d.event(self.width)?;

        if self.base != 0 && code < self.repeating_branches {
            // Another occurrence of the item we are repeating.
            self.count += 1;
            let j = self.repeating;
            self.advance_repeat(j);
            return Ok(Step::Item { index: j, branch: code, first: false });
        }

        // Below `minOccurs` the grammar has exactly one declared production —
        // another occurrence — and the code just read was not it. What is left
        // at this width is the non-strict second level, which stands for
        // undeclared content this codec does not accept. Falling through would
        // read it as "the next item" or as `EE` and silently let a peer omit a
        // mandatory repetition.
        if self.below_min {
            return Err(ExiError::UnknownEventCode);
        }

        let rel = code.checked_sub(self.base).ok_or(ExiError::UnknownEventCode)?;
        let abs = rel + self.shape.prod_before[self.pos];

        if abs == self.shape.total() {
            return Ok(Step::End);
        }

        // Locate the item this code names, and refuse codes past the first
        // required item — `prod_before` is sorted, so this is a scan of the
        // first set only.
        let mut index = self.pos;
        while index < self.shape.len() && self.shape.prod_before[index + 1] <= abs {
            if self.shape.min[index] > 0 {
                // A required item would have been skipped.
                return Err(ExiError::UnknownEventCode);
            }
            index += 1;
        }
        if index >= self.shape.len() {
            return Err(ExiError::UnknownEventCode);
        }

        let branch = abs - self.shape.prod_before[index];
        self.repeating = index;
        self.repeating_branches = self.shape.branches(index);
        self.count = 1;
        self.advance_repeat(index);
        Ok(Step::Item { index, branch, first: true })
    }

    /// Moves into the state that follows `self.count` occurrences of item `j`.
    fn advance_repeat(&mut self, j: usize) {
        self.pos = j + 1;
        self.below_min = self.count < self.shape.min[j];
        if self.count < self.shape.max[j] {
            self.base = 1;
            self.width = if self.below_min { BELOW_MIN_WIDTH } else { self.shape.repeat_width[j] };
        } else {
            self.base = 0;
            self.width = self.shape.width[self.pos];
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::exi::Header;

    /// `supportedAppProtocolReq`: one item, `AppProtocol{1,20}`.
    const REQ: Shape =
        Shape { prod_before: &[0, 1], width: &[1, 1], repeat_width: &[2], min: &[1], max: &[20] };

    /// `supportedAppProtocolRes`: `ResponseCode{1,1}` then `SchemaID{0,1}`.
    const RES: Shape = Shape {
        prod_before: &[0, 1, 2],
        width: &[1, 2, 1],
        repeat_width: &[0, 0],
        min: &[1, 0],
        max: &[1, 1],
    };

    /// Writes `items` as a content model and reads them back.
    fn roundtrip(shape: Shape, items: &[usize]) -> Vec<usize> {
        let mut buf = [0u8; 512];
        let mut encoder = Encoder::new(&mut buf);
        encoder.write_header(Header::ISO15118).unwrap();
        let mut writer = SeqWriter::new(shape);

        // Consecutive occurrences of the same item are one repetition.
        let mut pos = 0;
        while pos < items.len() {
            let item = items[pos];
            let mut count = 0u32;
            while items.get(pos + count as usize) == Some(&item) {
                writer.start(&mut encoder, item, count).unwrap();
                count += 1;
            }
            writer.finish(item, count);
            pos += count as usize;
        }
        writer.end(&mut encoder).unwrap();
        let len = encoder.finish().unwrap();

        let mut decoder = Decoder::new(&buf[..len]);
        decoder.read_header().unwrap();
        let mut reader = SeqReader::new(shape);
        let mut out = Vec::new();
        while let Step::Item { index, .. } = reader.next(&mut decoder).unwrap() {
            out.push(index);
        }
        decoder.finish().unwrap();
        out
    }

    #[test]
    fn a_single_repeated_item_roundtrips_at_every_count() {
        for n in 1..=20 {
            let items: Vec<usize> = core::iter::repeat_n(0, n).collect();
            assert_eq!(roundtrip(REQ, &items), items, "{n} occurrences");
        }
    }

    #[test]
    fn an_optional_trailing_item_roundtrips_either_way() {
        assert_eq!(roundtrip(RES, &[0]), vec![0]);
        assert_eq!(roundtrip(RES, &[0, 1]), vec![0, 1]);
    }

    #[test]
    fn widths_match_the_hand_written_app_protocol_codec() {
        // The same numbers `src/app_protocol.rs` uses, which its golden vectors
        // pin: one bit before the first entry, two while more may follow, one
        // once twenty have been written.
        let mut buf = [0u8; 512];
        let mut e = Encoder::new(&mut buf);
        let mut w = SeqWriter::new(REQ);
        w.start(&mut e, 0, 0).unwrap();
        assert_eq!(e.bit_len(), 1);
        w.finish(0, 1);
        let before = e.bit_len();
        w.end(&mut e).unwrap();
        assert_eq!(e.bit_len() - before, 2, "EE after one of twenty costs two bits");
    }

    #[test]
    fn a_code_naming_an_item_past_a_required_one_is_refused() {
        // Shape: required item 0, then item 1. Jumping straight to 1 would skip
        // a mandatory child, so the code for it must not exist at position 0.
        const S: Shape = Shape {
            prod_before: &[0, 1, 2],
            width: &[1, 1, 1],
            repeat_width: &[0, 0],
            min: &[1, 1],
            max: &[1, 1],
        };
        let mut buf = [0u8; 64];
        let mut e = Encoder::new(&mut buf);
        e.event(1, 1).unwrap(); // a code that names item 1 from position 0
        let len = e.finish().unwrap();

        let mut d = Decoder::new(&buf[..len]);
        let mut r = SeqReader::new(S);
        assert_eq!(r.next(&mut d), Err(ExiError::UnknownEventCode));
    }

    /// ISO 15118-20 WPT really has `minOccurs="2"` particles
    /// (`WPT_LF_ReceiverDataType/RxSpecData`). Below that minimum the grammar
    /// offers exactly one production, and the other code at that width is the
    /// non-strict second level — undeclared content, not "the next item" and
    /// not `EE`. Reading it as either would let a peer drop a mandatory
    /// repetition.
    #[test]
    fn the_second_level_escape_below_min_occurs_is_refused() {
        const S: Shape = Shape {
            prod_before: &[0, 1, 2],
            width: &[1, 1, 1],
            repeat_width: &[0, 2],
            min: &[1, 2],
            max: &[1, 255],
        };
        let mut buf = [0u8; 64];
        let mut e = Encoder::new(&mut buf);
        let mut w = SeqWriter::new(S);
        w.start(&mut e, 0, 0).unwrap(); // item 0, its only occurrence
        w.finish(0, 1);
        w.start(&mut e, 1, 0).unwrap(); // item 1, first of the two required
        // ...and now the escape code instead of the second occurrence.
        e.event(1, BELOW_MIN_WIDTH).unwrap();
        let len = e.finish().unwrap();

        let mut d = Decoder::new(&buf[..len]);
        let mut r = SeqReader::new(S);
        assert_eq!(r.next(&mut d).unwrap(), Step::Item { index: 0, branch: 0, first: true });
        assert_eq!(r.next(&mut d).unwrap(), Step::Item { index: 1, branch: 0, first: true });
        assert_eq!(r.next(&mut d), Err(ExiError::UnknownEventCode));
    }

    /// ...but the minimum being *met* must still leave the way out open.
    #[test]
    fn a_repetition_that_meets_its_minimum_can_end() {
        const S: Shape = Shape {
            prod_before: &[0, 1],
            width: &[1, 1],
            repeat_width: &[2],
            min: &[2],
            max: &[255],
        };
        assert_eq!(roundtrip(S, &[0, 0]), vec![0, 0]);
        assert_eq!(roundtrip(S, &[0, 0, 0]), vec![0, 0, 0]);
    }

    #[test]
    fn an_empty_content_model_reads_as_an_immediate_end() {
        const EMPTY: Shape =
            Shape { prod_before: &[0], width: &[0], repeat_width: &[], min: &[], max: &[] };
        assert!(EMPTY.is_empty());
        assert_eq!(roundtrip(EMPTY, &[]), Vec::<usize>::new());
    }
}
