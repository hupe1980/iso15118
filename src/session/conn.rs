//! Framing a byte stream into V2G messages, and back.
//!
//! Between the TCP (or TLS) stream and the message codecs sits a job that has
//! nothing to do with charging and everything to do with not getting it wrong:
//! V2GTP frames arrive split across reads and coalesced with their neighbours,
//! and the length field that says where one ends is attacker-controlled and
//! arrives before anything is authenticated.
//!
//! [`Connection`] does that and only that. It owns no session state, no timers
//! and no policy — it is the piece an EVCC and an SECC share exactly.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use crate::message::{Message, MessageError};
use crate::v2gtp::{self, PayloadType, V2gtpError};
use crate::{MAX_EXI_PAYLOAD_LEN, Protocol};

/// How many complete-but-undrained V2GTP frames a [`Connection`] will hold.
///
/// V2G is strictly half-duplex: neither side sends again until the other has
/// answered, so one frame in hand is the normal case and a queue this deep is
/// already generous. The bound exists because the *raw* input buffer being
/// bounded by one frame only moves the problem — a peer that keeps sending
/// whole small frames without waiting would otherwise grow the decoded queue
/// without limit.
pub const MAX_PENDING_FRAMES: usize = 4;

/// Reassembles V2GTP frames from a byte stream and serialises messages back
/// into it.
///
/// ```
/// use iso15118::Protocol;
/// use iso15118::app_protocol::SupportedAppProtocolReq;
/// use iso15118::message::Message;
/// use iso15118::session::Connection;
///
/// let mut evcc = Connection::new();
/// let req = SupportedAppProtocolReq::advertising(&[Protocol::Iso20]);
/// evcc.send(&Message::AppProtocolReq(Box::new(req)))?;
/// let wire = evcc.take_transmit();
///
/// // The charger reads the stream one byte at a time and still sees one frame.
/// let mut secc = Connection::new();
/// for byte in &wire {
///     secc.receive(&[*byte])?;
/// }
/// assert_eq!(secc.next_message()?.map(|m| m.name()), Some("supportedAppProtocolReq"));
/// assert!(secc.next_message()?.is_none());
/// # Ok::<_, iso15118::session::ConnectionError>(())
/// ```
#[derive(Debug)]
pub struct Connection {
    protocol: Option<Protocol>,
    max_payload_len: usize,
    /// Bytes that are not yet a whole frame. Bounded by one frame's worth,
    /// because everything complete has already moved to `frames`.
    rx: Vec<u8>,
    /// Complete frames, framed but not yet decoded.
    ///
    /// Splitting framing from decoding is what lets the input buffer be bounded
    /// exactly — but it moves the bound rather than removing it, so this queue
    /// has a ceiling of its own. See [`Connection::with_limits`].
    frames: VecDeque<(PayloadType, Vec<u8>)>,
    max_pending_frames: usize,
    tx: VecDeque<u8>,
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

impl Connection {
    /// A connection that has not yet negotiated a protocol.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(MAX_EXI_PAYLOAD_LEN)
    }

    /// The same, with an explicit ceiling on one frame's payload.
    ///
    /// An embedded EVCC with 64 KiB of RAM should set this to what it can
    /// actually hold, not to the crate default: the limit is what stops a peer
    /// from making the receiver buffer more than it has.
    #[must_use]
    pub fn with_limit(max_payload_len: usize) -> Self {
        Self::with_limits(max_payload_len, MAX_PENDING_FRAMES)
    }

    /// The same, also bounding how many decoded-but-undrained frames may queue
    /// up.
    ///
    /// The two limits answer different questions. `max_payload_len` bounds one
    /// frame; `max_pending_frames` bounds how many whole frames a peer may push
    /// ahead of the reader. V2G is strictly half-duplex — neither side may send
    /// again before the other has answered — so a peer that pipelines is
    /// already outside the protocol, and without this second bound it could
    /// make the receiver hold an unbounded number of frames it will never be
    /// asked for.
    #[must_use]
    pub fn with_limits(max_payload_len: usize, max_pending_frames: usize) -> Self {
        Self {
            protocol: None,
            max_payload_len,
            rx: Vec::new(),
            frames: VecDeque::new(),
            max_pending_frames: max_pending_frames.max(1),
            tx: VecDeque::new(),
        }
    }

    /// The protocol the session agreed on, once it has.
    #[must_use]
    pub const fn protocol(&self) -> Option<Protocol> {
        self.protocol
    }

    /// Records the outcome of the `supportedAppProtocol` handshake.
    ///
    /// Until this is called, payload type `0x8001` is read as the handshake;
    /// afterwards it is read as that protocol's message set. Nothing else can
    /// tell the two apart.
    pub const fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = Some(protocol);
    }

    /// Feeds bytes read from the wire. Any number, at any boundary.
    ///
    /// Whole frames are split off immediately and queued; only the trailing
    /// partial frame stays buffered as bytes. Call
    /// [`Connection::next_message`] afterwards to drain what became complete.
    ///
    /// Framing errors surface here rather than at decode time, because a stream
    /// that is not V2GTP cannot be resynchronised — there is no frame delimiter
    /// to scan for.
    pub fn receive(&mut self, data: &[u8]) -> Result<(), ConnectionError> {
        self.rx.extend_from_slice(data);
        loop {
            match v2gtp::split_frame(&self.rx, self.max_payload_len) {
                Ok((header, payload, rest)) => {
                    if self.frames.len() >= self.max_pending_frames {
                        // The peer is pushing frames faster than the protocol
                        // lets it. Nothing after this point can be answered in
                        // order, so the stream is finished.
                        self.rx.clear();
                        self.frames.clear();
                        return Err(ConnectionError::TooManyFrames {
                            limit: self.max_pending_frames,
                        });
                    }
                    let consumed = self.rx.len() - rest.len();
                    self.frames.push_back((header.payload_type, payload.to_vec()));
                    self.rx.drain(..consumed);
                }
                Err(V2gtpError::Incomplete) => break,
                Err(e) => {
                    // Nothing after a malformed header can be trusted; drop it
                    // rather than leave bytes that would be re-parsed as a
                    // frame boundary the peer never wrote.
                    self.rx.clear();
                    return Err(ConnectionError::Framing(e));
                }
            }
        }
        // What is left is a partial frame whose header already passed the
        // length limit, so the buffer is bounded by one frame's worth by
        // construction. The check is here anyway: it is one comparison, and it
        // turns a future mistake in the loop above into an error rather than
        // into unbounded growth on an unauthenticated peer's say-so.
        let ceiling = self.max_payload_len.saturating_add(v2gtp::HEADER_LEN);
        if self.rx.len() > ceiling {
            self.rx.clear();
            return Err(ConnectionError::Overflow { limit: ceiling });
        }
        Ok(())
    }

    /// Takes the next complete message, if one has arrived.
    ///
    /// `Ok(None)` means "not yet, read more". An error means the frame did not
    /// hold a message this session can decode.
    pub fn next_message(&mut self) -> Result<Option<Message>, ConnectionError> {
        let Some((payload_type, payload)) = self.frames.pop_front() else { return Ok(None) };
        Ok(Some(Message::decode(self.protocol, payload_type, &payload)?))
    }

    /// Queues a message for the wire.
    ///
    /// Borrowed rather than consumed: encoding only reads, and the session
    /// drivers need the message afterwards — to advance the ordering graph
    /// once, and only once, the bytes actually exist.
    pub fn send(&mut self, message: &Message) -> Result<(), ConnectionError> {
        let (payload_type, payload) = message.encode()?;
        if payload.len() > self.max_payload_len {
            return Err(ConnectionError::Overflow { limit: self.max_payload_len });
        }
        let mut frame = alloc::vec![0u8; v2gtp::HEADER_LEN + payload.len()];
        let n = v2gtp::write_frame(payload_type, &payload, &mut frame)
            .map_err(ConnectionError::Framing)?;
        self.tx.extend(frame[..n].iter().copied());
        Ok(())
    }

    /// True when there is nothing waiting to be written.
    #[must_use]
    pub fn transmit_is_empty(&self) -> bool {
        self.tx.is_empty()
    }

    /// Takes everything queued for the wire.
    #[must_use]
    pub fn take_transmit(&mut self) -> Vec<u8> {
        self.tx.drain(..).collect()
    }

    /// Number of buffered input bytes not yet part of a complete frame.
    #[must_use]
    pub fn pending_input(&self) -> usize {
        self.rx.len()
    }

    /// Number of complete frames waiting to be decoded.
    #[must_use]
    pub fn pending_frames(&self) -> usize {
        self.frames.len()
    }

    /// Drops all buffered input — what closing a session does.
    pub fn reset(&mut self) {
        self.rx.clear();
        self.frames.clear();
        self.tx.clear();
    }
}

/// Why a byte stream could not be framed or a message could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionError {
    /// The V2GTP framing was malformed.
    Framing(V2gtpError),
    /// The framed payload was not a message this build can decode.
    Message(MessageError),
    /// A frame, or the buffer waiting for one, exceeded the configured limit.
    Overflow {
        /// The limit that was exceeded, in bytes.
        limit: usize,
    },
    /// The peer pipelined more frames than the half-duplex protocol allows.
    TooManyFrames {
        /// How many undrained frames the connection will hold.
        limit: usize,
    },
}

impl From<V2gtpError> for ConnectionError {
    fn from(e: V2gtpError) -> Self {
        Self::Framing(e)
    }
}

impl From<MessageError> for ConnectionError {
    fn from(e: MessageError) -> Self {
        Self::Message(e)
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Framing(e) => write!(f, "V2GTP: {e}"),
            Self::Message(e) => write!(f, "{e}"),
            Self::Overflow { limit } => write!(f, "frame exceeds the {limit} byte limit"),
            Self::TooManyFrames { limit } => {
                write!(f, "the peer pipelined more than {limit} unanswered V2GTP frames")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Framing(e) => Some(e),
            Self::Message(e) => Some(e),
            Self::Overflow { .. } | Self::TooManyFrames { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use super::*;
    use crate::app_protocol::SupportedAppProtocolReq;

    fn handshake() -> Message {
        Message::AppProtocolReq(Box::new(SupportedAppProtocolReq::advertising(&[
            Protocol::Iso20,
            Protocol::Iso2,
        ])))
    }

    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        let mut out = Connection::new();
        out.send(&handshake()).unwrap();
        let wire = out.take_transmit();

        let mut c = Connection::new();
        for chunk in wire.chunks(3) {
            c.receive(chunk).unwrap();
        }
        assert!(c.next_message().unwrap().is_some());
        assert_eq!(c.pending_input(), 0);
    }

    #[test]
    fn two_frames_in_one_read_come_out_as_two_messages() {
        let mut out = Connection::new();
        out.send(&handshake()).unwrap();
        out.send(&handshake()).unwrap();
        let wire = out.take_transmit();

        let mut c = Connection::new();
        c.receive(&wire).unwrap();
        assert!(c.next_message().unwrap().is_some());
        assert!(c.next_message().unwrap().is_some());
        assert!(c.next_message().unwrap().is_none());
    }

    #[test]
    fn an_incomplete_frame_is_not_an_error() {
        let mut out = Connection::new();
        out.send(&handshake()).unwrap();
        let wire = out.take_transmit();

        let mut c = Connection::new();
        c.receive(&wire[..wire.len() - 1]).unwrap();
        assert_eq!(c.next_message().unwrap(), None, "still waiting, not broken");
    }

    #[test]
    fn a_forged_length_is_refused_before_anything_is_buffered_for_it() {
        // A header claiming 4 GiB, with nothing behind it.
        let mut c = Connection::with_limit(4096);
        assert!(matches!(
            c.receive(&[0x01, 0xFE, 0x80, 0x01, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(ConnectionError::Framing(V2gtpError::PayloadTooLarge { .. }))
        ));
        assert_eq!(c.pending_input(), 0, "nothing is kept from a stream we cannot parse");
    }

    /// The buffer a peer can grow is bounded by one legal frame, whatever it
    /// sends and however it splits it.
    #[test]
    fn a_peer_that_never_finishes_a_frame_cannot_grow_the_buffer() {
        const LIMIT: usize = 64;
        let ceiling = LIMIT + v2gtp::HEADER_LEN;
        let mut c = Connection::with_limit(LIMIT);
        // A header claiming the largest legal payload, then a trickle that
        // stops one byte short of completing it, forever.
        c.receive(&[0x01, 0xFE, 0x80, 0x01, 0x00, 0x00, 0x00, u8::try_from(LIMIT).unwrap()])
            .unwrap();
        for _ in 0..LIMIT - 1 {
            c.receive(&[0u8]).unwrap();
            assert!(c.pending_input() <= ceiling, "buffered {} bytes", c.pending_input());
        }
        assert_eq!(c.pending_frames(), 0, "the frame is still one byte short");
    }

    #[test]
    fn garbage_is_rejected_rather_than_skipped() {
        let mut c = Connection::new();
        assert!(c.receive(&[0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0]).is_err());
    }

    /// Several whole frames in one read stay inside the byte limit — that one
    /// bounds a frame, not a read — but the queue they land in has a ceiling of
    /// its own.
    #[test]
    fn whole_frames_in_one_read_are_not_a_byte_overflow() {
        let mut out = Connection::new();
        for _ in 0..MAX_PENDING_FRAMES {
            out.send(&handshake()).unwrap();
        }
        let wire = out.take_transmit();

        // A byte limit that one frame fits inside and four do not.
        let mut c = Connection::with_limit(wire.len() / MAX_PENDING_FRAMES);
        c.receive(&wire).unwrap();
        assert_eq!(c.pending_frames(), MAX_PENDING_FRAMES);
        assert_eq!(c.pending_input(), 0);
        for _ in 0..MAX_PENDING_FRAMES {
            assert!(c.next_message().unwrap().is_some());
        }
    }

    /// V2G is half-duplex: a peer that keeps sending without waiting for an
    /// answer is outside the protocol, and bounding only the *byte* buffer
    /// would have let it grow the decoded queue instead.
    #[test]
    fn a_peer_that_pipelines_without_waiting_is_cut_off() {
        let mut out = Connection::new();
        for _ in 0..=MAX_PENDING_FRAMES {
            out.send(&handshake()).unwrap();
        }
        let wire = out.take_transmit();

        let mut c = Connection::new();
        assert_eq!(
            c.receive(&wire),
            Err(ConnectionError::TooManyFrames { limit: MAX_PENDING_FRAMES })
        );
        assert_eq!(c.pending_frames(), 0, "nothing is kept from a stream we will not follow");
        assert_eq!(c.pending_input(), 0);
    }

    /// ...and draining as you go is not pipelining, however many frames the
    /// session carries in total.
    #[test]
    fn draining_between_reads_has_no_ceiling() {
        let mut out = Connection::new();
        out.send(&handshake()).unwrap();
        let one = out.take_transmit();

        let mut c = Connection::with_limits(4096, 1);
        for _ in 0..64 {
            c.receive(&one).unwrap();
            assert!(c.next_message().unwrap().is_some());
        }
    }

    /// Payload type `0x8001` means the handshake before negotiation and a -2
    /// message afterwards. Nothing in the frame says which.
    #[test]
    fn the_negotiated_protocol_decides_how_0x8001_is_read() {
        let mut out = Connection::new();
        out.send(&handshake()).unwrap();
        let wire = out.take_transmit();

        let mut c = Connection::new();
        c.set_protocol(Protocol::Iso2);
        c.receive(&wire).unwrap();
        assert!(
            c.next_message().is_err(),
            "a handshake read as a -2 message must fail, not decode to nonsense"
        );
    }
}
