//! The V2G timers, and the deadline set a session keeps.
//!
//! ISO 15118 specifies two families of timer and they fail in opposite
//! directions, which is why they are modelled separately here:
//!
//! * **Performance times** bound how long *this* side may take to answer. They
//!   are a promise, not a deadline to watch — missing one makes the peer time
//!   out, so the core surfaces them as advice rather than enforcing them.
//! * **Timeouts** bound how long this side waits for the *peer*. Missing one is
//!   a terminal condition: the session ends, and the spec says what to send.
//!
//! Every constant below says where it comes from, and says it honestly: a
//! requirement number where there is one, and "this crate's policy" where the
//! value is derived rather than quoted. ISO 15118-20's timing table is a paid
//! document this project does not have, so two of its loop budgets are the
//! second kind — see [`iso20`]. Where -2 and -20 differ, both values are given
//! rather than one being made to stand for both.

use super::{Instant, Millis};

/// ISO 15118-2 timing constants (§8.7, Table 105).
pub mod iso2 {
    use super::Millis;

    /// `V2G_SECC_Sequence_Timeout` — the SECC gives up if the EVCC sends no
    /// further request within this. \[V2G2-443\]
    pub const SECC_SEQUENCE_TIMEOUT: Millis = Millis::from_secs(60);

    /// `V2G_EVCC_Sequence_Performance_Time` — the EVCC should have its next
    /// request out within this of the previous response.
    pub const EVCC_SEQUENCE_PERFORMANCE_TIME: Millis = Millis::from_secs(40);

    /// `V2G_EVCC_CommunicationSetup_Timeout` — from the plug being detected to
    /// a `SessionSetupRes` in hand, SDP and TLS included. \[V2G2-716\]
    pub const EVCC_COMMUNICATION_SETUP_TIMEOUT: Millis = Millis::from_secs(20);

    /// `V2G_EVCC_Ongoing_Timeout` — how long the EVCC keeps re-sending a
    /// request the SECC keeps answering with `..._Ongoing`.
    pub const EVCC_ONGOING_TIMEOUT: Millis = Millis::from_secs(60);

    /// `V2G_EVCC_CableCheck_Timeout` — the DC cable-check loop as a whole.
    pub const EVCC_CABLE_CHECK_TIMEOUT: Millis = Millis::from_secs(40);

    /// `V2G_EVCC_PreCharge_Timeout` — the DC pre-charge loop as a whole.
    pub const EVCC_PRE_CHARGE_TIMEOUT: Millis = Millis::from_secs(7);

    /// The EVCC's per-message response timeout for most messages.
    pub const MSG_TIMEOUT_DEFAULT: Millis = Millis::from_secs(2);

    /// The longer per-message timeout for the messages that reach a backend:
    /// `ServiceDetail`, `PaymentDetails`, `PowerDelivery`, and the certificate
    /// flows.
    pub const MSG_TIMEOUT_BACKEND: Millis = Millis::from_secs(5);

    /// `CurrentDemandRes` — the DC charge loop runs at tens of milliseconds, so
    /// its timeout is an order of magnitude tighter than everything else.
    pub const MSG_TIMEOUT_CURRENT_DEMAND: Millis = Millis::from_millis(250);
}

/// ISO 15118-20 timing.
///
/// ISO 15118-20 has a timing table of its own (§8.5) and this crate does not
/// have that text — the standard is a paid document. So the two values -20
/// shares with -2 are cited, and the two loop budgets are **this crate's
/// policy**, derived below rather than quoted. They are named as such because a
/// constant that says "§8.5" when nobody checked §8.5 is worse than one that
/// says where it really came from: the first cannot be questioned, the second
/// can be replaced. [`EvccConfig::message_timeout`] and
/// [`SeccConfig::sequence_timeout`] override them for a caller that has the
/// table.
///
/// [`EvccConfig::message_timeout`]: crate::evcc::EvccConfig::message_timeout
/// [`SeccConfig::sequence_timeout`]: crate::secc::SeccConfig::sequence_timeout
pub mod iso20 {
    use super::Millis;

    /// `V2G_SECC_Sequence_Timeout` — 60 s, unchanged from -2.
    pub const SECC_SEQUENCE_TIMEOUT: Millis = Millis::from_secs(60);

    /// `V2G_EVCC_CommunicationSetup_Timeout` — 20 s, unchanged from -2.
    pub const EVCC_COMMUNICATION_SETUP_TIMEOUT: Millis = Millis::from_secs(20);

    /// How long a phase may go on being answered `..._Ongoing`.
    ///
    /// **This crate's policy, not a quoted constant.** It is derived from the
    /// one number that *is* specified: the peer gives up at
    /// [`SECC_SEQUENCE_TIMEOUT`], so a side that has not decided by then loses
    /// the session without ever saying why. Five seconds under it leaves room
    /// to answer.
    pub const ONGOING_TIMEOUT: Millis = Millis::from_secs(55);

    /// The same budget where a *human* is expected to finish the exchange —
    /// tapping a card, confirming in an app.
    ///
    /// **This crate's policy, not a quoted constant.** It is longer than
    /// [`SECC_SEQUENCE_TIMEOUT`] on purpose and that is not a contradiction:
    /// the sequence timer bounds the gap between two messages, and an
    /// authorization loop is sending one every second or so while it waits.
    /// What this bounds is the *loop*, and three minutes is roughly how long a
    /// driver takes to find their phone.
    pub const EIM_ONGOING_TIMEOUT: Millis = Millis::from_secs(180);
}

/// SECC discovery timing (ISO 15118-2 §7.9).
pub mod sdp {
    use super::Millis;

    /// The EVCC waits at least this long for a `SECCDiscoveryRes` before
    /// re-sending. \[V2G2-159\]
    pub const RESPONSE_TIMEOUT: Millis = Millis::from_millis(250);

    /// At most this many consecutive discovery requests. \[V2G2-161\]
    pub const MAX_REQUESTS: u32 = 50;
}

/// Which timer a [`Timers`] set is tracking.
///
/// They are independent: a session can be inside its ongoing-retry window and
/// its sequence window at once, and whichever expires first decides what
/// happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Timer {
    /// Waiting for the peer's next message. Expiry ends the session.
    Sequence,
    /// Waiting for the answer to the request just sent.
    Message,
    /// Re-sending a request the peer keeps answering with `..._Ongoing`.
    Ongoing,
    /// From link-up to `SessionSetupRes`.
    CommunicationSetup,
}

/// The number of distinct timers, and the array length [`Timers`] uses.
const TIMER_COUNT: usize = 4;

impl Timer {
    const ALL: [Self; TIMER_COUNT] =
        [Self::Sequence, Self::Message, Self::Ongoing, Self::CommunicationSetup];

    const fn index(self) -> usize {
        match self {
            Self::Sequence => 0,
            Self::Message => 1,
            Self::Ongoing => 2,
            Self::CommunicationSetup => 3,
        }
    }

    /// A short name for logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sequence => "sequence",
            Self::Message => "message",
            Self::Ongoing => "ongoing",
            Self::CommunicationSetup => "communication-setup",
        }
    }
}

/// The deadlines a session is currently waiting on.
///
/// A session holds one of these and asks it for the next deadline; the caller
/// arms its own timer for that instant and calls back. There is no polling and
/// no background task — the whole timing model is "what is the earliest thing
/// that could go wrong, and when".
///
/// ```
/// use iso15118::session::{Instant, Millis, Timer, Timers};
///
/// let mut timers = Timers::new();
/// let t0 = Instant::ZERO;
/// timers.arm(Timer::Sequence, t0, Millis::from_secs(60));
/// timers.arm(Timer::Message, t0, Millis::from_secs(2));
///
/// // The caller sleeps until the earliest deadline, not until each in turn.
/// assert_eq!(timers.next_deadline(), Some(t0 + Millis::from_secs(2)));
/// assert_eq!(timers.expired(t0 + Millis::from_secs(3)), Some(Timer::Message));
/// ```
#[derive(Debug, Clone, Default)]
pub struct Timers {
    deadlines: [Option<Instant>; TIMER_COUNT],
}

impl Timers {
    /// A set with nothing running.
    #[must_use]
    pub const fn new() -> Self {
        Self { deadlines: [None; TIMER_COUNT] }
    }

    /// Starts (or restarts) `timer` to expire `after` from `now`.
    pub const fn arm(&mut self, timer: Timer, now: Instant, after: Millis) {
        self.deadlines[timer.index()] = Some(now.saturating_add(after));
    }

    /// Stops `timer`.
    pub const fn disarm(&mut self, timer: Timer) {
        self.deadlines[timer.index()] = None;
    }

    /// Stops every timer — what session termination does.
    pub fn disarm_all(&mut self) {
        self.deadlines = [None; TIMER_COUNT];
    }

    /// The deadline of `timer`, if it is running.
    #[must_use]
    pub const fn deadline(&self, timer: Timer) -> Option<Instant> {
        self.deadlines[timer.index()]
    }

    /// True when `timer` is running.
    #[must_use]
    pub const fn is_armed(&self, timer: Timer) -> bool {
        self.deadlines[timer.index()].is_some()
    }

    /// The earliest deadline of any running timer.
    ///
    /// This is what a caller arms its own clock for. `None` means nothing is
    /// pending and the session needs no wake-up.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.iter().flatten().copied().min()
    }

    /// The timer that has expired at `now`, earliest deadline first, removing
    /// it from the set.
    ///
    /// Call in a loop: several may come due at the same instant, and each has
    /// its own consequence.
    pub fn expired(&mut self, now: Instant) -> Option<Timer> {
        let due = Timer::ALL
            .into_iter()
            .filter_map(|t| self.deadlines[t.index()].map(|d| (d, t)))
            .filter(|&(d, _)| d <= now)
            .min();
        if let Some((_, timer)) = due {
            self.disarm(timer);
            return Some(timer);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_pending_on_a_fresh_set() {
        let timers = Timers::new();
        assert_eq!(timers.next_deadline(), None);
        assert!(!timers.is_armed(Timer::Sequence));
    }

    #[test]
    fn the_earliest_deadline_wins() {
        let mut t = Timers::new();
        let now = Instant::ZERO;
        t.arm(Timer::Sequence, now, Millis::from_secs(60));
        t.arm(Timer::Ongoing, now, Millis::from_secs(55));
        t.arm(Timer::Message, now, Millis::from_secs(2));
        assert_eq!(t.next_deadline(), Some(now + Millis::from_secs(2)));
    }

    #[test]
    fn expiry_is_reported_once_and_in_deadline_order() {
        let mut t = Timers::new();
        let now = Instant::ZERO;
        t.arm(Timer::Sequence, now, Millis::from_secs(60));
        t.arm(Timer::Message, now, Millis::from_secs(2));

        let late = now + Millis::from_secs(61);
        assert_eq!(t.expired(late), Some(Timer::Message), "earlier deadline first");
        assert_eq!(t.expired(late), Some(Timer::Sequence));
        assert_eq!(t.expired(late), None, "each expires exactly once");
    }

    #[test]
    fn a_timer_that_is_not_due_does_not_fire() {
        let mut t = Timers::new();
        t.arm(Timer::Sequence, Instant::ZERO, Millis::from_secs(60));
        assert_eq!(t.expired(Instant::from_millis(59_999)), None);
        assert_eq!(t.expired(Instant::from_millis(60_000)), Some(Timer::Sequence));
    }

    #[test]
    fn rearming_replaces_the_old_deadline() {
        let mut t = Timers::new();
        t.arm(Timer::Sequence, Instant::ZERO, Millis::from_secs(60));
        t.arm(Timer::Sequence, Instant::from_millis(30_000), Millis::from_secs(60));
        assert_eq!(t.deadline(Timer::Sequence), Some(Instant::from_millis(90_000)));
    }

    /// The -20 ongoing window is deliberately shorter than the sequence window,
    /// so the SECC always decides before the EVCC gives up on it.
    #[test]
    fn the_ongoing_window_closes_before_the_sequence_window() {
        assert!(iso20::ONGOING_TIMEOUT < iso20::SECC_SEQUENCE_TIMEOUT);
    }
}
