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
//! Every constant below says where it comes from: the requirement and the
//! table that give its value, ISO 15118-2 Tables 108-111 for [`iso2`] and
//! ISO 15118-20:2022 Tables 214-223 for [`iso20`]. A timing constant is a
//! pair, one per role, and the generations are kept apart: where -2 and -20
//! differ — the charge loop, pre-charge, which messages get the backend
//! budget — each module has its own value and says what the other's is.

use super::{Instant, Millis};

/// ISO 15118-2 timing constants (§8.7, Tables 108-111).
pub mod iso2 {
    use super::Millis;

    /// `V2G_SECC_Sequence_Timeout` — the SECC gives up if the EVCC sends no
    /// further request within this. \[V2G2-443\]
    pub const SECC_SEQUENCE_TIMEOUT: Millis = Millis::from_secs(60);

    /// `V2G_EVCC_Sequence_Performance_Time` — the vehicle should have its next
    /// request out within this of the previous response. Table 109;
    /// \[V2G2-485\] and the thirty-odd clauses beside it phrase every step of
    /// the flow as "after receiving the ...Res, the EVCC shall send the ...Req
    /// **while** `V2G_EVCC_Sequence_Timer` is smaller than this".
    ///
    /// A performance time, so nothing enforces it — the consequence of missing
    /// it is the *station's* `V2G_SECC_Sequence_Timeout` (60 s) closing the
    /// session, twenty seconds later. [`Evcc::next_request_due`] surfaces it as
    /// a deadline so an application can see the gap it is spending.
    ///
    /// [`Evcc::next_request_due`]: crate::evcc::Evcc::next_request_due
    pub const EVCC_SEQUENCE_PERFORMANCE_TIME: Millis = Millis::from_secs(40);

    /// `V2G_EVCC_CommunicationSetup_Timeout` — from the plug being detected to
    /// a `SessionSetupRes` in hand, SDP and TLS included. \[V2G2-446\],
    /// \[V2G2-448\]; value from Table 111 \[V2G2-605\].
    ///
    /// The *station's* budget is a different parameter and a different number:
    /// `V2G_SECC_CommunicationSetup_Performance_Time` is 18 s \[V2G2-716\].
    pub const EVCC_COMMUNICATION_SETUP_TIMEOUT: Millis = Millis::from_secs(20);

    /// `V2G_SECC_CommunicationSetup_Performance_Time` — the station's own
    /// budget from link-up to a `SessionSetupRes` on the wire. \[V2G2-716\];
    /// value from Table 111 \[V2G2-605\].
    ///
    /// Two seconds tighter than the vehicle's 20 s
    /// [`EVCC_COMMUNICATION_SETUP_TIMEOUT`], and that ordering is the point: a
    /// station that has not answered by 18 s gives up while the vehicle is
    /// still listening, rather than being timed out by it.
    pub const SECC_COMMUNICATION_SETUP_PERFORMANCE_TIME: Millis = Millis::from_secs(18);

    /// `V2G_EVCC_Ongoing_Timeout` — how long the EVCC keeps re-sending a
    /// request the SECC keeps answering with `..._Ongoing`. \[V2G2-710\],
    /// \[V2G2-711\]; value from Table 109.
    ///
    /// **The field disagrees with this number, and the standard wins here
    /// anyway.** INL's ChargeX-consortium "Seamless Retry" recommended practice
    /// reports operators and equipment makers finding 60 s too short for an
    /// authorization a person has to complete, with drivers routinely needing
    /// more than 140 s to find their phone. That is a real observation and it is
    /// not this crate's to decide: the constant is what Table 109 says, rather
    /// than a library quietly disagreeing with the standard on a deployment's
    /// behalf. A deployment that has measured its own drivers sets
    /// [`LoopBudgets::authorization`]. ISO 15118-20 Table 215 keeps the same
    /// 60 s, authorization included ([`iso20::EIM_ONGOING_TIMEOUT`]).
    ///
    /// [`LoopBudgets::authorization`]: crate::session::LoopBudgets::authorization
    ///
    /// [`iso20::EIM_ONGOING_TIMEOUT`]: super::iso20::EIM_ONGOING_TIMEOUT
    pub const EVCC_ONGOING_TIMEOUT: Millis = Millis::from_secs(60);

    /// `V2G_SECC_Ongoing_Performance_Time` — the station's own budget for the
    /// same loop. \[V2G2-712\], \[V2G2-713\]; value from Table 109.
    ///
    /// Five seconds under the vehicle's [`EVCC_ONGOING_TIMEOUT`], and the gap
    /// is what the requirement is for: at 55 s the station is obliged to
    /// *answer* `FAILED` and stop the session, so the vehicle learns why
    /// instead of watching its own timer run out at 60.
    pub const SECC_ONGOING_PERFORMANCE_TIME: Millis = Millis::from_secs(55);

    /// `V2G_EVCC_CableCheck_Timeout` — the DC cable-check loop as a whole.
    /// \[V2G2-700\]..\[V2G2-703\]; value from Table 111.
    pub const EVCC_CABLE_CHECK_TIMEOUT: Millis = Millis::from_secs(40);

    /// `V2G_SECC_CableCheck_Performance_Time` — the station's own budget for
    /// the isolation test. Table 111.
    pub const SECC_CABLE_CHECK_PERFORMANCE_TIME: Millis = Millis::from_secs(38);

    /// `V2G_EVCC_PreCharge_Timeout` — the DC pre-charge loop as a whole.
    /// \[V2G2-704\]..\[V2G2-707\]; value from Table 111.
    pub const EVCC_PRE_CHARGE_TIMEOUT: Millis = Millis::from_secs(7);

    /// `V2G_SECC_PreCharge_Performance_Time` — the station's own budget for
    /// matching the link voltage. Table 111.
    pub const SECC_PRE_CHARGE_PERFORMANCE_TIME: Millis = Millis::from_secs(5);

    /// The EVCC's per-message response timeout for most messages.
    pub const MSG_TIMEOUT_DEFAULT: Millis = Millis::from_secs(2);

    /// The longer per-message timeout for the messages that reach a backend:
    /// `ServiceDetail`, `PaymentDetails`, `PowerDelivery`, and the certificate
    /// flows.
    pub const MSG_TIMEOUT_BACKEND: Millis = Millis::from_secs(5);

    /// `CurrentDemandRes` — the DC charge loop runs at tens of milliseconds, so
    /// its timeout is an order of magnitude tighter than everything else.
    pub const MSG_TIMEOUT_CURRENT_DEMAND: Millis = Millis::from_millis(250);

    // --- the other half of Table 109 -----------------------------------------
    //
    // `V2G_EVCC_Msg_Timeout` above is what the *vehicle* waits. Table 109 gives
    // the station a matching `V2G_SECC_Msg_Performance_Time` for every one of
    // the same eighteen messages. The two halves of each pair differ on
    // purpose, and by two different margins: half a second for the messages
    // that are a lookup, and a *tenth of the whole budget* for the DC charge
    // loop, where 250 ms of waiting leaves the station 25 ms to answer in.
    //
    // These are *performance* times, so nothing here enforces them — missing
    // one is not a fault this side can detect, it is the peer timing out. What
    // they are is the answer to "how long have I got", and a station that
    // cannot see the number cannot budget against it. `Secc::response_due`
    // surfaces it as a deadline.

    /// `V2G_SECC_Msg_Performance_Time` for most messages — 1,5 s. Table 109.
    ///
    /// Half a second under the vehicle's [`MSG_TIMEOUT_DEFAULT`], which is the
    /// same shape as every other pair here: the room a late answer still fits
    /// in.
    pub const SECC_MSG_PERFORMANCE_DEFAULT: Millis = Millis::from_millis(1_500);

    /// The same for the messages that reach a backend — 4,5 s. Table 109.
    ///
    /// `ServiceDetailRes`, `PaymentDetailsRes`, `PowerDeliveryRes` and the two
    /// certificate responses, matching [`MSG_TIMEOUT_BACKEND`] exactly half a
    /// second later.
    pub const SECC_MSG_PERFORMANCE_BACKEND: Millis = Millis::from_millis(4_500);

    /// `CurrentDemandRes` — **25 ms**. Table 109.
    ///
    /// The tightest number in ISO 15118-2 by an order of magnitude, and the one
    /// that decides whether a DC charge loop can be written in a garbage
    /// collected language at all: the vehicle's own budget is 250 ms
    /// ([`MSG_TIMEOUT_CURRENT_DEMAND`]) and the station is expected to have
    /// answered within a tenth of it.
    pub const SECC_MSG_PERFORMANCE_CURRENT_DEMAND: Millis = Millis::from_millis(25);
}

/// ISO 15118-20:2022 timing (§8.5, Tables 214-223).
///
/// Every value below is quoted from the 2022 text. Most
/// agree with ISO 15118-2, and where they do not the -2 value is given beside
/// the -20 one: the per-message table moved `PowerDeliveryReq` and the
/// authorization messages from the backend budget to the default one, the
/// charge loop got a looser per-message pair (0,5 s / 0,25 s against -2's
/// 250 ms / 25 ms) and a sequence pair of its own, and DC pre-charge got
/// longer (10 s / 9 s against 7 s / 5 s). Amendment 1:2026 changes none of
/// these in what its public preview shows.
///
/// [`EvccConfig::message_timeout`] and [`SeccConfig::sequence_timeout`]
/// override the per-message and sequence timeouts, and
/// [`LoopBudgets`](crate::session::LoopBudgets) overrides the `Ongoing` loop
/// budgets.
///
/// [`EvccConfig::message_timeout`]: crate::evcc::EvccConfig::message_timeout
/// [`SeccConfig::sequence_timeout`]: crate::secc::SeccConfig::sequence_timeout
pub mod iso20 {
    use super::Millis;

    // --- sequence: Table 215, and Tables 216-218 for the charge loop --------

    /// `V2G_SECC_Sequence_Timeout` — 60 s for every message but the charge
    /// loop. Table 215; \[V2G20-441\], \[V2G20-443\]. Same as -2.
    pub const SECC_SEQUENCE_TIMEOUT: Millis = Millis::from_secs(60);

    /// `V2G_EVCC_Sequence_Performance_Time` — 40 s for every message but the
    /// charge loop. Table 215; \[V2G20-434\]. Same as -2.
    pub const EVCC_SEQUENCE_PERFORMANCE_TIME: Millis = Millis::from_secs(40);

    /// `V2G_SECC_Sequence_Timeout` after an `AC_`/`DC_`/`WPT_ChargeLoopRes` —
    /// **0,5 s**. Tables 216, 217 and 218; \[V2G20-1500\], \[V2G20-1502\],
    /// \[V2G20-5070\]. -2 has no charge-loop value: its 60 s applies there too.
    /// The default of
    /// [`SeccConfig::charge_loop_sequence_timeout`](crate::secc::SeccConfig::charge_loop_sequence_timeout).
    pub const SECC_CHARGE_LOOP_SEQUENCE_TIMEOUT: Millis = Millis::from_millis(500);

    /// `V2G_EVCC_Sequence_Performance_Time` before the next
    /// `AC_`/`DC_`/`WPT_ChargeLoopReq` — **0,25 s**. Tables 216, 217 and 218;
    /// \[V2G20-1499\], \[V2G20-1501\], \[V2G20-5069\]. -2 has no charge-loop
    /// value: its 40 s applies there too.
    pub const EVCC_CHARGE_LOOP_SEQUENCE_PERFORMANCE_TIME: Millis = Millis::from_millis(250);

    // --- per message: Tables 215-219 -----------------------------------------

    /// `V2G_EVCC_Msg_Timeout` for most messages — 2 s. Tables 215-219;
    /// \[V2G20-436\], \[V2G20-438\]. Same as -2.
    ///
    /// Unlike -2, `AuthorizationReq`, `AuthorizationSetupReq`,
    /// `ScheduleExchangeReq`, `PowerDeliveryReq` and `MeteringConfirmationReq`
    /// are all at this value.
    pub const MSG_TIMEOUT_DEFAULT: Millis = Millis::from_secs(2);

    /// `V2G_EVCC_Msg_Timeout` for `CertificateInstallationReq` and
    /// `ServiceDetailReq` — 5 s, the only two -20 gives the longer budget.
    /// Table 215. -2 gives 5 s to more messages, `PowerDeliveryReq` among them.
    pub const MSG_TIMEOUT_BACKEND: Millis = Millis::from_secs(5);

    /// `V2G_EVCC_Msg_Timeout` for `AC_`/`DC_`/`WPT_ChargeLoopReq` — **0,5 s**.
    /// Tables 216, 217 and 218. -2's `CurrentDemandReq` is 250 ms.
    pub const MSG_TIMEOUT_CHARGE_LOOP: Millis = Millis::from_millis(500);

    /// `V2G_SECC_Msg_Performance_Time` for most messages — 1,5 s.
    /// Tables 215-219; \[V2G20-435\]. Same as -2.
    pub const SECC_MSG_PERFORMANCE_DEFAULT: Millis = Millis::from_millis(1_500);

    /// `V2G_SECC_Msg_Performance_Time` for `CertificateInstallationRes` and
    /// `ServiceDetailRes` — 4,5 s. Table 215. Same value as -2, fewer messages.
    pub const SECC_MSG_PERFORMANCE_BACKEND: Millis = Millis::from_millis(4_500);

    /// `V2G_SECC_Msg_Performance_Time` for the charge loop — **0,25 s**.
    /// Tables 216, 217 and 218. -2's `CurrentDemandRes` is 25 ms, a tenth of
    /// this.
    pub const SECC_MSG_PERFORMANCE_CHARGE_LOOP: Millis = Millis::from_millis(250);

    // --- communication setup: Table 221 --------------------------------------

    /// `V2G_EVCC_CommunicationSetup_Timeout` — 20 s, from the TCP/TLS
    /// connection to a `SessionSetupRes`. Table 221; \[V2G20-605\],
    /// \[V2G20-2298\], \[V2G20-448\]. Same value as -2, though -2 starts the
    /// timer at plug-in rather than at the connection.
    pub const EVCC_COMMUNICATION_SETUP_TIMEOUT: Millis = Millis::from_secs(20);

    /// `V2G_SECC_CommunicationSetup_Performance_Time` — 18 s. Table 221;
    /// \[V2G20-2303\], \[V2G20-716\]. Same as -2.
    pub const SECC_COMMUNICATION_SETUP_PERFORMANCE_TIME: Millis = Millis::from_secs(18);

    // --- EVSEProcessing / EVProcessing = Ongoing: Table 215 ------------------

    /// `V2G_EVCC_Ongoing_Timeout` — 60 s, how long the vehicle goes on
    /// re-sending a request the station answers `EVSEProcessing = Ongoing`.
    /// Table 215; \[V2G20-710\], \[V2G20-2101\]. Same as -2.
    pub const ONGOING_TIMEOUT: Millis = Millis::from_secs(60);

    /// `V2G_SECC_Ongoing_Performance_Time` — 55 s, after which the station may
    /// answer `FAILED` and stops the session. Table 215; \[V2G20-712\],
    /// \[V2G20-2102\]. Same as -2.
    pub const SECC_ONGOING_PERFORMANCE_TIME: Millis = Millis::from_secs(55);

    /// The authorization loop as the vehicle bounds it — 60 s,
    /// [`ONGOING_TIMEOUT`] itself. Table 215 gives one figure for every
    /// response with `EVSEProcessing = Ongoing`, `AuthorizationRes` included;
    /// a deployment whose drivers need longer sets
    /// [`LoopBudgets::authorization`](crate::session::LoopBudgets::authorization).
    pub const EIM_ONGOING_TIMEOUT: Millis = ONGOING_TIMEOUT;

    /// The authorization loop as the station bounds it — 55 s,
    /// [`SECC_ONGOING_PERFORMANCE_TIME`] itself. Table 215.
    pub const SECC_EIM_ONGOING_PERFORMANCE_TIME: Millis = SECC_ONGOING_PERFORMANCE_TIME;

    /// `V2G_SECC_Ongoing_Timeout` — 60 s, how long the station waits on a
    /// request the vehicle sends with `EVProcessing = Ongoing`. Table 215. New
    /// in -20, which lets the vehicle be the slow side too; no engine applies
    /// it.
    pub const SECC_ONGOING_TIMEOUT: Millis = Millis::from_secs(60);

    /// `V2G_EVCC_Ongoing_Performance_Time` — 55 s, the vehicle's half of the
    /// same loop. Table 215. New in -20; no engine applies it.
    pub const EVCC_ONGOING_PERFORMANCE_TIME: Millis = Millis::from_secs(55);

    // --- DC: Table 223 ---------------------------------------------------------

    /// `V2G_EVCC_DC_CableCheck_Timeout` — 40 s. Table 223; \[V2G20-1774\],
    /// \[V2G20-700\], \[V2G20-1398\]. Same as -2.
    pub const EVCC_CABLE_CHECK_TIMEOUT: Millis = Millis::from_secs(40);

    /// `V2G_SECC_DC_CableCheck_Performance_Time` — 38 s. Table 223. Same as -2.
    pub const SECC_CABLE_CHECK_PERFORMANCE_TIME: Millis = Millis::from_secs(38);

    /// `V2G_EVCC_DC_PreCharge_Timeout` — **10 s**. Table 223; \[V2G20-1774\],
    /// \[V2G20-704\], \[V2G20-706\]. -2 gives 7 s.
    pub const EVCC_PRE_CHARGE_TIMEOUT: Millis = Millis::from_secs(10);

    /// `V2G_SECC_DC_PreCharge_Performance_Time` — **9 s**. Table 223. -2 gives
    /// 5 s.
    pub const SECC_PRE_CHARGE_PERFORMANCE_TIME: Millis = Millis::from_secs(9);
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

    /// Every loop budget is a matched pair, and the station's half is always
    /// the shorter one.
    ///
    /// That ordering is the whole reason both halves exist: the station is
    /// obliged to *answer* `FAILED` before the vehicle's own timer runs out
    /// \[V2G2-713\], so a stalled phase ends with a response code somebody can
    /// read rather than with a socket going quiet. Inverting one of these pairs
    /// would not fail any other test — it would just make the station's timer
    /// unreachable — so it is checked at compile time.
    const _: () = {
        use iso2 as t2;
        use iso20 as t20;
        assert!(
            t2::SECC_COMMUNICATION_SETUP_PERFORMANCE_TIME.as_millis()
                < t2::EVCC_COMMUNICATION_SETUP_TIMEOUT.as_millis()
        );
        assert!(
            t2::SECC_ONGOING_PERFORMANCE_TIME.as_millis() < t2::EVCC_ONGOING_TIMEOUT.as_millis()
        );
        assert!(
            t2::SECC_CABLE_CHECK_PERFORMANCE_TIME.as_millis()
                < t2::EVCC_CABLE_CHECK_TIMEOUT.as_millis()
        );
        assert!(
            t2::SECC_PRE_CHARGE_PERFORMANCE_TIME.as_millis()
                < t2::EVCC_PRE_CHARGE_TIMEOUT.as_millis()
        );
        assert!(t20::SECC_ONGOING_PERFORMANCE_TIME.as_millis() < t20::ONGOING_TIMEOUT.as_millis());
        assert!(
            t20::EVCC_ONGOING_PERFORMANCE_TIME.as_millis() < t20::SECC_ONGOING_TIMEOUT.as_millis()
        );
        assert!(
            t20::SECC_COMMUNICATION_SETUP_PERFORMANCE_TIME.as_millis()
                < t20::EVCC_COMMUNICATION_SETUP_TIMEOUT.as_millis()
        );
        assert!(
            t20::SECC_CABLE_CHECK_PERFORMANCE_TIME.as_millis()
                < t20::EVCC_CABLE_CHECK_TIMEOUT.as_millis()
        );
        assert!(
            t20::SECC_PRE_CHARGE_PERFORMANCE_TIME.as_millis()
                < t20::EVCC_PRE_CHARGE_TIMEOUT.as_millis()
        );
        // The sequence pair runs the other way round: the vehicle's
        // performance time is the shorter, so its next request arrives before
        // the station stops waiting for it.
        assert!(
            t20::EVCC_SEQUENCE_PERFORMANCE_TIME.as_millis()
                < t20::SECC_SEQUENCE_TIMEOUT.as_millis()
        );
        assert!(
            t20::EVCC_CHARGE_LOOP_SEQUENCE_PERFORMANCE_TIME.as_millis()
                < t20::SECC_CHARGE_LOOP_SEQUENCE_TIMEOUT.as_millis()
        );
        // The per-message pair has the same ordering and the same reason: the
        // station is expected to have answered before the vehicle stops
        // waiting, and the gap is what a late answer fits in.
        assert!(t2::SECC_MSG_PERFORMANCE_DEFAULT.as_millis() < t2::MSG_TIMEOUT_DEFAULT.as_millis());
        assert!(t2::SECC_MSG_PERFORMANCE_BACKEND.as_millis() < t2::MSG_TIMEOUT_BACKEND.as_millis());
        assert!(
            t2::SECC_MSG_PERFORMANCE_CURRENT_DEMAND.as_millis()
                < t2::MSG_TIMEOUT_CURRENT_DEMAND.as_millis()
        );
        assert!(
            t20::SECC_EIM_ONGOING_PERFORMANCE_TIME.as_millis()
                < t20::EIM_ONGOING_TIMEOUT.as_millis()
        );
        assert!(
            t20::SECC_MSG_PERFORMANCE_DEFAULT.as_millis() < t20::MSG_TIMEOUT_DEFAULT.as_millis()
        );
        assert!(
            t20::SECC_MSG_PERFORMANCE_BACKEND.as_millis() < t20::MSG_TIMEOUT_BACKEND.as_millis()
        );
        assert!(
            t20::SECC_MSG_PERFORMANCE_CHARGE_LOOP.as_millis()
                < t20::MSG_TIMEOUT_CHARGE_LOOP.as_millis()
        );
    };

    /// The station's ongoing budget also has to close before the *peer's*
    /// sequence window, or the session dies of silence rather than of an
    /// answer.
    #[test]
    fn the_ongoing_window_closes_before_the_sequence_window() {
        assert!(iso20::SECC_ONGOING_PERFORMANCE_TIME < iso20::SECC_SEQUENCE_TIMEOUT);
        assert!(iso2::SECC_ONGOING_PERFORMANCE_TIME < iso2::SECC_SEQUENCE_TIMEOUT);
    }
}
