//! The clock the protocol cores run on — which the caller owns.
//!
//! Nothing in this crate reads a clock. Timers are deadlines expressed on a
//! monotonic millisecond timeline the caller supplies, so the same session code
//! runs against `std::time::Instant`, an RTC tick, a `SysTick` counter, or a
//! test's `now += 5 s`. That is what makes every spec timer a plain unit test
//! instead of a sleep.

use core::fmt;
use core::ops::{Add, Sub};

/// A point on the caller's monotonic clock, in milliseconds.
///
/// The origin is arbitrary and never inspected; only differences matter. The
/// source must be monotonic — a wall clock that jumps backwards over an NTP
/// step would make a deadline appear to un-expire.
///
/// ```
/// use iso15118::session::{Instant, Millis};
///
/// let t0 = Instant::ZERO;
/// let t1 = t0 + Millis::from_secs(60);
/// assert_eq!(t1 - t0, Millis::from_secs(60));
/// assert!(t1 > t0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Instant(u64);

impl Instant {
    /// The origin of the caller's timeline.
    pub const ZERO: Self = Self(0);

    /// Wraps a monotonic millisecond reading.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// The underlying millisecond reading.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Time elapsed since `earlier`, saturating at zero if the clock went
    /// backwards.
    #[must_use]
    pub const fn saturating_duration_since(self, earlier: Self) -> Millis {
        Millis(self.0.saturating_sub(earlier.0))
    }

    /// `self + duration`, saturating at the end of the timeline.
    #[must_use]
    pub const fn saturating_add(self, duration: Millis) -> Self {
        Self(self.0.saturating_add(duration.0))
    }
}

impl Add<Millis> for Instant {
    type Output = Self;
    fn add(self, rhs: Millis) -> Self {
        self.saturating_add(rhs)
    }
}

impl Sub for Instant {
    type Output = Millis;
    fn sub(self, rhs: Self) -> Millis {
        self.saturating_duration_since(rhs)
    }
}

impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// A duration in milliseconds.
///
/// Deliberately not [`core::time::Duration`]: every V2G timer is specified in
/// whole milliseconds or seconds, nanosecond precision would be noise, and a
/// `u64` of milliseconds is one register on the targets this crate cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Millis(u64);

impl Millis {
    /// Zero.
    pub const ZERO: Self = Self(0);

    /// From milliseconds.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// From whole seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1000))
    }

    /// As milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// As whole seconds, rounded down.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1000
    }
}

impl fmt::Display for Millis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_multiple_of(1000) {
            write!(f, "{}s", self.0 / 1000)
        } else {
            write!(f, "{}ms", self.0)
        }
    }
}

impl From<Millis> for core::time::Duration {
    fn from(value: Millis) -> Self {
        Self::from_millis(value.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backwards_clock_saturates_rather_than_wrapping() {
        let later = Instant::from_millis(10);
        let earlier = Instant::from_millis(100);
        assert_eq!(later - earlier, Millis::ZERO, "must not underflow into a huge duration");
    }

    #[test]
    fn deadlines_do_not_wrap_at_the_end_of_the_timeline() {
        let t = Instant::from_millis(u64::MAX);
        assert_eq!(t + Millis::from_secs(60), t);
    }

    #[test]
    fn durations_display_readably() {
        extern crate alloc;
        use alloc::string::ToString;
        assert_eq!(Millis::from_secs(60).to_string(), "60s");
        assert_eq!(Millis::from_millis(250).to_string(), "250ms");
    }
}
