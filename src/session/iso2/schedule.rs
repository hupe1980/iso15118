//! Does the vehicle's charging profile fit the schedule it was offered?
//!
//! In `PowerDeliveryReq` the vehicle picks one of the `SAScheduleTuple`s the
//! station offered in `ChargeParameterDiscoveryRes` and states, as a
//! `ChargingProfile`, the power it intends to draw over time. The standard
//! fixes both the rule and the answer:
//!
//! * \[V2G2-224\] the SECC **shall always accept** a profile that does not
//!   exceed the `PMax` of every `PMaxScheduleEntry` of the chosen tuple;
//! * \[V2G2-225\] and **shall answer `FAILED_ChargingProfileInvalid`** to one
//!   that does;
//! * \[V2G2-479\] `FAILED_TariffSelectionInvalid` if the `SAScheduleTupleID`
//!   was never offered.
//!
//! That is protocol, not policy: the station does not *decide* whether a
//! profile conforms, arithmetic does, and the response code follows. Without
//! it, `ResponseCode::FAILEDChargingProfileInvalid` is a value this crate can
//! name and no caller can know when to send.
//!
//! # The two timelines
//!
//! Both measure from the same origin — the moment the schedule was issued — and
//! both are step functions over it, with breakpoints that need not line up.
//!
//! ```text
//! offered   |<-- PMax A -->|<------ PMax B ------>|<-- PMax C -->|
//!           0             300                   1800           3600   (duration)
//!
//! profile   |<--- P1 --->|<-------- P2 -------->|<------- P3 ------->  (open)
//!           0           240                    1500
//! ```
//!
//! * `PMaxScheduleEntry` carries a `RelativeTimeInterval` whose `start` is
//!   seconds from NOW \[V2G2-328\] and is *also* the stop of the previous
//!   interval \[V2G2-329\]. Only the last may carry a `duration`, which ends
//!   the coverage \[V2G2-331\].
//! * `ChargingProfileEntryStart` is an offset from the same NOW, the next
//!   entry's start is when this one stops, and the last runs on until the
//!   profile is replaced \[V2G2-289\]..\[V2G2-291\].
//!
//! Where the schedule states no limit there is nothing to exceed and nothing
//! fails: a profile routinely runs past the coverage, and ISO 15118-2 handles
//! that by having the vehicle ask for a new schedule \[V2G2-305\]. [`coverage`]
//! reports where that edge is; [`pmax_at`] answers at a single instant.
//!
//! ISO 15118-20 is not here. Its model is a different shape — `EVPowerProfile`
//! entries carry a duration rather than a start, powers are `RationalNumber`,
//! and the schedule comes from `ScheduleExchangeRes` — so it needs its own
//! rules read from its own standard rather than this one adapted.

use alloc::vec::Vec;
use core::fmt;

use crate::iso2::{
    ChargingProfile, PMaxScheduleEntryChoice, PhysicalValue, PowerDeliveryReq, ResponseCode,
    SAScheduleList, SAScheduleTuple, UnitSymbol,
};

/// Power in milliwatts.
///
/// `PhysicalValueType` is `Value * 10 ^ Multiplier` with the multiplier in
/// `-3..=3` \[V2G2-279\], so a power can be a thousandth of a watt and the
/// comparison has to be exact. Milliwatts in an `i64` hold every representable
/// value — the largest is `i16::MAX * 10^6`, four orders of magnitude inside
/// the type — with no rounding and no floating point anywhere near a decision
/// that ends a charging session.
pub type Milliwatts = i64;

/// Converts a `PhysicalValueType` power to [`Milliwatts`].
///
/// Refuses a value that is not in watts: `PMax` and
/// `ChargingProfileEntryMaxPower` are both watts by Table 68 \[V2G2-832\], and
/// comparing a current against a power because both happen to be integers is
/// the kind of agreement nobody notices until a car draws it.
pub fn power_mw(value: &PhysicalValue) -> Result<Milliwatts, ProfileError> {
    if value.unit != UnitSymbol::W {
        return Err(ProfileError::NotWatts { unit: value.unit });
    }
    // `10^(multiplier + 3)` — milliwatts. The facet is -3..=3 and the decoder
    // enforces it, so the exponent is 0..=6; anything else is refused rather
    // than saturated, because a silently clamped power limit is worse than a
    // rejected message.
    let exponent = i32::from(value.multiplier) + 3;
    let Some(scale) = u32::try_from(exponent).ok().filter(|e| *e <= 6).map(|e| 10i64.pow(e)) else {
        return Err(ProfileError::MultiplierOutOfRange { multiplier: value.multiplier });
    };
    Ok(i64::from(value.value) * scale)
}

/// One step of a step function over the relative-seconds axis.
///
/// `end` is `None` for an interval that has no stated end — the schedule's last
/// entry without a `duration`, and the profile's last entry always
/// \[V2G2-291\].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Step {
    start: u32,
    end: Option<u32>,
    power: Milliwatts,
}

impl Step {
    /// Whether this step is active at any instant `other` also is.
    const fn overlaps(&self, other: &Self) -> bool {
        let a_end = match self.end {
            Some(e) => e,
            None => u32::MAX,
        };
        let b_end = match other.end {
            Some(e) => e,
            None => u32::MAX,
        };
        self.start < b_end && other.start < a_end
    }

    /// The first instant both are active, which is where a violation begins.
    const fn overlap_start(&self, other: &Self) -> u32 {
        if self.start > other.start { self.start } else { other.start }
    }
}

/// Reads the offered schedule as a step function, in order.
fn schedule_steps(tuple: &SAScheduleTuple) -> Result<Vec<Step>, ProfileError> {
    let entries = &tuple.p_max_schedule.p_max_schedule_entry;
    let mut steps: Vec<Step> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        // `TimeInterval` is the abstract head of the substitution group and
        // carries no time at all, so an entry that uses it says nothing about
        // when its limit applies. Only `RelativeTimeInterval` is usable.
        let PMaxScheduleEntryChoice::RelativeTimeInterval(interval) = &entry.choice else {
            return Err(ProfileError::ScheduleNotRelative { index });
        };
        let power = power_mw(&entry.p_max)?;
        if let Some(previous) = steps.last_mut() {
            if interval.start <= previous.start {
                return Err(ProfileError::ScheduleOutOfOrder { index });
            }
            // \[V2G2-329\]: a start is also the stop of the interval before it.
            previous.end = Some(interval.start);
        }
        steps.push(Step { start: interval.start, end: None, power });
    }
    // \[V2G2-331\]: only the last interval may carry a duration, and it marks
    // the end of the coverage.
    if let Some(last) = steps.last_mut()
        && let Some(PMaxScheduleEntryChoice::RelativeTimeInterval(interval)) =
            entries.last().map(|e| &e.choice)
        && let Some(duration) = interval.duration
    {
        last.end = Some(last.start.saturating_add(duration));
    }
    Ok(steps)
}

/// Reads the vehicle's profile as a step function, in order.
fn profile_steps(profile: &ChargingProfile) -> Result<Vec<Step>, ProfileError> {
    let mut steps: Vec<Step> = Vec::with_capacity(profile.profile_entry.len());
    for (index, entry) in profile.profile_entry.iter().enumerate() {
        let power = power_mw(&entry.charging_profile_entry_max_power)?;
        if let Some(previous) = steps.last_mut() {
            if entry.charging_profile_entry_start <= previous.start {
                return Err(ProfileError::ProfileOutOfOrder { index });
            }
            // \[V2G2-290\]: the next start is when this entry becomes inactive.
            previous.end = Some(entry.charging_profile_entry_start);
        }
        steps.push(Step { start: entry.charging_profile_entry_start, end: None, power });
    }
    Ok(steps)
}

/// The power the schedule permits `offset` seconds after it was issued.
///
/// `None` where the schedule says nothing — before its first interval, or past
/// the coverage its last `duration` declares. That is not the same as zero, and
/// the distinction is the whole of why this returns an `Option`: a caller that
/// read "no limit stated" as "no power" would refuse to charge at exactly the
/// moment the vehicle asked for a new schedule.
pub fn pmax_at(tuple: &SAScheduleTuple, offset: u32) -> Result<Option<Milliwatts>, ProfileError> {
    let steps = schedule_steps(tuple)?;
    Ok(steps
        .iter()
        .find(|s| s.start <= offset && s.end.is_none_or(|end| offset < end))
        .map(|s| s.power))
}

/// How far past its issue the schedule states a limit for, in seconds.
///
/// `None` when the last interval carries no `duration`, which \[V2G2-331\]
/// allows: the schedule then states no end and the limit of its last interval
/// stands until something replaces it.
#[must_use]
pub fn coverage(tuple: &SAScheduleTuple) -> Option<u32> {
    let steps = schedule_steps(tuple).ok()?;
    steps.last()?.end
}

/// Checks a `PowerDeliveryReq` against the schedules the station offered.
///
/// This is the station's side of \[V2G2-224\], \[V2G2-225\] and \[V2G2-479\] in
/// one call: `Ok(())` is a request to accept, and every error names the
/// `ResponseCode` the standard prescribes — [`ProfileError::response_code`].
///
/// `offered` is the `SAScheduleList` from the **last**
/// `ChargeParameterDiscoveryRes` this station sent \[V2G2-225\], which is the
/// one the vehicle answered; a station that renegotiated has a newer list and
/// must pass that one.
///
/// A request with no `ChargingProfile` is `Ok(())`: the element is optional in
/// the schema, and a vehicle that states no profile has stated nothing that can
/// exceed a limit. Whether to require one is the station's decision, not this
/// rule's.
///
/// ```
/// use iso15118::iso2::{
///     ChargeProgress, ChargingProfile, PMaxSchedule, PMaxScheduleEntry,
///     PMaxScheduleEntryChoice, PhysicalValue, PowerDeliveryReq, ProfileEntry,
///     RelativeTimeInterval, SAScheduleList, SAScheduleTuple, UnitSymbol,
/// };
/// use iso15118::session::iso2::schedule;
///
/// let watts = |w: i16| PhysicalValue { multiplier: 0, unit: UnitSymbol::W, value: w };
///
/// // The station offers 11 kW from the start.
/// let offered = SAScheduleList {
///     sa_schedule_tuple: vec![SAScheduleTuple {
///         sa_schedule_tuple_id: 1,
///         p_max_schedule: PMaxSchedule {
///             p_max_schedule_entry: vec![PMaxScheduleEntry {
///                 choice: PMaxScheduleEntryChoice::RelativeTimeInterval(
///                     RelativeTimeInterval { start: 0, duration: Some(3600) },
///                 ),
///                 p_max: PhysicalValue { multiplier: 1, unit: UnitSymbol::W, value: 1100 },
///             }],
///         },
///         sales_tariff: None,
///     }],
/// };
///
/// let mut req = PowerDeliveryReq {
///     charge_progress: ChargeProgress::Start,
///     sa_schedule_tuple_id: 1,
///     charging_profile: Some(ChargingProfile {
///         profile_entry: vec![ProfileEntry {
///             charging_profile_entry_start: 0,
///             charging_profile_entry_max_power: watts(7400),
///             charging_profile_entry_max_number_of_phases_in_use: None,
///         }],
///     }),
///     choice: None,
/// };
/// assert!(schedule::check_power_delivery(&offered, &req).is_ok());
///
/// // ...and 22 kW is not on offer.
/// req.charging_profile.as_mut().unwrap().profile_entry[0]
///     .charging_profile_entry_max_power =
///     PhysicalValue { multiplier: 1, unit: UnitSymbol::W, value: 2200 };
/// let err = schedule::check_power_delivery(&offered, &req).unwrap_err();
/// assert_eq!(err.response_code(), iso15118::iso2::ResponseCode::FAILEDChargingProfileInvalid);
/// # Ok::<_, iso15118::exi::ExiError>(())
/// ```
pub fn check_power_delivery(
    offered: &SAScheduleList,
    req: &PowerDeliveryReq,
) -> Result<(), ProfileError> {
    // \[V2G2-286\], \[V2G2-479\]: the id has to name a tuple that was offered.
    let tuple = offered
        .sa_schedule_tuple
        .iter()
        .find(|t| t.sa_schedule_tuple_id == req.sa_schedule_tuple_id)
        .ok_or(ProfileError::UnknownScheduleTuple { requested: req.sa_schedule_tuple_id })?;

    let Some(profile) = req.charging_profile.as_ref() else { return Ok(()) };
    check_profile(tuple, profile)
}

/// The same check against one already-selected tuple.
///
/// This is what an EVCC wants: the vehicle builds the profile, and checking it
/// before it goes on the wire beats learning about it from a
/// `FAILED_ChargingProfileInvalid` that also ends the session.
pub fn check_profile(
    tuple: &SAScheduleTuple,
    profile: &ChargingProfile,
) -> Result<(), ProfileError> {
    let limits = schedule_steps(tuple)?;
    let wanted = profile_steps(profile)?;

    for want in &wanted {
        for limit in &limits {
            // Where the schedule states nothing there is nothing to exceed, so
            // only overlapping intervals constrain each other. See the module
            // documentation for why that is not a hole.
            if want.overlaps(limit) && want.power > limit.power {
                return Err(ProfileError::ExceedsPMax {
                    at: want.overlap_start(limit),
                    requested: want.power,
                    permitted: limit.power,
                });
            }
        }
    }
    Ok(())
}

/// Why a `PowerDeliveryReq` cannot be accepted as it stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileError {
    /// The `SAScheduleTupleID` names no tuple the station offered.
    /// \[V2G2-286\], \[V2G2-479\]
    UnknownScheduleTuple {
        /// The id the vehicle asked for.
        requested: u8,
    },
    /// The profile draws more than the chosen schedule permits. \[V2G2-225\],
    /// \[V2G2-293\]
    ExceedsPMax {
        /// Seconds after the schedule was issued at which it first exceeds.
        at: u32,
        /// What the profile asked for.
        requested: Milliwatts,
        /// What the schedule permits at that instant.
        permitted: Milliwatts,
    },
    /// A power was given in some unit other than watts. \[V2G2-832\]
    NotWatts {
        /// The unit that arrived.
        unit: UnitSymbol,
    },
    /// A `PhysicalValueType` multiplier outside the schema's `-3..=3`.
    /// \[V2G2-279\]
    MultiplierOutOfRange {
        /// The multiplier that arrived.
        multiplier: i8,
    },
    /// Profile entries are not in increasing order of start time.
    ///
    /// Inferred rather than quoted: \[V2G2-290\] defines an entry's stop as the
    /// *next* entry's start, so an out-of-order list describes no interval at
    /// all and there is nothing to check it against.
    ProfileOutOfOrder {
        /// Index of the entry that does not start after the one before it.
        index: usize,
    },
    /// The station's own schedule entries are not in increasing order.
    ///
    /// A fault in what this station offered, not in what the vehicle answered
    /// — but it is found here, because this is the first thing that reads the
    /// two together.
    ScheduleOutOfOrder {
        /// Index of the offending entry.
        index: usize,
    },
    /// A schedule entry used the abstract `TimeInterval` rather than
    /// `RelativeTimeInterval`, so it says nothing about when its limit applies.
    ///
    /// Also a fault in what this station offered.
    ScheduleNotRelative {
        /// Index of the offending entry.
        index: usize,
    },
}

impl ProfileError {
    /// The `ResponseCode` ISO 15118-2 prescribes for this outcome.
    ///
    /// The point of the whole module: `FAILED_ChargingProfileInvalid` and
    /// `FAILED_TariffSelectionInvalid` are values a station could always name
    /// and never knew when to send.
    ///
    /// The three that are the *station's* own fault get
    /// `FAILED_ChargingProfileInvalid` too, because there is no code for "my
    /// schedule was malformed" and the session cannot go on either way — but
    /// [`ProfileError::is_local_fault`] tells them apart, because one of them
    /// belongs in your logs and the other belongs in the vehicle's.
    #[must_use]
    pub const fn response_code(self) -> ResponseCode {
        match self {
            Self::UnknownScheduleTuple { .. } => ResponseCode::FAILEDTariffSelectionInvalid,
            _ => ResponseCode::FAILEDChargingProfileInvalid,
        }
    }

    /// True when the fault is in the schedule this station offered rather than
    /// in the profile the vehicle answered with.
    #[must_use]
    pub const fn is_local_fault(self) -> bool {
        matches!(self, Self::ScheduleOutOfOrder { .. } | Self::ScheduleNotRelative { .. })
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownScheduleTuple { requested } => {
                write!(f, "SAScheduleTupleID {requested} was never offered")
            }
            Self::ExceedsPMax { at, requested, permitted } => write!(
                f,
                "the charging profile asks for {requested} mW at t+{at}s, \
                 where the schedule permits {permitted} mW"
            ),
            Self::NotWatts { unit } => write!(f, "a power was given in {unit:?}, not watts"),
            Self::MultiplierOutOfRange { multiplier } => {
                write!(f, "multiplier {multiplier} is outside the schema's -3..=3")
            }
            Self::ProfileOutOfOrder { index } => {
                write!(f, "charging profile entry {index} does not start after the one before it")
            }
            Self::ScheduleOutOfOrder { index } => {
                write!(f, "offered schedule entry {index} does not start after the one before it")
            }
            Self::ScheduleNotRelative { index } => {
                write!(f, "offered schedule entry {index} has no RelativeTimeInterval")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProfileError {}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::iso2::{
        ChargeProgress, PMaxSchedule, PMaxScheduleEntry, ProfileEntry, RelativeTimeInterval,
    };

    /// `Value * 10 ^ Multiplier [W]`.
    const fn watts(multiplier: i8, value: i16) -> PhysicalValue {
        PhysicalValue { multiplier, unit: UnitSymbol::W, value }
    }

    /// A schedule from `(start, duration, power)` triples.
    fn schedule(id: u8, entries: &[(u32, Option<u32>, PhysicalValue)]) -> SAScheduleTuple {
        SAScheduleTuple {
            sa_schedule_tuple_id: id,
            p_max_schedule: PMaxSchedule {
                p_max_schedule_entry: entries
                    .iter()
                    .map(|(start, duration, p_max)| PMaxScheduleEntry {
                        choice: PMaxScheduleEntryChoice::RelativeTimeInterval(
                            RelativeTimeInterval { start: *start, duration: *duration },
                        ),
                        p_max: p_max.clone(),
                    })
                    .collect(),
            },
            sales_tariff: None,
        }
    }

    /// A profile from `(start, power)` pairs.
    fn profile(entries: &[(u32, PhysicalValue)]) -> ChargingProfile {
        ChargingProfile {
            profile_entry: entries
                .iter()
                .map(|(start, power)| ProfileEntry {
                    charging_profile_entry_start: *start,
                    charging_profile_entry_max_power: power.clone(),
                    charging_profile_entry_max_number_of_phases_in_use: None,
                })
                .collect(),
        }
    }

    #[test]
    fn a_multiplier_is_a_power_of_ten_not_decoration() {
        // The whole point of `PhysicalValueType`: 1100 with multiplier 1 is
        // 11 kW, and reading the value alone would make it 1.1 kW.
        assert_eq!(power_mw(&watts(1, 1100)).unwrap(), 11_000_000);
        assert_eq!(power_mw(&watts(0, 11_000)).unwrap(), 11_000_000);
        assert_eq!(power_mw(&watts(3, 11)).unwrap(), 11_000_000);
        // ...and a negative multiplier is a fraction of a watt, exactly.
        assert_eq!(power_mw(&watts(-3, 1)).unwrap(), 1);
        assert_eq!(power_mw(&watts(-1, 5)).unwrap(), 500);
    }

    #[test]
    fn a_power_that_is_not_a_power_is_refused() {
        let amps = PhysicalValue { multiplier: 0, unit: UnitSymbol::A, value: 32 };
        assert_eq!(power_mw(&amps), Err(ProfileError::NotWatts { unit: UnitSymbol::A }));
        // 32 A and 32 W are the same integer, which is exactly why the unit is
        // checked rather than assumed.
        assert_eq!(power_mw(&watts(0, 32)).unwrap(), 32_000);
    }

    #[test]
    fn a_multiplier_outside_the_facet_is_refused_not_saturated() {
        for bad in [-4i8, 4, i8::MIN, i8::MAX] {
            assert_eq!(
                power_mw(&watts(bad, 1)),
                Err(ProfileError::MultiplierOutOfRange { multiplier: bad })
            );
        }
    }

    #[test]
    fn a_profile_inside_the_schedule_is_accepted() {
        // \[V2G2-224\]: the SECC *shall always accept* one that fits.
        let tuple = schedule(1, &[(0, Some(3600), watts(1, 1100))]);
        assert!(check_profile(&tuple, &profile(&[(0, watts(0, 7400))])).is_ok());
        // Exactly at the limit is inside it — "equal to or smaller" \[V2G2-293\].
        assert!(check_profile(&tuple, &profile(&[(0, watts(1, 1100))])).is_ok());
    }

    #[test]
    fn a_profile_over_the_limit_names_the_instant_it_goes_over() {
        // 11 kW until t+1800, then 3.7 kW.
        let tuple = schedule(1, &[(0, None, watts(1, 1100)), (1800, Some(1800), watts(0, 3700))]);
        // The vehicle asks for 7.4 kW throughout: fine at first, not after 1800.
        let err = check_profile(&tuple, &profile(&[(0, watts(0, 7400))])).unwrap_err();
        assert_eq!(
            err,
            ProfileError::ExceedsPMax { at: 1800, requested: 7_400_000, permitted: 3_700_000 }
        );
        assert_eq!(err.response_code(), ResponseCode::FAILEDChargingProfileInvalid);
        assert!(!err.is_local_fault());

        // Dropping to 3.7 kW in time is accepted.
        assert!(
            check_profile(&tuple, &profile(&[(0, watts(0, 7400)), (1800, watts(0, 3700))])).is_ok()
        );
    }

    #[test]
    fn a_start_is_also_the_stop_of_the_interval_before_it() {
        // \[V2G2-329\]. The first entry is 11 kW and ends at 300, not at 3600.
        let tuple = schedule(1, &[(0, None, watts(1, 1100)), (300, Some(300), watts(0, 1000))]);
        assert_eq!(pmax_at(&tuple, 0).unwrap(), Some(11_000_000));
        assert_eq!(pmax_at(&tuple, 299).unwrap(), Some(11_000_000));
        assert_eq!(pmax_at(&tuple, 300).unwrap(), Some(1_000_000));
        assert_eq!(pmax_at(&tuple, 599).unwrap(), Some(1_000_000));
        // ...and past the last interval's duration the schedule states nothing.
        assert_eq!(pmax_at(&tuple, 600).unwrap(), None);
        assert_eq!(coverage(&tuple), Some(600));
    }

    #[test]
    fn a_schedule_with_no_duration_states_no_end() {
        // \[V2G2-331\] makes `duration` optional; without it the last limit
        // stands until something replaces it.
        let tuple = schedule(1, &[(0, None, watts(1, 1100))]);
        assert_eq!(coverage(&tuple), None);
        assert_eq!(pmax_at(&tuple, u32::MAX).unwrap(), Some(11_000_000));
    }

    #[test]
    fn nothing_is_exceeded_where_the_schedule_says_nothing() {
        // The profile's last entry runs on indefinitely \[V2G2-291\] and the
        // schedule's coverage ends, so this is the ordinary case rather than an
        // exotic one. \[V2G2-225\] makes a profile invalid for exceeding a
        // `PMax`; where there is none there is nothing to exceed, and ISO
        // 15118-2 handles it by having the vehicle ask for a new schedule.
        let tuple = schedule(1, &[(0, Some(600), watts(0, 3700))]);
        assert!(
            check_profile(&tuple, &profile(&[(0, watts(0, 3700)), (600, watts(1, 2000))])).is_ok()
        );
        // ...but inside the coverage the limit still bites.
        assert!(
            check_profile(&tuple, &profile(&[(0, watts(0, 3700)), (599, watts(1, 2000))])).is_err()
        );
    }

    #[test]
    fn a_tuple_id_that_was_never_offered_is_a_tariff_selection_failure() {
        // \[V2G2-286\], \[V2G2-479\] — a different code from the profile one.
        let offered =
            SAScheduleList { sa_schedule_tuple: vec![schedule(1, &[(0, None, watts(1, 1100))])] };
        let req = PowerDeliveryReq {
            charge_progress: ChargeProgress::Start,
            sa_schedule_tuple_id: 7,
            charging_profile: Some(profile(&[(0, watts(0, 100))])),
            choice: None,
        };
        let err = check_power_delivery(&offered, &req).unwrap_err();
        assert_eq!(err, ProfileError::UnknownScheduleTuple { requested: 7 });
        assert_eq!(err.response_code(), ResponseCode::FAILEDTariffSelectionInvalid);
    }

    #[test]
    fn the_right_tuple_of_several_is_the_one_checked() {
        let offered = SAScheduleList {
            sa_schedule_tuple: vec![
                schedule(1, &[(0, None, watts(0, 3700))]),
                schedule(2, &[(0, None, watts(1, 2200))]),
            ],
        };
        let mut req = PowerDeliveryReq {
            charge_progress: ChargeProgress::Start,
            sa_schedule_tuple_id: 2,
            charging_profile: Some(profile(&[(0, watts(1, 1100))])),
            choice: None,
        };
        assert!(check_power_delivery(&offered, &req).is_ok(), "11 kW fits tuple 2's 22 kW");
        req.sa_schedule_tuple_id = 1;
        assert!(check_power_delivery(&offered, &req).is_err(), "...and not tuple 1's 3.7 kW");
    }

    #[test]
    fn no_profile_at_all_is_not_a_profile_that_exceeds_anything() {
        let offered =
            SAScheduleList { sa_schedule_tuple: vec![schedule(1, &[(0, None, watts(0, 0))])] };
        let req = PowerDeliveryReq {
            charge_progress: ChargeProgress::Stop,
            sa_schedule_tuple_id: 1,
            charging_profile: None,
            choice: None,
        };
        assert!(check_power_delivery(&offered, &req).is_ok());
    }

    #[test]
    fn an_out_of_order_list_describes_no_interval_at_all() {
        let tuple = schedule(1, &[(0, None, watts(0, 100))]);
        assert_eq!(
            check_profile(&tuple, &profile(&[(600, watts(0, 10)), (300, watts(0, 10))])),
            Err(ProfileError::ProfileOutOfOrder { index: 1 })
        );
        // A repeat is out of order too: it would be an interval of zero length
        // whose limit silently replaced its neighbour's.
        assert_eq!(
            check_profile(&tuple, &profile(&[(300, watts(0, 10)), (300, watts(0, 10))])),
            Err(ProfileError::ProfileOutOfOrder { index: 1 })
        );
    }

    #[test]
    fn a_malformed_offer_is_this_station_s_own_fault_and_says_so() {
        let backwards = schedule(1, &[(600, None, watts(0, 10)), (0, None, watts(0, 10))]);
        let err = check_profile(&backwards, &profile(&[(0, watts(0, 1))])).unwrap_err();
        assert_eq!(err, ProfileError::ScheduleOutOfOrder { index: 1 });
        assert!(err.is_local_fault(), "the vehicle did nothing wrong here");

        // An entry with the abstract `TimeInterval` carries no time at all.
        let abstract_interval = SAScheduleTuple {
            sa_schedule_tuple_id: 1,
            p_max_schedule: PMaxSchedule {
                p_max_schedule_entry: vec![PMaxScheduleEntry {
                    choice: PMaxScheduleEntryChoice::TimeInterval(crate::iso2::Interval),
                    p_max: watts(0, 100),
                }],
            },
            sales_tariff: None,
        };
        let err = check_profile(&abstract_interval, &profile(&[(0, watts(0, 1))])).unwrap_err();
        assert_eq!(err, ProfileError::ScheduleNotRelative { index: 0 });
        assert!(err.is_local_fault());
    }

    #[test]
    fn a_later_profile_entry_is_checked_against_an_earlier_schedule_entry_it_overlaps() {
        // The two step functions do not share breakpoints, which is the case
        // the arithmetic exists for: the profile steps up at 100, inside the
        // schedule's first interval, and must be caught there and not at 300.
        let tuple = schedule(1, &[(0, None, watts(0, 1000)), (300, Some(300), watts(1, 1100))]);
        let err = check_profile(&tuple, &profile(&[(0, watts(0, 500)), (100, watts(0, 5000))]))
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::ExceedsPMax { at: 100, requested: 5_000_000, permitted: 1_000_000 }
        );
    }
}
