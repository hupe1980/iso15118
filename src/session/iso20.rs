//! ISO 15118-20 message sequencing.
//!
//! The -20 flow is longer than -2's and reordered: authorization moves to the
//! front, service selection follows it rather than preceding it, and schedule
//! exchange becomes a phase of its own. Charging itself collapses into a single
//! `ChargeLoop` message per energy transfer mode, with the mode chosen at
//! service selection rather than inferred from a transfer-mode enumeration.
//!
//! Each of the four energy transfer services — AC, DC, WPT, ACDP — is a
//! separate schema with its own V2GTP payload type, but they share this one
//! flow; only which parameter-discovery and charge-loop messages are legal
//! differs.
//!
//! Same contract as [`super::iso2`]: no I/O, no timers, no policy, just the
//! graph and the response code a departure from it earns.
//!
//! ```
//! use iso15118::session::iso20::{Request, Sequencer, Service};
//!
//! let mut s = Sequencer::new();
//! s.accept(Request::SessionSetup)?;
//! s.accept(Request::AuthorizationSetup)?;
//! s.accept(Request::Authorization)?;
//! s.accept(Request::ServiceDiscovery)?;
//! s.accept(Request::ServiceSelection(Service::Dc))?;
//!
//! // Authorization comes first in -20, unlike -2 where it follows selection.
//! assert!(!s.permits(Request::Authorization));
//! # Ok::<_, iso15118::session::SequenceError>(())
//! ```

use crate::iso20::common::ResponseCode;
use crate::iso20::messages::{ChargeProgress, ChargingSession};

use super::SequenceError;

/// The energy transfer service a -20 session selected.
///
/// It decides which parameter-discovery and charge-loop messages exist for the
/// rest of the session, and whether the DC-only phases run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Service {
    /// AC charging, `V2G_CI_AC.xsd`, V2GTP payload type `0x8003`.
    Ac,
    /// DC charging, `V2G_CI_DC.xsd`, V2GTP payload type `0x8004`.
    Dc,
    /// Wireless power transfer, `V2G_CI_WPT.xsd`, payload type `0x8006`.
    Wpt,
    /// Automated connection device (pantograph), `V2G_CI_ACDP.xsd`, payload
    /// type `0x8005`.
    Acdp,
}

impl Service {
    /// The V2GTP payload type this service's messages travel under.
    #[must_use]
    pub const fn payload_type(self) -> crate::v2gtp::PayloadType {
        use crate::v2gtp::PayloadType as T;
        match self {
            Self::Ac => T::Part20Ac,
            Self::Dc => T::Part20Dc,
            Self::Wpt => T::Part20Wpt,
            Self::Acdp => T::Part20Acdp,
        }
    }

    /// True for the services that need an isolation check and a pre-charge
    /// before power flows, and a weld check afterwards.
    #[must_use]
    pub const fn is_dc(self) -> bool {
        matches!(self, Self::Dc)
    }
}

/// A -20 request, reduced to what sequencing depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Request {
    /// `SessionSetupReq`.
    SessionSetup,
    /// `AuthorizationSetupReq`.
    AuthorizationSetup,
    /// `AuthorizationReq`.
    Authorization,
    /// `ServiceDiscoveryReq`.
    ServiceDiscovery,
    /// `ServiceDetailReq`.
    ServiceDetail,
    /// `ServiceSelectionReq`. The chosen service decides the rest of the flow.
    ServiceSelection(Service),
    /// `CertificateInstallationReq`.
    CertificateInstallation,
    /// `AC_/DC_/WPT_/ACDP_ChargeParameterDiscoveryReq`.
    ChargeParameterDiscovery,
    /// `ScheduleExchangeReq`.
    ScheduleExchange,
    /// `DC_CableCheckReq`.
    CableCheck,
    /// `DC_PreChargeReq`.
    PreCharge,
    /// `PowerDeliveryReq`. Unlike -2, `ChargeProgress` here has four values:
    /// `Standby` suspends the loop without ending the session, and
    /// `ScheduleRenegotiation` returns to parameter discovery.
    PowerDelivery(ChargeProgress),
    /// `AC_/DC_/WPT_ChargeLoopReq`.
    ChargeLoop,
    /// `MeteringConfirmationReq`.
    MeteringConfirmation,
    /// `DC_WeldingDetectionReq`.
    WeldingDetection,
    /// `SessionStopReq`. `ChargingSession` decides what "stop" means:
    /// `Terminate` ends the session, `Pause` suspends it for a later resume
    /// under the same session id, and `ServiceRenegotiation` does not end it at
    /// all — it returns the flow to service discovery.
    SessionStop(ChargingSession),
    /// `VehicleCheckInReq` (ACDP).
    VehicleCheckIn,
    /// `VehicleCheckOutReq` (ACDP).
    VehicleCheckOut,
    /// An ACDP positioning or connection message: `ACDP_VehiclePositioningReq`,
    /// `ACDP_ConnectReq`, `ACDP_DisconnectReq`, `ACDP_SystemStatusReq`.
    AcdpControl,
    /// A WPT positioning message: `WPT_FinePositioningSetupReq`,
    /// `WPT_FinePositioningReq`, `WPT_PairingReq`, `WPT_AlignmentCheckReq`.
    WptPositioning,
}

impl Request {
    /// The element name, for logs and errors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SessionSetup => "SessionSetupReq",
            Self::AuthorizationSetup => "AuthorizationSetupReq",
            Self::Authorization => "AuthorizationReq",
            Self::ServiceDiscovery => "ServiceDiscoveryReq",
            Self::ServiceDetail => "ServiceDetailReq",
            Self::ServiceSelection(_) => "ServiceSelectionReq",
            Self::CertificateInstallation => "CertificateInstallationReq",
            Self::ChargeParameterDiscovery => "ChargeParameterDiscoveryReq",
            Self::ScheduleExchange => "ScheduleExchangeReq",
            Self::CableCheck => "DC_CableCheckReq",
            Self::PreCharge => "DC_PreChargeReq",
            Self::PowerDelivery(_) => "PowerDeliveryReq",
            Self::ChargeLoop => "ChargeLoopReq",
            Self::MeteringConfirmation => "MeteringConfirmationReq",
            Self::WeldingDetection => "DC_WeldingDetectionReq",
            Self::SessionStop(_) => "SessionStopReq",
            Self::VehicleCheckIn => "VehicleCheckInReq",
            Self::VehicleCheckOut => "VehicleCheckOutReq",
            Self::AcdpControl => "ACDP control message",
            Self::WptPositioning => "WPT positioning message",
        }
    }

    /// Classifies a decoded message for sequencing.
    ///
    /// `None` for a response, and for the two `CommonMessages` elements that
    /// are signed payloads rather than messages (`SignedInstallationData`,
    /// `SignedMeteringData`).
    #[must_use]
    pub fn of(message: &crate::message::Message) -> Option<Self> {
        use crate::message::Message as M;
        match message {
            M::Iso20(doc) => Self::of_common(doc),
            #[cfg(feature = "iso20-ac")]
            M::Iso20Ac(doc) => Self::of_ac(doc),
            #[cfg(feature = "iso20-dc")]
            M::Iso20Dc(doc) => Self::of_dc(doc),
            #[cfg(feature = "iso20-wpt")]
            M::Iso20Wpt(doc) => Self::of_wpt(doc),
            #[cfg(feature = "iso20-acdp")]
            M::Iso20Acdp(doc) => Self::of_acdp(doc),
            _ => None,
        }
    }

    fn of_common(doc: &crate::iso20::messages::Document) -> Option<Self> {
        use crate::iso20::messages::Document as D;
        Some(match doc {
            D::SessionSetupReq(_) => Self::SessionSetup,
            D::AuthorizationSetupReq(_) => Self::AuthorizationSetup,
            D::AuthorizationReq(_) => Self::Authorization,
            D::CertificateInstallationReq(_) => Self::CertificateInstallation,
            D::ServiceDiscoveryReq(_) => Self::ServiceDiscovery,
            D::ServiceDetailReq(_) => Self::ServiceDetail,
            D::ServiceSelectionReq(req) => Self::ServiceSelection(Service::of(req)?),
            D::ScheduleExchangeReq(_) => Self::ScheduleExchange,
            D::PowerDeliveryReq(req) => Self::PowerDelivery(req.charge_progress),
            D::MeteringConfirmationReq(_) => Self::MeteringConfirmation,
            D::SessionStopReq(req) => Self::SessionStop(req.charging_session),
            D::VehicleCheckInReq(_) => Self::VehicleCheckIn,
            D::VehicleCheckOutReq(_) => Self::VehicleCheckOut,
            _ => return None,
        })
    }

    #[cfg(feature = "iso20-ac")]
    fn of_ac(doc: &crate::iso20::ac::Document) -> Option<Self> {
        use crate::iso20::ac::Document as D;
        Some(match doc {
            D::ACChargeParameterDiscoveryReq(_) => Self::ChargeParameterDiscovery,
            D::ACChargeLoopReq(_) => Self::ChargeLoop,
            _ => return None,
        })
    }

    #[cfg(feature = "iso20-dc")]
    fn of_dc(doc: &crate::iso20::dc::Document) -> Option<Self> {
        use crate::iso20::dc::Document as D;
        Some(match doc {
            D::DCChargeParameterDiscoveryReq(_) => Self::ChargeParameterDiscovery,
            D::DCCableCheckReq(_) => Self::CableCheck,
            D::DCPreChargeReq(_) => Self::PreCharge,
            D::DCChargeLoopReq(_) => Self::ChargeLoop,
            D::DCWeldingDetectionReq(_) => Self::WeldingDetection,
            _ => return None,
        })
    }

    #[cfg(feature = "iso20-wpt")]
    fn of_wpt(doc: &crate::iso20::wpt::Document) -> Option<Self> {
        use crate::iso20::wpt::Document as D;
        Some(match doc {
            D::WPTChargeParameterDiscoveryReq(_) => Self::ChargeParameterDiscovery,
            D::WPTChargeLoopReq(_) => Self::ChargeLoop,
            D::WPTFinePositioningSetupReq(_)
            | D::WPTFinePositioningReq(_)
            | D::WPTPairingReq(_)
            | D::WPTAlignmentCheckReq(_) => Self::WptPositioning,
            _ => return None,
        })
    }

    /// The response timeout to arm after sending this request.
    ///
    /// ISO 15118-20 has its own timing table (§8.5) and this crate does not
    /// have that text — the standard is a paid document — so these are the
    /// ISO 15118-2 Table 105 values mapped onto the -20 messages **by role**,
    /// which is a judgement and is stated as one.
    ///
    /// The judgement that matters is the charge loop: it runs at tens of
    /// milliseconds, exactly as -2's `CurrentDemand` does, and giving it the
    /// two-second default would mean a vehicle that does not notice a stalled
    /// loop for two seconds. [`EvccConfig::message_timeout`] overrides all of
    /// this for a caller that has the table.
    ///
    /// [`EvccConfig::message_timeout`]: crate::evcc::EvccConfig::message_timeout
    #[must_use]
    pub const fn response_timeout(self) -> super::Millis {
        use super::timers::iso2 as t;
        match self {
            // The charge loop is a control loop, not a request/response.
            Self::ChargeLoop => t::MSG_TIMEOUT_CURRENT_DEMAND,
            // These reach a backend — a contract certificate pool, a tariff
            // service, a clearing house — so they get the longer budget.
            Self::Authorization
            | Self::AuthorizationSetup
            | Self::CertificateInstallation
            | Self::ServiceDetail
            | Self::ScheduleExchange
            | Self::PowerDelivery(_)
            | Self::MeteringConfirmation => t::MSG_TIMEOUT_BACKEND,
            _ => t::MSG_TIMEOUT_DEFAULT,
        }
    }

    /// The station's own budget for answering this request.
    ///
    /// The other half of the pair [`Request::response_timeout`] gives, and —
    /// like it — carried over from ISO 15118-2's Table 109 rather than quoted
    /// from -20's §8.5, which this project does not have. See
    /// [`timers::iso20`](super::timers::iso20).
    ///
    /// Nothing enforces it; [`Secc::response_due`] surfaces it so a station can.
    ///
    /// [`Secc::response_due`]: crate::secc::Secc::response_due
    #[must_use]
    pub const fn performance_time(self) -> super::Millis {
        use super::timers::iso2 as t;
        match self {
            Self::ChargeLoop => t::SECC_MSG_PERFORMANCE_CURRENT_DEMAND,
            Self::Authorization
            | Self::AuthorizationSetup
            | Self::CertificateInstallation
            | Self::ServiceDetail
            | Self::ScheduleExchange
            | Self::PowerDelivery(_)
            | Self::MeteringConfirmation => t::SECC_MSG_PERFORMANCE_BACKEND,
            _ => t::SECC_MSG_PERFORMANCE_DEFAULT,
        }
    }

    #[cfg(feature = "iso20-acdp")]
    fn of_acdp(doc: &crate::iso20::acdp::Document) -> Option<Self> {
        use crate::iso20::acdp::Document as D;
        Some(match doc {
            D::ACDPVehiclePositioningReq(_)
            | D::ACDPConnectReq(_)
            | D::ACDPDisconnectReq(_)
            | D::ACDPSystemStatusReq(_) => Self::AcdpControl,
            _ => return None,
        })
    }
}

impl Service {
    /// Reads the selected energy transfer service out of a
    /// `ServiceSelectionReq`.
    ///
    /// `None` when the id is not one of the energy transfer services — see
    /// [`Service::from_service_id`].
    #[must_use]
    pub fn of(req: &crate::iso20::messages::ServiceSelectionReq) -> Option<Self> {
        Self::from_service_id(req.selected_energy_transfer_service.service_id)
    }

    /// Maps an ISO 15118-20 service id to the flow it selects.
    ///
    /// The assignment is the standard's own — the same numbers `EVerest`'s
    /// `ServiceCategory` and Josev's `ServiceV20` both use:
    ///
    /// | Id | Service | Maps to |
    /// |---|---|---|
    /// | 1 | `AC` | [`Service::Ac`] |
    /// | 2 | `DC` | [`Service::Dc`] |
    /// | 3 | `WPT` | [`Service::Wpt`] |
    /// | 4 | `DC_ACDP` | [`Service::Acdp`] |
    /// | 5 | `AC_BPT` | [`Service::Ac`] |
    /// | 6 | `DC_BPT` | [`Service::Dc`] |
    /// | 7 | `DC_ACDP_BPT` | [`Service::Acdp`] |
    /// | 8, 9 | `MCS`, `MCS_BPT` | `None` — no schema set here |
    /// | 10 | `AC_DER` | `None` — no schema set here |
    /// | 65, 66 | `Internet`, `ParkingStatus` | `None` — value-added |
    ///
    /// The `_BPT` variants are bidirectional power transfer. Power flowing the
    /// other way changes the parameters, not the message flow, so each maps to
    /// the same [`Service`] as its unidirectional twin — which is also why
    /// there is no `iso20-bpt` feature.
    ///
    /// `None` means "not an energy transfer service this crate has a message set
    /// for", and it covers two different situations. 65 and 66 are *value-added*
    /// services: a session may select one alongside an energy transfer service,
    /// and it changes no part of the flow. 8, 9 and 10 — the megawatt charging
    /// system and the AC distributed-energy-resource service — are energy
    /// transfer services whose schemas are not in this crate, so a session that
    /// selects one has no flow here to follow. Both come back as `None`, and the
    /// sequencer refuses whatever follows either way.
    #[must_use]
    pub const fn from_service_id(id: u16) -> Option<Self> {
        Some(match id {
            1 | 5 => Self::Ac,
            2 | 6 => Self::Dc,
            3 => Self::Wpt,
            4 | 7 => Self::Acdp,
            _ => return None,
        })
    }
}

/// Where an ISO 15118-20 session has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Phase {
    /// Nothing has arrived yet.
    Start,
    /// A session exists.
    SessionSetup,
    /// The authorization methods on offer have been stated.
    AuthorizationSetup,
    /// The EVCC is authorized (or still being authorized).
    Authorized,
    /// Services have been listed.
    ServiceDiscovery,
    /// A service has been selected.
    ServiceSelected,
    /// Charge parameters have been exchanged.
    ChargeParameters,
    /// A schedule has been agreed.
    ScheduleExchanged,
    /// DC: the cable is being checked for isolation faults.
    CableCheck,
    /// DC: the link voltage is being matched to the battery.
    PreCharge,
    /// Power is flowing.
    Charging,
    /// The session is up but suspended — `ChargeProgress = Standby`.
    Standby,
    /// Power has stopped.
    PowerStopped,
    /// DC: checking the contactors did not weld shut.
    WeldingDetection,
    /// The session is suspended and may be resumed later under the same
    /// session id — `SessionStopReq` with `ChargingSession = Pause`.
    Paused,
    /// The session is over.
    Stopped,
}

impl Phase {
    /// How long a session may stay in this phase before the peer gives up.
    ///
    /// Several -20 phases are *loops*: the SECC answers `..._Ongoing` and the
    /// EVCC repeats the same request until it does not. Each such loop has a
    /// bound of its own, separate from the per-message response timeout, and
    /// missing it is how a vehicle sits waiting for a decision that will never
    /// come.
    ///
    /// None of these budgets is quoted from ISO 15118-20 — its timing table is
    /// a paid document this project does not have — so all of them are
    /// judgements, and are stated as such in [`timers::iso20`]. Authorization
    /// gets the long one because the sequencer does not know whether the
    /// session chose EIM or a contract, and cutting an EIM authorization short
    /// would refuse a driver who was still reaching for their phone. The DC
    /// safety phases take -2's budgets, which *are* quoted: the physics of an
    /// isolation test did not change between the two generations.
    ///
    /// [`timers::iso20`]: super::timers::iso20
    ///
    /// `None` for the phases that are not loops, and for `Charging` — a charge
    /// loop runs as long as the vehicle wants it to.
    ///
    /// `role` picks which half of the pair applies, for the reason
    /// [`Role`](super::Role) gives: the station's budget is deliberately the
    /// shorter one, so that a phase which stalls ends with a `FAILED` the
    /// vehicle can read rather than with the vehicle's own timer running out.
    #[must_use]
    pub const fn loop_timeout(self, role: super::Role) -> Option<super::Millis> {
        use super::Role;
        use super::timers::{iso2 as t2, iso20 as t};
        Some(match (self, role) {
            (Self::Authorized, Role::Evcc) => t::EIM_ONGOING_TIMEOUT,
            (Self::Authorized, Role::Secc) => t::SECC_EIM_ONGOING_PERFORMANCE_TIME,
            (
                Self::ChargeParameters | Self::ScheduleExchanged | Self::WeldingDetection,
                Role::Evcc,
            ) => t::ONGOING_TIMEOUT,
            (
                Self::ChargeParameters | Self::ScheduleExchanged | Self::WeldingDetection,
                Role::Secc,
            ) => t::SECC_ONGOING_PERFORMANCE_TIME,
            (Self::CableCheck, Role::Evcc) => t2::EVCC_CABLE_CHECK_TIMEOUT,
            (Self::CableCheck, Role::Secc) => t2::SECC_CABLE_CHECK_PERFORMANCE_TIME,
            (Self::PreCharge, Role::Evcc) => t2::EVCC_PRE_CHARGE_TIMEOUT,
            (Self::PreCharge, Role::Secc) => t2::SECC_PRE_CHARGE_PERFORMANCE_TIME,
            _ => return None,
        })
    }
}

/// Tracks an ISO 15118-20 session's position in the message flow.
///
/// As in [`super::iso2`], it holds no buffers and no keys, so a snapshot is
/// cheap to take and — with the `serde` feature — to store and read back. -20
/// is the generation where that matters most: a paused session keeps its
/// authorization, its selected service and its agreed schedule, and those have
/// to survive whatever the station does in between.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Sequencer {
    phase: Phase,
    service: Option<Service>,
    /// Set by a `PowerDeliveryReq(ScheduleRenegotiation)`: the DC safety phases
    /// are behind us and must not be demanded again.
    renegotiated: bool,
    /// Set once a `FAILED_*` response has gone past, after which the only
    /// request left is `SessionStopReq`.
    failed: bool,
}

impl Default for Sequencer {
    fn default() -> Self {
        Self::new()
    }
}

impl Sequencer {
    /// A session that has not yet seen its first request.
    #[must_use]
    pub const fn new() -> Self {
        Self { phase: Phase::Start, service: None, renegotiated: false, failed: false }
    }

    /// Picks up a paused session, from just after `SessionSetup`.
    ///
    /// ISO 15118-20 lets a session paused with `ChargingSession = Pause` be
    /// resumed under the same session id, in which case authorization and
    /// service selection survived the pause and the flow restarts at parameter
    /// discovery. Whether an arriving session id names a resumable session is
    /// stored state the core does not hold, so the application decides and
    /// calls this while answering `SessionSetupReq` with `OK_OldSessionJoined`.
    pub const fn resume(&mut self, service: Service) {
        self.service = Some(service);
        self.phase = Phase::ServiceSelected;
        self.renegotiated = false;
    }

    /// Records that a `FAILED_*` response has gone past.
    ///
    /// ISO 15118 leaves no discretion after a failure: the session ends, and
    /// the only request the peer may still send is `SessionStopReq`
    /// \[V2G20-1502\]. Calling this is what stops a peer from carrying on
    /// down the flow as though the failure had not happened — the class of bug
    /// `EVerest`'s `GHSA-9vv5-67cv-9crq` describes.
    pub const fn failed(&mut self) {
        self.failed = true;
    }

    /// True once a failure response has ended the session's forward progress.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        self.failed
    }

    /// Where the session is.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// The selected service, once `ServiceSelection` has said.
    #[must_use]
    pub const fn service(&self) -> Option<Service> {
        self.service
    }

    /// True once the vehicle has asked to renegotiate its schedule.
    ///
    /// The second pass through schedule exchange is not the first: the charger
    /// is revising a schedule it has already committed to, and for DC the
    /// contactors never opened — which is why the safety phases do not repeat.
    #[must_use]
    pub const fn has_renegotiated(&self) -> bool {
        self.renegotiated
    }

    /// True when the session is over and no further request is legal.
    ///
    /// Both a terminated and a paused session are finished; they differ in
    /// whether the state may be picked up again, which is
    /// [`Sequencer::is_paused`].
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self.phase, Phase::Stopped | Phase::Paused)
    }

    /// True when the session was *paused* rather than terminated.
    ///
    /// The difference is what the station keeps: a paused session's schedule,
    /// authorization and selected service survive, and the vehicle may resume
    /// it under the same session id.
    #[must_use]
    pub const fn is_paused(&self) -> bool {
        matches!(self.phase, Phase::Paused)
    }

    /// Records that `request` arrived, advancing the session.
    ///
    /// See [`super::iso2::Sequencer::accept`] — same contract, different graph.
    pub fn accept(&mut self, request: Request) -> Result<Phase, SequenceError> {
        let Some(next) = self.next_phase(request) else {
            return Err(self.refusal(request));
        };
        // Coming *back* to parameter discovery from a charge that has already
        // started is a renegotiation: the DC safety phases are behind us and
        // the cable is live, so they must not be demanded again. Keyed on the
        // transition rather than on the request, as in `super::iso2`.
        if next == Phase::ChargeParameters
            && matches!(self.phase, Phase::Charging | Phase::Standby | Phase::PowerStopped)
        {
            self.renegotiated = true;
        }
        // Record the facts the rest of the graph branches on before moving.
        match request {
            Request::ServiceSelection(service) => self.service = Some(service),
            // A *service* renegotiation unwinds the session to just after
            // authorization, and the two facts the DC branch depends on unwind
            // with it. Leaving `renegotiated` set would let the next service —
            // a DC one this time — go straight to `PowerDelivery(Start)`
            // without an isolation test, on the strength of a renegotiation
            // that happened under a different service and whose contactors are
            // now open. Leaving `service` set would keep answering "DC" about a
            // service nobody has selected yet.
            Request::SessionStop(ChargingSession::ServiceRenegotiation) => {
                self.service = None;
                self.renegotiated = false;
            }
            _ => {}
        }
        self.phase = next;
        Ok(next)
    }

    /// True when `request` would be accepted right now.
    #[must_use]
    pub fn permits(&self, request: Request) -> bool {
        self.next_phase(request).is_some()
    }

    /// The refusal `request` would earn right now, whether or not it would
    /// actually be refused.
    ///
    /// The response code and the two names in one place, so that a caller
    /// checking with [`Sequencer::permits`] reports the same thing
    /// [`Sequencer::accept`] would have.
    #[must_use]
    pub const fn refusal(&self, request: Request) -> SequenceError {
        SequenceError {
            got: request.name(),
            phase: self.phase_name(),
            response_code: ResponseCode::FAILEDSequenceError as u8,
        }
    }

    /// The whole of the ISO 15118-20 flow, as one table.
    #[allow(
        clippy::match_same_arms,
        reason = "one arm per ordering rule; merging them by target phase would \
                  hide which rule is which"
    )]
    fn next_phase(&self, request: Request) -> Option<Phase> {
        use ChargeProgress as P;
        use Phase as F;
        use Request as R;

        use ChargingSession as S;

        let dc = self.service.is_some_and(Service::is_dc);
        let acdp = self.service == Some(Service::Acdp);
        let wpt = self.service == Some(Service::Wpt);

        // After a `FAILED_*` response the session is over bar the formalities:
        // the peer may stop it and nothing else. Renegotiating a service it was
        // just refused is not stopping it.
        if self.failed {
            return match (self.phase, request) {
                (F::Start | F::Stopped | F::Paused, _) => None,
                (_, R::SessionStop(S::Terminate)) => Some(F::Stopped),
                // A failure does not make a live cable safe to walk away from,
                // so the pause rule below applies here too.
                (F::CableCheck | F::PreCharge | F::Charging, R::SessionStop(S::Pause)) => None,
                (_, R::SessionStop(S::Pause)) => Some(F::Paused),
                _ => None,
            };
        }

        Some(match (self.phase, request) {
            (F::Start, R::SessionSetup) => F::SessionSetup,

            (F::SessionSetup, R::AuthorizationSetup) => F::AuthorizationSetup,
            // The contract certificate is installed between learning which
            // methods the SECC offers and using one.
            (F::AuthorizationSetup, R::CertificateInstallation) => F::AuthorizationSetup,
            (F::AuthorizationSetup, R::Authorization) => F::Authorized,
            // Authorization repeats while the SECC answers `..._Ongoing`.
            (F::Authorized, R::Authorization) => F::Authorized,
            (F::Authorized, R::ServiceDiscovery) => F::ServiceDiscovery,

            // `ServiceDetail` is optional and repeatable.
            (F::ServiceDiscovery, R::ServiceDetail) => F::ServiceDiscovery,
            (F::ServiceDiscovery, R::ServiceSelection(_)) => F::ServiceSelected,

            // The pantograph parks and lowers itself, and the wireless coupler
            // aligns itself, before any power is discussed. The order *within*
            // each of those exchanges is left to the peers: the standard
            // constrains it, and this crate does not have that text, so it
            // enforces only that they belong here.
            (F::ServiceSelected, R::VehicleCheckIn | R::AcdpControl) if acdp => F::ServiceSelected,
            (F::ServiceSelected, R::WptPositioning) if wpt => F::ServiceSelected,
            (F::ServiceSelected, R::ChargeParameterDiscovery) => F::ChargeParameters,
            (F::ChargeParameters, R::ChargeParameterDiscovery) => F::ChargeParameters,
            (F::ChargeParameters, R::ScheduleExchange) => F::ScheduleExchanged,
            // Schedule exchange repeats while the SECC answers `..._Ongoing`.
            (F::ScheduleExchanged, R::ScheduleExchange) => F::ScheduleExchanged,

            (F::ScheduleExchanged, R::CableCheck) if dc => F::CableCheck,
            // As in -2: DC runs the isolation test and the pre-charge once, on
            // the way up. A schedule renegotiation comes back through here with
            // power still flowing and the contactors still closed, so demanding
            // them again would strand every DC vehicle that renegotiates.
            (F::ScheduleExchanged, R::PowerDelivery(P::Start)) if !dc || self.renegotiated => {
                F::Charging
            }
            (F::CableCheck, R::CableCheck) => F::CableCheck,
            (F::CableCheck, R::PreCharge) => F::PreCharge,
            (F::PreCharge, R::PreCharge) => F::PreCharge,
            (F::PreCharge, R::PowerDelivery(P::Start)) => F::Charging,

            (F::Charging, R::ChargeLoop) => F::Charging,
            (F::Charging, R::MeteringConfirmation) => F::Charging,
            // A *schedule* renegotiation is not a *service* renegotiation. It
            // returns to parameter discovery, where another
            // `ChargeParameterDiscoveryReq` is optional and a fresh
            // `ScheduleExchangeReq` is the point of the exercise; the selected
            // service, the authorization and the power flow all stand. Sending
            // it back to service selection would re-open a negotiation nobody
            // asked to re-open — that is what `SessionStopReq` with
            // `ChargingSession = ServiceRenegotiation` is for, below.
            // Standby suspends the loop without giving up the session.
            (F::Charging, R::PowerDelivery(P::ScheduleRenegotiation)) => F::ChargeParameters,
            (F::Charging, R::PowerDelivery(P::Standby)) => F::Standby,
            (F::Standby, R::PowerDelivery(P::Start)) => F::Charging,
            (F::Standby, R::PowerDelivery(P::Stop)) => F::PowerStopped,
            (F::Charging, R::PowerDelivery(P::Stop)) => F::PowerStopped,

            (F::PowerStopped, R::WeldingDetection) if dc => F::WeldingDetection,
            (F::WeldingDetection, R::WeldingDetection) => F::WeldingDetection,
            (F::PowerStopped, R::VehicleCheckOut) if acdp => F::PowerStopped,
            (F::PowerStopped, R::AcdpControl) if acdp => F::PowerStopped,

            // `SessionStopReq` is legal from any established phase, not only
            // at the end of a completed charge. A vehicle aborts — a fault, a
            // driver unplugging, a response it did not like — and the defined
            // reaction is to stop the session rather than to sit until the
            // sequence timer runs out. `Start` is the exception: there is no
            // session to stop before `SessionSetupReq`.
            (F::Start | F::Stopped | F::Paused, R::SessionStop(_)) => return None,
            (_, R::SessionStop(S::Terminate)) => F::Stopped,
            // Pausing is not that same freedom. A pause takes the transport
            // connection down and expects to be resumed later, so one accepted
            // while the cable is live would end the conversation with the
            // contactors closed and the link still at battery voltage. -2 says
            // so outright — §8.4.1 permits a pause only after
            // `PowerDeliveryReq(Stop)` — and the physics did not change between
            // the generations. `Standby` is already power-down and does
            // qualify.
            (F::CableCheck | F::PreCharge | F::Charging, R::SessionStop(S::Pause)) => return None,
            (_, R::SessionStop(S::Pause)) => F::Paused,
            // `ServiceRenegotiation` is a "stop" that does not stop anything:
            // the session keeps its authorization and returns to service
            // discovery to pick a different one. A station that does not
            // support it answers `FAILED_NoServiceRenegotiationSupported`,
            // which ends the session by the failure rule above.
            //
            // It needs a service to renegotiate, and insisting on that is not
            // pedantry — it is the difference between a shortcut and an
            // authorization bypass. The phase it lands in is the one from which
            // `ServiceDiscoveryReq` is legal, which in -20 is the phase
            // *after* authorization; reachable from `SessionSetup` or
            // `AuthorizationSetup`, this arm would let a peer that had never
            // sent an `AuthorizationReq` arrive there and walk the rest of the
            // flow to `PowerDeliveryReq(Start)`.
            (
                F::ServiceSelected
                | F::ChargeParameters
                | F::ScheduleExchanged
                | F::CableCheck
                | F::PreCharge
                | F::Charging
                | F::Standby
                | F::PowerStopped
                | F::WeldingDetection,
                R::SessionStop(S::ServiceRenegotiation),
            ) => F::Authorized,

            _ => return None,
        })
    }

    /// How long the session may stay in its current phase, as `role` bounds
    /// it.
    ///
    /// See [`Phase::loop_timeout`]; this is that value for the phase the
    /// session is in.
    #[must_use]
    pub const fn loop_timeout(&self, role: super::Role) -> Option<super::Millis> {
        self.phase.loop_timeout(role)
    }

    /// The name of the current phase, for logs and errors.
    #[must_use]
    pub const fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::Start => "Start",
            Phase::SessionSetup => "SessionSetup",
            Phase::AuthorizationSetup => "AuthorizationSetup",
            Phase::Authorized => "Authorized",
            Phase::ServiceDiscovery => "ServiceDiscovery",
            Phase::ServiceSelected => "ServiceSelected",
            Phase::ChargeParameters => "ChargeParameters",
            Phase::ScheduleExchanged => "ScheduleExchanged",
            Phase::CableCheck => "CableCheck",
            Phase::PreCharge => "PreCharge",
            Phase::Charging => "Charging",
            Phase::Standby => "Standby",
            Phase::PowerStopped => "PowerStopped",
            Phase::WeldingDetection => "WeldingDetection",
            Phase::Paused => "Paused",
            Phase::Stopped => "Stopped",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(requests: &[Request]) -> Sequencer {
        let mut s = Sequencer::new();
        for &r in requests {
            s.accept(r).unwrap_or_else(|e| panic!("{r:?}: {e}"));
        }
        s
    }

    const PREAMBLE: [Request; 4] = [
        Request::SessionSetup,
        Request::AuthorizationSetup,
        Request::Authorization,
        Request::ServiceDiscovery,
    ];

    /// A service renegotiation needs a service to renegotiate — and insisting
    /// on that is not pedantry, it is the difference between a shortcut and an
    /// authorization bypass.
    ///
    /// `SessionStopReq(ServiceRenegotiation)` lands the flow in the phase from
    /// which `ServiceDiscoveryReq` is legal, which in -20 is the phase *after*
    /// authorization. Reachable from `SessionSetup`, it would let a peer that
    /// never sent an `AuthorizationReq` arrive there and walk the whole flow to
    /// `PowerDeliveryReq(Start)` — a full charge on a session that was never
    /// authorized.
    #[test]
    fn service_renegotiation_cannot_stand_in_for_authorization() {
        for preamble in [&PREAMBLE[..1], &PREAMBLE[..2]] {
            let s = run(preamble);
            let phase = s.phase();
            assert!(
                !s.permits(Request::SessionStop(ChargingSession::ServiceRenegotiation)),
                "renegotiating from {phase:?} skips authorization"
            );
            // Stopping the session is a different matter and stays available.
            assert!(s.permits(Request::SessionStop(ChargingSession::Terminate)));
        }

        // It is also refused between authorization and a selected service:
        // there is still nothing to renegotiate.
        let mut s = run(&PREAMBLE);
        assert!(!s.permits(Request::SessionStop(ChargingSession::ServiceRenegotiation)));
        s.accept(Request::ServiceSelection(Service::Ac)).unwrap();
        assert!(s.permits(Request::SessionStop(ChargingSession::ServiceRenegotiation)));
    }

    /// A renegotiation that unwinds to a *different* service must not carry the
    /// previous one's "the safety phases are behind us" with it.
    #[test]
    fn a_service_renegotiation_forgets_the_previous_service() {
        let mut s = run(&PREAMBLE);
        for r in [
            Request::ServiceSelection(Service::Ac),
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::PowerDelivery(ChargeProgress::ScheduleRenegotiation),
        ] {
            s.accept(r).unwrap();
        }
        assert!(s.has_renegotiated());

        s.accept(Request::SessionStop(ChargingSession::ServiceRenegotiation)).unwrap();
        assert_eq!(s.service(), None);
        assert!(!s.has_renegotiated(), "a DC service now must still prove its isolation");

        s.accept(Request::ServiceDiscovery).unwrap();
        s.accept(Request::ServiceSelection(Service::Dc)).unwrap();
        s.accept(Request::ChargeParameterDiscovery).unwrap();
        s.accept(Request::ScheduleExchange).unwrap();
        assert!(
            !s.permits(Request::PowerDelivery(ChargeProgress::Start)),
            "the contactors opened when the previous service ended"
        );
        assert!(s.permits(Request::CableCheck));
    }

    /// A pause takes the transport connection down and expects to be resumed,
    /// so one accepted while the cable is live would end the conversation with
    /// the contactors closed. -2 says so outright (§8.4.1) and the physics did
    /// not change between the generations.
    #[test]
    fn a_pause_is_refused_while_the_cable_is_live() {
        let mut s = run(&PREAMBLE);
        for r in [
            Request::ServiceSelection(Service::Dc),
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
        ] {
            s.accept(r).unwrap();
        }
        assert!(s.permits(Request::SessionStop(ChargingSession::Pause)), "nothing is live yet");

        for r in [Request::CableCheck, Request::PreCharge] {
            s.accept(r).unwrap();
            let phase = s.phase();
            assert!(
                !s.permits(Request::SessionStop(ChargingSession::Pause)),
                "pausing from {phase:?} would leave the link energised"
            );
        }
        s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap();
        assert!(!s.permits(Request::SessionStop(ChargingSession::Pause)));

        // Standby is already power-down, so it qualifies...
        s.accept(Request::PowerDelivery(ChargeProgress::Standby)).unwrap();
        assert!(s.permits(Request::SessionStop(ChargingSession::Pause)));
        // ...and so, of course, does a stopped charge.
        s.accept(Request::PowerDelivery(ChargeProgress::Stop)).unwrap();
        assert!(s.permits(Request::SessionStop(ChargingSession::Pause)));
    }

    /// The loop budgets, and the relationships between them that have to hold
    /// whatever the numbers turn out to be: the station must decide before the
    /// vehicle gives up on it, the station must decide before the *sequence*
    /// window closes, and a person is slower than a backend.
    #[test]
    fn only_the_loops_have_a_loop_budget() {
        use crate::session::Role::{Evcc, Secc};
        use crate::session::timers::iso20 as t;
        assert_eq!(Phase::Authorized.loop_timeout(Evcc), Some(t::EIM_ONGOING_TIMEOUT));
        assert_eq!(Phase::ChargeParameters.loop_timeout(Evcc), Some(t::ONGOING_TIMEOUT));
        assert_eq!(Phase::ScheduleExchanged.loop_timeout(Evcc), Some(t::ONGOING_TIMEOUT));
        assert_eq!(Phase::WeldingDetection.loop_timeout(Evcc), Some(t::ONGOING_TIMEOUT));
        for phase in
            [Phase::Start, Phase::SessionSetup, Phase::Charging, Phase::Standby, Phase::Stopped]
        {
            for role in [Evcc, Secc] {
                assert_eq!(phase.loop_timeout(role), None, "{phase:?} is not a loop for {role}");
            }
        }
        for phase in [
            Phase::Authorized,
            Phase::ChargeParameters,
            Phase::ScheduleExchanged,
            Phase::WeldingDetection,
            Phase::CableCheck,
            Phase::PreCharge,
        ] {
            let (evcc, secc) = (phase.loop_timeout(Evcc), phase.loop_timeout(Secc));
            assert!(secc < evcc, "{phase:?}: station {secc:?} must close before vehicle {evcc:?}");
        }
        assert!(
            t::SECC_ONGOING_PERFORMANCE_TIME < t::SECC_SEQUENCE_TIMEOUT,
            "the station decides first"
        );
        assert!(t::EIM_ONGOING_TIMEOUT > t::ONGOING_TIMEOUT, "a person is slower than a backend");
    }

    #[test]
    fn the_dc_flow_runs_end_to_end() {
        let mut s = run(&PREAMBLE);
        for r in [
            Request::ServiceSelection(Service::Dc),
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
            Request::CableCheck,
            Request::PreCharge,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::ChargeLoop,
            Request::MeteringConfirmation,
            Request::ChargeLoop,
            Request::PowerDelivery(ChargeProgress::Stop),
            Request::WeldingDetection,
            Request::SessionStop(ChargingSession::Terminate),
        ] {
            s.accept(r).unwrap_or_else(|e| panic!("{r:?}: {e}"));
        }
        assert!(s.is_finished());
    }

    #[test]
    fn the_ac_flow_skips_the_dc_phases() {
        let mut s = run(&PREAMBLE);
        s.accept(Request::ServiceSelection(Service::Ac)).unwrap();
        s.accept(Request::ChargeParameterDiscovery).unwrap();
        s.accept(Request::ScheduleExchange).unwrap();
        assert!(!s.permits(Request::CableCheck));
        s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap();
        s.accept(Request::ChargeLoop).unwrap();
        s.accept(Request::PowerDelivery(ChargeProgress::Stop)).unwrap();
        assert!(!s.permits(Request::WeldingDetection));
        s.accept(Request::SessionStop(ChargingSession::Terminate)).unwrap();
    }

    /// The headline reordering against -2: authorization moved to the front.
    #[test]
    fn authorization_precedes_service_discovery() {
        let mut s = Sequencer::new();
        s.accept(Request::SessionSetup).unwrap();
        assert!(!s.permits(Request::ServiceDiscovery), "-2's order, not -20's");
        s.accept(Request::AuthorizationSetup).unwrap();
        s.accept(Request::Authorization).unwrap();
        assert!(s.permits(Request::ServiceDiscovery));
    }

    #[test]
    fn a_resumed_session_skips_straight_to_parameters() {
        let mut s = Sequencer::new();
        s.accept(Request::SessionSetup).unwrap();
        s.resume(Service::Dc);
        assert_eq!(s.phase(), Phase::ServiceSelected);
        assert!(!s.permits(Request::AuthorizationSetup), "already settled before the pause");
        s.accept(Request::ChargeParameterDiscovery).unwrap();
        s.accept(Request::ScheduleExchange).unwrap();
        s.accept(Request::CableCheck).unwrap();
    }

    #[test]
    fn a_schedule_renegotiation_returns_to_parameter_discovery() {
        let mut s = run(&PREAMBLE);
        for r in [
            Request::ServiceSelection(Service::Ac),
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::ChargeLoop,
        ] {
            s.accept(r).unwrap();
        }
        assert_eq!(
            s.accept(Request::PowerDelivery(ChargeProgress::ScheduleRenegotiation)).unwrap(),
            Phase::ChargeParameters
        );
        assert!(s.has_renegotiated());
        assert_eq!(s.service(), Some(Service::Ac), "the service survives renegotiation");
        // Re-discovering parameters is optional; a new schedule is the point.
        assert!(s.permits(Request::ChargeParameterDiscovery));
        s.accept(Request::ScheduleExchange).unwrap();
        s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap();
        assert_eq!(s.phase(), Phase::Charging);
    }

    /// A schedule renegotiation must not re-run the DC safety phases: the
    /// contactors never opened and the link is still at the battery's voltage.
    #[test]
    fn dc_schedule_renegotiation_does_not_repeat_the_cable_check() {
        let mut s = run(&PREAMBLE);
        for r in [
            Request::ServiceSelection(Service::Dc),
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
            Request::CableCheck,
            Request::PreCharge,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::ChargeLoop,
            Request::PowerDelivery(ChargeProgress::ScheduleRenegotiation),
            Request::ScheduleExchange,
        ] {
            s.accept(r).unwrap_or_else(|e| panic!("{r:?}: {e}"));
        }
        assert_eq!(
            s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap(),
            Phase::Charging
        );
    }

    /// ...but on the way *up* the isolation test is not optional.
    #[test]
    fn dc_cannot_skip_the_cable_check_before_the_first_power_delivery() {
        let mut s = run(&PREAMBLE);
        for r in [
            Request::ServiceSelection(Service::Dc),
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
        ] {
            s.accept(r).unwrap();
        }
        assert!(!s.permits(Request::PowerDelivery(ChargeProgress::Start)));
        assert!(s.permits(Request::CableCheck));
    }

    /// `SessionStopReq(ServiceRenegotiation)` is the one that reopens the
    /// service choice; the schedule renegotiation above is not.
    #[test]
    fn a_service_renegotiation_returns_to_service_discovery() {
        let mut s = run(&PREAMBLE);
        for r in [
            Request::ServiceSelection(Service::Ac),
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
            Request::PowerDelivery(ChargeProgress::Start),
        ] {
            s.accept(r).unwrap();
        }
        assert_eq!(
            s.accept(Request::SessionStop(ChargingSession::ServiceRenegotiation)).unwrap(),
            Phase::Authorized
        );
        assert!(!s.is_finished(), "renegotiating a service does not end the session");
        assert!(s.permits(Request::ServiceDiscovery));
    }

    #[test]
    fn the_pantograph_checks_in_before_charging_and_out_after() {
        let mut s = run(&PREAMBLE);
        s.accept(Request::ServiceSelection(Service::Acdp)).unwrap();
        s.accept(Request::VehicleCheckIn).unwrap();
        for r in [
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::ChargeLoop,
            Request::PowerDelivery(ChargeProgress::Stop),
        ] {
            s.accept(r).unwrap();
        }
        s.accept(Request::VehicleCheckOut).unwrap();
        s.accept(Request::SessionStop(ChargingSession::Terminate)).unwrap();
    }

    #[test]
    fn a_check_in_needs_a_pantograph() {
        let mut s = run(&PREAMBLE);
        s.accept(Request::ServiceSelection(Service::Dc)).unwrap();
        assert!(!s.permits(Request::VehicleCheckIn));
    }

    #[test]
    fn an_out_of_sequence_request_is_refused_without_advancing() {
        let mut s = Sequencer::new();
        let e = s.accept(Request::ChargeLoop).unwrap_err();
        assert_eq!(e.got, "ChargeLoopReq");
        assert_eq!(e.phase, "Start");
        assert_eq!(e.response_code, ResponseCode::FAILEDSequenceError as u8);
        assert_eq!(s.phase(), Phase::Start);
    }

    #[test]
    fn a_failure_leaves_only_session_stop() {
        let mut s = run(&PREAMBLE);
        s.accept(Request::ServiceSelection(Service::Dc)).unwrap();
        s.failed();
        assert!(s.is_failed());
        for r in [
            Request::ChargeParameterDiscovery,
            Request::ServiceDiscovery,
            // Renegotiating a service the station just refused is not stopping.
            Request::SessionStop(ChargingSession::ServiceRenegotiation),
        ] {
            assert!(!s.permits(r), "{r:?} must not survive a failure response");
        }
        s.accept(Request::SessionStop(ChargingSession::Terminate)).unwrap();
        assert!(s.is_finished());
    }

    /// `ServiceRenegotiation` is a `SessionStopReq` that does not stop the
    /// session: it keeps the authorization and goes back to pick a different
    /// service. Treating it as terminal would drop a session the standard says
    /// carries on.
    #[test]
    fn service_renegotiation_does_not_end_the_session() {
        let mut s = run(&PREAMBLE);
        for r in [
            Request::ServiceSelection(Service::Ac),
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::ChargeLoop,
            Request::PowerDelivery(ChargeProgress::Stop),
        ] {
            s.accept(r).unwrap();
        }
        assert_eq!(
            s.accept(Request::SessionStop(ChargingSession::ServiceRenegotiation)).unwrap(),
            Phase::Authorized
        );
        assert!(!s.is_finished(), "the session goes on with a different service");
        // ...and the authorization survived it.
        assert!(!s.permits(Request::AuthorizationSetup));
        s.accept(Request::ServiceDiscovery).unwrap();
        s.accept(Request::ServiceSelection(Service::Dc)).unwrap();
        assert_eq!(s.service(), Some(Service::Dc));
    }

    #[test]
    fn a_paused_session_is_finished_but_not_terminated() {
        let mut s = run(&PREAMBLE);
        s.accept(Request::ServiceSelection(Service::Ac)).unwrap();
        s.accept(Request::SessionStop(ChargingSession::Pause)).unwrap();
        assert!(s.is_finished());
        assert!(s.is_paused());
        assert!(!s.permits(Request::ChargeParameterDiscovery), "a paused session is over");
    }

    #[test]
    fn a_session_can_be_stopped_from_any_established_phase() {
        for extra in [&[][..], &[Request::ServiceSelection(Service::Dc)]] {
            let mut s = run(&PREAMBLE);
            for &r in extra {
                s.accept(r).unwrap();
            }
            let phase = s.phase();
            s.accept(Request::SessionStop(ChargingSession::Terminate))
                .unwrap_or_else(|e| panic!("stopping from {phase:?}: {e}"));
        }
        assert!(!Sequencer::new().permits(Request::SessionStop(ChargingSession::Terminate)));
    }

    #[test]
    fn the_charge_loop_gets_the_tight_timeout() {
        use crate::session::timers::iso2 as t;
        assert_eq!(Request::ChargeLoop.response_timeout(), t::MSG_TIMEOUT_CURRENT_DEMAND);
        assert_eq!(Request::ScheduleExchange.response_timeout(), t::MSG_TIMEOUT_BACKEND);
        assert_eq!(Request::CableCheck.response_timeout(), t::MSG_TIMEOUT_DEFAULT);
    }

    /// The ISO 15118-20 service id assignment. Getting one of these wrong routes
    /// a session down the wrong flow entirely: a wireless vehicle would be asked to check
    /// its pantograph in, and a pantograph vehicle would never be.
    #[test]
    fn service_ids_map_to_the_flow_the_standard_assigns_them() {
        for (id, expected) in [
            (1u16, Some(Service::Ac)), // AC
            (2, Some(Service::Dc)),    // DC
            (3, Some(Service::Wpt)),   // WPT
            (4, Some(Service::Acdp)),  // DC_ACDP
            (5, Some(Service::Ac)),    // AC_BPT
            (6, Some(Service::Dc)),    // DC_BPT
            (7, Some(Service::Acdp)),  // DC_ACDP_BPT
            (0, None),
            (8, None),  // MCS — an energy transfer service with no schema set here
            (9, None),  // MCS_BPT — likewise
            (10, None), // AC_DER — likewise
            (65, None), // Internet — value-added
            (66, None), // ParkingStatus — value-added
            (u16::MAX, None),
        ] {
            assert_eq!(Service::from_service_id(id), expected, "service id {id}");
        }
    }

    /// Bidirectional power transfer is the same flow in the other direction,
    /// which is why there is no `iso20-bpt` feature and no `Service::AcBpt`.
    #[test]
    fn the_bpt_variants_share_their_twin_s_flow() {
        assert_eq!(Service::from_service_id(5), Service::from_service_id(1));
        assert_eq!(Service::from_service_id(6), Service::from_service_id(2));
        assert_eq!(Service::from_service_id(7), Service::from_service_id(4));
    }

    /// A schedule renegotiation earns a DC session its way past the isolation
    /// test, because the contactors never opened. A *service* renegotiation
    /// opens them, so it must not inherit that.
    #[test]
    fn a_service_renegotiation_does_not_inherit_a_schedule_renegotiation() {
        let mut s = run(&PREAMBLE);
        for r in [
            Request::ServiceSelection(Service::Dc),
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
            Request::CableCheck,
            Request::PreCharge,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::PowerDelivery(ChargeProgress::ScheduleRenegotiation),
        ] {
            s.accept(r).unwrap_or_else(|e| panic!("{r:?}: {e}"));
        }
        assert!(s.has_renegotiated());

        s.accept(Request::SessionStop(ChargingSession::ServiceRenegotiation)).unwrap();
        assert!(!s.has_renegotiated(), "the schedule renegotiation did not survive");
        assert_eq!(s.service(), None, "nor did the service it happened under");

        for r in [
            Request::ServiceDiscovery,
            Request::ServiceSelection(Service::Dc),
            Request::ChargeParameterDiscovery,
            Request::ScheduleExchange,
        ] {
            s.accept(r).unwrap_or_else(|e| panic!("{r:?}: {e}"));
        }
        assert!(
            !s.permits(Request::PowerDelivery(ChargeProgress::Start)),
            "the contactors opened; the isolation test runs again"
        );
        assert!(s.permits(Request::CableCheck));
    }

    #[test]
    fn each_service_travels_under_its_own_payload_type() {
        use crate::v2gtp::PayloadType;
        assert_eq!(Service::Ac.payload_type(), PayloadType::Part20Ac);
        assert_eq!(Service::Dc.payload_type(), PayloadType::Part20Dc);
        assert_eq!(Service::Wpt.payload_type(), PayloadType::Part20Wpt);
        assert_eq!(Service::Acdp.payload_type(), PayloadType::Part20Acdp);
    }
}
