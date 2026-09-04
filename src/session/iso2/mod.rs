//! ISO 15118-2 message sequencing.
//!
//! The -2 message set is a graph, not a list: which request may follow which
//! depends on the payment option chosen at `PaymentServiceSelection` and on the
//! energy transfer mode chosen at `ChargeParameterDiscovery`, and the DC loop
//! has three extra phases the AC loop does not. The spec expresses this as a
//! pair of state charts (§8.4.2) and prescribes exactly one response when a
//! peer departs from them: `FAILED_SequenceError`, followed by termination.
//!
//! This module is that graph and nothing else — no I/O, no timers, no policy.
//! It answers two questions:
//!
//! * given where the session is, is this request legal, and where does it go?
//! * given where the session is, what *would* be legal? (which is what an EVCC
//!   uses to choose its next request, and what a fuzzer uses to stay on-path)
//!
//! ```
//! use iso15118::session::Security;
//! use iso15118::session::iso2::{Request, Sequencer};
//! use iso15118::iso2::{ChargeProgress, EnergyTransferMode, PaymentOption};
//!
//! // The transport decides one rule: Plug & Charge needs TLS [V2G2-634].
//! let mut s = Sequencer::new(Security::Tls);
//! s.accept(Request::SessionSetup)?;
//! s.accept(Request::ServiceDiscovery)?;
//! s.accept(Request::PaymentServiceSelection(PaymentOption::ExternalPayment))?;
//! s.accept(Request::Authorization)?;
//! s.accept(Request::ChargeParameterDiscovery(EnergyTransferMode::DCExtended))?;
//!
//! // DC inserts cable check and pre-charge before power flows.
//! assert!(s.accept(Request::PowerDelivery(ChargeProgress::Start)).is_err());
//! s.accept(Request::CableCheck)?;
//! # Ok::<_, iso15118::session::SequenceError>(())
//! ```

pub mod schedule;

use crate::iso2::{
    ChargeProgress, ChargingSession, EnergyTransferMode, PaymentOption, ResponseCode,
};

use super::{Security, SequenceError};

/// A request, reduced to what sequencing depends on.
///
/// The three variants that carry a value carry it because the *next* legal
/// request depends on it — that is the whole reason the -2 flow is a graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Request {
    /// `SessionSetupReq`.
    SessionSetup,
    /// `ServiceDiscoveryReq`.
    ServiceDiscovery,
    /// `ServiceDetailReq`.
    ServiceDetail,
    /// `PaymentServiceSelectionReq`. The option decides whether the contract
    /// certificate flow runs before authorization.
    PaymentServiceSelection(PaymentOption),
    /// `CertificateInstallationReq`.
    CertificateInstallation,
    /// `CertificateUpdateReq`.
    CertificateUpdate,
    /// `PaymentDetailsReq`.
    PaymentDetails,
    /// `AuthorizationReq`.
    Authorization,
    /// `ChargeParameterDiscoveryReq`. The transfer mode decides whether the DC
    /// phases follow.
    ChargeParameterDiscovery(EnergyTransferMode),
    /// `CableCheckReq` (DC only).
    CableCheck,
    /// `PreChargeReq` (DC only).
    PreCharge,
    /// `PowerDeliveryReq`. `Start` opens the charge loop, `Stop` closes it, and
    /// `Renegotiate` returns to `ChargeParameterDiscovery`.
    PowerDelivery(ChargeProgress),
    /// `ChargingStatusReq` (AC charge loop).
    ChargingStatus,
    /// `CurrentDemandReq` (DC charge loop).
    CurrentDemand,
    /// `MeteringReceiptReq`.
    MeteringReceipt,
    /// `WeldingDetectionReq` (DC only).
    WeldingDetection,
    /// `SessionStopReq`. `ChargingSession` decides whether the session is
    /// terminated or merely paused, and a paused one keeps its session id for a
    /// later resume.
    SessionStop(ChargingSession),
}

impl Request {
    /// The element name, for logs and errors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SessionSetup => "SessionSetupReq",
            Self::ServiceDiscovery => "ServiceDiscoveryReq",
            Self::ServiceDetail => "ServiceDetailReq",
            Self::PaymentServiceSelection(_) => "PaymentServiceSelectionReq",
            Self::CertificateInstallation => "CertificateInstallationReq",
            Self::CertificateUpdate => "CertificateUpdateReq",
            Self::PaymentDetails => "PaymentDetailsReq",
            Self::Authorization => "AuthorizationReq",
            Self::ChargeParameterDiscovery(_) => "ChargeParameterDiscoveryReq",
            Self::CableCheck => "CableCheckReq",
            Self::PreCharge => "PreChargeReq",
            Self::PowerDelivery(_) => "PowerDeliveryReq",
            Self::ChargingStatus => "ChargingStatusReq",
            Self::CurrentDemand => "CurrentDemandReq",
            Self::MeteringReceipt => "MeteringReceiptReq",
            Self::WeldingDetection => "WeldingDetectionReq",
            Self::SessionStop(_) => "SessionStopReq",
        }
    }

    /// Classifies a decoded message for sequencing.
    ///
    /// `None` for a response, and for the schema elements that are not messages
    /// in their own right.
    #[must_use]
    pub fn of(message: &crate::message::Message) -> Option<Self> {
        let crate::message::Message::Iso2(doc) = message else { return None };
        // -2 routes all thirty-four messages through one `V2G_Message` root, so
        // the body's choice is where the message name lives.
        let crate::iso2::Document::V2GMessage(v2g) = &**doc else { return None };
        Self::of_body(v2g.body.choice.as_ref()?)
    }

    /// The same, from a `V2G_Message` body directly.
    #[must_use]
    pub fn of_body(body: &crate::iso2::BodyChoice) -> Option<Self> {
        use crate::iso2::BodyChoice as B;
        Some(match body {
            B::SessionSetupReq(_) => Self::SessionSetup,
            B::ServiceDiscoveryReq(_) => Self::ServiceDiscovery,
            B::ServiceDetailReq(_) => Self::ServiceDetail,
            B::PaymentServiceSelectionReq(req) => {
                Self::PaymentServiceSelection(req.selected_payment_option)
            }
            B::CertificateInstallationReq(_) => Self::CertificateInstallation,
            B::CertificateUpdateReq(_) => Self::CertificateUpdate,
            B::PaymentDetailsReq(_) => Self::PaymentDetails,
            B::AuthorizationReq(_) => Self::Authorization,
            B::ChargeParameterDiscoveryReq(req) => {
                Self::ChargeParameterDiscovery(req.requested_energy_transfer_mode)
            }
            B::CableCheckReq(_) => Self::CableCheck,
            B::PreChargeReq(_) => Self::PreCharge,
            B::PowerDeliveryReq(req) => Self::PowerDelivery(req.charge_progress),
            B::ChargingStatusReq(_) => Self::ChargingStatus,
            B::CurrentDemandReq(_) => Self::CurrentDemand,
            B::MeteringReceiptReq(_) => Self::MeteringReceipt,
            B::WeldingDetectionReq(_) => Self::WeldingDetection,
            B::SessionStopReq(req) => Self::SessionStop(req.charging_session),
            _ => return None,
        })
    }

    /// The `V2G_EVCC_Msg_Timeout` for this request's response
    /// (ISO 15118-2 Table 109, \[V2G2-436\]).
    #[must_use]
    pub const fn response_timeout(self) -> super::Millis {
        use super::timers::iso2 as t;
        match self {
            // The DC charge loop runs an order of magnitude faster than
            // everything else, and its timeout is set accordingly.
            Self::CurrentDemand => t::MSG_TIMEOUT_CURRENT_DEMAND,
            // These reach a backend — a clearing house, a contract certificate
            // pool — so they get the longer budget.
            Self::ServiceDetail
            | Self::PaymentDetails
            | Self::PowerDelivery(_)
            | Self::CertificateInstallation
            | Self::CertificateUpdate => t::MSG_TIMEOUT_BACKEND,
            _ => t::MSG_TIMEOUT_DEFAULT,
        }
    }

    /// The `V2G_SECC_Msg_Performance_Time` for this request's response
    /// (ISO 15118-2 Table 109).
    ///
    /// The other half of the pair [`Request::response_timeout`] gives. That one
    /// is how long the *vehicle* waits and it is enforced — the session ends
    /// when it expires. This one is how long the *station* has to answer, and
    /// nothing enforces it, because nothing on this side can: missing it is not
    /// a fault the station observes, it is the vehicle timing out half a second
    /// later.
    ///
    /// What it is good for is budgeting. A station that has to reach a clearing
    /// house to answer `PaymentDetailsReq` has 4,5 s to do it in and can decide
    /// what to do at 4 s; one answering `CurrentDemandReq` has **25 ms**, which
    /// is a fact about the architecture rather than about the request handler.
    /// [`Secc::response_due`] turns it into a deadline against the session
    /// clock.
    ///
    /// [`Secc::response_due`]: crate::secc::Secc::response_due
    #[must_use]
    pub const fn performance_time(self) -> super::Millis {
        use super::timers::iso2 as t;
        match self {
            Self::CurrentDemand => t::SECC_MSG_PERFORMANCE_CURRENT_DEMAND,
            Self::ServiceDetail
            | Self::PaymentDetails
            | Self::PowerDelivery(_)
            | Self::CertificateInstallation
            | Self::CertificateUpdate => t::SECC_MSG_PERFORMANCE_BACKEND,
            _ => t::SECC_MSG_PERFORMANCE_DEFAULT,
        }
    }
}

/// Where an ISO 15118-2 session has got to.
///
/// Named after the request that most recently advanced it, which is how the
/// spec's state charts are labelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Phase {
    /// Nothing has arrived yet.
    Start,
    /// A session exists.
    SessionSetup,
    /// Services have been listed.
    ServiceDiscovery,
    /// A payment option and services have been selected.
    ServiceSelected,
    /// A contract certificate has been installed or updated.
    ///
    /// Its own phase rather than a return to [`Phase::ServiceSelected`],
    /// because \[V2G2-554\], \[V2G2-557\] and \[V2G2-558\] all leave exactly one
    /// legal next request — `PaymentDetailsReq` — whether the certificate
    /// exchange succeeded or failed. Looping back would leave a second
    /// `CertificateInstallationReq` legal, and that one reaches the CPO's
    /// certificate pool: a peer with no credentials could hold the session open
    /// and keep the backend busy for as long as it liked, one legal request at
    /// a time.
    CertificateInstalled,
    /// Contract credentials have been presented.
    PaymentDetails,
    /// The EVCC is authorized (or still being authorized).
    Authorized,
    /// Charge parameters have been exchanged.
    ChargeParameters,
    /// DC: the cable is being checked for isolation faults.
    CableCheck,
    /// DC: the link voltage is being matched to the battery.
    PreCharge,
    /// Power is flowing.
    Charging,
    /// Power has stopped.
    PowerStopped,
    /// DC: checking the contactors did not weld shut.
    WeldingDetection,
    /// The session is suspended and may be resumed under the same session id —
    /// `SessionStopReq` with `ChargingSession = Pause`.
    Paused,
    /// The session is over.
    Stopped,
}

impl Phase {
    /// How long a session may stay in this phase before the vehicle gives up.
    ///
    /// Several -2 phases are *loops*: the SECC answers `EVSEProcessing =
    /// Ongoing` and the EVCC repeats the same request until it does not. Each
    /// such loop has a bound of its own, separate from the per-message response
    /// timeout, and missing it is how a vehicle sits for an hour waiting for an
    /// isolation test that will never finish: `V2G_EVCC_CableCheck_Timer`
    /// \[V2G2-700\]..\[V2G2-703\], `V2G_EVCC_PreCharge_Timer`
    /// \[V2G2-704\]..\[V2G2-707\], and `V2G_EVCC_Ongoing_Timer`
    /// \[V2G2-710\], \[V2G2-711\] for every phase answered `Ongoing`.
    ///
    /// `None` for the phases that are not loops, and for `Charging` — a charge
    /// loop runs as long as the vehicle wants it to.
    ///
    /// Every one of these budgets is a *pair*, and `role` picks the half that
    /// applies: Table 109 and Table 111 give the station a shorter figure than
    /// the vehicle for the same loop, so that a station which cannot decide
    /// answers `FAILED` while the vehicle is still listening \[V2G2-713\]. A
    /// station armed with the vehicle's number has a deadline it can never
    /// reach in time to say anything. See [`Role`](super::Role).
    #[must_use]
    pub const fn loop_timeout(self, role: super::Role) -> Option<super::Millis> {
        use super::Role;
        use super::timers::iso2 as t;
        Some(match (self, role) {
            // The DC safety phases have budgets of their own, and they are much
            // tighter than the general one: an isolation test that has not
            // finished in forty seconds has failed, and a pre-charge that has
            // not matched the battery voltage in seven is not going to.
            (Self::CableCheck, Role::Evcc) => t::EVCC_CABLE_CHECK_TIMEOUT,
            (Self::CableCheck, Role::Secc) => t::SECC_CABLE_CHECK_PERFORMANCE_TIME,
            (Self::PreCharge, Role::Evcc) => t::EVCC_PRE_CHARGE_TIMEOUT,
            (Self::PreCharge, Role::Secc) => t::SECC_PRE_CHARGE_PERFORMANCE_TIME,
            // Everything else that can answer `..._Ongoing`: authorization
            // waiting on a backend or a driver, parameter discovery waiting on
            // a schedule, welding detection waiting on the contactors to open.
            (Self::Authorized | Self::ChargeParameters | Self::WeldingDetection, Role::Evcc) => {
                t::EVCC_ONGOING_TIMEOUT
            }
            (Self::Authorized | Self::ChargeParameters | Self::WeldingDetection, Role::Secc) => {
                t::SECC_ONGOING_PERFORMANCE_TIME
            }
            _ => return None,
        })
    }
}

/// Whether the session is charging over AC or DC — the fork that decides
/// whether cable check, pre-charge and welding detection happen at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Transfer {
    /// AC charging.
    Ac,
    /// DC charging.
    Dc,
}

impl From<EnergyTransferMode> for Transfer {
    fn from(mode: EnergyTransferMode) -> Self {
        match mode {
            EnergyTransferMode::ACSinglePhaseCore | EnergyTransferMode::ACThreePhaseCore => {
                Self::Ac
            }
            _ => Self::Dc,
        }
    }
}

/// Tracks an ISO 15118-2 session's position in the message flow.
///
/// One instance per session, on either side of the plug: the SECC uses it to
/// decide whether an arriving request is legal, and the EVCC uses it to decide
/// what to send next. Both need the same graph, and having one copy of it means
/// the two sides cannot drift apart.
///
/// It holds no buffers, no keys and no schedule — five small fields — so a
/// snapshot is cheap to take and, with the `serde` feature, to store. That is
/// what resuming a paused session across a power cycle needs: the phase and the
/// two facts the graph branches on, written down and read back.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Sequencer {
    phase: Phase,
    /// What the transport underneath is, which decides whether Plug & Charge is
    /// available at all. \[V2G2-634\], \[V2G2-635\]
    security: Security,
    transfer: Option<Transfer>,
    payment: Option<PaymentOption>,
    /// Set by a `PowerDeliveryReq(Renegotiate)`.
    renegotiated: bool,
    /// Set once a `FAILED_*` response has gone past, after which the only
    /// request left is `SessionStopReq`.
    failed: bool,
}

impl Sequencer {
    /// A session that has not yet seen its first request, over a transport that
    /// is `security`.
    ///
    /// There is no `Default`, and that is deliberate: the safe value of
    /// `security` is the restrictive one, and a `Default` would have to pick a
    /// side of a security decision on the caller's behalf. Saying it is one
    /// word.
    #[must_use]
    pub const fn new(security: Security) -> Self {
        Self {
            phase: Phase::Start,
            security,
            transfer: None,
            payment: None,
            renegotiated: false,
            failed: false,
        }
    }

    /// What the transport underneath this session is.
    #[must_use]
    pub const fn security(&self) -> Security {
        self.security
    }

    /// Records that a `FAILED_*` response has gone past.
    ///
    /// ISO 15118-2 leaves no discretion after a failure: the session ends, and
    /// the only request the vehicle may still send is `SessionStopReq`
    /// \[V2G2-ED2-1664\]..\[V2G2-ED2-1667\]. Calling this is what stops a
    /// peer from carrying on down the flow as though the failure had not
    /// happened — the class of bug `EVerest`'s `GHSA-9vv5-67cv-9crq` describes.
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

    /// AC or DC, once `ChargeParameterDiscovery` has said.
    #[must_use]
    pub const fn transfer(&self) -> Option<Transfer> {
        self.transfer
    }

    /// The payment option, once `PaymentServiceSelection` has said.
    #[must_use]
    pub const fn payment(&self) -> Option<PaymentOption> {
        self.payment
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
    #[must_use]
    pub const fn is_paused(&self) -> bool {
        matches!(self.phase, Phase::Paused)
    }

    /// True once the vehicle has asked to renegotiate.
    ///
    /// The second pass through `ChargeParameterDiscovery` is not the first: a
    /// charger that has already committed to a schedule is revising it, which
    /// is a different decision from making one.
    #[must_use]
    pub const fn has_renegotiated(&self) -> bool {
        self.renegotiated
    }

    /// Records that `request` arrived, advancing the session.
    ///
    /// A request that is legal *now* moves the session on; anything else is
    /// refused with the response code the spec prescribes, and the session is
    /// left where it was so the caller can send that code and terminate.
    ///
    /// A request that repeats — the SECC answered `..._Ongoing`, or the charge
    /// loop is turning — is legal and leaves the phase unchanged.
    pub fn accept(&mut self, request: Request) -> Result<Phase, SequenceError> {
        let Some(next) = self.next_phase(request) else {
            return Err(self.refusal(request));
        };
        // Record the facts the rest of the graph branches on before moving.
        match request {
            Request::PaymentServiceSelection(option) => self.payment = Some(option),
            Request::ChargeParameterDiscovery(mode) => self.transfer = Some(mode.into()),
            _ => {}
        }
        // Coming *back* to parameter discovery from the charge loop, or from a
        // charge whose power has been stopped, is a renegotiation whichever
        // request got us here — `PowerDeliveryReq(Renegotiate)` \[V2G2-813\],
        // a `ChargeParameterDiscoveryReq` after `PowerDeliveryReq(Stop)`
        // \[V2G2-601\], or one after a metering receipt \[V2G2-797\]. What the
        // flag records is a physical fact rather than a message: the DC
        // isolation test and the pre-charge are behind us and the cable is
        // live, so they must not be demanded again. Keying it on the
        // *transition* rather than on one request is what keeps the three
        // spellings from needing three copies of the rule — and what stops the
        // two the graph gained here from deadlocking DC on the way back up.
        if next == Phase::ChargeParameters
            && matches!(self.phase, Phase::Charging | Phase::PowerStopped)
        {
            self.renegotiated = true;
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

    /// The phase `request` would move the session to, or `None` if it is out of
    /// sequence.
    ///
    /// This is the whole of the ISO 15118-2 flow. Read it as: "in this phase,
    /// these requests are legal, and each goes here".
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

        let dc = self.transfer == Some(Transfer::Dc);
        let contract = self.payment == Some(PaymentOption::Contract);

        // After a `FAILED_*` response the session is over bar the formalities:
        // the vehicle may stop it and nothing else.
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
            (F::SessionSetup, R::ServiceDiscovery) => F::ServiceDiscovery,

            // Plug & Charge is not available without TLS. \[V2G2-634\] forbids
            // the station to *provide* the PnC message sets over an unsecured
            // session and \[V2G2-635\] forbids the vehicle to apply them;
            // \[V2G2-633\] leaves such a session external identification and
            // nothing else. Refusing the selection is where that becomes
            // enforceable, because it is the one message that says which of the
            // two a session is — and everything a contract would otherwise put
            // on a plaintext wire (the certificate chain, the signature, the
            // EMAID) hangs off it.
            (F::ServiceDiscovery, R::PaymentServiceSelection(PaymentOption::Contract))
                if !self.security.permits_plug_and_charge() =>
            {
                return None;
            }

            // `ServiceDetail` is optional and repeatable; the EVCC asks about
            // as many of the advertised services as it cares to.
            (F::ServiceDiscovery, R::ServiceDetail) => F::ServiceDiscovery,
            (F::ServiceDiscovery, R::PaymentServiceSelection(_)) => F::ServiceSelected,

            // With a contract, credentials come next — optionally preceded by
            // installing or updating that contract certificate. With external
            // identification there is nothing to present.
            //
            // The certificate exchange happens at most once, and lands in a
            // phase of its own: \[V2G2-554\], \[V2G2-557\] and \[V2G2-558\] leave
            // `PaymentDetailsReq` as the only legal next request either way.
            (F::ServiceSelected, R::CertificateInstallation | R::CertificateUpdate) if contract => {
                F::CertificateInstalled
            }
            (F::ServiceSelected | F::CertificateInstalled, R::PaymentDetails) if contract => {
                F::PaymentDetails
            }
            (F::ServiceSelected, R::Authorization) if !contract => F::Authorized,
            (F::PaymentDetails, R::Authorization) => F::Authorized,

            // Authorization repeats while the SECC answers `..._Ongoing`.
            (F::Authorized, R::Authorization) => F::Authorized,
            (F::Authorized, R::ChargeParameterDiscovery(_)) => F::ChargeParameters,

            // ...and so does charge parameter discovery.
            (F::ChargeParameters, R::ChargeParameterDiscovery(_)) => F::ChargeParameters,
            (F::ChargeParameters, R::CableCheck) if dc => F::CableCheck,
            // AC has no isolation test and no pre-charge, so power follows the
            // parameters directly. DC has both — but only once. A renegotiation
            // returns here with the contactors closed and the link already at
            // the battery's voltage, so repeating the cable check would be
            // asking a charging vehicle to prove its cable is not connected.
            // Refusing `PowerDelivery` here is what deadlocks DC renegotiation.
            (F::ChargeParameters, R::PowerDelivery(P::Start)) if !dc || self.renegotiated => {
                F::Charging
            }

            (F::CableCheck, R::CableCheck) => F::CableCheck,
            (F::CableCheck, R::PreCharge) => F::PreCharge,
            (F::PreCharge, R::PreCharge) => F::PreCharge,
            (F::PreCharge, R::PowerDelivery(P::Start)) => F::Charging,

            // The charge loop. `MeteringReceipt` interleaves with it under a
            // contract, acknowledging the signed meter readings — and only
            // under a contract: \[V2G2-903\] has the vehicle sign that message
            // "using the private key belonging to the Contract Certificate it
            // has sent in PaymentDetailsReq in this session", which an
            // externally identified session never sent. The station asks for
            // one by setting `ReceiptRequired` \[V2G2-577\], \[V2G2-795\];
            // asking an EIM session for a signature it has no key to make is
            // the station's own error, and answering it is not possible.
            (F::Charging, R::ChargingStatus) if !dc => F::Charging,
            (F::Charging, R::CurrentDemand) if dc => F::Charging,
            (F::Charging, R::MeteringReceipt) if contract => F::Charging,
            // Renegotiation goes back for new parameters without dropping the
            // session — a tariff change, or the EV revising its target.
            (F::Charging, R::PowerDelivery(P::Renegotiate)) => F::ChargeParameters,
            (F::Charging, R::PowerDelivery(P::Stop)) => F::PowerStopped,

            // DC lets the vehicle revise its parameters after the power has
            // stopped without dropping the session — a second charge under a
            // new schedule, with the contactors still closed. \[V2G2-601\]
            // names it alongside welding detection and the session stop, and
            // refusing it is what strands a DC vehicle that wanted to carry on.
            (F::PowerStopped, R::ChargeParameterDiscovery(_)) if dc => F::ChargeParameters,
            // ...and \[V2G2-797\] allows the same jump straight out of the
            // charge loop, once a metering receipt has been acknowledged.
            (F::Charging, R::ChargeParameterDiscovery(_)) if dc && contract => F::ChargeParameters,

            // DC checks for welded contactors before anyone touches the cable.
            (F::PowerStopped, R::WeldingDetection) if dc => F::WeldingDetection,
            (F::WeldingDetection, R::WeldingDetection) => F::WeldingDetection,

            // `SessionStopReq` is legal from any established phase, not only at
            // the end of a completed charge. A vehicle aborts — a fault, a
            // driver unplugging, a response it did not like — and the defined
            // reaction is to stop the session rather than to sit until the
            // sequence timer runs out. `Start` is the exception: there is no
            // session to stop before `SessionSetupReq`.
            (F::Start | F::Stopped | F::Paused, R::SessionStop(_)) => return None,
            (_, R::SessionStop(S::Terminate)) => F::Stopped,
            // Pausing is *not* the same freedom, and the difference is
            // physical. §8.4.1 says an EV may pause "at any time after sending
            // PowerDeliveryReq with ChargeProgress equal to 'Stop'", and
            // \[V2G2-739\] has the pause take the transport connection down with
            // it. So a pause accepted while the cable is live would end the
            // conversation with the contactors still closed and the link still
            // at battery voltage, leaving the power flowing with nobody talking
            // about it. The vehicle stops power delivery first; then it may
            // pause.
            (F::CableCheck | F::PreCharge | F::Charging, R::SessionStop(S::Pause)) => return None,
            (_, R::SessionStop(S::Pause)) => F::Paused,

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
            Phase::ServiceDiscovery => "ServiceDiscovery",
            Phase::ServiceSelected => "ServiceSelected",
            Phase::CertificateInstalled => "CertificateInstalled",
            Phase::PaymentDetails => "PaymentDetails",
            Phase::Authorized => "Authorized",
            Phase::ChargeParameters => "ChargeParameters",
            Phase::CableCheck => "CableCheck",
            Phase::PreCharge => "PreCharge",
            Phase::Charging => "Charging",
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

    const DC: EnergyTransferMode = EnergyTransferMode::DCExtended;
    const AC: EnergyTransferMode = EnergyTransferMode::ACThreePhaseCore;
    const EIM: PaymentOption = PaymentOption::ExternalPayment;
    const PNC: PaymentOption = PaymentOption::Contract;

    fn run(requests: &[Request]) -> Result<Sequencer, SequenceError> {
        run_with(Security::Tls, requests)
    }

    /// The same over a stated transport, for the one rule that depends on it.
    fn run_with(security: Security, requests: &[Request]) -> Result<Sequencer, SequenceError> {
        let mut s = Sequencer::new(security);
        for &r in requests {
            s.accept(r)?;
        }
        Ok(s)
    }

    fn up_to_authorized(payment: PaymentOption) -> Sequencer {
        let mut steps = alloc::vec![
            Request::SessionSetup,
            Request::ServiceDiscovery,
            Request::PaymentServiceSelection(payment),
        ];
        if payment == PNC {
            steps.push(Request::PaymentDetails);
        }
        steps.push(Request::Authorization);
        run(&steps).unwrap()
    }

    #[test]
    fn the_ac_eim_flow_runs_end_to_end() {
        let mut s = up_to_authorized(EIM);
        for r in [
            Request::ChargeParameterDiscovery(AC),
            Request::PowerDelivery(ChargeProgress::Start),
            Request::ChargingStatus,
            Request::ChargingStatus,
            Request::PowerDelivery(ChargeProgress::Stop),
            Request::SessionStop(ChargingSession::Terminate),
        ] {
            s.accept(r).unwrap_or_else(|e| panic!("{r:?}: {e}"));
        }
        assert!(s.is_finished());
    }

    #[test]
    fn the_dc_pnc_flow_runs_end_to_end() {
        let mut s = up_to_authorized(PNC);
        for r in [
            Request::ChargeParameterDiscovery(DC),
            Request::CableCheck,
            Request::CableCheck,
            Request::PreCharge,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::CurrentDemand,
            Request::MeteringReceipt,
            Request::CurrentDemand,
            Request::PowerDelivery(ChargeProgress::Stop),
            Request::WeldingDetection,
            Request::SessionStop(ChargingSession::Terminate),
        ] {
            s.accept(r).unwrap_or_else(|e| panic!("{r:?}: {e}"));
        }
        assert!(s.is_finished());
    }

    #[test]
    fn dc_cannot_skip_the_cable_check() {
        let mut s = up_to_authorized(EIM);
        s.accept(Request::ChargeParameterDiscovery(DC)).unwrap();
        let e = s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap_err();
        assert_eq!(e.got, "PowerDeliveryReq");
        assert_eq!(e.response_code, ResponseCode::FAILEDSequenceError as u8);
        assert_eq!(s.phase(), Phase::ChargeParameters, "a refusal must not advance the session");
    }

    #[test]
    fn ac_has_no_cable_check_to_run() {
        let mut s = up_to_authorized(EIM);
        s.accept(Request::ChargeParameterDiscovery(AC)).unwrap();
        assert!(!s.permits(Request::CableCheck));
        assert!(!s.permits(Request::WeldingDetection));
    }

    #[test]
    fn external_identification_has_no_contract_to_present() {
        let s = run(&[
            Request::SessionSetup,
            Request::ServiceDiscovery,
            Request::PaymentServiceSelection(EIM),
        ])
        .unwrap();
        assert!(!s.permits(Request::PaymentDetails));
        assert!(!s.permits(Request::CertificateInstallation));
        assert!(s.permits(Request::Authorization));
    }

    #[test]
    fn a_contract_must_be_presented_before_authorization() {
        let mut s = run(&[
            Request::SessionSetup,
            Request::ServiceDiscovery,
            Request::PaymentServiceSelection(PNC),
        ])
        .unwrap();
        assert!(s.accept(Request::Authorization).is_err());
        assert!(s.permits(Request::PaymentDetails));
    }

    #[test]
    fn a_metering_receipt_needs_a_contract_to_receipt() {
        let mut s = up_to_authorized(EIM);
        s.accept(Request::ChargeParameterDiscovery(AC)).unwrap();
        s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap();
        assert!(!s.permits(Request::MeteringReceipt), "there is no contract to sign against");
    }

    #[test]
    fn renegotiation_returns_to_charge_parameter_discovery() {
        let mut s = up_to_authorized(EIM);
        s.accept(Request::ChargeParameterDiscovery(AC)).unwrap();
        s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap();
        s.accept(Request::ChargingStatus).unwrap();
        assert!(!s.has_renegotiated());
        assert_eq!(
            s.accept(Request::PowerDelivery(ChargeProgress::Renegotiate)).unwrap(),
            Phase::ChargeParameters
        );
        assert!(s.has_renegotiated(), "the charger is revising a schedule, not making one");
        // ...and the loop can be re-entered from there.
        s.accept(Request::ChargeParameterDiscovery(AC)).unwrap();
        s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap();
        assert_eq!(s.phase(), Phase::Charging);
    }

    /// The DC renegotiation loop. Cable check and pre-charge happen once, on
    /// the way up; a renegotiation revises the schedule while power is already
    /// flowing, and the contactors never opened. Requiring the isolation test
    /// again would strand every DC vehicle that renegotiates.
    #[test]
    fn dc_renegotiation_does_not_repeat_the_cable_check() {
        let mut s = up_to_authorized(EIM);
        for r in [
            Request::ChargeParameterDiscovery(DC),
            Request::CableCheck,
            Request::PreCharge,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::CurrentDemand,
            Request::PowerDelivery(ChargeProgress::Renegotiate),
            Request::ChargeParameterDiscovery(DC),
        ] {
            s.accept(r).unwrap_or_else(|e| panic!("{r:?}: {e}"));
        }
        assert!(s.has_renegotiated());
        assert_eq!(
            s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap(),
            Phase::Charging
        );
        // ...and a charger that does want to re-verify isolation may still ask.
        assert!(s.permits(Request::CurrentDemand));
    }

    #[test]
    fn nothing_but_session_setup_starts_a_session() {
        let s = Sequencer::new(Security::Tls);
        for r in [
            Request::ServiceDiscovery,
            Request::Authorization,
            Request::SessionStop(ChargingSession::Terminate),
        ] {
            assert!(!s.permits(r), "{r:?} must not start a session");
        }
        assert!(s.permits(Request::SessionSetup));
    }

    #[test]
    fn a_stopped_session_accepts_nothing() {
        let mut s = up_to_authorized(EIM);
        for r in [
            Request::ChargeParameterDiscovery(AC),
            Request::PowerDelivery(ChargeProgress::Start),
            Request::PowerDelivery(ChargeProgress::Stop),
            Request::SessionStop(ChargingSession::Terminate),
        ] {
            s.accept(r).unwrap();
        }
        assert!(!s.permits(Request::SessionSetup));
        assert!(!s.permits(Request::ChargingStatus));
        assert!(!s.permits(Request::SessionStop(ChargingSession::Terminate)));
    }

    /// ISO 15118-2 \[V2G2-ED2-1664\]..: after a `FAILED_*` response the SECC
    /// waits for `SessionStopReq`, and for nothing else.
    #[test]
    fn a_failure_leaves_only_session_stop() {
        let mut s = up_to_authorized(EIM);
        s.accept(Request::ChargeParameterDiscovery(DC)).unwrap();
        s.failed();
        assert!(s.is_failed());
        for r in [Request::CableCheck, Request::ChargeParameterDiscovery(DC), Request::SessionSetup]
        {
            assert!(!s.permits(r), "{r:?} must not survive a failure response");
        }
        s.accept(Request::SessionStop(ChargingSession::Terminate)).unwrap();
        assert!(s.is_finished());
    }

    /// A vehicle aborts. Refusing the stop would leave the session to time out
    /// instead of ending cleanly.
    #[test]
    fn a_session_can_be_stopped_from_any_established_phase() {
        for setup in [
            &[Request::SessionSetup][..],
            &[Request::SessionSetup, Request::ServiceDiscovery],
            &[
                Request::SessionSetup,
                Request::ServiceDiscovery,
                Request::PaymentServiceSelection(EIM),
                Request::Authorization,
                Request::ChargeParameterDiscovery(DC),
                Request::CableCheck,
            ],
        ] {
            let mut s = run(setup).unwrap();
            let phase = s.phase();
            s.accept(Request::SessionStop(ChargingSession::Terminate))
                .unwrap_or_else(|e| panic!("stopping from {phase:?}: {e}"));
        }
        // ...but there is no session to stop before there is a session.
        assert!(
            !Sequencer::new(Security::Tls)
                .permits(Request::SessionStop(ChargingSession::Terminate))
        );
    }

    #[test]
    fn a_paused_session_is_finished_but_not_terminated() {
        let mut s = up_to_authorized(EIM);
        s.accept(Request::ChargeParameterDiscovery(AC)).unwrap();
        s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap();
        s.accept(Request::PowerDelivery(ChargeProgress::Stop)).unwrap();
        s.accept(Request::SessionStop(ChargingSession::Pause)).unwrap();
        assert!(s.is_finished());
        assert!(s.is_paused(), "a pause keeps the session id for a later resume");
    }

    /// \[V2G2-634\], \[V2G2-635\]: Plug & Charge is not available without TLS.
    ///
    /// The contract certificate chain, the signature over the authorization and
    /// the EMAID all hang off this one selection, so refusing it is where the
    /// rule becomes enforceable — and everything it would have put on a
    /// plaintext wire stays off it.
    #[test]
    fn a_contract_cannot_be_selected_over_an_unsecured_transport() {
        let mut plain =
            run_with(Security::None, &[Request::SessionSetup, Request::ServiceDiscovery])
                .expect("the session itself is fine");

        assert!(
            !plain.permits(Request::PaymentServiceSelection(PNC)),
            "a contract over plaintext is what [V2G2-634] forbids"
        );
        let e = plain.accept(Request::PaymentServiceSelection(PNC)).unwrap_err();
        assert_eq!(e.got, "PaymentServiceSelectionReq");
        assert_eq!(e.response_code, ResponseCode::FAILEDSequenceError as u8);
        assert_eq!(plain.phase(), Phase::ServiceDiscovery, "a refusal does not advance");

        // External identification is exactly what such a session is left with.
        assert!(plain.permits(Request::PaymentServiceSelection(EIM)));
        plain.accept(Request::PaymentServiceSelection(EIM)).unwrap();
        plain.accept(Request::Authorization).unwrap();

        // ...and with TLS the same selection is the ordinary one.
        let mut secured =
            run_with(Security::Tls, &[Request::SessionSetup, Request::ServiceDiscovery]).unwrap();
        assert!(secured.permits(Request::PaymentServiceSelection(PNC)));
        secured.accept(Request::PaymentServiceSelection(PNC)).unwrap();
        assert!(secured.permits(Request::PaymentDetails));
    }

    /// The rule is about the *contract*, not about the certificate flows in
    /// general: without a contract selected they were already unreachable, so
    /// nothing else in the graph needs a second condition.
    #[test]
    fn an_unsecured_session_reaches_no_part_of_the_contract_flow() {
        let mut plain =
            run_with(Security::None, &[Request::SessionSetup, Request::ServiceDiscovery]).unwrap();
        plain.accept(Request::PaymentServiceSelection(EIM)).unwrap();
        for request in
            [Request::PaymentDetails, Request::CertificateInstallation, Request::CertificateUpdate]
        {
            assert!(!plain.permits(request), "{request:?} needs a contract, and there is none");
        }
        assert_eq!(plain.security(), Security::None);
    }

    /// §8.4.1 permits a pause only "after sending `PowerDeliveryReq` with
    /// `ChargeProgress` equal to 'Stop'", and \[V2G2-739\] has the pause take the
    /// transport connection down with it. So a pause accepted while the cable
    /// is live ends the conversation with the contactors closed and the link at
    /// battery voltage — power flowing with nobody talking about it.
    #[test]
    fn a_pause_is_refused_while_the_cable_is_live() {
        let live = |steps: &[Request]| {
            let mut s = up_to_authorized(EIM);
            for &r in steps {
                s.accept(r).unwrap();
            }
            let phase = s.phase();
            assert!(
                !s.permits(Request::SessionStop(ChargingSession::Pause)),
                "pausing from {phase:?} would leave the power on"
            );
            // Stopping outright is still always available.
            assert!(s.permits(Request::SessionStop(ChargingSession::Terminate)));
            s
        };

        live(&[Request::ChargeParameterDiscovery(DC), Request::CableCheck]);
        live(&[Request::ChargeParameterDiscovery(DC), Request::CableCheck, Request::PreCharge]);
        let mut s = live(&[
            Request::ChargeParameterDiscovery(AC),
            Request::PowerDelivery(ChargeProgress::Start),
        ]);

        // Stopping power delivery is what unlocks it.
        s.accept(Request::PowerDelivery(ChargeProgress::Stop)).unwrap();
        assert!(s.permits(Request::SessionStop(ChargingSession::Pause)));
    }

    /// \[V2G2-601\]: after `PowerDeliveryRes` for `ChargeProgress = Stop`, a DC
    /// session may go back to `ChargeParameterDiscoveryReq` as well as to
    /// welding detection and the session stop — a second charge under a new
    /// schedule, without dropping the session.
    ///
    /// The way back up must not demand the isolation test again: the contactors
    /// never opened, so a cable check would be asking a connected vehicle to
    /// prove its cable is not connected. Refusing `PowerDelivery(Start)` there
    /// is what would strand it.
    #[test]
    fn dc_can_renegotiate_after_stopping_power() {
        let mut s = up_to_authorized(EIM);
        for r in [
            Request::ChargeParameterDiscovery(DC),
            Request::CableCheck,
            Request::PreCharge,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::CurrentDemand,
            Request::PowerDelivery(ChargeProgress::Stop),
        ] {
            s.accept(r).unwrap();
        }
        assert_eq!(s.phase(), Phase::PowerStopped);
        assert!(!s.has_renegotiated());

        assert_eq!(
            s.accept(Request::ChargeParameterDiscovery(DC)).unwrap(),
            Phase::ChargeParameters
        );
        assert!(s.has_renegotiated(), "the safety phases are behind us");
        // ...so power may resume without repeating them. A cable check is
        // still *offered* — \[V2G2-582\] names it after every DC
        // `ChargeParameterDiscoveryRes` — but it is no longer demanded, and
        // demanding it is what would strand the vehicle.
        s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap();
        assert_eq!(s.phase(), Phase::Charging);

        // AC has no such rule: [V2G2-568] leaves only SessionStopReq.
        let mut ac = up_to_authorized(EIM);
        ac.accept(Request::ChargeParameterDiscovery(AC)).unwrap();
        ac.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap();
        ac.accept(Request::PowerDelivery(ChargeProgress::Stop)).unwrap();
        assert!(!ac.permits(Request::ChargeParameterDiscovery(AC)));
    }

    /// \[V2G2-797\]: a DC metering receipt also leaves
    /// `ChargeParameterDiscoveryReq` open, straight out of the charge loop.
    #[test]
    fn dc_can_renegotiate_from_the_charge_loop_under_a_contract() {
        let mut s = up_to_authorized(PNC);
        for r in [
            Request::ChargeParameterDiscovery(DC),
            Request::CableCheck,
            Request::PreCharge,
            Request::PowerDelivery(ChargeProgress::Start),
            Request::CurrentDemand,
            Request::MeteringReceipt,
        ] {
            s.accept(r).unwrap();
        }
        assert_eq!(
            s.accept(Request::ChargeParameterDiscovery(DC)).unwrap(),
            Phase::ChargeParameters
        );
        assert!(s.has_renegotiated());
        s.accept(Request::PowerDelivery(ChargeProgress::Start)).unwrap();
    }

    /// \[V2G2-554\], \[V2G2-557\] and \[V2G2-558\] leave `PaymentDetailsReq` as
    /// the only legal request after a certificate exchange, whichever way it
    /// went.
    ///
    /// Worth being strict about rather than lenient: `CertificateInstallationReq`
    /// reaches the CPO's certificate pool, so a peer that could repeat it
    /// indefinitely — every request legal, the sequence timer restarting on each
    /// one — would hold the session open and keep the backend working without
    /// ever presenting a credential.
    #[test]
    fn a_certificate_exchange_happens_once_and_leads_to_payment_details() {
        let mut s = run(&[
            Request::SessionSetup,
            Request::ServiceDiscovery,
            Request::PaymentServiceSelection(PNC),
        ])
        .unwrap();
        s.accept(Request::CertificateInstallation).unwrap();
        assert_eq!(s.phase(), Phase::CertificateInstalled);
        assert!(!s.permits(Request::CertificateInstallation), "once is once");
        assert!(!s.permits(Request::CertificateUpdate));
        assert!(!s.permits(Request::Authorization), "credentials come first");
        assert!(s.permits(Request::PaymentDetails));
        s.accept(Request::PaymentDetails).unwrap();
        s.accept(Request::Authorization).unwrap();
    }

    /// A loop budget is not a per-message timeout: it bounds a phase the peer
    /// repeats, and the phases that are not loops must have none — a bound on
    /// the charge loop would end a session that is working.
    #[test]
    fn only_the_loops_have_a_loop_budget() {
        use crate::session::Role::{Evcc, Secc};
        use crate::session::timers::iso2 as t;
        assert_eq!(Phase::CableCheck.loop_timeout(Evcc), Some(t::EVCC_CABLE_CHECK_TIMEOUT));
        assert_eq!(Phase::PreCharge.loop_timeout(Evcc), Some(t::EVCC_PRE_CHARGE_TIMEOUT));
        assert_eq!(Phase::Authorized.loop_timeout(Evcc), Some(t::EVCC_ONGOING_TIMEOUT));
        assert_eq!(Phase::ChargeParameters.loop_timeout(Evcc), Some(t::EVCC_ONGOING_TIMEOUT));
        assert_eq!(Phase::WeldingDetection.loop_timeout(Evcc), Some(t::EVCC_ONGOING_TIMEOUT));
        for phase in [Phase::Start, Phase::SessionSetup, Phase::Charging, Phase::Stopped] {
            for role in [Evcc, Secc] {
                assert_eq!(phase.loop_timeout(role), None, "{phase:?} is not a loop for {role}");
            }
        }
        // Pre-charge is the tightest: the link either reaches the battery's
        // voltage quickly or it is not going to.
        assert!(
            Phase::PreCharge.loop_timeout(Evcc) < Phase::CableCheck.loop_timeout(Evcc),
            "an isolation test takes longer than a voltage match"
        );
    }

    /// The station's budget for a loop is the shorter half of every pair, and
    /// that is the whole reason there are two: at 55 s the station is obliged
    /// to answer `FAILED` \[V2G2-713\], and a station carrying the vehicle's
    /// 60 s could only ever reach its deadline after the vehicle had already
    /// abandoned the session — a timer that can never fire in time to say
    /// anything.
    #[test]
    fn the_station_decides_before_the_vehicle_gives_up() {
        use crate::session::Role::{Evcc, Secc};
        for phase in [
            Phase::Authorized,
            Phase::ChargeParameters,
            Phase::WeldingDetection,
            Phase::CableCheck,
            Phase::PreCharge,
        ] {
            let (evcc, secc) = (phase.loop_timeout(Evcc), phase.loop_timeout(Secc));
            assert!(secc < evcc, "{phase:?}: station {secc:?} must close before vehicle {evcc:?}");
        }
    }

    #[test]
    fn the_dc_charge_loop_gets_the_tight_timeout() {
        use crate::session::timers::iso2 as t;
        assert_eq!(Request::CurrentDemand.response_timeout(), t::MSG_TIMEOUT_CURRENT_DEMAND);
        assert_eq!(Request::PaymentDetails.response_timeout(), t::MSG_TIMEOUT_BACKEND);
        assert_eq!(
            Request::SessionStop(ChargingSession::Terminate).response_timeout(),
            t::MSG_TIMEOUT_DEFAULT
        );
    }
}
