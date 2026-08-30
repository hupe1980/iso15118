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
//! use iso15118::session::iso2::{Request, Sequencer};
//! use iso15118::iso2::{ChargeProgress, EnergyTransferMode, PaymentOption};
//!
//! let mut s = Sequencer::new();
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

use crate::iso2::{
    ChargeProgress, ChargingSession, EnergyTransferMode, PaymentOption, ResponseCode,
};

use super::SequenceError;

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
    /// (ISO 15118-2 Table 105).
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
    /// isolation test that will never finish \[V2G2-716\]..\[V2G2-718\].
    ///
    /// `None` for the phases that are not loops, and for `Charging` — a charge
    /// loop runs as long as the vehicle wants it to.
    #[must_use]
    pub const fn loop_timeout(self) -> Option<super::Millis> {
        use super::timers::iso2 as t;
        Some(match self {
            // The DC safety phases have budgets of their own, and they are much
            // tighter than the general one: an isolation test that has not
            // finished in forty seconds has failed, and a pre-charge that has
            // not matched the battery voltage in seven is not going to.
            Self::CableCheck => t::EVCC_CABLE_CHECK_TIMEOUT,
            Self::PreCharge => t::EVCC_PRE_CHARGE_TIMEOUT,
            // Everything else that can answer `..._Ongoing`: authorization
            // waiting on a backend or a driver, parameter discovery waiting on
            // a schedule, welding detection waiting on the contactors to open.
            Self::Authorized | Self::ChargeParameters | Self::WeldingDetection => {
                t::EVCC_ONGOING_TIMEOUT
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
#[derive(Debug, Clone)]
pub struct Sequencer {
    phase: Phase,
    transfer: Option<Transfer>,
    payment: Option<PaymentOption>,
    /// Set by a `PowerDeliveryReq(Renegotiate)`.
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
        Self {
            phase: Phase::Start,
            transfer: None,
            payment: None,
            renegotiated: false,
            failed: false,
        }
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
            Request::PowerDelivery(ChargeProgress::Renegotiate) => self.renegotiated = true,
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
                (_, R::SessionStop(S::Pause)) => Some(F::Paused),
                _ => None,
            };
        }

        Some(match (self.phase, request) {
            (F::Start, R::SessionSetup) => F::SessionSetup,
            (F::SessionSetup, R::ServiceDiscovery) => F::ServiceDiscovery,

            // `ServiceDetail` is optional and repeatable; the EVCC asks about
            // as many of the advertised services as it cares to.
            (F::ServiceDiscovery, R::ServiceDetail) => F::ServiceDiscovery,
            (F::ServiceDiscovery, R::PaymentServiceSelection(_)) => F::ServiceSelected,

            // With a contract, credentials come next — optionally preceded by
            // installing or updating that contract certificate. With external
            // identification there is nothing to present.
            (F::ServiceSelected, R::CertificateInstallation | R::CertificateUpdate) if contract => {
                F::ServiceSelected
            }
            (F::ServiceSelected, R::PaymentDetails) if contract => F::PaymentDetails,
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
            // contract, acknowledging the signed meter readings.
            (F::Charging, R::ChargingStatus) if !dc => F::Charging,
            (F::Charging, R::CurrentDemand) if dc => F::Charging,
            (F::Charging, R::MeteringReceipt) if contract => F::Charging,
            // Renegotiation goes back for new parameters without dropping the
            // session — a tariff change, or the EV revising its target.
            (F::Charging, R::PowerDelivery(P::Renegotiate)) => F::ChargeParameters,
            (F::Charging, R::PowerDelivery(P::Stop)) => F::PowerStopped,

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
            (_, R::SessionStop(S::Pause)) => F::Paused,

            _ => return None,
        })
    }

    /// How long the session may stay in its current phase.
    ///
    /// See [`Phase::loop_timeout`]; this is that value for the phase the
    /// session is in.
    #[must_use]
    pub const fn loop_timeout(&self) -> Option<super::Millis> {
        self.phase.loop_timeout()
    }

    /// The name of the current phase, for logs and errors.
    #[must_use]
    pub const fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::Start => "Start",
            Phase::SessionSetup => "SessionSetup",
            Phase::ServiceDiscovery => "ServiceDiscovery",
            Phase::ServiceSelected => "ServiceSelected",
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
        let mut s = Sequencer::new();
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
        let s = Sequencer::new();
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
        assert!(!Sequencer::new().permits(Request::SessionStop(ChargingSession::Terminate)));
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

    /// A loop budget is not a per-message timeout: it bounds a phase the peer
    /// repeats, and the phases that are not loops must have none — a bound on
    /// the charge loop would end a session that is working.
    #[test]
    fn only_the_loops_have_a_loop_budget() {
        use crate::session::timers::iso2 as t;
        assert_eq!(Phase::CableCheck.loop_timeout(), Some(t::EVCC_CABLE_CHECK_TIMEOUT));
        assert_eq!(Phase::PreCharge.loop_timeout(), Some(t::EVCC_PRE_CHARGE_TIMEOUT));
        assert_eq!(Phase::Authorized.loop_timeout(), Some(t::EVCC_ONGOING_TIMEOUT));
        assert_eq!(Phase::ChargeParameters.loop_timeout(), Some(t::EVCC_ONGOING_TIMEOUT));
        assert_eq!(Phase::WeldingDetection.loop_timeout(), Some(t::EVCC_ONGOING_TIMEOUT));
        for phase in [Phase::Start, Phase::SessionSetup, Phase::Charging, Phase::Stopped] {
            assert_eq!(phase.loop_timeout(), None, "{phase:?} is not a loop");
        }
        // Pre-charge is the tightest: the link either reaches the battery's
        // voltage quickly or it is not going to.
        assert!(
            Phase::PreCharge.loop_timeout() < Phase::CableCheck.loop_timeout(),
            "an isolation test takes longer than a voltage match"
        );
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
