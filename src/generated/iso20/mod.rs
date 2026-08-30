//! ISO 15118-20 message types, generated from the V2G XSD schemas.
//!
//! Each of the five schema sets is its own EXI document with its own document
//! grammar — and its own V2GTP payload type — so each gets a module. They all
//! import `CommonTypes`, which is generated once into
//! [`common`](crate::iso20::common) and referred
//! to from the others, so a `RationalNumber` is the same Rust type everywhere.
//!
//! | Module | Schema | V2GTP payload type |
//! |---|---|---|
//! | [`messages`](crate::iso20::messages) | `CommonMessages` | `0x8002` |
//! | [`ac`](crate::iso20::ac) | `AC` | `0x8003` |
//! | [`dc`](crate::iso20::dc) | `DC` | `0x8004` |
//! | [`acdp`](crate::iso20::acdp) | `ACDP` | `0x8005` |
//! | [`wpt`](crate::iso20::wpt) | `WPT` | `0x8006` |

/// Types shared by every ISO 15118-20 schema.
pub mod common;

#[cfg(feature = "iso20-common")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso20-common")))]
/// ISO 15118-20 `CommonMessages`: session setup, authorization, service
/// discovery and selection, schedule exchange, power delivery, session stop.
pub mod messages;

#[cfg(feature = "iso20-ac")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso20-ac")))]
/// ISO 15118-20 AC charging: charge parameter discovery and the AC charge
/// loop, including bidirectional power transfer.
pub mod ac;

#[cfg(feature = "iso20-dc")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso20-dc")))]
/// ISO 15118-20 DC charging: cable check, pre-charge, the DC charge loop and
/// welding detection, including bidirectional power transfer.
pub mod dc;

#[cfg(feature = "iso20-wpt")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso20-wpt")))]
/// ISO 15118-20 wireless power transfer: alignment check, fine positioning
/// and the WPT charge loop.
pub mod wpt;

#[cfg(feature = "iso20-acdp")]
#[cfg_attr(docsrs, doc(cfg(feature = "iso20-acdp")))]
/// ISO 15118-20 automated connection device (pantograph): vehicle
/// positioning, connect and disconnect.
pub mod acdp;
