//! Engine-side DAITA configuration: how a running engine shapes and frames its traffic.
//!
//! The pure cell codec and shaping decision live in the [`oxide_daita`] crate; this type
//! wires them to the engine (see [`crate::Engine::with_daita`]). Two roles:
//!
//!   * [`Daita::shaping`] (the **client**, v1 egress target) — runs a constant-rate shaper:
//!     every real outbound datagram is queued and drained one cell per slot, with cover
//!     cells filling idle slots. The client→server flow becomes a steady, contentless
//!     stream of fixed-size cells.
//!   * [`Daita::framing`] (the **server**, or any peer that only needs to *speak* the cell
//!     format) — wraps each outbound datagram as a fixed-size real cell so the shaping peer
//!     can parse it, and drops inbound cover, but does not generate cover or a constant
//!     rate. So server→client is size-normalized but reactive; bidirectional rate shaping
//!     is Sprint 4A.
//!
//! Cells ride *inside* the obfs frame, so DAITA requires a stealth transport
//! (`Transport::Obfuscated` / `QuicMimic` / `Mimic`) — the shared key is what lets the peer
//! recognize and drop cover. Every wrapping layer costs MTU; see the [`oxide_daita`] docs
//! for the constant-bandwidth trade-off.

use std::sync::Mutex;
use std::time::Duration;

use oxide_daita::pacer::Pacer;
use oxide_daita::{Shaper, DEFAULT_CELL_SIZE, DEFAULT_MAX_QUEUE, DEFAULT_SLOT_MS};

/// DAITA settings attached to an [`crate::Engine`] via [`crate::Engine::with_daita`].
pub struct Daita {
    pub(crate) cell_size: usize,
    pub(crate) slot: Duration,
    /// When true this engine runs the constant-rate shaper (client egress). When false it
    /// only frames outbound cells and drops inbound cover (server/reactive side).
    pub(crate) shape_egress: bool,
    pub(crate) shaper: Shaper,
    /// Adaptive pacing (Sprint 4A): when set, the shaper task paces cells by this state machine
    /// (jittered timing + idle taper) instead of the fixed `slot`. `None` = constant-rate DAITA.
    /// Behind a `Mutex` since `next_delay` mutates and the shaper task holds the `Daita` via `Arc`.
    pub(crate) pacer: Option<Mutex<Pacer>>,
}

impl Daita {
    /// Client role: shape egress to a constant rate with cover traffic.
    pub fn shaping(cell_size: usize, slot: Duration) -> Self {
        Daita {
            cell_size,
            slot,
            shape_egress: true,
            shaper: Shaper::new(cell_size, DEFAULT_MAX_QUEUE),
            pacer: None,
        }
    }

    /// Client role with **adaptive** pacing (4A): jittered timing + idle taper via [`Pacer`]
    /// instead of a fixed slot. Trades a little active/idle envelope leakage for much less idle
    /// cost; see the [`oxide_daita::pacer`] docs.
    pub fn shaping_adaptive(cell_size: usize, slot: Duration) -> Self {
        Daita {
            pacer: Some(Mutex::new(Pacer::with_defaults(slot))),
            ..Self::shaping(cell_size, slot)
        }
    }

    /// Server role: speak the cell framing (wrap egress, drop inbound cover) without
    /// generating cover or a constant rate.
    pub fn framing(cell_size: usize) -> Self {
        Daita {
            cell_size,
            // Unused in framing mode (no shaper task), but kept sensible.
            slot: Duration::from_millis(DEFAULT_SLOT_MS),
            shape_egress: false,
            shaper: Shaper::new(cell_size, DEFAULT_MAX_QUEUE),
            pacer: None,
        }
    }

    /// Client role with default cell size and slot cadence (constant-rate).
    pub fn client() -> Self {
        Self::shaping(DEFAULT_CELL_SIZE, Duration::from_millis(DEFAULT_SLOT_MS))
    }

    /// Client role with default cell size + **adaptive** pacing (4A).
    pub fn client_adaptive() -> Self {
        Self::shaping_adaptive(DEFAULT_CELL_SIZE, Duration::from_millis(DEFAULT_SLOT_MS))
    }

    /// Server role with the default cell size.
    pub fn server() -> Self {
        Self::framing(DEFAULT_CELL_SIZE)
    }
}
