//! Engine-side DAITA configuration: how a running engine shapes and frames its traffic.
//!
//! The pure cell codec, shaper queue, and pacing state machine live in the [`oxide_daita`]
//! crate; this type wires them to the engine (see [`crate::Engine::with_daita`]). Two roles:
//!
//!   * [`Daita::shaping`] — runs a per-peer shaper: every real outbound datagram is queued
//!     and drained one cell per paced slot, with cover cells filling idle slots, so the flow
//!     toward that peer becomes a steady, contentless stream of fixed-size cells. Both the
//!     **client** (toward its server) and the **server** (toward every connected client) use
//!     this, so *both directions* are shaped — bidirectional cover, Sprint 4A. The cadence
//!     comes from a [`oxide_daita::machine::Machine`] (constant-rate or adaptive).
//!   * [`Daita::framing`] — a lighter role that only *speaks* the cell format: it wraps each
//!     outbound datagram as a fixed-size real cell and drops inbound cover, but generates no
//!     cover or paced rate (size-normalized but reactive). Kept for size-only normalization;
//!     the shaping roles are the full defense.
//!
//! Cells ride *inside* the obfs frame, so DAITA requires a stealth transport
//! (`Transport::Obfuscated` / `QuicMimic` / `Mimic`) — the shared key is what lets the peer
//! recognize and drop cover. Every wrapping layer costs MTU; see the [`oxide_daita`] docs
//! for the constant-bandwidth trade-off.

use std::time::Duration;

use oxide_daita::machine::Machine;
use oxide_daita::{DEFAULT_CELL_SIZE, DEFAULT_MAX_QUEUE, DEFAULT_SLOT_MS};

/// DAITA settings attached to an [`crate::Engine`] via [`crate::Engine::with_daita`].
pub struct Daita {
    pub(crate) cell_size: usize,
    /// Bound on each peer's pending-real-datagram queue.
    pub(crate) max_queue: usize,
    /// When true this engine runs the shaper task: it drains each peer's [per-peer shaper]
    /// (`crate::peer::Peer::shaper`) into a paced cell stream (+ cover) to that peer's endpoint —
    /// so a **server** shapes toward every client, not just a client toward its server
    /// (bidirectional, 4A). When false it only frames outbound cells and drops inbound cover.
    pub(crate) shape_egress: bool,
    /// The pacing state-machine **template** (Sprint 4A). `Some` iff `shape_egress`; the shaper
    /// task clones a fresh copy per peer so each peer's cover stream has independent state.
    /// Constant-rate DAITA is a single-state machine, adaptive a multi-state one.
    pub(crate) machine: Option<Machine>,
}

impl Daita {
    fn shaping_with(cell_size: usize, machine: Machine) -> Self {
        Daita {
            cell_size,
            max_queue: DEFAULT_MAX_QUEUE,
            shape_egress: true,
            machine: Some(machine),
        }
    }

    /// Client role: shape egress to a constant rate with cover traffic (a single-state machine).
    pub fn shaping(cell_size: usize, slot: Duration) -> Self {
        Self::shaping_with(cell_size, Machine::constant_rate(slot))
    }

    /// Client role with the **adaptive** machine (4A): jittered timing + an idle taper instead of
    /// a fixed slot. Trades a little active/idle envelope leakage for much less idle cost; see the
    /// [`oxide_daita::machine`] docs.
    pub fn shaping_adaptive(cell_size: usize, slot: Duration) -> Self {
        Self::shaping_with(cell_size, Machine::adaptive_default(slot))
    }

    /// Framing-only role: wrap egress cells + drop inbound cover, but generate no cover or paced
    /// rate. A lighter, size-only normalization (no bandwidth floor); prefer the shaping roles for
    /// the full defense.
    pub fn framing(cell_size: usize) -> Self {
        Daita {
            cell_size,
            max_queue: DEFAULT_MAX_QUEUE,
            shape_egress: false,
            machine: None,
        }
    }

    /// Client role with default cell size and slot cadence (constant-rate).
    pub fn client() -> Self {
        Self::shaping(DEFAULT_CELL_SIZE, Duration::from_millis(DEFAULT_SLOT_MS))
    }

    /// Client role with default cell size + the **adaptive** machine (4A).
    pub fn client_adaptive() -> Self {
        Self::shaping_adaptive(DEFAULT_CELL_SIZE, Duration::from_millis(DEFAULT_SLOT_MS))
    }

    /// Server role: **shape toward every peer** (bidirectional cover, constant-rate). The shaper
    /// task drains each client's per-peer queue into a paced cell stream to that client.
    pub fn server() -> Self {
        Self::shaping(DEFAULT_CELL_SIZE, Duration::from_millis(DEFAULT_SLOT_MS))
    }

    /// Server role with the **adaptive** machine (4A) toward every peer.
    pub fn server_adaptive() -> Self {
        Self::shaping_adaptive(DEFAULT_CELL_SIZE, Duration::from_millis(DEFAULT_SLOT_MS))
    }
}
