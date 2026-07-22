//! DAITA — Defence Against AI-guided Traffic Analysis (v1).
//!
//! The obfuscation layer ([`oxide_obfs`]) already normalizes the *size* of each datagram
//! into a few buckets. DAITA closes the two remaining traffic-analysis dimensions:
//!
//!   * **constant rate** — the sender emits exactly one **cell** every fixed slot, whether
//!     or not it has real data. A passive/ML observer (and even our own multihop entry)
//!     sees a steady, contentless stream: no bursts, no gaps, no packet-timing signal.
//!   * **constant size + cover** — every cell is padded to one fixed `cell_size`, and idle
//!     slots are filled with **cover** cells that are indistinguishable on the wire but
//!     recognized and dropped by the peer *before* boringtun ever sees them.
//!
//! ## Cell format (the plaintext handed to the obfs layer)
//! ```text
//! [ type: 1 ][ len: 2 BE ][ payload ][ random padding → cell_size ]
//! ```
//! `type` is [`REAL`] (carries a WireGuard datagram of `len` bytes) or [`COVER`] (`len` is
//! 0 and the whole body is padding). The cell is the *plaintext* the obfs frame wraps, so
//! the type byte and padding are never visible on the wire — the obfs ChaCha20 keystream
//! makes every cell a unique high-entropy blob, and because the cell is a fixed size the
//! obfs bucketing always lands on the same bucket: **one wire size for every cell**.
//! Recognizing/dropping cover therefore requires the shared obfs key — so DAITA v1 implies
//! stealth (obfuscation) is on.
//!
//! ## Cost (be honest)
//! This is a padding + constant-rate defence with a real, quantifiable price, not a
//! learned/adaptive framework (that is Sprint 4A — maybenot-style state machines). A
//! sender transmits `cell_size` bytes every slot regardless of demand:
//!   `throughput = cell_size * 8 / slot`  (e.g. 1440 B / 5 ms ≈ 2.3 Mbit/s each way).
//! That is the constant bandwidth floor *and* ceiling: an idle tunnel pays it in cover
//! traffic, and an app that wants to send faster than the slot rate queues and then drops
//! (the shaper's rate is the tunnel's ceiling). Pick `slot`/`cell_size` for the
//! rate/latency/overhead trade-off you want.

use std::collections::VecDeque;
use std::sync::Mutex;

use rand_core::{OsRng, RngCore};

/// Cell type tag: carries a real WireGuard datagram.
pub const REAL: u8 = 1;
/// Cell type tag: cover traffic — dropped by the peer, no WireGuard payload.
pub const COVER: u8 = 0;

/// `type(1) + len(2)` — the fixed cell header before the payload.
pub const HEADER: usize = 3;

/// Default cell size. Chosen so a full stealth-MTU WireGuard datagram fits (tunnel MTU
/// ~1380 + ~32 WG overhead = ~1412 ≤ [`max_payload`]) and the obfs frame
/// (`nonce 12 + len 2 + 1440 = 1454`) lands in the top obfs size bucket (1472), keeping
/// the datagram-plus-IPv4/UDP-headers within a 1500-byte path.
pub const DEFAULT_CELL_SIZE: usize = 1440;

/// Default slot cadence. One cell every 5 ms ≈ 2.3 Mbit/s of constant, contentless volume
/// per direction — a deliberate trade of bandwidth for a flat traffic profile.
pub const DEFAULT_SLOT_MS: u64 = 5;

/// How many pending real datagrams the shaper buffers before dropping the oldest. Bounds
/// added latency to `max_queue * slot`; beyond it the constant rate is the ceiling and
/// excess is shed (like any rate limiter).
pub const DEFAULT_MAX_QUEUE: usize = 1024;

/// The largest WireGuard datagram that fits in a cell of `cell_size`.
pub fn max_payload(cell_size: usize) -> usize {
    cell_size.saturating_sub(HEADER)
}

/// A decoded cell: either a real WireGuard datagram to hand to boringtun, or cover to drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cell {
    Real(Vec<u8>),
    Cover,
}

/// Frame a real WireGuard datagram into a fixed-size cell, or `None` if it doesn't fit
/// (`payload` longer than [`max_payload`] — a caller with a too-high MTU under DAITA).
pub fn frame_real(payload: &[u8], cell_size: usize) -> Option<Vec<u8>> {
    if cell_size < HEADER
        || payload.len() > max_payload(cell_size)
        || payload.len() > u16::MAX as usize
    {
        return None;
    }
    let mut cell = vec![0u8; cell_size];
    cell[0] = REAL;
    cell[1..HEADER].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    cell[HEADER..HEADER + payload.len()].copy_from_slice(payload);
    // Random padding so the pre-obfs plaintext carries no zero-run distinguisher.
    OsRng.fill_bytes(&mut cell[HEADER + payload.len()..]);
    Some(cell)
}

/// Frame a cover cell (all padding, no WireGuard payload).
pub fn frame_cover(cell_size: usize) -> Vec<u8> {
    let mut cell = vec![0u8; cell_size.max(HEADER)];
    cell[0] = COVER;
    // len stays 0; the rest is random padding.
    OsRng.fill_bytes(&mut cell[HEADER..]);
    cell
}

/// Decode a cell plaintext (recovered from the obfs layer). `None` for a malformed cell
/// (too short, bad type, or a `len` that overruns the buffer) — the caller drops it.
pub fn parse(cell: &[u8]) -> Option<Cell> {
    if cell.len() < HEADER {
        return None;
    }
    match cell[0] {
        COVER => Some(Cell::Cover),
        REAL => {
            let len = u16::from_be_bytes([cell[1], cell[2]]) as usize;
            if HEADER + len > cell.len() {
                return None;
            }
            Some(Cell::Real(cell[HEADER..HEADER + len].to_vec()))
        }
        _ => None,
    }
}

/// The pure shaping decision: a bounded queue of pending real datagrams drained one cell
/// per slot. All state is behind a `Mutex` (no async, no I/O) so it is trivially testable
/// and safe to share across the engine's tasks.
pub struct Shaper {
    cell_size: usize,
    max_queue: usize,
    queue: Mutex<VecDeque<Vec<u8>>>,
}

impl Shaper {
    pub fn new(cell_size: usize, max_queue: usize) -> Self {
        Shaper {
            cell_size,
            max_queue,
            queue: Mutex::new(VecDeque::new()),
        }
    }

    /// Queue a real WireGuard datagram for the next available slot. Returns `false` if it
    /// was dropped: oversized (won't fit a cell), or the queue was full (the oldest pending
    /// datagram is evicted to bound latency — the slot rate is the tunnel's ceiling).
    pub fn enqueue(&self, datagram: Vec<u8>) -> bool {
        if datagram.len() > max_payload(self.cell_size) {
            return false;
        }
        let mut q = self.queue.lock().unwrap();
        let dropped = if q.len() >= self.max_queue {
            q.pop_front();
            true
        } else {
            false
        };
        q.push_back(datagram);
        !dropped
    }

    /// Produce exactly one cell for this slot: the oldest queued real datagram if any,
    /// otherwise a cover cell. Always returns `cell_size` bytes.
    pub fn next_cell(&self) -> Vec<u8> {
        let datagram = self.queue.lock().unwrap().pop_front();
        match datagram {
            // frame_real only fails on oversize, which enqueue already rejects; fall back
            // to cover rather than ever emitting a wrong-sized cell.
            Some(d) => {
                frame_real(&d, self.cell_size).unwrap_or_else(|| frame_cover(self.cell_size))
            }
            None => frame_cover(self.cell_size),
        }
    }

    /// Number of real datagrams waiting (for tests / metrics).
    pub fn queued(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CELL: usize = 256;

    #[test]
    fn real_cell_roundtrips_and_is_fixed_size() {
        let payload = b"a wireguard datagram";
        let cell = frame_real(payload, CELL).unwrap();
        assert_eq!(cell.len(), CELL, "every cell is exactly cell_size");
        assert_eq!(parse(&cell), Some(Cell::Real(payload.to_vec())));
    }

    #[test]
    fn cover_cell_parses_as_cover_and_is_fixed_size() {
        let cell = frame_cover(CELL);
        assert_eq!(cell.len(), CELL);
        assert_eq!(parse(&cell), Some(Cell::Cover));
    }

    #[test]
    fn real_and_cover_are_the_same_size() {
        let real = frame_real(b"x", CELL).unwrap();
        let cover = frame_cover(CELL);
        assert_eq!(
            real.len(),
            cover.len(),
            "real and cover are indistinguishable by size"
        );
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let too_big = vec![0u8; max_payload(CELL) + 1];
        assert!(frame_real(&too_big, CELL).is_none());
    }

    #[test]
    fn empty_payload_roundtrips() {
        let cell = frame_real(b"", CELL).unwrap();
        assert_eq!(parse(&cell), Some(Cell::Real(vec![])));
    }

    #[test]
    fn malformed_cells_are_rejected() {
        assert_eq!(parse(&[]), None); // too short
        assert_eq!(parse(&[REAL, 0, 0]), Some(Cell::Real(vec![]))); // header-only real
                                                                    // A REAL cell claiming more payload than it carries is rejected.
        let mut bad = frame_real(b"hi", CELL).unwrap();
        bad[1..HEADER].copy_from_slice(&(CELL as u16).to_be_bytes());
        assert_eq!(parse(&bad), None);
        // Unknown type byte.
        let mut unknown = frame_cover(CELL);
        unknown[0] = 0x7f;
        assert_eq!(parse(&unknown), None);
    }

    #[test]
    fn shaper_emits_cover_when_idle() {
        let shaper = Shaper::new(CELL, DEFAULT_MAX_QUEUE);
        // No real traffic queued: every slot yields a fixed-size cover cell.
        for _ in 0..3 {
            let cell = shaper.next_cell();
            assert_eq!(cell.len(), CELL);
            assert_eq!(parse(&cell), Some(Cell::Cover));
        }
    }

    #[test]
    fn shaper_drains_real_then_covers_all_one_size() {
        let shaper = Shaper::new(CELL, DEFAULT_MAX_QUEUE);
        shaper.enqueue(b"one".to_vec());
        shaper.enqueue(b"two".to_vec());
        assert_eq!(shaper.queued(), 2);

        // Real datagrams drain in FIFO order...
        assert_eq!(
            parse(&shaper.next_cell()),
            Some(Cell::Real(b"one".to_vec()))
        );
        assert_eq!(
            parse(&shaper.next_cell()),
            Some(Cell::Real(b"two".to_vec()))
        );
        // ...then idle slots are cover.
        assert_eq!(parse(&shaper.next_cell()), Some(Cell::Cover));

        // Constant cadence: whatever the slot carries, the cell is always one size.
        shaper.enqueue(b"three".to_vec());
        assert_eq!(shaper.next_cell().len(), CELL);
        assert_eq!(shaper.next_cell().len(), CELL);
    }

    #[test]
    fn shaper_drops_oldest_when_queue_full() {
        let shaper = Shaper::new(CELL, 2);
        assert!(shaper.enqueue(b"a".to_vec()));
        assert!(shaper.enqueue(b"b".to_vec()));
        assert!(!shaper.enqueue(b"c".to_vec())); // full: evicts "a", reports a drop
        assert_eq!(shaper.queued(), 2);
        // "a" was evicted; "b" then "c" remain.
        assert_eq!(parse(&shaper.next_cell()), Some(Cell::Real(b"b".to_vec())));
        assert_eq!(parse(&shaper.next_cell()), Some(Cell::Real(b"c".to_vec())));
    }

    #[test]
    fn shaper_rejects_oversized_enqueue() {
        let shaper = Shaper::new(CELL, DEFAULT_MAX_QUEUE);
        assert!(!shaper.enqueue(vec![0u8; max_payload(CELL) + 1]));
        assert_eq!(shaper.queued(), 0);
    }
}
