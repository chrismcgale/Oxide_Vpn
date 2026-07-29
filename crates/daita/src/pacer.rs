//! Adaptive pacing for DAITA (Sprint 4A — maybenot-flavoured, first step).
//!
//! DAITA v1 emits exactly one cell per **fixed** slot: a flat, constant-rate stream that leaks
//! nothing about timing but pays the full `cell_size/slot` bandwidth every direction, always.
//! This is a small **state machine** that instead decides the *delay* before each cell, so the
//! cadence can adapt to traffic. Two changes over constant-rate:
//!
//!   * **randomized timing** — each delay is jittered (±25%), so there is no fixed inter-cell
//!     interval for an ML classifier to lock onto, at the *same average* rate while active.
//!   * **idle taper** — after a run of cover-only cells (nothing real to send) the cadence slows
//!     toward `slot * max_mult`, cutting the constant-bandwidth cost of an idle tunnel.
//!
//! **Honest trade:** the idle taper leaks the coarse active/idle *envelope* — an observer sees
//! the rate change when you start/stop sending. Constant-rate leaks nothing but always costs;
//! this trades a little leakage for a lot less idle cost, the classic maybenot cost/leak knob.
//! Keep constant-rate ([`crate::Shaper`] driven by a fixed slot) when you want zero envelope
//! leak. Pure and deterministic in its *state* logic (only the jitter uses the OS RNG), so the
//! transitions are unit-tested.

use std::time::Duration;

use rand_core::{OsRng, RngCore};

/// Consecutive cover cells (nothing real to send) before the pacer starts tapering to idle.
pub const DEFAULT_IDLE_AFTER: u32 = 8;
/// The idle cadence caps at `slot * DEFAULT_MAX_MULT`.
pub const DEFAULT_MAX_MULT: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Real traffic recently — pace at ~`slot` to keep it hidden in a steady stream.
    Active,
    /// A run of idle (cover-only) slots — taper the cadence to cut cost.
    Idle,
}

/// The adaptive pacing state machine. Feed back whether each emitted cell carried real data via
/// [`Pacer::next_delay`], which returns the (jittered) delay before the next cell.
pub struct Pacer {
    slot: Duration,
    idle_after: u32,
    max_mult: u32,
    state: State,
    consecutive_covers: u32,
}

impl Pacer {
    pub fn new(slot: Duration, idle_after: u32, max_mult: u32) -> Self {
        Pacer {
            slot,
            idle_after: idle_after.max(1),
            max_mult: max_mult.max(1),
            state: State::Active,
            consecutive_covers: 0,
        }
    }

    /// Adaptive pacer with the default idle threshold + cap.
    pub fn with_defaults(slot: Duration) -> Self {
        Self::new(slot, DEFAULT_IDLE_AFTER, DEFAULT_MAX_MULT)
    }

    /// Transition on what the just-emitted cell carried, and return the (jittered) delay before
    /// the next cell. A real cell resets to `Active` (pace at ~`slot`); a run of cover cells past
    /// `idle_after` enters `Idle` and grows the cadence toward `slot * max_mult`.
    pub fn next_delay(&mut self, last_was_real: bool) -> Duration {
        if last_was_real {
            self.consecutive_covers = 0;
            self.state = State::Active;
        } else {
            self.consecutive_covers = self.consecutive_covers.saturating_add(1);
            if self.consecutive_covers >= self.idle_after {
                self.state = State::Idle;
            }
        }
        let mult = match self.state {
            State::Active => 1,
            // Grow with how long we've been idle (1 at the threshold), capped at max_mult.
            State::Idle => self
                .consecutive_covers
                .saturating_sub(self.idle_after)
                .saturating_add(1)
                .min(self.max_mult),
        };
        jitter(self.slot.saturating_mul(mult))
    }
}

/// Apply ±25% uniform jitter to `d` (using the OS RNG), floored at 1µs so a delay is never zero.
fn jitter(d: Duration) -> Duration {
    let base = d.as_micros() as u64;
    if base == 0 {
        return Duration::from_micros(1);
    }
    let quarter = (base / 4).max(1);
    // delta ∈ [0, 2*quarter] → result ∈ [base - quarter, base + quarter].
    let delta = OsRng.next_u64() % (2 * quarter + 1);
    Duration::from_micros((base + delta - quarter).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT: Duration = Duration::from_millis(10);

    /// A delay must be within ±25% of `slot * mult`.
    fn within_jitter(d: Duration, mult: u32) -> bool {
        let base = SLOT.as_micros() as u64 * mult as u64;
        let lo = base - base / 4;
        let hi = base + base / 4;
        let us = d.as_micros() as u64;
        us >= lo && us <= hi
    }

    #[test]
    fn real_traffic_paces_at_the_active_slot() {
        let mut p = Pacer::with_defaults(SLOT);
        for _ in 0..20 {
            let d = p.next_delay(true);
            assert!(within_jitter(d, 1), "active cadence is ~slot: {d:?}");
        }
    }

    #[test]
    fn taper_kicks_in_only_after_the_idle_threshold() {
        let mut p = Pacer::new(SLOT, 4, 8);
        // The first `idle_after` covers are still ~slot (grace before tapering).
        for _ in 0..4 {
            assert!(within_jitter(p.next_delay(false), 1));
        }
        // Past the threshold the cadence starts growing (mult >= 2).
        let d = p.next_delay(false);
        assert!(
            d.as_micros() as u64 >= SLOT.as_micros() as u64 * 2 - SLOT.as_micros() as u64 / 2,
            "past the threshold the delay grows: {d:?}"
        );
    }

    #[test]
    fn idle_cadence_grows_and_caps_at_max_mult() {
        let mut p = Pacer::new(SLOT, 2, 5);
        let mut last = Duration::ZERO;
        for _ in 0..50 {
            last = p.next_delay(false);
        }
        // Deep idle sits at the cap (slot * max_mult), within jitter.
        assert!(
            within_jitter(last, 5),
            "idle cadence caps at slot*max_mult: {last:?}"
        );
    }

    #[test]
    fn a_real_cell_snaps_back_to_active() {
        let mut p = Pacer::new(SLOT, 2, 8);
        for _ in 0..30 {
            p.next_delay(false); // drive deep into idle
        }
        // One real cell resets to the active cadence immediately.
        let d = p.next_delay(true);
        assert!(
            within_jitter(d, 1),
            "real traffic snaps back to ~slot: {d:?}"
        );
    }
}
