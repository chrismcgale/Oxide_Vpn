//! A general maybenot-style **state machine** for DAITA cell pacing (Sprint 4A).
//!
//! This replaces the hard-coded two-state pacer with a data-defined machine: a set of
//! [`State`]s, each with a delay [`Dist`]ribution and event-driven [`transitions`](State::
//! transitions). The engine emits one cell per firing (a queued real datagram, else cover) and
//! feeds the machine what the cell carried; the machine transitions and samples the delay before
//! the next cell. This generalizes both DAITA v1's **constant rate** ([`Machine::constant_rate`]
//! — one `Constant` state) and the **adaptive** Active/Idle behaviour ([`Machine::adaptive`]),
//! and extends to arbitrary state graphs (bursts, multi-phase idle, etc.).
//!
//! It's the DAITA-cell analogue of maybenot's padding machines: states + sampled timers +
//! transitions on events. Pure — only [`Dist::sample`] touches the OS RNG — so the transition
//! logic is fully unit-tested. (Received-traffic events are a natural extension of [`Event`];
//! the engine currently feeds only the emit-side events.)

use std::time::Duration;

use rand_core::{OsRng, RngCore};

/// Consecutive cover cells before the default adaptive machine tapers from Active to Idle.
pub const DEFAULT_IDLE_AFTER: u64 = 8;
/// The default adaptive Idle cadence spans up to `slot * DEFAULT_MAX_MULT`.
pub const DEFAULT_MAX_MULT: u32 = 8;

/// A distribution the machine samples for a per-state inter-cell delay.
#[derive(Debug, Clone)]
pub enum Dist {
    /// Always exactly this duration (constant-rate).
    Constant(Duration),
    /// Uniformly random in `[min, max]` (randomized timing — no fixed interval to fingerprint).
    Uniform { min: Duration, max: Duration },
}

impl Dist {
    /// Sample a delay. Uses the OS RNG for `Uniform`.
    pub fn sample(&self) -> Duration {
        match self {
            Dist::Constant(d) => *d,
            Dist::Uniform { min, max } => {
                let lo = min.as_micros() as u64;
                let hi = (max.as_micros() as u64).max(lo);
                let us = if hi == lo {
                    lo
                } else {
                    lo + OsRng.next_u64() % (hi - lo + 1)
                };
                Duration::from_micros(us)
            }
        }
    }
}

/// What just happened, fed to the machine after each emitted cell to drive transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A real (data-carrying) cell was emitted.
    RealEmitted,
    /// A cover cell was emitted.
    CoverEmitted,
    /// The current state hit its consecutive-cover limit (takes precedence over `CoverEmitted`).
    LimitReached,
}

/// One state: how long to wait before the next cell here, an optional consecutive-cover limit,
/// and where to go on each event (first match wins; an unmatched event stays in this state).
#[derive(Debug, Clone)]
pub struct State {
    pub delay: Dist,
    /// After this many consecutive covers, synthesize a [`Event::LimitReached`] (`None` = never).
    pub cover_limit: Option<u64>,
    pub transitions: Vec<(Event, usize)>,
}

/// A pacing state machine: states + sampled delays + event-driven transitions.
pub struct Machine {
    states: Vec<State>,
    current: usize,
    consecutive_covers: u64,
}

impl Machine {
    /// Build a machine from its states (state 0 is the start). Out-of-range transition targets
    /// are clamped, so a machine can never step outside its own state set.
    pub fn new(states: Vec<State>) -> Self {
        assert!(!states.is_empty(), "a machine needs at least one state");
        Machine {
            states,
            current: 0,
            consecutive_covers: 0,
        }
    }

    /// Feed the just-emitted cell's kind, transition, and return the delay before the next cell.
    pub fn next_delay(&mut self, last_was_real: bool) -> Duration {
        let event = if last_was_real {
            self.consecutive_covers = 0;
            Event::RealEmitted
        } else {
            self.consecutive_covers += 1;
            let limit = self.states[self.current].cover_limit;
            if limit.is_some_and(|l| self.consecutive_covers >= l) {
                self.consecutive_covers = 0;
                Event::LimitReached
            } else {
                Event::CoverEmitted
            }
        };
        if let Some(next) = self.transition_for(event) {
            self.current = next;
        }
        self.states[self.current].delay.sample()
    }

    fn transition_for(&self, e: Event) -> Option<usize> {
        self.states[self.current]
            .transitions
            .iter()
            .find(|(ev, _)| *ev == e)
            .map(|(_, s)| (*s).min(self.states.len() - 1))
    }

    /// The constant-rate machine (DAITA v1): a single state, fixed `slot`, cover fills the gaps.
    pub fn constant_rate(slot: Duration) -> Self {
        Machine::new(vec![State {
            delay: Dist::Constant(slot),
            cover_limit: None,
            transitions: Vec::new(),
        }])
    }

    /// The adaptive machine: **Active** (jittered ±25% around `slot`) until `idle_after`
    /// consecutive covers, then **Idle** (sparse, uniformly random from `2*slot` up to
    /// `slot*max_mult`); a real cell snaps back to Active. Reproduces + generalizes the old pacer.
    pub fn adaptive(slot: Duration, idle_after: u64, max_mult: u32) -> Self {
        let q = slot / 4;
        let active = State {
            delay: Dist::Uniform {
                min: slot.saturating_sub(q),
                max: slot + q,
            },
            cover_limit: Some(idle_after.max(1)),
            transitions: vec![(Event::LimitReached, 1)],
        };
        let idle = State {
            delay: Dist::Uniform {
                min: slot.saturating_mul(2),
                max: slot.saturating_mul(max_mult.max(2)),
            },
            cover_limit: None,
            transitions: vec![(Event::RealEmitted, 0)],
        };
        Machine::new(vec![active, idle])
    }

    /// The adaptive machine with default thresholds.
    pub fn adaptive_default(slot: Duration) -> Self {
        Self::adaptive(slot, DEFAULT_IDLE_AFTER, DEFAULT_MAX_MULT)
    }

    #[cfg(test)]
    pub fn state(&self) -> usize {
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT: Duration = Duration::from_millis(10);

    #[test]
    fn uniform_samples_within_range() {
        let d = Dist::Uniform {
            min: Duration::from_millis(5),
            max: Duration::from_millis(15),
        };
        for _ in 0..1000 {
            let s = d.sample();
            assert!(s >= Duration::from_millis(5) && s <= Duration::from_millis(15));
        }
        assert_eq!(Dist::Constant(SLOT).sample(), SLOT);
    }

    #[test]
    fn constant_rate_stays_in_one_state_at_a_fixed_delay() {
        let mut m = Machine::constant_rate(SLOT);
        for real in [true, false, false, true, false] {
            assert_eq!(m.next_delay(real), SLOT);
            assert_eq!(m.state(), 0);
        }
    }

    #[test]
    fn adaptive_goes_idle_on_the_cover_limit_and_back_on_real() {
        let mut m = Machine::adaptive(SLOT, 3, 6);
        assert_eq!(m.state(), 0); // Active
                                  // Two covers: still Active (under the limit of 3).
        m.next_delay(false);
        m.next_delay(false);
        assert_eq!(m.state(), 0);
        // The third cover hits the limit → Idle.
        let idle_delay = m.next_delay(false);
        assert_eq!(m.state(), 1);
        assert!(
            idle_delay >= SLOT * 2,
            "idle cadence is sparser: {idle_delay:?}"
        );
        // A real cell snaps back to Active.
        let active_delay = m.next_delay(true);
        assert_eq!(m.state(), 0);
        assert!(active_delay <= SLOT + SLOT / 4);
    }

    #[test]
    fn active_delay_is_jittered_around_slot() {
        let mut m = Machine::adaptive_default(SLOT);
        for _ in 0..200 {
            let d = m.next_delay(true); // stay Active
            assert!(d >= SLOT - SLOT / 4 && d <= SLOT + SLOT / 4, "±25%: {d:?}");
        }
    }

    #[test]
    fn arbitrary_state_graph_follows_its_transitions() {
        // A 3-state burst machine: A --real--> B --real--> C --cover--> A. Proves the framework
        // isn't limited to the built-in Active/Idle shapes.
        let st = |to_real: usize, to_cover: usize| State {
            delay: Dist::Constant(SLOT),
            cover_limit: None,
            transitions: vec![
                (Event::RealEmitted, to_real),
                (Event::CoverEmitted, to_cover),
            ],
        };
        let mut m = Machine::new(vec![st(1, 0), st(2, 0), st(2, 0)]);
        assert_eq!(m.state(), 0);
        m.next_delay(true);
        assert_eq!(m.state(), 1);
        m.next_delay(true);
        assert_eq!(m.state(), 2);
        m.next_delay(false);
        assert_eq!(m.state(), 0);
    }

    #[test]
    fn out_of_range_transition_is_clamped() {
        let m = Machine::new(vec![State {
            delay: Dist::Constant(SLOT),
            cover_limit: None,
            transitions: vec![(Event::RealEmitted, 99)],
        }]);
        // transition_for clamps to the last valid index; with one state that's 0.
        assert_eq!(m.transition_for(Event::RealEmitted), Some(0));
    }
}
