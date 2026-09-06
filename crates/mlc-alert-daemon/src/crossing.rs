//! Stateless price-crossing detection — the server-side subset of
//! `mylittlechart`'s `mlc-backend::alert::crossing::check_crossings`. That
//! function cannot be reused directly: it takes a full native `AlertItem`
//! from a crate this workspace cannot depend on (`mlc-core`/`mlc-backend`
//! live in the separate `mylittlechart` submodule) — see `alert_item.rs`'s
//! module doc for why the wire shape is its own narrower type instead.
//! This is the same crossing math, restricted to the three conditions the
//! wire shape's [`crate::alert_item::Direction`] can express
//! (`CrossingUp`/`CrossingDown`/`Crossing`).

use crate::alert_item::Direction;

/// Whether `prev -> current` crosses `level` in the direction `dir` asks
/// for.
///
/// - `Up`: `prev < level && current >= level` (mirrors `CrossingUp`).
/// - `Down`: `prev > level && current <= level` (mirrors `CrossingDown`).
/// - `Either`: either of the above (mirrors `Crossing`).
pub fn crosses(dir: Direction, prev: f64, current: f64, level: f64) -> bool {
    let crossed_up = prev < level && current >= level;
    let crossed_down = prev > level && current <= level;
    match dir {
        Direction::Up => crossed_up,
        Direction::Down => crossed_down,
        Direction::Either => crossed_up || crossed_down,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sample price sequence walked pairwise, checked at every step
    /// against a fixed level of 100.0. Expected fire points: index 0->1
    /// (98 -> 102, crosses up), 2->3 (103 -> 97, crosses down), 4->5
    /// (97 -> 97, no movement, no fire), 5->6 (97 -> 100, crosses up —
    /// landing exactly ON the level counts, per `current >= level`).
    const SEQUENCE: [f64; 7] = [98.0, 102.0, 103.0, 97.0, 97.0, 97.0, 100.0];

    #[test]
    fn either_direction_fires_on_the_expected_pairs_only() {
        let mut fired_at = Vec::new();
        for i in 0..SEQUENCE.len() - 1 {
            if crosses(Direction::Either, SEQUENCE[i], SEQUENCE[i + 1], 100.0) {
                fired_at.push(i);
            }
        }
        assert_eq!(fired_at, vec![0, 2, 5]);
    }

    #[test]
    fn up_only_ignores_downward_crossings() {
        assert!(crosses(Direction::Up, 98.0, 102.0, 100.0));
        assert!(!crosses(Direction::Up, 103.0, 97.0, 100.0));
    }

    #[test]
    fn down_only_ignores_upward_crossings() {
        assert!(crosses(Direction::Down, 103.0, 97.0, 100.0));
        assert!(!crosses(Direction::Down, 98.0, 102.0, 100.0));
    }

    #[test]
    fn landing_exactly_on_the_level_counts_as_a_crossing() {
        assert!(crosses(Direction::Up, 97.0, 100.0, 100.0));
        assert!(crosses(Direction::Down, 103.0, 100.0, 100.0));
    }

    #[test]
    fn no_movement_relative_to_level_never_fires() {
        assert!(!crosses(Direction::Either, 97.0, 97.0, 100.0));
        assert!(!crosses(Direction::Either, 105.0, 105.0, 100.0));
    }

    #[test]
    fn staying_strictly_on_one_side_never_fires() {
        assert!(!crosses(Direction::Either, 101.0, 103.0, 100.0));
        assert!(!crosses(Direction::Either, 99.0, 98.0, 100.0));
    }
}
