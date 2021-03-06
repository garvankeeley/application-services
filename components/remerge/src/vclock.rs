/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Our implementation of vector clocks. See the remerge RFC's appendix for an
//! overview of how these work if you're unfamiliar.

use crate::Guid;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use std::collections::BTreeMap;

pub type Counter = u64;

/// A vector clock.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct VClock(pub BTreeMap<Guid, Counter>);

/// Basically equivalent to Option<std::cmp::Ordering>, but more explicit about
/// what each value means. The variant documentation assumes this is generated by
/// something similar to `lhs.get_ordering(rhs)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClockOrdering {
    /// The two clocks are equivalent.
    Equivalent,
    /// The `lhs` clock is an ancestor of the `rhs` clock.
    Ancestor,
    /// The `lhs` clock is a decendent of the `rhs` clock.
    Descendent,
    /// The two clocks are in conflict, and some other means of resolution must
    /// be used.
    Conflicting,
}

impl VClock {
    pub fn new(own_client_id: Guid, counter: Counter) -> Self {
        VClock(std::iter::once((own_client_id, counter)).collect())
    }

    /// Determine the ordering between `self` and `other`.
    pub fn get_ordering(&self, other: &VClock) -> ClockOrdering {
        let mut seen_gt = false;
        let mut seen_lt = false;

        let self_kvs = self.0.iter().map(|(id, &ctr)| (id, Some(ctr), None));
        let other_kvs = other.0.iter().map(|(id, &ctr)| (id, None, Some(ctr)));

        for (k, sv, ov) in self_kvs.chain(other_kvs) {
            let sv = sv.unwrap_or_else(|| self.get(k));
            let ov = ov.unwrap_or_else(|| other.get(k));
            if sv > ov {
                seen_gt = true;
            }
            if sv < ov {
                seen_lt = true;
            }
            if seen_gt && seen_lt {
                // No need to keep going once we've seen both.
                return ClockOrdering::Conflicting;
            }
        }
        match (seen_gt, seen_lt) {
            (false, false) => ClockOrdering::Equivalent,
            (true, false) => ClockOrdering::Descendent,
            (false, true) => ClockOrdering::Ancestor,
            (true, true) => ClockOrdering::Conflicting,
        }
    }

    pub fn is_equivalent(&self, o: &VClock) -> bool {
        self.get_ordering(o) == ClockOrdering::Equivalent
    }

    pub fn is_ancestor_of(&self, o: &VClock) -> bool {
        self.get_ordering(o) == ClockOrdering::Ancestor
    }

    pub fn is_descendent_of(&self, o: &VClock) -> bool {
        self.get_ordering(o) == ClockOrdering::Descendent
    }

    pub fn is_conflicting(&self, o: &VClock) -> bool {
        self.get_ordering(o) == ClockOrdering::Conflicting
    }

    /// Get the clock's value for client_id, or 0 if it hasn't seen it.
    pub fn get(&self, client_id: &Guid) -> Counter {
        self.0.get(&client_id).copied().unwrap_or_default()
    }

    /// Add one to the clock's value for client_id
    pub fn increment(&mut self, client_id: Guid) {
        *self.0.entry(client_id).or_default() += 1
    }

    /// Assign `value` for client_id directly. Usually you want `apply` instead
    pub fn set_directly(&mut self, client_id: Guid, value: Counter) {
        if value == 0 {
            self.0.remove(&client_id);
        } else {
            self.0.insert(client_id, value);
        }
    }

    /// If `value` is greater than the current value for client_id store that
    /// instead. Otherwise, do nothing.
    ///
    /// Notes that this clock has seen the `value`th event of `client_id`.
    #[must_use]
    pub fn apply(mut self, client_id: Guid, value: Counter) -> Self {
        if value == 0 {
            // Avoid inserting 0 if we can help it.
            return self;
        }
        let old_value = self.0.entry(client_id).or_default();
        if *old_value < value {
            *old_value = value;
        }
        self
    }

    #[must_use]
    pub fn combine(self, o: &VClock) -> Self {
        o.0.iter()
            .fold(self, |accum, (id, ctr)| accum.apply(id.clone(), *ctr))
    }
}

impl<'a> IntoIterator for &'a VClock {
    type IntoIter = std::collections::btree_map::Iter<'a, Guid, Counter>;
    type Item = (&'a Guid, &'a Counter);
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl PartialOrd for VClock {
    fn partial_cmp(&self, other: &VClock) -> Option<std::cmp::Ordering> {
        match self.get_ordering(other) {
            ClockOrdering::Equivalent => Some(std::cmp::Ordering::Equal),
            ClockOrdering::Ancestor => Some(std::cmp::Ordering::Less),
            ClockOrdering::Descendent => Some(std::cmp::Ordering::Greater),
            ClockOrdering::Conflicting => None,
        }
    }
}

impl ToSql for VClock {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        // serde_json::to_string only fails for types which can't be encoded as
        // JSON (recursive graphs, maps with non-string keys, etc) so unwrap
        // here is fine.
        Ok(ToSqlOutput::from(serde_json::to_string(self).unwrap()))
    }
}

impl FromSql for VClock {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        value.as_str().and_then(|s| {
            serde_json::from_str(s).map_err(|e| {
                log::error!("Failed to read vector clock from SQL");
                log::debug!("  error: {:?}", e);
                FromSqlError::Other(Box::new(e))
            })
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_clock_basic() {
        let id = Guid::new("000000000000");
        let a = VClock::new(id.clone(), 1);

        assert!(!a.is_descendent_of(&a));
        assert!(!a.is_ancestor_of(&a));
        assert!(!a.is_conflicting(&a));
        assert!(a.is_equivalent(&a));

        let b = VClock::new(id, 2);

        assert!(!a.is_descendent_of(&b));
        assert!(b.is_descendent_of(&a));
        assert!(!b.is_ancestor_of(&a));
        assert!(a.is_ancestor_of(&b));

        assert!(!b.is_conflicting(&a));
        assert!(!a.is_conflicting(&b));

        assert!(!b.is_equivalent(&a));
        assert!(!a.is_equivalent(&b));

        assert!(a < b);
        assert!(a <= b);
        assert!(b > a);
        assert!(b >= a);
        assert_ne!(a, b);

        // b completely subsumes a, so this just copies b.
        let b2 = b.clone().combine(&a);
        assert!(b.is_equivalent(&b2));
        assert!(b2.is_equivalent(&b));
        assert_eq!(b2, b);
    }

    #[test]
    fn test_clock_multi_ids() {
        let id0 = Guid::new("000000000000");
        let id1 = Guid::new("111111111111");
        let a = VClock::new(id0.clone(), 1).apply(id1, 2);
        let b = VClock::new(id0, 1);

        assert!(a.is_descendent_of(&b));
        assert!(!b.is_descendent_of(&a));
        assert!(b.is_ancestor_of(&a));
        assert!(!a.is_ancestor_of(&b));

        assert!(!b.is_conflicting(&a));
        assert!(!a.is_conflicting(&b));

        assert!(!b.is_equivalent(&a));
        assert!(!a.is_equivalent(&b));
    }

    #[allow(clippy::neg_cmp_op_on_partial_ord)]
    #[test]
    fn test_clock_conflict() {
        let id0 = Guid::new("000000000000");
        let id1 = Guid::new("111111111111");
        let a = VClock::new(id0.clone(), 1).apply(id1, 2);
        let b = VClock::new(id0, 2);
        assert!(b.is_conflicting(&a));
        assert!(a.is_conflicting(&b));

        assert!(!b.is_equivalent(&a));
        assert!(!a.is_equivalent(&b));
        // all of these should be false, per partialeq rules
        assert!(!(a < b));
        assert!(!(a <= b));
        assert!(!(b > a));
        assert!(!(b >= a));
        assert_ne!(a, b);
    }

    #[test]
    fn test_clock_combine() {
        let id0 = Guid::new("000000000000");
        let id1 = Guid::new("111111111111");
        let a = VClock::new(id0.clone(), 1).apply(id1, 2);
        let b = VClock::new(id0, 2);
        let updated = b.clone().combine(&a);
        assert!(updated.is_descendent_of(&a));
        assert!(updated.is_descendent_of(&b));
        assert!(a.is_ancestor_of(&updated));
        assert!(b.is_ancestor_of(&updated));

        assert!(!updated.is_conflicting(&a));
        assert!(!updated.is_conflicting(&b));

        assert!(!updated.is_equivalent(&a));
        assert!(!updated.is_equivalent(&b));
    }
}
