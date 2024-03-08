// Copyright (C) Microsoft Corporation.
// Licensed under the MIT License.

//! Implement a range map data structure.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use core::cmp::Ordering;
use std::ops::RangeInclusive;

/// A range map that supports lookups for a value V, based on a key type K.
/// Ranges are defined as a [`RangeInclusive`]. The map does not allow
/// overlapping ranges.
///
/// This implementation is done by using a sorted vec and using binary search
/// for insertion and removal.
#[derive(Debug, Clone)]
pub struct RangeMap<K, V> {
    // This vec _must_ be in sorted order.
    data: Vec<(K, K, V)>,
}

/// An entry returned by [`RangeMap::entry`].
#[derive(Debug)]
pub enum Entry<'a, K, V> {
    /// An entry already exists that overlaps.
    Overlapping(OverlappingEntry<'a, K, V>),
    /// No entry exists.
    Vacant(VacantEntry<'a, K, V>),
}

/// An object representing a an existing entry that overlaps the range passed to
/// [`RangeMap::entry`].
#[derive(Debug)]
pub struct OverlappingEntry<'a, K, V>(&'a Vec<(K, K, V)>, usize);

impl<K, V> OverlappingEntry<'_, K, V> {
    /// Gets the entry that's already in the map.
    pub fn get(&self) -> &(K, K, V) {
        &self.0[self.1]
    }
}

/// An object representing a range of the map with no entries.
#[derive(Debug)]
pub struct VacantEntry<'a, K, V> {
    data: &'a mut Vec<(K, K, V)>,
    insert_index: usize,
    start: K,
    end: K,
}

impl<K, V> VacantEntry<'_, K, V> {
    /// Inserts a value into the map.
    pub fn insert(self, value: V) {
        self.data
            .insert(self.insert_index, (self.start, self.end, value));
    }
}

impl<K, V> RangeMap<K, V>
where
    K: PartialOrd + Clone,
{
    /// Check if a given range contains the following value.
    fn range_contains(range: &(K, K, V), value: &K) -> bool {
        *value >= range.0 && *value <= range.1
    }

    /// Check if two ranges overlap in any way.
    fn ranges_overlaps(a_start: &K, a_end: &K, b_start: &K, b_end: &K) -> bool {
        *a_start <= *b_end && *b_start <= *a_end
    }

    /// Do an ordered comparison for a given value against an range.
    fn range_compare(range: &(K, K, V), value: &K) -> Ordering {
        if *value < range.0 {
            Ordering::Less
        } else if *value > range.1 {
            Ordering::Greater
        } else {
            debug_assert!(RangeMap::<K, V>::range_contains(range, value));
            Ordering::Equal
        }
    }

    /// Do an ordered comparison against an range and another.
    fn range_compare_range(range: &(K, K, V), start: &K, end: &K) -> Ordering {
        debug_assert!(end >= start);
        if *end < range.0 {
            debug_assert!(!RangeMap::<K, V>::ranges_overlaps(
                &range.0, &range.1, start, end
            ));
            Ordering::Less
        } else if *start > range.1 {
            debug_assert!(!RangeMap::<K, V>::ranges_overlaps(
                &range.0, &range.1, start, end
            ));
            Ordering::Greater
        } else {
            debug_assert!(RangeMap::<K, V>::ranges_overlaps(
                &range.0, &range.1, start, end
            ));
            Ordering::Equal
        }
    }

    /// Binary search the data member for a range containing the given value,
    /// or a valid insert location.
    fn binary_search_find(&self, value: &K) -> Result<usize, usize> {
        self.data
            .binary_search_by(|element| RangeMap::<K, V>::range_compare(element, value))
    }

    /// Binary search the data member for a range overlapping the given range,
    /// or a valid insert location.
    ///
    /// The range must be a non-empty range, or else this function will panic.
    fn binary_search_find_range(&self, range: &RangeInclusive<K>) -> Result<usize, usize> {
        assert!(!range.is_empty());
        self.data.binary_search_by(|element| {
            RangeMap::<K, V>::range_compare_range(element, range.start(), range.end())
        })
    }

    /// Create a new empty [`RangeMap`].
    pub fn new() -> Self {
        RangeMap { data: Vec::new() }
    }

    /// Returns an entry for the given range. If the range overlaps an existing
    /// region, returns an [`Entry::Overlapping`]; otherwise, returns
    /// [`Entry::Vacant`].
    ///
    /// Note that there could be multiple ranges in the map that overlap the
    /// given `range` but only one overlap will be returned by this function.
    ///
    /// This function panics if `range.is_empty()` is true.
    pub fn entry(&mut self, range: RangeInclusive<K>) -> Entry<'_, K, V> {
        assert!(!range.is_empty());

        match self.binary_search_find_range(&range) {
            Ok(index) => Entry::Overlapping(OverlappingEntry(&self.data, index)),
            Err(insert_index) => Entry::Vacant(VacantEntry {
                data: &mut self.data,
                insert_index,
                start: range.start().clone(),
                end: range.end().clone(),
            }),
        }
    }

    /// Insert a new range into the map.
    ///
    /// Returns true if the map did not contain an overlapping range. Returns
    /// false if the map contained an overlapping range.
    ///
    /// This function panics if `range.is_empty()` is true.
    ///
    /// Note that two entries with adjacent ranges that contain the same value
    /// are not merged. Adjacent entries can be merged using
    /// [`RangeMap::merge_adjacent`].
    ///
    /// # Examples
    ///
    /// ```
    /// use range_map_vec::RangeMap;
    ///
    /// let mut map: RangeMap<u64, u64> = RangeMap::new();
    /// assert_eq!(map.insert(0..=5, 0), true);
    /// assert_eq!(map.insert(1..=20, 1), false);
    /// assert_eq!(map.get_entry(&3).unwrap(), &(0, 5, 0));
    /// ```
    pub fn insert(&mut self, range: RangeInclusive<K>, value: V) -> bool {
        assert!(!range.is_empty());

        match self.entry(range) {
            Entry::Overlapping(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(value);
                true
            }
        }
    }

    /// Remove a given range from the map given a value covered by the range.
    /// Returns the value removed from the map, (start, end, value), if any.
    pub fn remove(&mut self, value: &K) -> Option<(K, K, V)> {
        if let Ok(pos) = self.binary_search_find(value) {
            Some(self.data.remove(pos))
        } else {
            None
        }
    }

    /// Removes any entries that overlaps the specified range. Returns a sorted
    /// vector representing ranges removed.
    pub fn remove_range(&mut self, range: RangeInclusive<K>) -> Vec<(K, K, V)> {
        let mut removed = vec![];

        while let Ok(index) = self.binary_search_find_range(&range) {
            removed.push(self.data.remove(index));
        }

        removed.sort_by(|a, b| Self::range_compare_range(b, &a.0, &a.1));
        removed
    }

    /// Remove all ranges in the map and return them as a Vec, with `(start,
    /// end, value)`.
    pub fn into_vec(self) -> Vec<(K, K, V)> {
        self.data
    }

    /// Returns true if the map contains an range that covers the value.
    pub fn contains(&self, value: &K) -> bool {
        self.binary_search_find(value).is_ok()
    }

    /// Returns a reference to the value covered by a range in the map, if any.
    ///
    /// ```
    /// use range_map_vec::RangeMap;
    ///
    /// let mut map: RangeMap<u64, u64> = RangeMap::new();
    /// assert_eq!(map.insert(0..=3, 0), true);
    /// assert_eq!(map.insert(5..=10, 1), true);
    /// assert_eq!(map.get(&3).unwrap(), &0);
    /// assert!(map.get(&4).is_none());
    /// ```
    pub fn get(&self, value: &K) -> Option<&V> {
        match self.binary_search_find(value) {
            Ok(index) => Some(&self.data[index].2),
            Err(_) => None,
        }
    }

    /// Returns a reference to the value that overlaps the given range, if any.
    ///
    /// Note that there could be multiple ranges in the map that overlap the
    /// given `range` but only one overlap will be returned by this function.
    ///
    /// This function panics if `range.is_empty()` is true.
    pub fn get_range(&self, range: RangeInclusive<K>) -> Option<&V> {
        assert!(!range.is_empty());
        match self.binary_search_find_range(&range) {
            Ok(index) => Some(&self.data[index].2),
            Err(_) => None,
        }
    }

    /// Returns a reference to the entry that covers `value`, if any.
    pub fn get_entry(&self, value: &K) -> Option<&(K, K, V)> {
        match self.binary_search_find(value) {
            Ok(index) => Some(&self.data[index]),
            Err(_) => None,
        }
    }

    /// Returns a reference to the entry overlapping the specified `range`, if
    /// any.
    ///
    /// Note that there could be multiple ranges in the map that overlap the
    /// given `range` but only one overlap will be returned by this function.
    pub fn get_range_entry(&self, range: RangeInclusive<K>) -> Option<&(K, K, V)> {
        assert!(!range.is_empty());
        match self.binary_search_find_range(&range) {
            Ok(index) => Some(&self.data[index]),
            Err(_) => None,
        }
    }

    /// Provides an iterator to iterate through the whole map.
    pub fn iter(&self) -> impl Clone + Iterator<Item = (RangeInclusive<K>, &V)> {
        self.data
            .iter()
            .map(|(start, end, v)| (start.clone()..=end.clone(), v))
    }

    /// Merge adjacent ranges that hold the same value using the provided
    /// closure to determine if a range is adjacent to another.
    ///
    /// The closure accepts two arguments, with the first argument being smaller
    /// than the second.
    ///
    /// # Examples
    ///
    /// ```
    /// use range_map_vec::RangeMap;
    ///
    /// let mut map: RangeMap<u64, u64> = RangeMap::new();
    /// assert_eq!(map.insert(0..=2, 0), true);
    /// assert_eq!(map.insert(3..=5, 0), true);
    /// assert_eq!(map.insert(7..=10, 0), true);
    ///
    /// map.merge_adjacent(|smaller, larger| {
    ///     let next = *smaller.end() + 1;
    ///     next == *larger.start()
    /// });
    ///
    /// assert_eq!(map.get_entry(&3).unwrap(), &(0, 5, 0));
    /// assert_eq!(map.get_entry(&8).unwrap(), &(7, 10, 0));
    /// ```
    pub fn merge_adjacent<F>(&mut self, is_adjacent: F)
    where
        F: Fn(RangeInclusive<K>, RangeInclusive<K>) -> bool,
        V: Eq,
    {
        loop {
            let mut new_range = None;
            for (left, right) in self.data.iter().zip(self.data.iter().skip(1)) {
                let left_range = left.0.clone()..=left.1.clone();
                let right_range = right.0.clone()..=right.1.clone();

                // Range map is sorted in descending order, so swap left and
                // right so the smaller range is passed to the closure first.
                if is_adjacent(right_range, left_range) && left.2 == right.2 {
                    new_range = Some(right.0.clone()..=left.1.clone());
                    break;
                }
            }

            match new_range {
                Some(new_range) => {
                    let value = self
                        .remove_range(new_range.clone())
                        .pop()
                        .expect("should have removed ranges")
                        .2;
                    assert!(self.insert(new_range, value));
                }
                None => return,
            }
        }
    }
}

impl<K, V> Default for RangeMap<K, V>
where
    K: PartialOrd + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

/// A default implementation for a u64 key type for
/// [`RangeMap::merge_adjacent`].
pub fn u64_is_adjacent(smaller: RangeInclusive<u64>, larger: RangeInclusive<u64>) -> bool {
    let next = *smaller.end() + 1;
    next == *larger.start()
}

#[cfg(test)]
mod tests {
    use super::Entry;
    use super::RangeMap;

    #[test]
    fn basic_functionality() {
        let mut tree: RangeMap<u64, u64> = RangeMap::new();

        assert_eq!(tree.insert(0..=5, 0), true);
        assert_eq!(tree.insert(10..=20, 1), true);

        assert_eq!(tree.contains(&0), true);
        assert_eq!(tree.contains(&3), true);
        assert_eq!(tree.contains(&5), true);
        assert_eq!(tree.contains(&8), false);
        assert_eq!(tree.contains(&15), true);

        assert_eq!(tree.get(&0), Some(&0));
        assert_eq!(tree.get(&3), Some(&0));
        assert_eq!(tree.get(&5), Some(&0));
        assert_eq!(tree.get(&8), None);
        assert_eq!(tree.get(&15), Some(&1));

        assert_eq!(tree.remove(&2), Some((0, 5, 0)));
        assert_eq!(tree.remove(&18), Some((10, 20, 1)));
        assert_eq!(tree.remove(&0), None);
    }

    #[test]
    #[should_panic]
    #[allow(clippy::reversed_empty_ranges)]
    fn test_insert_invalid_range() {
        let mut tree: RangeMap<u64, u64> = RangeMap::new();
        tree.insert(20..=10, 0);
    }

    #[test]
    #[should_panic]
    #[allow(clippy::reversed_empty_ranges)]
    fn test_entry_invalid_range() {
        let mut tree: RangeMap<u64, u64> = RangeMap::new();
        tree.entry(20..=10);
    }

    #[test]
    #[should_panic]
    #[allow(clippy::reversed_empty_ranges)]
    fn test_get_range_invalid_range() {
        let tree: RangeMap<u64, u64> = RangeMap::new();
        tree.get_range(20..=10);
    }

    #[test]
    fn test_add_multiple_overlap() {
        let mut tree: RangeMap<u64, u64> = RangeMap::new();

        assert_eq!(tree.insert(1..=5, 0), true);
        assert_eq!(tree.insert(1..=5, 0), false);
        assert_eq!(tree.insert(2..=3, 0), false);
        assert_eq!(tree.insert(0..=1, 0), false);
        assert_eq!(tree.insert(5..=10, 0), false);
        assert_eq!(tree.insert(2..=10, 0), false);
        assert_eq!(tree.insert(0..=10, 0), false);
    }

    #[test]
    fn test_get() {
        let mut tree: RangeMap<u64, u64> = RangeMap::new();

        assert_eq!(tree.insert(1..=5, 0), true);
        assert_eq!(tree.insert(6..=10, 1), true);
        assert_eq!(tree.insert(12..=13, 2), true);
        assert_eq!(tree.insert(20..=30, 3), true);

        assert_eq!(tree.get(&0), None);

        for x in 1..=5 {
            assert_eq!(tree.get(&x), Some(&0));
        }

        for x in 6..=10 {
            assert_eq!(tree.get(&x), Some(&1));
        }

        assert_eq!(tree.get(&11), None);

        for x in 12..=13 {
            assert_eq!(tree.get(&x), Some(&2));
        }

        for x in 14..=19 {
            assert_eq!(tree.get(&x), None);
        }

        for x in 20..=30 {
            assert_eq!(tree.get(&x), Some(&3));
        }

        for x in 31..40 {
            assert_eq!(tree.get(&x), None);
        }
    }

    #[test]
    fn test_remove() {
        let mut tree: RangeMap<u64, u64> = RangeMap::new();

        assert_eq!(tree.insert(10..=20, 1), true);

        assert_eq!(tree.insert(1..=5, 0), true);
        assert_eq!(tree.remove(&1), Some((1, 5, 0)));
        assert_eq!(tree.remove(&1), None);
        assert_eq!(tree.remove(&3), None);
        assert_eq!(tree.remove(&5), None);

        assert_eq!(tree.insert(1..=5, 0), true);
        assert_eq!(tree.remove(&5), Some((1, 5, 0)));
        assert_eq!(tree.remove(&1), None);
        assert_eq!(tree.remove(&3), None);
        assert_eq!(tree.remove(&5), None);

        assert_eq!(tree.insert(1..=5, 0), true);
        assert_eq!(tree.remove(&3), Some((1, 5, 0)));
        assert_eq!(tree.remove(&1), None);
        assert_eq!(tree.remove(&3), None);
        assert_eq!(tree.remove(&5), None);
    }

    #[test]
    fn test_contains() {
        let mut tree: RangeMap<u64, u64> = RangeMap::new();

        assert_eq!(tree.insert(1..=5, 0), true);
        assert_eq!(tree.insert(6..=10, 1), true);
        assert_eq!(tree.insert(12..=13, 2), true);
        assert_eq!(tree.insert(20..=30, 3), true);

        assert_eq!(tree.contains(&0), false);

        for x in 1..=5 {
            assert_eq!(tree.contains(&x), true);
        }

        for x in 6..=10 {
            assert_eq!(tree.contains(&x), true);
        }

        assert_eq!(tree.contains(&11), false);

        for x in 12..=13 {
            assert_eq!(tree.contains(&x), true);
        }

        for x in 14..=19 {
            assert_eq!(tree.contains(&x), false);
        }

        for x in 20..=30 {
            assert_eq!(tree.contains(&x), true);
        }

        for x in 31..40 {
            assert_eq!(tree.contains(&x), false);
        }
    }

    #[test]
    fn test_start_end_equal() {
        let mut tree: RangeMap<u64, u64> = RangeMap::new();

        assert_eq!(tree.insert(0..=0, 0), true);
        assert_eq!(tree.insert(1..=1, 1), true);
        assert_eq!(tree.insert(2..=2, 2), true);
        assert_eq!(tree.insert(3..=3, 3), true);
        assert_eq!(tree.insert(0..=3, 4), false);
    }

    #[test]
    fn test_entry() {
        let mut tree: RangeMap<u64, u64> = RangeMap::new();

        match tree.entry(1..=2) {
            Entry::Overlapping(_) => panic!(),
            Entry::Vacant(e) => e.insert(0x1000),
        }

        match tree.entry(2..=4) {
            Entry::Overlapping(e) => {
                assert_eq!(e.get(), &(1, 2, 0x1000));
            }
            Entry::Vacant(_) => panic!(),
        }
    }

    #[test]
    fn test_remove_range() {
        let mut map: RangeMap<u64, u64> = RangeMap::new();

        assert_eq!(map.insert(1..=5, 0), true);
        assert_eq!(map.insert(6..=10, 1), true);
        assert_eq!(map.insert(12..=13, 2), true);
        assert_eq!(map.insert(20..=30, 3), true);

        let removed = map.remove_range(2..=19);
        assert_eq!(removed, vec![(1, 5, 0), (6, 10, 1), (12, 13, 2)]);
        let removed = map.remove_range(1..=100);
        assert_eq!(removed, vec![(20, 30, 3)]);
        let removed = map.remove_range(1..=100);
        assert_eq!(removed, vec![]);
    }

    #[test]
    fn test_merge_adjacent() {
        let mut map: RangeMap<u64, u64> = RangeMap::new();

        assert_eq!(map.insert(1..=5, 0), true);
        assert_eq!(map.insert(6..=7, 0), true);
        assert_eq!(map.insert(8..=10, 0), true);
        assert_eq!(map.insert(11..=13, 1), true);
        assert_eq!(map.insert(15..=30, 1), true);
        assert_eq!(map.insert(31..=32, 1), true);

        map.merge_adjacent(super::u64_is_adjacent);

        let expected = vec![(1, 10, 0), (11, 13, 1), (15, 32, 1)];
        let mut actual = map.into_vec();
        actual.sort();

        assert_eq!(expected, actual);
    }
}
