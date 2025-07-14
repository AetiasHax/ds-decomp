use std::{cmp::Ordering, ops::Range};

#[derive(Debug)]
pub struct RangeSet<T> {
    ranges: Vec<(T, T)>,
}

impl<T> RangeSet<T>
where
    T: PartialOrd + Ord + Copy,
{
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn from_ranges<I>(ranges: I) -> Self
    where
        I: IntoIterator<Item = (T, T)>,
    {
        let mut set = Self::new();
        for range in ranges {
            set.insert(range.0, range.1);
        }
        set
    }

    pub fn insert(&mut self, start: T, end: T) -> bool {
        if start >= end {
            return false; // Invalid range
        }

        let overlaps = self.indices_overlapping(start, end);
        if overlaps.is_empty() {
            self.ranges.insert(overlaps.start, (start, end));
            true
        } else if overlaps.len() == 1 {
            let old_start = self.ranges[overlaps.start].0;
            let old_end = self.ranges[overlaps.start].1;
            let new_start = old_start.min(start);
            let new_end = old_end.max(end);
            if old_start == new_start && old_end == new_end {
                return false; // No change
            }
            self.ranges[overlaps.start] = (new_start, new_end);
            true
        } else {
            let new_start = self.ranges[overlaps.start].0.min(start);
            let new_end = self.ranges[overlaps.end - 1].1.max(end);
            self.ranges.copy_within(overlaps.end.., overlaps.start + 1);
            self.ranges.truncate(self.ranges.len() - overlaps.len() + 1);
            self.ranges[overlaps.start] = (new_start, new_end);
            true
        }
    }

    pub fn indices_overlapping(&self, start: T, end: T) -> Range<usize> {
        let min = self
            .ranges
            .binary_search_by(|&(s, e)| {
                if start < s {
                    Ordering::Greater
                } else if start < e {
                    Ordering::Equal
                } else {
                    Ordering::Less
                }
            })
            .unwrap_or_else(|x| x);
        let max = self
            .ranges
            .binary_search_by(|&(s, e)| {
                if end < s {
                    Ordering::Greater
                } else if end < e {
                    Ordering::Equal
                } else {
                    Ordering::Less
                }
            })
            .map(|x| x + 1)
            .unwrap_or_else(|x| x);
        min..max
    }

    pub fn contains(&self, value: T) -> bool {
        self.ranges
            .binary_search_by(|&(s, e)| {
                if value < s {
                    Ordering::Greater
                } else if value < e {
                    Ordering::Equal
                } else {
                    Ordering::Less
                }
            })
            .is_ok()
    }

    pub fn iter(&self) -> impl Iterator<Item = &(T, T)> {
        self.ranges.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_set() {
        let mut set = RangeSet::new();
        set.insert(1, 5);
        set.insert(12, 18);
        set.insert(3, 7);
        set.insert(10, 15);

        assert_eq!(set.ranges.len(), 2);
        assert_eq!(set.ranges[0], (1, 7));
        assert_eq!(set.ranges[1], (10, 18));

        set.insert(20, 25);
        assert_eq!(set.ranges.len(), 3);
        assert_eq!(set.ranges[2], (20, 25));

        let indices = set.indices_overlapping(4, 12);
        assert_eq!(indices, 0..2);

        let indices = set.indices_overlapping(0, 100);
        assert_eq!(indices, 0..3);

        set.insert(0, 100);
        assert_eq!(set.ranges.len(), 1);
        assert_eq!(set.ranges[0], (0, 100));

        set.insert(50, 60);
        assert_eq!(set.ranges.len(), 1);
        assert_eq!(set.ranges[0], (0, 100));
    }
}
