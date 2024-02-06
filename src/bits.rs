// Axel '0vercl0k' Souchet - January 21 2024
use std::mem;
use std::ops::RangeInclusive;

/// Utility trait to make it easier to extract ranges of bits.
pub trait Bits: Sized {
    /// Get a range of bits.
    fn bits(&self, r: RangeInclusive<usize>) -> Self;

    /// Get a bit.
    fn bit(&self, n: usize) -> Self {
        self.bits(n..=n)
    }
}

impl<T> Bits for T
where
    T: Into<u128> + Copy + TryFrom<u128>,
    <T as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn bits(&self, r: RangeInclusive<usize>) -> Self {
        let (start, end) = r.into_inner();
        let capacity = mem::size_of_val(self) * 8;
        assert!(start <= end, "the range should have a start <= end");
        assert!(
            end < capacity,
            "the end ({end}) of the range can't exceed the bits capacity ({capacity}) of Self"
        );
        let value = (*self).into();
        let base = value >> start;
        let n = end - start + 1;

        let mask = if n == capacity {
            // This prevents to overflow a u128 when doing `(1 << 128) - 1`
            !0
        } else {
            (1 << n) - 1
        };

        // This cannot fail as we are zero extending `Self` into a `u128` and then the
        // `mask` cannot index outside the bit capacity of `Self`.
        T::try_from(base & mask).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::Bits;

    #[test]
    fn bits64() {
        let v = 0xAB_CD_EF_01_23_45_67_89u64;
        assert_eq!(v.bits(0..=63), v);
        assert_eq!(v.bits(0..=55), 0xCD_EF_01_23_45_67_89);
        assert_eq!(v.bits(0..=47), 0xEF_01_23_45_67_89);
        assert_eq!(v.bits(0..=39), 0x01_23_45_67_89);
        assert_eq!(v.bits(0..=31), 0x23_45_67_89);
        assert_eq!(v.bits(0..=23), 0x45_67_89);
        assert_eq!(v.bits(0..=15), 0x67_89);
        assert_eq!(v.bits(0..=7), 0x89);
        assert_eq!(v.bits(0..=3), 0x9);

        assert_eq!(v.bits(0..=7), 0x89);
        assert_eq!(v.bits(8..=15), 0x67);
        assert_eq!(v.bits(16..=23), 0x45);
        assert_eq!(v.bits(24..=31), 0x23);
        assert_eq!(v.bits(32..=39), 0x01);
        assert_eq!(v.bits(40..=47), 0xEF);
        assert_eq!(v.bits(48..=55), 0xCD);
        assert_eq!(v.bits(56..=63), 0xAB);
        assert_eq!(v.bit(0), 1);
    }

    #[test]
    fn bits128() {
        let v = 0xAB_CD_EF_01_23_45_67_89u128;
        assert_eq!(v.bits(0..=125), v);
        assert_eq!(v.bits(0..=55), 0xCD_EF_01_23_45_67_89);
        assert_eq!(v.bits(0..=47), 0xEF_01_23_45_67_89);
        assert_eq!(v.bits(0..=39), 0x01_23_45_67_89);
        assert_eq!(v.bits(0..=31), 0x23_45_67_89);
        assert_eq!(v.bits(0..=23), 0x45_67_89);
        assert_eq!(v.bits(0..=15), 0x67_89);
        assert_eq!(v.bits(0..=7), 0x89);
        assert_eq!(v.bits(0..=3), 0x9);

        assert_eq!(v.bits(0..=7), 0x89);
        assert_eq!(v.bits(8..=15), 0x67);
        assert_eq!(v.bits(16..=23), 0x45);
        assert_eq!(v.bits(24..=31), 0x23);
        assert_eq!(v.bits(32..=39), 0x01);
        assert_eq!(v.bits(40..=47), 0xEF);
        assert_eq!(v.bits(48..=55), 0xCD);
        assert_eq!(v.bits(56..=63), 0xAB);
    }

    #[test]
    fn invalid_ranges() {
        assert!(std::panic::catch_unwind(|| 1u64.bits(10..=0)).is_err());
        assert!(std::panic::catch_unwind(|| 1u128.bits(0..=128)).is_err());
        assert!(std::panic::catch_unwind(|| 1u64.bits(0..=64)).is_err());
    }
}
