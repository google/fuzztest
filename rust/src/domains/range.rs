// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::utility::map_char_to_int;
use super::utility::map_int_to_char;
use super::utility::mutate_float;
use super::utility::mutate_integer;
use super::utility::shrink_towards;
use super::utility::SpecialValues;
use super::Domain;
use std::fmt::Display;

use anyhow;
use rand::RngExt;

/// Generates values of type `T` in a given range.
///
/// For example, `InRange::new(0, 100)` generates integer
/// values from the inclusive range `[0, 100]`.
///
/// Example usage:
/// ```
/// # use fuzztest::domains::Domain;
/// # use fuzztest::domains::range::InRange;
/// # use rand::prelude::*;
///
/// let mut range_i32 = InRange::new(21i32, 73);
/// let sample = range_i32.init(&mut rand::rng());
///
/// assert!(sample.is_ok());
/// let sample = sample.unwrap();
/// assert!(sample >= 21);
/// assert!(sample <= 73);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct InRange<T> {
    lower: T,
    upper: T,
}

pub(crate) trait DomainRangeBounds {
    fn validate(lower: &Self, upper: &Self);
    fn shrinking_target(lower: &Self, upper: &Self) -> Self
    where
        Self: Sized;
}

macro_rules! impl_domain_range_bounds_for_integer {
    ($($ty:ty),*) => {
        $(
            impl DomainRangeBounds for $ty {
                fn validate(lower: &Self, upper: &Self) {
                    assert!(lower <= upper, "InRange: lower bound {} must be <= upper bound {}", lower, upper);
                }
                fn shrinking_target(lower: &Self, upper: &Self) -> Self {
                    #[allow(unused_comparisons)]
                    if *lower <= 0 && *upper >= 0 {
                        0
                    } else if *lower > 0 {
                        *lower
                    } else {
                        *upper
                    }
                }
            }
        )*
    };
}

impl_domain_range_bounds_for_integer!(
    i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize
);

macro_rules! impl_domain_range_bounds_for_float {
    ($($ty:ty),*) => {
        $(
            impl DomainRangeBounds for $ty {
                fn validate(lower: &Self, upper: &Self) {
                    assert!(lower <= upper, "InRange: lower bound {} must be <= upper bound {}", lower, upper);
                    // Rejects both overflowing finite ranges and infinite bounds (including
                    // `lower == upper == ±INFINITY`, where `upper - lower` is `NaN`), matching
                    // C++ `InRangeImpl` and `rand`'s `UniformFloat` finite-bound requirement.
                    assert!((*upper - *lower).is_finite(), "Range is too large!");
                }
                fn shrinking_target(lower: &Self, upper: &Self) -> Self {
                    if *lower <= 0.0 && *upper >= 0.0 {
                        0.0
                    } else if *lower > 0.0 {
                        *lower
                    } else {
                        *upper
                    }
                }
            }
        )*
    };
}

impl_domain_range_bounds_for_float!(f32, f64);

impl DomainRangeBounds for char {
    fn validate(lower: &Self, upper: &Self) {
        assert!(lower <= upper, "InRange: lower bound {} must be <= upper bound {}", lower, upper);
    }
    fn shrinking_target(lower: &Self, _upper: &Self) -> Self {
        *lower
    }
}

#[allow(private_bounds)]
impl<T> InRange<T>
where
    T: DomainRangeBounds + PartialOrd + Display,
{
    pub fn new(lower: T, upper: T) -> Self {
        T::validate(&lower, &upper);
        Self { lower, upper }
    }
}

macro_rules! impl_domain_for_in_range_integer {
    // `rand` does not implement `SampleUniform` for `isize` (required by
    // `rng.random_range`, `shrink_towards`, and `mutate_integer`), and `usize` is mapped
    // through `u64` for symmetry. Casting the result back `as $ty` cannot truncate even on
    // 32-bit targets because all outputs are bounded by `[lower, upper]`.
    ($ty:ty, $int_ty:ty) => {
        impl Domain for InRange<$ty> {
            type UserValue<'user> = $ty;
            type CorpusValue = $ty;

            fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
                let lower = self.lower as $int_ty;
                let upper = self.upper as $int_ty;

                if rng.random_bool(0.2) {
                    let mut specials = Vec::new();
                    specials.push(self.lower);
                    specials.push(self.upper);

                    let default_specials = <$ty as SpecialValues>::get();
                    for &v in default_specials {
                        if v > self.lower && v < self.upper {
                            specials.push(v);
                        }
                    }
                    let idx = rng.random_range(0..specials.len());
                    return Ok(specials[idx]);
                }

                Ok(rng.random_range(lower..=upper) as $ty)
            }

            fn mutate(
                &mut self,
                val: &mut Self::CorpusValue,
                rng: &mut dyn rand::Rng,
                only_shrink: bool,
            ) -> anyhow::Result<()> {
                if self.lower == self.upper {
                    *val = self.lower;
                    return Ok(());
                }
                let lower = self.lower as $int_ty;
                let upper = self.upper as $int_ty;
                if only_shrink {
                    let target = <$ty>::shrinking_target(&self.lower, &self.upper) as $int_ty;
                    *val = shrink_towards(rng, *val as $int_ty, target) as $ty;
                } else {
                    let range = 5;
                    *val = mutate_integer(rng, *val as $int_ty, range, Some(lower), Some(upper))
                        as $ty;
                }
                Ok(())
            }

            fn corpus_to_user_value<'a>(
                &self,
                corpus_value: &'a Self::CorpusValue,
            ) -> anyhow::Result<Self::UserValue<'a>> {
                Ok(*corpus_value)
            }

            fn validate_corpus_value(
                &self,
                corpus_value: &Self::CorpusValue,
            ) -> anyhow::Result<()> {
                if *corpus_value < self.lower || *corpus_value > self.upper {
                    anyhow::bail!(
                        "Value {} is out of range [{}, {}]",
                        corpus_value,
                        self.lower,
                        self.upper
                    );
                }
                Ok(())
            }
        }
    };
}

impl_domain_for_in_range_integer!(i8, i8);
impl_domain_for_in_range_integer!(u8, u8);
impl_domain_for_in_range_integer!(i16, i16);
impl_domain_for_in_range_integer!(u16, u16);
impl_domain_for_in_range_integer!(i32, i32);
impl_domain_for_in_range_integer!(u32, u32);
impl_domain_for_in_range_integer!(i64, i64);
impl_domain_for_in_range_integer!(u64, u64);
impl_domain_for_in_range_integer!(i128, i128);
impl_domain_for_in_range_integer!(u128, u128);
impl_domain_for_in_range_integer!(isize, i64);
impl_domain_for_in_range_integer!(usize, u64);

macro_rules! impl_domain_for_in_range_float {
    ($ty:ty) => {
        impl Domain for InRange<$ty> {
            type UserValue<'user> = $ty;
            type CorpusValue = $ty;

            fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
                if rng.random_bool(0.2) {
                    let mut specials = Vec::new();
                    specials.push(self.lower);
                    specials.push(self.upper);

                    let default_specials = <$ty as SpecialValues>::get();
                    for &v in default_specials {
                        if v > self.lower && v < self.upper {
                            specials.push(v);
                        }
                    }
                    let idx = rng.random_range(0..specials.len());
                    return Ok(specials[idx]);
                }

                Ok(rng.random_range(self.lower..=self.upper))
            }

            fn mutate(
                &mut self,
                val: &mut Self::CorpusValue,
                rng: &mut dyn rand::Rng,
                only_shrink: bool,
            ) -> anyhow::Result<()> {
                mutate_float(rng, val, only_shrink, Some((self.lower, self.upper)))
            }

            fn corpus_to_user_value<'a>(
                &self,
                corpus_value: &'a Self::CorpusValue,
            ) -> anyhow::Result<Self::UserValue<'a>> {
                Ok(*corpus_value)
            }

            fn validate_corpus_value(
                &self,
                corpus_value: &Self::CorpusValue,
            ) -> anyhow::Result<()> {
                if corpus_value.is_nan() || *corpus_value < self.lower || *corpus_value > self.upper
                {
                    anyhow::bail!(
                        "Value {} is out of range [{}, {}]",
                        corpus_value,
                        self.lower,
                        self.upper
                    );
                }
                Ok(())
            }
        }
    };
}

impl_domain_for_in_range_float!(f32);
impl_domain_for_in_range_float!(f64);

impl Domain for InRange<char> {
    type UserValue<'user> = char;
    type CorpusValue = char;

    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        if rng.random_bool(0.2) {
            let mut specials = Vec::new();
            specials.push(self.lower);
            specials.push(self.upper);

            let default_specials = <char as SpecialValues>::get();
            for &v in default_specials {
                if v > self.lower && v < self.upper {
                    specials.push(v);
                }
            }
            let idx = rng.random_range(0..specials.len());
            return Ok(specials[idx]);
        }

        Ok(rng.random_range(self.lower..=self.upper))
    }

    fn mutate(
        &mut self,
        val: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        if self.lower == self.upper {
            *val = self.lower;
            return Ok(());
        }
        if only_shrink {
            let target = <char>::shrinking_target(&self.lower, &self.upper);
            // Pass `char` directly rather than casting to `u32` so `SampleUniform`
            // compacts the UTF-16 surrogate gap (0xD800..=0xDFFF) during sampling.
            *val = shrink_towards(rng, *val, target);
        } else {
            // Mutate in compacted codepoint space so random walks and bit flips never land
            // in the UTF-16 surrogate gap (0xD800..=0xDFFF).
            let lower = map_char_to_int(self.lower);
            let upper = map_char_to_int(self.upper);
            let val_int = map_char_to_int((*val).clamp(self.lower, self.upper));
            let mutated_int = mutate_integer(rng, val_int, 5, Some(lower), Some(upper));
            *val = map_int_to_char(mutated_int);
        }
        Ok(())
    }

    fn corpus_to_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        Ok(*corpus_value)
    }

    fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
        if *corpus_value < self.lower || *corpus_value > self.upper {
            anyhow::bail!(
                "Value {} is out of range [{}, {}]",
                corpus_value,
                self.lower,
                self.upper
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::any::type_name;
    use std::fmt::Debug;

    use rand::rngs::{SmallRng, SysRng};
    use rand::SeedableRng;

    use super::*;

    fn get_rng() -> SmallRng {
        SmallRng::try_from_rng(&mut SysRng).unwrap()
    }

    fn test_in_range_init_property<T>(lower: T, upper: T)
    where
        T: DomainRangeBounds + PartialOrd + Debug + Copy + PartialEq + Display + 'static,
        InRange<T>: Domain<CorpusValue = T>,
    {
        let mut range = InRange::new(lower, upper);
        let mut rng = get_rng();
        for _ in 0..100 {
            let val = range.init(&mut rng).unwrap();
            assert!(
                val >= lower && val <= upper,
                "Init value {:?} out of range [{:?}, {:?}]",
                val,
                lower,
                upper
            );
        }
    }

    fn test_in_range_mutate_property<T>(lower: T, upper: T)
    where
        T: DomainRangeBounds + PartialOrd + Debug + Copy + PartialEq + Display + 'static,
        InRange<T>: Domain<CorpusValue = T>,
    {
        let mut range = InRange::new(lower, upper);
        let mut rng = get_rng();
        let val = range.init(&mut rng).unwrap();
        let mut mutated_val = val;
        let mut changed = false;
        for _ in 0..100 {
            let prev = mutated_val;
            range.mutate(&mut mutated_val, &mut rng, false).unwrap();
            assert!(
                mutated_val >= lower && mutated_val <= upper,
                "Mutated value {:?} out of range [{:?}, {:?}]",
                mutated_val,
                lower,
                upper
            );
            if mutated_val != prev {
                changed = true;
            }
        }
        assert!(
            changed,
            "Value did not change after 100 mutations for type {:?}",
            type_name::<T>()
        );
    }

    fn test_in_range_shrink_property<T>(lower: T, upper: T)
    where
        T: DomainRangeBounds + PartialOrd + Debug + Copy + PartialEq + Display + 'static,
        InRange<T>: Domain<CorpusValue = T>,
    {
        let mut range = InRange::new(lower, upper);
        let mut rng = get_rng();
        let target = T::shrinking_target(&lower, &upper);

        // Test shrinking from upper bound
        let mut shrunk_val = upper;
        for _ in 0..100 {
            let prev = shrunk_val;
            range.mutate(&mut shrunk_val, &mut rng, true).unwrap();
            assert!(
                shrunk_val >= lower && shrunk_val <= upper,
                "Shrunk value {:?} out of range [{:?}, {:?}]",
                shrunk_val,
                lower,
                upper
            );
            if prev > target {
                assert!(shrunk_val <= prev, "Value {:?} should be <= prev {:?}", shrunk_val, prev);
                assert!(
                    shrunk_val >= target,
                    "Value {:?} should be >= target {:?}",
                    shrunk_val,
                    target
                );
            }
        }

        // Test shrinking from lower bound
        let mut shrunk_val = lower;
        for _ in 0..100 {
            let prev = shrunk_val;
            range.mutate(&mut shrunk_val, &mut rng, true).unwrap();
            assert!(
                shrunk_val >= lower && shrunk_val <= upper,
                "Shrunk value {:?} out of range [{:?}, {:?}]",
                shrunk_val,
                lower,
                upper
            );
            if prev < target {
                assert!(shrunk_val >= prev, "Value {:?} should be >= prev {:?}", shrunk_val, prev);
                assert!(
                    shrunk_val <= target,
                    "Value {:?} should be <= target {:?}",
                    shrunk_val,
                    target
                );
            }
        }
    }

    fn test_in_range_properties<T>(lower: T, upper: T)
    where
        T: DomainRangeBounds + PartialOrd + Debug + Copy + PartialEq + Display + 'static,
        InRange<T>: Domain<CorpusValue = T>,
    {
        test_in_range_init_property(lower, upper);
        test_in_range_mutate_property(lower, upper);
        test_in_range_shrink_property(lower, upper);
    }

    #[test]
    fn test_in_range_i8() {
        test_in_range_properties::<i8>(-10, 10);
        test_in_range_properties::<i8>(0, 100);
        test_in_range_properties::<i8>(-100, -10);
    }
    #[test]
    fn test_in_range_u8() {
        test_in_range_properties::<u8>(10, 50);
    }
    #[test]
    fn test_in_range_i16() {
        test_in_range_properties::<i16>(-100, 100);
        test_in_range_properties::<i16>(0, 1000);
        test_in_range_properties::<i16>(-1000, -100);
    }
    #[test]
    fn test_in_range_u16() {
        test_in_range_properties::<u16>(100, 500);
    }
    #[test]
    fn test_in_range_i32() {
        test_in_range_properties::<i32>(-1000, 1000);
        test_in_range_properties::<i32>(0, 10000);
        test_in_range_properties::<i32>(-10000, -1000);
    }
    #[test]
    fn test_in_range_u32() {
        test_in_range_properties::<u32>(1000, 5000);
    }
    #[test]
    fn test_in_range_i64() {
        test_in_range_properties::<i64>(-10000, 10000);
        test_in_range_properties::<i64>(0, 100000);
        test_in_range_properties::<i64>(-100000, -10000);
    }
    #[test]
    fn test_in_range_u64() {
        test_in_range_properties::<u64>(10000, 50000);
    }
    #[test]
    fn test_in_range_i128() {
        test_in_range_properties::<i128>(-100000, 100000);
        test_in_range_properties::<i128>(0, 1000000);
        test_in_range_properties::<i128>(-1000000, -100000);
    }
    #[test]
    fn test_in_range_u128() {
        test_in_range_properties::<u128>(0, 200000);
        test_in_range_properties::<u128>(100000, 500000);
        test_in_range_properties::<u128>(1000000, 2000000);
    }
    #[test]
    fn test_in_range_isize() {
        test_in_range_properties::<isize>(-1000, 1000);
        test_in_range_properties::<isize>(0, 10000);
        test_in_range_properties::<isize>(-10000, -1000);
    }
    #[test]
    fn test_in_range_usize() {
        test_in_range_properties::<usize>(0, 2000);
        test_in_range_properties::<usize>(1000, 5000);
        test_in_range_properties::<usize>(10000, 20000);
    }
    #[test]
    fn test_in_range_f32() {
        test_in_range_properties::<f32>(-1.0, 1.0);
        test_in_range_properties::<f32>(0.0, 100.0);
        test_in_range_properties::<f32>(-100.0, -10.0);
        test_in_range_properties::<f32>(1.0, f32::from_bits(1.0f32.to_bits() + 1));
    }
    #[test]
    fn test_in_range_f64() {
        test_in_range_properties::<f64>(-1.0, 1.0);
        test_in_range_properties::<f64>(0.0, 1.0e10);
        test_in_range_properties::<f64>(-1.0e10, -1.0);
    }
    #[test]
    fn test_in_range_char() {
        test_in_range_properties::<char>('a', 'z');
        test_in_range_properties::<char>('A', 'Z');
        test_in_range_properties::<char>('0', '9');
        test_in_range_properties::<char>('\u{D700}', '\u{E100}');
    }

    #[test]
    #[should_panic(expected = "InRange: lower bound")]
    fn test_invalid_range_panic_integer() {
        InRange::<i32>::new(10, 0);
    }

    #[test]
    #[should_panic(expected = "InRange: lower bound")]
    fn test_invalid_range_panic_float() {
        InRange::<f32>::new(1.0, 0.0);
    }

    #[test]
    #[should_panic(expected = "Range is too large!")]
    fn test_invalid_range_panic_float_large() {
        InRange::<f32>::new(-3.0e38f32, 3.0e38f32);
    }

    #[test]
    fn test_in_range_singleton() {
        let mut rng = get_rng();

        let mut int_range = InRange::<i32>::new(5, 5);
        let mut int_val = int_range.init(&mut rng).unwrap();
        assert_eq!(int_val, 5);
        int_range.mutate(&mut int_val, &mut rng, false).unwrap();
        assert_eq!(int_val, 5);
        int_range.mutate(&mut int_val, &mut rng, true).unwrap();
        assert_eq!(int_val, 5);

        let mut float_range = InRange::<f64>::new(2.5, 2.5);
        let mut float_val = float_range.init(&mut rng).unwrap();
        assert_eq!(float_val, 2.5);
        float_range.mutate(&mut float_val, &mut rng, false).unwrap();
        assert_eq!(float_val, 2.5);
        float_range.mutate(&mut float_val, &mut rng, true).unwrap();
        assert_eq!(float_val, 2.5);

        let mut char_range = InRange::<char>::new('a', 'a');
        let mut char_val = char_range.init(&mut rng).unwrap();
        assert_eq!(char_val, 'a');
        char_range.mutate(&mut char_val, &mut rng, false).unwrap();
        assert_eq!(char_val, 'a');
        char_range.mutate(&mut char_val, &mut rng, true).unwrap();
        assert_eq!(char_val, 'a');
    }
}
