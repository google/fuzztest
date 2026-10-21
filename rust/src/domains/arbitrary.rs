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

use super::utility::choose_value;
use super::utility::map_char_to_int;
use super::utility::map_int_to_char;
use super::utility::mutate_integer;
use super::utility::shrink_towards;
use super::utility::NUM_VALID_CODEPOINTS;
use super::Domain;
use super::ReversibleDomain;
use std::fmt;
use std::marker::PhantomData;

use anyhow;
use rand::RngExt;

/// Generates arbitrary values of type `T`.
///
/// This domain is used to generate values of a specific type without any constraints
/// beyond the type's intrinsic range. For example, `Arbitrary<i32>` generates `i32`
/// values spanning the whole `i32` domain `[i32::MIN, i32::MAX]`.
///
/// Example usage:
/// ```
/// # use fuzztest::domains::Domain;
/// # use fuzztest::domains::arbitrary::Arbitrary;
/// # use rand::rngs::SmallRng;
/// # use rand::SeedableRng;
///
/// let mut arbitrary_i32 = Arbitrary::<i32>::default();
/// let mut rng = SmallRng::seed_from_u64(73);
///
/// let sample = arbitrary_i32.init(&mut rng);
/// assert!(sample.is_ok());
/// ```
pub struct Arbitrary<T> {
    _phantom: PhantomData<T>,
}

impl<T: Clone> Clone for Arbitrary<T> {
    fn clone(&self) -> Self {
        Self { _phantom: PhantomData }
    }
}

impl<T: fmt::Debug> fmt::Debug for Arbitrary<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Arbitrary").field("_phantom", &self._phantom).finish()
    }
}

// We cannot just use `#[derive(Default)]` because `T` might not be `Default`.
impl<T> Default for Arbitrary<T> {
    fn default() -> Self {
        Self { _phantom: PhantomData }
    }
}

impl<T> Arbitrary<T> {
    /// Creates a new `Arbitrary` domain for the given type `T`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Domain for Arbitrary<bool> {
    type UserValue<'user> = bool;
    type CorpusValue = bool;

    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        Ok(rng.random())
    }

    fn mutate(
        &mut self,
        val: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        if only_shrink {
            // Convention taken from the C++ fuzztest library.
            *val = false;
        } else {
            *val = rng.random();
        }
        Ok(())
    }

    fn corpus_to_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        Ok(*corpus_value)
    }

    fn validate_corpus_value(&self, _corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
        Ok(())
    }
}

impl ReversibleDomain<bool> for Arbitrary<bool> {
    fn to_unvalidated_corpus_value(&self, value: bool) -> anyhow::Result<Self::CorpusValue> {
        Ok(value)
    }
}

impl<'a> ReversibleDomain<&'a bool> for Arbitrary<bool> {
    fn to_unvalidated_corpus_value(&self, value: &'a bool) -> anyhow::Result<Self::CorpusValue> {
        Ok(*value)
    }
}

macro_rules! impl_domain_for_integer {
    // We need an additional "integer type" for this, because
    // rand::distr::Distribution<> is not implemented for StandardUniform for isize and usize.
    // so we perform the generation using integer types and cast to the size types if needed.
    ($ty:ty, $int_ty:ty) => {
        impl Domain for Arbitrary<$ty> {
            type UserValue<'user> = $ty;
            type CorpusValue = $ty;

            fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
                // We generate the equivalent integer type so this works for size types.
                let val: $int_ty = choose_value(rng);
                Ok(val as $ty)
            }

            fn mutate(
                &mut self,
                val: &mut Self::CorpusValue,
                rng: &mut dyn rand::Rng,
                only_shrink: bool,
            ) -> anyhow::Result<()> {
                if only_shrink {
                    *val = shrink_towards(rng, *val as $int_ty, 0) as $ty;
                } else {
                    let original_val = *val;
                    loop {
                        *val = mutate_integer(rng, *val as $int_ty, 5, None, None) as $ty;
                        if *val != original_val {
                            break;
                        }
                    }
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
                _corpus_value: &Self::CorpusValue,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }

        impl ReversibleDomain<$ty> for Arbitrary<$ty> {
            fn to_unvalidated_corpus_value(&self, value: $ty) -> anyhow::Result<Self::CorpusValue> {
                Ok(value)
            }
        }

        impl<'a> ReversibleDomain<&'a $ty> for Arbitrary<$ty> {
            fn to_unvalidated_corpus_value(
                &self,
                value: &'a $ty,
            ) -> anyhow::Result<Self::CorpusValue> {
                Ok(*value)
            }
        }
    };
}

impl_domain_for_integer!(i8, i8);
impl_domain_for_integer!(u8, u8);
impl_domain_for_integer!(i16, i16);
impl_domain_for_integer!(u16, u16);
impl_domain_for_integer!(i32, i32);
impl_domain_for_integer!(u32, u32);
impl_domain_for_integer!(i64, i64);
impl_domain_for_integer!(u64, u64);
impl_domain_for_integer!(i128, i128);
impl_domain_for_integer!(u128, u128);
impl_domain_for_integer!(isize, i64);
impl_domain_for_integer!(usize, u64);

macro_rules! impl_domain_for_float {
    ($ty:ty) => {
        impl Domain for Arbitrary<$ty> {
            type UserValue<'user> = $ty;
            type CorpusValue = $ty;

            fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
                Ok(choose_value(rng))
            }

            fn mutate(
                &mut self,
                val: &mut Self::CorpusValue,
                rng: &mut dyn rand::Rng,
                only_shrink: bool,
            ) -> anyhow::Result<()> {
                if only_shrink {
                    // Shrink only finite, non-terminal values.
                    if val.is_finite() && *val != 0.0 {
                        *val = shrink_towards(rng, *val, 0.0);
                    }
                    return Ok(());
                }
                // Non-shrinking mutation.
                let original_val = *val;
                loop {
                    // Loop to ensure mutation
                    if !val.is_finite() {
                        // NaN or Infinity
                        *val = self.init(rng)?;
                    } else {
                        match rng.random_range(0..4) {
                            0 => *val /= 2.0,
                            1 => *val = -*val,
                            2 => *val += 1.0,
                            3 => *val *= 3.0,
                            _ => unreachable!(),
                        }
                    }

                    if (val.is_nan() && original_val.is_nan()) || *val == original_val {
                        continue;
                    }
                    break;
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
                _corpus_value: &Self::CorpusValue,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }

        impl ReversibleDomain<$ty> for Arbitrary<$ty> {
            fn to_unvalidated_corpus_value(&self, value: $ty) -> anyhow::Result<Self::CorpusValue> {
                Ok(value)
            }
        }

        impl<'a> ReversibleDomain<&'a $ty> for Arbitrary<$ty> {
            fn to_unvalidated_corpus_value(
                &self,
                value: &'a $ty,
            ) -> anyhow::Result<Self::CorpusValue> {
                Ok(*value)
            }
        }
    };
}

impl_domain_for_float!(f32);
impl_domain_for_float!(f64);

impl Domain for Arbitrary<char> {
    type UserValue<'user> = char;
    type CorpusValue = char;

    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        Ok(choose_value(rng))
    }

    fn mutate(
        &mut self,
        val: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        if only_shrink {
            // Shrink towards the null character (0 as char).
            *val = shrink_towards(rng, *val, 0 as char);
        } else {
            let original_val = *val;
            loop {
                // Map the current char to a u32 in a contiguous range.
                let mapped_val = map_char_to_int(*val);
                // Mutate the u32 value within the valid range of mapped code points.
                let mutated_mapped_val =
                    mutate_integer(rng, mapped_val, 5, Some(0), Some(NUM_VALID_CODEPOINTS - 1));
                // Map the mutated u32 back to a char.
                *val = map_int_to_char(mutated_mapped_val);
                if *val != original_val {
                    break;
                }
            }
        }
        Ok(())
    }

    fn corpus_to_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        Ok(*corpus_value)
    }

    fn validate_corpus_value(&self, _corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
        Ok(())
    }
}

impl ReversibleDomain<char> for Arbitrary<char> {
    fn to_unvalidated_corpus_value(&self, value: char) -> anyhow::Result<Self::CorpusValue> {
        Ok(value)
    }
}

impl<'a> ReversibleDomain<&'a char> for Arbitrary<char> {
    fn to_unvalidated_corpus_value(&self, value: &'a char) -> anyhow::Result<Self::CorpusValue> {
        Ok(*value)
    }
}

impl Domain for Arbitrary<()> {
    type UserValue<'user> = ();
    type CorpusValue = ();

    fn init(&mut self, _rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        Ok(())
    }

    fn mutate(
        &mut self,
        _val: &mut Self::CorpusValue,
        _rng: &mut dyn rand::Rng,
        _only_shrink: bool,
    ) -> anyhow::Result<()> {
        // No possible mutation for the unit type
        Ok(())
    }

    fn corpus_to_user_value<'a>(
        &self,
        _corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        Ok(())
    }

    fn validate_corpus_value(&self, _corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
        Ok(())
    }
}

impl ReversibleDomain<()> for Arbitrary<()> {
    fn to_unvalidated_corpus_value(&self, value: ()) -> anyhow::Result<Self::CorpusValue> {
        Ok(value)
    }
}

impl<'a> ReversibleDomain<&'a ()> for Arbitrary<()> {
    fn to_unvalidated_corpus_value(&self, value: &'a ()) -> anyhow::Result<Self::CorpusValue> {
        Ok(*value)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fmt::Debug;
    use std::hash::Hash;

    use googletest::prelude::*;
    use num_traits::{Float, One, Zero};
    use rand::distr::uniform::SampleUniform;
    use rand::distr::{Distribution, StandardUniform};
    use rand::rngs::{SmallRng, SysRng};
    use rand::SeedableRng;

    use crate::domains::utility::SpecialValues;
    use crate::domains::Domain;
    use crate::domains::ReversibleDomain;
    use crate::domains::SeedableDomainExt;

    use super::*;

    type CorpusValueForArbitrary<T> = <Arbitrary<T> as Domain>::CorpusValue;

    fn get_rng() -> SmallRng {
        SmallRng::try_from_rng(&mut SysRng).unwrap()
    }

    /// Trait to be able to treat numerical types uniformly w.r.t. finiteness and shrinking target.
    trait NumTraitsExtended {
        fn is_finite_value(&self) -> bool;
        fn is_at_shrink_target(&self) -> bool;
    }

    macro_rules! impl_num_traits_extended_for_floats {
        ($($ty:ty),*) => {
            $(
                impl NumTraitsExtended for $ty {
                    fn is_finite_value(&self) -> bool {
                        self.is_finite()
                    }
                    fn is_at_shrink_target(&self) -> bool {
                        // We arbitrarily use EPSILON^2 as the accuracy margin for approximate equality.
                        self.abs() < <$ty>::EPSILON * <$ty>::EPSILON
                    }
                }
            )*
        };
    }

    impl_num_traits_extended_for_floats!(f32, f64);

    macro_rules! impl_num_traits_extended_for_non_floats {
        ($($ty:ty),*) => {
            $(
                impl NumTraitsExtended for $ty {
                    fn is_finite_value(&self) -> bool {
                        true
                    }
                    fn is_at_shrink_target(&self) -> bool {
                        *self == <$ty>::default()
                    }
                }
            )*
        };
    }

    impl_num_traits_extended_for_non_floats!(
        i8,
        i16,
        i32,
        i64,
        i128,
        isize,
        u8,
        u16,
        u32,
        u64,
        u128,
        usize,
        bool,
        char,
        ()
    );

    fn test_arbitrary_mutations_change_value<T>()
    where
        for<'user> Arbitrary<T>: Domain<UserValue<'user> = T>,
        CorpusValueForArbitrary<T>:
            std::fmt::Debug + Default + Clone + Copy + PartialOrd + PartialEq + 'static,
    {
        let mut domain = Arbitrary::<T>::default();
        let mut rng = get_rng();
        let mut value = domain.init(&mut rng).unwrap();

        // Mutation is guaranteed to change the value.
        for _ in 0..100 {
            let original_value = value;
            domain.mutate(&mut value, &mut rng, false).unwrap();
            assert_ne!(
                value,
                original_value,
                "Mutation did not change the value for type {}",
                std::any::type_name::<T>()
            );
        }
    }

    fn test_arbitrary_mutations_generates_diverse_values<T>()
    where
        for<'user> Arbitrary<T>: Domain<UserValue<'user> = T>,
        CorpusValueForArbitrary<T>: std::fmt::Debug
            + Default
            + Clone
            + Copy
            + PartialOrd
            + PartialEq
            + Eq
            + std::hash::Hash
            + 'static,
    {
        let mut domain = Arbitrary::<T>::default();
        let mut rng = get_rng();
        for _ in 0..100 {
            let mut value = domain.init(&mut rng).unwrap();
            let mut values = HashSet::new();
            values.insert(value);

            for _ in 0..100 {
                domain.mutate(&mut value, &mut rng, false).unwrap();
                values.insert(value);
            }
            assert!(
                values.len() >= 50,
                "Mutation did not generate diverse values for type {}: found {} distinct values, expected >= 50",
                std::any::type_name::<T>(),
                values.len()
            );
        }
    }

    fn test_arbitrary_shrinking_reduces_and_terminates<T>()
    where
        for<'user> Arbitrary<T>: Domain<UserValue<'user> = T>,
        CorpusValueForArbitrary<T>: std::fmt::Debug
            + Default
            + Clone
            + Copy
            + PartialOrd
            + PartialEq
            + NumTraitsExtended
            + 'static,
    {
        let mut domain = Arbitrary::<T>::default();
        let mut rng = get_rng();

        // Get a value that is not the shrink target
        let shrink_target = CorpusValueForArbitrary::<T>::default();
        let mut value;
        loop {
            value = domain.init(&mut rng).unwrap();
            if !value.is_at_shrink_target() && value.is_finite_value() {
                break;
            }
        }

        for _ in 0..1000 {
            let prev_value = value;
            domain.mutate(&mut value, &mut rng, true).unwrap();

            if value.is_at_shrink_target() {
                // Ensure that once the shrink target is reached, further shrinking doesn't change
                // it.
                domain.mutate(&mut value, &mut rng, true).unwrap();
                assert!(
                    value.is_at_shrink_target(),
                    "Shrinking past the target changed the value for type {}",
                    std::any::type_name::<T>()
                );
                return;
            }

            // Check progress
            if prev_value > shrink_target {
                assert!(
                    value < prev_value,
                    "Value should decrease when shrinking towards target from above. Type: {}, Prev: {:?}, Current: {:?}",
                    std::any::type_name::<T>(),
                    prev_value,
                    value
                );
                assert!(
                    value >= shrink_target,
                    "Value should not shrink past the target from above. Type: {}, Prev: {:?}, Current: {:?}, Target: {:?}",
                    std::any::type_name::<T>(),
                    prev_value,
                    value,
                    shrink_target
                );
            } else {
                // prev_value < shrink_target
                assert!(
                    value > prev_value,
                    "Value should increase when shrinking towards target from below. Type: {}, Prev: {:?}, Current: {:?}",
                    std::any::type_name::<T>(),
                    prev_value,
                    value
                );
                assert!(
                    value <= shrink_target,
                    "Value should not shrink past the target from below. Type: {}, Prev: {:?}, Current: {:?}, Target: {:?}",
                    std::any::type_name::<T>(),
                    prev_value,
                    value,
                    shrink_target
                );
            }
        }

        panic!(
            "Shrinking did not terminate in 1000 iterations for type {}",
            std::any::type_name::<T>()
        );
    }

    fn test_arbitrary<T>()
    where
        for<'user> Arbitrary<T>: Domain<UserValue<'user> = T>,
        CorpusValueForArbitrary<T>: std::fmt::Debug
            + Default
            + Clone
            + Copy
            + PartialOrd
            + PartialEq
            + Eq
            + std::hash::Hash
            + NumTraitsExtended
            + 'static,
    {
        test_arbitrary_mutations_change_value::<T>();
        test_arbitrary_mutations_generates_diverse_values::<T>();
        test_arbitrary_shrinking_reduces_and_terminates::<T>();
    }

    #[test]
    fn test_i8() {
        test_arbitrary::<i8>();
    }
    #[test]
    fn test_u8() {
        test_arbitrary::<u8>();
    }
    #[test]
    fn test_i16() {
        test_arbitrary::<i16>();
    }
    #[test]
    fn test_u16() {
        test_arbitrary::<u16>();
    }
    #[test]
    fn test_i32() {
        test_arbitrary::<i32>();
    }
    #[test]
    fn test_u32() {
        test_arbitrary::<u32>();
    }
    #[test]
    fn test_i64() {
        test_arbitrary::<i64>();
    }
    #[test]
    fn test_u64() {
        test_arbitrary::<u64>();
    }
    #[test]
    fn test_i128() {
        test_arbitrary::<i128>();
    }
    #[test]
    fn test_u128() {
        test_arbitrary::<u128>();
    }
    #[test]
    fn test_isize() {
        test_arbitrary::<isize>();
    }
    #[test]
    fn test_usize() {
        test_arbitrary::<usize>();
    }

    #[test]
    fn test_char() {
        test_arbitrary::<char>();
    }

    fn test_bool_shrink() {
        let mut domain = Arbitrary::<bool>::default();
        let mut rng = get_rng();
        let mut value = true;
        domain.mutate(&mut value, &mut rng, true).unwrap();
        assert_eq!(value, false);
        domain.mutate(&mut value, &mut rng, true).unwrap();
        assert_eq!(value, false);
    }

    #[test]
    fn test_bool() {
        test_arbitrary_shrinking_reduces_and_terminates::<bool>();
        test_bool_shrink();
    }
    #[test]
    fn test_unit() {
        let mut rng = get_rng();
        let mut domain = Arbitrary::<()>::default();

        // init() always returns ()
        assert_eq!(domain.init(&mut rng).unwrap(), ());

        // mutate (non-shrinking) always returns ()
        let mut value = ();
        domain.mutate(&mut value, &mut rng, false).unwrap();
        assert_eq!(value, ());

        // mutate (shrinking) always returns ()
        let mut value = ();
        domain.mutate(&mut value, &mut rng, true).unwrap();
        assert_eq!(value, ());
    }

    fn test_float_special_value_shrink<T>()
    where
        for<'user> Arbitrary<T>: Domain<UserValue<'user> = T>,
        CorpusValueForArbitrary<T>:
            Float + SampleUniform + std::fmt::Display + std::fmt::Debug + SpecialValues + 'static,
        StandardUniform: Distribution<T>,
    {
        let mut domain = Arbitrary::<T>::default();
        let mut rng = get_rng();

        // Positive.
        let mut v = CorpusValueForArbitrary::<T>::one();
        let original_v = v;
        domain.mutate(&mut v, &mut rng, true).unwrap();
        assert!(
            v >= CorpusValueForArbitrary::<T>::zero() && v < original_v,
            "Shrinking {} to {}",
            original_v,
            v
        );

        // Negative.
        let mut v = -CorpusValueForArbitrary::<T>::one();
        let original_v = v;
        domain.mutate(&mut v, &mut rng, true).unwrap();
        assert!(
            v > original_v && v <= CorpusValueForArbitrary::<T>::zero(),
            "Shrinking {} to {}",
            original_v,
            v
        );

        // Zero.
        let mut v = CorpusValueForArbitrary::<T>::zero();
        domain.mutate(&mut v, &mut rng, true).unwrap();
        assert_eq!(v, CorpusValueForArbitrary::<T>::zero());

        let mut v = CorpusValueForArbitrary::<T>::neg_zero();
        domain.mutate(&mut v, &mut rng, true).unwrap();
        assert_eq!(v, CorpusValueForArbitrary::<T>::neg_zero());

        // NaN / Inf are not changed by this shrink implementation.
        let mut v = CorpusValueForArbitrary::<T>::nan();
        domain.mutate(&mut v, &mut rng, true).unwrap();
        assert!(v.is_nan(), "NaN should remain NaN");

        let mut v = CorpusValueForArbitrary::<T>::infinity();
        domain.mutate(&mut v, &mut rng, true).unwrap();
        assert!(v.is_infinite() && v.is_sign_positive(), "Infinity should remain Infinity");

        let mut v = CorpusValueForArbitrary::<T>::neg_infinity();
        domain.mutate(&mut v, &mut rng, true).unwrap();
        assert!(v.is_infinite() && v.is_sign_negative(), "Neg Infinity should remain Neg Infinity");
    }

    #[test]
    fn test_f32() {
        test_arbitrary_mutations_change_value::<f32>();
        test_arbitrary_shrinking_reduces_and_terminates::<f32>();
        test_float_special_value_shrink::<f32>();
    }

    #[test]
    fn test_f64() {
        test_arbitrary_mutations_change_value::<f64>();
        test_arbitrary_shrinking_reduces_and_terminates::<f64>();
        test_float_special_value_shrink::<f64>();
    }

    #[test]
    fn test_char_mutate_boundaries() {
        let mut domain = Arbitrary::<char>::default();
        let mut rng = get_rng();
        let mut val = '\u{0000}';
        domain.mutate(&mut val, &mut rng, false).unwrap();
        assert!(val >= '\u{0000}');

        val = '\u{10FFFF}';
        domain.mutate(&mut val, &mut rng, false).unwrap();
        assert!(val <= '\u{10FFFF}');

        val = '\u{D7FF}'; // Before surrogate
        domain.mutate(&mut val, &mut rng, false).unwrap();

        val = '\u{E000}'; // After surrogate
        domain.mutate(&mut val, &mut rng, false).unwrap();
    }

    #[test]
    fn test_char_shrink_to_null() {
        for _ in 0..10 {
            let mut domain = Arbitrary::<char>::default();
            let mut rng = get_rng();
            let mut value = domain.init(&mut rng).unwrap();

            let mut iterations = 0;
            const MAX_ITERATIONS: u32 = 100_000;

            while value != '\0' && iterations < MAX_ITERATIONS {
                domain.mutate(&mut value, &mut rng, true).unwrap();
                // Ensure that the value is always a valid char after mutation.
                assert!(char::from_u32(value as u32).is_some());
                iterations += 1;
            }
            assert_eq!(
                value, '\0',
                "Char did not shrink to null within {} iterations. Final value: {}",
                MAX_ITERATIONS, value
            );
        }
    }

    fn test_arbitrary_seeding<T>(eager_seeds: [T; 2], provider_seeds: [T; 2])
    where
        T: Copy + Eq + Hash + Debug + Send + 'static,
        for<'u> Arbitrary<T>: ReversibleDomain<T, UserValue<'u> = T, CorpusValue = T>,
    {
        let mut domain = Arbitrary::<T>::default()
            .with_seeds(eager_seeds)
            .with_seed_provider(move || provider_seeds);
        let mut rng = get_rng();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        for seed in eager_seeds {
            expect_that!(observed, contains(eq(&seed)));
        }
        for seed in provider_seeds {
            expect_that!(observed, contains(eq(&seed)));
        }
    }

    #[gtest]
    fn test_arbitrary_seeding_integers_and_char() {
        test_arbitrary_seeding::<i8>([-42, 42], [i8::MIN, i8::MAX]);
        test_arbitrary_seeding::<u8>([7, 42], [u8::MIN, u8::MAX]);
        test_arbitrary_seeding::<i16>([-1234, 1234], [i16::MIN, i16::MAX]);
        test_arbitrary_seeding::<u16>([1234, 5678], [u16::MIN, u16::MAX]);
        test_arbitrary_seeding::<i32>([-123456, 123456], [i32::MIN, i32::MAX]);
        test_arbitrary_seeding::<u32>([123456, 654321], [u32::MIN, u32::MAX]);
        test_arbitrary_seeding::<i64>([-123456789, 123456789], [i64::MIN, i64::MAX]);
        test_arbitrary_seeding::<u64>([123456789, 987654321], [u64::MIN, u64::MAX]);
        test_arbitrary_seeding::<i128>([-123456789, 123456789], [i128::MIN, i128::MAX]);
        test_arbitrary_seeding::<u128>([123456789, 987654321], [u128::MIN, u128::MAX]);
        test_arbitrary_seeding::<isize>([-12345, 12345], [isize::MIN, isize::MAX]);
        test_arbitrary_seeding::<usize>([12345, 54321], [usize::MIN, usize::MAX]);
        test_arbitrary_seeding::<char>(['a', 'Z'], ['\0', '\u{10FFFF}']);
    }

    #[gtest]
    fn test_arbitrary_seeding_bool() {
        let mut domain =
            Arbitrary::<bool>::default().with_seeds([true]).with_seed_provider(|| [false]);
        let mut rng = get_rng();
        let mut observed = HashSet::new();
        for _ in 0..200 {
            observed.insert(domain.init(&mut rng).unwrap());
        }
        expect_true!(observed.contains(&true));
        expect_true!(observed.contains(&false));
    }

    #[gtest]
    fn test_arbitrary_seeding_floats() {
        {
            let seeds = [42.5f32, f32::INFINITY, f32::NEG_INFINITY];
            let provider_seeds = [f32::NAN, -0.0f32];
            let mut domain = Arbitrary::<f32>::default()
                .with_seeds(seeds)
                .with_seed_provider(move || provider_seeds);
            let mut rng = get_rng();
            let mut observed_bits = HashSet::new();
            for _ in 0..300 {
                observed_bits.insert(domain.init(&mut rng).unwrap().to_bits());
            }
            for expected in seeds.into_iter().chain(provider_seeds) {
                expect_that!(observed_bits, contains(eq(&expected.to_bits())));
            }
        }

        {
            let seeds = [42.5f64, f64::INFINITY, f64::NEG_INFINITY];
            let provider_seeds = [f64::NAN, -0.0f64];
            let mut domain = Arbitrary::<f64>::default()
                .with_seeds(seeds)
                .with_seed_provider(move || provider_seeds);
            let mut rng = get_rng();
            let mut observed_bits = HashSet::new();
            for _ in 0..300 {
                observed_bits.insert(domain.init(&mut rng).unwrap().to_bits());
            }
            for expected in seeds.into_iter().chain(provider_seeds) {
                expect_that!(observed_bits, contains(eq(&expected.to_bits())));
            }
        }
    }

    #[gtest]
    fn test_arbitrary_seeding_unit() {
        let mut domain = Arbitrary::<()>::default()
            .with_seeds([()])
            .with_seeds(&[()])
            .with_seed_provider(|| [()]);
        let mut rng = get_rng();
        for _ in 0..10 {
            expect_that!(domain.init(&mut rng).unwrap(), eq(()));
        }
    }
}
