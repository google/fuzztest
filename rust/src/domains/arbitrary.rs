use super::utility::choose_value;
use super::utility::mutate_integer;
use super::utility::shrink_towards;
use super::Domain;

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
/// let arbitrary_i32 = Arbitrary::<i32>::default();
/// let mut rng = SmallRng::seed_from_u64(73);
///
/// let sample = arbitrary_i32.init(&mut rng);
/// assert!(sample.is_ok());
/// ```

pub struct Arbitrary<T> {
    _phantom: std::marker::PhantomData<T>,
}

// We cannot just use `#[derive(Default)]` because `T` might not be `Default`.
impl<T> Default for Arbitrary<T> {
    fn default() -> Self {
        Self { _phantom: std::marker::PhantomData }
    }
}

impl<T> Arbitrary<T> {
    /// Creates a new `Arbitrary` domain for the given type `T`.
    pub fn new() -> Self {
        Self { _phantom: std::marker::PhantomData }
    }
}

impl Domain for Arbitrary<bool> {
    type UserValue<'user> = bool;
    type CorpusValue = bool;

    fn init(&self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        Ok(rng.random())
    }

    fn mutate(
        &self,
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

    fn get_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        Ok(*corpus_value)
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

            fn init(&self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
                // We generate a the equivalent integer type so this works for size types.
                let val: $int_ty = choose_value(rng);
                Ok(val as $ty)
            }

            fn mutate(
                &self,
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

            fn get_user_value<'a>(
                &self,
                corpus_value: &'a Self::CorpusValue,
            ) -> anyhow::Result<Self::UserValue<'a>> {
                Ok(*corpus_value)
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

            fn init(&self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
                Ok(choose_value(rng))
            }

            fn mutate(
                &self,
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

            fn get_user_value<'a>(
                &self,
                corpus_value: &'a Self::CorpusValue,
            ) -> anyhow::Result<Self::UserValue<'a>> {
                Ok(*corpus_value)
            }
        }
    };
}

impl_domain_for_float!(f32);
impl_domain_for_float!(f64);

const SURROGATE_START: u32 = 0xD800;
const SURROGATE_END: u32 = 0xDFFF;
const MAX_VALID_CODEPOINT: u32 = 0x10FFFF;
const NUM_VALID_CODEPOINTS: u32 = MAX_VALID_CODEPOINT - (SURROGATE_END - SURROGATE_START);

/// Maps a `char` to a `u32` in a contiguous range.
///
/// Rust's `char` type represents a Unicode Scalar Value, which means it cannot be a
/// surrogate code point (U+D800 to U+DFFF). This function maps `char` values to a
/// contiguous integer range by shifting down the code points that are above the
/// surrogate range. This is useful for mutation strategies like random walks over
/// a dense integer space.
fn map_char_to_int(c: char) -> u32 {
    let val = c as u32;
    if val >= SURROGATE_START {
        val - (SURROGATE_END - SURROGATE_START + 1)
    } else {
        val
    }
}

/// Maps a `u32` from the contiguous range back to a `char`.
///
/// This is the inverse of `map_char_to_int`. It converts an integer from the
/// dense range back to a `char`. Integers that fall within the range previously
/// occupied by surrogates are shifted up to their correct code points.
fn map_int_to_char(u: u32) -> char {
    assert!(
        u < NUM_VALID_CODEPOINTS,
        "input to map_int_to_char out of range: got {}, expected value < {}",
        u,
        NUM_VALID_CODEPOINTS
    );
    let val = if u >= SURROGATE_START { u + (SURROGATE_END - SURROGATE_START + 1) } else { u };
    std::char::from_u32(val).unwrap()
}

impl Domain for Arbitrary<char> {
    type UserValue<'user> = char;
    type CorpusValue = char;

    fn init(&self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        Ok(choose_value(rng))
    }

    fn mutate(
        &self,
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

    fn get_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        Ok(*corpus_value)
    }
}

impl Domain for Arbitrary<()> {
    type UserValue<'user> = ();
    type CorpusValue = ();

    fn init(&self, _rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        Ok(())
    }

    fn mutate(
        &self,
        _val: &mut Self::CorpusValue,
        _rng: &mut dyn rand::Rng,
        _only_shrink: bool,
    ) -> anyhow::Result<()> {
        // No possible mutation for the unit type
        Ok(())
    }

    fn get_user_value<'a>(
        &self,
        _corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::domains::utility::SpecialValues;
    use num_traits::{Float, One, Zero};
    use rand::distr::uniform::SampleUniform;
    use rand::distr::{Distribution, StandardUniform};
    use rand::rngs::{SmallRng, SysRng};
    use rand::SeedableRng;

    use crate::domains::Domain;

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
        let domain = Arbitrary::<T>::default();
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
        let domain = Arbitrary::<T>::default();
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
        let domain = Arbitrary::<T>::default();
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
                // Ensure that once the shrink target is reached, further shrinking doesn't change it.
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
        let domain = Arbitrary::<bool>::default();
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
        let domain = Arbitrary::<()>::default();

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
        let domain = Arbitrary::<T>::default();
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
        let domain = Arbitrary::<char>::default();
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
    fn test_char_mapping() {
        // Test boundary conditions and values around the surrogate range
        assert_eq!(map_char_to_int('\u{0000}'), 0);
        assert_eq!(map_int_to_char(0), '\u{0000}');

        let before_surrogate = SURROGATE_START - 1;
        assert_eq!(
            map_char_to_int(std::char::from_u32(before_surrogate).unwrap()),
            before_surrogate
        );
        assert_eq!(
            map_int_to_char(before_surrogate),
            std::char::from_u32(before_surrogate).unwrap()
        );

        let after_surrogate = SURROGATE_END + 1;
        let mapped_after_surrogate = map_char_to_int(std::char::from_u32(after_surrogate).unwrap());
        assert_eq!(mapped_after_surrogate, SURROGATE_START);
        assert_eq!(map_int_to_char(SURROGATE_START), std::char::from_u32(after_surrogate).unwrap());

        assert_eq!(map_char_to_int('\u{10FFFF}'), NUM_VALID_CODEPOINTS - 1);
        assert_eq!(map_int_to_char(NUM_VALID_CODEPOINTS - 1), '\u{10FFFF}');
    }

    #[test]
    fn test_char_shrink_to_null() {
        for _ in 0..10 {
            let domain = Arbitrary::<char>::default();
            let mut rng = get_rng();
            let mut value = domain.init(&mut rng).unwrap();

            let mut iterations = 0;
            const MAX_ITERATIONS: u32 = 100_000;

            while value != '\0' && iterations < MAX_ITERATIONS {
                domain.mutate(&mut value, &mut rng, true).unwrap();
                // Ensure that the value is always a valid char after mutation.
                assert!(std::char::from_u32(value as u32).is_some());
                iterations += 1;
            }
            assert_eq!(
                value, '\0',
                "Char did not shrink to null within {} iterations. Final value: {}",
                MAX_ITERATIONS, value
            );
        }
    }
}
