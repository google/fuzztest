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

use std::cmp::Ordering;

use num_traits::PrimInt;
use rand::distr::uniform::SampleUniform;
use rand::distr::{Distribution, StandardUniform};
use rand::RngExt;
use std::fmt::Display;

/// Shrinks a `val` towards a `target` value.
///
/// The new value is chosen uniformly from the range between `val` and `target`.
/// - If `val > target`, the range is `[target, val)`.
/// - If `val < target`, the range is `(val, target]`.
/// - If `val == target`, `val` is returned.
///
/// # Arguments
/// * `rng`: Random number generator.
/// * `val`: The current value to shrink.
/// * `target`: The value to shrink towards.
pub fn shrink_towards<T, R: rand::Rng + ?Sized>(rng: &mut R, val: T, target: T) -> T
where
    T: SampleUniform + PartialOrd + Copy + Display,
{
    match val.partial_cmp(&target) {
        Some(Ordering::Equal) => val,
        Some(Ordering::Less) => {
            // val < target
            // Sample from (val, target].
            // To do that, we sample from [val, target) and return target if we draw val.
            let sample = rng.random_range(val..target);
            if sample == val {
                target
            } else {
                sample
            }
        }
        Some(Ordering::Greater) => {
            // val > target
            // Sample from [target, val).
            rng.random_range(target..val)
        }
        None => val, // Cannot compare, return original
    }
}

/// Mutates an integer value using one of several strategies.
///
/// The mutation strategies are:
/// 1. Random Walk: Add/subtract a small value within the given `range`.
/// 2. Bit Flip: Flip a single random bit.
/// 3. Random Choice: Replace with a new completely random value.
///
/// # Arguments
/// * `rng`: Random number generator.
/// * `val`: The integer value to mutate.
/// * `range`: The maximum +/- delta for the random walk.
/// * `min_value`: Optional minimum boundary for mutation. If `None`, `T::min_value()` is used.
/// * `max_value`: Optional maximum boundary for mutation. If `None`, `T::max_value()` is used.
// REQUIRES: range > 0
// REQUIRES: min_value <= max_value (after unwrapping)
// TODO(b/405382579): Add dictionary-based mutation strategies similar to C++ implementation
// (See `value_mutation_helpers.h`)
pub fn mutate_integer<T, R: rand::Rng + ?Sized>(
    rng: &mut R,
    val: T,
    range: T,
    min_value: Option<T>,
    max_value: Option<T>,
) -> T
where
    T: PrimInt + SampleUniform + Display,
{
    assert!(range > T::zero(), "mutate_integer: range value cannot be <= 0: {range}");

    let min_val = min_value.unwrap_or(T::min_value());
    let max_val = max_value.unwrap_or(T::max_value());
    assert!(
        min_val <= max_val,
        "mutate_integer: min_val must be <= max_val: min={min_val}, max={max_val}"
    );
    if min_val == max_val {
        return min_val;
    }

    match rng.random_range(0..3) {
        0 => {
            // 1/3 chance: Random Walk
            // Establish a window around the current value. If val > max_val, we should walk
            // around max_val instead to bring the value back into a valid range.
            let center = val.clamp(min_val, max_val);
            let lo = center.saturating_sub(range).max(min_val);
            let hi = center.saturating_add(range).min(max_val);

            // Sample uniformly within the clamped window [lo, hi].
            rng.random_range(lo..=hi)
        }
        1 => {
            // 1/3 chance: Flip a random bit
            bit_flip_integer(rng, val, min_val, max_val)
        }
        _ => {
            // 1/3 chance: Replace with a new random value
            rng.random_range(min_val..=max_val)
        }
    }
}

fn bit_flip_integer<T, R: rand::Rng + ?Sized>(rng: &mut R, val: T, lower: T, upper: T) -> T
where
    T: PrimInt + Display + Copy,
{
    assert!(lower <= upper, "bit_flip_integer: lower bound must be <= upper bound");

    // For same-sign bounds, `lower ^ upper` zeros shared high-order bits so flips stay
    // within the active bit width of the interval. When the range straddles zero
    // (`lower < 0 <= upper`), `lower ^ upper` has the sign bit set (`leading_zeros() == 0`),
    // so bound the magnitude bit width by the active sign half and include the sign bit
    // (`type_bits - 1`) as one additional candidate. This avoids sampling dead
    // sign-extension bits for narrow ranges while still allowing sign-bit flips for
    // full-range signed types (`Arbitrary<iN>`) and asymmetric ranges straddling zero.
    let type_bits = size_of::<T>() * 8;
    let bit = if lower < T::zero() && upper >= T::zero() {
        let mag_width = if val >= T::zero() {
            type_bits - upper.leading_zeros() as usize
        } else {
            type_bits - (!lower).leading_zeros() as usize
        };
        let idx = rng.random_range(0..=mag_width);
        if idx == mag_width {
            type_bits - 1
        } else {
            idx
        }
    } else {
        let width = type_bits - (lower ^ upper).leading_zeros() as usize;
        if width == 0 {
            return val;
        }
        rng.random_range(0..width)
    };

    let next = val ^ (T::one() << bit);
    if next >= lower && next <= upper {
        next
    } else {
        val
    }
}

const SURROGATE_START: u32 = 0xD800;
const SURROGATE_END: u32 = 0xDFFF;
const MAX_VALID_CODEPOINT: u32 = 0x10FFFF;
pub(crate) const NUM_VALID_CODEPOINTS: u32 =
    MAX_VALID_CODEPOINT - (SURROGATE_END - SURROGATE_START);

/// Maps a `char` to a `u32` in a contiguous range `[0, NUM_VALID_CODEPOINTS)` by
/// shifting down code points above the UTF-16 surrogate range (`0xD800..=0xDFFF`).
pub(crate) fn map_char_to_int(c: char) -> u32 {
    let val = c as u32;
    if val >= SURROGATE_START {
        val - (SURROGATE_END - SURROGATE_START + 1)
    } else {
        val
    }
}

/// Maps a `u32` from the contiguous range `[0, NUM_VALID_CODEPOINTS)` back to a `char`.
pub(crate) fn map_int_to_char(u: u32) -> char {
    assert!(
        u < NUM_VALID_CODEPOINTS,
        "input to map_int_to_char out of range: got {}, expected value < {}",
        u,
        NUM_VALID_CODEPOINTS
    );
    let val = if u >= SURROGATE_START { u + (SURROGATE_END - SURROGATE_START + 1) } else { u };
    char::from_u32(val).unwrap()
}

pub trait SpecialValues: Sized + Copy {
    fn get() -> &'static [Self];
}

macro_rules! impl_special_values_signed {
    ($($ty:ty),*) => {
        $(
            impl SpecialValues for $ty {
                fn get() -> &'static [Self] {
                    &[0, 1, -1, <$ty>::MIN, <$ty>::MAX]
                }
            }
        )*
    };
}

macro_rules! impl_special_values_unsigned {
    ($($ty:ty),*) => {
        $(
            impl SpecialValues for $ty {
                fn get() -> &'static [Self] {
                    &[0, 1, <$ty>::MAX, <$ty>::MAX >> 1]
                }
            }
        )*
    };
}

impl_special_values_signed!(i8, i16, i32, i64, i128, isize);
impl_special_values_unsigned!(u8, u16, u32, u64, u128, usize);

macro_rules! impl_special_values_float {
    ($($ty:ty),*) => {
        $(
            impl SpecialValues for $ty {
                fn get() -> &'static [Self] {
                    &[0.0, -0.0, 1.0, -1.0, <$ty>::MIN, <$ty>::MAX, <$ty>::INFINITY, <$ty>::NEG_INFINITY, <$ty>::NAN]
                }
            }
        )*
    };
}
impl_special_values_float!(f32, f64);

impl SpecialValues for char {
    fn get() -> &'static [Self] {
        &[
            '\0',         // Null
            'a',          // Common ASCII
            '~',          // Last printable ASCII
            '\n',         // Newline
            ' ',          // Space
            '\u{0080}',   // Start of multi-byte UTF-8
            '\u{D7FF}',   // Before surrogate range
            '\u{E000}',   // After surrogate range
            '\u{10FFFF}', // Max valid Unicode scalar value
        ]
    }
}

/// Chooses a value of type `T`, potentially from a set of "special values".
///
/// This function has a higher chance of returning one of the predefined "special values"
/// for the type `T` (as defined by the `SpecialValues` trait). Otherwise, it generates
/// a completely random value of type `T`.
///
/// # Arguments
/// * `rng`: Random number generator.
///
/// # Type Parameters
/// * `T`: The type of the value to choose. Must implement `SpecialValues` and `StandardUniform`
///   must be able to generate values of type `T`.
pub fn choose_value<T, R: rand::Rng + ?Sized>(rng: &mut R) -> T
where
    T: SpecialValues + 'static,
    StandardUniform: Distribution<T>,
{
    let special_values = T::get();
    let index = rng.random_range(0..=special_values.len());
    if index < special_values.len() {
        special_values[index]
    } else {
        rng.random()
    }
}

/// Mutates a float value.
pub fn mutate_float<T, R: rand::Rng + ?Sized>(
    rng: &mut R,
    val: &mut T,
    only_shrink: bool,
    range: Option<(T, T)>,
) -> anyhow::Result<()>
where
    T: num_traits::Float + SampleUniform + Display + Copy + SpecialValues + 'static,
    StandardUniform: Distribution<T>,
{
    if let Some((lower, upper)) = range {
        assert!(lower <= upper, "mutate_float: lower bound must be <= upper bound");
        assert!(!lower.is_nan() && !upper.is_nan(), "mutate_float: bounds cannot be NaN");
    }

    if only_shrink {
        if val.is_finite() {
            let target = if let Some((lower, upper)) = range {
                if lower <= T::zero() && upper >= T::zero() {
                    T::zero()
                } else if lower > T::zero() {
                    lower
                } else {
                    upper
                }
            } else {
                T::zero()
            };
            if *val != target {
                *val = shrink_towards(rng, *val, target);
            }
        }
        return Ok(());
    }

    if let Some((lower, upper)) = range {
        if lower == upper {
            *val = lower;
            return Ok(());
        }

        if !val.is_finite() || *val < lower || *val > upper {
            *val = rng.random_range(lower..=upper);
            return Ok(());
        }

        let original_val = *val;
        // Cap retry attempts because for narrow float ranges (e.g. a few ULPs wide),
        // `delta = width / 100.0` underflows relative to `*val` (`lo == hi == *val`),
        // and uniform float sampling can repeatedly round to the current value.
        for _ in 0..10 {
            match rng.random_range(0..2) {
                0 => {
                    // Random Walk
                    let width = upper - lower;
                    let delta = if width > T::zero() && width.is_finite() {
                        width / T::from(100.0).unwrap()
                    } else {
                        T::from(1.0).unwrap()
                    };
                    let lo = (*val - delta).max(lower);
                    let hi = (*val + delta).min(upper);
                    *val = rng.random_range(lo..=hi);
                }
                1 => {
                    // Uniform Choice
                    *val = rng.random_range(lower..=upper);
                }
                _ => unreachable!(),
            }
            if *val != original_val {
                return Ok(());
            }
        }
        *val = if original_val == lower { upper } else { lower };
        return Ok(());
    }

    let original_val = *val;
    loop {
        if !val.is_finite() {
            *val = choose_value(rng);
        } else {
            match rng.random_range(0..4) {
                0 => *val = *val / (T::one() + T::one()),
                1 => *val = -*val,
                2 => *val = *val + T::one(),
                3 => *val = *val * (T::one() + T::one() + T::one()),
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

/// Returns the number of iterations needed to hit each of `num_cases` cases, where each case is
/// hit with probability at least `hit_probability` per iteration, such that the probability of
/// missing some case is at most 10^-15 (by the union bound).
#[cfg(test)]
pub(crate) fn iterations_to_hit_all(num_cases: usize, hit_probability: f64) -> usize {
    assert!(num_cases > 0, "iterations_to_hit_all: num_cases must be > 0");
    assert!(
        0.0 < hit_probability && hit_probability < 1.0,
        "iterations_to_hit_all: hit_probability must be in (0.0, 1.0), got {hit_probability}"
    );
    const CONFIDENCE_LEVEL: f64 = 15.0;
    let numerator = CONFIDENCE_LEVEL * std::f64::consts::LN_10 + (num_cases as f64).ln();
    (numerator / -(-hit_probability).ln_1p()).ceil() as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{
        rngs::{SmallRng, SysRng},
        SeedableRng,
    };
    use std::fmt::Debug;

    fn get_rng() -> SmallRng {
        SmallRng::try_from_rng(&mut SysRng).unwrap()
    }

    fn check_shrink_towards<T>(smaller: T, larger: T)
    where
        T: SampleUniform + PartialOrd + Copy + Display + Debug + PartialEq,
    {
        let mut rng = get_rng();

        // val > target (e.g. larger -> smaller)
        // Range should be [smaller, larger)
        let mut results = Vec::new();
        for _ in 0..100 {
            let sample = shrink_towards(&mut rng, larger, smaller);
            assert!(sample >= smaller && sample < larger);
            if !results.contains(&sample) {
                results.push(sample);
            }
        }
        assert!(results.len() > 1);

        // val < target (e.g. smaller -> larger)
        // Range should be (smaller, larger]
        let mut results = Vec::new();
        for _ in 0..100 {
            let sample = shrink_towards(&mut rng, smaller, larger);
            assert!(sample > smaller && sample <= larger);
            if !results.contains(&sample) {
                results.push(sample);
            }
        }
        assert!(results.len() > 1);

        // identical target
        let sample = shrink_towards(&mut rng, smaller, smaller);
        assert_eq!(sample, smaller);
    }

    #[test]
    fn test_shrink_towards_all_types() {
        check_shrink_towards::<i8>(5, 10);
        check_shrink_towards::<u8>(5, 10);
        check_shrink_towards::<i16>(5, 10);
        check_shrink_towards::<u16>(5, 10);
        check_shrink_towards::<i32>(5, 10);
        check_shrink_towards::<u32>(5, 10);
        check_shrink_towards::<i64>(5, 10);
        check_shrink_towards::<u64>(5, 10);
        check_shrink_towards::<i128>(5, 10);
        check_shrink_towards::<u128>(5, 10);
        check_shrink_towards::<f32>(5.0, 10.0);
        check_shrink_towards::<f64>(5.0, 10.0);
    }

    fn check_mutate_integer<T>()
    where
        T: PrimInt + SampleUniform + Display + Debug + SpecialValues + 'static,
        StandardUniform: Distribution<T>,
    {
        let mut rng = get_rng();

        let min_val = T::zero();
        let max_val = T::one() + T::one() + T::one() + T::one() + T::one();
        let range = T::one() + T::one();

        // Bounded mutation stays in bounds
        for _ in 0..100 {
            let val: T = choose_value(&mut rng).clamp(min_val, max_val);
            let next = mutate_integer(&mut rng, val, range, Some(min_val), Some(max_val));
            assert!(
                next >= min_val && next <= max_val,
                "mutate_integer bounded range check failed for value {} not in [{}, {}]",
                next,
                min_val,
                max_val
            );
        }

        // Unbounded mutation changes value
        let mut val = T::zero();
        let mut changed = false;
        for _ in 0..100 {
            let next = mutate_integer(&mut rng, val, range, None, None);
            if next != val {
                changed = true;
                break;
            }
            val = next;
        }
        assert!(changed, "mutate_integer did not change value");
    }

    #[test]
    fn test_mutate_integer_all_types() {
        check_mutate_integer::<i8>();
        check_mutate_integer::<u8>();
        check_mutate_integer::<i16>();
        check_mutate_integer::<u16>();
        check_mutate_integer::<i32>();
        check_mutate_integer::<u32>();
        check_mutate_integer::<i64>();
        check_mutate_integer::<u64>();
        check_mutate_integer::<i128>();
        check_mutate_integer::<u128>();
    }

    fn check_mutate_float<T>()
    where
        T: num_traits::Float + SampleUniform + Display + Debug + Copy + SpecialValues + 'static,
        StandardUniform: Distribution<T>,
    {
        let mut rng = get_rng();

        // Mutation changes value
        let mut val = T::one();
        let mut changed = false;
        for _ in 0..100 {
            let mut next = val;
            mutate_float(&mut rng, &mut next, false, None).unwrap();
            // Floats might mutate to NaN
            if next != val || (next.is_nan() && !val.is_nan()) {
                changed = true;
                if next.is_nan() {
                    val = T::one();
                } else {
                    val = next;
                }
            }
        }
        assert!(changed, "mutate_float did not change value");

        // Shrinking
        let mut val = T::one() + T::one() + T::one();
        let original_abs = val.abs();
        for _ in 0..10 {
            let mut next = val;
            mutate_float(&mut rng, &mut next, true, None).unwrap();
            assert!(next.abs() <= val.abs(), "mutate_float shrink increased absolute value");
            val = next;
        }
        assert!(val.abs() < original_abs, "mutate_float did not shrink value");
    }

    #[test]
    fn test_mutate_float_all_types() {
        check_mutate_float::<f32>();
        check_mutate_float::<f64>();
    }

    #[test]
    fn test_bit_flip_integer_sign_bit() {
        let mut rng = get_rng();
        // Full signed range [i8::MIN, i8::MAX]: flipping the sign bit of 3 yields -125.
        let mut flipped_sign_full = false;
        for _ in 0..200 {
            if bit_flip_integer(&mut rng, 3i8, i8::MIN, i8::MAX) == -125i8 {
                flipped_sign_full = true;
                break;
            }
        }
        assert!(
            flipped_sign_full,
            "bit_flip_integer should be able to flip sign bit on full i8 range"
        );

        // Asymmetric range straddling zero [i8::MIN, 5]: flipping the sign bit of 3 yields -125.
        let mut flipped_sign_asymmetric = false;
        for _ in 0..200 {
            if bit_flip_integer(&mut rng, 3i8, i8::MIN, 5i8) == -125i8 {
                flipped_sign_asymmetric = true;
                break;
            }
        }
        assert!(
            flipped_sign_asymmetric,
            "bit_flip_integer should be able to flip sign bit on asymmetric range straddling zero"
        );
    }

    #[test]
    fn test_mutate_integer_singleton() {
        let mut rng = get_rng();
        assert_eq!(mutate_integer(&mut rng, 5i32, 5, Some(5), Some(5)), 5);
    }

    #[test]
    fn test_char_mapping() {
        // Test boundary conditions and values around the surrogate range
        assert_eq!(map_char_to_int('\u{0000}'), 0);
        assert_eq!(map_int_to_char(0), '\u{0000}');

        let before_surrogate = SURROGATE_START - 1;
        assert_eq!(map_char_to_int(char::from_u32(before_surrogate).unwrap()), before_surrogate);
        assert_eq!(map_int_to_char(before_surrogate), char::from_u32(before_surrogate).unwrap());

        let after_surrogate = SURROGATE_END + 1;
        let mapped_after_surrogate = map_char_to_int(char::from_u32(after_surrogate).unwrap());
        assert_eq!(mapped_after_surrogate, SURROGATE_START);
        assert_eq!(map_int_to_char(SURROGATE_START), char::from_u32(after_surrogate).unwrap());

        assert_eq!(map_char_to_int('\u{10FFFF}'), NUM_VALID_CODEPOINTS - 1);
        assert_eq!(map_int_to_char(NUM_VALID_CODEPOINTS - 1), '\u{10FFFF}');
    }

    #[test]
    fn test_iterations_to_hit_all() {
        assert_eq!(iterations_to_hit_all(1, 0.5), 50);
        assert_eq!(iterations_to_hit_all(2, 0.5), 51);
        assert_eq!(iterations_to_hit_all(1, 0.01), 3437);
        assert_eq!(iterations_to_hit_all(2, 0.01), 3506);
    }
}
