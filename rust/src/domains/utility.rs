use std::cmp::Ordering;

use num_traits::PrimInt;
use rand::distr::uniform::SampleUniform;
use rand::distr::{Distribution, StandardUniform};
use rand::RngExt;

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
    T: SampleUniform + PartialOrd + Copy + std::fmt::Display,
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
/// 1.  Random Walk: Add/subtract a small value within the given `range`.
/// 2.  Bit Flip: Flip a single random bit.
/// 3.  Random Choice: Replace with a new completely random value.
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
// (See `third_party/googlefuzztest/internal/domains/value_mutation_helpers.h`)
pub fn mutate_integer<T, R: rand::Rng + ?Sized>(
    rng: &mut R,
    val: T,
    range: T,
    min_value: Option<T>,
    max_value: Option<T>,
) -> T
where
    T: PrimInt + SampleUniform + std::fmt::Display,
{
    assert!(range > T::zero(), "mutate_integer: range value cannot be <= 0: {range}");

    let min_val = min_value.unwrap_or(T::min_value());
    let max_val = max_value.unwrap_or(T::max_value());
    assert!(
        min_val < max_val,
        "mutate_integer: min_val must be strictly smaller than max_val: min={min_val}, max={max_val}"
    );

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
            let num_bits = std::mem::size_of::<T>() * 8;
            let bit_index = rng.random_range(0..num_bits);
            let mask = T::one() << bit_index;
            let result = val ^ mask;
            if result < min_val || result > max_val {
                val
            } else {
                result
            }
        }
        _ => {
            // 1/3 chance: Replace with a new random value
            rng.random_range(min_val..=max_val)
        }
    }
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

impl_special_values_signed!(i8, i16, i32, i64, i128);
impl_special_values_unsigned!(u8, u16, u32, u64, u128);

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
/// * `T`: The type of the value to choose. Must implement `SpecialValues` and
///        `StandardUniform` must be able to generate values of type `T`.
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
    _range: Option<(T, T)>, // TODO: Implement range support for floats.
) -> anyhow::Result<()>
where
    T: num_traits::Float + SampleUniform + std::fmt::Display + Copy + SpecialValues + 'static,
    StandardUniform: Distribution<T>,
{
    if only_shrink {
        // Shrink only finite, non-terminal values.
        if val.is_finite() && *val != T::zero() {
            *val = shrink_towards(rng, *val, T::zero());
        }
        return Ok(());
    }
    // Non-shrinking mutation.
    let original_val = *val;
    loop {
        // Loop to ensure mutation
        if !val.is_finite() {
            // NaN or Infinity
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{
        rngs::{SmallRng, SysRng},
        SeedableRng,
    };

    fn get_rng() -> SmallRng {
        SmallRng::try_from_rng(&mut SysRng).unwrap()
    }

    fn check_shrink_towards<T>(smaller: T, larger: T)
    where
        T: SampleUniform + PartialOrd + Copy + std::fmt::Display + std::fmt::Debug + PartialEq,
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
        T: PrimInt + SampleUniform + std::fmt::Display + std::fmt::Debug + SpecialValues + 'static,
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
        T: num_traits::Float
            + SampleUniform
            + std::fmt::Display
            + std::fmt::Debug
            + Copy
            + SpecialValues
            + 'static,
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
}
