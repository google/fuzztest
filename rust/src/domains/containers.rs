use rand::RngExt;
use std::fmt;
use super::Domain;

const DEFAULT_MAX_LEN: usize = 5000;

macro_rules! choose_one {
    ($rng:expr, $( $cond:expr $(; w = $weight:expr)? => $action:expr ),* $(,)? ) => {{
        struct Branch {
            cond: bool,
            weight: usize,
        }

        let branches = [
            $( Branch { cond: $cond, weight: choose_one!(@default 1usize, $($weight)?) } ),*
        ];
        let total_weight: usize = branches.iter()
            .map(|&Branch { cond, weight }| if cond { weight } else { 0 })
            .sum();

        if total_weight > 0 {
            let choice = ::rand::RngExt::random_range($rng, 0..total_weight);
            let mut current = 0usize;
            let mut i = 0usize;
            'choose_one_loop: {
                $(
                    if branches[i].cond {
                        let w = branches[i].weight;
                        if choice >= current && choice < current + w {
                            let _ = { $action };
                            break 'choose_one_loop;
                        }
                        #[allow(unused_assignments)]
                        { current += w; }
                    }
                    i += 1;
                )*
            }
        }
    }};
    (@default $default:expr, ) => { $default };
    (@default $default:expr, $val:expr) => { $val };
}

/// A trait for configuring the length constraints of container domains.
///
/// This trait provides a fluent interface to specify the length requirements
/// for domains that generate collections, such as [`VecOf`].
pub trait ContainerDomain: Sized {
    /// Sets the length of the container to be exactly `len`.
    fn with_len(self, len: usize) -> Self;

    /// Sets the minimum length of the container.
    ///
    /// # Panics
    ///
    /// Panics if the specified `min_len` is greater than the current maximum length (if set).
    fn with_min_len(self, min_len: usize) -> Self;

    /// Sets the maximum length of the container.
    ///
    /// Using this API will override any previous `with_soft_max_len` call.
    ///
    /// # Panics
    ///
    /// Panics if the specified `max_len` is less than the current minimum length.
    fn with_max_len(self, max_len: usize) -> Self;

    /// Sets a "soft" maximum length of the container.
    ///
    /// Using this API will override any previous `with_max_len` call.
    ///
    /// With this constraint, the domain will consider containers longer than
    /// `soft_max_len` as valid. When mutating the containers, the domain will
    /// not increase their size further if it is already greater or equal to
    /// `soft_max_len`.
    ///
    /// # Panics
    ///
    /// Panics if the specified `soft_max_len` is less than the current minimum length.
    fn with_soft_max_len(self, soft_max_len: usize) -> Self;
}

pub struct VecOf<T> {
    inner: T,
    min_len: usize,
    max_len: Option<usize>,
    max_len_is_soft: bool,
}

impl<T: Clone> Clone for VecOf<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            min_len: self.min_len,
            max_len: self.max_len,
            max_len_is_soft: self.max_len_is_soft,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for VecOf<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VecOf")
            .field("inner", &self.inner)
            .field("min_len", &self.min_len)
            .field("max_len", &self.max_len)
            .field("max_len_is_soft", &self.max_len_is_soft)
            .finish()
    }
}

impl<T> VecOf<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            min_len: 0,
            max_len: None,
            max_len_is_soft: false,
        }
    }

    fn max_len(&self) -> usize {
        self.max_len.unwrap_or(self.min_len.max(DEFAULT_MAX_LEN))
    }
}

impl<T> Domain for VecOf<T>
where
    T: Domain,
{
    type CorpusValue = Vec<T::CorpusValue>;
    type UserValue<'user> = Vec<T::UserValue<'user>>;

    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        if self.max_len() == 0 {
            return Ok(Vec::new());
        }

        let initial_size = if self.min_len == 0 { rng.random_range(0..=1) } else { self.min_len };

        let mut val = Vec::with_capacity(initial_size);
        for _ in 0..initial_size {
            val.push(self.inner.init(rng)?);
        }
        Ok(val)
    }

    fn mutate(
        &mut self,
        val: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        if self.max_len_is_soft {
            anyhow::ensure!(
                self.min_len <= val.len(),
                "Length {} is less than the minimum length {}",
                val.len(),
                self.min_len
            );
        } else {
            anyhow::ensure!(
                self.min_len <= val.len() && val.len() <= self.max_len(),
                "Length {} is not between the minimum length {} and maximum length {}",
                val.len(),
                self.min_len,
                self.max_len()
            );
        }

        choose_one!(rng,
            val.len() > self.min_len => {
                let idx = rng.random_range(0..val.len());
                val.remove(idx);
            },
            !only_shrink && val.len() < self.max_len() => {
                let idx = rng.random_range(0..=val.len());
                val.insert(idx, self.inner.init(rng)?);
            },
            !val.is_empty() => {
                let idx = rng.random_range(0..val.len());
                self.inner.mutate(&mut val[idx], rng, only_shrink)?;
            },
        );

        Ok(())
    }

    fn get_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        let mut user_values = Vec::with_capacity(corpus_value.len());
        for item in corpus_value {
            user_values.push(self.inner.get_user_value(item)?);
        }
        Ok(user_values)
    }

    fn from_value(&self, value: Self::UserValue<'_>) -> anyhow::Result<Self::CorpusValue> {
        let mut corpus_values = Vec::with_capacity(value.len());
        for item in value {
            corpus_values.push(self.inner.from_value(item)?);
        }
        Ok(corpus_values)
    }

    fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
        if self.max_len_is_soft {
            anyhow::ensure!(
                self.min_len <= corpus_value.len(),
                "Length {} is less than the minimum length {}",
                corpus_value.len(),
                self.min_len
            );
        } else {
            anyhow::ensure!(
                self.min_len <= corpus_value.len() && corpus_value.len() <= self.max_len(),
                "Length {} is not between the minimum length {} and maximum length {}",
                corpus_value.len(),
                self.min_len,
                self.max_len()
            );
        }
        for item in corpus_value {
            self.inner.validate_corpus_value(item)?;
        }
        Ok(())
    }
}

impl<T: Domain> ContainerDomain for VecOf<T> {
    fn with_len(self, len: usize) -> Self {
        Self { min_len: len, max_len: Some(len), ..self }
    }

    fn with_min_len(self, min_len: usize) -> Self {
        assert!(
            self.max_len.is_none_or(|max| min_len <= max),
            "Minimum length {} cannot be greater than the maximum length {}",
            min_len,
            self.max_len.unwrap()
        );
        Self { min_len, ..self }
    }

    fn with_max_len(self, max_len: usize) -> Self {
        assert!(
            max_len >= self.min_len,
            "Maximum length {} cannot be less than the minimum length {}",
            max_len,
            self.min_len
        );
        Self { max_len_is_soft: false, max_len: Some(max_len), ..self }
    }

    fn with_soft_max_len(self, soft_max_len: usize) -> Self {
        assert!(
            soft_max_len >= self.min_len,
            "Soft maximum length {} cannot be less than the minimum length {}",
            soft_max_len,
            self.min_len
        );
        Self { max_len_is_soft: true, max_len: Some(soft_max_len), ..self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::arbitrary::Arbitrary;
    use googletest::prelude::*;
    use rand::rngs::{SmallRng, SysRng};
    use rand::SeedableRng;

    fn get_rng() -> SmallRng {
        SmallRng::try_from_rng(&mut SysRng).expect("Failed to create RNG")
    }

    #[gtest]
    fn test_vec_of_mutate_shrink() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default()).with_max_len(10);

        let mut rng = get_rng();

        let mut val = vec![1, 2, 3, 4, 5];

        // Test shrinking length
        for _ in 0..100 {
            let orig_len = val.len();
            if orig_len == 0 {
                break;
            }
            domain.mutate(&mut val, &mut rng, true).unwrap();
            expect_that!(val.len(), le(orig_len));
        }
    }

    #[gtest]
    fn test_vec_of_mutate_grow_and_change() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default()).with_max_len(10);

        let mut rng = get_rng();

        let mut val = vec![1];
        let mut grew = false;

        for _ in 0..100 {
            let orig_len = val.len();
            domain.mutate(&mut val, &mut rng, false).unwrap();
            expect_that!(val.len(), le(10));
            if val.len() > orig_len {
                grew = true;
            }
        }
        expect_that!(grew, eq(true), "VecOf should be able to grow during normal mutation");
    }

    #[gtest]
    fn test_vec_of_init_respects_min_len() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default()).with_min_len(5);
        let mut rng = get_rng();

        for _ in 0..100 {
            let val = domain.init(&mut rng).unwrap();
            expect_that!(val.len(), ge(5));
        }
    }

    #[gtest]
    fn test_vec_of_init_fixed_len() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default()).with_len(7);
        let mut rng = get_rng();

        for _ in 0..100 {
            let val = domain.init(&mut rng).unwrap();
            expect_that!(val.len(), eq(7));
        }
    }

    #[gtest]
    fn test_vec_of_init_default_max_len() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default());
        let mut rng = get_rng();

        for _ in 0..100 {
            let val = domain.init(&mut rng).unwrap();
            expect_that!(val.len(), le(DEFAULT_MAX_LEN));
        }
    }

    #[gtest]
    fn test_vec_of_mutate_respects_min_len() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default()).with_min_len(3);
        let mut rng = get_rng();

        let mut val = vec![1, 2, 3];
        for _ in 0..100 {
            domain.mutate(&mut val, &mut rng, true).unwrap();
            expect_that!(val.len(), ge(3));
        }
    }

    #[gtest]
    fn test_vec_of_mutate_respects_max_len() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default()).with_max_len(3);
        let mut rng = get_rng();

        let mut val = vec![1, 2, 3];
        for _ in 0..100 {
            domain.mutate(&mut val, &mut rng, false).unwrap();
            expect_that!(val.len(), le(3));
        }
    }

    #[gtest]
    fn test_vec_of_mutate_min_len_validation() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default()).with_min_len(5);
        let mut rng = get_rng();

        let mut val = vec![1, 2, 3]; // Length 3, which is < 5
        let result = domain.mutate(&mut val, &mut rng, false);
        expect_that!(result.is_err(), eq(true));
        let err_msg = format!("{}", result.unwrap_err());
        expect_that!(
            err_msg,
            contains_substring(
                "Length 3 is not between the minimum length 5 and maximum length 5000"
            )
        );
    }

    #[gtest]
    fn test_vec_of_mutate_soft_max_len_behavior() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default()).with_soft_max_len(5);
        let mut rng = get_rng();

        // Valid mutation within bounds
        let mut valid_val = vec![1, 2, 3, 4, 5];
        let valid_result = domain.mutate(&mut valid_val, &mut rng, false);
        expect_that!(valid_result.is_ok(), eq(true));

        // In soft max mode, we DON'T error if we are already over the limit on entry
        let mut over_val = vec![1, 2, 3, 4, 5, 6];
        let result = domain.mutate(&mut over_val, &mut rng, false);
        expect_that!(result.is_ok(), eq(true));
        // But it should not have grown further
        expect_that!(over_val.len(), le(6));
    }

    #[gtest]
    #[should_panic(expected = "Minimum length 6 cannot be greater than the maximum length 5")]
    fn test_vec_of_with_invalid_min_len() {
        VecOf::new(Arbitrary::<u32>::default()).with_max_len(5).with_min_len(6);
    }

    #[gtest]
    #[should_panic(expected = "Maximum length 4 cannot be less than the minimum length 5")]
    fn test_vec_of_with_invalid_max_len() {
        VecOf::new(Arbitrary::<u32>::default()).with_min_len(5).with_max_len(4);
    }

    #[gtest]
    #[should_panic(expected = "Soft maximum length 4 cannot be less than the minimum length 5")]
    fn test_vec_of_with_invalid_soft_max_len() {
        VecOf::new(Arbitrary::<u32>::default()).with_min_len(5).with_soft_max_len(4);
    }

    #[gtest]
    fn test_vec_of_mutate_no_action_at_bounds() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default()).with_len(1);
        let mut rng = get_rng();

        let mut val = vec![100u32];
        for _ in 0..100 {
            // with_len(1) means min=1, max=1.
            // insert/remove should be disabled.
            // mutate inner should still be possible.
            let orig_val = val[0];
            domain.mutate(&mut val, &mut rng, false).unwrap();
            expect_that!(val.len(), eq(1));
            // In this case, since action_count will be 1 (can_change), it MUST call inner.mutate
            // Arbitrary::<u32> mutate should eventually change the value.
            if val[0] != orig_val {
                return;
            }
        }
    }

    #[gtest]
    fn test_vec_of_zero_len() {
        let mut domain = VecOf::new(Arbitrary::<u32>::default()).with_len(0);
        let mut rng = get_rng();

        let val = domain.init(&mut rng).unwrap();
        expect_that!(val, is_empty());

        let mut val = Vec::new();
        domain.mutate(&mut val, &mut rng, false).unwrap();
        expect_that!(val, is_empty());
    }

    #[gtest]
    fn test_vec_of_get_user_value() {
        let domain = VecOf::new(Arbitrary::<u32>::default());
        let corpus_val = vec![1u32, 2u32, 3u32];
        let user_val = domain.get_user_value(&corpus_val).unwrap();
        expect_that!(user_val, container_eq(vec![1u32, 2u32, 3u32]));
    }

}
