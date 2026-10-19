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

use std::fmt;

use anyhow;
use anyhow::Context;

use super::Domain;

/// Maximum number of rejection-sampling attempts in [`Filter::init`] and [`Filter::mutate`]
/// before returning an error.
pub const MAX_FILTER_ATTEMPTS: usize = 1000;

/// Filters the values produced by an inner domain `D` to only those satisfying a predicate `P`.
///
/// `Filter` uses bounded rejection sampling (up to [`MAX_FILTER_ATTEMPTS`] attempts) in `init`
/// and `mutate`, and validates both the inner domain's constraints and the predicate in
/// `validate_corpus_value`.
///
/// Note: `Filter` should only be used to exclude unlikely values. To restrict a significant
/// portion of an input domain, prefer constructing a constrained domain directly (such as
/// [`InRange`](super::range::InRange) or [`Map`](super::map::Map)).
///
/// It can be constructed via [`Domain::filter`] or [`Filter::new`].
///
/// Example usage:
/// ```
/// # use fuzztest::domains::Domain;
/// # use fuzztest::domains::range::InRange;
/// # use rand::rngs::SmallRng;
/// # use rand::SeedableRng;
///
/// let mut domain = InRange::new(-10i32, 10).filter(|x: &i32| *x != 0);
/// let mut rng = SmallRng::seed_from_u64(42);
///
/// let corpus_val = domain.init(&mut rng).unwrap();
/// let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
/// assert!(user_val >= -10 && user_val <= 10 && user_val != 0);
/// ```
pub struct Filter<D, P> {
    inner: D,
    predicate: P,
}

impl<D: Clone, P: Clone> Clone for Filter<D, P> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), predicate: self.predicate.clone() }
    }
}

impl<D: fmt::Debug, P> fmt::Debug for Filter<D, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Filter").field("inner", &self.inner).finish_non_exhaustive()
    }
}

impl<D, P> Filter<D, P> {
    /// Creates a new `Filter` domain wrapping `inner` and keeping only values matching `predicate`.
    pub fn new(inner: D, predicate: P) -> Self {
        Self { inner, predicate }
    }
}

impl<D, P> Domain for Filter<D, P>
where
    D: Domain,
    P: for<'a> Fn(&D::UserValue<'a>) -> bool,
{
    type UserValue<'user> = D::UserValue<'user>;
    type CorpusValue = D::CorpusValue;

    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        for _ in 0..MAX_FILTER_ATTEMPTS {
            let candidate = self.inner.init(rng)?;
            let matches = {
                let user_value = self.inner.corpus_to_user_value(&candidate)?;
                (self.predicate)(&user_value)
            };
            if matches {
                return Ok(candidate);
            }
        }
        anyhow::bail!(
            "Filter() predicate rejected all {} initialization attempts",
            MAX_FILTER_ATTEMPTS
        )
    }

    fn mutate(
        &mut self,
        corpus_value: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        let original = corpus_value.clone();
        for _ in 0..MAX_FILTER_ATTEMPTS {
            let mut candidate = original.clone();
            self.inner.mutate(&mut candidate, rng, only_shrink)?;
            let matches = {
                let user_value = self.inner.corpus_to_user_value(&candidate)?;
                (self.predicate)(&user_value)
            };
            if matches {
                *corpus_value = candidate;
                return Ok(());
            }
        }
        anyhow::bail!("Filter() predicate rejected all {} mutation attempts", MAX_FILTER_ATTEMPTS)
    }

    fn corpus_to_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        self.inner.corpus_to_user_value(corpus_value)
    }

    fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<Self::CorpusValue> {
        self.inner.parse_corpus(data)
    }

    fn serialize_corpus(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<Vec<u8>> {
        self.inner.serialize_corpus(corpus_value)
    }

    fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
        self.inner
            .validate_corpus_value(corpus_value)
            .context("Invalid corpus value for the inner domain in Filter()")?;
        let user_value = self.inner.corpus_to_user_value(corpus_value)?;
        anyhow::ensure!((self.predicate)(&user_value), "Value does not match Filter() predicate.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::arbitrary::Arbitrary;
    use crate::domains::range::InRange;
    use googletest::prelude::*;
    use rand::rngs::{SmallRng, SysRng};
    use rand::SeedableRng;

    fn get_rng() -> SmallRng {
        SmallRng::try_from_rng(&mut SysRng).expect("Failed to create RNG")
    }

    #[gtest]
    fn test_filter_init_respects_predicate() {
        let mut domain = InRange::new(0i32, 100).filter(|x| *x % 2 == 0);
        let mut rng = get_rng();

        for _ in 0..100 {
            let corpus_val = domain.init(&mut rng).unwrap();
            let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
            expect_that!(user_val, all!(ge(0), le(100)));
            expect_that!(user_val % 2, eq(0));
        }
    }

    #[gtest]
    fn test_filter_mutate_and_shrink_respect_predicate() {
        let mut domain = InRange::new(0i32, 100).filter(|x| *x % 2 == 0);
        let mut rng = get_rng();

        // Start from 0 (the minimum/fully-shrunk value of InRange(0, 100)) so that a
        // non-shrinking mutation (`only_shrink = false`) must grow the value above 0.
        let mut val = 0i32;
        let mut grew_from_zero = false;
        for _ in 0..100 {
            domain.mutate(&mut val, &mut rng, false).unwrap();
            expect_that!(val, all!(ge(0), le(100)));
            expect_that!(val % 2, eq(0));
            if val > 0 {
                grew_from_zero = true;
            }
        }
        expect_that!(grew_from_zero, eq(true));

        let mut shrink_val = 100i32;
        for _ in 0..50 {
            let prev = shrink_val;
            domain.mutate(&mut shrink_val, &mut rng, true).unwrap();
            expect_that!(shrink_val, all!(ge(0), le(prev)));
            expect_that!(shrink_val % 2, eq(0));
        }
        expect_that!(shrink_val, lt(100));

        // Shrinking at 0 must stay at 0.
        let mut zero_val = 0i32;
        for _ in 0..50 {
            domain.mutate(&mut zero_val, &mut rng, true).unwrap();
            expect_that!(zero_val, eq(0));
        }
    }

    #[gtest]
    fn test_filter_bounded_rejection_sampling_fails_on_unsatisfiable_predicate() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = AtomicUsize::new(0);
        let mut domain = InRange::new(1i32, 10).filter(|_x| {
            attempts.fetch_add(1, Ordering::SeqCst);
            false
        });
        let mut rng = get_rng();

        let init_err = domain.init(&mut rng).unwrap_err();
        expect_that!(
            format!("{init_err}"),
            contains_substring("Filter() predicate rejected all 1000 initialization attempts")
        );
        expect_that!(attempts.load(Ordering::SeqCst), eq(MAX_FILTER_ATTEMPTS));

        attempts.store(0, Ordering::SeqCst);
        let mut val = 5i32;
        let mutate_err = domain.mutate(&mut val, &mut rng, false).unwrap_err();
        expect_that!(
            format!("{mutate_err}"),
            contains_substring("Filter() predicate rejected all 1000 mutation attempts")
        );
        expect_that!(attempts.load(Ordering::SeqCst), eq(MAX_FILTER_ATTEMPTS));
        // Failed mutation must leave the original corpus value intact.
        expect_that!(val, eq(5));
    }

    #[gtest]
    fn test_filter_validate_corpus_value() {
        let domain = InRange::new(0i32, 20).filter(|x| *x % 2 == 0);

        expect_that!(domain.validate_corpus_value(&10).is_ok(), eq(true));

        // Fails predicate check
        let pred_err = domain.validate_corpus_value(&11).unwrap_err();
        expect_that!(
            format!("{pred_err:#}"),
            contains_substring("Value does not match Filter() predicate.")
        );

        // Fails inner domain constraint check
        let inner_err = domain.validate_corpus_value(&30).unwrap_err();
        let inner_err_chain = format!("{inner_err:#}");
        expect_that!(
            inner_err_chain,
            contains_substring("Invalid corpus value for the inner domain in Filter()")
        );
        expect_that!(inner_err_chain, contains_substring("Value 30 is out of range [0, 20]"));
    }

    #[gtest]
    fn test_filter_serde_roundtrip() {
        let domain = Arbitrary::<i32>::default().filter(|x| *x > 0);

        let corpus_val = 42i32;
        let bytes = domain.serialize_corpus(&corpus_val).unwrap();
        let parsed = domain.parse_corpus(&bytes).unwrap();
        expect_that!(parsed, eq(42));
        expect_that!(domain.validate_corpus_value(&parsed).is_ok(), eq(true));
    }

    #[gtest]
    fn test_filter_and_map_composition() {
        let mut domain =
            InRange::new(1i32, 50).filter(|x| *x % 2 == 1).map(|x| x * 2).filter(|y| *y > 10);
        let cloned = domain.clone();
        expect_that!(
            format!("{cloned:?}"),
            all!(contains_substring("Filter"), contains_substring("inner"))
        );
        expect_that!(cloned.validate_corpus_value(&7).is_ok(), eq(true));
        expect_that!(cloned.validate_corpus_value(&3).is_err(), eq(true));

        let mut rng = get_rng();
        for _ in 0..50 {
            let corpus_val = domain.init(&mut rng).unwrap();
            expect_that!(domain.validate_corpus_value(&corpus_val).is_ok(), eq(true));
            let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
            // corpus_val is odd in [1, 50], user_val = 2 * corpus_val > 10 and divisible by 2 but
            // not 4.
            expect_that!(user_val, all!(gt(10), le(100)));
            expect_that!(user_val % 4, eq(2));
        }

        // corpus_val = 3 -> user_val = 6, which fails the outer filter `y > 10`.
        expect_that!(domain.validate_corpus_value(&3).is_err(), eq(true));
        // corpus_val = 4 -> fails the inner filter `x % 2 == 1`.
        expect_that!(domain.validate_corpus_value(&4).is_err(), eq(true));
        // corpus_val = 7 -> user_val = 14, satisfies both filters and inner range.
        expect_that!(domain.validate_corpus_value(&7).is_ok(), eq(true));
    }

    #[gtest]
    fn test_filter_retries_until_predicate_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = AtomicUsize::new(0);
        let mut domain = Filter::new(InRange::new(1i32, 100), |_x: &i32| {
            attempts.fetch_add(1, Ordering::SeqCst) >= 5
        });
        let mut rng = get_rng();

        let mut corpus_val = domain.init(&mut rng).unwrap();
        expect_that!(corpus_val, all!(ge(1), le(100)));
        expect_that!(attempts.load(Ordering::SeqCst), eq(6));

        attempts.store(0, Ordering::SeqCst);
        domain.mutate(&mut corpus_val, &mut rng, false).unwrap();
        expect_that!(corpus_val, all!(ge(1), le(100)));
        expect_that!(attempts.load(Ordering::SeqCst), eq(6));
    }

    #[gtest]
    fn test_filter_propagates_inner_domain_error() {
        use crate::domains::containers::{ContainerDomain, VecOf};

        let mut domain = VecOf::new(Arbitrary::<u32>::default())
            .with_min_len(5)
            .filter(|_v: &Vec<u32>| panic!("Predicate must not be called when inner mutate fails"));
        let mut rng = get_rng();

        let mut invalid_corpus = vec![1u32, 2];
        let err = domain.mutate(&mut invalid_corpus, &mut rng, false).unwrap_err();
        expect_that!(
            format!("{err}"),
            contains_substring("Length 2 is not between the minimum length 5")
        );
    }
}
