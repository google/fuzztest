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

use super::{Domain, ReversibleDomain};

/// Maximum number of rejection-sampling attempts in [`Filter::init`] and [`Filter::mutate`]
/// before returning an error.
const MAX_FILTER_ATTEMPTS: usize = 1000;

/// Filters the values produced by an inner domain `D` to only those satisfying a predicate `P`.
///
/// `Filter` uses bounded rejection sampling in `init` and `mutate`, and validates both the
/// inner domain's constraints and the predicate in `parse_corpus` and `validate_corpus_value`.
///
/// Note: `Filter` should only be used to exclude unlikely values. To restrict a significant
/// portion of an input domain, prefer constructing a constrained domain directly (such as
/// [`InRange`](super::range::InRange) or `Map`).
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
/// let mut domain = InRange::new(-10i32, 10).filter(|x| *x != 0);
/// let mut rng = SmallRng::seed_from_u64(42);
///
/// let corpus_val = domain.init(&mut rng).unwrap();
/// let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
/// assert!(user_val >= -10 && user_val <= 10 && user_val != 0);
/// ```
#[derive(Clone)]
#[must_use]
pub struct Filter<D, P> {
    inner: D,
    predicate: P,
}

impl<D: fmt::Debug, P> fmt::Debug for Filter<D, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Filter").field("inner", &self.inner).finish_non_exhaustive()
    }
}

impl<D, P> Filter<D, P> {
    /// Creates a new `Filter` domain wrapping `inner` and keeping only values matching `predicate`.
    #[must_use]
    pub fn new(inner: D, predicate: P) -> Self
    where
        D: Domain,
        P: for<'a> Fn(&D::UserValue<'a>) -> bool,
    {
        Self { inner, predicate }
    }

    /// Returns a reference to the inner domain.
    #[must_use]
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Consumes the `Filter` wrapper and returns the inner domain.
    #[must_use]
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D, P> Domain for Filter<D, P>
where
    D: Domain,
    P: for<'a> Fn(&D::UserValue<'a>) -> bool,
{
    type UserValue<'user> = D::UserValue<'user>;
    type CorpusValue = D::CorpusValue;

    // TODO(b/575475915): Track cumulative skip rate across non-shrinking `init` and `mutate`
    // calls and abort when the rejection rate exceeds 90% after >100 skips.
    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        for _ in 0..MAX_FILTER_ATTEMPTS {
            let candidate = self.inner.init(rng)?;
            if (self.predicate)(&self.inner.corpus_to_user_value(&candidate)?) {
                return Ok(candidate);
            }
        }
        anyhow::bail!(
            "Filter() predicate rejected all {MAX_FILTER_ATTEMPTS} initialization attempts. \
             Use Filter() only to skip unlikely values; to restrict a significant portion of \
             an input domain, construct a constrained domain directly (e.g., via InRange or Map)."
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
            let attempt = self.inner.mutate(corpus_value, rng, only_shrink).and_then(|()| {
                Ok((self.predicate)(&self.inner.corpus_to_user_value(corpus_value)?))
            });
            match attempt {
                Ok(true) => return Ok(()),
                Ok(false) => corpus_value.clone_from(&original),
                Err(err) => {
                    *corpus_value = original;
                    return Err(err);
                }
            }
        }
        if only_shrink {
            return Ok(());
        }
        anyhow::bail!(
            "Filter() predicate rejected all {MAX_FILTER_ATTEMPTS} mutation attempts. \
             Use Filter() only to skip unlikely values; to restrict a significant portion of \
             an input domain, construct a constrained domain directly (e.g., via InRange or Map)."
        )
    }

    fn corpus_to_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        self.inner.corpus_to_user_value(corpus_value)
    }

    fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<Self::CorpusValue> {
        let corpus_value = self
            .inner
            .parse_corpus(data)
            .context("Invalid corpus value for the inner domain in Filter()")?;
        anyhow::ensure!(
            (self.predicate)(&self.inner.corpus_to_user_value(&corpus_value)?),
            "Value does not match Filter() predicate."
        );
        Ok(corpus_value)
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

impl<D, P, T> ReversibleDomain<T> for Filter<D, P>
where
    D: ReversibleDomain<T>,
    P: for<'a> Fn(&D::UserValue<'a>) -> bool,
{
    fn to_unvalidated_corpus_value(&self, value: T) -> anyhow::Result<Self::CorpusValue> {
        self.inner.to_unvalidated_corpus_value(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::arbitrary::Arbitrary;
    use crate::domains::range::InRange;
    use crate::domains::utility::iterations_to_hit_all;
    use googletest::prelude::*;
    use rand::rngs::{SmallRng, SysRng};
    use rand::SeedableRng;
    use std::collections::HashSet;

    fn get_rng() -> SmallRng {
        SmallRng::try_from_rng(&mut SysRng).expect("Failed to create RNG")
    }

    #[gtest]
    fn test_filter_init_respects_predicate() {
        let mut domain = InRange::new(1i32, 10).filter(|x| *x % 2 == 0);
        let mut rng = get_rng();
        let mut observed = HashSet::new();

        for _ in 0..iterations_to_hit_all(5, 1.0 / 5.0) {
            let corpus_val = domain.init(&mut rng).unwrap();
            let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
            expect_that!(user_val, all!(ge(1), le(10)));
            expect_that!(user_val % 2, eq(0));
            observed.insert(user_val);
            if observed.len() == 5 {
                break;
            }
        }
        expect_that!(observed, unordered_elements_are![&2, &4, &6, &8, &10]);
    }

    #[gtest]
    fn test_filter_mutate_and_shrink_respect_predicate() {
        let mut small_domain = InRange::new(1i32, 10).filter(|x| *x % 2 == 0);
        let mut rng = get_rng();
        let mut val = 2i32;
        let mut observed = HashSet::new();
        for _ in 0..iterations_to_hit_all(5, 1.0 / 15.0) {
            small_domain.mutate(&mut val, &mut rng, false).unwrap();
            expect_that!(val, all!(ge(1), le(10)));
            expect_that!(val % 2, eq(0));
            observed.insert(val);
            if observed.len() == 5 {
                break;
            }
        }
        expect_that!(observed, unordered_elements_are![&2, &4, &6, &8, &10]);

        let mut domain = InRange::new(0i32, 100).filter(|x| *x % 2 == 0);

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
        expect_true!(grew_from_zero);

        let mut shrink_val = 100i32;
        for _ in 0..100 {
            let prev = shrink_val;
            domain.mutate(&mut shrink_val, &mut rng, true).unwrap();
            expect_that!(shrink_val, all!(ge(0), le(prev)));
            expect_that!(shrink_val % 2, eq(0));
        }
        expect_that!(shrink_val, eq(0));

        // Shrinking at 0 must stay at 0.
        let mut zero_val = 0i32;
        for _ in 0..50 {
            domain.mutate(&mut zero_val, &mut rng, true).unwrap();
            expect_that!(zero_val, eq(0));
        }

        // Shrinking when the inner domain's shrink target (0) is rejected by the predicate
        // must converge to 1 and return Ok(()) leaving the value unchanged once at 1.
        let mut nonzero_domain = InRange::new(-10i32, 10).filter(|x| *x != 0);
        let mut nonzero_val = 10i32;
        for _ in 0..50 {
            let prev = nonzero_val;
            nonzero_domain.mutate(&mut nonzero_val, &mut rng, true).unwrap();
            expect_that!(nonzero_val, all!(ge(1), le(prev)));
        }
        expect_that!(nonzero_val, eq(1));
        nonzero_domain.mutate(&mut nonzero_val, &mut rng, true).unwrap();
        expect_that!(nonzero_val, eq(1));
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

        expect_that!(domain.validate_corpus_value(&10), ok(anything()));

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
        let domain = InRange::new(-10i32, 10).filter(|x| *x > 0);

        let corpus_val = 7i32;
        let bytes = domain.serialize_corpus(&corpus_val).unwrap();
        let parsed = domain.parse_corpus(&bytes).unwrap();
        expect_that!(parsed, eq(7));
        expect_that!(domain.validate_corpus_value(&parsed), ok(anything()));

        // Serialized value satisfying inner domain but violating filter predicate must be rejected.
        let invalid_pred_bytes = domain.serialize_corpus(&-5i32).unwrap();
        let pred_err = domain.parse_corpus(&invalid_pred_bytes).unwrap_err();
        expect_that!(
            format!("{pred_err:#}"),
            contains_substring("Value does not match Filter() predicate.")
        );

        // Serialized value violating inner domain constraints must also be rejected.
        let invalid_inner_bytes = domain.serialize_corpus(&50i32).unwrap();
        let inner_err = domain.parse_corpus(&invalid_inner_bytes).unwrap_err();
        expect_that!(
            format!("{inner_err:#}"),
            contains_substring("Invalid corpus value for the inner domain in Filter()")
        );

        let cloned = domain.clone();
        expect_that!(
            format!("{cloned:?}"),
            all!(contains_substring("Filter"), contains_substring("inner"))
        );
    }

    #[gtest]
    fn test_filter_retries_until_predicate_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = AtomicUsize::new(0);
        let mut domain =
            Filter::new(InRange::new(1i32, 100), |_x| attempts.fetch_add(1, Ordering::SeqCst) >= 5);
        expect_that!(domain.inner().validate_corpus_value(&50), ok(anything()));
        let mut rng = get_rng();

        let mut corpus_val = domain.init(&mut rng).unwrap();
        expect_that!(corpus_val, all!(ge(1), le(100)));
        expect_that!(attempts.load(Ordering::SeqCst), eq(6));

        attempts.store(0, Ordering::SeqCst);
        domain.mutate(&mut corpus_val, &mut rng, false).unwrap();
        expect_that!(corpus_val, all!(ge(1), le(100)));
        expect_that!(attempts.load(Ordering::SeqCst), eq(6));

        let inner = domain.into_inner();
        expect_that!(inner.validate_corpus_value(&100), ok(anything()));
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

        #[derive(Clone, Debug)]
        struct FailingDomain {
            fail_init: bool,
            fail_user_value: bool,
        }

        impl Domain for FailingDomain {
            type UserValue<'user> = i32;
            type CorpusValue = i32;

            fn init(&mut self, _rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
                anyhow::ensure!(!self.fail_init, "inner init error");
                Ok(1)
            }

            fn mutate(
                &mut self,
                corpus_value: &mut Self::CorpusValue,
                _rng: &mut dyn rand::Rng,
                _only_shrink: bool,
            ) -> anyhow::Result<()> {
                *corpus_value = 99;
                Ok(())
            }

            fn corpus_to_user_value<'a>(
                &self,
                corpus_value: &'a Self::CorpusValue,
            ) -> anyhow::Result<Self::UserValue<'a>> {
                anyhow::ensure!(!self.fail_user_value, "inner corpus_to_user_value error");
                Ok(*corpus_value)
            }
        }

        let mut init_fail_domain = FailingDomain { fail_init: true, fail_user_value: false }
            .filter(|_x| panic!("Predicate must not be called when inner init fails"));
        expect_that!(
            format!("{:#}", init_fail_domain.init(&mut rng).unwrap_err()),
            contains_substring("inner init error")
        );

        let mut user_val_fail_domain = FailingDomain { fail_init: false, fail_user_value: true }
            .filter(|_x| {
                panic!("Predicate must not be called when inner corpus_to_user_value fails")
            });
        expect_that!(
            format!("{:#}", user_val_fail_domain.init(&mut rng).unwrap_err()),
            contains_substring("inner corpus_to_user_value error")
        );
        let mut val = 5i32;
        expect_that!(
            format!("{:#}", user_val_fail_domain.mutate(&mut val, &mut rng, false).unwrap_err()),
            contains_substring("inner corpus_to_user_value error")
        );
        expect_that!(val, eq(5));
    }

    #[gtest]
    fn test_filter_reversible_domain_and_with_seeds() {
        use crate::domains::SeedableDomainExt;

        #[derive(Clone, Debug)]
        struct SeedableI32;

        impl Domain for SeedableI32 {
            type UserValue<'user> = i32;
            type CorpusValue = i32;

            fn init(&mut self, _rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
                Ok(2)
            }

            fn mutate(
                &mut self,
                _corpus_value: &mut Self::CorpusValue,
                _rng: &mut dyn rand::Rng,
                _only_shrink: bool,
            ) -> anyhow::Result<()> {
                Ok(())
            }

            fn corpus_to_user_value<'a>(
                &self,
                corpus_value: &'a Self::CorpusValue,
            ) -> anyhow::Result<Self::UserValue<'a>> {
                Ok(*corpus_value)
            }
        }

        impl ReversibleDomain<i32> for SeedableI32 {
            fn to_unvalidated_corpus_value(&self, value: i32) -> anyhow::Result<Self::CorpusValue> {
                Ok(value)
            }
        }

        let filtered = SeedableI32.filter(|x| *x % 2 == 0);
        expect_that!(filtered.into_corpus_value(4), ok(eq(&4)));
        expect_that!(
            format!("{:#}", filtered.into_corpus_value(3).unwrap_err()),
            contains_substring("Value does not match Filter() predicate.")
        );

        let mut seeded = filtered.with_seeds([10]);
        let mut rng = get_rng();
        let mut saw_seed = false;
        for _ in 0..50 {
            if seeded.init(&mut rng).unwrap() == 10 {
                saw_seed = true;
                break;
            }
        }
        expect_true!(saw_seed);
    }

    #[gtest]
    fn test_filter_borrowing_user_value() {
        #[derive(Clone, Debug)]
        struct StrDomain;

        impl Domain for StrDomain {
            type UserValue<'user> = &'user str;
            type CorpusValue = String;

            fn init(&mut self, _rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
                Ok(String::from("hello"))
            }

            fn mutate(
                &mut self,
                corpus_value: &mut Self::CorpusValue,
                _rng: &mut dyn rand::Rng,
                _only_shrink: bool,
            ) -> anyhow::Result<()> {
                corpus_value.push('!');
                Ok(())
            }

            fn corpus_to_user_value<'a>(
                &self,
                corpus_value: &'a Self::CorpusValue,
            ) -> anyhow::Result<Self::UserValue<'a>> {
                Ok(corpus_value.as_str())
            }
        }

        let mut domain = StrDomain.filter(|s| !s.is_empty());
        let mut rng = get_rng();
        let mut corpus_val = domain.init(&mut rng).unwrap();
        expect_that!(domain.corpus_to_user_value(&corpus_val).unwrap(), eq("hello"));
        domain.mutate(&mut corpus_val, &mut rng, false).unwrap();
        expect_that!(domain.corpus_to_user_value(&corpus_val).unwrap(), eq("hello!"));
        expect_that!(domain.validate_corpus_value(&String::from("ok")), ok(anything()));
        expect_that!(domain.validate_corpus_value(&String::new()), err(anything()));
    }
}
