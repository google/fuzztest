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

mod sealed {
    pub trait Sealed<T> {}
    impl<F, T, U> Sealed<T> for F where F: Fn(T) -> U {}
}

/// Helper trait representing a mapping function from `T` to `Self::Output`.
///
/// This trait allows [`Map<D, F>`] to project the mapped output type for any
/// lifetime `'user` without requiring an unconstrained output type parameter on
/// the [`Domain`] implementation.
#[doc(hidden)]
pub trait MapFn<T>: sealed::Sealed<T> {
    /// The output type produced by the mapping function.
    type Output;

    /// Applies the mapping function to `input`.
    fn call(&self, input: T) -> Self::Output;
}

impl<F, T, U> MapFn<T> for F
where
    F: Fn(T) -> U,
{
    type Output = U;

    fn call(&self, input: T) -> Self::Output {
        (self)(input)
    }
}

/// Transforms user values produced by an inner domain `D` using a mapping function `F`.
///
/// `Map` delegates `init`, `mutate`, `parse_corpus`, `serialize_corpus`, and
/// `validate_corpus_value` to the inner domain `D`, and applies `F` in `corpus_to_user_value`
/// to produce the mapped user value.
///
/// It can be constructed via [`Domain::map`] or [`Map::new`]. To map over multiple domains,
/// compose a tuple domain with `.map(...)` (e.g., `(d0, d1).map(|(a, b)| ...)`).
///
/// # Seeding
///
/// `Map` is a one-way transformation and intentionally does not implement
/// [`ReversibleDomain`](super::ReversibleDomain), so `.map(...).with_seeds(...)` is rejected at
/// compile time. Calling `.with_seeds(...).map(...)` seeds the pre-mapped inner domain `D`.
///
/// Example usage:
/// ```
/// # use fuzztest::domains::Domain;
/// # use fuzztest::domains::range::InRange;
/// # use rand::rngs::SmallRng;
/// # use rand::SeedableRng;
///
/// let mut domain = InRange::new(1i32, 10).map(|x| x * 2);
/// let mut rng = SmallRng::seed_from_u64(42);
///
/// let corpus_val = domain.init(&mut rng).unwrap();
/// let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
/// assert!(user_val >= 2 && user_val <= 20 && user_val % 2 == 0);
/// ```
// TODO(b/575475915): Add a `ReversibleMap` combinator for invertible mappings that support
// `ReversibleDomain`.
#[derive(Clone)]
#[must_use]
pub struct Map<D, F> {
    inner: D,
    mapper: F,
}

impl<D: fmt::Debug, F> fmt::Debug for Map<D, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Map").field("inner", &self.inner).finish_non_exhaustive()
    }
}

impl<D, F> Map<D, F> {
    /// Creates a new `Map` domain wrapping `inner` and transforming user values with `mapper`.
    #[must_use]
    pub fn new(inner: D, mapper: F) -> Self {
        Self { inner, mapper }
    }

    /// Returns a reference to the inner domain.
    #[must_use]
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Consumes the `Map` wrapper and returns the inner domain.
    #[must_use]
    pub fn into_inner(self) -> D {
        self.inner
    }
}

#[allow(private_bounds)]
impl<D, F> Domain for Map<D, F>
where
    D: Domain,
    F: for<'a> MapFn<D::UserValue<'a>>,
{
    type UserValue<'user> = <F as MapFn<D::UserValue<'user>>>::Output;
    type CorpusValue = D::CorpusValue;

    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        self.inner.init(rng)
    }

    fn mutate(
        &mut self,
        corpus_value: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        self.inner.mutate(corpus_value, rng, only_shrink)
    }

    fn corpus_to_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        let inner_user_value = self.inner.corpus_to_user_value(corpus_value)?;
        Ok(self.mapper.call(inner_user_value))
    }

    fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<Self::CorpusValue> {
        self.inner.parse_corpus(data).context("Invalid value for Map()-ed domain")
    }

    fn serialize_corpus(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<Vec<u8>> {
        self.inner.serialize_corpus(corpus_value)
    }

    fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
        self.inner.validate_corpus_value(corpus_value).context("Invalid value for Map()-ed domain")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::arbitrary::Arbitrary;
    use crate::domains::containers::{ContainerDomain, VecOf};
    use crate::domains::range::InRange;
    use googletest::prelude::*;
    use rand::rngs::{SmallRng, SysRng};
    use rand::SeedableRng;

    fn get_rng() -> SmallRng {
        SmallRng::try_from_rng(&mut SysRng).expect("Failed to create RNG")
    }

    #[derive(Debug, PartialEq, Eq)]
    struct WrappedId(String);

    #[gtest]
    fn test_map_same_domain_and_range() {
        let mut domain = Arbitrary::<i32>::default().map(|x| !x);
        let mut rng = get_rng();

        for _ in 0..50 {
            let corpus_val = domain.init(&mut rng).unwrap();
            let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
            expect_that!(user_val, eq(!corpus_val));
        }
    }

    #[gtest]
    fn test_map_different_domain_and_range() {
        let mut domain = InRange::new(1u32, 100).map(|x| WrappedId(format!("id-{x}")));
        let mut rng = get_rng();

        let corpus_val = domain.init(&mut rng).unwrap();
        expect_that!(corpus_val, all!(ge(1), le(100)));

        let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
        expect_that!(user_val, eq(&WrappedId(format!("id-{corpus_val}"))));
    }

    #[gtest]
    fn test_map_mutate_and_shrink_delegate_to_inner() {
        let mut domain = InRange::new(0i32, 1000).map(|x| x * 10);
        let mut rng = get_rng();

        // Start from 0 (the minimum/fully-shrunk value of InRange(0, 1000)) so that a
        // non-shrinking mutation (`only_shrink = false`) must grow the value above 0.
        let mut corpus_val = 0i32;
        let mut grew_from_zero = false;
        for _ in 0..100 {
            domain.mutate(&mut corpus_val, &mut rng, false).unwrap();
            expect_that!(corpus_val, all!(ge(0), le(1000)));
            let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
            expect_that!(user_val, eq(corpus_val * 10));
            if corpus_val > 0 {
                grew_from_zero = true;
            }
        }
        expect_true!(grew_from_zero);

        let mut shrink_val = 1000i32;
        for _ in 0..100 {
            let prev = shrink_val;
            domain.mutate(&mut shrink_val, &mut rng, true).unwrap();
            expect_that!(shrink_val, all!(ge(0), le(prev)));
            expect_that!(domain.corpus_to_user_value(&shrink_val).unwrap(), eq(shrink_val * 10));
        }
        expect_that!(shrink_val, eq(0));

        // Shrinking at 0 must stay at 0.
        let mut zero_val = 0i32;
        for _ in 0..50 {
            domain.mutate(&mut zero_val, &mut rng, true).unwrap();
            expect_that!(zero_val, eq(0));
        }
    }

    #[gtest]
    fn test_map_validate_corpus_value() {
        let domain = InRange::new(10i32, 20).map(|x| x * 2);

        expect_that!(domain.validate_corpus_value(&15), ok(anything()));

        let err = domain.validate_corpus_value(&5).unwrap_err();
        let err_chain = format!("{err:#}");
        expect_that!(err_chain, contains_substring("Invalid value for Map()-ed domain"));
        expect_that!(err_chain, contains_substring("Value 5 is out of range [10, 20]"));
    }

    #[gtest]
    fn test_map_serde_roundtrip() {
        let domain = VecOf::new(InRange::new(0u8, 10)).with_max_len(5).map(|v| v.len());

        let corpus_val = vec![1u8, 2, 3];
        let bytes = domain.serialize_corpus(&corpus_val).unwrap();
        let parsed = domain.parse_corpus(&bytes).unwrap();
        expect_that!(parsed, container_eq(vec![1u8, 2, 3]));
        expect_that!(domain.corpus_to_user_value(&parsed).unwrap(), eq(3));

        // Deserializing a vector that violates inner domain constraints (length > 5) must fail.
        let invalid_bytes = domain.serialize_corpus(&vec![1u8, 2, 3, 4, 5, 6]).unwrap();
        let err = domain.parse_corpus(&invalid_bytes).unwrap_err();
        let err_chain = format!("{err:#}");
        expect_that!(err_chain, contains_substring("Invalid value for Map()-ed domain"));
    }

    #[gtest]
    fn test_map_chaining_and_clone_debug() {
        let domain = InRange::new(1i32, 5).map(|x| x + 1).map(|y| y.to_string());
        let cloned = domain.clone();

        expect_that!(
            format!("{cloned:?}"),
            all!(contains_substring("Map"), contains_substring("inner"))
        );
        expect_that!(cloned.corpus_to_user_value(&3).unwrap(), eq("4"));
        expect_that!(cloned.inner().corpus_to_user_value(&3).unwrap(), eq(4));
        let inner = cloned.into_inner();
        expect_that!(inner.corpus_to_user_value(&3).unwrap(), eq(4));
    }

    #[gtest]
    fn test_map_new_and_generic_domain() {
        use crate::domains::GenericDomain;

        let mut domain = Map::new(InRange::new(10i32, 20), |x| x * 3);
        let mut rng = get_rng();

        let mut generic_val = GenericDomain::init(&mut domain, &mut rng).unwrap();
        GenericDomain::mutate(&mut domain, &mut generic_val, &mut rng, false).unwrap();
        let bytes = GenericDomain::serialize_corpus(&domain, &generic_val).unwrap();
        let reparsed = GenericDomain::parse_corpus(&domain, &bytes).unwrap();
        let concrete_corpus = *reparsed.downcast_ref::<i32>().unwrap();
        expect_that!(concrete_corpus, all!(ge(10), le(20)));
        expect_that!(
            domain.corpus_to_user_value(&concrete_corpus).unwrap(),
            eq(concrete_corpus * 3)
        );
    }

    #[gtest]
    fn test_map_borrowing_user_value() {
        #[derive(Clone, Debug)]
        struct StrDomain;

        impl Domain for StrDomain {
            type UserValue<'user> = &'user str;
            type CorpusValue = String;

            fn init(&mut self, _rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
                Ok(String::from("  hello  "))
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
                Ok(corpus_value.as_str())
            }
        }

        let mut rng = get_rng();

        // Borrowed UserValue<'user> -> owned output via `Domain::map`.
        let mut len_domain = StrDomain.map(|s| s.len());
        let corpus_val = len_domain.init(&mut rng).unwrap();
        expect_that!(len_domain.corpus_to_user_value(&corpus_val).unwrap(), eq(9));

        // Borrowed UserValue<'user> -> borrowed `'user` output via `Map::new`.
        let mut trim_domain = Map::new(StrDomain, str::trim);
        let corpus_val = trim_domain.init(&mut rng).unwrap();
        expect_that!(trim_domain.corpus_to_user_value(&corpus_val).unwrap(), eq("hello"));
    }

    #[gtest]
    fn test_map_propagates_inner_domain_error() {
        #[derive(Clone, Debug)]
        struct FailingDomain {
            fail_init: bool,
            fail_mutate: bool,
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
                _corpus_value: &mut Self::CorpusValue,
                _rng: &mut dyn rand::Rng,
                _only_shrink: bool,
            ) -> anyhow::Result<()> {
                anyhow::ensure!(!self.fail_mutate, "inner mutate error");
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

        let mut rng = get_rng();

        let mut init_fail =
            FailingDomain { fail_init: true, fail_mutate: false, fail_user_value: false }
                .map(|_x| panic!("Mapper must not be called when inner init fails"));
        expect_that!(
            format!("{:#}", init_fail.init(&mut rng).unwrap_err()),
            contains_substring("inner init error")
        );

        let mut mutate_fail =
            FailingDomain { fail_init: false, fail_mutate: true, fail_user_value: false }
                .map(|_x| panic!("Mapper must not be called when inner mutate fails"));
        let mut val = 1i32;
        expect_that!(
            format!("{:#}", mutate_fail.mutate(&mut val, &mut rng, false).unwrap_err()),
            contains_substring("inner mutate error")
        );

        let user_val_fail =
            FailingDomain { fail_init: false, fail_mutate: false, fail_user_value: true }.map(
                |_x| panic!("Mapper must not be called when inner corpus_to_user_value fails"),
            );
        expect_that!(
            format!("{:#}", user_val_fail.corpus_to_user_value(&1).unwrap_err()),
            contains_substring("inner corpus_to_user_value error")
        );
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
        expect_that!(cloned.validate_corpus_value(&7), ok(anything()));
        expect_that!(cloned.validate_corpus_value(&3), err(anything()));

        let mut rng = get_rng();
        for _ in 0..50 {
            let corpus_val = domain.init(&mut rng).unwrap();
            expect_that!(domain.validate_corpus_value(&corpus_val), ok(anything()));
            let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
            // corpus_val is odd in [1, 50], user_val = 2 * corpus_val > 10 and divisible by 2 but
            // not 4.
            expect_that!(user_val, all!(gt(10), le(100)));
            expect_that!(user_val % 4, eq(2));
        }

        // corpus_val = 3 -> user_val = 6, which fails the outer filter `y > 10`.
        expect_that!(domain.validate_corpus_value(&3), err(anything()));
        // corpus_val = 4 -> fails the inner filter `x % 2 == 1`.
        expect_that!(domain.validate_corpus_value(&4), err(anything()));
        // corpus_val = 7 -> user_val = 14, satisfies both filters and inner range.
        expect_that!(domain.validate_corpus_value(&7), ok(anything()));
    }
}
