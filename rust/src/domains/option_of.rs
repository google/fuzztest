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

use rand::RngExt;
use std::fmt;

use super::Domain;

/// Generates optional values of type `Option<T>` using an inner domain.
///
/// An `OptionOf` domain produces either `None` or `Some(value)`, where `value`
/// is drawn from the wrapped inner domain.
///
/// Example usage:
/// ```
/// # use fuzztest::domains::Domain;
/// # use fuzztest::domains::arbitrary::Arbitrary;
/// # use fuzztest::domains::option_of::OptionOf;
/// # use rand::rngs::SmallRng;
/// # use rand::SeedableRng;
///
/// let domain = OptionOf::new(Arbitrary::<i32>::default());
/// let mut rng = SmallRng::seed_from_u64(42);
///
/// let sample = domain.init(&mut rng);
/// assert!(sample.is_ok());
/// ```
pub struct OptionOf<T> {
    inner: T,
}

impl<T: Clone> Clone for OptionOf<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T: fmt::Debug> fmt::Debug for OptionOf<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OptionOf").field("inner", &self.inner).finish()
    }
}

impl<T> OptionOf<T> {
    /// Creates a new `OptionOf` domain wrapping the specified inner domain.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> Domain for OptionOf<T>
where
    T: Domain,
{
    type CorpusValue = Option<T::CorpusValue>;
    type UserValue<'user> = Option<T::UserValue<'user>>;

    fn init(&self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        // 50% chance of returning None, 50% chance of Some(inner).
        if rng.random_bool(0.5) {
            Ok(None)
        } else {
            Ok(Some(self.inner.init(rng)?))
        }
    }

    fn mutate(
        &self,
        val: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        match val {
            None => {
                if !only_shrink {
                    *val = Some(self.inner.init(rng)?);
                }
            }
            Some(inner_val) => {
                if only_shrink {
                    // When shrinking, either drop to None or shrink the inner value.
                    if rng.random_bool(0.25) {
                        *val = None;
                    } else {
                        self.inner.mutate(inner_val, rng, true)?;
                    }
                } else {
                    // When mutating without shrinking: 1/100 chance to set to None (matching
                    // C++ FuzzTest), otherwise mutate the inner value.
                    if rng.random_bool(0.01) {
                        *val = None;
                    } else {
                        self.inner.mutate(inner_val, rng, false)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn corpus_to_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        match corpus_value {
            None => Ok(None),
            Some(v) => Ok(Some(self.inner.corpus_to_user_value(v)?)),
        }
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
    fn test_option_of_init_produces_both_none_and_some() {
        let domain = OptionOf::new(Arbitrary::<i32>::default());
        let mut rng = get_rng();

        let mut has_none = false;
        let mut has_some = false;

        for _ in 0..200 {
            let sample = domain.init(&mut rng).unwrap();
            if sample.is_none() {
                has_none = true;
            } else {
                has_some = true;
            }
            if has_none && has_some {
                break;
            }
        }

        expect_that!(has_none, eq(true), "OptionOf::init should produce None");
        expect_that!(has_some, eq(true), "OptionOf::init should produce Some");
    }

    #[gtest]
    fn test_option_of_mutate_from_none_can_become_some() {
        let domain = OptionOf::new(Arbitrary::<i32>::default());
        let mut rng = get_rng();

        let mut val: Option<i32> = None;
        domain.mutate(&mut val, &mut rng, false).unwrap();
        expect_that!(val.is_some(), eq(true), "Mutating None without shrinking should produce Some");
    }

    #[gtest]
    fn test_option_of_shrink_from_none_stays_none() {
        let domain = OptionOf::new(Arbitrary::<i32>::default());
        let mut rng = get_rng();

        let mut val: Option<i32> = None;
        for _ in 0..50 {
            domain.mutate(&mut val, &mut rng, true).unwrap();
            expect_that!(val.is_none(), eq(true), "Shrinking None must stay None");
        }
    }

    #[gtest]
    fn test_option_of_shrink_from_some_eventually_becomes_none() {
        let domain = OptionOf::new(Arbitrary::<i32>::default());
        let mut rng = get_rng();

        let mut val: Option<i32> = Some(1000);
        let mut became_none = false;

        for _ in 0..200 {
            domain.mutate(&mut val, &mut rng, true).unwrap();
            if val.is_none() {
                became_none = true;
                break;
            }
        }

        expect_that!(became_none, eq(true), "Shrinking Some should eventually produce None");
    }

    #[gtest]
    fn test_option_of_corpus_to_user_value() {
        let domain = OptionOf::new(Arbitrary::<i32>::default());

        let none_val: Option<i32> = None;
        let some_val: Option<i32> = Some(42);

        expect_that!(domain.corpus_to_user_value(&none_val).unwrap(), eq(None));
        expect_that!(domain.corpus_to_user_value(&some_val).unwrap(), eq(Some(42)));
    }

    #[gtest]
    fn test_option_of_serde_roundtrip() {
        let domain = OptionOf::new(Arbitrary::<i32>::default());

        let none_corpus: Option<i32> = None;
        let bytes = domain.serialize_corpus(&none_corpus).unwrap();
        let parsed = domain.parse_corpus(&bytes).unwrap();
        expect_that!(parsed, eq(None));

        let some_corpus: Option<i32> = Some(12345);
        let bytes = domain.serialize_corpus(&some_corpus).unwrap();
        let parsed = domain.parse_corpus(&bytes).unwrap();
        expect_that!(parsed, eq(Some(12345)));
    }
}
