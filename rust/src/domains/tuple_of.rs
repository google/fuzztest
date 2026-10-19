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

//! [`Domain`] implementations for native Rust tuples.
//!
//! Any tuple `(T0, ...)` of domains (from 0 up to 12 elements) is itself a [`Domain`] that
//! generates tuples of elements drawn from the inner domains.
//!
//! # Examples
//!
//! ```
//! # use fuzztest::domains::Domain;
//! # use fuzztest::domains::arbitrary::Arbitrary;
//! # use fuzztest::domains::range::InRange;
//! # use rand::rngs::SmallRng;
//! # use rand::SeedableRng;
//! let mut domain = (InRange::new(0i32, 10), Arbitrary::<bool>::default());
//! let mut rng = SmallRng::seed_from_u64(42);
//!
//! let sample = domain.init(&mut rng).unwrap();
//! assert!((0..=10).contains(&sample.0));
//! ```

use super::{Domain, ReversibleDomain};
use anyhow::{Context, Result};
use rand::{Rng, RngExt};

// TODO(yamilmorales, tinmar, mathuxny-73): Replace generated wrapper domain (to deduplicate
// implementations for tests with the same number of parameters) with these tuple domains.

impl Domain for () {
    type UserValue<'user> = ();
    type CorpusValue = ();

    fn init(&mut self, _rng: &mut dyn Rng) -> Result<Self::CorpusValue> {
        Ok(())
    }

    fn mutate(
        &mut self,
        _corpus_value: &mut Self::CorpusValue,
        _rng: &mut dyn Rng,
        _only_shrink: bool,
    ) -> Result<()> {
        Ok(())
    }

    fn corpus_to_user_value<'a>(
        &self,
        _corpus_value: &'a Self::CorpusValue,
    ) -> Result<Self::UserValue<'a>> {
        Ok(())
    }
}

impl ReversibleDomain<()> for () {
    fn to_unvalidated_corpus_value(&self, _value: ()) -> Result<Self::CorpusValue> {
        Ok(())
    }
}

impl<'a> ReversibleDomain<&'a ()> for () {
    fn to_unvalidated_corpus_value(&self, _value: &'a ()) -> Result<Self::CorpusValue> {
        Ok(())
    }
}

macro_rules! impl_domain_for_tuple {
    ($( $idx:tt : $ty:ident / $seed_ty:ident ),+ $(,)?) => {
        impl<$( $ty ),+> Domain for ( $( $ty, )+ )
        where
            $( $ty: Domain, )+
        {
            type UserValue<'user> = ( $( $ty::UserValue<'user>, )+ );
            type CorpusValue = ( $( $ty::CorpusValue, )+ );

            fn init(&mut self, rng: &mut dyn Rng) -> Result<Self::CorpusValue> {
                Ok(( $( self.$idx.init(rng)?, )+ ))
            }

            fn mutate(
                &mut self,
                corpus_value: &mut Self::CorpusValue,
                rng: &mut dyn Rng,
                only_shrink: bool,
            ) -> Result<()> {
                const COUNT: usize = [$( $idx ),+].len();
                match rng.random_range(0..COUNT) {
                    $(
                        $idx => self.$idx.mutate(&mut corpus_value.$idx, rng, only_shrink),
                    )+
                    _ => unreachable!(),
                }
            }

            fn corpus_to_user_value<'a>(
                &self,
                corpus_value: &'a Self::CorpusValue,
            ) -> Result<Self::UserValue<'a>> {
                Ok(( $( self.$idx.corpus_to_user_value(&corpus_value.$idx)?, )+ ))
            }

            fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> Result<()> {
                $(
                    self.$idx
                        .validate_corpus_value(&corpus_value.$idx)
                        .with_context(|| format!("Invalid value in tuple element {}", $idx))?;
                )+
                Ok(())
            }
        }

        impl<$( $ty, $seed_ty ),+> ReversibleDomain<( $( $seed_ty, )+ )> for ( $( $ty, )+ )
        where
            $( $ty: ReversibleDomain<$seed_ty>, )+
        {
            fn to_unvalidated_corpus_value(
                &self,
                value: ( $( $seed_ty, )+ ),
            ) -> Result<Self::CorpusValue> {
                Ok(( $(
                    self.$idx
                        .to_unvalidated_corpus_value(value.$idx)
                        .with_context(|| {
                            format!("Failed to convert seed in tuple element {}", $idx)
                        })?,
                )+ ))
            }
        }

        impl<'a, $( $ty, $seed_ty ),+> ReversibleDomain<&'a ( $( $seed_ty, )+ )> for ( $( $ty, )+ )
        where
            $( $ty: ReversibleDomain<&'a $seed_ty>, )+
        {
            fn to_unvalidated_corpus_value(
                &self,
                value: &'a ( $( $seed_ty, )+ ),
            ) -> Result<Self::CorpusValue> {
                Ok(( $(
                    self.$idx
                        .to_unvalidated_corpus_value(&value.$idx)
                        .with_context(|| {
                            format!("Failed to convert seed in tuple element {}", $idx)
                        })?,
                )+ ))
            }
        }
    };
}

impl_domain_for_tuple!(0: T0 / S0);
impl_domain_for_tuple!(0: T0 / S0, 1: T1 / S1);
impl_domain_for_tuple!(0: T0 / S0, 1: T1 / S1, 2: T2 / S2);
impl_domain_for_tuple!(0: T0 / S0, 1: T1 / S1, 2: T2 / S2, 3: T3 / S3);
impl_domain_for_tuple!(0: T0 / S0, 1: T1 / S1, 2: T2 / S2, 3: T3 / S3, 4: T4 / S4);
impl_domain_for_tuple!(0: T0 / S0, 1: T1 / S1, 2: T2 / S2, 3: T3 / S3, 4: T4 / S4, 5: T5 / S5);
impl_domain_for_tuple!(
    0: T0 / S0,
    1: T1 / S1,
    2: T2 / S2,
    3: T3 / S3,
    4: T4 / S4,
    5: T5 / S5,
    6: T6 / S6
);
impl_domain_for_tuple!(
    0: T0 / S0,
    1: T1 / S1,
    2: T2 / S2,
    3: T3 / S3,
    4: T4 / S4,
    5: T5 / S5,
    6: T6 / S6,
    7: T7 / S7
);
impl_domain_for_tuple!(
    0: T0 / S0,
    1: T1 / S1,
    2: T2 / S2,
    3: T3 / S3,
    4: T4 / S4,
    5: T5 / S5,
    6: T6 / S6,
    7: T7 / S7,
    8: T8 / S8
);
impl_domain_for_tuple!(
    0: T0 / S0,
    1: T1 / S1,
    2: T2 / S2,
    3: T3 / S3,
    4: T4 / S4,
    5: T5 / S5,
    6: T6 / S6,
    7: T7 / S7,
    8: T8 / S8,
    9: T9 / S9
);
impl_domain_for_tuple!(
    0: T0 / S0,
    1: T1 / S1,
    2: T2 / S2,
    3: T3 / S3,
    4: T4 / S4,
    5: T5 / S5,
    6: T6 / S6,
    7: T7 / S7,
    8: T8 / S8,
    9: T9 / S9,
    10: T10 / S10
);
impl_domain_for_tuple!(
    0: T0 / S0,
    1: T1 / S1,
    2: T2 / S2,
    3: T3 / S3,
    4: T4 / S4,
    5: T5 / S5,
    6: T6 / S6,
    7: T7 / S7,
    8: T8 / S8,
    9: T9 / S9,
    10: T10 / S10,
    11: T11 / S11
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::arbitrary::Arbitrary;
    use crate::domains::containers::{ContainerDomain, VecOf};
    use crate::domains::range::InRange;
    use crate::domains::utility::iterations_to_hit_all;
    use crate::domains::SeedableDomainExt;
    use googletest::prelude::*;
    use rand::rngs::{SmallRng, SysRng};
    use rand::SeedableRng;
    use std::collections::HashSet;

    fn get_rng() -> SmallRng {
        SmallRng::try_from_rng(&mut SysRng).expect("Failed to create RNG")
    }

    #[gtest]
    fn test_tuple_of_1_domain() {
        let mut domain = (InRange::new(10i32, 20),);
        let mut rng = get_rng();

        for _ in 0..50 {
            let mut val = domain.init(&mut rng).unwrap();
            expect_that!(val.0, all!(ge(10), le(20)));
            expect_that!(domain.validate_corpus_value(&val), ok(anything()));
            expect_that!(domain.corpus_to_user_value(&val).unwrap(), eq(val));

            domain.mutate(&mut val, &mut rng, false).unwrap();
            expect_that!(val.0, all!(ge(10), le(20)));
        }

        // Verify shrinking vs non-shrinking on 1-tuple.
        let mut arb_domain = (Arbitrary::<i32>::default(),);
        let mut zero_val = (0i32,);
        arb_domain.mutate(&mut zero_val, &mut rng, true).unwrap();
        expect_that!(zero_val, eq((0,)));
        arb_domain.mutate(&mut zero_val, &mut rng, false).unwrap();
        expect_that!(zero_val, not(eq((0,))));

        let mut shrink_val = (1000i32,);
        arb_domain.mutate(&mut shrink_val, &mut rng, true).unwrap();
        expect_that!(shrink_val.0, all!(ge(0), lt(1000)));

        expect_that!(domain.validate_corpus_value(&(5,)), err(anything()));
        expect_that!(domain.validate_corpus_value(&(25,)), err(anything()));
    }

    #[gtest]
    fn test_tuple_of_2_init_and_corpus_to_user_value() {
        let mut domain = (InRange::new(-5i32, 5), VecOf::new(InRange::new(1u8, 3)).with_len(2));
        let mut rng = get_rng();

        for _ in 0..50 {
            let corpus_val = domain.init(&mut rng).unwrap();
            expect_that!(corpus_val.0, all!(ge(-5), le(5)));
            expect_that!(corpus_val.1.len(), eq(2));
            for &elem in &corpus_val.1 {
                expect_that!(elem, all!(ge(1), le(3)));
            }

            let user_val = domain.corpus_to_user_value(&corpus_val).unwrap();
            expect_that!(user_val, eq(&corpus_val));
        }
    }

    struct BorrowedStrDomain;

    impl Domain for BorrowedStrDomain {
        type UserValue<'user> = &'user str;
        type CorpusValue = String;

        fn init(&mut self, _rng: &mut dyn Rng) -> anyhow::Result<Self::CorpusValue> {
            Ok(String::from("hello"))
        }

        fn mutate(
            &mut self,
            corpus_value: &mut Self::CorpusValue,
            _rng: &mut dyn Rng,
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

    #[gtest]
    fn test_tuple_of_custom_and_borrowing_corpus_to_user_value() {
        let mut domain = (BorrowedStrDomain, InRange::new(10i32, 20));
        let mut rng = get_rng();

        let mut corpus_val: (String, i32) = domain.init(&mut rng).unwrap();
        let user_val: (&str, i32) = domain.corpus_to_user_value(&corpus_val).unwrap();
        expect_that!(user_val.0, eq("hello"));
        expect_that!(user_val.1, all!(ge(10), le(20)));

        domain.mutate(&mut corpus_val, &mut rng, false).unwrap();
        let mutated_user_val: (&str, i32) = domain.corpus_to_user_value(&corpus_val).unwrap();
        expect_that!(mutated_user_val.0, any!(eq("hello"), eq("hello!")));
        expect_that!(mutated_user_val.1, all!(ge(10), le(20)));
    }

    #[gtest]
    fn test_tuple_of_mutate_mutates_one_element_per_step_and_covers_all() {
        let mut domain =
            (Arbitrary::<i32>::default(), Arbitrary::<i32>::default(), Arbitrary::<i32>::default());
        let mut rng = get_rng();
        let mut val = (0, 0, 0);

        let mut mutated_0 = false;
        let mut mutated_1 = false;
        let mut mutated_2 = false;

        for _ in 0..iterations_to_hit_all(3, 1.0 / 3.0) {
            let prev = val;
            domain.mutate(&mut val, &mut rng, false).unwrap();
            let changed_0 = val.0 != prev.0;
            let changed_1 = val.1 != prev.1;
            let changed_2 = val.2 != prev.2;

            let changed_count =
                usize::from(changed_0) + usize::from(changed_1) + usize::from(changed_2);
            expect_that!(
                changed_count,
                eq(1),
                "Each tuple mutation step should mutate exactly one element"
            );

            mutated_0 |= changed_0;
            mutated_1 |= changed_1;
            mutated_2 |= changed_2;
        }

        expect_true!(mutated_0);
        expect_true!(mutated_1);
        expect_true!(mutated_2);
    }

    #[gtest]
    fn test_tuple_of_shrink_converges_to_target() {
        let mut domain =
            (Arbitrary::<i32>::default(), Arbitrary::<u8>::default(), Arbitrary::<bool>::default());
        let mut rng = get_rng();
        let mut val = (1000i32, 200u8, true);

        for _ in 0..1000 {
            if val == (0, 0, false) {
                break;
            }
            let prev = val;
            domain.mutate(&mut val, &mut rng, true).unwrap();
            expect_that!(val.0.abs(), le(prev.0.abs()));
            expect_that!(val.1, le(prev.1));
            if !prev.2 {
                expect_that!(val.2, eq(false));
            }
        }

        expect_that!(val, eq((0, 0, false)));

        // Shrinking at target must stay at target.
        domain.mutate(&mut val, &mut rng, true).unwrap();
        expect_that!(val, eq((0, 0, false)));
    }

    #[gtest]
    fn test_tuple_of_validate_corpus_value() {
        let constrained = (
            InRange::new(10i32, 20),
            VecOf::new(InRange::new(1u8, 5)).with_min_len(1).with_max_len(2),
        );

        let valid_val = (15i32, vec![2u8, 4u8]);
        expect_that!(constrained.validate_corpus_value(&valid_val), ok(anything()));

        let invalid_first = (5i32, vec![2u8, 4u8]);
        expect_that!(constrained.validate_corpus_value(&invalid_first), err(anything()));

        let invalid_second_elem = (15i32, vec![2u8, 9u8]);
        expect_that!(constrained.validate_corpus_value(&invalid_second_elem), err(anything()));

        let invalid_second_len = (15i32, Vec::<u8>::new());
        expect_that!(constrained.validate_corpus_value(&invalid_second_len), err(anything()));
    }

    #[gtest]
    fn test_tuple_of_serde_roundtrip() {
        let domain = (
            InRange::new(10i32, 20),
            VecOf::new(InRange::new(1u8, 5)).with_min_len(1).with_max_len(2),
        );

        let val = (15i32, vec![2u8, 4u8]);
        let bytes = domain.serialize_corpus(&val).unwrap();
        expect_that!(domain.parse_corpus(&bytes).unwrap(), eq(&val));

        let unconstrained = (Arbitrary::<i32>::default(), VecOf::new(Arbitrary::<u8>::default()));
        let invalid_bytes = unconstrained.serialize_corpus(&(5i32, vec![2u8])).unwrap();
        expect_that!(domain.parse_corpus(&invalid_bytes), err(anything()));
    }

    #[gtest]
    fn test_tuple_of_nested() {
        let mut domain = (
            (InRange::new(1i32, 5), Arbitrary::<bool>::default()),
            VecOf::new(InRange::new(10u8, 20)).with_len(2),
        );
        let mut rng = get_rng();

        let mut val = domain.init(&mut rng).unwrap();
        expect_that!(domain.validate_corpus_value(&val), ok(anything()));

        for _ in 0..50 {
            domain.mutate(&mut val, &mut rng, false).unwrap();
            expect_that!(domain.validate_corpus_value(&val), ok(anything()));
        }

        let bytes = domain.serialize_corpus(&val).unwrap();
        let parsed = domain.parse_corpus(&bytes).unwrap();
        expect_that!(parsed, eq(&val));
    }

    #[gtest]
    fn test_tuple_of_arities_up_to_12() {
        let mut rng = get_rng();

        let mut d0 = ();
        let mut v0 = d0.init(&mut rng).unwrap();
        d0.mutate(&mut v0, &mut rng, false).unwrap();
        expect_that!(d0.validate_corpus_value(&v0), ok(anything()));
        expect_that!(d0.corpus_to_user_value(&v0), ok(eq(&())));
        let bytes0 = d0.serialize_corpus(&v0).unwrap();
        expect_that!(d0.parse_corpus(&bytes0), ok(eq(&())));

        macro_rules! check_tuple_arity {
            ($( $idx:tt ),+ $(,)?) => {{
                let mut domain = ( $( { let _ = $idx; InRange::new(1u8, 5) }, )+ );
                let mut val = domain.init(&mut rng).unwrap();
                for _ in 0..10 {
                    domain.mutate(&mut val, &mut rng, false).unwrap();
                    expect_that!(domain.validate_corpus_value(&val), ok(anything()));
                }
                expect_that!(domain.corpus_to_user_value(&val), ok(eq(&val)));
                let bytes = domain.serialize_corpus(&val).unwrap();
                expect_that!(domain.parse_corpus(&bytes), ok(eq(&val)));

                $(
                    let mut invalid = val;
                    invalid.$idx = 99;
                    let err = domain.validate_corpus_value(&invalid).unwrap_err();
                    expect_that!(
                        format!("{err:#}"),
                        contains_substring(format!("Invalid value in tuple element {}", $idx))
                    );
                )+
            }};
        }

        check_tuple_arity!(0);
        check_tuple_arity!(0, 1);
        check_tuple_arity!(0, 1, 2);
        check_tuple_arity!(0, 1, 2, 3);
        check_tuple_arity!(0, 1, 2, 3, 4);
        check_tuple_arity!(0, 1, 2, 3, 4, 5);
        check_tuple_arity!(0, 1, 2, 3, 4, 5, 6);
        check_tuple_arity!(0, 1, 2, 3, 4, 5, 6, 7);
        check_tuple_arity!(0, 1, 2, 3, 4, 5, 6, 7, 8);
        check_tuple_arity!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
        check_tuple_arity!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        check_tuple_arity!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
    }

    #[derive(Clone, Debug)]
    struct ReversibleRangeU8 {
        min: u8,
        max: u8,
    }

    impl Domain for ReversibleRangeU8 {
        type UserValue<'user> = u8;
        type CorpusValue = u8;

        fn init(&mut self, rng: &mut dyn Rng) -> anyhow::Result<Self::CorpusValue> {
            Ok(rng.random_range(self.min..=self.max))
        }

        fn mutate(
            &mut self,
            corpus_value: &mut Self::CorpusValue,
            rng: &mut dyn Rng,
            _only_shrink: bool,
        ) -> anyhow::Result<()> {
            *corpus_value = self.init(rng)?;
            Ok(())
        }

        fn corpus_to_user_value<'a>(
            &self,
            corpus_value: &'a Self::CorpusValue,
        ) -> anyhow::Result<Self::UserValue<'a>> {
            Ok(*corpus_value)
        }

        fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
            anyhow::ensure!(
                (self.min..=self.max).contains(corpus_value),
                "value {corpus_value} out of range [{}..={}]",
                self.min,
                self.max
            );
            Ok(())
        }
    }

    impl ReversibleDomain<u8> for ReversibleRangeU8 {
        fn to_unvalidated_corpus_value(&self, value: u8) -> anyhow::Result<Self::CorpusValue> {
            Ok(value)
        }
    }

    impl<'a> ReversibleDomain<&'a u8> for ReversibleRangeU8 {
        fn to_unvalidated_corpus_value(&self, value: &'a u8) -> anyhow::Result<Self::CorpusValue> {
            Ok(*value)
        }
    }

    #[gtest]
    fn test_tuple_of_reversible_domain_and_seeding() {
        let mut rng = get_rng();

        let unit_domain = ();
        expect_that!(unit_domain.into_corpus_value(()), ok(eq(&())));
        expect_that!(unit_domain.into_corpus_value(&()), ok(eq(&())));

        let base_domain =
            (ReversibleRangeU8 { min: 10, max: 20 }, ReversibleRangeU8 { min: 30, max: 40 });
        expect_that!(base_domain.into_corpus_value((12u8, 34u8)), ok(eq(&(12u8, 34u8))));
        expect_that!(base_domain.into_corpus_value(&(15u8, 38u8)), ok(eq(&(15u8, 38u8))));
        expect_that!(base_domain.into_corpus_value((5u8, 34u8)), err(anything()));
        expect_that!(base_domain.into_corpus_value((12u8, 99u8)), err(anything()));

        let mut seeded = base_domain
            .with_seeds([(11u8, 31u8)])
            .with_seeds(&[(19u8, 39u8)])
            .with_seed_provider(|| vec![(15u8, 35u8)]);

        let mut observed = HashSet::new();
        for _ in 0..iterations_to_hit_all(3, 0.5 / 3.0) {
            observed.insert(seeded.init(&mut rng).unwrap());
        }
        expect_that!(observed, contains(eq(&(11u8, 31u8))));
        expect_that!(observed, contains(eq(&(19u8, 39u8))));
        expect_that!(observed, contains(eq(&(15u8, 35u8))));
    }
}
