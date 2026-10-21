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

use super::Domain;
use anyhow::Result;
use rand::{Rng, RngExt};

// TODO(yamilmorales, tinmar, mathuxny-73): Replace generated wrapper domain (to deduplicate
// implementations for tests with the same number of parameters) with these tuple domains.

pub type TupleOf1<T0> = (T0,);
pub type TupleOf2<T0, T1> = (T0, T1);
pub type TupleOf3<T0, T1, T2> = (T0, T1, T2);
pub type TupleOf4<T0, T1, T2, T3> = (T0, T1, T2, T3);
pub type TupleOf5<T0, T1, T2, T3, T4> = (T0, T1, T2, T3, T4);
pub type TupleOf6<T0, T1, T2, T3, T4, T5> = (T0, T1, T2, T3, T4, T5);
pub type TupleOf7<T0, T1, T2, T3, T4, T5, T6> = (T0, T1, T2, T3, T4, T5, T6);
pub type TupleOf8<T0, T1, T2, T3, T4, T5, T6, T7> = (T0, T1, T2, T3, T4, T5, T6, T7);
pub type TupleOf9<T0, T1, T2, T3, T4, T5, T6, T7, T8> = (T0, T1, T2, T3, T4, T5, T6, T7, T8);
pub type TupleOf10<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9> =
    (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9);
pub type TupleOf11<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10> =
    (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
pub type TupleOf12<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11> =
    (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);

impl<T0> Domain for (T0,)
where
    T0: Domain,
{
    type UserValue<'user> = (T0::UserValue<'user>,);
    type CorpusValue = (T0::CorpusValue,);

    fn init(&mut self, rng: &mut dyn Rng) -> Result<Self::CorpusValue> {
        Ok((self.0.init(rng)?,))
    }

    fn mutate(
        &mut self,
        corpus_value: &mut Self::CorpusValue,
        rng: &mut dyn Rng,
        only_shrink: bool,
    ) -> Result<()> {
        self.0.mutate(&mut corpus_value.0, rng, only_shrink)
    }

    fn corpus_to_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> Result<Self::UserValue<'a>> {
        Ok((self.0.corpus_to_user_value(&corpus_value.0)?,))
    }

    fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> Result<()> {
        self.0.validate_corpus_value(&corpus_value.0)
    }
}

macro_rules! impl_domain_for_tuple {
    ($count:expr, $( $idx:tt : $ty:ident ),+ $(,)?) => {
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
                match rng.random_range(0usize..$count) {
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
                $( self.$idx.validate_corpus_value(&corpus_value.$idx)?; )+
                Ok(())
            }
        }
    };
}

impl_domain_for_tuple!(2, 0: T0, 1: T1);
impl_domain_for_tuple!(3, 0: T0, 1: T1, 2: T2);
impl_domain_for_tuple!(4, 0: T0, 1: T1, 2: T2, 3: T3);
impl_domain_for_tuple!(5, 0: T0, 1: T1, 2: T2, 3: T3, 4: T4);
impl_domain_for_tuple!(6, 0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5);
impl_domain_for_tuple!(7, 0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6);
impl_domain_for_tuple!(8, 0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6, 7: T7);
impl_domain_for_tuple!(9, 0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6, 7: T7, 8: T8);
impl_domain_for_tuple!(
    10,
    0: T0,
    1: T1,
    2: T2,
    3: T3,
    4: T4,
    5: T5,
    6: T6,
    7: T7,
    8: T8,
    9: T9
);
impl_domain_for_tuple!(
    11,
    0: T0,
    1: T1,
    2: T2,
    3: T3,
    4: T4,
    5: T5,
    6: T6,
    7: T7,
    8: T8,
    9: T9,
    10: T10
);
impl_domain_for_tuple!(
    12,
    0: T0,
    1: T1,
    2: T2,
    3: T3,
    4: T4,
    5: T5,
    6: T6,
    7: T7,
    8: T8,
    9: T9,
    10: T10,
    11: T11
);

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

    #[gtest]
    fn test_tuple_of_1_domain() {
        let mut domain: TupleOf1<_> = (InRange::new(10i32, 20),);
        let mut rng = get_rng();

        for _ in 0..50 {
            let mut val = domain.init(&mut rng).unwrap();
            expect_that!(val.0, all!(ge(10), le(20)));
            expect_that!(domain.validate_corpus_value(&val).is_ok(), eq(true));
            expect_that!(domain.corpus_to_user_value(&val).unwrap(), eq(val));

            domain.mutate(&mut val, &mut rng, false).unwrap();
            expect_that!(val.0, all!(ge(10), le(20)));
        }

        expect_that!(domain.validate_corpus_value(&(5,)).is_err(), eq(true));
        expect_that!(domain.validate_corpus_value(&(25,)).is_err(), eq(true));
    }

    #[gtest]
    fn test_tuple_of_2_init_and_corpus_to_user_value() {
        let mut domain: TupleOf2<_, _> =
            (InRange::new(-5i32, 5), VecOf::new(InRange::new(1u8, 3)).with_len(2));
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

    #[gtest]
    fn test_tuple_of_mutate_mutates_one_element_per_step_and_covers_all() {
        let mut domain: TupleOf3<_, _, _> =
            (Arbitrary::<i32>::default(), Arbitrary::<i32>::default(), Arbitrary::<i32>::default());
        let mut rng = get_rng();
        let mut val = (10, 20, 30);

        let mut mutated_0 = false;
        let mut mutated_1 = false;
        let mut mutated_2 = false;

        for _ in 0..100 {
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

        expect_that!(mutated_0, eq(true));
        expect_that!(mutated_1, eq(true));
        expect_that!(mutated_2, eq(true));
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
    }

    #[gtest]
    fn test_tuple_of_validate_corpus_value() {
        let constrained = (
            InRange::new(10i32, 20),
            VecOf::new(InRange::new(1u8, 5)).with_min_len(1).with_max_len(2),
        );

        let valid_val = (15i32, vec![2u8, 4u8]);
        expect_that!(constrained.validate_corpus_value(&valid_val).is_ok(), eq(true));

        let invalid_first = (5i32, vec![2u8, 4u8]);
        expect_that!(constrained.validate_corpus_value(&invalid_first).is_err(), eq(true));

        let invalid_second_elem = (15i32, vec![2u8, 9u8]);
        expect_that!(constrained.validate_corpus_value(&invalid_second_elem).is_err(), eq(true));

        let invalid_second_len = (15i32, Vec::<u8>::new());
        expect_that!(constrained.validate_corpus_value(&invalid_second_len).is_err(), eq(true));
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
    }

    #[gtest]
    fn test_tuple_of_nested() {
        let mut domain = (
            (InRange::new(1i32, 5), Arbitrary::<bool>::default()),
            VecOf::new(InRange::new(10u8, 20)).with_len(2),
        );
        let mut rng = get_rng();

        let mut val = domain.init(&mut rng).unwrap();
        expect_that!(domain.validate_corpus_value(&val).is_ok(), eq(true));

        for _ in 0..50 {
            domain.mutate(&mut val, &mut rng, false).unwrap();
            expect_that!(domain.validate_corpus_value(&val).is_ok(), eq(true));
        }

        let bytes = domain.serialize_corpus(&val).unwrap();
        let parsed = domain.parse_corpus(&bytes).unwrap();
        expect_that!(parsed, eq(&val));
    }

    #[gtest]
    fn test_tuple_of_arities_up_to_12() {
        let mut rng = get_rng();

        let mut d4: TupleOf4<_, _, _, _> = (
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
        );
        let mut v4 = d4.init(&mut rng).unwrap();
        d4.mutate(&mut v4, &mut rng, false).unwrap();
        expect_that!(d4.validate_corpus_value(&v4).is_ok(), eq(true));

        let mut d5: TupleOf5<_, _, _, _, _> = (
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
        );
        let mut v5 = d5.init(&mut rng).unwrap();
        d5.mutate(&mut v5, &mut rng, false).unwrap();
        expect_that!(d5.validate_corpus_value(&v5).is_ok(), eq(true));

        let mut d6: TupleOf6<_, _, _, _, _, _> = (
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
        );
        let mut v6 = d6.init(&mut rng).unwrap();
        d6.mutate(&mut v6, &mut rng, false).unwrap();
        expect_that!(d6.validate_corpus_value(&v6).is_ok(), eq(true));

        let mut d7: TupleOf7<_, _, _, _, _, _, _> = (
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
        );
        let mut v7 = d7.init(&mut rng).unwrap();
        d7.mutate(&mut v7, &mut rng, false).unwrap();
        expect_that!(d7.validate_corpus_value(&v7).is_ok(), eq(true));

        let mut d8: TupleOf8<_, _, _, _, _, _, _, _> = (
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
        );
        let mut v8 = d8.init(&mut rng).unwrap();
        d8.mutate(&mut v8, &mut rng, false).unwrap();
        expect_that!(d8.validate_corpus_value(&v8).is_ok(), eq(true));

        let mut d9: TupleOf9<_, _, _, _, _, _, _, _, _> = (
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
        );
        let mut v9 = d9.init(&mut rng).unwrap();
        d9.mutate(&mut v9, &mut rng, false).unwrap();
        expect_that!(d9.validate_corpus_value(&v9).is_ok(), eq(true));

        let mut d10: TupleOf10<_, _, _, _, _, _, _, _, _, _> = (
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
        );
        let mut v10 = d10.init(&mut rng).unwrap();
        d10.mutate(&mut v10, &mut rng, false).unwrap();
        expect_that!(d10.validate_corpus_value(&v10).is_ok(), eq(true));

        let mut d11: TupleOf11<_, _, _, _, _, _, _, _, _, _, _> = (
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
            InRange::new(0u8, 5),
        );
        let mut v11 = d11.init(&mut rng).unwrap();
        d11.mutate(&mut v11, &mut rng, false).unwrap();
        expect_that!(d11.validate_corpus_value(&v11).is_ok(), eq(true));

        let mut d12: TupleOf12<_, _, _, _, _, _, _, _, _, _, _, _> = (
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
            InRange::new(1u8, 5),
        );
        let mut v12 = d12.init(&mut rng).unwrap();
        for _ in 0..50 {
            d12.mutate(&mut v12, &mut rng, false).unwrap();
            expect_that!(d12.validate_corpus_value(&v12).is_ok(), eq(true));
        }
        let user_v12 = d12.corpus_to_user_value(&v12).unwrap();
        expect_that!(user_v12, eq(v12));
        let bytes12 = d12.serialize_corpus(&v12).unwrap();
        expect_that!(d12.parse_corpus(&bytes12).unwrap(), eq(v12));

        let mut invalid_v12 = v12;
        invalid_v12.11 = 99;
        expect_that!(d12.validate_corpus_value(&invalid_v12).is_err(), eq(true));
    }
}
