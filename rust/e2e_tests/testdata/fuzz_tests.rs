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

use fuzztest::domains::arbitrary::Arbitrary;
use fuzztest::domains::range::InRange;
use fuzztest::domains::Domain;
use fuzztest::fuzztest;
use rand::RngExt;
use std::mem::MaybeUninit;

struct ByteVectorDomain {}

impl ByteVectorDomain {
    pub fn new() -> Self {
        Self {}
    }
}

// Test-only domain.
impl Domain for ByteVectorDomain {
    type UserValue<'user> = Vec<u8>;
    type CorpusValue = Vec<u8>;

    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        let mut val = vec![0u8; rng.random_range(0..100)];
        rng.fill(&mut val[..]);
        Ok(val)
    }

    fn mutate(
        &mut self,
        val: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        if only_shrink {
            if rng.random::<f32>() < 0.05 && !val.is_empty() {
                val.remove(rng.random_range(..val.len()));
            }

            for elem in val {
                if *elem != 0 {
                    *elem -= 1;
                }
            }

            return Ok(());
        }
        if rng.random::<f32>() < 0.05 {
            val.insert(rng.random_range(0..=val.len()), rng.random());
        }

        if rng.random::<f32>() < 0.05 && !val.is_empty() {
            val.remove(rng.random_range(..val.len()));
        }

        let start = rng.random_range(0..=val.len());
        let end = rng.random_range(start..=val.len());
        rng.fill(&mut val[start..end]);

        Ok(())
    }

    fn get_user_value<'a>(
        &self,
        val: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        Ok(val.clone())
    }

    fn from_value(&self, value: Self::UserValue<'_>) -> anyhow::Result<Self::CorpusValue> {
        Ok(value)
    }
}

#[fuzztest(_a = Arbitrary::<bool>::default())]
fn bool_fuzz_test(_a: bool) {}

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn i32_fuzz_test(_a: i32) {}

#[fuzztest(
    _a = Arbitrary::<i32>::default(),
    _b = Arbitrary::<f32>::default(),
    _c = Arbitrary::<bool>::default(),
    _d = ByteVectorDomain::new()
)]
fn multi_arg_fuzz_test(_a: i32, _b: f32, _c: bool, _d: Vec<u8>) {}

// Designed to fail in a "rare" instance.
#[fuzztest(a = ByteVectorDomain::new())]
fn find_bug_fuzz_test(a: Vec<u8>) {
    if !a.is_empty() && a[0] == 123 {
        panic!("Bug found!");
    }
}

// Designed to fail in an even rarer instance to prove that coverage is working.
#[fuzztest(a = ByteVectorDomain::new())]
fn find_rarer_bug_fuzz_test(a: Vec<u8>) {
    if a.len() == 5 && a[0] == b'P' && a[1] == b'a' && a[2] == b'N' && a[3] == b'i' && a[4] == b'C'
    {
        panic!("Bug found!");
    }
}

#[fuzztest(a = ByteVectorDomain::new(), b = ByteVectorDomain::new())]
fn find_rarer_bug_2_args_fuzz_test(a: Vec<u8>, b: Vec<u8>) {
    if !a.is_empty() && a[0] >= 128 && !b.is_empty() && b[0] == 42 {
        panic!("Bug found!");
    }
}

#[fuzztest(a = ByteVectorDomain::new(), b = Arbitrary::<f32>::default(), c = InRange::<i32>::new(0, 100))]
fn find_rarer_bug_3_args_fuzz_test(a: Vec<u8>, b: f32, c: i32) {
    if !a.is_empty() && a[0] >= 128 && b < 0.0 && c >= 95 {
        panic!("Bug found!");
    }
}
#[fuzztest(a = ByteVectorDomain::new())]
fn use_after_free_asan_death_test(mut a: Vec<u8>) {
    if !a.is_empty() && a[0] == 123 {
        let ptr = a.as_mut_ptr();
        drop(a);
        // Intentionally trigger a use-after-free bug for ASAN to detect.
        unsafe {
            *(std::hint::black_box(ptr)) = 1;
        }
    }
}

#[fuzztest(a = ByteVectorDomain::new())]
fn msan_death_test(a: Vec<u8>) {
    if !a.is_empty() && a[0] == 123 {
        // Intentionally trigger an uninitialized memory bug for MSAN to detect.
        unsafe {
            let x: MaybeUninit<i32> = MaybeUninit::uninit();
            let y = std::hint::black_box(x).assume_init();
            println!("y: {}", y);
        }
    }
}

struct FallibleDomain {}

impl FallibleDomain {
    pub fn new() -> Self {
        Self {}
    }
}

impl Domain for FallibleDomain {
    type UserValue<'user> = u32;
    type CorpusValue = u32;

    fn init(&mut self, _rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        Ok(0)
    }

    fn mutate(
        &mut self,
        _val: &mut Self::CorpusValue,
        _rng: &mut dyn rand::Rng,
        _only_shrink: bool,
    ) -> anyhow::Result<()> {
        anyhow::bail!("Intentional mutate failure")
    }

    fn get_user_value<'a>(
        &self,
        val: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        Ok(*val)
    }

    fn from_value(&self, value: Self::UserValue<'_>) -> anyhow::Result<Self::CorpusValue> {
        Ok(value)
    }
}

#[fuzztest(a = FallibleDomain::new())]
fn fallible_fuzz_test(_a: u32) {}
