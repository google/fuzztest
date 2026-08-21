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

use anyhow;
use rand::distr::uniform::SampleUniform;
use rand::distr::uniform::UniformSampler;
use std::fmt;

/// Generates values of type `T` in a given range.
pub struct InRange<T> {
    lower: T,
    upper: T,
}

impl<T: Clone> Clone for InRange<T> {
    fn clone(&self) -> Self {
        Self {
            lower: self.lower.clone(),
            upper: self.upper.clone(),
        }
    }
}

impl<T: fmt::Debug + Clone> fmt::Debug for InRange<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InRange")
            .field("lower", &self.lower)
            .field("upper", &self.upper)
            .finish()
    }
}

impl InRange<i32> {
    pub fn new(lower: i32, upper: i32) -> Self {
        Self { lower, upper }
    }

    pub fn get_in_range(&self, rng: &mut dyn rand::Rng) -> i32 {
        <i32 as SampleUniform>::Sampler::sample_single(self.lower, self.upper, rng)
            .expect("Failed to sample from Uniform distribution")
    }
}

impl Domain for InRange<i32> {
    type UserValue<'user> = i32;
    type CorpusValue = i32;

    fn init(&mut self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        Ok(self.get_in_range(rng))
    }

    fn mutate(
        &mut self,
        val: &mut Self::CorpusValue,
        rng: &mut dyn rand::Rng,
        only_shrink: bool,
    ) -> anyhow::Result<()> {
        if only_shrink {
            *val -= 1;
        } else {
            *val = self.get_in_range(rng);
        }
        Ok(())
    }

    fn get_user_value<'a>(
        &self,
        corpus_value: &'a Self::CorpusValue,
    ) -> anyhow::Result<Self::UserValue<'a>> {
        Ok(*corpus_value)
    }

    fn from_value(&self, value: Self::UserValue<'_>) -> anyhow::Result<Self::CorpusValue> {
        Ok(value)
    }

    fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> anyhow::Result<()> {
        if *corpus_value < self.lower || *corpus_value > self.upper {
            anyhow::bail!(
                "Value {} is out of range [{}, {}]",
                corpus_value, self.lower, self.upper
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn test_in_range() {
        let in_range = InRange::<i32>::new(0, 100);
        let mut rng = rand::rngs::StdRng::from_seed([73; 32]);
        let in_range_val = in_range.get_in_range(&mut rng);
        assert!(in_range_val >= 0 && in_range_val <= 100);
    }
}
