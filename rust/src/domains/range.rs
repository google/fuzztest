use super::Domain;

use anyhow;
use rand::distr::uniform::SampleUniform;
use rand::distr::uniform::UniformSampler;

/// Generates values of type `T` in a given range.
///
/// For example, `InRange::new(0, 100)` generates integer
/// values from the inclusive range `[0, 100]`.
///
/// Example usage:
/// ```
/// # use fuzztest::domains::Domain;
/// # use fuzztest::domains::range::InRange;
/// # use rand::prelude::*;
///
/// let range_i32 = InRange::new(21i32, 73);
/// let sample = range_i32.init(&mut rand::rng());
///
/// assert!(sample.is_ok());
/// let sample = sample.unwrap();
/// assert!(sample >= 21);
/// assert!(sample <= 73);
/// ```
pub struct InRange<T> {
    lower: T,
    upper: T,
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

    fn init(&self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        Ok(self.get_in_range(rng))
    }

    fn mutate(
        &self,
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
