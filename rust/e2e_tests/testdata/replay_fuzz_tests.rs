use fuzztest::domains::arbitrary::Arbitrary;
use fuzztest::domains::Domain;
use fuzztest::fuzztest;
use rand::RngExt;

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

    fn init(&self, rng: &mut dyn rand::Rng) -> anyhow::Result<Self::CorpusValue> {
        let mut val = vec![0u8; rng.random_range(0..100)];
        rng.fill(&mut val[..]);
        Ok(val)
    }

    fn mutate(
        &self,
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
}

#[fuzztest(a = ByteVectorDomain::new())]
fn find_bug_fuzz_test(a: Vec<u8>) {
    println!("PROPERTY_FUNCTION_EXECUTED");
    if !a.is_empty() && a[0] == 123 {
        panic!("Bug found!");
    }
}

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn untargeted_test_1(_a: i32) {
    println!("UNTARGETED_TEST_1_EXECUTED");
}

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn untargeted_test_2(_a: i32) {
    println!("UNTARGETED_TEST_2_EXECUTED");
}
