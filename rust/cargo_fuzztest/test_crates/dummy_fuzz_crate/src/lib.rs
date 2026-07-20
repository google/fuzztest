use fuzztest::domains::arbitrary::Arbitrary;
use fuzztest::fuzztest;

#[fuzztest(data = Arbitrary::<i32>::default())]
fn dummy_fuzztest_target(data: i32) {
    let _ = data;
}
