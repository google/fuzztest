use fuzztest::domains::arbitrary::Arbitrary;
use fuzztest::fuzztest;

#[fuzztest(data = Arbitrary::<i32>::default())]
fn sample_fuzztest_target(data: i32) {
    let _ = data;
}

#[fuzztest(data = Arbitrary::<i32>::default())]
fn another_sample_fuzztest_target(data: i32) {
    let _ = data;
}
