use fuzztest::domains::arbitrary::Arbitrary;
use fuzztest::fuzztest;

#[fuzztest(data = Arbitrary::<i32>::default())]
fn dummy_fuzztest_target(data: i32) {
    let _ = data;
}

#[fuzztest(data = Arbitrary::<i32>::default())]
fn another_dummy_fuzztest_target(data: i32) {
    let _ = data;
}

#[fuzztest(data = Arbitrary::<i32>::default())]
fn jobs_fuzztest_target(_data: i32) {
    println!("JOBS_TEST_PID: {}", std::process::id());
}
