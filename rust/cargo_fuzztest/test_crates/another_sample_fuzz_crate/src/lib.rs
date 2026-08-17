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

#[fuzztest(data = Arbitrary::<i32>::default())]
fn jobs_fuzztest_target(_data: i32) {
    println!("JOBS_TEST_PID: {}", std::process::id());
}

#[fuzztest(data = Arbitrary::<u8>::default())]
fn crashing_fuzztest_target(data: u8) {
    if data == 10 {
        panic!("Crashing bug found!");
    }
}
