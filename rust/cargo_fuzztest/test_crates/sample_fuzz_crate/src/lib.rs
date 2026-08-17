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

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn jobs_test(_a: i32) {
    println!("JOBS_TEST_PID: {}", std::process::id());
    std::thread::sleep(std::time::Duration::from_millis(250));
}
