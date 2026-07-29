use fuzztest::domains::arbitrary::Arbitrary;
use fuzztest::fuzztest;

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn standalone_validation_test(_a: i32) {
    // Minimal test function to validate standalone mode.
    println!("STANDALONE_VALIDATION_WORKER_EXECUTED");
    println!("STANDALONE_VALIDATION_INPUT: {}", _a);
}

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn second_validation_test(_a: i32) {
    println!("SECOND_VALIDATION_TEST_EXECUTED");
    println!("SECOND_VALIDATION_INPUT: {}", _a);
}

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn jobs_test(_a: i32) {
    println!("JOBS_TEST_PID: {}", std::process::id());
    std::thread::sleep(std::time::Duration::from_millis(250));
}
