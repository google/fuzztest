use fuzztest::domains::arbitrary::Arbitrary;
use fuzztest::fuzztest;

#[fuzztest(a = Arbitrary::<i32>::default())]
fn find_bug_fuzz_test(a: i32) {
    println!("PROPERTY_FUNCTION_EXECUTED");
    if a == 10 || a == 20 || a == 30 {
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
