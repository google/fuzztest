use fuzztest::domains::arbitrary::Arbitrary;
use fuzztest::fuzztest;

#[fuzztest(a = Arbitrary::<i32>::default())]
fn find_bug_fuzz_test(a: i32) {
    println!("PROPERTY_FUNCTION_EXECUTED");
    if a == 10 || a == 20 || a == 30 {
        panic!("Bug found!");
    }
}

#[fuzztest(a = Arbitrary::<i32>::default())]
fn find_two_bugs_fuzz_test(a: i32) {
    println!("PROPERTY_FUNCTION_EXECUTED");
    if a < -1 {
        panic!("Bug 1 found!");
    } else if a > 1 {
        println!("Bug 2 found!");
        // Safety: We are intentionally causing a segfault to test that the engine would catch it.
        unsafe {
            std::ptr::null_mut::<i32>().write_volatile(42);
        }
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
