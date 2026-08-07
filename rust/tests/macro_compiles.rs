use fuzztest::domains::arbitrary::Arbitrary;
use fuzztest::fuzztest;

#[fuzztest(_a = Arbitrary::<i32>::default())]
fn fuzztest_macro_compiles(_a: i32) {}

#[fuzztest(_a = Arbitrary::<i32>::default(), _b = Arbitrary::<i32>::default())]
fn fuzztest_macro_compiles_with_two_args(_a: i32, _b: i32) {}

fn main() {}
