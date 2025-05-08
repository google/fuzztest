#[test]
fn fuzztest() {
    let t = trybuild::TestCases::new();
    t.pass("tests/macro_compiles.rs");
}
