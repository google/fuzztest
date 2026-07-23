use super::domains::GenericCorpusValue;
use super::domains::GenericDomain;
use std::collections::HashMap;
use std::sync::LazyLock;

/// A trait implemented by types used to Fuzz a given property function.
///
/// When a test is annotated with the `fuzztest` macro attribute, that test will be wrapped in a
/// FuzzTestObject that implements this trait. The FuzzTestObject is created by the macro and holds,
/// among others, the property function and the domains of its arguments.
/// The FuzzTestObject is then manipulated by Fuzzing Test Engine through the APIs of this trait.
pub trait FuzzTest {
    // TODO(tinmar): refine arguments as we get a clearer picture of
    // what the dispatcher interface looks like
    fn name(&self) -> &'static str;
    fn activate(&mut self);
    fn mutate(&mut self);
    /// Executes the property function with the given arguments
    /// (will attempt to downcast to actual user values).
    ///
    /// Returns `true` if the property function holds, `false` if it crashes.
    fn execute<'a>(&self, args: &'a GenericCorpusValue) -> bool;
    fn print_finding_report(&self);
    fn domains(&self) -> &dyn GenericDomain;
}

/// Identifies the property function of a fuzz test.
///
/// `FuzzTestInfo` is instantiated by the `fuzztest` macro which populates the fields with the
/// appropriate values.
pub struct FuzzTestInfo {
    pub name: &'static str,
    pub file: &'static str,
    pub line: u32,
}

pub type BoxedFuzzTest = Box<dyn FuzzTest + Send + Sync>;

pub struct FuzzTestRegistration {
    pub info: &'static FuzzTestInfo,
    pub factory: fn() -> BoxedFuzzTest,
}

inventory::collect!(FuzzTestRegistration);

pub static FUZZ_TEST_NAME_TO_FACTORY: LazyLock<HashMap<&str, fn() -> BoxedFuzzTest>> =
    LazyLock::new(|| {
        inventory::iter
            .into_iter()
            .map(|&FuzzTestRegistration { info, factory }| (info.name, factory))
            .collect()
    });

pub struct InputStateAndDomain<I, D> {
    pub input_state: Option<I>,
    pub domain: D,
}
