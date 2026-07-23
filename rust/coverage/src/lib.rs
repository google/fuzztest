mod coverage;

pub use coverage::SanCovRuntimeRawFeatureParts;

pub fn prepare_coverage(full_clear: bool) {
    coverage::SanCovRuntimeClearCoverage(full_clear)
}

pub fn get_coverage(reject_input: bool) -> SanCovRuntimeRawFeatureParts {
    coverage::SanCovRuntimeGetCoverage(reject_input)
}

pub fn post_process_coverage(reject_input: bool) {
    coverage::SanCovRuntimePostProcessCoverage(reject_input)
}
