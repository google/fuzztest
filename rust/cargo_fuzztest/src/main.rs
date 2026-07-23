use cargo_fuzztest::FuzztestRunner;

fn main() -> anyhow::Result<()> {
    let host_triple = cargo_fuzztest::get_host_target_triple()?;

    let runner = FuzztestRunner::new(host_triple);
    let exit_code = runner.run()?;

    std::process::exit(exit_code);
}
