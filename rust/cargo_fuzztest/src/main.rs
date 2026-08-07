use cargo_fuzztest::FuzztestRunner;

fn main() -> anyhow::Result<()> {
    let host_triple = cargo_fuzztest::get_host_target_triple()?;
    let options = cargo_fuzztest::parse_cli_options();

    let runner = FuzztestRunner::new(host_triple, options);
    let exit_code = runner.run()?;

    std::process::exit(exit_code);
}
