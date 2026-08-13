// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![deny(unused_imports)]
#![deny(clippy::absolute_paths)]

use cargo_fuzztest::FuzztestRunner;
use std::process;

fn main() -> anyhow::Result<()> {
    let host_triple = cargo_fuzztest::get_host_target_triple()?;
    let options = cargo_fuzztest::parse_cli_options();

    let runner = FuzztestRunner::new(host_triple, options);
    let exit_code = runner.run()?;

    process::exit(exit_code);
}
