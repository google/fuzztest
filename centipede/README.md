
# Centipede - a distributed fuzzing engine. Work-in-progress.

**Important:** Centipede is merged into
[FuzzTest](https://github.com/google/fuzztest)
to consolidate fuzzing development - see documentation
[here](https://github.com/google/fuzztest/blob/main/centipede/USER_MIGRATION.md)
for user migration.

See also:
[Rich coverage signal and consequences for scaling (slides)](https://docs.google.com/presentation/d/16Zov-QmGZjGrEoTr6Qh2fyp-bvgOa4cmqxPrXw4fNeE/)

## Why Centipede

Why not? We are currently trying to fuzz some very large and very slow targets
for which [libFuzzer](https://llvm.org/docs/LibFuzzer.html),
[AFL](https://lcamtuf.coredump.cx/afl/), and the like do not necessarily scale
well. For one of our motivating examples
see [SiliFuzz](https://arxiv.org/abs/2110.11519). While working on Centipede we
plan to experiment with new approaches to massive-scale differential fuzzing,
that the existing fuzzing engines don't try to do.

Notable features:

* Out-of-the-box support for libFuzzer-based fuzz targets. In order to use your
  favourite `LLVMFuzzerTestOneInput()` you only need to build your target with
  Centipede's compiler and linker options.

* **Work-in-progress**. We test centipede within a small team on a couple
  of targets. Unless you are part of the Centipede project, or want to help us,
  **you probably don't want to read further just yet**.

* Scale. The intent is to be able to run any number of jobs concurrently, with
  very little communication overhead. We currently test with 100 local jobs and
  with 10k jobs on a cluster.

* Out of process. The target runs in a separate process. Any crashes in it will
  not affect the fuzzer. Centipede can be used in-process as well, but this mode
  is not the main goal. If your target is small and fast you probably still want
  libFuzzer.

* Integration with the sanitizers is achieved via separate builds. If during
  fuzzing you want to find bugs with
  [ASAN](https://github.com/google/sanitizers/wiki/AddressSanitizer),
  [MSAN](https://github.com/google/sanitizers/wiki/MemorySanitizer), or
  [TSAN](https://github.com/google/sanitizers/wiki/ThreadSanitizer), you will
  need to provide separate binaries for every sanitizer as well as one main
  binary for Centipede itself. The main binary should not use any of the
  sanitizers.

* No part of the internal interface is stable. Anything may change at this
  stage.

## Terminology

#### Fuzzing engine a.k.a. fuzzer <a id='fuzzer'></a>

A program that produces an infinite stream of inputs for a target and
orchestrates the execution.

#### Fuzz target <a id='target'></a>

A binary, a library, an API, or rather anything that can consume bytes for input
and produce some sort of coverage data as an output.
A [libFuzzer](https://llvm.org/docs/LibFuzzer.html)'s
target can be a Centipede's target. Read
more [here](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md).

#### Input <a id='input'></a>

A sequence of bytes that can be fed to a target. The input can be an arbitrary
bag of bytes, or some structured data, e.g. serialized proto.

#### Feature

A number that represents some unique behavior of the target. E.g. a feature
1234567 may represent the fact that a basic block number 987 in the target has
been executed 7 times. When executing an input with the target, the fuzzer
collects the features that were observed during execution.

#### Feature set

A set of features associated with one specific input.

#### Coverage

Some information about the behaviour of the target when it executes a given
input. Coverage is usually represented as feature set that the input has
triggered in the target.

#### Mutator

A function that takes bytes as input and outputs a small random mutation of the
input. See also:
[structure-aware fuzzing](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md).

#### Executor <a id='executor'></a>

A function that knows how to feed an input into a target and get coverage in
return (i.e. to **execute**).

#### Centipede

A customizable fuzzing engine that allows the user to substitute the Mutator and
the Executor.

#### Centipede runner <a id='runner'></a>

A library that implements the executor interface expected by the Centipede
fuzzer. The runner knows how to run
a [sancov](https://clang.llvm.org/docs/SanitizerCoverage.html)-instrumented
target, collect the resulting coverage, and pass it back to Centipede.
Prospective Centipede fuzz targets can be linked with this library to make them
runnable by Centipede.

#### Corpus (_plural: corpora_)

A set of inputs.

#### Distillation (creating a _distilled corpus_)

A process of choosing a subset of a larger corpus, such that the subset has the
same coverage features as the original corpus.

#### Shard

A file representing a subset of the corpus and another file representing feature
sets for that same subset of the corpus.

#### Merging shards

To merge shard B into shard A means: for every input in shard B that has
features missing in shard A, add that input to A.

#### Job

A single fuzzer process. One job writes only to one shard, but may read multiple
shards.

#### Workdir or WD

A local or remote directory that contains data produced or consumed by a fuzzer.

## Build Centipede

```shell
git clone https://github.com/google/fuzztest.git
cd fuzztest
CENTIPEDE_SRC=`pwd`/centipede
BIN_DIR=`pwd`/bazel-bin/centipede
bazel build -c opt centipede:all
```

What you will need for the subsequent steps:

* `$BIN_DIR/centipede` - the binary of the engine (the fuzzer).
* `$BIN_DIR/libcentipede_runner.pic.a` - the library you need to link with your
  fuzz target (the runner).
* `$CENTIPEDE_SRC/clang-flags.txt` - recommended clang compilation flags for the
  target.

You can keep these files where they are or copy them somewhere.

## Build your fuzz target

We provide two examples of building the target: one tiny single-file target and
libpng. Once you've built your target, proceed to the fuzz target running step.

### The simple example

This example uses one of the simple example fuzz targets, a.k.a. *puzzles*,
included in `$CENTIPEDE_SRC/puzzles` of the repo.

#### Compile

NOTE: The commands below use the flags from $CENTIPEDE_SRC/clang-flags.txt.
You may choose to use some other set of instrumentation flags:
clang-flags.txt only provides a simple default option.

```shell
FUZZ_TARGET=byte_cmp_4  # or any other source under $CENTIPEDE_SRC/puzzles
clang++ @$CENTIPEDE_SRC/clang-flags.txt -c $CENTIPEDE_SRC/puzzles/$FUZZ_TARGET.cc -o $BIN_DIR/$FUZZ_TARGET.o
```

#### Link

This step links the just-built fuzz target with libcentipede_runner.pic.a and
other required libraries.

```shell
clang++ $BIN_DIR/$FUZZ_TARGET.o $BIN_DIR/libcentipede_runner.pic.a \
    -ldl -lrt -lpthread -o $BIN_DIR/$FUZZ_TARGET
```

Skip to the fuzz target running step.

### The libpng example

#### Download and compile libpng

```shell

LIBPNG_BRANCH=v1.6.37  # You can experiment with other branches if you'd like
git clone --branch $LIBPNG_BRANCH --single-branch https://github.com/glennrp/libpng.git
cd libpng
CC=clang CFLAGS=@$CENTIPEDE_SRC/clang-flags.txt ./configure --disable-shared
make -j
```

#### Link libpng's own fuzz target with libcentipede_runner.pic.a

```shell
FUZZ_TARGET=libpng_read_fuzzer
clang++ -include cstdlib \
    ./contrib/oss-fuzz/$FUZZ_TARGET.cc \
    ./.libs/libpng16.a \
    $BIN_DIR/libcentipede_runner.pic.a \
    -ldl -lrt -lpthread -lz \
    -o $BIN_DIR/$FUZZ_TARGET
```

## Run Centipede locally <a id='run-step'></a>

Running locally will not give the full scale, but it could be useful during the
fuzzer development stage. We recommend that both the fuzzer and the target are
copied to a local directory before running in order to avoid stressing a network
file system.

### Prepare for a run

```shell
WD=$HOME/centipede_run
mkdir -p $WD
```

NOTE: You may need to add
[`llvm-symbolizer`](https://llvm.org/docs/CommandGuide/llvm-symbolizer.html)
to your `$PATH` for some of the Centipede functionality to work. The
symbolizer can be installed as part of the [LLVM](https://releases.llvm.org)
distribution:

```shell
sudo apt install llvm
which llvm-symbolizer  # normally /usr/bin/llvm-symbolizer
```

### Run one fuzzing job

```shell
rm -rf $WD/*
$BIN_DIR/centipede --binary=$BIN_DIR/$FUZZ_TARGET --workdir=$WD --num_runs=100
```

See what's in the working directory

```shell
tree $WD
```

```
...
├── <fuzz target name>-d9d90139ee2ccc687f7c9d5821bcc04b8a847df5
│   └── features.000000
└── corpus.000000
```

### Run 5 concurrent fuzzing jobs

WARNING: Do not exceed the number of cores on your machine for the `--j` flag.

```shell
rm -rf $WD/*
$BIN_DIR/centipede --binary=$BIN_DIR/$FUZZ_TARGET --workdir=$WD --num_runs=100 --j=5
```

See what's in the working directory:

```shell
tree $WD
```

```
...
├── <fuzz target name>-d9d90139ee2ccc687f7c9d5821bcc04b8a847df5
│   ├── features.000000
│   ├── features.000001
│   ├── features.000002
│   ├── features.000003
│   └── features.000004
├── corpus.000000
├── corpus.000001
├── corpus.000002
├── corpus.000003
└── corpus.000004
```

## Corpus distillation

Each Centipede shard typically does not cover all features that the entire
corpus covers. Besides, all shards combined will have plenty of redundancy. In
order to distill the corpus, a Centipede process will need to read all shards.
Distillation works like this:

First, run fuzzing as described above, so that all shards have their feature
sets computed. Stop fuzzing.

Then, run the same command line, but with `--distill --total_shards=N
--num_threads=K`. This will read `N` corpus shards and produce `K` independent
distilled corpus files and `K` corresponding feature files. Each of the
distilled corpora should have the same features as the `N` shards combined, but
the inputs might be different between the `K` distilled corpora. In most cases
`K==1` is sufficient, i.e. you simply omit `--num_threads=K`.

The `--distill` flag requires that you pass the `--binary` or
`--coverage_binary` so that it knows where to look for the `features` files, but
it will not execute the binary. By default, when you pass `--binary` or
`--coverage_binary`, Centipede computes a hash of the binary file. If the binary
is not present on disk, you need to additionally pass `--binary_hash=<HASH>` and
then you only need to pass the base name of the binary. E.g. if you fuzzed with
`--binary=/path/to/foo`, and `/path/to/foo` is not present on disk during
distillation, you can still pass `--binary=/path/to/foo --binary_hash=<HASH>`,
but you can also pass `--binary=foo --binary_hash=<HASH>` or
`--binary=/invalid/path/foo --binary_hash=<HASH>`.

Unlike fuzzing, the distillation step is not distributed and needs to run on a
single machine. The distillation is a much lighter-weight process than fuzzing
because it does not require executing the target, and thus it doesn't need to be
distributed. Distillation is however IO-bound.

```shell
$BIN_DIR/centipede --binary=$FUZZ_TARGET --workdir=$WD \
  --binary_hash=a5e87c9b6057e5ffd3b32a5b9a9ef3978527e9cd --distill \
  --total_shards=5 --num_threads=3
```

Note: `--binary=$FUZZ_TARGET` in this example does not point to a real file and
so we also pass `--binary_hash=<HASH>`.

The result of this command is that `$WD` will now contain 3 distilled versions
of the corpus, while the features subdirectory, `$WD/<fuzz target name>-<fuzz
target hash>`, will contain 3 distilled versions of the features:

```shell
tree $WD
```

```
...
├── <fuzz target name>-d9d90139ee2ccc687f7c9d5821bcc04b8a847df5
│   ├── distilled-features-byte_cmp_4.000000
│   ├── distilled-features-byte_cmp_4.000001
│   ├── distilled-features-byte_cmp_4.000002
│   ├── features.000000
│   ...
├── corpus.000000
│   ...
├── distilled-byte_cmp_4.000000
├── distilled-byte_cmp_4.000001
├── distilled-byte_cmp_4.000002

```

## Coverage Reports

Centipede provides two ways to write coverage reports: a simple text-based
report and a human-readable HTML report. It is important to note that the HTML
report requires additional setup and may impact performance.

### Simple Text Coverage Report

The simple text coverage report is generated by default and is available as soon
as Centipede begins fuzzing. It is saved as a text file in the `workdir`
directory with the name `coverage-report-BINARY.SHARD.txt` where `BINARY` is
the name of the target and `SHARD` is the shard number. The report reflects
the coverage as observed by the shard after loading the corpus.

The report shows functions that are fully covered (all control flow edges are
observed at least once), not covered, or partially covered. For partially
covered functions the report contains symbolic information for all covered and
uncovered edges.

The report will look something like this:

```
FULL: FUNCTION_A a.cc:1:0
NONE: FUNCTION_BB bb.cc:1:0
PARTIAL: FUNCTION_CCC ccc.cc:1:0
+ FUNCTION_CCC ccc.cc:1:0
- FUNCTION_CCC ccc.cc:2:0
- FUNCTION_CCC ccc.cc:3:0
```

### HTML Coverage Report

Centipede also provides the option to generate a human-readable HTML coverage
report by taking advantage of source level coverage instrumentation provided
by clang. The HTML report provides a more interactive way to analyze code
coverage by providing a browsable view of the instrumented source tree with hit
counts for lines of code. Source-level information from the compiler is used to
track coverage, so it can be more precise than the text-based output.

The existing fuzz target used with Centipede contains instrumentation that is
helpful for fuzzing, but lacks some detail needed for the HTML coverage report.
In order to include this information in the binary, you need to build an
additional binary for your fuzz target with this source-level coverage
instrumentation. You can build this additional fuzz target with options
`-fprofile-instr-generate -fcoverage-mapping`. Ensure `llvm-cov` and
`llvm-profdata` are available in your `$PATH`, then pass your original fuzz
target binary with `--binary` and pass this new binary using
`--clang_coverage_binary`. A full command line invocation might look like this:

```shell
$BIN_DIR/centipede --binary=$BIN_DIR/$FUZZ_TARGET --workdir=$WD --clang_coverage_binary=$BIN_DIR/$FUZZ_TARGET_CLANG_COVERAGE
```

Report generation assumes that your current working directory is the root of
the source files for your built binary. Otherwise, you may encounter a
`No such file or directory` error. We may add a flag to specify your source
directory in a future version of Centipede.

Note that generating the HTML report may impact performance since the additional
coverage binary must be run on new inputs to collect coverage. Currently, this
feature only works for local fuzz jobs. It does not merge coverage reports from
remote fuzzing instances.

For more information about clang's source-based coverage reports, please see
https://clang.llvm.org/docs/SourceBasedCodeCoverage.html.

## Customization

TBD

## Related Reading

* [Centipede Design](doc/DESIGN.md)
