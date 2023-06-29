
[TOC]

# Centipede Design

We are trying to build Centipede based on our experience with libFuzzer (and to
a lesser extent with AFL and others). We keep what worked well, and change what didn't.

See [README](../README.md) for user documentation and most of the terminology.

## Execution Features

Centipede reasons about the execution feedback in terms of *features*. A feature
is some unique behavior of the target exercised by a given input. So, executing
an input is a way to compute the input's features.

The currently supported features (see [feature.h](../feature.h) for details)
are:

* Control flow edges with
  [8-bit counters](https://clang.llvm.org/docs/SanitizerCoverage.html#inline-8bit-counters)
  .
* Simplified data flow edges: either {store-PC, load-PC} or {global-address,
  load-PC}.
* Bounded control flow paths.
* Instrumented CMP instructions.
* ... more coming.

However, the target may generate features of its own type without Centipede
having to support it explicitly.

## Persistent state

Centipede aims to handle both large and slow targets, so even a minimized corpus
may consist of 100K-1M inputs and executing every input can take 1ms-1s. We
also aim to support many more feature types than most other engines, which will
in turn bloat the corpus further.

At the same time, we aim to execute on cheap ("preemptible") cloud VMs, so
we need to minimize the startup computations.

Therefore, we try hard to eliminate all redundant executions.

Centipede state consists of the following:

* Corpus. A set of inputs. The corpus is a property of a group of fuzz targets
  sharing the same input data format.
* Feature sets. For every corpus element we preserve the set of its features.
  Features are a property of a specific target binary. Different binaries (e.g.
  from a different revision, or different build options, or from different
  code) will have their own persistent feature set. A feature set is associated
  with an input via the input's hash.

On startup, Centipede loads the corpus, and checks which corpus elements have
their corresponding feature sets. Only when the feature set is not present for
an input in the corpus, Centipede will recompute it.

## Concurrent execution

Centipede jobs run concurrently (in separate processes, potentially on different
machines). They peek at each other's corpus (and feature sets) periodically.
Every job writes only to its own persistent state, but can read any other job's
state concurrently with that job writing to it.

Centipede implements this via appendable storage format.

## Storage format

Very simple and inefficient home-brewed appendable data format is currently
used, see `PackBytesForAppendFile()` in [util.h](../util.h). We may need to
replace it with something more efficient when this one stops scaling.

## Out-of-process target execution

Centipede executes the target out of process. In order to minimize the process
startup costs, it passes inputs to the target in batches, and receives features
in batches as well.

The specific mechanism of execution and passing the data between processes can
be overridden. The default implementation is `CentipedeCallbacks::Execute()` in
[centipede_interface.h](../centipede_interface.h).

It is possible to override the execution to do it in-process, but this way
Centipede will lose the ability to set RAM and time limit, and it will not
tolerate crashes in the target.

## Instrumentation

Centipede is decoupled from the mechanism that collects the execution feedback.
Any source of feedback can be used: compiler instrumentation, run-time
instrumentation, simulation, hardware-based tracing, etc. The default
implementation in [runner_main.cc](../runner_main.cc) and other `runner_*.cc`
files
relies on
[SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html)

## Mutations

Centipede is decoupled from Mutations - they are provided by the user via
`CentipedeCallbacks::Mutate()`.

Centipede provides a default implementation of mutations via `ByteArrayMutator`.

## Corpus management

One of the important heuristics during fuzzing is which corpus elements to
mutate, and which to discard.

Centipede tries to mutate only those corpus elements that have *rare* features.

TODO(kcc): explain how this works.

## Related reading

Centipede currently doesn't do all of the following, but aspires to eventually
do much more.

* [Entropic] Boosting fuzzer efficiency: an information theoretic perspective.
  https://dl.acm.org/doi/abs/10.1145/3368089.3409748
* [Nezha]: Efficient Domain-Independent Differential Testing
  https://www.cs.columbia.edu/~suman/docs/nezha.pdf
