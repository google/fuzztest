# FuzzTest Rust

A framework for fuzzing Rust projects using Google FuzzTest.

## Prerequisites

1.  Clone the repository.
2.  Build the C++ Centipede static library engine using Bazel (from the
    repository root):

    ```bash
    cd /path/to/fuzztest
    bazel build //centipede:centipede_engine_static
    ```
3. Copy the libcentipede_engine_static.a library to another location:

    ```bash
    mkdir -p $HOME/.local/lib
    cp /path/to/fuzztest/bazel-bin/centipede/libcentipede_engine_static.a \
        $HOME/.local/lib/
    ```

## Setup a Project

1.  Create a new Rust project:

    ```bash
    cargo new my_fuzz_project --bin
    ```

2.  Add `fuzztest` as a dependency in your `Cargo.toml`:

    ```toml
    [dependencies]
    fuzztest = { path = "/path/to/fuzztest/rust" }
    googletest = "0.14.3"
    ```

## Write a Fuzz Test

In `src/main.rs`:

```rust
#[cfg(test)]
mod tests {
    use fuzztest::domains::arbitrary::Arbitrary;
    use fuzztest::fuzztest;

    #[fuzztest(a = Arbitrary::<i32>::default(), b = Arbitrary::<i32>::default())]
    fn test_addition(a: i32, b: i32) {
        let _ = a.wrapping_add(b);
    }
}
```

## Build and Run Fuzz Tests

To run the fuzz tests, you must specify:

```bash
RUSTFLAGS="-L $HOME/.local/lib" cargo test __fuzztest_mod__::test_addition
```
