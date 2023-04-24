# Centipede User Migration

Centipede has been merged into FuzzTest to consolidate fuzzing development.

If your projects do not use Bazel other than building the Centipede binaries,
the build instructions have been updated in [README.md](./README.md).

If your projects integrate Centipede in Bazel workspaces, update your Centipede
references with the following steps:

1.  In the Bazel WORKSPACE files, remove the Centipede respository
    (https://github.com/google/centipede), and add the
    [FuzzTest](../doc/quickstart-bazel.md#set-up-a-bazel-workspace) repository
    and any missing dependencies instead.

2.  In the Bazel BUILD/bzl files, replace any references of the Centipede
    repository `@centipede//` with the new package path
    `@com_google_fuzztest//centipede` in the FuzzTest repository. E.g.
    `@centipede//:centipede_runner` becomes
    `@com_google_fuzztest//centipede:centipede_runner`.
