# Steps to run the batch fuzz example:

## Build a customized Centipede

```shell
$ mkdir -p /tmp/CentipedeExample
$ blaze build -c opt //third_party/googlefuzztest/centipede/batch_fuzz_example:customized_centipede
$ cp -rf blaze-bin/third_party/googlefuzztest/centipede/batch_fuzz_example/customized_centipede /tmp/CentipedeExample/centipede
```

## Build a fuzz target instrumented with Centipede

```shell
$ blaze build --config=centipede -c opt //third_party/googlefuzztest/centipede/batch_fuzz_example:standalone_fuzz_target_main
$ cp -rf blaze-bin/third_party/googlefuzztest/centipede/batch_fuzz_example/standalone_fuzz_target_main /tmp/CentipedeExample/fuzz_target_main
```

## Run Centipede locally

```shell
$ export CENTIPEDE_RUNNER_FLAGS=":use_pc_features:exit_on_crash:"
$ rm -rf /tmp/CentipedeExample/WD/*
$ /tmp/CentipedeExample/centipede --workdir "/tmp/CentipedeExample/WD" --binary "/tmp/CentipedeExample/fuzz_target_main"
```
