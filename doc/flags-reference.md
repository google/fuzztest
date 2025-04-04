# FuzzTest Flags Reference

You can run the FuzzTest binary in different modes/configurations by providing
the following flags.

| Purpose             | Flag                                  | Value          |
| :------------------ | :-----------------------------------: | -------------: |
| Run a fuzz test in  | `--fuzz=MySuite.MyTest`      | Fuzz test name |
: fuzzing mode        :                                       :                :
: indefinitely        :                                       :                :
| Run all fuzz tests  | `--fuzz_for=T`               | Duration       |
: in fuzzing mode for :                                       :                :
: `T` duration        :                                       :                :
| Limit memory usage  | `--rss_limit_mb=123`         | Mb             |
| Limit time          | `--time_limit_per_input=90s` | Duration       |
| Limit stack-trace   | `--stack_limit_kb=123`       | Kb             |
