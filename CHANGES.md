# Issue with Private RE2 Headers in FuzzTest

## Problem

The FuzzTest library uses **RE2** for regular expressions.  
In FuzzTest, the module `regexp_dfa.cc` directly includes **private RE2 headers**:

```cpp
#include "re2/prog.h"
```

These headers are not exported when RE2 is installed via CMake (make install) or from system packages.
As a result:
- Building with system RE2 (-DFUZZTEST_USE_SYSTEM_RE2=ON) fails:

```angular2html
fatal error: 're2/prog.h' file not found
```
- The problem occurs only for regexp_dfa and modules depending on it.

RE2 separates headers into:
Public headers (re2/re2.h, re2/set.h, re2/filtered_re2.h) — available after install and in system packages.
Private headers (re2/prog.h, etc.) — only present in source tree, not exported via CMake install.
FuzzTest directly uses private headers, making system RE2 incompatible without build modifications.

## Solution

- Conditionally build:
```angular2html
option(FUZZTEST_BUILD_REGEXP_DFA "Build regexp_dfa (needs private RE2 headers)" ON)
```

- Disable regexp_dfa when using external RE2:
```angular2html
if(FUZZTEST_USE_SYSTEM_RE2)
...
  set(FUZZTEST_BUILD_REGEXP_DFA OFF CACHE BOOL "" FORCE)
...
```

- Conditional dependencies added to libraries that depend on regexp_dfa:
```angular2html
if(FUZZTEST_BUILD_REGEXP_DFA)
  set(EXTRA_REGEXP_DFA_DEPS fuzztest::regexp_dfa)
else()
  set(EXTRA_REGEXP_DFA_DEPS "")
endif()
```

With that:
1. With system RE2, regexp_dfa is skipped; FuzzTest builds successfully.
2. With FetchContent(RE2) (source), private headers are available; regexp_dfa is built.

## Outcome

Eliminated the fatal error: ```'re2/prog.h' file not found ``` issue when using system RE2.
FuzzTest builds correctly in both scenarios:
1. System RE2 without private headers
2. RE2 from source with private headers

Trying rewriting the regexp_dfa via using only public set/re2 API is impossible - there simply are no such tools (I tried).
