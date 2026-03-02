// Copyright 2025 Google LLC
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

#include "./fuzztest/internal/register_fuzzing_mocks.h"

#include <cmath>
#include <cstdint>
#include <limits>
#include <tuple>
#include <type_traits>

#include "absl/base/fast_type_id.h"
#include "absl/functional/function_ref.h"
#include "absl/random/bernoulli_distribution.h"
#include "absl/random/beta_distribution.h"
#include "absl/random/distributions.h"
#include "absl/random/exponential_distribution.h"
#include "absl/random/gaussian_distribution.h"
#include "absl/random/log_uniform_int_distribution.h"
#include "absl/random/poisson_distribution.h"
#include "absl/random/zipf_distribution.h"

namespace fuzztest::internal {
namespace {

enum class Instruction : uint8_t {
  kDataStreamVariate = 0,
  kLCGVariate = 1,
  kMin = 2,
  kMax = 3,
  kMean = 4,
  kAlternateVariate = 5,
};

class ImplURBG {
 public:
  DataStreamFn data_stream_fn_;
  uint8_t control_byte_;

  Instruction instruction() {
    return static_cast<Instruction>(control_byte_ % 6);
  }

  template <typename T>
  T get_int_value() {
    T x = 0;
    data_stream_fn_(&x, sizeof(x));
    return x;
  }

  template <typename T>
  T get_int_value_in_range(uint64_t range) {
    // Consume fewer bytes of the data_stream when dealing with a power
    // of 2 range.
    if (range == 0) {
      return 0;
    }
    uint64_t x = 0;
    if (range <= (std::numeric_limits<uint8_t>::max)()) {
      x = get_int_value<uint8_t>();
    } else if (range <= (std::numeric_limits<uint16_t>::max)()) {
      x = get_int_value<uint16_t>();
    } else if (range <= (std::numeric_limits<uint32_t>::max)()) {
      x = get_int_value<uint32_t>();
    } else {
      x = get_int_value<uint64_t>();
    }
    if ((range & (range + 1)) == 0) {
      return static_cast<T>(x & range);  // power of 2 range
    } else {
      return static_cast<T>(x % (range + 1));
    }
  }

  // URBG interface.
  using result_type = uint64_t;

  static constexpr result_type(min)() {
    return (std::numeric_limits<result_type>::min)();
  }
  static constexpr result_type(max)() {
    return (std::numeric_limits<result_type>::max)();
  }

  void reset() {}

  uint64_t operator()() { return get_int_value<uint64_t>(); }
};

// -----------------------------------------------------------------------------

// Bernoulli
struct ImplBernoulli {
  ImplURBG urbg;

  using DistrT = absl::bernoulli_distribution;
  using ArgTupleT = std::tuple<double>;
  using ResultT = bool;

  ResultT operator()(double p) {
    // Just generate a boolean; mostly ignoring p.
    // The 0/1 cases are special cased to avoid returning false on constants.
    if (p <= 0.0) {
      return false;
    } else if (p >= 1.0) {
      return true;
    }
    switch (urbg.instruction()) {
      case Instruction::kMin:
        return false;
      case Instruction::kMax:
        return true;
      case Instruction::kMean:
        return p >= 0.5;
      default:
        break;
    }
    return urbg.get_int_value<uint8_t>() & 1;
  }
};

// Beta
template <typename RealType>
struct ImplBeta {
  ImplURBG urbg;

  using DistrT = absl::beta_distribution<RealType>;
  using ArgTupleT = std::tuple<RealType, RealType>;
  using ResultT = RealType;

  ResultT operator()(RealType a, RealType b) {
    switch (urbg.instruction()) {
      case Instruction::kMin:
        return 0.0;
      case Instruction::kMax:
        return 1.0;
      case Instruction::kMean:
        return a / (a + b);  // mean
      default:
        break;
    }
    return DistrT(a, b)(urbg);
  }
};

// Exponential
template <typename RealType>
struct ImplExponential {
  ImplURBG urbg;

  using DistrT = absl::exponential_distribution<RealType>;
  using ArgTupleT = std::tuple<RealType>;
  using ResultT = RealType;

  ResultT operator()(RealType lambda) {
    switch (urbg.instruction()) {
      case Instruction::kMin:
        return 0;
      case Instruction::kMean:
        return RealType{1} / lambda;  // mean
      case Instruction::kMax:
        return (std::numeric_limits<RealType>::max)();
      case Instruction::kAlternateVariate:
        return absl::uniform_real_distribution<RealType>(
            0, (std::numeric_limits<RealType>::max)())(urbg);
      default:
        break;
    }
    return DistrT(lambda)(urbg);
  }
};

// Gaussian
template <typename RealType>
struct ImplGaussian {
  ImplURBG urbg;

  using DistrT = absl::gaussian_distribution<RealType>;
  using ArgTupleT = std::tuple<RealType, RealType>;
  using ResultT = RealType;

  ResultT operator()(RealType mean, RealType sigma) {
    const auto ten_sigma = sigma * 10;
    switch (urbg.instruction()) {
      // Technically the min/max are -inf/+inf.
      case Instruction::kMin:
        return -(std::numeric_limits<RealType>::max)();
      case Instruction::kMax:
        return (std::numeric_limits<RealType>::max)();
      case Instruction::kMean:
        return mean;
      case Instruction::kAlternateVariate:
        // this makes unlikely values much more likely.
        return absl::uniform_real_distribution<RealType>(
            mean - ten_sigma, mean + ten_sigma)(urbg);
      default:
        break;
    }
    return DistrT(mean, sigma)(urbg);
  }
};

// LogUniform
template <typename IntType>
struct ImplLogUniform {
  ImplURBG urbg;

  using DistrT = absl::log_uniform_int_distribution<IntType>;
  using ArgTupleT = std::tuple<IntType, IntType, IntType>;
  using ResultT = IntType;

  ResultT operator()(IntType a, IntType b, IntType base) {
    switch (urbg.instruction()) {
      case Instruction::kMin:
        return a;
      case Instruction::kMax:
        return b;
      case Instruction::kMean:
        if (a > 0 && b > a) {
          double log_b_over_a = std::log(static_cast<double>(b) / a);
          return static_cast<IntType>(static_cast<double>(b - a) /
                                      log_b_over_a);
        }
        break;
      case Instruction::kAlternateVariate:
        return urbg.get_int_value_in_range<IntType>(b - a) + a;
      default:
        break;
    }
    return DistrT(a, b, base)(urbg);
  }
};

// Poisson
template <typename IntType>
struct ImplPoisson {
  ImplURBG urbg;

  using DistrT = absl::poisson_distribution<IntType>;
  using ArgTupleT = std::tuple<double>;
  using ResultT = IntType;

  ResultT operator()(double lambda) {
    switch (urbg.instruction()) {
      case Instruction::kMin:
        return 0;
      case Instruction::kMax:
        return (std::numeric_limits<IntType>::max)();
      case Instruction::kMean:
        return static_cast<IntType>(lambda);
      case Instruction::kAlternateVariate:
        return urbg.get_int_value_in_range<IntType>(
            (std::numeric_limits<IntType>::max)());
      default:
        break;
    }
    return DistrT(lambda)(urbg);
  }
};

// Zipf
template <typename IntType>
struct ImplZipf {
  ImplURBG urbg;

  using DistrT = absl::zipf_distribution<IntType>;
  using ArgTupleT = std::tuple<IntType, double, double>;
  using ResultT = IntType;

  ResultT operator()(IntType k, double q, double v) {
    switch (urbg.instruction()) {
      case Instruction::kMin:
        return 0;
      case Instruction::kMax:
        return k;
      case Instruction::kAlternateVariate:
        return urbg.get_int_value_in_range<IntType>(k);
      default:
        break;
    }
    return DistrT(k, q, v)(urbg);
  }
};

// Uniform
template <typename R>
struct ImplUniform {
  ImplURBG urbg;
  using DistrT = absl::random_internal::UniformDistributionWrapper<R>;
  using ResultT = R;

  ResultT operator()(absl::IntervalClosedClosedTag, R min, R max) {
    if constexpr (std::is_floating_point_v<R>) {
      return operator()(absl::IntervalClosedOpen, min,
                        std::nexttoward(max, (std::numeric_limits<R>::max)()));
    }
    // Only int-typed calls should reach here.
    if constexpr (std::is_integral_v<R>) {
      switch (urbg.instruction()) {
        case Instruction::kMin:
          return min;
        case Instruction::kMax:
          return max;
        case Instruction::kMean:
          return min + ((max - min) / 2);
        default:
          break;
      }
      if constexpr (sizeof(R) <= sizeof(uint8_t)) {
        return min + urbg.get_int_value_in_range<R>(static_cast<uint64_t>(max) -
                                                    static_cast<uint64_t>(min));
      }
      // Fallback to absl::uniform_int_distribution.
      return absl::uniform_int_distribution<R>(min, max)(urbg);
    } else {
      return 0;
    }
  }

  ResultT operator()(absl::IntervalClosedOpenTag, R min, R max) {
    if constexpr (std::is_integral_v<R>) {
      return operator()(absl::IntervalClosedClosed, min, max - 1);
    }
    // Only real-typed calls should reach here.
    if constexpr (std::is_floating_point_v<R>) {
      switch (urbg.instruction()) {
        case Instruction::kMin:
          return min;
        case Instruction::kMax:
          return std::nexttoward(max, std::numeric_limits<R>::min());
        case Instruction::kMean:
          return min + ((max - min) / 2);
        default:
          break;
      }
      return absl::uniform_real_distribution<R>(min, max)(urbg);
    } else {
      return 0;
    }
  }

  ResultT operator()(absl::IntervalOpenOpenTag, R min, R max) {
    if constexpr (std::is_floating_point_v<R>) {
      return operator()(absl::IntervalClosedOpen, std::nexttoward(min, max),
                        max);
    } else {
      return operator()(absl::IntervalClosedOpen, min + 1, max);
    }
  }

  ResultT operator()(absl::IntervalOpenClosedTag, R min, R max) {
    if constexpr (std::is_floating_point_v<R>) {
      return operator()(absl::IntervalClosedClosed, std::nexttoward(min, max),
                        max);
    } else {
      return operator()(absl::IntervalClosedClosed, min + 1, max);
    }
  }

  ResultT operator()(R min, R max) {
    return operator()(absl::IntervalClosedOpen, min, max);
  }

  ResultT operator()() {
    static_assert(std::is_unsigned_v<R>);
    return operator()(absl::IntervalClosedClosed, 0,
                      (std::numeric_limits<R>::max)());
  }
};

// -----------------------------------------------------------------------------

// InvokeFuzzFunction is a type-erased function pointer which is responsible
// for casting the args_tuple and result parameters to the correct types and
// then invoking the implementation functor. It is important that the
// ArgsTupleT and ResultT types match the types of the distribution and the
// implementation functions, so the HandleFuzzedFunction overloads are used to
// determine the correct types.
template <typename FuzzFunctionT, typename ResultT, typename ArgTupleT>
void InvokeFuzzFunction(DataStreamFn data_stream_fn, uint8_t control_byte,
                        void* args_tuple, void* result) {
  FuzzFunctionT fn{ImplURBG{data_stream_fn, control_byte}};
  *static_cast<ResultT*>(result) =
      absl::apply(fn, *static_cast<ArgTupleT*>(args_tuple));
}

template <typename FuzzFunctionT>
void HandleFuzzedFunctionX(
    absl::FunctionRef<void(absl::FastTypeIdType, TypeErasedFuzzFunctionT)>
        register_fn) {
  using DistrT = typename FuzzFunctionT::DistrT;
  using ArgTupleT = typename FuzzFunctionT::ArgTupleT;
  using ResultT = typename FuzzFunctionT::ResultT;
  using KeyT = ResultT(DistrT, ArgTupleT);

  register_fn(absl::FastTypeId<KeyT>(),
              &InvokeFuzzFunction<FuzzFunctionT, ResultT, ArgTupleT>);
}

template <typename FuzzFunctionT, typename... Args>
void HandleFuzzedFunctionU(
    absl::FunctionRef<void(absl::FastTypeIdType, TypeErasedFuzzFunctionT)>
        register_fn) {
  using DistrT = typename FuzzFunctionT::DistrT;
  using ArgTupleT = std::tuple<std::decay_t<Args>...>;
  using ResultT = typename FuzzFunctionT::ResultT;
  using KeyT = ResultT(DistrT, ArgTupleT);

  register_fn(absl::FastTypeId<KeyT>(),
              &InvokeFuzzFunction<FuzzFunctionT, ResultT, ArgTupleT>);
}

// -----------------------------------------------------------------------------
// X_ macros to invoke X_IMPL_T macros for each type.
// -----------------------------------------------------------------------------

#define X_SINT(Impl)                                  \
  if constexpr (std::is_signed_v<char> &&             \
                !std::is_same_v<char, signed char>) { \
    X_IMPL_T(char, Impl);                             \
  }                                                   \
  X_IMPL_T(signed char, Impl);                        \
  X_IMPL_T(short, Impl);     /*NOLINT*/               \
  X_IMPL_T(long, Impl);      /*NOLINT*/               \
  X_IMPL_T(long long, Impl); /*NOLINT*/               \
  X_IMPL_T(int, Impl)

#define X_UINT(Impl)                                    \
  if constexpr (std::is_unsigned_v<char> &&             \
                !std::is_same_v<char, unsigned char>) { \
    X_IMPL_T(char, Impl);                               \
  }                                                     \
  X_IMPL_T(unsigned char, Impl);                        \
  X_IMPL_T(unsigned short, Impl);     /*NOLINT*/        \
  X_IMPL_T(unsigned long, Impl);      /*NOLINT*/        \
  X_IMPL_T(unsigned long long, Impl); /*NOLINT*/        \
  X_IMPL_T(unsigned int, Impl)

#define X_REAL(Impl)     \
  X_IMPL_T(float, Impl); \
  X_IMPL_T(double, Impl)

#define X_XINT(Impl) \
  X_SINT(Impl);      \
  X_UINT(Impl)

#define X_ALL(Impl) \
  X_SINT(Impl);     \
  X_UINT(Impl);     \
  X_REAL(Impl)

}  // namespace

// Registers the fuzzing functions into the fuzztest mock map.
void RegisterAbslRandomFuzzingMocks(
    absl::FunctionRef<void(absl::FastTypeIdType, TypeErasedFuzzFunctionT)>
        register_fn) {
#define X_IMPL_T(T, Impl) HandleFuzzedFunctionX<Impl<T>>(register_fn)

  HandleFuzzedFunctionX<ImplBernoulli>(register_fn);

  X_REAL(ImplBeta);
  X_REAL(ImplExponential);
  X_REAL(ImplGaussian);
  X_XINT(ImplLogUniform);
  X_XINT(ImplPoisson);
  X_XINT(ImplZipf);

#undef X_IMPL_T
#define X_IMPL_T(T, Impl)                                              \
  HandleFuzzedFunctionU<Impl<T>, absl::IntervalOpenOpenTag, T, T>(     \
      register_fn);                                                    \
  HandleFuzzedFunctionU<Impl<T>, absl::IntervalOpenClosedTag, T, T>(   \
      register_fn);                                                    \
  HandleFuzzedFunctionU<Impl<T>, absl::IntervalClosedOpenTag, T, T>(   \
      register_fn);                                                    \
  HandleFuzzedFunctionU<Impl<T>, absl::IntervalClosedClosedTag, T, T>( \
      register_fn);                                                    \
  HandleFuzzedFunctionU<Impl<T>, T, T>(register_fn)

  X_ALL(ImplUniform);

#undef X_IMPL_T
#define X_IMPL_T(T, Impl) HandleFuzzedFunctionU<Impl<T>>(register_fn)

  X_UINT(ImplUniform);

#undef X_IMPL_T
}

}  // namespace fuzztest::internal
