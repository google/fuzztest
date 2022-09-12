// Copyright 2022 Google LLC
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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_POLYMORPHIC_VALUE_H_
#define FUZZTEST_FUZZTEST_INTERNAL_POLYMORPHIC_VALUE_H_

#include <cstddef>
#include <tuple>
#include <type_traits>
#include <utility>

#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"

namespace fuzztest::internal {

// Trivially copyable/destructible class that handles type erasure for a value.
// It does not own the input value. That is, it will not manage the lifetime of
// the object or implement deep copies.
// It is a building block for other abstractions.
template <typename... Visitor>
class VisitableValue {
 public:
  VisitableValue() : vtable_(nullptr), value_(nullptr) {}

  template <typename T>
  explicit VisitableValue(std::in_place_t, T* value) {
    vtable_ = &VTableFor<T>;
    value_ = value;
  }

  bool has_value() const { return vtable_ != nullptr; }

  template <typename T>
  bool Has() const {
    return vtable_->type_id == type_id<T>;
  }

  template <typename T>
  T& GetAs() {
    FUZZTEST_INTERNAL_CHECK(Has<T>(), "Wrong type!");
    return *static_cast<T*>(value_);
  }

  template <typename T>
  const T& GetAs() const {
    FUZZTEST_INTERNAL_CHECK(Has<T>(), "Wrong type!");
    return *static_cast<T*>(value_);
  }

  template <typename V, typename... Args,
            typename = std::enable_if_t<always_true<V> &&
                                        (std::is_same_v<V, Visitor> || ...)>>
  auto Visit(V visitor, Args&&... args) {
    return std::get<GetVisitIndex<V>()>(vtable_->visitors)(
        visitor, value_, std::forward<Args>(args)...);
  }

  template <typename V, typename... Args,
            typename = std::enable_if_t<always_true<V> &&
                                        (std::is_same_v<V, Visitor> || ...)>>
  auto Visit(V visitor, Args&&... args) const {
    return std::get<GetVisitIndex<V>()>(vtable_->visitors)(
        visitor, static_cast<const void*>(value_), std::forward<Args>(args)...);
  }

 private:
  template <typename T, typename R, typename V, typename... Args>
  static R DispatchImpl(
      V v, std::conditional_t<std::is_const_v<T>, const void, void>* p,
      Args... args) {
    return v(*static_cast<T*>(p), std::forward<Args>(args)...);
  }
  template <typename T, typename R, typename V, typename... Args>
  static constexpr auto GetDispatchImpl(R (V::*)(T&, Args...))
      -> decltype(&DispatchImpl<T, R, V, Args...>) {
    return DispatchImpl<T, R, V, Args...>;
  }

  template <typename T, typename V>
  static constexpr auto GetDispatch()
      -> decltype(GetDispatchImpl(&V::template operator()<T>)) {
    return GetDispatchImpl(&V::template operator()<T>);
  }

  template <typename V>
  using VisitImpl = decltype(GetDispatch<int, V>());

  struct VTable {
    TypeId type_id;
    std::tuple<VisitImpl<Visitor>...> visitors;
  };

  template <typename T>
  static constexpr VTable VTableFor = {type_id<T>,
                                       {GetDispatch<T, Visitor>()...}};

  template <typename V, size_t i = 0>
  static constexpr auto GetVisitIndex() {
    if constexpr (std::is_same_v<
                      VisitImpl<V>,
                      std::tuple_element_t<i, decltype(VTable::visitors)>>) {
      return i;
    } else {
      return GetVisitIndex<V, i + 1>();
    }
  }

  const VTable* vtable_;
  void* value_;
};

struct DestroyVisitor {
  template <typename T>
  void operator()(T& v) {
    delete &v;
  }
};

template <typename P>
struct CopyVisitor {
  template <typename T>
  P operator()(const T& v) {
    return P(std::in_place, v);
  }
};

// A class similar to std::any with the following differences:
//  - You declare which operations can be applied on the object via Visitors.
//  - To access the object you use Has<T>()/GetAs<T>() instead of any_cast.
//
// A visitor is a callable object with a signature like:
//   template <typename T>
//   R operator()(T&, Args...)
//
// Visitors allow accessing the type erased value in a generic manner.
// PolymorphicValue will provide the dynamic dispatch necessary for all the
// visitors to work.
//
// Eg:
// struct PrintVisitor {
//   template <typename T>
//   void operator()(const T& v) {
//     std::cout << v;
//   }
// };
// PolymorphicValue<PrintVisitor> v;
// v = 1;
// v.Visit(PrintVisitor{});  // Prints "1"
// v = 1.5;
// v.Visit(PrintVisitor{});  // Prints "1.5"
// v = "ABC";
// v.Visit(PrintVisitor{});  // Prints "ABC"
template <typename... Visitor>
class PolymorphicValue
    : private VisitableValue<DestroyVisitor,
                             CopyVisitor<PolymorphicValue<Visitor...>>,
                             Visitor...> {
  using Base =
      VisitableValue<DestroyVisitor, CopyVisitor<PolymorphicValue>, Visitor...>;

 public:
  PolymorphicValue() {}

  template <typename T>
  explicit PolymorphicValue(std::in_place_t, T value)
      : Base(std::in_place, new T(std::move(value))) {}

  PolymorphicValue(const PolymorphicValue& other) {
    if (other.has_value()) {
      *this = other.Visit(CopyVisitor<PolymorphicValue>{});
    }
  }
  PolymorphicValue(PolymorphicValue&& other) { *this = std::move(other); }

  PolymorphicValue& operator=(const PolymorphicValue& other) {
    *this = PolymorphicValue(other);
    return *this;
  }

  PolymorphicValue& operator=(PolymorphicValue&& other) {
    if (this == &other) return *this;
    if (has_value()) Visit(DestroyVisitor{});
    static_cast<Base&>(*this) =
        std::exchange(static_cast<Base&>(other), Base{});
    return *this;
  }

  ~PolymorphicValue() {
    if (has_value()) Visit(DestroyVisitor{});
  }

  using Base::GetAs;
  using Base::Has;
  using Base::has_value;
  using Base::Visit;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_POLYMORPHIC_VALUE_H_
