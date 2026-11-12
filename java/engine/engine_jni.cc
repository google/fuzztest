// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./java/engine/engine_jni.h"

#include <jni.h>
#include <pthread.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "./centipede/engine_abi.h"
#include "./centipede/engine_worker_abi.h"

namespace fuzztest::java_jni {
namespace {

static_assert(sizeof(FuzzTestInputHandle) <= sizeof(jlong),
              "FuzzTestInputHandle must fit in a 64-bit Java long");

struct JniCache {
  jclass engine_cls = nullptr;
  jmethodID binary_id_bytes = nullptr;
  jmethodID test_name_bytes = nullptr;
  jmethodID construct_adapter = nullptr;
  jmethodID collect_coverage_domains = nullptr;
  jmethodID format_throwable_utf8 = nullptr;

  jclass native_sink_cls = nullptr;
  jmethodID native_sink_ctor = nullptr;
  jmethodID native_sink_invalidate = nullptr;

  jclass domain_reg_cls = nullptr;
  jfieldID domain_id_field = nullptr;
  jfieldID domain_name_field = nullptr;
  jfieldID domain_feature_bits_field = nullptr;
  jfieldID domain_counter_bits_field = nullptr;

  jclass adapter_cls = nullptr;
  jmethodID adapter_preset_seeds = nullptr;
  jmethodID adapter_random_seed = nullptr;
  jmethodID adapter_mutate = nullptr;
  jmethodID adapter_cross_over = nullptr;
  jmethodID adapter_execute = nullptr;
  jmethodID adapter_serialize_content = nullptr;
  jmethodID adapter_deserialize_content = nullptr;
  jmethodID adapter_serialize_metadata = nullptr;
  jmethodID adapter_update_metadata = nullptr;
  jmethodID adapter_free_input = nullptr;
  jmethodID adapter_close = nullptr;
};

pthread_mutex_t g_cache_mu = PTHREAD_MUTEX_INITIALIZER;
bool g_cache_initialized = false;
JniCache g_cache;

class ScopedPthreadLock {
 public:
  explicit ScopedPthreadLock(pthread_mutex_t* mu) : mu_(mu) {
    pthread_mutex_lock(mu_);
  }
  ~ScopedPthreadLock() { pthread_mutex_unlock(mu_); }
  ScopedPthreadLock(const ScopedPthreadLock&) = delete;
  ScopedPthreadLock& operator=(const ScopedPthreadLock&) = delete;

 private:
  pthread_mutex_t* mu_;
};

// Pushes a JNI local reference frame so persistent-mode loops executing tens of
// thousands of batches inside one native call never accumulate local refs.
class ScopedLocalFrame {
 public:
  explicit ScopedLocalFrame(JNIEnv* env, jint capacity = 32) : env_(env) {
    pushed_ = (env_ != nullptr && env_->PushLocalFrame(capacity) == JNI_OK);
  }
  ~ScopedLocalFrame() {
    if (pushed_) {
      env_->PopLocalFrame(nullptr);
    }
  }
  ScopedLocalFrame(const ScopedLocalFrame&) = delete;
  ScopedLocalFrame& operator=(const ScopedLocalFrame&) = delete;

  bool ok() const { return pushed_; }

 private:
  JNIEnv* env_;
  bool pushed_ = false;
};

jclass FindClassGlobal(JNIEnv* env, const char* internal_name) {
  jclass local = env->FindClass(internal_name);
  if (local == nullptr || env->ExceptionCheck()) {
    return nullptr;
  }
  jclass global = static_cast<jclass>(env->NewGlobalRef(local));
  env->DeleteLocalRef(local);
  return global;
}

bool EnsureJniCache(JNIEnv* env) {
  ScopedPthreadLock lock(&g_cache_mu);
  if (g_cache_initialized) {
    return true;
  }

  JniCache c;
  c.engine_cls =
      FindClassGlobal(env, "com/google/fuzztest/engine/FuzzTestEngine");
  c.native_sink_cls = FindClassGlobal(
      env, "com/google/fuzztest/engine/FuzzTestEngine$NativeDiagnosticSink");
  c.domain_reg_cls = FindClassGlobal(
      env, "com/google/fuzztest/engine/FuzzTestEngine$DomainRegistration");
  c.adapter_cls =
      FindClassGlobal(env, "com/google/fuzztest/engine/FuzzTestAdapter");
  if (c.engine_cls == nullptr || c.native_sink_cls == nullptr ||
      c.domain_reg_cls == nullptr || c.adapter_cls == nullptr) {
    return false;
  }

  c.binary_id_bytes = env->GetStaticMethodID(
      c.engine_cls, "binaryIdBytes",
      "(Lcom/google/fuzztest/engine/FuzzTestAdapterManager;)[B");
  c.test_name_bytes = env->GetStaticMethodID(
      c.engine_cls, "testNameBytes",
      "(Lcom/google/fuzztest/engine/FuzzTestAdapterManager;)[B");
  c.construct_adapter = env->GetStaticMethodID(
      c.engine_cls, "constructAdapter",
      "(Lcom/google/fuzztest/engine/FuzzTestAdapterManager;"
      "Lcom/google/fuzztest/engine/FuzzTestEngine$NativeDiagnosticSink;)"
      "Lcom/google/fuzztest/engine/FuzzTestAdapter;");
  c.collect_coverage_domains = env->GetStaticMethodID(
      c.engine_cls, "collectCoverageDomains",
      "(Lcom/google/fuzztest/engine/FuzzTestAdapter;)"
      "[Lcom/google/fuzztest/engine/FuzzTestEngine$DomainRegistration;");
  c.format_throwable_utf8 = env->GetStaticMethodID(
      c.engine_cls, "formatThrowableUtf8", "(Ljava/lang/Throwable;)[B");

  c.native_sink_ctor = env->GetMethodID(c.native_sink_cls, "<init>", "(J)V");
  c.native_sink_invalidate =
      env->GetMethodID(c.native_sink_cls, "invalidate", "()V");

  c.domain_id_field = env->GetFieldID(c.domain_reg_cls, "domainId", "I");
  c.domain_name_field = env->GetFieldID(c.domain_reg_cls, "nameUtf8", "[B");
  c.domain_feature_bits_field =
      env->GetFieldID(c.domain_reg_cls, "featureIdBitSize", "I");
  c.domain_counter_bits_field =
      env->GetFieldID(c.domain_reg_cls, "counterBitSize", "I");

  c.adapter_preset_seeds =
      env->GetMethodID(c.adapter_cls, "presetSeedInputs", "()[J");
  c.adapter_random_seed =
      env->GetMethodID(c.adapter_cls, "randomSeedInput", "()J");
  c.adapter_mutate = env->GetMethodID(c.adapter_cls, "mutate", "(JZ)J");
  c.adapter_cross_over = env->GetMethodID(c.adapter_cls, "crossOver", "(JJ)J");
  c.adapter_execute = env->GetMethodID(c.adapter_cls, "execute", "(J)[J");
  c.adapter_serialize_content =
      env->GetMethodID(c.adapter_cls, "serializeInputContent", "(J)[B");
  c.adapter_deserialize_content =
      env->GetMethodID(c.adapter_cls, "deserializeInputContent", "([B)J");
  c.adapter_serialize_metadata =
      env->GetMethodID(c.adapter_cls, "serializeInputMetadata", "(J)[B");
  c.adapter_update_metadata =
      env->GetMethodID(c.adapter_cls, "updateInputMetadata", "([BJ)V");
  c.adapter_free_input = env->GetMethodID(c.adapter_cls, "freeInput", "(J)V");
  c.adapter_close = env->GetMethodID(c.adapter_cls, "close", "()V");

  if (env->ExceptionCheck()) {
    return false;
  }

  g_cache = c;
  g_cache_initialized = true;
  return true;
}

JNIEnv* GetCurrentEnv(JavaVM* jvm) {
  if (jvm == nullptr) {
    return nullptr;
  }
  JNIEnv* env = nullptr;
  if (jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8) == JNI_OK) {
    return env;
  }
  if (jvm->AttachCurrentThreadAsDaemon(reinterpret_cast<void**>(&env),
                                       nullptr) == JNI_OK) {
    return env;
  }
  return nullptr;
}

void EmitStringToDiagnosticError(const FuzzTestDiagnosticSink* sink,
                                 std::string_view msg) {
  if (sink == nullptr || sink->EmitError == nullptr) {
    std::fwrite(msg.data(), 1, msg.size(), stderr);
    std::fwrite("\n", 1, 1, stderr);
    std::fflush(stderr);
    return;
  }
  FuzzTestBytesView view = {
      reinterpret_cast<const uint8_t*>(msg.data()),
      msg.size(),
  };
  sink->EmitError(sink->ctx, &view);
}

std::string CopyJavaByteArrayToString(JNIEnv* env, jbyteArray arr) {
  if (arr == nullptr) {
    return "";
  }
  const jsize len = env->GetArrayLength(arr);
  if (len <= 0) {
    return "";
  }
  std::string out(static_cast<size_t>(len), '\0');
  env->GetByteArrayRegion(arr, 0, len, reinterpret_cast<jbyte*>(out.data()));
  return out;
}

std::string ExtractAndClearJavaException(JNIEnv* env, const char* context) {
  jthrowable exc = env->ExceptionOccurred();
  env->ExceptionClear();
  std::string prefix = std::string("Java exception in ") + context + ": ";
  if (exc == nullptr) {
    return prefix + "(unknown)";
  }
  auto formatted = static_cast<jbyteArray>(env->CallStaticObjectMethod(
      g_cache.engine_cls, g_cache.format_throwable_utf8, exc));
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    env->DeleteLocalRef(exc);
    return prefix + "(failed to format stack trace)";
  }
  std::string details = CopyJavaByteArrayToString(env, formatted);
  if (formatted != nullptr) {
    env->DeleteLocalRef(formatted);
  }
  env->DeleteLocalRef(exc);
  return prefix + details;
}

bool CheckExceptionAndEmitError(JNIEnv* env, const FuzzTestDiagnosticSink* sink,
                                const char* context) {
  if (!env->ExceptionCheck()) {
    return false;
  }
  const std::string msg = ExtractAndClearJavaException(env, context);
  EmitStringToDiagnosticError(sink, msg);
  return true;
}

void EmitJavaByteArrayToSink(JNIEnv* env, jbyteArray arr,
                             const FuzzTestBytesSink* sink) {
  if (arr == nullptr || sink == nullptr || sink->Emit == nullptr) {
    return;
  }
  const jsize len = env->GetArrayLength(arr);
  if (len <= 0) {
    return;
  }
  constexpr jsize kStackBufSize = 4096;
  if (len <= kStackBufSize) {
    jbyte stack_buf[kStackBufSize];
    env->GetByteArrayRegion(arr, 0, len, stack_buf);
    FuzzTestBytesView view = {
        reinterpret_cast<const uint8_t*>(stack_buf),
        static_cast<size_t>(len),
    };
    sink->Emit(sink->ctx, &view);
    return;
  }
  std::vector<jbyte> heap_buf(static_cast<size_t>(len));
  env->GetByteArrayRegion(arr, 0, len, heap_buf.data());
  FuzzTestBytesView view = {
      reinterpret_cast<const uint8_t*>(heap_buf.data()),
      heap_buf.size(),
  };
  sink->Emit(sink->ctx, &view);
}

jbyteArray MakeJavaByteArray(JNIEnv* env, const FuzzTestBytesView* view) {
  const jsize len = (view == nullptr) ? 0 : static_cast<jsize>(view->size);
  jbyteArray arr = env->NewByteArray(len);
  if (arr == nullptr) {
    return nullptr;
  }
  if (len > 0 && view->data != nullptr) {
    env->SetByteArrayRegion(arr, 0, len,
                            reinterpret_cast<const jbyte*>(view->data));
  }
  return arr;
}

struct AdapterBridgeCtx {
  JavaVM* jvm = nullptr;
  FuzzTestDiagnosticSink diagnostic_sink = {};
  jobject adapter_global = nullptr;
  jobject native_sink_global = nullptr;
  std::atomic<bool> in_execute{false};
  std::atomic<bool> active{true};
};

class ScopedExecuteFlag {
 public:
  explicit ScopedExecuteFlag(std::atomic<bool>& flag) : flag_(flag) {
    flag_.store(true, std::memory_order_release);
  }
  ~ScopedExecuteFlag() { flag_.store(false, std::memory_order_release); }

 private:
  std::atomic<bool>& flag_;
};

struct ManagerBridgeState {
  JavaVM* jvm = nullptr;
  jobject manager_ref = nullptr;
  jthrowable pending_exception = nullptr;
};

AdapterBridgeCtx* AsAdapterCtx(FuzzTestAdapterCtx* raw) {
  return reinterpret_cast<AdapterBridgeCtx*>(raw);
}

ManagerBridgeState* AsManagerState(FuzzTestAdapterManagerCtx* raw) {
  return reinterpret_cast<ManagerBridgeState*>(raw);
}

void AdapterSetUpCoverageDomains(
    FuzzTestAdapterCtx* raw_ctx,
    const FuzzTestCoverageDomainRegistry* registry) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr || registry == nullptr ||
      registry->Register == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 32);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(
        &ctx->diagnostic_sink, "PushLocalFrame failed in SetUpCoverageDomains");
    return;
  }

  auto domains_arr = static_cast<jobjectArray>(env->CallStaticObjectMethod(
      g_cache.engine_cls, g_cache.collect_coverage_domains,
      ctx->adapter_global));
  if (CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                 "FuzzTestAdapter.setUpCoverageDomains") ||
      domains_arr == nullptr) {
    return;
  }

  const jsize count = env->GetArrayLength(domains_arr);
  for (jsize i = 0; i < count; ++i) {
    jobject entry = env->GetObjectArrayElement(domains_arr, i);
    if (entry == nullptr) {
      continue;
    }
    const jint domain_id = env->GetIntField(entry, g_cache.domain_id_field);
    const jint feature_bits =
        env->GetIntField(entry, g_cache.domain_feature_bits_field);
    const jint counter_bits =
        env->GetIntField(entry, g_cache.domain_counter_bits_field);
    auto name_arr = static_cast<jbyteArray>(
        env->GetObjectField(entry, g_cache.domain_name_field));
    const std::string name_str = CopyJavaByteArrayToString(env, name_arr);

    FuzzTestCoverageDomain c_domain = {};
    c_domain.domain_id = static_cast<uint8_t>(domain_id);
    c_domain.name.data = reinterpret_cast<const uint8_t*>(name_str.data());
    c_domain.name.size = name_str.size();
    c_domain.feature_id_bit_size = static_cast<uint8_t>(feature_bits);
    c_domain.counter_bit_size = static_cast<uint8_t>(counter_bits);
    registry->Register(registry->ctx, &c_domain);

    if (name_arr != nullptr) {
      env->DeleteLocalRef(name_arr);
    }
    env->DeleteLocalRef(entry);
  }
}

void AdapterGetPresetSeedInputs(FuzzTestAdapterCtx* raw_ctx,
                                const FuzzTestInputSink* sink) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr || sink == nullptr ||
      sink->Emit == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 16);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(&ctx->diagnostic_sink,
                                "PushLocalFrame failed in GetPresetSeedInputs");
    return;
  }

  auto handles_arr = static_cast<jlongArray>(
      env->CallObjectMethod(ctx->adapter_global, g_cache.adapter_preset_seeds));
  if (CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                 "FuzzTestAdapter.presetSeedInputs")) {
    return;
  }
  if (handles_arr == nullptr) {
    EmitStringToDiagnosticError(
        &ctx->diagnostic_sink,
        "FuzzTestAdapter.presetSeedInputs returned null");
    return;
  }
  const jsize len = env->GetArrayLength(handles_arr);
  if (len <= 0) {
    return;
  }
  std::vector<jlong> handles(static_cast<size_t>(len));
  env->GetLongArrayRegion(handles_arr, 0, len, handles.data());
  for (jlong h : handles) {
    sink->Emit(sink->ctx,
               static_cast<FuzzTestInputHandle>(static_cast<uint64_t>(h)));
  }
}

void AdapterGetRandomSeedInput(FuzzTestAdapterCtx* raw_ctx,
                               const FuzzTestInputSink* sink) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr || sink == nullptr ||
      sink->Emit == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 16);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(&ctx->diagnostic_sink,
                                "PushLocalFrame failed in GetRandomSeedInput");
    return;
  }

  const jlong handle =
      env->CallLongMethod(ctx->adapter_global, g_cache.adapter_random_seed);
  if (CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                 "FuzzTestAdapter.randomSeedInput")) {
    return;
  }
  sink->Emit(sink->ctx,
             static_cast<FuzzTestInputHandle>(static_cast<uint64_t>(handle)));
}

void AdapterMutate(FuzzTestAdapterCtx* raw_ctx, FuzzTestInputHandle origin,
                   int shrink, const FuzzTestInputSink* sink) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr || sink == nullptr ||
      sink->Emit == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 16);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(&ctx->diagnostic_sink,
                                "PushLocalFrame failed in Mutate");
    return;
  }

  const jlong mutant =
      env->CallLongMethod(ctx->adapter_global, g_cache.adapter_mutate,
                          static_cast<jlong>(static_cast<uint64_t>(origin)),
                          shrink != 0 ? JNI_TRUE : JNI_FALSE);
  if (CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                 "FuzzTestAdapter.mutate")) {
    return;
  }
  sink->Emit(sink->ctx,
             static_cast<FuzzTestInputHandle>(static_cast<uint64_t>(mutant)));
}

void AdapterCrossOver(FuzzTestAdapterCtx* raw_ctx, FuzzTestInputHandle origin,
                      FuzzTestInputHandle other,
                      const FuzzTestInputSink* sink) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr || sink == nullptr ||
      sink->Emit == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 16);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(&ctx->diagnostic_sink,
                                "PushLocalFrame failed in CrossOver");
    return;
  }

  const jlong mutant =
      env->CallLongMethod(ctx->adapter_global, g_cache.adapter_cross_over,
                          static_cast<jlong>(static_cast<uint64_t>(origin)),
                          static_cast<jlong>(static_cast<uint64_t>(other)));
  if (CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                 "FuzzTestAdapter.crossOver")) {
    return;
  }
  sink->Emit(sink->ctx,
             static_cast<FuzzTestInputHandle>(static_cast<uint64_t>(mutant)));
}

void AdapterExecute(FuzzTestAdapterCtx* raw_ctx, FuzzTestInputHandle input,
                    const FuzzTestFeedbackSink* sink) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 16);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(&ctx->diagnostic_sink,
                                "PushLocalFrame failed in Execute");
    return;
  }

  jlongArray features_arr = nullptr;
  {
    ScopedExecuteFlag in_execute_guard(ctx->in_execute);
    features_arr = static_cast<jlongArray>(env->CallObjectMethod(
        ctx->adapter_global, g_cache.adapter_execute,
        static_cast<jlong>(static_cast<uint64_t>(input))));
    if (CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                   "FuzzTestAdapter.execute")) {
      return;
    }
  }

  if (features_arr == nullptr) {
    EmitStringToDiagnosticError(&ctx->diagnostic_sink,
                                "FuzzTestAdapter.execute returned null");
    return;
  }
  if (sink == nullptr || sink->EmitCoverageFeatures == nullptr) {
    return;
  }

  const jsize len = env->GetArrayLength(features_arr);
  if (len <= 0) {
    return;
  }

  constexpr jsize kStackFeatureCap = 512;
  if (len <= kStackFeatureCap) {
    uint64_t stack_features[kStackFeatureCap];
    env->GetLongArrayRegion(features_arr, 0, len,
                            reinterpret_cast<jlong*>(stack_features));
    FuzzTestUint64sView view = {stack_features, static_cast<size_t>(len)};
    sink->EmitCoverageFeatures(sink->ctx, &view);
    return;
  }

  std::vector<uint64_t> heap_features(static_cast<size_t>(len));
  env->GetLongArrayRegion(features_arr, 0, len,
                          reinterpret_cast<jlong*>(heap_features.data()));
  FuzzTestUint64sView view = {heap_features.data(), heap_features.size()};
  sink->EmitCoverageFeatures(sink->ctx, &view);
}

void AdapterSerializeInputContent(FuzzTestAdapterCtx* raw_ctx,
                                  FuzzTestInputHandle input,
                                  const FuzzTestBytesSink* sink) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 16);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(
        &ctx->diagnostic_sink,
        "PushLocalFrame failed in SerializeInputContent");
    return;
  }

  auto bytes_arr = static_cast<jbyteArray>(env->CallObjectMethod(
      ctx->adapter_global, g_cache.adapter_serialize_content,
      static_cast<jlong>(static_cast<uint64_t>(input))));
  if (CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                 "FuzzTestAdapter.serializeInputContent")) {
    return;
  }
  if (bytes_arr == nullptr) {
    EmitStringToDiagnosticError(
        &ctx->diagnostic_sink,
        "FuzzTestAdapter.serializeInputContent returned null");
    return;
  }
  EmitJavaByteArrayToSink(env, bytes_arr, sink);
}

void AdapterDeserializeInputContent(FuzzTestAdapterCtx* raw_ctx,
                                    const FuzzTestBytesView* content,
                                    const FuzzTestInputSink* sink) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr || sink == nullptr ||
      sink->Emit == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 16);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(
        &ctx->diagnostic_sink,
        "PushLocalFrame failed in DeserializeInputContent");
    return;
  }

  jbyteArray content_arr = MakeJavaByteArray(env, content);
  if (CheckExceptionAndEmitError(
          env, &ctx->diagnostic_sink,
          "NewByteArray in FuzzTestAdapter.deserializeInputContent") ||
      content_arr == nullptr) {
    return;
  }

  const jlong handle = env->CallLongMethod(
      ctx->adapter_global, g_cache.adapter_deserialize_content, content_arr);
  if (CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                 "FuzzTestAdapter.deserializeInputContent")) {
    return;
  }
  sink->Emit(sink->ctx,
             static_cast<FuzzTestInputHandle>(static_cast<uint64_t>(handle)));
}

void AdapterSerializeInputMetadata(FuzzTestAdapterCtx* raw_ctx,
                                   FuzzTestInputHandle input,
                                   const FuzzTestBytesSink* sink) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 16);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(
        &ctx->diagnostic_sink,
        "PushLocalFrame failed in SerializeInputMetadata");
    return;
  }

  auto metadata_arr = static_cast<jbyteArray>(env->CallObjectMethod(
      ctx->adapter_global, g_cache.adapter_serialize_metadata,
      static_cast<jlong>(static_cast<uint64_t>(input))));
  if (CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                 "FuzzTestAdapter.serializeInputMetadata")) {
    return;
  }
  if (metadata_arr == nullptr) {
    EmitStringToDiagnosticError(
        &ctx->diagnostic_sink,
        "FuzzTestAdapter.serializeInputMetadata returned null");
    return;
  }
  EmitJavaByteArrayToSink(env, metadata_arr, sink);
}

void AdapterUpdateInputMetadata(FuzzTestAdapterCtx* raw_ctx,
                                const FuzzTestBytesView* metadata,
                                FuzzTestInputHandle input) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 16);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(&ctx->diagnostic_sink,
                                "PushLocalFrame failed in UpdateInputMetadata");
    return;
  }

  jbyteArray metadata_arr = MakeJavaByteArray(env, metadata);
  if (CheckExceptionAndEmitError(
          env, &ctx->diagnostic_sink,
          "NewByteArray in FuzzTestAdapter.updateInputMetadata") ||
      metadata_arr == nullptr) {
    return;
  }

  env->CallVoidMethod(ctx->adapter_global, g_cache.adapter_update_metadata,
                      metadata_arr,
                      static_cast<jlong>(static_cast<uint64_t>(input)));
  (void)CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                   "FuzzTestAdapter.updateInputMetadata");
}

void AdapterFreeInput(FuzzTestAdapterCtx* raw_ctx, FuzzTestInputHandle input) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr || ctx->adapter_global == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  ScopedLocalFrame frame(env, 8);
  if (!frame.ok()) {
    EmitStringToDiagnosticError(&ctx->diagnostic_sink,
                                "PushLocalFrame failed in FreeInput");
    return;
  }

  env->CallVoidMethod(ctx->adapter_global, g_cache.adapter_free_input,
                      static_cast<jlong>(static_cast<uint64_t>(input)));
  (void)CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                   "FuzzTestAdapter.freeInput");
}

void AdapterFreeCtx(FuzzTestAdapterCtx* raw_ctx) {
  AdapterBridgeCtx* ctx = AsAdapterCtx(raw_ctx);
  if (ctx == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(ctx->jvm);
  if (env != nullptr) {
    {
      ScopedLocalFrame frame(env, 8);
      if (frame.ok()) {
        if (ctx->adapter_global != nullptr) {
          env->CallVoidMethod(ctx->adapter_global, g_cache.adapter_close);
          (void)CheckExceptionAndEmitError(env, &ctx->diagnostic_sink,
                                           "FuzzTestAdapter.close");
        }
        if (ctx->native_sink_global != nullptr) {
          env->CallVoidMethod(ctx->native_sink_global,
                              g_cache.native_sink_invalidate);
          if (env->ExceptionCheck()) {
            env->ExceptionClear();
          }
        }
      }
    }
    if (ctx->adapter_global != nullptr) {
      env->DeleteGlobalRef(ctx->adapter_global);
      ctx->adapter_global = nullptr;
    }
    if (ctx->native_sink_global != nullptr) {
      env->DeleteGlobalRef(ctx->native_sink_global);
      ctx->native_sink_global = nullptr;
    }
  }
  ctx->active.store(false, std::memory_order_release);
  delete ctx;
}

void PopulateAdapterCallbacks(AdapterBridgeCtx* ctx,
                              FuzzTestAdapter* adapter_out) {
  FuzzTestAdapter out = {};
  out.ctx = reinterpret_cast<FuzzTestAdapterCtx*>(ctx);
  out.SetUpCoverageDomains = &AdapterSetUpCoverageDomains;
  out.GetPresetSeedInputs = &AdapterGetPresetSeedInputs;
  out.GetRandomSeedInput = &AdapterGetRandomSeedInput;
  out.Mutate = &AdapterMutate;
  out.CrossOver = &AdapterCrossOver;
  out.Execute = &AdapterExecute;
  out.SerializeInputContent = &AdapterSerializeInputContent;
  out.DeserializeInputContent = &AdapterDeserializeInputContent;
  out.SerializeInputMetadata = &AdapterSerializeInputMetadata;
  out.UpdateInputMetadata = &AdapterUpdateInputMetadata;
  out.FreeInput = &AdapterFreeInput;
  out.FreeCtx = &AdapterFreeCtx;
  *adapter_out = out;
}

void ManagerGetBinaryId(FuzzTestAdapterManagerCtx* raw_ctx,
                        const FuzzTestBytesSink* sink) {
  ManagerBridgeState* state = AsManagerState(raw_ctx);
  if (state == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(state->jvm);
  if (env == nullptr) {
    return;
  }
  auto arr = static_cast<jbyteArray>(env->CallStaticObjectMethod(
      g_cache.engine_cls, g_cache.binary_id_bytes, state->manager_ref));
  if (env->ExceptionCheck()) {
    jthrowable exc = env->ExceptionOccurred();
    env->ExceptionClear();
    if (state->pending_exception == nullptr) {
      state->pending_exception = exc;
    } else if (exc != nullptr) {
      env->DeleteLocalRef(exc);
    }
    return;
  }
  EmitJavaByteArrayToSink(env, arr, sink);
  if (arr != nullptr) {
    env->DeleteLocalRef(arr);
  }
}

void ManagerGetTestName(FuzzTestAdapterManagerCtx* raw_ctx,
                        const FuzzTestBytesSink* sink) {
  ManagerBridgeState* state = AsManagerState(raw_ctx);
  if (state == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(state->jvm);
  if (env == nullptr) {
    return;
  }
  auto arr = static_cast<jbyteArray>(env->CallStaticObjectMethod(
      g_cache.engine_cls, g_cache.test_name_bytes, state->manager_ref));
  if (env->ExceptionCheck()) {
    jthrowable exc = env->ExceptionOccurred();
    env->ExceptionClear();
    if (state->pending_exception == nullptr) {
      state->pending_exception = exc;
    } else if (exc != nullptr) {
      env->DeleteLocalRef(exc);
    }
    return;
  }
  EmitJavaByteArrayToSink(env, arr, sink);
  if (arr != nullptr) {
    env->DeleteLocalRef(arr);
  }
}

void ManagerConstructAdapter(FuzzTestAdapterManagerCtx* raw_ctx,
                             const FuzzTestDiagnosticSink* diagnostic_sink,
                             FuzzTestAdapter* adapter_out) {
  ManagerBridgeState* state = AsManagerState(raw_ctx);
  if (state == nullptr || adapter_out == nullptr) {
    return;
  }
  JNIEnv* env = GetCurrentEnv(state->jvm);
  ScopedLocalFrame frame(env, 16);

  auto* bridge_ctx = new AdapterBridgeCtx();
  bridge_ctx->jvm = state->jvm;
  if (diagnostic_sink != nullptr) {
    bridge_ctx->diagnostic_sink = *diagnostic_sink;
  }
  PopulateAdapterCallbacks(bridge_ctx, adapter_out);

  if (!frame.ok()) {
    EmitStringToDiagnosticError(&bridge_ctx->diagnostic_sink,
                                "PushLocalFrame failed in ConstructAdapter");
    return;
  }

  jobject local_sink = env->NewObject(
      g_cache.native_sink_cls, g_cache.native_sink_ctor,
      static_cast<jlong>(reinterpret_cast<uintptr_t>(bridge_ctx)));
  if (CheckExceptionAndEmitError(env, &bridge_ctx->diagnostic_sink,
                                 "NativeDiagnosticSink.<init>") ||
      local_sink == nullptr) {
    return;
  }
  bridge_ctx->native_sink_global = env->NewGlobalRef(local_sink);

  jobject local_adapter =
      env->CallStaticObjectMethod(g_cache.engine_cls, g_cache.construct_adapter,
                                  state->manager_ref, local_sink);
  if (CheckExceptionAndEmitError(env, &bridge_ctx->diagnostic_sink,
                                 "FuzzTestAdapterManager.constructAdapter") ||
      local_adapter == nullptr) {
    return;
  }
  bridge_ctx->adapter_global = env->NewGlobalRef(local_adapter);
}

FuzzTestAdapterManager MakeManagerStruct(ManagerBridgeState* state) {
  FuzzTestAdapterManager manager = {};
  manager.ctx = reinterpret_cast<FuzzTestAdapterManagerCtx*>(state);
  manager.GetBinaryId = &ManagerGetBinaryId;
  manager.GetTestName = &ManagerGetTestName;
  manager.ConstructAdapter = &ManagerConstructAdapter;
  return manager;
}

}  // namespace
}  // namespace fuzztest::java_jni

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_google_fuzztest_engine_FuzzTestEngine_00024NativeHolder_nativeIsWorkerRequired(
    JNIEnv* /*env*/, jclass /*clazz*/) {
  return FuzzTestWorkerIsRequired() != 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_google_fuzztest_engine_FuzzTestEngine_00024NativeHolder_nativeMaybeRunWorker(
    JNIEnv* env, jclass /*clazz*/, jobject j_manager) {
  if (!fuzztest::java_jni::EnsureJniCache(env)) {
    return static_cast<jint>(kFuzzTestWorkerFailure);
  }
  fuzztest::java_jni::ManagerBridgeState state;
  if (env->GetJavaVM(&state.jvm) != JNI_OK) {
    return static_cast<jint>(kFuzzTestWorkerFailure);
  }
  state.manager_ref = j_manager;

  const FuzzTestAdapterManager c_manager =
      fuzztest::java_jni::MakeManagerStruct(&state);
  const FuzzTestWorkerStatus status = FuzzTestWorkerMaybeRun(&c_manager);

  if (state.pending_exception != nullptr) {
    env->Throw(state.pending_exception);
    env->DeleteLocalRef(state.pending_exception);
  }
  return static_cast<jint>(status);
}

JNIEXPORT void JNICALL
Java_com_google_fuzztest_engine_FuzzTestEngine_00024NativeHolder_nativeEmitError(
    JNIEnv* env, jclass /*clazz*/, jlong sink_ptr, jbyteArray message_utf8) {
  auto* ctx = reinterpret_cast<fuzztest::java_jni::AdapterBridgeCtx*>(
      static_cast<uintptr_t>(sink_ptr));
  if (ctx == nullptr || !ctx->active.load(std::memory_order_acquire)) {
    return;
  }
  const std::string msg =
      fuzztest::java_jni::CopyJavaByteArrayToString(env, message_utf8);
  fuzztest::java_jni::EmitStringToDiagnosticError(&ctx->diagnostic_sink, msg);
}

JNIEXPORT void JNICALL
Java_com_google_fuzztest_engine_FuzzTestEngine_00024NativeHolder_nativeEmitWarning(
    JNIEnv* env, jclass /*clazz*/, jlong sink_ptr, jbyteArray message_utf8) {
  auto* ctx = reinterpret_cast<fuzztest::java_jni::AdapterBridgeCtx*>(
      static_cast<uintptr_t>(sink_ptr));
  if (ctx == nullptr || !ctx->active.load(std::memory_order_acquire) ||
      ctx->diagnostic_sink.EmitWarning == nullptr) {
    return;
  }
  const std::string msg =
      fuzztest::java_jni::CopyJavaByteArrayToString(env, message_utf8);
  FuzzTestBytesView view = {
      reinterpret_cast<const uint8_t*>(msg.data()),
      msg.size(),
  };
  ctx->diagnostic_sink.EmitWarning(ctx->diagnostic_sink.ctx, &view);
}

JNIEXPORT void JNICALL
Java_com_google_fuzztest_engine_FuzzTestEngine_00024NativeHolder_nativeEmitFinding(
    JNIEnv* env, jclass /*clazz*/, jlong sink_ptr, jbyteArray description_utf8,
    jbyteArray signature_utf8) {
  auto* ctx = reinterpret_cast<fuzztest::java_jni::AdapterBridgeCtx*>(
      static_cast<uintptr_t>(sink_ptr));
  if (ctx == nullptr || !ctx->active.load(std::memory_order_acquire)) {
    return;
  }
  const std::string desc =
      fuzztest::java_jni::CopyJavaByteArrayToString(env, description_utf8);
  const std::string sig =
      fuzztest::java_jni::CopyJavaByteArrayToString(env, signature_utf8);

  // Enforce the engine_abi.h invariant that EmitFinding is only invoked inside
  // FuzzTestAdapter::Execute; route out-of-window calls to EmitError instead of
  // tripping WorkerCheck's std::_Exit(1).
  if (!ctx->in_execute.load(std::memory_order_acquire) ||
      ctx->diagnostic_sink.EmitFinding == nullptr) {
    const std::string err =
        "DiagnosticSink.emitFinding called outside FuzzTestAdapter.execute: " +
        desc;
    fuzztest::java_jni::EmitStringToDiagnosticError(&ctx->diagnostic_sink, err);
    return;
  }

  FuzzTestBytesView desc_view = {
      reinterpret_cast<const uint8_t*>(desc.data()),
      desc.size(),
  };
  FuzzTestBytesView sig_view = {
      reinterpret_cast<const uint8_t*>(sig.data()),
      sig.size(),
  };
  ctx->diagnostic_sink.EmitFinding(ctx->diagnostic_sink.ctx, &desc_view,
                                   &sig_view);
}

JNIEXPORT void JNICALL FuzzTestJavaRunWithManagerForTesting(
    JNIEnv* env, jobject j_manager, FuzzTestJavaManagerTestCallback callback,
    void* callback_ctx) {
  if (callback == nullptr || !fuzztest::java_jni::EnsureJniCache(env)) {
    return;
  }
  fuzztest::java_jni::ManagerBridgeState state;
  if (env->GetJavaVM(&state.jvm) != JNI_OK) {
    return;
  }
  state.manager_ref = j_manager;
  const FuzzTestAdapterManager c_manager =
      fuzztest::java_jni::MakeManagerStruct(&state);
  callback(&c_manager, callback_ctx);
  if (state.pending_exception != nullptr) {
    env->Throw(state.pending_exception);
    env->DeleteLocalRef(state.pending_exception);
  }
}

}  // extern "C"
