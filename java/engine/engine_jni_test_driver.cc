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

#include <dlfcn.h>
#include <jni.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "./centipede/engine_abi.h"
#include "./java/engine/engine_jni.h"

namespace {

struct HarnessCapture {
  std::string binary_id;
  std::string test_name;
  std::vector<std::string> errors;
  std::vector<std::string> warnings;
  std::vector<std::string> findings;
  std::vector<uint8_t> domain_ids;
  std::vector<std::string> domain_names;
  std::vector<uint64_t> last_features;
  std::vector<uint8_t> round_tripped_content;
  std::vector<uint8_t> round_tripped_metadata;
  size_t preset_seed_count = 0;
};

std::string ToString(const FuzzTestBytesView* v) {
  if (v == nullptr || v->data == nullptr || v->size == 0) {
    return "";
  }
  return std::string(reinterpret_cast<const char*>(v->data), v->size);
}

FuzzTestBytesSink MakeBytesSink(std::vector<uint8_t>* target) {
  FuzzTestBytesSink sink = {};
  sink.ctx = reinterpret_cast<FuzzTestBytesSinkCtx*>(target);
  sink.Emit = [](FuzzTestBytesSinkCtx* ctx, const FuzzTestBytesView* view) {
    auto* out = reinterpret_cast<std::vector<uint8_t>*>(ctx);
    if (view != nullptr && view->data != nullptr && view->size > 0) {
      out->insert(out->end(), view->data, view->data + view->size);
    }
  };
  return sink;
}

FuzzTestInputSink MakeInputSink(std::vector<FuzzTestInputHandle>* target) {
  FuzzTestInputSink sink = {};
  sink.ctx = reinterpret_cast<FuzzTestInputSinkCtx*>(target);
  sink.Emit = [](FuzzTestInputSinkCtx* ctx, FuzzTestInputHandle input) {
    auto* out = reinterpret_cast<std::vector<FuzzTestInputHandle>*>(ctx);
    out->push_back(input);
  };
  return sink;
}

void RunFullAbiRoundTrip(const FuzzTestAdapterManager* manager,
                         void* raw_capture) {
  auto* cap = static_cast<HarnessCapture*>(raw_capture);

  std::vector<uint8_t> bin_bytes;
  FuzzTestBytesSink bin_sink = MakeBytesSink(&bin_bytes);
  manager->GetBinaryId(manager->ctx, &bin_sink);
  cap->binary_id.assign(bin_bytes.begin(), bin_bytes.end());

  std::vector<uint8_t> name_bytes;
  FuzzTestBytesSink name_sink = MakeBytesSink(&name_bytes);
  manager->GetTestName(manager->ctx, &name_sink);
  cap->test_name.assign(name_bytes.begin(), name_bytes.end());

  FuzzTestDiagnosticSink diag = {};
  diag.ctx = reinterpret_cast<FuzzTestDiagnosticSinkCtx*>(cap);
  diag.EmitError = [](FuzzTestDiagnosticSinkCtx* ctx,
                      const FuzzTestBytesView* msg) {
    reinterpret_cast<HarnessCapture*>(ctx)->errors.push_back(ToString(msg));
  };
  diag.EmitWarning = [](FuzzTestDiagnosticSinkCtx* ctx,
                        const FuzzTestBytesView* msg) {
    reinterpret_cast<HarnessCapture*>(ctx)->warnings.push_back(ToString(msg));
  };
  diag.EmitFinding = [](FuzzTestDiagnosticSinkCtx* ctx,
                        const FuzzTestBytesView* desc,
                        const FuzzTestBytesView* sig) {
    reinterpret_cast<HarnessCapture*>(ctx)->findings.push_back(
        ToString(desc) + "|" + ToString(sig));
  };

  FuzzTestAdapter adapter = {};
  manager->ConstructAdapter(manager->ctx, &diag, &adapter);
  if (!cap->errors.empty()) {
    adapter.FreeCtx(adapter.ctx);
    return;
  }

  FuzzTestCoverageDomainRegistry registry = {};
  registry.ctx = reinterpret_cast<FuzzTestCoverageDomainRegistryCtx*>(cap);
  registry.Register = [](FuzzTestCoverageDomainRegistryCtx* ctx,
                         const FuzzTestCoverageDomain* d) {
    auto* c = reinterpret_cast<HarnessCapture*>(ctx);
    c->domain_ids.push_back(d->domain_id);
    c->domain_names.push_back(ToString(&d->name));
  };
  adapter.SetUpCoverageDomains(adapter.ctx, &registry);

  std::vector<FuzzTestInputHandle> presets;
  FuzzTestInputSink preset_sink = MakeInputSink(&presets);
  adapter.GetPresetSeedInputs(adapter.ctx, &preset_sink);
  cap->preset_seed_count = presets.size();
  for (FuzzTestInputHandle h : presets) {
    adapter.FreeInput(adapter.ctx, h);
  }

  std::vector<FuzzTestInputHandle> seeds;
  FuzzTestInputSink seed_sink = MakeInputSink(&seeds);
  adapter.GetRandomSeedInput(adapter.ctx, &seed_sink);
  if (!seeds.empty()) {
    FuzzTestInputHandle seed = seeds[0];

    FuzzTestFeedbackSink fb = {};
    fb.ctx = reinterpret_cast<FuzzTestFeedbackSinkCtx*>(cap);
    fb.EmitCoverageFeatures = [](FuzzTestFeedbackSinkCtx* ctx,
                                 const FuzzTestUint64sView* view) {
      auto* c = reinterpret_cast<HarnessCapture*>(ctx);
      if (view != nullptr && view->data != nullptr && view->size > 0) {
        c->last_features.insert(c->last_features.end(), view->data,
                                view->data + view->size);
      }
    };
    adapter.Execute(adapter.ctx, seed, &fb);

    FuzzTestBytesSink content_sink = MakeBytesSink(&cap->round_tripped_content);
    adapter.SerializeInputContent(adapter.ctx, seed, &content_sink);

    FuzzTestBytesSink meta_sink = MakeBytesSink(&cap->round_tripped_metadata);
    adapter.SerializeInputMetadata(adapter.ctx, seed, &meta_sink);

    std::vector<FuzzTestInputHandle> deserialized;
    FuzzTestInputSink deser_sink = MakeInputSink(&deserialized);
    FuzzTestBytesView content_view = {cap->round_tripped_content.data(),
                                      cap->round_tripped_content.size()};
    adapter.DeserializeInputContent(adapter.ctx, &content_view, &deser_sink);
    if (!deserialized.empty()) {
      FuzzTestBytesView meta_view = {cap->round_tripped_metadata.data(),
                                     cap->round_tripped_metadata.size()};
      adapter.UpdateInputMetadata(adapter.ctx, &meta_view, deserialized[0]);

      std::vector<FuzzTestInputHandle> mutants;
      FuzzTestInputSink mutant_sink = MakeInputSink(&mutants);
      adapter.Mutate(adapter.ctx, deserialized[0], /*shrink=*/0, &mutant_sink);
      adapter.CrossOver(adapter.ctx, seed, deserialized[0], &mutant_sink);
      for (FuzzTestInputHandle m : mutants) {
        adapter.Execute(adapter.ctx, m, &fb);
        adapter.FreeInput(adapter.ctx, m);
      }
      adapter.FreeInput(adapter.ctx, deserialized[0]);
    }
    adapter.FreeInput(adapter.ctx, seed);
  }

  adapter.FreeCtx(adapter.ctx);
}

}  // namespace

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_google_fuzztest_engine_FuzzTestEngineTest_nativeRunAbiHarness(
    JNIEnv* env, jclass /*clazz*/, jstring j_engine_so_path,
    jobject j_manager) {
  const char* so_chars = env->GetStringUTFChars(j_engine_so_path, nullptr);
  std::string so_path(so_chars == nullptr ? "" : so_chars);
  if (so_chars != nullptr) {
    env->ReleaseStringUTFChars(j_engine_so_path, so_chars);
  }

  void* lib_handle = dlopen(so_path.c_str(), RTLD_NOLOAD | RTLD_LAZY);
  if (lib_handle == nullptr) {
    jclass ise = env->FindClass("java/lang/IllegalStateException");
    env->ThrowNew(
        ise, "Engine JNI library was not already loaded in current process");
    return nullptr;
  }

  using RunFn =
      void (*)(JNIEnv*, jobject, FuzzTestJavaManagerTestCallback, void*);
  auto run_fn = reinterpret_cast<RunFn>(
      dlsym(lib_handle, "FuzzTestJavaRunWithManagerForTesting"));
  dlclose(lib_handle);
  if (run_fn == nullptr) {
    jclass ise = env->FindClass("java/lang/IllegalStateException");
    env->ThrowNew(ise, "Missing FuzzTestJavaRunWithManagerForTesting symbol");
    return nullptr;
  }

  HarnessCapture cap;
  run_fn(env, j_manager, &RunFullAbiRoundTrip, &cap);
  if (env->ExceptionCheck()) {
    return nullptr;
  }

  // Return summary strings: [binary_id, test_name, errors_joined,
  // warnings_joined, findings_joined, domains_joined, features_count,
  // preset_count]
  auto join = [](const std::vector<std::string>& items) {
    std::string out;
    for (size_t i = 0; i < items.size(); ++i) {
      if (i > 0) out += "\n";
      out += items[i];
    }
    return out;
  };

  std::string domains_summary;
  for (size_t i = 0; i < cap.domain_ids.size(); ++i) {
    if (i > 0) domains_summary += ",";
    domains_summary +=
        std::to_string(cap.domain_ids[i]) + ":" + cap.domain_names[i];
  }

  std::vector<std::string> fields = {
      cap.binary_id,
      cap.test_name,
      join(cap.errors),
      join(cap.warnings),
      join(cap.findings),
      domains_summary,
      std::to_string(cap.last_features.size()),
      std::to_string(cap.preset_seed_count),
  };

  jclass str_cls = env->FindClass("java/lang/String");
  jobjectArray out =
      env->NewObjectArray(static_cast<jsize>(fields.size()), str_cls, nullptr);
  for (size_t i = 0; i < fields.size(); ++i) {
    jstring s = env->NewStringUTF(fields[i].c_str());
    env->SetObjectArrayElement(out, static_cast<jsize>(i), s);
    env->DeleteLocalRef(s);
  }
  return out;
}
