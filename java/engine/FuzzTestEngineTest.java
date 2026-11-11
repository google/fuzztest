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

package com.google.fuzztest.engine;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit and subprocess worker-protocol tests for {@link FuzzTestEngine} and {@code engine_jni.cc}.
 */
@RunWith(JUnit4.class)
public final class FuzzTestEngineTest {

  private static String loadedEngineSoPath;

  @BeforeClass
  public static void loadTestDriverJni() throws IOException {
    // Ensure FuzzTestEngine's lazy holder loads libfuzztest_java_engine_jni.so first.
    assertThat(FuzzTestEngine.isWorkerRequired()).isFalse();
    loadedEngineSoPath = findRunfilesLibrary("libfuzztest_java_engine_jni.so").toString();
    Path testDriverSo = findRunfilesLibrary("libfuzztest_java_engine_test_jni.so");
    System.load(testDriverSo.toString());
  }

  @Test
  public void defaultTestEnvironment_reportsWorkerNotRequiredWithoutConstructingAdapter() {
    AtomicBoolean constructed = new AtomicBoolean(false);
    FuzzTestAdapterManager manager =
        new FuzzTestAdapterManager() {
          @Override
          public String binaryId() {
            return "test-bin";
          }

          @Override
          public String testName() {
            return "com.example.MyTest.prop";
          }

          @Override
          public FuzzTestAdapter constructAdapter(DiagnosticSink diagnosticSink) {
            constructed.set(true);
            throw new AssertionError("Should not construct adapter when worker is not required");
          }
        };

    assertThat(FuzzTestEngine.isWorkerRequired()).isFalse();
    assertThat(FuzzTestEngine.maybeRunWorker(manager))
        .isEqualTo(FuzzTestEngine.WorkerStatus.NOT_REQUIRED);
    assertThat(constructed.get()).isFalse();
  }

  @Test
  public void allTwelveAdapterCallbacksAndDiagnostics_roundTripOverJniWithCleanup() {
    AtomicBoolean closed = new AtomicBoolean(false);
    AtomicReference<DiagnosticSink> capturedSink = new AtomicReference<>();

    FuzzTestAdapterManager manager =
        new FuzzTestAdapterManager() {
          @Override
          public String binaryId() {
            return "path/to/MyFuzzTest";
          }

          @Override
          public String testName() {
            return "com.example.Outer$Inner.fuzzProp";
          }

          @Override
          public FuzzTestAdapter constructAdapter(DiagnosticSink sink) {
            capturedSink.set(sink);
            return new RecordingToyAdapter(sink, closed);
          }
        };

    String[] summary = nativeRunAbiHarness(loadedEngineSoPath, manager);
    assertThat(summary[0]).isEqualTo("path/to/MyFuzzTest");
    assertThat(summary[1]).isEqualTo("com.example.Outer$Inner.fuzzProp");
    assertThat(summary[2]).isEmpty(); // 0 errors
    assertThat(summary[3]).isEqualTo("sample-warning");
    assertThat(summary[4]).isEqualTo("found-bug-on-mutated|SIG:mutated");
    assertThat(summary[5]).isEqualTo("1:jvm_pcs,6:jvm_cmp_moddiff");
    assertThat(Integer.parseInt(summary[6])).isGreaterThan(0);
    assertThat(Integer.parseInt(summary[7])).isEqualTo(2);
    assertThat(closed.get()).isTrue();

    // After FreeCtx, DiagnosticSink rejects any late use cleanly instead of dereferencing C memory:
    assertThrows(
        IllegalStateException.class, () -> capturedSink.get().emitWarning("after-free-ctx"));
  }

  @Test
  public void emitFindingOutsideExecuteAndCallbackExceptions_routeToEmitErrorWithoutAbortingJni() {
    FuzzTestAdapterManager badFindingWindowManager =
        new FuzzTestAdapterManager() {
          @Override
          public String testName() {
            return "com.example.BadWindow.test";
          }

          @Override
          public FuzzTestAdapter constructAdapter(DiagnosticSink sink) {
            // Illegal: emitFinding called inside constructAdapter (outside Execute)!
            sink.emitFinding("premature-finding", "SIG:premature");
            return new RecordingToyAdapter(sink, new AtomicBoolean());
          }
        };

    String[] windowSummary = nativeRunAbiHarness(loadedEngineSoPath, badFindingWindowManager);
    assertThat(windowSummary[4]).isEmpty(); // Not recorded as a finding!
    assertThat(windowSummary[2])
        .contains("DiagnosticSink.emitFinding called outside FuzzTestAdapter.execute");

    FuzzTestAdapterManager throwingMutateManager =
        new FuzzTestAdapterManager() {
          @Override
          public String testName() {
            return "com.example.ThrowingMutate.test";
          }

          @Override
          public FuzzTestAdapter constructAdapter(DiagnosticSink sink) {
            return new RecordingToyAdapter(sink, new AtomicBoolean()) {
              @Override
              public long mutate(long origin, boolean shrink) {
                throw new IllegalArgumentException("synthetic-mutate-boom");
              }
            };
          }
        };

    String[] exceptionSummary = nativeRunAbiHarness(loadedEngineSoPath, throwingMutateManager);
    assertThat(exceptionSummary[2]).contains("FuzzTestAdapter.mutate");
    assertThat(exceptionSummary[2]).contains("synthetic-mutate-boom");
  }

  @Test
  public void realEngineWorkerSubprocess_executesListTestsDumpBinaryIdAndDumpSeeds()
      throws Exception {
    Path tmpDir = Files.createTempDirectory(Path.of("/tmp"), "fuzztest_java_engine_test_");
    try {
      Path binaryIdFile = tmpDir.resolve("binary_id.txt");
      assertThat(runHelperSubprocess(":dump_binary_id:binary_id_output=" + binaryIdFile + ":"))
          .isEqualTo(0);
      assertThat(Files.readString(binaryIdFile, StandardCharsets.UTF_8))
          .isEqualTo("subproc/WorkerTarget");

      Path testListFile = tmpDir.resolve("tests.txt");
      assertThat(runHelperSubprocess(":list_tests:test_listing_output=" + testListFile + ":"))
          .isEqualTo(0);
      assertThat(Files.readString(testListFile, StandardCharsets.UTF_8).trim())
          .isEqualTo("com.example.SubprocTest.targetProp");

      Path seedsDir = tmpDir.resolve("seeds");
      Files.createDirectories(seedsDir);
      assertThat(
              runHelperSubprocess(
                  ":dump_seed_inputs:min_seeds=4:test=com.example.SubprocTest.targetProp:arg1="
                      + seedsDir
                      + ":"))
          .isEqualTo(0);

      List<Path> dumpedSeeds = new ArrayList<>();
      try (DirectoryStream<Path> ds = Files.newDirectoryStream(seedsDir)) {
        for (Path p : ds) {
          dumpedSeeds.add(p);
        }
      }
      assertThat(dumpedSeeds).hasSize(4);
      for (Path seedFile : dumpedSeeds) {
        assertThat(Files.size(seedFile)).isGreaterThan(0L);
      }
    } finally {
      deleteRecursively(tmpDir);
    }
  }

  /** Subprocess entrypoint exercised by {@link #realEngineWorkerSubprocess_executesListTestsDumpBinaryIdAndDumpSeeds}. */
  public static void main(String[] args) {
    AtomicBoolean closed = new AtomicBoolean();
    FuzzTestEngine.WorkerStatus status =
        FuzzTestEngine.maybeRunWorker(
            new FuzzTestAdapterManager() {
              @Override
              public String binaryId() {
                return "subproc/WorkerTarget";
              }

              @Override
              public String testName() {
                return "com.example.SubprocTest.targetProp";
              }

              @Override
              public FuzzTestAdapter constructAdapter(DiagnosticSink sink) {
                return new RecordingToyAdapter(sink, closed);
              }
            });
    if (status != FuzzTestEngine.WorkerStatus.SUCCESS) {
      throw new AssertionError("Expected WorkerStatus.SUCCESS, got " + status);
    }
  }

  private static int runHelperSubprocess(String centipedeRunnerFlags)
      throws IOException, InterruptedException {
    String javaBin = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    String classPath = System.getProperty("java.class.path");
    ProcessBuilder pb =
        new ProcessBuilder(javaBin, "-cp", classPath, FuzzTestEngineTest.class.getName())
            .inheritIO();
    pb.environment().put("CENTIPEDE_RUNNER_FLAGS", centipedeRunnerFlags);
    return pb.start().waitFor();
  }

  private static Path findRunfilesLibrary(String fileName) throws IOException {
    String testSrcdir = System.getenv("TEST_SRCDIR");
    if (testSrcdir == null || testSrcdir.isEmpty()) {
      throw new IllegalStateException("TEST_SRCDIR is not set");
    }
    String[] relDirs = {"third_party/googlefuzztest/java/engine", "java/engine"};
    Path base = Path.of(testSrcdir);
    List<Path> roots = new ArrayList<>();
    roots.add(base);
    try (DirectoryStream<Path> children = Files.newDirectoryStream(base)) {
      for (Path child : children) {
        if (Files.isDirectory(child)) {
          roots.add(child);
        }
      }
    }
    for (Path root : roots) {
      for (String relDir : relDirs) {
        Path candidate = root.resolve(relDir).resolve(fileName);
        if (Files.isRegularFile(candidate)) {
          return candidate.toAbsolutePath();
        }
      }
    }
    throw new IllegalStateException("Failed to find " + fileName + " under " + testSrcdir);
  }

  private static void deleteRecursively(Path dir) throws IOException {
    if (!Files.exists(dir)) {
      return;
    }
    try (var stream = Files.walk(dir)) {
      for (Path p : stream.sorted((a, b) -> b.compareTo(a)).toList()) {
        Files.deleteIfExists(p);
      }
    }
  }

  private static native String[] nativeRunAbiHarness(
      String engineSoPath, FuzzTestAdapterManager manager);

  private static class RecordingToyAdapter implements FuzzTestAdapter {
    private final DiagnosticSink sink;
    private final AtomicBoolean closed;
    private final Map<Long, byte[]> inputs = new HashMap<>();
    private final Map<Long, byte[]> metadata = new HashMap<>();
    private long nextHandle = 1L;

    RecordingToyAdapter(DiagnosticSink sink, AtomicBoolean closed) {
      this.sink = sink;
      this.closed = closed;
    }

    private long alloc(String text) {
      long h = nextHandle++;
      inputs.put(h, text.getBytes(StandardCharsets.UTF_8));
      return h;
    }

    @Override
    public void setUpCoverageDomains(CoverageDomainRegistry registry) {
      registry.register(1, "jvm_pcs", 27, 0);
      registry.register(6, "jvm_cmp_moddiff", 21, 6);
    }

    @Override
    public long[] presetSeedInputs() {
      return new long[] {alloc("preset-0"), alloc("preset-1")};
    }

    @Override
    public long randomSeedInput() {
      return alloc("seed-" + nextHandle);
    }

    @Override
    public long mutate(long origin, boolean shrink) {
      String base = new String(inputs.get(origin), StandardCharsets.UTF_8);
      return alloc(shrink ? "shrunk" : base + "-mutated");
    }

    @Override
    public long crossOver(long origin, long other) {
      String a = new String(inputs.get(origin), StandardCharsets.UTF_8);
      String b = new String(inputs.get(other), StandardCharsets.UTF_8);
      return alloc(a + "+" + b);
    }

    @Override
    public long[] execute(long input) {
      String s = new String(inputs.get(input), StandardCharsets.UTF_8);
      metadata.put(input, ("meta:" + s).getBytes(StandardCharsets.UTF_8));
      if (s.equals("seed-3")) {
        sink.emitWarning("sample-warning");
      }
      if (s.endsWith("-mutated")) {
        sink.emitFinding("found-bug-on-mutated", "SIG:mutated");
      }
      return new long[] {(1L << 59) | (42L << 32)};
    }

    @Override
    public byte[] serializeInputContent(long input) {
      return inputs.get(input).clone();
    }

    @Override
    public long deserializeInputContent(byte[] content) {
      long h = nextHandle++;
      inputs.put(h, content.clone());
      return h;
    }

    @Override
    public byte[] serializeInputMetadata(long input) {
      byte[] m = metadata.get(input);
      return m == null ? new byte[0] : m.clone();
    }

    @Override
    public void updateInputMetadata(byte[] meta, long input) {
      metadata.put(input, meta.clone());
    }

    @Override
    public void freeInput(long input) {
      if (inputs.remove(input) == null) {
        throw new IllegalArgumentException("Double or invalid freeInput: " + input);
      }
      metadata.remove(input);
    }

    @Override
    public void close() {
      if (!inputs.isEmpty()) {
        throw new IllegalStateException("Leaked handles at close(): " + inputs.keySet());
      }
      closed.set(true);
    }
  }
}
