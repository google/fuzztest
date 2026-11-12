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

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * JNI worker entry points binding {@link FuzzTestAdapterManager} and {@link FuzzTestAdapter} to
 * {@code centipede/engine_worker_abi.h}.
 *
 * <p>The native worker library is loaded lazily inside {@link NativeHolder}'s static initializer so
 * {@code WorkerInitEarly} runs only when a worker entry point is invoked, and strictly before the
 * first native worker call.
 */
public final class FuzzTestEngine {

  private static final String JNI_LIBRARY_NAME = "fuzztest_java_engine_jni";
  private static final String[] RUNFILES_RELATIVE_SO_PATHS = {
    "third_party/googlefuzztest/java/engine/libfuzztest_java_engine_jni.so",
    "third_party/googlefuzztest/java/engine/libfuzztest_java_engine_jni.dylib",
    "java/engine/libfuzztest_java_engine_jni.so",
    "java/engine/libfuzztest_java_engine_jni.dylib",
  };

  /** Outcome of {@link #maybeRunWorker}, matching {@code FuzzTestWorkerStatus}. */
  public enum WorkerStatus {
    /** Worker completed its requested action without findings ({@code kFuzzTestWorkerSuccess}). */
    SUCCESS,
    /** Worker execution reported a finding ({@code kFuzzTestWorkerFailure}). */
    FAILURE,
    /** Process was not launched as a FuzzTest worker ({@code kFuzzTestWorkerNotRequired}). */
    NOT_REQUIRED
  }

  /**
   * Returns whether the current JVM process was launched with active FuzzTest worker flags ({@code
   * FuzzTestWorkerIsRequired}).
   */
  public static boolean isWorkerRequired() {
    return NativeHolder.nativeIsWorkerRequired();
  }

  /**
   * Runs the FuzzTest worker loop with {@code manager} when worker flags are active ({@code
   * FuzzTestWorkerMaybeRun}), or returns {@link WorkerStatus#NOT_REQUIRED} otherwise.
   */
  public static WorkerStatus maybeRunWorker(FuzzTestAdapterManager manager) {
    requireNonNull(manager, "manager");
    int status = NativeHolder.nativeMaybeRunWorker(manager);
    return switch (status) {
      case 0 -> WorkerStatus.SUCCESS;
      case 1 -> WorkerStatus.FAILURE;
      case 2 -> WorkerStatus.NOT_REQUIRED;
      default -> throw new IllegalStateException("Unexpected FuzzTestWorkerStatus: " + status);
    };
  }

  /** Packed coverage-domain descriptor marshaled across JNI during {@code SetUpCoverageDomains}. */
  static final class DomainRegistration {
    final int domainId;
    final byte[] nameUtf8;
    final int featureIdBitSize;
    final int counterBitSize;

    DomainRegistration(int domainId, byte[] nameUtf8, int featureIdBitSize, int counterBitSize) {
      this.domainId = domainId;
      this.nameUtf8 = nameUtf8;
      this.featureIdBitSize = featureIdBitSize;
      this.counterBitSize = counterBitSize;
    }
  }

  /** JNI-backed {@link DiagnosticSink} valid until {@code FreeCtx} invalidates its pointer. */
  static final class NativeDiagnosticSink implements DiagnosticSink {
    private volatile long nativePtr;

    NativeDiagnosticSink(long nativePtr) {
      this.nativePtr = nativePtr;
    }

    void invalidate() {
      this.nativePtr = 0L;
    }

    @Override
    public void emitError(String message) {
      requireNonNull(message, "message");
      long ptr = requireActivePtr();
      NativeHolder.nativeEmitError(ptr, message.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void emitWarning(String message) {
      requireNonNull(message, "message");
      long ptr = requireActivePtr();
      NativeHolder.nativeEmitWarning(ptr, message.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void emitFinding(String description, String signature) {
      requireNonNull(description, "description");
      requireNonNull(signature, "signature");
      long ptr = requireActivePtr();
      NativeHolder.nativeEmitFinding(
          ptr,
          description.getBytes(StandardCharsets.UTF_8),
          signature.getBytes(StandardCharsets.UTF_8));
    }

    private long requireActivePtr() {
      long ptr = this.nativePtr;
      if (ptr == 0L) {
        throw new IllegalStateException("DiagnosticSink used after FuzzTestAdapter FreeCtx");
      }
      return ptr;
    }
  }

  static byte[] binaryIdBytes(FuzzTestAdapterManager manager) {
    String id =
        requireNonNull(manager.binaryId(), "FuzzTestAdapterManager.binaryId() returned null");
    return id.getBytes(StandardCharsets.UTF_8);
  }

  static byte[] testNameBytes(FuzzTestAdapterManager manager) {
    String name =
        requireNonNull(manager.testName(), "FuzzTestAdapterManager.testName() returned null");
    return name.getBytes(StandardCharsets.UTF_8);
  }

  static FuzzTestAdapter constructAdapter(
      FuzzTestAdapterManager manager, NativeDiagnosticSink sink) {
    return requireNonNull(
        manager.constructAdapter(sink), "FuzzTestAdapterManager.constructAdapter() returned null");
  }

  static DomainRegistration[] collectCoverageDomains(FuzzTestAdapter adapter) {
    List<DomainRegistration> domains = new ArrayList<>();
    adapter.setUpCoverageDomains((domainId, name, featureIdBitSize, counterBitSize) -> {
      requireNonNull(name, "domain name");
      if (domainId < 0 || domainId >= 32) {
        throw new IllegalArgumentException("domainId out of 5-bit range [0, 31]: " + domainId);
      }
      if (featureIdBitSize < 0 || featureIdBitSize > 27) {
        throw new IllegalArgumentException(
            "featureIdBitSize out of range [0, 27]: " + featureIdBitSize);
      }
      if (counterBitSize < 0 || counterBitSize > 32) {
        throw new IllegalArgumentException(
            "counterBitSize out of range [0, 32]: " + counterBitSize);
      }
      domains.add(
          new DomainRegistration(
              domainId, name.getBytes(StandardCharsets.UTF_8), featureIdBitSize, counterBitSize));
    });
    return domains.toArray(new DomainRegistration[0]);
  }

  static byte[] formatThrowableUtf8(Throwable t) {
    try {
      StringWriter sw = new StringWriter(512);
      try (PrintWriter pw = new PrintWriter(sw)) {
        t.printStackTrace(pw);
      }
      return sw.toString().getBytes(StandardCharsets.UTF_8);
    } catch (Throwable _) {
      String fallback = "Java exception in FuzzTest adapter: " + t.getClass().getName();
      return fallback.getBytes(StandardCharsets.UTF_8);
    }
  }

  private static void loadNativeLibrary() {
    try {
      System.loadLibrary(JNI_LIBRARY_NAME);
      return;
    } catch (UnsatisfiedLinkError primaryError) {
      for (Path runfilesRoot : candidateRunfilesRoots()) {
        for (String relPath : RUNFILES_RELATIVE_SO_PATHS) {
          Path candidate = runfilesRoot.resolve(relPath);
          if (Files.isRegularFile(candidate)) {
            System.load(candidate.toAbsolutePath().toString());
            return;
          }
        }
      }
      throw primaryError;
    }
  }

  private static List<Path> candidateRunfilesRoots() {
    List<Path> roots = new ArrayList<>();
    String[] envKeys = {"TEST_SRCDIR", "RUNFILES_DIR", "JAVA_RUNFILES"};
    String workspace = System.getenv("TEST_WORKSPACE");
    for (String key : envKeys) {
      String dir = System.getenv(key);
      if (dir == null || dir.isEmpty()) {
        continue;
      }
      Path base = Path.of(dir);
      if (!Files.isDirectory(base)) {
        continue;
      }
      if (workspace != null && !workspace.isEmpty()) {
        addIfDirectory(roots, base.resolve(workspace));
      }
      addIfDirectory(roots, base);
      try (DirectoryStream<Path> children = Files.newDirectoryStream(base)) {
        for (Path child : children) {
          addIfDirectory(roots, child);
        }
      } catch (IOException _) {
        // Best-effort runfiles directory scan.
      }
    }
    return roots;
  }

  private static void addIfDirectory(List<Path> out, Path dir) {
    if (Files.isDirectory(dir) && !out.contains(dir)) {
      out.add(dir);
    }
  }

  /** Lazy holder whose {@code <clinit>} loads the JNI worker library on first worker access. */
  static final class NativeHolder {
    static {
      loadNativeLibrary();
    }

    static native boolean nativeIsWorkerRequired();

    static native int nativeMaybeRunWorker(FuzzTestAdapterManager manager);

    static native void nativeEmitError(long sinkPtr, byte[] messageUtf8);

    static native void nativeEmitWarning(long sinkPtr, byte[] messageUtf8);

    static native void nativeEmitFinding(
        long sinkPtr, byte[] descriptionUtf8, byte[] signatureUtf8);

    private NativeHolder() {}
  }

  private FuzzTestEngine() {}
}
