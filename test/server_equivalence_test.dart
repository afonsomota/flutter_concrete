/// Cross-client FHE server inference equivalence tests.
///
/// Two test modes per model:
///
/// **Test A: "exact decrypt — Python-encrypted input"**
///   Uses the Python-encrypted ciphertext (saved in reference.json) so that
///   encryption randomness is identical.  Sends it to the Python FHEModelServer,
///   then Dart decrypts with the shared secret key.  Scores must match to 1e-4.
///
/// **Test B: "Dart encrypt → server → decrypt matches prediction"**
///   Dart encrypts with fresh randomness, so raw scores will differ.  For
///   classifiers the argmax (predicted class) must match; for regressors the
///   sign must match and relative error must be < 50 %.
///
/// Requires:
///   1. libfhe_client built: `cd rust && cargo build`
///   2. Python 3 with concrete-ml == 1.9.0 on PATH
///   3. Fixture models generated: `cd test/fixtures && python generate_models.py`
///      (each fixture must contain client.zip, server.zip, and reference.json
///       with python_fhe_scores and encrypted_input_b64)
///
/// Run with:
///   # macOS
///   DYLD_LIBRARY_PATH=rust/target/debug flutter test test/server_equivalence_test.dart -t server_equivalence
///   # Linux
///   LD_LIBRARY_PATH=rust/target/debug flutter test test/server_equivalence_test.dart -t server_equivalence
@Tags(['integration', 'server_equivalence'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/client_zip_parser.dart';
import 'package:flutter_concrete/src/concrete_cipher_info.dart';
import 'package:flutter_concrete/src/fhe_native.dart';
import 'package:flutter_concrete/src/post_processing.dart';

/// Run the Python fhe_server_helper.py subprocess to perform FHE inference.
///
/// Returns the encrypted result bytes from server.run().
Future<Uint8List> runServerInference({
  required String serverDir,
  required String evalKeyB64,
  required String encryptedInputB64,
}) async {
  final process = await Process.start('python3', [
    'test/fixtures/fhe_server_helper.py',
  ]);

  final request = jsonEncode({
    'server_dir': serverDir,
    'evaluation_key_b64': evalKeyB64,
    'encrypted_input_b64': encryptedInputB64,
  });

  process.stdin.write(request);
  await process.stdin.close();

  final stdout = await process.stdout.transform(utf8.decoder).join();
  final stderr = await process.stderr.transform(utf8.decoder).join();
  final exitCode = await process.exitCode;

  // Parse stdout first — the Python concrete-ml native library may crash with
  // SIGABRT (exit -6) during process cleanup AFTER writing valid JSON output.
  // The crash may append garbage after the JSON line, so try the first line
  // if full-string parsing fails (Python's print() outputs one line).
  Map<String, dynamic>? response;
  try {
    response = jsonDecode(stdout) as Map<String, dynamic>;
  } on FormatException {
    // stdout may contain valid JSON on the first line followed by crash output.
    final firstLine = stdout.split('\n').first.trim();
    if (firstLine.isNotEmpty) {
      try {
        response = jsonDecode(firstLine) as Map<String, dynamic>;
      } on FormatException {
        // still not valid JSON
      }
    }
  }

  if (response != null && response['status'] == 'ok') {
    // Process may have crashed during cleanup (SIGABRT) after writing valid
    // output — accept the result regardless of exit code.
    return Uint8List.fromList(
        base64Decode(response['encrypted_result_b64'] as String));
  }

  // Truncate stdout in error messages — ciphertext base64 can be huge.
  final stdoutPreview = stdout.length > 500
      ? '${stdout.substring(0, 500)}...(truncated, ${stdout.length} chars)'
      : stdout;

  if (exitCode != 0) {
    fail('fhe_server_helper.py crashed (exit $exitCode).\n'
        'stdout: $stdoutPreview\nstderr: $stderr');
  }

  if (response == null) {
    fail('fhe_server_helper.py produced invalid JSON.\nstdout: $stdoutPreview');
  }

  fail('fhe_server_helper.py error: ${response['error']}');
}

int _argmax(List<double> values) {
  int idx = 0;
  for (int i = 1; i < values.length; i++) {
    if (values[i] > values[idx]) idx = i;
  }
  return idx;
}

/// Whether this model is a classifier (multiple output scores).
bool _isClassifier(Map<String, dynamic> reference) {
  final nClasses = reference['n_classes'] as int? ?? 0;
  return nClasses > 0;
}

void testServerEquivalence(String dirName) {
  group('$dirName server equivalence', () {
    late Uint8List clientZipBytes;
    late ParseResult parseResult;
    late Map<String, dynamic> reference;
    late FheNative native;
    late KeygenResult keyResult;
    bool hasServerZip = false;
    bool hasKeys = false;

    setUpAll(() {
      final dir = Directory('test/fixtures/$dirName');
      if (!dir.existsSync()) {
        fail('Fixture directory not found: ${dir.path}');
      }

      final serverZipFile = File('${dir.path}/server.zip');
      hasServerZip = serverZipFile.existsSync();
      if (!hasServerZip) return;

      final clientZipFile = File('${dir.path}/client.zip');
      final referenceFile = File('${dir.path}/reference.json');

      clientZipBytes = clientZipFile.readAsBytesSync();
      reference =
          jsonDecode(referenceFile.readAsStringSync()) as Map<String, dynamic>;
      parseResult = ClientZipParser.parse(Uint8List.fromList(clientZipBytes));

      // Skip if this fixture lacks CONCRETE cipher info (TFHE-RS only)
      if (parseResult.inputCipherInfo == null) {
        return;
      }

      // Load pre-generated keys (produced by generate_models.py) so that
      // both tests share the same key material.
      final secretKeyFile = File('test/fixtures/$dirName/secret_key.bin');
      final evalKeyFile = File('test/fixtures/$dirName/eval_key.bin');
      if (!secretKeyFile.existsSync() || !evalKeyFile.existsSync()) {
        return; // Will be caught by the test with markTestSkipped
      }

      native = FheNative();
      final clientKey = secretKeyFile.readAsBytesSync();
      final serverKey = evalKeyFile.readAsBytesSync();
      keyResult = KeygenResult(clientKey: clientKey, serverKey: serverKey);
      hasKeys = true;
    });

    // ------------------------------------------------------------------
    // Test A: exact decrypt — Python-encrypted input
    // ------------------------------------------------------------------
    test('exact decrypt — Python-encrypted input', () async {
      if (!hasServerZip) {
        markTestSkipped('$dirName: server.zip not found (LLVM compilation '
            'may have failed). Regenerate fixtures to include this model.');
        return;
      }
      if (!hasKeys) {
        markTestSkipped('$dirName: secret_key.bin or eval_key.bin not found. '
            'Regenerate fixtures with generate_models.py to include keys.');
        return;
      }
      final outputInfo = parseResult.outputCipherInfo;
      if (parseResult.inputCipherInfo == null || outputInfo == null) {
        markTestSkipped('$dirName: missing CONCRETE cipher info');
        return;
      }

      final testVectors = reference['test_vectors'] as List<dynamic>;
      final serverDir = Directory('test/fixtures/$dirName').absolute.path;

      for (final vec in testVectors) {
        final pythonFheScores = vec['python_fhe_scores'] as List<dynamic>?;
        if (pythonFheScores == null) {
          fail('python_fhe_scores missing for "${vec['description']}". '
              'Regenerate fixtures.');
        }
        final encryptedInputB64 = vec['encrypted_input_b64'] as String?;
        if (encryptedInputB64 == null) {
          fail('encrypted_input_b64 missing for "${vec['description']}". '
              'Regenerate fixtures with updated generate_models.py.');
        }

        final description = vec['description'] as String;

        // Send Python's encrypted input directly to server
        final encryptedResult = await runServerInference(
          serverDir: serverDir,
          evalKeyB64: base64Encode(keyResult.serverKey),
          encryptedInputB64: encryptedInputB64,
        );

        // Decrypt via Rust FFI
        final (ctData, nCts) = native.deserializeValue(encryptedResult);
        final rawScores = native.lweDecryptFull(
          keyResult.clientKey,
          ctData,
          nCts,
          outputInfo.encodingWidth,
          outputInfo.encodingIsSigned,
          outputInfo.lweDimension,
        );

        // Dequantize + post-process (same as ConcreteClient.decryptAndDequantize)
        final dequantized =
            parseResult.quantParams.dequantizeOutputs(rawScores);
        final pp = resolveAuto(parseResult.modelClassName);
        final outputShape = (reference['output_shape'] as List<dynamic>)
            .map((v) => (v as num).toInt())
            .toList();
        final dartScores = pp.apply(dequantized, outputShape);

        final expectedScores =
            pythonFheScores.map((v) => (v as num).toDouble()).toList();

        // Compare exact scores (same encryption randomness → same result)
        expect(dartScores.length, expectedScores.length,
            reason: 'Score length mismatch for "$description"');

        for (int i = 0; i < dartScores.length; i++) {
          expect(dartScores[i], closeTo(expectedScores[i], 1e-4),
              reason: 'Score[$i] mismatch for "$description": '
                  'dart=${dartScores[i]}, python=${expectedScores[i]}');
        }
      }
    }, timeout: const Timeout(Duration(minutes: 10)));

    // ------------------------------------------------------------------
    // Test B: Dart encrypt → server → decrypt matches prediction
    // ------------------------------------------------------------------
    test('Dart encrypt → server → decrypt matches prediction', () async {
      if (!hasServerZip) {
        markTestSkipped('$dirName: server.zip not found (LLVM compilation '
            'may have failed). Regenerate fixtures to include this model.');
        return;
      }
      if (!hasKeys) {
        markTestSkipped('$dirName: secret_key.bin or eval_key.bin not found. '
            'Regenerate fixtures with generate_models.py to include keys.');
        return;
      }
      final inputInfo = parseResult.inputCipherInfo;
      final outputInfo = parseResult.outputCipherInfo;
      if (inputInfo == null || outputInfo == null) {
        markTestSkipped('$dirName: missing CONCRETE cipher info');
        return;
      }

      final testVectors = reference['test_vectors'] as List<dynamic>;
      final serverDir = Directory('test/fixtures/$dirName').absolute.path;
      final isClassifier = _isClassifier(reference);

      for (final vec in testVectors) {
        final pythonFheScores = vec['python_fhe_scores'] as List<dynamic>?;
        if (pythonFheScores == null) {
          fail('python_fhe_scores missing for "${vec['description']}". '
              'Regenerate fixtures.');
        }

        final description = vec['description'] as String;

        // Use the same quantized input as the Python reference
        final quantized = Int64List.fromList(
          (vec['quantized_input'] as List<dynamic>)
              .map((v) => (v as num).toInt())
              .toList(),
        );

        // Encrypt via Rust FFI (fresh encryption randomness)
        final ctRaw = native.lweEncryptSeeded(
          keyResult.clientKey,
          quantized,
          inputInfo.concreteShape.last,
          inputInfo.lweDimension,
          inputInfo.variance,
        );
        final encrypted = native.serializeValue(
          ctRaw,
          inputInfo.concreteShape,
          inputInfo.abstractShape,
          inputInfo.encodingWidth,
          inputInfo.encodingIsSigned,
          inputInfo.lweDimension,
          inputInfo.keyId,
          inputInfo.variance,
          inputInfo.compression == ConcreteCipherCompression.seed ? 1 : 0,
        );

        // Run FHE inference via Python subprocess
        final encryptedResult = await runServerInference(
          serverDir: serverDir,
          evalKeyB64: base64Encode(keyResult.serverKey),
          encryptedInputB64: base64Encode(encrypted),
        );

        // Decrypt via Rust FFI
        final (ctData, nCts) = native.deserializeValue(encryptedResult);
        final rawScores = native.lweDecryptFull(
          keyResult.clientKey,
          ctData,
          nCts,
          outputInfo.encodingWidth,
          outputInfo.encodingIsSigned,
          outputInfo.lweDimension,
        );

        // Dequantize + post-process (same as ConcreteClient.decryptAndDequantize)
        final dequantized =
            parseResult.quantParams.dequantizeOutputs(rawScores);
        final pp = resolveAuto(parseResult.modelClassName);
        final outputShape = (reference['output_shape'] as List<dynamic>)
            .map((v) => (v as num).toInt())
            .toList();
        final dartScores = pp.apply(dequantized, outputShape);

        final expectedScores =
            pythonFheScores.map((v) => (v as num).toDouble()).toList();

        expect(dartScores.length, expectedScores.length,
            reason: 'Score length mismatch for "$description"');

        if (isClassifier) {
          // Classifier: argmax prediction must match
          expect(_argmax(dartScores.toList()), _argmax(expectedScores),
              reason: 'Prediction (argmax) mismatch for "$description": '
                  'dart=$dartScores, python=$expectedScores');
        } else {
          // Regressor: sign must match and relative error < 50%
          for (int i = 0; i < dartScores.length; i++) {
            final dartVal = dartScores[i];
            final pyVal = expectedScores[i];

            // Sign check (treat near-zero as matching)
            if (pyVal.abs() > 1e-6 && dartVal.abs() > 1e-6) {
              expect(dartVal.sign, pyVal.sign,
                  reason: 'Sign mismatch for "$description" score[$i]: '
                      'dart=$dartVal, python=$pyVal');
            }

            // Relative error check
            final denom = pyVal.abs() > 1e-6 ? pyVal.abs() : 1.0;
            final relError = (dartVal - pyVal).abs() / denom;
            expect(relError, lessThan(0.5),
                reason: 'Relative error too large for "$description" '
                    'score[$i]: dart=$dartVal, python=$pyVal, '
                    'relError=$relError (> 50%)');
          }
        }
      }
    }, timeout: const Timeout(Duration(minutes: 10)));
  });
}

void main() {
  // Python with concrete-ml is required — fail hard if missing
  setUpAll(() {
    try {
      final result = Process.runSync('python3', ['-c', 'import concrete.ml']);
      if (result.exitCode != 0) {
        fail('concrete-ml not available. '
            'Install with: pip install -r test/fixtures/requirements.txt\n'
            'stderr: ${result.stderr}');
      }
    } on ProcessException {
      fail('python3 not found on PATH');
    }
  });

  testServerEquivalence('xgb_classifier_multiclass');
  testServerEquivalence('xgb_classifier_binary');
  testServerEquivalence('random_forest_classifier');
  testServerEquivalence('decision_tree_classifier');
  testServerEquivalence('xgb_regressor');
  testServerEquivalence('random_forest_regressor');
  testServerEquivalence('logistic_regression');
  testServerEquivalence('linear_regression');
}
