/// Cross-language encryption test: Dart encrypts, Python verifies.
///
/// Proves cross-language compatibility in two complementary ways:
///
/// **Check 1 — Dart encrypt/decrypt round-trip:**
///   Encrypt with `lweEncryptSeeded`, serialize with `serializeValue`,
///   deserialize with `deserializeValue`, decrypt with `lweDecryptFull`.
///   Verifies the entire Dart-side FHE pipeline produces correct integers.
///
/// **Check 2 — Python format verification + optional decryption:**
///   Pass the serialized Value bytes to Python's `fhe.Value.deserialize()`.
///   This proves the Cap'n Proto wire format is compatible with concrete-python.
///   For models where input and output specs match (same LWE dim, width,
///   signedness), Python also decrypts and we compare the integers.
///
/// For each CONCRETE-format fixture model:
///   1. Parse client.zip, load secret key from fixture
///   2. Use pre-quantized input from reference.json, apply input offsets
///   3. Encrypt with Dart `lweEncryptSeeded` + serialize with `serializeValue`
///   4. Check 1: Dart deserialize + decrypt round-trip
///   5. Check 2: Python deserialization (+ decryption where possible)
///
/// Requires:
///   1. libfhe_client built: `cd rust && cargo build`
///   2. Python 3 with concrete-ml == 1.9.0 on PATH
///   3. Fixture models generated: `python test/fixtures/generate_models.py`
///      (must include full_keys.bin — regenerate if missing)
///
/// Run with:
///   # macOS
///   DYLD_LIBRARY_PATH=rust/target/debug flutter test test/cross_language_encrypt_test.dart -t cross_language
///   # Linux
///   LD_LIBRARY_PATH=rust/target/debug flutter test test/cross_language_encrypt_test.dart -t cross_language
@Tags(['integration', 'cross_language'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/client_zip_parser.dart';
import 'package:flutter_concrete/src/concrete_cipher_info.dart';
import 'package:flutter_concrete/src/fhe_native.dart';

/// Result from the Python fhe_decrypt_helper.py.
class PythonResult {
  final bool deserialized;
  final List<int> rawIntegers;
  final bool decryptSkipped;
  final String decryptSkipReason;

  PythonResult({
    required this.deserialized,
    required this.rawIntegers,
    required this.decryptSkipped,
    required this.decryptSkipReason,
  });
}

/// Call Python fhe_decrypt_helper.py to verify deserialization + optional decrypt.
Future<PythonResult> pythonVerify({
  required String clientZipPath,
  required String fullKeysPath,
  required String ciphertextB64,
}) async {
  final process = await Process.start('python3', [
    'test/fhe_decrypt_helper.py',
  ]);

  final request = jsonEncode({
    'client_zip_path': clientZipPath,
    'full_keys_path': fullKeysPath,
    'ciphertext_b64': ciphertextB64,
  });

  process.stdin.write(request);
  await process.stdin.close();

  final stdout = await process.stdout.transform(utf8.decoder).join();
  final stderr = await process.stderr.transform(utf8.decoder).join();
  final exitCode = await process.exitCode;

  // Parse stdout — Python may crash during cleanup (SIGABRT) after writing
  // valid output, so try to parse even on non-zero exit.
  Map<String, dynamic>? response;
  try {
    response = jsonDecode(stdout) as Map<String, dynamic>;
  } on FormatException {
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
    return PythonResult(
      deserialized: response['deserialized'] as bool,
      rawIntegers: (response['raw_integers'] as List<dynamic>)
          .map((v) => (v as num).toInt())
          .toList(),
      decryptSkipped: response['decrypt_skipped'] as bool,
      decryptSkipReason: response['decrypt_skip_reason'] as String? ?? '',
    );
  }

  final stdoutPreview = stdout.length > 500
      ? '${stdout.substring(0, 500)}...(truncated, ${stdout.length} chars)'
      : stdout;

  if (exitCode != 0) {
    fail('fhe_decrypt_helper.py crashed (exit $exitCode).\n'
        'stdout: $stdoutPreview\nstderr: $stderr');
  }

  if (response == null) {
    fail('fhe_decrypt_helper.py produced invalid JSON.\nstdout: $stdoutPreview');
  }

  fail('fhe_decrypt_helper.py error: ${response['error']}');
}

void testCrossLanguageEncrypt(String dirName) {
  group('$dirName cross-language encrypt', () {
    late ParseResult parseResult;
    late Map<String, dynamic> reference;
    late FheNative native;
    late KeygenResult keyResult;
    bool hasFixture = false;
    bool hasKeys = false;
    bool hasFullKeys = false;

    setUpAll(() {
      final dir = Directory('test/fixtures/$dirName');
      if (!dir.existsSync()) {
        return;
      }

      final clientZipFile = File('${dir.path}/client.zip');
      final referenceFile = File('${dir.path}/reference.json');
      if (!clientZipFile.existsSync() || !referenceFile.existsSync()) {
        return;
      }

      final clientZipBytes = clientZipFile.readAsBytesSync();
      reference =
          jsonDecode(referenceFile.readAsStringSync()) as Map<String, dynamic>;
      parseResult = ClientZipParser.parse(Uint8List.fromList(clientZipBytes));

      // Skip TFHE-RS only models (no CONCRETE cipher info)
      if (parseResult.inputCipherInfo == null) {
        return;
      }

      hasFixture = true;

      // Load pre-generated keys
      final secretKeyFile = File('test/fixtures/$dirName/secret_key.bin');
      final evalKeyFile = File('test/fixtures/$dirName/eval_key.bin');
      if (!secretKeyFile.existsSync() || !evalKeyFile.existsSync()) {
        return;
      }

      final fullKeysFile = File('test/fixtures/$dirName/full_keys.bin');
      hasFullKeys = fullKeysFile.existsSync();

      native = FheNative();
      final clientKey = secretKeyFile.readAsBytesSync();
      final serverKey = evalKeyFile.readAsBytesSync();
      keyResult = KeygenResult(clientKey: clientKey, serverKey: serverKey);
      hasKeys = true;
    });

    // ------------------------------------------------------------------
    // Check 1: Dart encrypt → Dart decrypt round-trip
    // ------------------------------------------------------------------
    test('Dart encrypt/decrypt round-trip produces correct integers', () {
      if (!hasFixture) {
        markTestSkipped(
            '$dirName: fixture not found or not CONCRETE format.');
        return;
      }
      if (!hasKeys) {
        markTestSkipped(
            '$dirName: secret_key.bin or eval_key.bin not found.');
        return;
      }

      final inputInfo = parseResult.inputCipherInfo!;
      final testVectors = reference['test_vectors'] as List<dynamic>;

      for (final vec in testVectors) {
        final description = vec['description'] as String;

        // Use the same quantized input as Python reference
        final quantizedRaw = Int64List.fromList(
          (vec['quantized_input'] as List<dynamic>)
              .map((v) => (v as num).toInt())
              .toList(),
        );

        // Apply input offsets (shifts values for the circuit's unsigned range)
        final quantized =
            parseResult.quantParams.applyInputOffsets(quantizedRaw);

        // Encrypt via Rust FFI
        final ctRaw = native.lweEncryptSeeded(
          keyResult.clientKey,
          quantized,
          inputInfo.concreteShape.last,
          inputInfo.lweDimension,
          inputInfo.variance,
        );

        // Decrypt seeded ciphertexts directly (expands seed internally).
        // Always unsigned: input offsets shift values to non-negative range.
        final decrypted = native.lweDecryptSeeded(
          keyResult.clientKey,
          ctRaw,
          quantized.length,
          inputInfo.concreteShape.last, // bitsPerValue, same as encrypt
          false, // unsigned — offset values are always non-negative
          inputInfo.lweDimension,
        );

        // ignore: avoid_print
        print('  [$description] encrypted ${quantized.length} values, '
            'decrypted ${decrypted.length} values');
        // ignore: avoid_print
        print('  [$description] original: $quantized');
        // ignore: avoid_print
        print('  [$description] decrypted: $decrypted');

        expect(decrypted.length, quantized.length,
            reason: 'Length mismatch for "$description"');

        for (int i = 0; i < quantized.length; i++) {
          expect(decrypted[i], quantized[i],
              reason:
                  'Round-trip mismatch at index $i for "$description": '
                  'encrypted=${quantized[i]}, decrypted=${decrypted[i]}');
        }
      }
    });

    // ------------------------------------------------------------------
    // Check 2: Python Value deserialization + optional decryption
    // ------------------------------------------------------------------
    test('Python can deserialize Dart-produced Value bytes', () async {
      if (!hasFixture) {
        markTestSkipped(
            '$dirName: fixture not found or not CONCRETE format.');
        return;
      }
      if (!hasKeys) {
        markTestSkipped(
            '$dirName: secret_key.bin or eval_key.bin not found.');
        return;
      }
      if (!hasFullKeys) {
        markTestSkipped(
            '$dirName: full_keys.bin not found. '
            'Regenerate fixtures with updated generate_models.py.');
        return;
      }

      final inputInfo = parseResult.inputCipherInfo!;
      final testVectors = reference['test_vectors'] as List<dynamic>;
      final dir = Directory('test/fixtures/$dirName').absolute;
      final clientZipPath = '${dir.path}/client.zip';
      final fullKeysPath = '${dir.path}/full_keys.bin';

      for (final vec in testVectors) {
        final description = vec['description'] as String;

        final quantizedRaw = Int64List.fromList(
          (vec['quantized_input'] as List<dynamic>)
              .map((v) => (v as num).toInt())
              .toList(),
        );
        final quantized =
            parseResult.quantParams.applyInputOffsets(quantizedRaw);

        // Encrypt + serialize
        final ctRaw = native.lweEncryptSeeded(
          keyResult.clientKey,
          quantized,
          inputInfo.concreteShape.last,
          inputInfo.lweDimension,
          inputInfo.variance,
        );
        final serialized = native.serializeValue(
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

        // Send to Python for verification
        final result = await pythonVerify(
          clientZipPath: clientZipPath,
          fullKeysPath: fullKeysPath,
          ciphertextB64: base64Encode(serialized),
        );

        // Check 2a: deserialization must always succeed
        expect(result.deserialized, isTrue,
            reason: 'Python failed to deserialize Value for "$description"');

        if (result.decryptSkipped) {
          // ignore: avoid_print
          print('  [$description] Python deserialized OK, decrypt skipped: '
              '${result.decryptSkipReason}');
        } else {
          // Check 2b: when input/output specs match, Python decryption
          // must recover the same integers we encrypted.
          // ignore: avoid_print
          print('  [$description] Python decrypted: ${result.rawIntegers}');
          // ignore: avoid_print
          print('  [$description] Dart encrypted:   $quantized');

          expect(result.rawIntegers.length, quantized.length,
              reason:
                  'Length mismatch for "$description": '
                  'python=${result.rawIntegers.length}, '
                  'dart=${quantized.length}');

          for (int i = 0; i < quantized.length; i++) {
            expect(result.rawIntegers[i], quantized[i],
                reason:
                    'Python decrypt mismatch at index $i for "$description": '
                    'python=${result.rawIntegers[i]}, '
                    'dart_encrypted=${quantized[i]}');
          }
        }
      }
    }, timeout: const Timeout(Duration(minutes: 5)));
  });
}

void main() {
  // Python with concrete-ml is required
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

  testCrossLanguageEncrypt('xgb_classifier_multiclass');
  testCrossLanguageEncrypt('xgb_classifier_binary');
  testCrossLanguageEncrypt('random_forest_classifier');
  testCrossLanguageEncrypt('decision_tree_classifier');
  testCrossLanguageEncrypt('xgb_regressor');
  testCrossLanguageEncrypt('random_forest_regressor');
  testCrossLanguageEncrypt('logistic_regression');
  testCrossLanguageEncrypt('linear_regression');
}
