/// Encrypt-decrypt roundtrip tests (no server required).
///
/// Validates that Dart FFI lweEncryptSeeded and lweDecryptFull are proper
/// inverses: encrypting quantized+offset integers and decrypting them yields
/// back the same integers exactly.
///
/// For each fixture model with CONCRETE format:
///   1. Parse client.zip -> ConcreteCipherInfo, QuantizationParams
///   2. Load pre-generated secret key from fixture
///   3. Take float input from reference.json -> quantize -> apply input offsets
///   4. Encrypt via lweEncryptSeeded
///   5. Decrypt via lweDecryptFull
///   6. Assert decrypted integers exactly match pre-encrypt values
///
/// This is deterministic (no server, no MLIR) so results must be exact.
///
/// Requires:
///   1. Native library built: `cd rust && cargo build`
///   2. Fixture models generated: `cd test/fixtures && python generate_models.py`
///
/// Run with:
///   # macOS
///   DYLD_LIBRARY_PATH=rust/target/debug flutter test test/encrypt_decrypt_roundtrip_test.dart -t integration
///   # Linux
///   LD_LIBRARY_PATH=rust/target/debug flutter test test/encrypt_decrypt_roundtrip_test.dart -t integration
@Tags(['integration'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/client_zip_parser.dart';
import 'package:flutter_concrete/src/fhe_native.dart';

void testEncryptDecryptRoundtrip(String dirName) {
  group('$dirName encrypt-decrypt roundtrip', () {
    late ParseResult parseResult;
    late Map<String, dynamic> reference;
    late FheNative native;
    late Uint8List secretKey;
    bool hasFixture = false;

    setUpAll(() {
      final dir = Directory('test/fixtures/$dirName');
      if (!dir.existsSync()) {
        return;
      }

      final clientZipFile = File('${dir.path}/client.zip');
      final referenceFile = File('${dir.path}/reference.json');
      final secretKeyFile = File('${dir.path}/secret_key.bin');

      if (!clientZipFile.existsSync() ||
          !referenceFile.existsSync() ||
          !secretKeyFile.existsSync()) {
        return;
      }

      final clientZipBytes = clientZipFile.readAsBytesSync();
      reference =
          jsonDecode(referenceFile.readAsStringSync()) as Map<String, dynamic>;
      parseResult = ClientZipParser.parse(Uint8List.fromList(clientZipBytes));

      // Only test CONCRETE format models
      if (parseResult.inputCipherInfo == null) {
        return;
      }

      native = FheNative();
      secretKey = secretKeyFile.readAsBytesSync();
      hasFixture = true;
    });

    test('quantize+offset -> encrypt -> decrypt yields same integers', () {
      if (!hasFixture) {
        markTestSkipped(
            '$dirName: fixture files missing or not CONCRETE format');
        return;
      }

      final inputInfo = parseResult.inputCipherInfo!;
      final testVectors = reference['test_vectors'] as List<dynamic>;

      for (final vec in testVectors) {
        final description = vec['description'] as String;

        // Quantize float input (same as python_equivalence_test)
        final inputFloat = Float32List.fromList(
          (vec['input_float'] as List<dynamic>)
              .map((v) => (v as num).toDouble())
              .toList(),
        );
        final quantized = parseResult.quantParams.quantizeInputs(inputFloat);

        // Apply input offsets (shifts signed values to unsigned range for
        // the FHE circuit, same as ConcreteClient.quantizeAndEncrypt)
        final toEncrypt = parseResult.quantParams.applyInputOffsets(quantized);

        // Encrypt via seeded LWE
        final ctRaw = native.lweEncryptSeeded(
          secretKey,
          toEncrypt,
          inputInfo.concreteShape.last, // bitsPerValue
          inputInfo.lweDimension,
          inputInfo.variance,
        );

        // Decrypt seeded ciphertexts directly (expands seed internally).
        // Always unsigned: input offsets shift values to non-negative range.
        final decrypted = native.lweDecryptSeeded(
          secretKey,
          ctRaw,
          toEncrypt.length,
          inputInfo.concreteShape.last, // bitsPerValue, same as encrypt
          false, // unsigned — offset values are always non-negative
          inputInfo.lweDimension,
        );

        // The decrypted integers must exactly match the pre-encrypt values.
        // This is deterministic — no server or MLIR involved.
        expect(decrypted.length, toEncrypt.length,
            reason: 'Length mismatch for "$description": '
                'decrypted ${decrypted.length} vs expected ${toEncrypt.length}');

        for (int i = 0; i < toEncrypt.length; i++) {
          expect(decrypted[i], toEncrypt[i],
              reason: 'Mismatch at index $i for "$description": '
                  'decrypted=${decrypted[i]}, expected=${toEncrypt[i]}');
        }

        // ignore: avoid_print
        print(
            '  [$description] roundtrip OK: ${toEncrypt.length} values match');
      }
    });
  });
}

void main() {
  testEncryptDecryptRoundtrip('xgb_classifier_multiclass');
  testEncryptDecryptRoundtrip('xgb_classifier_binary');
  testEncryptDecryptRoundtrip('random_forest_classifier');
  testEncryptDecryptRoundtrip('decision_tree_classifier');
  testEncryptDecryptRoundtrip('xgb_regressor');
  testEncryptDecryptRoundtrip('random_forest_regressor');
  testEncryptDecryptRoundtrip('logistic_regression');
  testEncryptDecryptRoundtrip('linear_regression');
}
