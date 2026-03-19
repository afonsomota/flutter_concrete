/// Integration test for CiphertextFormat.CONCRETE encrypt/serialize layer.
///
/// Tests the new CONCRETE LWE functions without keygen (keygen has a
/// pre-existing parameter mismatch issue with the Concrete compiler's
/// chosen GLWE dimensions vs. the V0_10 parameter set).
///
/// Requires:
///   1. libfhe_client.so built and on LD_LIBRARY_PATH
///   2. client.zip from a CONCRETE-format model
///
/// Run with:
///   LD_LIBRARY_PATH=rust/target/debug flutter test test/integration_test.dart

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/client_zip_parser.dart';
import 'package:flutter_concrete/src/concrete_cipher_info.dart';
import 'package:flutter_concrete/src/fhe_native.dart';

void main() {
  late Uint8List clientZipBytes;
  late FheNative native;

  setUpAll(() {
    final candidates = [
      '${Directory.current.parent.path}/journal_app/assets/fhe/client.zip',
      '../journal_app/assets/fhe/client.zip',
    ];
    for (final path in candidates) {
      final file = File(path);
      if (file.existsSync()) {
        clientZipBytes = file.readAsBytesSync();
        native = FheNative();
        return;
      }
    }
    fail('client.zip not found');
  });

  test('parses CONCRETE format ConcreteCipherInfo from client.zip', () {
    final result = ClientZipParser.parse(clientZipBytes);

    // Input
    final inputInfo = result.inputCipherInfo;
    expect(inputInfo, isNotNull);
    expect(inputInfo!.compression, ConcreteCipherCompression.seed);
    expect(inputInfo.isNativeMode, isTrue);
    expect(inputInfo.encodingWidth, 3);
    expect(inputInfo.encodingIsSigned, isFalse);
    expect(inputInfo.lweDimension, 2048);
    expect(inputInfo.concreteShape, [1, 50, 3]);
    expect(inputInfo.abstractShape, [1, 50]);

    // Output
    final outputInfo = result.outputCipherInfo;
    expect(outputInfo, isNotNull);
    expect(outputInfo!.compression, ConcreteCipherCompression.none);
    expect(outputInfo.isNativeMode, isTrue);
    expect(outputInfo.encodingWidth, 3);
    expect(outputInfo.encodingIsSigned, isTrue);
    expect(outputInfo.lweDimension, 2048);
    print('ConcreteCipherInfo parsing: OK');
  });

  test('CONCRETE: serialize → deserialize Value round-trip via FFI', () {
    final result = ClientZipParser.parse(clientZipBytes);
    final inputInfo = result.inputCipherInfo!;

    // Create fake seeded ciphertext data: 16 seed + 50*3 b-values
    final nCts = 50 * 3;
    final fakeCtData = Uint8List(16 + nCts * 8);
    // Fill with recognizable pattern
    for (int i = 0; i < fakeCtData.length; i++) {
      fakeCtData[i] = i % 256;
    }

    // Serialize
    final serialized = native.serializeValue(
      fakeCtData, inputInfo.concreteShape, inputInfo.abstractShape,
      inputInfo.encodingWidth, inputInfo.encodingIsSigned,
      inputInfo.lweDimension, inputInfo.keyId, inputInfo.variance,
      1, // seed compression
    );
    print('Serialized: ${serialized.length} bytes');
    expect(serialized.length, greaterThan(fakeCtData.length));

    // Deserialize
    final (recovered, recoveredNcts) = native.deserializeValue(serialized);
    expect(recovered, fakeCtData);
    expect(recoveredNcts, 50); // product of shape[0..2] = 1*50
    print('Value serialize/deserialize round-trip: OK');
  });
}
