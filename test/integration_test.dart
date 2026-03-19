/// Integration test for CiphertextFormat.CONCRETE end-to-end flow.
///
/// Requires:
///   1. libfhe_client.so built and on LD_LIBRARY_PATH
///   2. client.zip from a CONCRETE-format model
///   3. Backend running on localhost:8000 (for HTTP test)
///
/// Run with:
///   LD_LIBRARY_PATH=rust/target/debug flutter test test/integration_test.dart

import 'dart:convert';
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

    // Deserialize — seed is stripped, so we get body only
    final (recovered, recoveredNcts) = native.deserializeValue(serialized);
    final expectedBody = fakeCtData.sublist(16); // body without seed
    expect(recovered, expectedBody);
    expect(recoveredNcts, 50); // product of shape[0..2] = 1*50
    print('Value serialize/deserialize round-trip: OK');
  });

  test('CONCRETE: keygen + encrypt + backend + decrypt', () async {
    final result = ClientZipParser.parse(clientZipBytes);
    final inputInfo = result.inputCipherInfo!;
    final outputInfo = result.outputCipherInfo!;

    // 1. Generate keys from topology
    print('Generating keys...');
    final keyResult = native.keygen(result.topology.pack());
    final clientKey = keyResult.clientKey;
    print('  clientKey: ${clientKey.length} bytes');
    print('  serverKey: ${keyResult.serverKey.length} bytes');

    // 2. Upload eval key to backend
    print('Uploading eval key...');
    final httpClient = HttpClient();
    final keyReq = await httpClient
        .postUrl(Uri.parse('http://localhost:8000/fhe/key'));
    keyReq.headers.contentType = ContentType.json;
    keyReq.write(jsonEncode({
      'client_id': 'dart_integration_test',
      'evaluation_key_b64': base64Encode(keyResult.serverKey),
    }));
    final keyResp = await keyReq.close();
    final keyBody = await keyResp.transform(utf8.decoder).join();
    print('  Key upload: ${keyResp.statusCode} $keyBody');
    expect(keyResp.statusCode, 200);

    // 3. Encrypt test input (50 features, 3-bit values 0-7)
    final quantized = Int64List(inputInfo.abstractShape.last);
    for (int i = 0; i < quantized.length; i++) {
      quantized[i] = i % 8;
    }

    final ctRaw = native.lweEncryptSeeded(
      clientKey, quantized,
      inputInfo.encodingWidth, inputInfo.lweDimension, inputInfo.variance,
    );
    final encrypted = native.serializeValue(
      ctRaw, inputInfo.concreteShape, inputInfo.abstractShape,
      inputInfo.encodingWidth, inputInfo.encodingIsSigned,
      inputInfo.lweDimension, inputInfo.keyId, inputInfo.variance,
      1, // seed compression
    );
    print('Encrypted input: ${encrypted.length} bytes');

    // 4. Send to backend for FHE inference
    print('Running FHE inference...');
    final predictReq = await httpClient
        .postUrl(Uri.parse('http://localhost:8000/fhe/predict'));
    predictReq.headers.contentType = ContentType.json;
    predictReq.write(jsonEncode({
      'client_id': 'dart_integration_test',
      'encrypted_input_b64': base64Encode(encrypted),
    }));
    final predictResp = await predictReq.close();
    final predictBody = await predictResp.transform(utf8.decoder).join();
    print('  Predict: ${predictResp.statusCode}');
    expect(predictResp.statusCode, 200,
        reason: 'Backend rejected ciphertext: $predictBody');

    final resultB64 =
        jsonDecode(predictBody)['encrypted_result_b64'] as String;
    final resultBytes = base64Decode(resultB64);
    print('  Result: ${resultBytes.length} bytes');

    // 5. Decrypt
    final (ctData, nCts) =
        native.deserializeValue(Uint8List.fromList(resultBytes));
    print('  Deserialized: nCts=$nCts');

    final rawScores = native.lweDecryptFull(
      clientKey, ctData, nCts,
      outputInfo.encodingWidth, outputInfo.encodingIsSigned,
      outputInfo.lweDimension,
    );
    print('  Decrypted ${rawScores.length} raw scores');

    // 6. Dequantize — nClasses comes from output abstractShape
    // abstractShape = [1, 5, 50] → nClasses=5, nTrees=50
    final nClasses = outputInfo.abstractShape[1];
    final nTrees = rawScores.length ~/ nClasses;
    print('  nClasses=$nClasses, nTrees=$nTrees');

    final p = result.quantParams.output;
    final scores = List<double>.filled(nClasses, 0.0);
    for (int c = 0; c < nClasses; c++) {
      double sum = 0.0;
      final base = c * nTrees;
      for (int t = 0; t < nTrees; t++) {
        sum += (rawScores[base + t] + p.offset - p.zeroPoint) * p.scale;
      }
      scores[c] = sum;
    }
    print('  Class scores: $scores');

    final labels = ['anger', 'joy', 'neutral', 'sadness', 'surprise'];
    int maxIdx = 0;
    for (int i = 1; i < nClasses; i++) {
      if (scores[i] > scores[maxIdx]) maxIdx = i;
    }
    print('  Prediction: ${labels[maxIdx]}');
    expect(labels[maxIdx], isNotEmpty); // sanity check

    httpClient.close();
    print('END-TO-END TEST PASSED');
  }, timeout: const Timeout(Duration(minutes: 15)));
}
