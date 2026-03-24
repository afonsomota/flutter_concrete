/// Integration test requiring a running backend on localhost:8000.
///
/// Requires:
///   1. libfhe_client.so built and on LD_LIBRARY_PATH
///   2. client.zip from a CONCRETE-format model
///   3. Backend running on localhost:8000
///
/// Run with:
///   LD_LIBRARY_PATH=rust/target/debug flutter test test/integration_backend_test.dart
@Tags(['integration', 'backend'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/client_zip_parser.dart';
import 'package:flutter_concrete/src/fhe_native.dart';

void main() {
  late Uint8List clientZipBytes;
  late FheNative native;

  setUpAll(() {
    clientZipBytes = File('test/fixtures/client.zip').readAsBytesSync();
    native = FheNative();
  });

  test('CONCRETE: keygen + encrypt + backend + decrypt', () async {
    final result = ClientZipParser.parse(clientZipBytes);
    final inputInfo = result.inputCipherInfo!;
    final outputInfo = result.outputCipherInfo!;

    // 1. Generate keys from topology

    final keyResult = native.keygen(result.topology.pack());
    final clientKey = keyResult.clientKey;

    // 2. Upload eval key to backend

    final httpClient = HttpClient();
    final keyReq =
        await httpClient.postUrl(Uri.parse('http://localhost:8000/fhe/key'));
    keyReq.headers.contentType = ContentType.json;
    keyReq.write(jsonEncode({
      'client_id': 'dart_integration_test',
      'evaluation_key_b64': base64Encode(keyResult.serverKey),
    }));
    final keyResp = await keyReq.close();
    await keyResp.drain<void>();

    expect(keyResp.statusCode, 200);

    // 3. Encrypt test input (50 features, 3-bit values 0-7)
    final quantized = Int64List(inputInfo.abstractShape.last);
    for (int i = 0; i < quantized.length; i++) {
      quantized[i] = i % 8;
    }

    final ctRaw = native.lweEncryptSeeded(
      clientKey,
      quantized,
      inputInfo.encodingWidth,
      inputInfo.lweDimension,
      inputInfo.variance,
    );
    final encrypted = native.serializeValue(
      ctRaw, inputInfo.concreteShape, inputInfo.abstractShape,
      inputInfo.encodingWidth, inputInfo.encodingIsSigned,
      inputInfo.lweDimension, inputInfo.keyId, inputInfo.variance,
      1, // seed compression
    );

    // 4. Send to backend for FHE inference

    final predictReq = await httpClient
        .postUrl(Uri.parse('http://localhost:8000/fhe/predict'));
    predictReq.headers.contentType = ContentType.json;
    predictReq.write(jsonEncode({
      'client_id': 'dart_integration_test',
      'encrypted_input_b64': base64Encode(encrypted),
    }));
    final predictResp = await predictReq.close();
    final predictBody = await predictResp.transform(utf8.decoder).join();

    expect(predictResp.statusCode, 200,
        reason: 'Backend rejected ciphertext: $predictBody');

    final resultB64 = jsonDecode(predictBody)['encrypted_result_b64'] as String;
    final resultBytes = base64Decode(resultB64);

    // 5. Decrypt
    final (ctData, nCts) =
        native.deserializeValue(Uint8List.fromList(resultBytes));

    final rawScores = native.lweDecryptFull(
      clientKey,
      ctData,
      nCts,
      outputInfo.encodingWidth,
      outputInfo.encodingIsSigned,
      outputInfo.lweDimension,
    );

    // 6. Dequantize — nClasses comes from output abstractShape
    // abstractShape = [1, 5, 50] → nClasses=5, nTrees=50
    final nClasses = outputInfo.abstractShape[1];
    final nTrees = rawScores.length ~/ nClasses;

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

    final labels = ['anger', 'joy', 'neutral', 'sadness', 'surprise'];
    int maxIdx = 0;
    for (int i = 1; i < nClasses; i++) {
      if (scores[i] > scores[maxIdx]) maxIdx = i;
    }

    expect(labels[maxIdx], isNotEmpty); // sanity check

    httpClient.close();
  }, timeout: const Timeout(Duration(minutes: 15)));
}
