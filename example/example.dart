// ignore_for_file: avoid_print
import 'dart:typed_data';

import 'package:flutter_concrete/flutter_concrete.dart';

/// In-memory [KeyStorage] for demonstration purposes.
///
/// A real app should use secure storage (e.g. flutter_secure_storage).
class MemoryKeyStorage implements KeyStorage {
  final _store = <String, Uint8List>{};

  @override
  Future<Uint8List?> read(String key) async => _store[key];

  @override
  Future<void> write(String key, Uint8List value) async => _store[key] = value;

  @override
  Future<void> delete(String key) async => _store.remove(key);
}

Future<void> main() async {
  final client = ConcreteClient();
  final storage = MemoryKeyStorage();

  // 1. Load client.zip bytes (bundled as a Flutter asset in a real app).
  final clientZipBytes = Uint8List(0); // replace with actual bytes

  // 2. Setup: parses the zip, generates or restores TFHE-rs keys.
  await client.setup(clientZipBytes: clientZipBytes, storage: storage);
  print('Client ready: ${client.isReady}');

  // 3. Upload the evaluation key to your backend.
  final evalKeyBase64 = client.serverKeyBase64;
  print('Eval key length: ${evalKeyBase64.length} chars');

  // 4. Encrypt a feature vector for server-side FHE inference.
  //    The vector contents depend on your ML pipeline (e.g. embeddings,
  //    normalized sensor readings, tabular features, etc.).
  final features = Float32List.fromList([0.1, -0.3, 0.5]);
  final ciphertext = client.quantizeAndEncrypt(features);
  print('Ciphertext size: ${ciphertext.length} bytes');

  // 5. Send ciphertext to your backend, receive the encrypted result,
  //    then decrypt and dequantize.
  final encryptedResult = Uint8List(0); // replace with backend response

  // Auto post-processing (default): detected from model class in client.zip.
  print('Detected model: ${client.modelClassName}');
  print('Post-processing: ${client.detectedPostProcessing}');
  final scores = client.decryptAndDequantize(encryptedResult);
  print('Scores: $scores');

  // Explicit post-processing override:
  final rawScores = client.decryptAndDequantize(
    encryptedResult,
    postProcessing: const PostProcessing.none(),
  );
  print('Raw dequantized: $rawScores');

  // Custom post-processing:
  final customScores = client.decryptAndDequantize(
    encryptedResult,
    postProcessing: PostProcessing.custom((values, shape) {
      // Apply your own transform here.
      return values;
    }),
  );
  print('Custom: $customScores');
}
