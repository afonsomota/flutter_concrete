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

  // 4. Encrypt a feature vector (e.g. from TF-IDF + LSA).
  final features = Float32List.fromList([0.1, -0.3, 0.5]);
  final ciphertext = client.quantizeAndEncrypt(features);
  print('Ciphertext size: ${ciphertext.length} bytes');

  // 5. Send ciphertext to backend for FHE inference, then decrypt the result.
  final encryptedResult = Uint8List(0); // replace with backend response
  final scores = client.decryptAndDequantize(encryptedResult);
  print('Scores: $scores');
}
