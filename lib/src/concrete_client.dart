// lib/src/concrete_client.dart
//
// High-level Concrete ML FHE client.
// Wraps native TFHE-rs operations with quantization support.

import 'dart:typed_data';

import 'fhe_native.dart';
import 'quantizer.dart';

/// High-level client for Concrete ML FHE operations.
///
/// Combines native TFHE-rs encrypt/decrypt with quantization.
/// The caller is responsible for key persistence and asset loading.
class ConcreteClient {
  final QuantizationParams _quantParams;
  final FheNative _native = FheNative();

  Uint8List? _clientKey;
  Uint8List? _serverKey;

  ConcreteClient({required QuantizationParams quantParams})
      : _quantParams = quantParams;

  /// Whether keys have been generated or restored.
  bool get hasKeys => _clientKey != null && _serverKey != null;

  /// The current client key, or null if not yet generated/restored.
  Uint8List? get clientKey => _clientKey;

  /// The current server (evaluation) key, or null if not yet generated/restored.
  Uint8List? get serverKey => _serverKey;

  /// Generate a fresh TFHE-rs keypair.
  ///
  /// Returns a [KeygenResult] — the caller should persist the keys.
  /// This is CPU-intensive (~10–60 s on mobile).
  KeygenResult generateKeys() {
    final result = _native.keygen();
    _clientKey = result.clientKey;
    _serverKey = result.serverKey;
    return result;
  }

  /// Restore previously persisted keys.
  void restoreKeys({required Uint8List clientKey, required Uint8List serverKey}) {
    _clientKey = clientKey;
    _serverKey = serverKey;
  }

  /// Quantize a float feature vector to uint8 and FHE-encrypt it.
  ///
  /// Returns the encrypted ciphertext bytes (bincode `Vec<FheUint8>`).
  Uint8List quantizeAndEncrypt(Float32List features) {
    _requireKeys();
    final quantized = _quantParams.quantizeInputs(features);
    return _native.encryptU8(_clientKey!, quantized);
  }

  /// FHE-decrypt ciphertext and dequantize to float scores.
  ///
  /// Returns dequantized float64 scores (one per output class).
  Float64List decryptAndDequantize(Uint8List ciphertext) {
    _requireKeys();
    final rawScores = _native.decryptI8(_clientKey!, ciphertext);
    return _quantParams.dequantizeOutputs(rawScores);
  }

  void _requireKeys() {
    if (!hasKeys) {
      throw StateError(
          'ConcreteClient: call generateKeys() or restoreKeys() first');
    }
  }
}
