// lib/src/concrete_client.dart
//
// High-level Concrete ML FHE client.
//
// Owns the full FHE lifecycle: client.zip parsing, key management,
// quantization, encryption, and decryption.

import 'dart:convert';
import 'dart:typed_data';

import 'client_zip_parser.dart';
import 'fhe_native.dart';
import 'key_storage.dart';
import 'quantizer.dart';

// Storage key names for key persistence.
const _kClientKeyStorageKey = 'fhe_client_key';
const _kServerKeyStorageKey = 'fhe_server_key';

/// High-level client for Concrete ML FHE operations.
///
/// Call [setup] once with the Concrete ML `client.zip` bytes and a
/// [KeyStorage] implementation. After setup, use [quantizeAndEncrypt]
/// and [decryptAndDequantize] for FHE inference.
class ConcreteClient {
  FheNative? _nativeInstance;
  FheNative get _native => _nativeInstance ??= FheNative();

  QuantizationParams? _quantParams;
  Uint8List? _clientKey;
  Uint8List? _serverKey;
  String? _serverKeyB64Cache;
  bool _isReady = false;

  /// True after [setup] completes successfully.
  bool get isReady => _isReady;

  /// Raw server (evaluation) key bytes.
  ///
  /// Throws [StateError] if called before [setup].
  Uint8List get serverKey {
    _requireReady();
    return _serverKey!;
  }

  /// Base64-encoded server key. Cached after first access.
  String get serverKeyBase64 {
    _requireReady();
    return _serverKeyB64Cache ??= base64Encode(_serverKey!);
  }

  /// Parse [clientZipBytes] (Concrete ML `client.zip`), extract
  /// quantization params, and generate or restore FHE keys via [storage].
  ///
  /// Idempotent: subsequent calls are no-ops if already set up.
  /// Call [reset] first to re-initialize with a different model.
  Future<void> setup({
    required Uint8List clientZipBytes,
    required KeyStorage storage,
  }) async {
    if (_isReady) return;

    // 1. Parse quantization params from client.zip
    _quantParams = ClientZipParser.parse(clientZipBytes);

    // 2. Try to restore persisted keys
    final storedClient = await storage.read(_kClientKeyStorageKey);
    final storedServer = await storage.read(_kServerKeyStorageKey);

    if (storedClient != null && storedServer != null) {
      _clientKey = storedClient;
      _serverKey = storedServer;
    } else {
      // Generate fresh keys (CPU-intensive)
      final result = _native.keygen();
      _clientKey = result.clientKey;
      _serverKey = result.serverKey;
      // lweKey is discarded (unused, retained in FFI for ABI stability)

      // Persist for next launch
      await Future.wait([
        storage.write(_kClientKeyStorageKey, _clientKey!),
        storage.write(_kServerKeyStorageKey, _serverKey!),
      ]);
    }

    _isReady = true;
  }

  /// Clear internal state so [setup] can be called again.
  ///
  /// Does not delete persisted keys from storage.
  void reset() {
    _isReady = false;
    _quantParams = null;
    _clientKey = null;
    _serverKey = null;
    _serverKeyB64Cache = null;
    _nativeInstance = null;
  }

  /// Quantize a float feature vector to uint8 and FHE-encrypt it.
  ///
  /// Returns encrypted ciphertext bytes (bincode `Vec<FheUint8>`).
  Uint8List quantizeAndEncrypt(Float32List features) {
    _requireReady();
    final quantized = _quantParams!.quantizeInputs(features);
    return _native.encryptU8(_clientKey!, quantized);
  }

  /// FHE-decrypt ciphertext and dequantize to float scores.
  ///
  /// Returns dequantized float64 scores (one per output class).
  Float64List decryptAndDequantize(Uint8List ciphertext) {
    _requireReady();
    final rawScores = _native.decryptI8(_clientKey!, ciphertext);
    return _quantParams!.dequantizeOutputs(rawScores);
  }

  void _requireReady() {
    if (!_isReady) {
      throw StateError('ConcreteClient: call setup() first');
    }
  }
}
