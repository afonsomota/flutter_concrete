// lib/src/concrete_client.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';

import 'circuit_encoding.dart';
import 'client_zip_parser.dart';
import 'fhe_native.dart';
import 'key_storage.dart';
import 'key_topology.dart';
import 'quantizer.dart';

const _kClientKeyStorageKey = 'fhe_client_key';
const _kServerKeyStorageKey = 'fhe_server_key';
const _kModelHashStorageKey = 'fhe_model_hash';

class ConcreteClient {
  static const modelHashStorageKey = _kModelHashStorageKey;

  FheNative? _nativeInstance;
  FheNative get _native => _nativeInstance ??= FheNative();

  QuantizationParams? _quantParams;
  KeyTopology? _topology;
  CircuitEncoding? _encoding;
  Uint8List? _clientKey;
  Uint8List? _serverKey;
  String? _serverKeyB64Cache;
  bool _isReady = false;

  bool get isReady => _isReady;

  Uint8List get serverKey {
    _requireReady();
    return _serverKey!;
  }

  String get serverKeyBase64 {
    _requireReady();
    return _serverKeyB64Cache ??= base64Encode(_serverKey!);
  }

  Future<void> setup({
    required Uint8List clientZipBytes,
    required KeyStorage storage,
  }) async {
    if (_isReady) return;

    // 1. Parse client.zip
    final result = ClientZipParser.parse(clientZipBytes);
    _quantParams = result.quantParams;
    _topology = result.topology;
    _encoding = result.encoding;

    // 2. Compute model hash from topology + encoding
    final currentHash = _topology!.computeModelHash(_encoding!);

    // 3. Check stored hash
    final storedHash = await storage.read(_kModelHashStorageKey);
    final storedClient = await storage.read(_kClientKeyStorageKey);
    final storedServer = await storage.read(_kServerKeyStorageKey);

    final hashMatches = storedHash != null &&
        const ListEquality<int>().equals(storedHash, currentHash);

    if (hashMatches && storedClient != null && storedServer != null) {
      // Restore existing keys
      _clientKey = storedClient;
      _serverKey = storedServer;
    } else {
      // Hash mismatch or missing keys — delete old and regenerate
      await Future.wait([
        storage.delete(_kClientKeyStorageKey),
        storage.delete(_kServerKeyStorageKey),
        storage.delete(_kModelHashStorageKey),
      ]);

      final keyResult = _native.keygen(_topology!.pack());
      _clientKey = keyResult.clientKey;
      _serverKey = keyResult.serverKey;

      await Future.wait([
        storage.write(_kClientKeyStorageKey, _clientKey!),
        storage.write(_kServerKeyStorageKey, _serverKey!),
        storage.write(_kModelHashStorageKey, currentHash),
      ]);
    }

    _isReady = true;
  }

  void reset() {
    _isReady = false;
    _quantParams = null;
    _topology = null;
    _encoding = null;
    _clientKey = null;
    _serverKey = null;
    _serverKeyB64Cache = null;
    _nativeInstance = null;
  }

  Uint8List quantizeAndEncrypt(Float32List features) {
    _requireReady();
    final quantized = _quantParams!.quantizeInputs(features);
    return _native.encrypt(
      _clientKey!, quantized,
      _encoding!.tfheInputBitWidth, _encoding!.inputIsSigned,
    );
  }

  Float64List decryptAndDequantize(Uint8List ciphertext) {
    _requireReady();
    final rawScores = _native.decrypt(
      _clientKey!, ciphertext,
      _encoding!.tfheOutputBitWidth, _encoding!.outputIsSigned,
    );
    return _quantParams!.dequantizeOutputs(rawScores);
  }

  void _requireReady() {
    if (!_isReady) {
      throw StateError('ConcreteClient: call setup() first');
    }
  }
}
