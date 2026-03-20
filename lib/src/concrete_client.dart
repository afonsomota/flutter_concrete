// lib/src/concrete_client.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';

import 'circuit_encoding.dart';
import 'client_zip_parser.dart';
import 'concrete_cipher_info.dart';
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
  ConcreteCipherInfo? _inputCipherInfo;
  ConcreteCipherInfo? _outputCipherInfo;
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
    _inputCipherInfo = result.inputCipherInfo;
    _outputCipherInfo = result.outputCipherInfo;

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
    _inputCipherInfo = null;
    _outputCipherInfo = null;
    _clientKey = null;
    _serverKey = null;
    _serverKeyB64Cache = null;
    _nativeInstance = null;
  }

  Uint8List quantizeAndEncrypt(Float32List features) {
    _requireReady();
    final quantized = _quantParams!.quantizeInputs(features);

    if (_inputCipherInfo != null) {
      final info = _inputCipherInfo!;
      if (!info.isNativeMode) {
        throw UnsupportedError(
            'ConcreteClient: only native encoding mode is supported');
      }
      // Concrete LWE path: seeded encrypt → serialize as Value
      final ct = _native.lweEncryptSeeded(
        _clientKey!, quantized,
        info.encodingWidth, info.lweDimension, info.variance,
      );
      return _native.serializeValue(
        ct, info.concreteShape, info.abstractShape,
        info.encodingWidth, info.encodingIsSigned,
        info.lweDimension, info.keyId, info.variance,
        info.compression == ConcreteCipherCompression.seed ? 1 : 0,
      );
    }

    // TFHE-rs path (existing)
    return _native.encrypt(
      _clientKey!, quantized,
      _encoding!.tfheInputBitWidth, _encoding!.inputIsSigned,
    );
  }

  Float64List decryptAndDequantize(Uint8List ciphertext) {
    _requireReady();

    if (_outputCipherInfo != null) {
      final info = _outputCipherInfo!;
      if (!info.isNativeMode) {
        throw UnsupportedError(
            'ConcreteClient: only native encoding mode is supported');
      }
      // Concrete LWE path: deserialize Value → full decrypt
      final (ctData, nCts) = _native.deserializeValue(ciphertext);
      final rawScores = _native.lweDecryptFull(
        _clientKey!, ctData,
        nCts, info.encodingWidth, info.encodingIsSigned, info.lweDimension,
      );
      return _quantParams!.dequantizeOutputs(rawScores);
    }

    // TFHE-rs path (existing)
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
