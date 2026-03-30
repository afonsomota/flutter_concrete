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
import 'post_processing.dart';
import 'quantizer.dart';

const _kClientKeyStorageKey = 'fhe_client_key';
const _kServerKeyStorageKey = 'fhe_server_key';
const _kModelHashStorageKey = 'fhe_model_hash';

/// FHE client for Concrete ML models.
///
/// Parses a Concrete ML `client.zip`, manages TFHE-rs key generation and
/// persistence, and provides quantize+encrypt / decrypt+dequantize operations.
class ConcreteClient {
  /// Storage key used to persist the model hash for key invalidation.
  static const modelHashStorageKey = _kModelHashStorageKey;

  FheNative? _nativeInstance;
  FheNative get _native => _nativeInstance ??= FheNative();

  QuantizationParams? _quantParams;
  KeyTopology? _topology;
  CircuitEncoding? _encoding;
  ConcreteCipherInfo? _inputCipherInfo;
  ConcreteCipherInfo? _outputCipherInfo;
  List<int> _outputShape = const [];
  String? _modelClassName;
  PostProcessing? _resolvedPostProcessing;
  Uint8List? _clientKey;
  Uint8List? _serverKey;
  String? _serverKeyB64Cache;
  bool _isReady = false;

  /// Whether [setup] has completed successfully.
  bool get isReady => _isReady;

  /// Model class name from `client.zip` (e.g. `"XGBClassifier"`).
  /// Available after [setup].
  String? get modelClassName {
    _requireReady();
    return _modelClassName;
  }

  /// The post-processing variant resolved from [modelClassName] at setup time.
  /// Available after [setup].
  PostProcessing get detectedPostProcessing {
    _requireReady();
    return _resolvedPostProcessing!;
  }

  /// The serialized evaluation (server) key. Upload this to the backend.
  Uint8List get serverKey {
    _requireReady();
    return _serverKey!;
  }

  /// Base64-encoded evaluation key, cached after first access.
  String get serverKeyBase64 {
    _requireReady();
    return _serverKeyB64Cache ??= base64Encode(_serverKey!);
  }

  /// Initialize the client: parse [clientZipBytes], generate or restore keys
  /// via [storage], and prepare for encryption/decryption.
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
    _outputShape = result.outputShape;
    _modelClassName = result.modelClassName;
    _resolvedPostProcessing = resolveAuto(_modelClassName);

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

  /// Clear all state. The client must be [setup] again before use.
  void reset() {
    _isReady = false;
    _quantParams = null;
    _topology = null;
    _encoding = null;
    _inputCipherInfo = null;
    _outputCipherInfo = null;
    _outputShape = const [];
    _modelClassName = null;
    _resolvedPostProcessing = null;
    _clientKey = null;
    _serverKey = null;
    _serverKeyB64Cache = null;
    _nativeInstance = null;
  }

  /// Quantize a float feature vector and encrypt it for server-side FHE inference.
  Uint8List quantizeAndEncrypt(Float32List features) {
    _requireReady();
    final quantized = _quantParams!.quantizeInputs(features);
    // Apply input offsets to shift signed values into the unsigned range
    // expected by the FHE circuit (Python's fhe.Client.encrypt does this
    // internally).
    final shifted = _quantParams!.applyInputOffsets(quantized);

    if (_inputCipherInfo != null) {
      final info = _inputCipherInfo!;
      if (!info.isNativeMode) {
        throw UnsupportedError(
            'ConcreteClient: only native encoding mode is supported');
      }
      // Concrete LWE path: seeded encrypt → serialize as Value
      final ct = _native.lweEncryptSeeded(
        _clientKey!,
        shifted,
        info.concreteShape.last,
        info.lweDimension,
        info.variance,
      );
      return _native.serializeValue(
        ct,
        info.concreteShape,
        info.abstractShape,
        info.encodingWidth,
        info.encodingIsSigned,
        info.lweDimension,
        info.keyId,
        info.variance,
        info.compression == ConcreteCipherCompression.seed ? 1 : 0,
      );
    }

    // TFHE-rs path (existing)
    return _native.encrypt(
      _clientKey!,
      quantized,
      _encoding!.tfheInputBitWidth,
      _encoding!.inputIsSigned,
    );
  }

  /// Decrypt an FHE result ciphertext, dequantize, and apply post-processing.
  ///
  /// By default uses [PostProcessing.auto], which resolves from the model
  /// class name in `client.zip`. Pass an explicit variant to override.
  ///
  /// See [PostProcessing] for available variants and their behavior.
  Float64List decryptAndDequantize(
    Uint8List ciphertext, {
    PostProcessing postProcessing = const PostProcessing.auto(),
  }) {
    _requireReady();

    Int64List rawScores;
    if (_outputCipherInfo != null) {
      final info = _outputCipherInfo!;
      if (!info.isNativeMode) {
        throw UnsupportedError(
            'ConcreteClient: only native encoding mode is supported');
      }
      // Concrete LWE path: deserialize Value → full decrypt
      final (ctData, nCts) = _native.deserializeValue(ciphertext);
      rawScores = _native.lweDecryptFull(
        _clientKey!,
        ctData,
        nCts,
        info.encodingWidth,
        info.encodingIsSigned,
        info.lweDimension,
      );
    } else {
      // TFHE-rs path
      rawScores = _native.decrypt(
        _clientKey!,
        ciphertext,
        _encoding!.tfheOutputBitWidth,
        _encoding!.outputIsSigned,
      );
    }

    // Dequantize (element-wise).
    final dequantized = _quantParams!.dequantizeOutputs(rawScores);

    // Apply post-processing.
    final pp = postProcessing is AutoPostProcessing
        ? _resolvedPostProcessing!
        : postProcessing;
    return pp.apply(dequantized, _outputShape);
  }

  void _requireReady() {
    if (!_isReady) {
      throw StateError('ConcreteClient: call setup() first');
    }
  }
}
