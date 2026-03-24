// lib/src/client_zip_parser.dart
//
// Parses Concrete ML's client.zip to extract quantization parameters
// from serialized_processing.json, plus KeyTopology and CircuitEncoding
// from client.specs.json.

import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';

import 'circuit_encoding.dart';
import 'concrete_cipher_info.dart';
import 'key_topology.dart';
import 'quantizer.dart';

/// Result of parsing a Concrete ML `client.zip`.
class ParseResult {
  /// Quantization parameters extracted from `serialized_processing.json`.
  final QuantizationParams quantParams;

  /// Key topology extracted from `client.specs.json`.
  final KeyTopology topology;

  /// Circuit I/O encoding extracted from `client.specs.json`.
  final CircuitEncoding encoding;

  /// Concrete LWE cipher info for input (null if TFHE-rs format).
  final ConcreteCipherInfo? inputCipherInfo;

  /// Concrete LWE cipher info for output (null if TFHE-rs format).
  final ConcreteCipherInfo? outputCipherInfo;

  /// Output abstract shape from circuit specs (e.g. `[1, 5, 200]`).
  final List<int> outputShape;

  /// Model class name from `serialized_processing.json` (e.g. `"XGBClassifier"`).
  /// Null if parsing failed or field not present.
  final String? modelClassName;

  const ParseResult({
    required this.quantParams,
    required this.topology,
    required this.encoding,
    this.inputCipherInfo,
    this.outputCipherInfo,
    this.outputShape = const [],
    this.modelClassName,
  });
}

/// Parses a Concrete ML `client.zip` and extracts [ParseResult].
///
/// The zip must contain:
/// - `serialized_processing.json` with `input_quantizers` and
///   `output_quantizers` arrays in Concrete ML's UniformQuantizer format.
/// - `client.specs.json` with `keyset` and `circuits` sections.
class ClientZipParser {
  ClientZipParser._();

  /// Parse [zipBytes] and return [ParseResult].
  ///
  /// Throws [FormatException] if the zip structure is invalid.
  static ParseResult parse(Uint8List zipBytes) {
    final archive = ZipDecoder().decodeBytes(zipBytes);

    // --- Parse serialized_processing.json ---
    final procFile = archive.findFile('serialized_processing.json');
    if (procFile == null) {
      throw const FormatException(
        'client.zip missing serialized_processing.json',
      );
    }

    final proc = jsonDecode(utf8.decode(procFile.content as List<int>))
        as Map<String, dynamic>;

    final inputQuantizers = proc['input_quantizers'] as List<dynamic>;
    final outputQuantizers = proc['output_quantizers'] as List<dynamic>;

    if (outputQuantizers.isEmpty) {
      throw const FormatException('client.zip has no output_quantizers');
    }

    // Parse input quantizers
    final input = <InputQuantParam>[];
    for (final q in inputQuantizers) {
      final sv = (q as Map<String, dynamic>)['serialized_value']
          as Map<String, dynamic>;
      input.add(InputQuantParam(
        scale: _extractFloat(sv['scale']),
        zeroPoint: _extractInt(sv['zero_point']),
        nBits: sv.containsKey('n_bits') ? (sv['n_bits'] as num).toInt() : 8,
        isSigned: sv.containsKey('is_signed') ? sv['is_signed'] as bool : false,
      ));
    }

    // Parse output quantizer (first one)
    final outSv = (outputQuantizers[0]
        as Map<String, dynamic>)['serialized_value'] as Map<String, dynamic>;
    final zpRaw = outSv['zero_point'];
    final zpResult = _extractIntOrList(zpRaw);
    final output = OutputQuantParam(
      scale: _extractFloat(outSv['scale']),
      zeroPoint: zpResult.$1,
      zeroPoints: zpResult.$2,
      offset: outSv.containsKey('offset') ? _extractInt(outSv['offset']) : 0,
    );

    // --- Parse client.specs.json (required) ---
    final specsFile = archive.findFile('client.specs.json');
    if (specsFile == null) {
      throw const FormatException('client.zip missing client.specs.json');
    }

    final specs = jsonDecode(utf8.decode(specsFile.content as List<int>))
        as Map<String, dynamic>;

    // Parse output shape from tfhers_specs if available.
    List<int>? tfhersOutputShape;
    final tfhersSpecs = specs['tfhers_specs'] as Map<String, dynamic>?;
    if (tfhersSpecs != null) {
      final outputShapes =
          tfhersSpecs['output_shapes_per_func'] as Map<String, dynamic>?;
      if (outputShapes != null && outputShapes.isNotEmpty) {
        final shapes = outputShapes.values.first as List<dynamic>;
        if (shapes.isNotEmpty && shapes[0] is List) {
          tfhersOutputShape = (shapes[0] as List<dynamic>)
              .map((d) => (d as num).toInt())
              .toList();
        }
      }
    }

    final quantParams = QuantizationParams(input: input, output: output);

    // --- Parse KeyTopology from keyset ---
    final keyset = specs['keyset'] as Map<String, dynamic>;

    // Build SK lookup map: id -> lweDimension
    final skList = keyset['lweSecretKeys'] as List<dynamic>;
    final skById = <int, int>{};
    final secretKeys = <SecretKeySpec>[];
    for (final sk in skList) {
      final skMap = sk as Map<String, dynamic>;
      final id = (skMap['id'] as num).toInt();
      final lweDim =
          ((skMap['params'] as Map<String, dynamic>)['lweDimension'] as num)
              .toInt();
      skById[id] = lweDim;
      secretKeys.add(SecretKeySpec(id: id, lweDimension: lweDim));
    }

    // Parse BSKs with cross-referenced inputLweDimension from SK map
    final bskList = keyset['lweBootstrapKeys'] as List<dynamic>;
    final bootstrapKeys = <BootstrapKeySpec>[];
    for (final bsk in bskList) {
      final bskMap = bsk as Map<String, dynamic>;
      final params = bskMap['params'] as Map<String, dynamic>;
      final inputId = (bskMap['inputId'] as num).toInt();
      final outputId = (bskMap['outputId'] as num).toInt();
      final inputLweDim = params.containsKey('inputLweDimension')
          ? (params['inputLweDimension'] as num).toInt()
          : (skById[inputId] ?? 0);
      bootstrapKeys.add(BootstrapKeySpec(
        inputId: inputId,
        outputId: outputId,
        levelCount: (params['levelCount'] as num).toInt(),
        baseLog: (params['baseLog'] as num).toInt(),
        glweDimension: (params['glweDimension'] as num).toInt(),
        polynomialSize: (params['polynomialSize'] as num).toInt(),
        inputLweDimension: inputLweDim,
        variance: (params['variance'] as num).toDouble(),
      ));
    }

    // Parse KSKs with cross-referenced input/outputLweDimension from SK map
    final kskList = keyset['lweKeyswitchKeys'] as List<dynamic>;
    final keyswitchKeys = <KeyswitchKeySpec>[];
    for (final ksk in kskList) {
      final kskMap = ksk as Map<String, dynamic>;
      final params = kskMap['params'] as Map<String, dynamic>;
      final inputId = (kskMap['inputId'] as num).toInt();
      final outputId = (kskMap['outputId'] as num).toInt();
      final inputLweDim = params.containsKey('inputLweDimension')
          ? (params['inputLweDimension'] as num).toInt()
          : (skById[inputId] ?? 0);
      final outputLweDim = params.containsKey('outputLweDimension')
          ? (params['outputLweDimension'] as num).toInt()
          : (skById[outputId] ?? 0);
      keyswitchKeys.add(KeyswitchKeySpec(
        inputId: inputId,
        outputId: outputId,
        levelCount: (params['levelCount'] as num).toInt(),
        baseLog: (params['baseLog'] as num).toInt(),
        inputLweDimension: inputLweDim,
        outputLweDimension: outputLweDim,
        variance: (params['variance'] as num).toDouble(),
      ));
    }

    final topology = KeyTopology(
      secretKeys: secretKeys,
      bootstrapKeys: bootstrapKeys,
      keyswitchKeys: keyswitchKeys,
    );

    // --- Parse CircuitEncoding from circuits[0] ---
    final circuits = specs['circuits'] as List<dynamic>;
    if (circuits.isEmpty) {
      throw const FormatException('client.specs.json has no circuits');
    }
    final circuit = circuits[0] as Map<String, dynamic>;

    final circuitInputs = circuit['inputs'] as List<dynamic>;
    final circuitOutputs = circuit['outputs'] as List<dynamic>;

    if (circuitInputs.isEmpty) {
      throw const FormatException('client.specs.json circuit has no inputs');
    }
    if (circuitOutputs.isEmpty) {
      throw const FormatException('client.specs.json circuit has no outputs');
    }

    final inputTypeInfo = (circuitInputs[0] as Map<String, dynamic>)['typeInfo']
        as Map<String, dynamic>;
    final outputTypeInfo = (circuitOutputs[0]
        as Map<String, dynamic>)['typeInfo'] as Map<String, dynamic>;

    final inEncoding = _parseIntegerEncoding(inputTypeInfo);
    final outEncoding = _parseIntegerEncoding(outputTypeInfo);

    final encoding = CircuitEncoding(
      inputWidth: inEncoding.$1,
      inputIsSigned: inEncoding.$2,
      outputWidth: outEncoding.$1,
      outputIsSigned: outEncoding.$2,
    );

    // Parse ConcreteCipherInfo (null for TFHE-rs format specs)
    final inputCipherInfo = _parseCipherInfo(inputTypeInfo);
    final outputCipherInfo = _parseCipherInfo(outputTypeInfo);

    // Determine output shape: prefer Concrete path, fall back to TFHE-rs.
    final outputShape =
        outputCipherInfo?.abstractShape ?? tfhersOutputShape ?? const [];

    // Parse model class name from serialized_processing.json.
    final modelClassName = _parseModelClassName(proc);

    return ParseResult(
      quantParams: quantParams,
      topology: topology,
      encoding: encoding,
      inputCipherInfo: inputCipherInfo,
      outputCipherInfo: outputCipherInfo,
      outputShape: outputShape,
      modelClassName: modelClassName,
    );
  }

  /// Parse [ConcreteCipherInfo] from a circuit gate's typeInfo.
  ///
  /// Returns null if the `encryption` field is missing, indicating TFHE-rs
  /// format where these fields aren't populated.
  static ConcreteCipherInfo? _parseCipherInfo(Map<String, dynamic> typeInfo) {
    final lweCtInfo = typeInfo['lweCiphertext'] as Map<String, dynamic>?;
    if (lweCtInfo == null) return null;

    final encryption = lweCtInfo['encryption'] as Map<String, dynamic>?;
    if (encryption == null) return null;

    final compressionStr = lweCtInfo['compression'] as String? ?? 'none';
    final compression = compressionStr == 'seed'
        ? ConcreteCipherCompression.seed
        : ConcreteCipherCompression.none;

    final encodingWrapper = lweCtInfo['encoding'] as Map<String, dynamic>?;
    final integer = encodingWrapper?['integer'] as Map<String, dynamic>?;
    if (integer == null) return null;

    final mode = integer['mode'] as Map<String, dynamic>?;
    final isNative = mode != null && mode.containsKey('native');

    final concreteShapeMap =
        lweCtInfo['concreteShape'] as Map<String, dynamic>?;
    final concreteShape = (concreteShapeMap?['dimensions'] as List<dynamic>?)
            ?.map((d) => (d as num).toInt())
            .toList() ??
        [];

    final abstractShapeMap =
        lweCtInfo['abstractShape'] as Map<String, dynamic>?;
    final abstractShape = (abstractShapeMap?['dimensions'] as List<dynamic>?)
            ?.map((d) => (d as num).toInt())
            .toList() ??
        [];

    return ConcreteCipherInfo(
      lweDimension: (encryption['lweDimension'] as num).toInt(),
      keyId: (encryption['keyId'] as num).toInt(),
      variance: (encryption['variance'] as num).toDouble(),
      compression: compression,
      encodingWidth: (integer['width'] as num).toInt(),
      encodingIsSigned: integer['isSigned'] as bool,
      isNativeMode: isNative,
      concreteShape: concreteShape,
      abstractShape: abstractShape,
    );
  }

  /// Extract integer encoding (width, isSigned) from a typeInfo map.
  ///
  /// Expects: `{"lweCiphertext": {"encoding": {"integer": {"width": N, "isSigned": B}}}}`
  static (int, bool) _parseIntegerEncoding(Map<String, dynamic> typeInfo) {
    final lweCiphertext = typeInfo['lweCiphertext'] as Map<String, dynamic>;
    final encodingWrapper = lweCiphertext['encoding'] as Map<String, dynamic>;
    final integer = encodingWrapper['integer'] as Map<String, dynamic>;
    final width = (integer['width'] as num).toInt();
    final isSigned = integer['isSigned'] as bool;
    return (width, isSigned);
  }

  /// Extract a float value that may be raw or wrapped in
  /// `{"serialized_value": ...}`.
  static double _extractFloat(dynamic value) {
    if (value is num) return value.toDouble();
    if (value is Map<String, dynamic>) {
      return (value['serialized_value'] as num).toDouble();
    }
    throw FormatException('Cannot parse float from: $value');
  }

  /// Extract an int value that may be raw or wrapped in
  /// `{"serialized_value": ...}`.
  static int _extractInt(dynamic value) {
    if (value is num) return value.toInt();
    if (value is Map<String, dynamic>) {
      return (value['serialized_value'] as num).toInt();
    }
    throw FormatException('Cannot parse int from: $value');
  }

  /// Extract an int that may be a scalar or a per-class array.
  ///
  /// Returns `(scalar, null)` for scalar values, or `(first, list)` for
  /// array values like `{"type_name": "numpy_array", "serialized_value": [[14, 0, -10]]}`.
  static (int, List<int>?) _extractIntOrList(dynamic value) {
    if (value is num) return (value.toInt(), null);
    if (value is Map<String, dynamic>) {
      final sv = value['serialized_value'];
      if (sv is num) return (sv.toInt(), null);
      if (sv is List) {
        // numpy_array: serialized_value is [[v0, v1, ...]] (nested list)
        final flat = sv.first is List
            ? (sv.first as List).map((e) => (e as num).toInt()).toList()
            : sv.map((e) => (e as num).toInt()).toList();
        return (flat.first, flat);
      }
    }
    throw FormatException('Cannot parse int or int list from: $value');
  }

  /// Parse the model class name from the `model_type` field in
  /// `serialized_processing.json`.
  ///
  /// The field is a Skops-serialized Python type object:
  /// `{"type_name": "type", "serialized_value": "<hex-encoded ZIP>"}`.
  /// The ZIP contains `schema.json` with a `__class__` field.
  ///
  /// Returns null if parsing fails for any reason.
  static String? _parseModelClassName(Map<String, dynamic> proc) {
    try {
      final modelType = proc['model_type'] as Map<String, dynamic>?;
      if (modelType == null) return null;

      final hexString = modelType['serialized_value'] as String?;
      if (hexString == null) return null;

      // Decode hex string to bytes.
      final bytes = Uint8List(hexString.length ~/ 2);
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = int.parse(hexString.substring(i * 2, i * 2 + 2), radix: 16);
      }

      // Parse as ZIP and extract schema.json.
      final archive = ZipDecoder().decodeBytes(bytes);
      final schemaFile = archive.findFile('schema.json');
      if (schemaFile == null) return null;

      final schema = jsonDecode(utf8.decode(schemaFile.content as List<int>))
          as Map<String, dynamic>;
      return schema['__class__'] as String?;
    } catch (_) {
      return null;
    }
  }
}
