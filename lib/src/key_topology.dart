import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;

import 'circuit_encoding.dart';

/// LWE secret key spec from client.specs.json.
class SecretKeySpec {
  final int id;
  final int lweDimension;
  const SecretKeySpec({required this.id, required this.lweDimension});
}

/// Bootstrap key spec from client.specs.json.
class BootstrapKeySpec {
  final int inputId;
  final int outputId;
  final int levelCount;
  final int baseLog;
  final int glweDimension;
  final int polynomialSize;
  final int inputLweDimension;
  final double variance;

  const BootstrapKeySpec({
    required this.inputId,
    required this.outputId,
    required this.levelCount,
    required this.baseLog,
    required this.glweDimension,
    required this.polynomialSize,
    required this.inputLweDimension,
    required this.variance,
  });
}

/// Keyswitch key spec from client.specs.json.
class KeyswitchKeySpec {
  final int inputId;
  final int outputId;
  final int levelCount;
  final int baseLog;
  final int inputLweDimension;
  final int outputLweDimension;
  final double variance;

  const KeyswitchKeySpec({
    required this.inputId,
    required this.outputId,
    required this.levelCount,
    required this.baseLog,
    required this.inputLweDimension,
    required this.outputLweDimension,
    required this.variance,
  });
}

/// Full key topology parsed from client.specs.json keyset section.
///
/// Use [pack] to serialize into a flat [Uint64List] for FFI transport.
class KeyTopology {
  final List<SecretKeySpec> secretKeys;
  final List<BootstrapKeySpec> bootstrapKeys;
  final List<KeyswitchKeySpec> keyswitchKeys;

  const KeyTopology({
    required this.secretKeys,
    required this.bootstrapKeys,
    required this.keyswitchKeys,
  });

  /// Pack into a flat [Uint64List] for FFI transport to Rust.
  ///
  /// Layout:
  /// ```
  /// [num_sks, id0, dim0, id1, dim1, ...,
  ///  num_bsks, input_id, output_id, level_count, base_log,
  ///            glwe_dim, poly_size, input_lwe_dim, variance_bits, ...,
  ///  num_ksks, input_id, output_id, level_count, base_log,
  ///            input_lwe_dim, output_lwe_dim, variance_bits, ...]
  /// ```
  Uint64List pack() {
    final size = 1 + secretKeys.length * 2 +
        1 + bootstrapKeys.length * 8 +
        1 + keyswitchKeys.length * 7;
    final buf = Uint64List(size);
    int i = 0;

    buf[i++] = secretKeys.length;
    for (final sk in secretKeys) {
      buf[i++] = sk.id;
      buf[i++] = sk.lweDimension;
    }

    buf[i++] = bootstrapKeys.length;
    for (final bsk in bootstrapKeys) {
      buf[i++] = bsk.inputId;
      buf[i++] = bsk.outputId;
      buf[i++] = bsk.levelCount;
      buf[i++] = bsk.baseLog;
      buf[i++] = bsk.glweDimension;
      buf[i++] = bsk.polynomialSize;
      buf[i++] = bsk.inputLweDimension;
      final bd = ByteData(8)..setFloat64(0, bsk.variance);
      buf[i++] = bd.getUint64(0);
    }

    buf[i++] = keyswitchKeys.length;
    for (final ksk in keyswitchKeys) {
      buf[i++] = ksk.inputId;
      buf[i++] = ksk.outputId;
      buf[i++] = ksk.levelCount;
      buf[i++] = ksk.baseLog;
      buf[i++] = ksk.inputLweDimension;
      buf[i++] = ksk.outputLweDimension;
      final bd = ByteData(8)..setFloat64(0, ksk.variance);
      buf[i++] = bd.getUint64(0);
    }

    return buf;
  }

  /// Compute a SHA-256 hash of the packed topology combined with
  /// [CircuitEncoding] for model change detection.
  Uint8List computeModelHash(CircuitEncoding encoding) {
    final packed = pack();
    final topoBytes = packed.buffer.asUint8List();
    final encBuf = ByteData(12);
    encBuf.setInt32(0, encoding.inputWidth);
    encBuf.setInt16(4, encoding.inputIsSigned ? 1 : 0);
    encBuf.setInt32(6, encoding.outputWidth);
    encBuf.setInt16(10, encoding.outputIsSigned ? 1 : 0);
    final combined = Uint8List(topoBytes.length + 12)
      ..setAll(0, topoBytes)
      ..setAll(topoBytes.length, encBuf.buffer.asUint8List());
    return Uint8List.fromList(sha256.convert(combined).bytes);
  }
}
