// lib/src/client_zip_parser.dart
//
// Parses Concrete ML's client.zip to extract quantization parameters
// from serialized_processing.json.

import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';

import 'quantizer.dart';

/// Parses a Concrete ML `client.zip` and extracts [QuantizationParams].
///
/// The zip must contain `serialized_processing.json` with `input_quantizers`
/// and `output_quantizers` arrays in Concrete ML's UniformQuantizer format.
class ClientZipParser {
  ClientZipParser._();

  /// Parse [zipBytes] and return [QuantizationParams].
  ///
  /// Throws [FormatException] if the zip structure is invalid or
  /// quantization bit width is not 8.
  static QuantizationParams parse(Uint8List zipBytes) {
    final archive = ZipDecoder().decodeBytes(zipBytes);

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
      _validateNBits(sv, signed: false);
      input.add(InputQuantParam(
        scale: _extractFloat(sv['scale']),
        zeroPoint: _extractInt(sv['zero_point']),
      ));
    }

    // Parse output quantizer (first one)
    final outSv = (outputQuantizers[0] as Map<String, dynamic>)
        ['serialized_value'] as Map<String, dynamic>;
    _validateNBits(outSv, signed: true);
    final output = OutputQuantParam(
      scale: _extractFloat(outSv['scale']),
      zeroPoint: _extractInt(outSv['zero_point']),
      offset: _extractInt(outSv['offset']),
    );

    return QuantizationParams(input: input, output: output);
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

  /// Validate that n_bits == 8 and is_signed matches expectations.
  static void _validateNBits(Map<String, dynamic> sv, {required bool signed}) {
    final nBits = sv['n_bits'] as int;
    if (nBits != 8) {
      throw FormatException(
        'Unsupported n_bits=$nBits (expected 8). '
        'flutter_concrete only supports 8-bit quantization.',
      );
    }
    final isSigned = sv['is_signed'] as bool;
    if (isSigned != signed) {
      throw FormatException(
        'Unexpected is_signed=$isSigned for ${signed ? "output" : "input"} '
        'quantizer (expected $signed).',
      );
    }
  }
}
