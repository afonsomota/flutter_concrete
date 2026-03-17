// lib/src/quantizer.dart
//
// Quantization utilities for Concrete ML FHE inference.
// Converts between float feature vectors and quantized integer representations.

import 'dart:typed_data';

/// Per-feature input quantization parameters.
class InputQuantParam {
  final double scale;
  final int zeroPoint;
  const InputQuantParam({required this.scale, required this.zeroPoint});
}

/// Output dequantization parameters (shared across all output classes).
class OutputQuantParam {
  final double scale;
  final int zeroPoint;
  final int offset;
  const OutputQuantParam({
    required this.scale,
    required this.zeroPoint,
    required this.offset,
  });
}

/// Parsed quantization parameters for input features and output scores.
class QuantizationParams {
  final List<InputQuantParam> input;
  final OutputQuantParam output;

  const QuantizationParams({required this.input, required this.output});

  /// Quantize float feature vector to uint8 using per-feature input params.
  ///
  /// Formula: q = round(float / scale) + zero_point, clamped to [0, 255].
  Uint8List quantizeInputs(Float32List features) {
    assert(
      features.length == input.length,
      'Feature length ${features.length} != quant param length ${input.length}',
    );
    final result = Uint8List(features.length);
    for (int i = 0; i < features.length; i++) {
      final p = input[i];
      final q = (features[i] / p.scale).round() + p.zeroPoint;
      result[i] = q.clamp(0, 255);
    }
    return result;
  }

  /// Dequantize raw int8 output scores to float64.
  ///
  /// Formula: float = (raw + offset - zero_point) * scale.
  Float64List dequantizeOutputs(Int8List rawScores) {
    final result = Float64List(rawScores.length);
    final p = output;
    for (int i = 0; i < rawScores.length; i++) {
      result[i] = (rawScores[i] + p.offset - p.zeroPoint) * p.scale;
    }
    return result;
  }
}
