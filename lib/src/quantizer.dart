// lib/src/quantizer.dart
//
// Quantization utilities for Concrete ML FHE inference.
// Converts between float feature vectors and quantized integer representations.

import 'dart:typed_data';

/// Per-feature input quantization parameters.
class InputQuantParam {
  final double scale;
  final int zeroPoint;
  final int nBits;
  final bool isSigned;
  const InputQuantParam({
    required this.scale,
    required this.zeroPoint,
    this.nBits = 8,
    this.isSigned = false,
  });
}

/// Output dequantization parameters (shared across all output classes).
class OutputQuantParam {
  final double scale;
  final int zeroPoint;
  final int offset;
  final int nBits;
  final bool isSigned;
  const OutputQuantParam({
    required this.scale,
    required this.zeroPoint,
    required this.offset,
    this.nBits = 8,
    this.isSigned = true,
  });
}

/// Parsed quantization parameters for input features and output scores.
class QuantizationParams {
  final List<InputQuantParam> input;
  final OutputQuantParam output;

  const QuantizationParams({
    required this.input,
    required this.output,
  });

  /// Quantize float feature vector to Int64List using per-feature input params.
  ///
  /// Formula: q = round(float / scale) + zero_point, clamped to the range
  /// determined by [InputQuantParam.nBits] and [InputQuantParam.isSigned]:
  /// - Unsigned: [0, (1 << nBits) - 1]
  /// - Signed: [-(1 << (nBits - 1)), (1 << (nBits - 1)) - 1]
  Int64List quantizeInputs(Float32List features) {
    assert(
      features.length == input.length,
      'Feature length ${features.length} != quant param length ${input.length}',
    );
    final result = Int64List(features.length);
    for (int i = 0; i < features.length; i++) {
      final p = input[i];
      final q = (features[i] / p.scale).round() + p.zeroPoint;
      if (p.isSigned) {
        final minVal = -(1 << (p.nBits - 1));
        final maxVal = (1 << (p.nBits - 1)) - 1;
        result[i] = q.clamp(minVal, maxVal);
      } else {
        final maxVal = (1 << p.nBits) - 1;
        result[i] = q.clamp(0, maxVal);
      }
    }
    return result;
  }

  /// Dequantize raw int64 output scores to float64 (element-wise).
  ///
  /// Formula per element: `float = (raw + offset - zero_point) * scale`.
  ///
  /// Model-specific post-processing (tree aggregation, softmax, etc.) is
  /// handled separately by [PostProcessing].
  Float64List dequantizeOutputs(Int64List rawScores) {
    final p = output;
    final result = Float64List(rawScores.length);
    for (int i = 0; i < rawScores.length; i++) {
      result[i] = (rawScores[i] + p.offset - p.zeroPoint) * p.scale;
    }
    return result;
  }
}
