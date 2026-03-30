// lib/src/quantizer.dart
//
// Quantization utilities for Concrete ML FHE inference.
// Converts between float feature vectors and quantized integer representations.

import 'dart:typed_data';

/// Per-feature input quantization parameters.
class InputQuantParam {
  final double scale;
  final int zeroPoint;
  final int offset;
  final int nBits;
  final bool isSigned;
  const InputQuantParam({
    required this.scale,
    required this.zeroPoint,
    this.offset = 0,
    this.nBits = 8,
    this.isSigned = false,
  });
}

/// Output dequantization parameters.
///
/// Supports both scalar (shared across all outputs) and per-class zero points.
/// When [zeroPoints] is provided, each output element uses its own zero point
/// (cycling if the raw output is longer than the list). Otherwise [zeroPoint]
/// is used for all elements.
class OutputQuantParam {
  final double scale;
  final int zeroPoint;
  final List<int>? zeroPoints;
  final int offset;
  final int nBits;
  final bool isSigned;
  const OutputQuantParam({
    required this.scale,
    required this.offset,
    this.zeroPoint = 0,
    this.zeroPoints,
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
  /// Formula: q = round(float / scale) + zero_point + offset, clamped to the
  /// range determined by [InputQuantParam.nBits] and [InputQuantParam.isSigned]:
  /// - Unsigned: [0, (1 << nBits) - 1]
  /// - Signed: [-(1 << (nBits - 1)), (1 << (nBits - 1)) - 1]
  ///
  /// The offset shifts signed quantized values into the unsigned range
  /// expected by the FHE circuit.
  Int64List quantizeInputs(Float32List features) {
    assert(
      features.length == input.length || input.length == 1,
      'Feature length ${features.length} != quant param length ${input.length}',
    );
    final result = Int64List(features.length);
    for (int i = 0; i < features.length; i++) {
      final p = input[i % input.length];
      final q = (features[i] / p.scale).round() + p.zeroPoint + p.offset;
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
  /// Formula per element: `float = (raw - zero_point) * scale`.
  ///
  /// The output quantizer's `offset` is NOT applied here — it matches
  /// Python's `dequantize_output` which does `scale * (raw - zp)`.
  ///
  /// Model-specific post-processing (tree aggregation, softmax, etc.) is
  /// handled separately by [PostProcessing].
  Float64List dequantizeOutputs(Int64List rawScores) {
    final p = output;
    final zps = p.zeroPoints;
    final result = Float64List(rawScores.length);
    for (int i = 0; i < rawScores.length; i++) {
      final zp = zps != null ? zps[i % zps.length] : p.zeroPoint;
      result[i] = (rawScores[i] - zp) * p.scale;
    }
    return result;
  }
}
