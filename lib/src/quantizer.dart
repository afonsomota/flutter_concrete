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

  /// Number of output classes (from FHE circuit output shape).
  /// When set, [dequantizeOutputs] aggregates per-tree scores by summing
  /// across trees for each class.
  final int? nClasses;

  const QuantizationParams({
    required this.input,
    required this.output,
    this.nClasses,
  });

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
  /// For tree-ensemble models (XGBoost), the FHE circuit outputs one value
  /// per class per tree. When [nClasses] is set and `rawScores.length` is a
  /// multiple of it, the raw values are interpreted as shape
  /// `(nClasses, nTrees)` and summed across trees to produce one score per
  /// class.
  ///
  /// Formula per element: float = (raw + offset - zero_point) * scale.
  Float64List dequantizeOutputs(Int8List rawScores) {
    final p = output;

    // Aggregate per-tree outputs when nClasses is known.
    if (nClasses != null &&
        nClasses! > 0 &&
        rawScores.length > nClasses! &&
        rawScores.length % nClasses! == 0) {
      final nTrees = rawScores.length ~/ nClasses!;
      final result = Float64List(nClasses!);
      // Layout: class 0 × nTrees, class 1 × nTrees, …
      for (int c = 0; c < nClasses!; c++) {
        double sum = 0.0;
        final base = c * nTrees;
        for (int t = 0; t < nTrees; t++) {
          sum += (rawScores[base + t] + p.offset - p.zeroPoint) * p.scale;
        }
        result[c] = sum;
      }
      return result;
    }

    // Fallback: no aggregation.
    final result = Float64List(rawScores.length);
    for (int i = 0; i < rawScores.length; i++) {
      result[i] = (rawScores[i] + p.offset - p.zeroPoint) * p.scale;
    }
    return result;
  }
}
