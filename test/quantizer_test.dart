import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/quantizer.dart';

void main() {
  group('quantizeInputs', () {
    test('uses n_bits for clamping range (8-bit unsigned)', () {
      final params = QuantizationParams(
        input: [InputQuantParam(scale: 1.0, zeroPoint: 0, nBits: 8, isSigned: false)],
        output: OutputQuantParam(scale: 1.0, zeroPoint: 0, offset: 0),
      );
      final features = Float32List.fromList([300.0]);
      final result = params.quantizeInputs(features);
      expect(result[0], 255);
    });

    test('uses n_bits for clamping range (16-bit unsigned)', () {
      final params = QuantizationParams(
        input: [InputQuantParam(scale: 1.0, zeroPoint: 0, nBits: 16, isSigned: false)],
        output: OutputQuantParam(scale: 1.0, zeroPoint: 0, offset: 0),
      );
      final features = Float32List.fromList([70000.0]);
      final result = params.quantizeInputs(features);
      expect(result[0], 65535);
    });

    test('uses n_bits for clamping range (8-bit signed)', () {
      final params = QuantizationParams(
        input: [
          InputQuantParam(scale: 1.0, zeroPoint: 0, nBits: 8, isSigned: true),
          InputQuantParam(scale: 1.0, zeroPoint: 0, nBits: 8, isSigned: true),
        ],
        output: OutputQuantParam(scale: 1.0, zeroPoint: 0, offset: 0),
      );
      final features = Float32List.fromList([-200.0, 200.0]);
      final result = params.quantizeInputs(features);
      expect(result[0], -128);
      expect(result[1], 127);
    });

    test('default nBits=8 preserves backward compat', () {
      final params = QuantizationParams(
        input: [InputQuantParam(scale: 1.0, zeroPoint: 0)],
        output: OutputQuantParam(scale: 1.0, zeroPoint: 0, offset: 0),
      );
      final features = Float32List.fromList([300.0]);
      final result = params.quantizeInputs(features);
      expect(result[0], 255);
    });
  });

  group('dequantizeOutputs with Int64List', () {
    test('dequantizes 8-bit signed values', () {
      final params = QuantizationParams(
        input: [],
        output: OutputQuantParam(scale: 0.5, zeroPoint: 0, offset: 128),
      );
      final raw = Int64List.fromList([-1, 0, 1]);
      final result = params.dequantizeOutputs(raw);
      expect(result[0], 63.5);
      expect(result[1], 64.0);
    });

    test('aggregates per-tree outputs when nClasses is set', () {
      final params = QuantizationParams(
        input: [],
        output: OutputQuantParam(scale: 1.0, zeroPoint: 0, offset: 0),
        nClasses: 2,
      );
      final raw = Int64List.fromList([1, 2, 3, 4, 5, 6]);
      final result = params.dequantizeOutputs(raw);
      expect(result.length, 2);
      expect(result[0], 6.0);
      expect(result[1], 15.0);
    });
  });
}
