import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/circuit_encoding.dart';

void main() {
  group('roundUpBitWidth', () {
    test('rounds 1-8 to 8', () {
      for (int w = 1; w <= 8; w++) {
        expect(roundUpBitWidth(w), 8, reason: 'width=$w');
      }
    });

    test('rounds 9-16 to 16', () {
      expect(roundUpBitWidth(9), 16);
      expect(roundUpBitWidth(10), 16);
      expect(roundUpBitWidth(16), 16);
    });

    test('rounds 17-32 to 32', () {
      expect(roundUpBitWidth(17), 32);
      expect(roundUpBitWidth(32), 32);
    });

    test('rounds 33-64 to 64', () {
      expect(roundUpBitWidth(33), 64);
      expect(roundUpBitWidth(64), 64);
    });

    test('rejects width > 64', () {
      expect(() => roundUpBitWidth(65), throwsArgumentError);
    });

    test('rejects width <= 0', () {
      expect(() => roundUpBitWidth(0), throwsArgumentError);
    });
  });

  group('CircuitEncoding', () {
    test('stores input and output encoding', () {
      final enc = CircuitEncoding(
        inputWidth: 10,
        inputIsSigned: false,
        outputWidth: 8,
        outputIsSigned: true,
      );
      expect(enc.inputWidth, 10);
      expect(enc.inputIsSigned, false);
      expect(enc.outputWidth, 8);
      expect(enc.outputIsSigned, true);
    });

    test('tfheInputBitWidth rounds up', () {
      final enc = CircuitEncoding(
        inputWidth: 10,
        inputIsSigned: false,
        outputWidth: 8,
        outputIsSigned: true,
      );
      expect(enc.tfheInputBitWidth, 16);
      expect(enc.tfheOutputBitWidth, 8);
    });
  });
}
