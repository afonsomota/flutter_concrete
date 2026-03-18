import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/key_topology.dart';
import 'package:flutter_concrete/src/circuit_encoding.dart';

void main() {
  group('KeyTopology.pack', () {
    test('packs a simple topology into Uint64List', () {
      final topology = KeyTopology(
        secretKeys: [
          SecretKeySpec(id: 0, lweDimension: 2048),
          SecretKeySpec(id: 1, lweDimension: 599),
        ],
        bootstrapKeys: [
          BootstrapKeySpec(
            inputId: 1, outputId: 0,
            levelCount: 1, baseLog: 23,
            glweDimension: 4, polynomialSize: 512,
            inputLweDimension: 599,
            variance: 8.442253112932959e-31,
          ),
        ],
        keyswitchKeys: [
          KeyswitchKeySpec(
            inputId: 0, outputId: 1,
            levelCount: 3, baseLog: 3,
            inputLweDimension: 2048,
            outputLweDimension: 599,
            variance: 2.207703775750815e-08,
          ),
        ],
      );

      final packed = topology.pack();
      expect(packed, isA<Uint64List>());

      // SK section: [num_sks=2, id0=0, dim0=2048, id1=1, dim1=599]
      expect(packed[0], 2);
      expect(packed[1], 0);
      expect(packed[2], 2048);
      expect(packed[3], 1);
      expect(packed[4], 599);

      // BSK section: [num_bsks=1, input_id, output_id, level_count, base_log, glwe_dim, poly_size, input_lwe_dim, variance_bits]
      expect(packed[5], 1);
      expect(packed[6], 1);
      expect(packed[7], 0);
      expect(packed[8], 1);
      expect(packed[9], 23);

      // KSK section starts at index 14
      expect(packed[14], 1);
      expect(packed[15], 0);
      expect(packed[16], 1);
    });

    test('variance round-trips through f64 bits', () {
      final variance = 8.442253112932959e-31;
      final topology = KeyTopology(
        secretKeys: [
          SecretKeySpec(id: 0, lweDimension: 2048),
          SecretKeySpec(id: 1, lweDimension: 599),
        ],
        bootstrapKeys: [
          BootstrapKeySpec(
            inputId: 1, outputId: 0,
            levelCount: 1, baseLog: 23,
            glweDimension: 4, polynomialSize: 512,
            inputLweDimension: 599,
            variance: variance,
          ),
        ],
        keyswitchKeys: [],
      );

      final packed = topology.pack();
      final varianceBits = packed[13];
      final bd = ByteData(8)..setUint64(0, varianceBits);
      final recovered = bd.getFloat64(0);
      expect(recovered, variance);
    });
  });

  group('KeyTopology.computeModelHash', () {
    final encoding = CircuitEncoding(
      inputWidth: 10, inputIsSigned: false,
      outputWidth: 8, outputIsSigned: true,
    );

    test('returns consistent hash for same topology + encoding', () {
      final topology = KeyTopology(
        secretKeys: [SecretKeySpec(id: 0, lweDimension: 2048)],
        bootstrapKeys: [],
        keyswitchKeys: [],
      );
      expect(topology.computeModelHash(encoding), topology.computeModelHash(encoding));
    });

    test('changes when topology changes', () {
      final t1 = KeyTopology(
        secretKeys: [SecretKeySpec(id: 0, lweDimension: 2048)],
        bootstrapKeys: [],
        keyswitchKeys: [],
      );
      final t2 = KeyTopology(
        secretKeys: [SecretKeySpec(id: 0, lweDimension: 1024)],
        bootstrapKeys: [],
        keyswitchKeys: [],
      );
      expect(t1.computeModelHash(encoding), isNot(t2.computeModelHash(encoding)));
    });

    test('changes when encoding changes', () {
      final topology = KeyTopology(
        secretKeys: [SecretKeySpec(id: 0, lweDimension: 2048)],
        bootstrapKeys: [],
        keyswitchKeys: [],
      );
      final enc2 = CircuitEncoding(
        inputWidth: 16, inputIsSigned: false,
        outputWidth: 8, outputIsSigned: true,
      );
      expect(topology.computeModelHash(encoding), isNot(topology.computeModelHash(enc2)));
    });
  });
}
