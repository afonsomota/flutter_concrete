# Dynamic Key Topology and Multi-Bit-Width Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make flutter_concrete's key generation, encryption, and decryption data-driven from `client.specs.json` instead of hardcoded, supporting any Concrete ML circuit topology and encoding width up to 64-bit.

**Architecture:** Dart parses `client.specs.json` from the zip to extract key topology and circuit encoding. Topology is packed into a flat `Uint64List` and passed to Rust via FFI. Rust generates keys dynamically and dispatches encrypt/decrypt to the correct TFHE-rs type based on bit width parameters. Quantization clamping continues to use `n_bits` from `serialized_processing.json`.

**Tech Stack:** Dart (FFI, archive), Rust (tfhe-rs, capnp, bincode)

**Spec:** `docs/superpowers/specs/2026-03-18-dynamic-topology-and-bitwidth-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `lib/src/key_topology.dart` | **New.** `KeyTopology`, `SecretKeySpec`, `BootstrapKeySpec`, `KeyswitchKeySpec` data classes + `pack()` to flat `Uint64List` |
| `lib/src/circuit_encoding.dart` | **New.** `CircuitEncoding` data class, `roundUpBitWidth()` helper |
| `lib/src/client_zip_parser.dart` | **Modify.** Parse `client.specs.json` keyset + circuits. Return `ParseResult` containing `QuantizationParams`, `KeyTopology`, `CircuitEncoding`. Remove `_validateNBits`. |
| `lib/src/quantizer.dart` | **Modify.** `dequantizeOutputs` accepts `Int64List`. Remove hardcoded `[0,255]`/`[-128,127]` — derive from `n_bits`. |
| `lib/src/fhe_native.dart` | **Modify.** New FFI signatures: `fhe_keygen` takes topology, `fhe_encrypt`/`fhe_decrypt` take bit_width + is_signed. Uniform `i64` output. |
| `lib/src/concrete_client.dart` | **Modify.** Store `KeyTopology` + `CircuitEncoding`. Model hash for key invalidation. Wire new FFI signatures. |
| `rust/src/lib.rs` | **Modify.** Dynamic keygen from packed topology, encrypt/decrypt dispatch on bit width, dynamic Cap'n Proto. |
| `test/key_topology_test.dart` | **New.** Pack/unpack round-trip, variance encoding. |
| `test/circuit_encoding_test.dart` | **New.** Bit width rounding. |
| `test/client_zip_parser_test.dart` | **Extend.** Topology + encoding extraction from real zip. |
| `test/quantizer_test.dart` | **New.** Multi-width clamping, `Int64List` dequantize. |
| `test/concrete_client_test.dart` | **Extend.** Model hash invalidation. |

---

### Task 1: CircuitEncoding data class

**Files:**
- Create: `lib/src/circuit_encoding.dart`
- Test: `test/circuit_encoding_test.dart`

- [ ] **Step 1: Write failing tests for CircuitEncoding**

```dart
// test/circuit_encoding_test.dart
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/afonso/Documents/projects/e2ee_journal/flutter_concrete && flutter test test/circuit_encoding_test.dart`
Expected: FAIL — file not found

- [ ] **Step 3: Implement CircuitEncoding**

```dart
// lib/src/circuit_encoding.dart

/// Round an encoding bit width to the next supported TFHE-rs integer size.
///
/// Supported: 8, 16, 32, 64. Throws [ArgumentError] if [width] is <= 0 or > 64.
int roundUpBitWidth(int width) {
  if (width <= 0 || width > 64) {
    throw ArgumentError.value(width, 'width', 'must be 1–64');
  }
  if (width <= 8) return 8;
  if (width <= 16) return 16;
  if (width <= 32) return 32;
  return 64;
}

/// I/O encoding widths parsed from client.specs.json circuits section.
///
/// [inputWidth]/[outputWidth] are the raw encoding widths from the spec.
/// Use [tfheInputBitWidth]/[tfheOutputBitWidth] for TFHE-rs type selection.
class CircuitEncoding {
  final int inputWidth;
  final bool inputIsSigned;
  final int outputWidth;
  final bool outputIsSigned;

  const CircuitEncoding({
    required this.inputWidth,
    required this.inputIsSigned,
    required this.outputWidth,
    required this.outputIsSigned,
  });

  /// Input width rounded up to a supported TFHE-rs integer size.
  int get tfheInputBitWidth => roundUpBitWidth(inputWidth);

  /// Output width rounded up to a supported TFHE-rs integer size.
  int get tfheOutputBitWidth => roundUpBitWidth(outputWidth);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/afonso/Documents/projects/e2ee_journal/flutter_concrete && flutter test test/circuit_encoding_test.dart`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add lib/src/circuit_encoding.dart test/circuit_encoding_test.dart
git commit -m "feat: add CircuitEncoding data class with bit-width rounding"
```

---

### Task 2: KeyTopology data classes and pack()

**Files:**
- Create: `lib/src/key_topology.dart`
- Test: `test/key_topology_test.dart`

- [ ] **Step 1: Write failing tests for KeyTopology**

```dart
// test/key_topology_test.dart
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/key_topology.dart';

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
      expect(packed[0], 2); // num_sks
      expect(packed[1], 0); // id0
      expect(packed[2], 2048); // dim0
      expect(packed[3], 1); // id1
      expect(packed[4], 599); // dim1

      // BSK section: [num_bsks=1, input_id, output_id, level_count, base_log, glwe_dim, poly_size, input_lwe_dim, variance_bits]
      expect(packed[5], 1); // num_bsks
      expect(packed[6], 1); // input_id
      expect(packed[7], 0); // output_id
      expect(packed[8], 1); // level_count
      expect(packed[9], 23); // base_log

      // KSK section starts after BSK
      // index = 5 + 1 + (1 * 8) = 14
      expect(packed[14], 1); // num_ksks
      expect(packed[15], 0); // input_id
      expect(packed[16], 1); // output_id
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
      // Variance is at BSK offset + 8 (9th field, index 13)
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `flutter test test/key_topology_test.dart`
Expected: FAIL — file not found

- [ ] **Step 3: Implement KeyTopology**

```dart
// lib/src/key_topology.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;

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

    // Secret keys
    buf[i++] = secretKeys.length;
    for (final sk in secretKeys) {
      buf[i++] = sk.id;
      buf[i++] = sk.lweDimension;
    }

    // Bootstrap keys (8 fields each)
    buf[i++] = bootstrapKeys.length;
    for (final bsk in bootstrapKeys) {
      buf[i++] = bsk.inputId;
      buf[i++] = bsk.outputId;
      buf[i++] = bsk.levelCount;
      buf[i++] = bsk.baseLog;
      buf[i++] = bsk.glweDimension;
      buf[i++] = bsk.polynomialSize;
      buf[i++] = bsk.inputLweDimension;
      // Encode f64 variance as u64 bits
      final bd = ByteData(8)..setFloat64(0, bsk.variance);
      buf[i++] = bd.getUint64(0);
    }

    // Keyswitch keys (7 fields each)
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
  ///
  /// Any change to topology OR encoding triggers key regeneration.
  Uint8List computeModelHash(CircuitEncoding encoding) {
    final packed = pack();
    final topoBytes = packed.buffer.asUint8List();
    // Append encoding fields: inputWidth, inputIsSigned, outputWidth, outputIsSigned
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
```

**Note:** This requires adding `crypto` to `pubspec.yaml`:
```yaml
dependencies:
  crypto: ^3.0.0
```

- [ ] **Step 4: Add crypto dependency**

Run: `cd /Users/afonso/Documents/projects/e2ee_journal/flutter_concrete && flutter pub add crypto`

- [ ] **Step 5: Run tests to verify they pass**

Run: `flutter test test/key_topology_test.dart`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add lib/src/key_topology.dart test/key_topology_test.dart pubspec.yaml pubspec.lock
git commit -m "feat: add KeyTopology data classes with pack() and computeHash()"
```

---

### Task 3: Extend ClientZipParser to parse client.specs.json

**Files:**
- Modify: `lib/src/client_zip_parser.dart`
- Extend: `test/client_zip_parser_test.dart`

- [ ] **Step 1: Write failing tests for specs parsing**

Add to `test/client_zip_parser_test.dart`:

```dart
// Add these imports at the top:
import 'package:flutter_concrete/src/key_topology.dart';
import 'package:flutter_concrete/src/circuit_encoding.dart';

// Add inside the main() function, after existing group:

group('ClientZipParser.parse — topology and encoding', () {
  test('extracts KeyTopology from client.specs.json', () {
    final result = ClientZipParser.parse(zipBytes);
    final topo = result.topology;
    expect(topo, isNotNull);
    // Current model has 6 secret keys, 3 BSKs, 3 KSKs
    expect(topo!.secretKeys.length, 6);
    expect(topo.bootstrapKeys.length, 3);
    expect(topo.keyswitchKeys.length, 3);

    // Spot check SK[0]
    expect(topo.secretKeys[0].id, 0);
    expect(topo.secretKeys[0].lweDimension, 2048);

    // Spot check BSK[0] — inputLweDimension cross-referenced from SK
    expect(topo.bootstrapKeys[0].inputId, 1);
    expect(topo.bootstrapKeys[0].inputLweDimension, 599);
    expect(topo.bootstrapKeys[0].glweDimension, 4);
    expect(topo.bootstrapKeys[0].polynomialSize, 512);
    expect(topo.bootstrapKeys[0].variance, isPositive);

    // Spot check KSK[0]
    expect(topo.keyswitchKeys[0].inputId, 0);
    expect(topo.keyswitchKeys[0].outputId, 1);
    expect(topo.keyswitchKeys[0].inputLweDimension, 2048);
    expect(topo.keyswitchKeys[0].outputLweDimension, 599);
  });

  test('extracts CircuitEncoding from client.specs.json', () {
    final result = ClientZipParser.parse(zipBytes);
    final enc = result.encoding;
    expect(enc, isNotNull);
    // Current model: input width=10 unsigned, output width=8 signed
    expect(enc!.inputWidth, 10);
    expect(enc.inputIsSigned, false);
    expect(enc.outputWidth, 8);
    expect(enc.outputIsSigned, true);
  });

  test('throws if client.specs.json is missing', () {
    // Create zip with only serialized_processing.json, no specs
    final proc = {
      'input_quantizers': [
        {
          'serialized_value': {
            'n_bits': 8, 'is_signed': false,
            'scale': 0.01, 'zero_point': 0,
          }
        }
      ],
      'output_quantizers': [
        {
          'serialized_value': {
            'n_bits': 8, 'is_signed': true,
            'scale': 0.01, 'zero_point': 0, 'offset': 128,
          }
        }
      ],
    };
    final zip = _createZipWithProcessing(proc);
    expect(
      () => ClientZipParser.parse(zip),
      throwsA(isA<FormatException>().having(
        (e) => e.message, 'message', contains('client.specs.json'),
      )),
    );
  });
});

// Update the 'validates n_bits is 8' test — it should no longer reject n_bits=16:
test('accepts non-8-bit quantization n_bits', () {
  final proc = {
    'input_quantizers': [
      {
        'serialized_value': {
          'n_bits': 16, 'is_signed': false,
          'scale': 0.01, 'zero_point': 0,
        }
      }
    ],
    'output_quantizers': [
      {
        'serialized_value': {
          'n_bits': 8, 'is_signed': true,
          'scale': 0.01, 'zero_point': 0, 'offset': 128,
        }
      }
    ],
  };
  final zip = _createZipWithProcessingAndSpecs(proc, _minimalSpecs());
  final result = ClientZipParser.parse(zip);
  expect(result.quantParams.input.length, 1);
});
```

Also add these test helpers:

```dart
Uint8List _createZipWithProcessingAndSpecs(
  Map<String, dynamic> processing,
  Map<String, dynamic> specs,
) {
  final archive = Archive();
  final procBytes = utf8.encode(jsonEncode(processing));
  archive.addFile(ArchiveFile('serialized_processing.json', procBytes.length, procBytes));
  final specsBytes = utf8.encode(jsonEncode(specs));
  archive.addFile(ArchiveFile('client.specs.json', specsBytes.length, specsBytes));
  return Uint8List.fromList(ZipEncoder().encode(archive));
}

Map<String, dynamic> _minimalSpecs() => {
  'keyset': {
    'lweSecretKeys': [
      {'id': 0, 'params': {'lweDimension': 2048}},
      {'id': 1, 'params': {'lweDimension': 599}},
    ],
    'lweBootstrapKeys': [
      {
        'id': 0, 'inputId': 1, 'outputId': 0,
        'params': {
          'levelCount': 1, 'baseLog': 23,
          'glweDimension': 4, 'polynomialSize': 512,
          'variance': 8.4e-31, 'inputLweDimension': 599,
        },
      },
    ],
    'lweKeyswitchKeys': [
      {
        'id': 0, 'inputId': 0, 'outputId': 1,
        'params': {
          'levelCount': 3, 'baseLog': 3,
          'variance': 2.2e-08,
          'inputLweDimension': 2048, 'outputLweDimension': 599,
        },
      },
    ],
    'packingKeyswitchKeys': [],
  },
  'circuits': [
    {
      'inputs': [
        {
          'typeInfo': {
            'lweCiphertext': {
              'encoding': {'integer': {'width': 8, 'isSigned': false}},
            },
          },
        },
      ],
      'outputs': [
        {
          'typeInfo': {
            'lweCiphertext': {
              'encoding': {'integer': {'width': 8, 'isSigned': true}},
            },
          },
        },
      ],
    },
  ],
  'tfhers_specs': {
    'output_shapes_per_func': {},
    'input_shapes_per_func': {},
    'input_types_per_func': {},
    'output_types_per_func': {},
  },
};
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `flutter test test/client_zip_parser_test.dart`
Expected: FAIL — `ClientZipParser.parse` returns `QuantizationParams`, not a result with `.topology`

- [ ] **Step 3: Implement the changes to ClientZipParser**

Modify `lib/src/client_zip_parser.dart`:

1. Add a `ParseResult` class:
```dart
class ParseResult {
  final QuantizationParams quantParams;
  final KeyTopology? topology;
  final CircuitEncoding? encoding;
  const ParseResult({required this.quantParams, this.topology, this.encoding});
}
```

2. Change `parse` return type from `QuantizationParams` to `ParseResult`

3. Remove `_validateNBits` method entirely. Keep `is_signed` validation only (as a warning, not an error).

4. After the existing `nClasses` parsing block, add topology and encoding parsing from the already-loaded `specs` JSON:

```dart
// Parse keyset topology
KeyTopology? topology;
CircuitEncoding? encoding;

if (specsFile == null) {
  throw const FormatException('client.zip missing client.specs.json');
}

// specs is already parsed above
final keyset = specs['keyset'] as Map<String, dynamic>;
final skList = keyset['lweSecretKeys'] as List<dynamic>;
final bskList = keyset['lweBootstrapKeys'] as List<dynamic>;
final kskList = keyset['lweKeyswitchKeys'] as List<dynamic>;

// Build SK lookup for cross-referencing dimensions
final skDims = <int, int>{};
final secretKeys = <SecretKeySpec>[];
for (final sk in skList) {
  final m = sk as Map<String, dynamic>;
  final id = m['id'] as int;
  final dim = (m['params'] as Map<String, dynamic>)['lweDimension'] as int;
  skDims[id] = dim;
  secretKeys.add(SecretKeySpec(id: id, lweDimension: dim));
}

final bootstrapKeys = <BootstrapKeySpec>[];
for (final bsk in bskList) {
  final m = bsk as Map<String, dynamic>;
  final params = m['params'] as Map<String, dynamic>;
  final inputId = m['inputId'] as int;
  bootstrapKeys.add(BootstrapKeySpec(
    inputId: inputId,
    outputId: m['outputId'] as int,
    levelCount: params['levelCount'] as int,
    baseLog: params['baseLog'] as int,
    glweDimension: params['glweDimension'] as int,
    polynomialSize: params['polynomialSize'] as int,
    inputLweDimension: skDims[inputId] ?? (params['inputLweDimension'] as int),
    variance: (params['variance'] as num).toDouble(),
  ));
}

final keyswitchKeys = <KeyswitchKeySpec>[];
for (final ksk in kskList) {
  final m = ksk as Map<String, dynamic>;
  final params = m['params'] as Map<String, dynamic>;
  final inputId = m['inputId'] as int;
  final outputId = m['outputId'] as int;
  keyswitchKeys.add(KeyswitchKeySpec(
    inputId: inputId,
    outputId: outputId,
    levelCount: params['levelCount'] as int,
    baseLog: params['baseLog'] as int,
    inputLweDimension: skDims[inputId] ?? (params['inputLweDimension'] as int),
    outputLweDimension: skDims[outputId] ?? (params['outputLweDimension'] as int),
    variance: (params['variance'] as num).toDouble(),
  ));
}

topology = KeyTopology(
  secretKeys: secretKeys,
  bootstrapKeys: bootstrapKeys,
  keyswitchKeys: keyswitchKeys,
);

// Parse circuit encoding
final circuits = specs['circuits'] as List<dynamic>;
if (circuits.isNotEmpty) {
  final circuit = circuits[0] as Map<String, dynamic>;
  final inputs = circuit['inputs'] as List<dynamic>;
  final outputs = circuit['outputs'] as List<dynamic>;
  if (inputs.isNotEmpty && outputs.isNotEmpty) {
    final inEnc = ((inputs[0] as Map<String, dynamic>)['typeInfo']
        as Map<String, dynamic>)['lweCiphertext'] as Map<String, dynamic>;
    final inEncInt = (inEnc['encoding'] as Map<String, dynamic>)['integer']
        as Map<String, dynamic>;
    final outEnc = ((outputs[0] as Map<String, dynamic>)['typeInfo']
        as Map<String, dynamic>)['lweCiphertext'] as Map<String, dynamic>;
    final outEncInt = (outEnc['encoding'] as Map<String, dynamic>)['integer']
        as Map<String, dynamic>;
    encoding = CircuitEncoding(
      inputWidth: inEncInt['width'] as int,
      inputIsSigned: inEncInt['isSigned'] as bool,
      outputWidth: outEncInt['width'] as int,
      outputIsSigned: outEncInt['isSigned'] as bool,
    );
  }
}

return ParseResult(
  quantParams: QuantizationParams(input: input, output: output, nClasses: nClasses),
  topology: topology,
  encoding: encoding,
);
```

5. Update `ConcreteClient` to use `ParseResult` (just change `_quantParams = ClientZipParser.parse(...)` to `final result = ClientZipParser.parse(...); _quantParams = result.quantParams;` — we'll wire topology in Task 6).

- [ ] **Step 4: Update the old test that checked n_bits=16 rejection**

The test `'validates n_bits is 8'` should be replaced with the new `'accepts non-8-bit quantization n_bits'` test. Also update `_createZipWithProcessing` to include a minimal `client.specs.json` since it's now required.

- [ ] **Step 5: Run tests to verify they pass**

Run: `flutter test test/client_zip_parser_test.dart`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add lib/src/client_zip_parser.dart test/client_zip_parser_test.dart lib/src/concrete_client.dart
git commit -m "feat: parse KeyTopology and CircuitEncoding from client.specs.json"
```

---

### Task 4: Update QuantizationParams for multi-width and Int64List

**Files:**
- Modify: `lib/src/quantizer.dart`
- Modify: `lib/src/client_zip_parser.dart`
- Create: `test/quantizer_test.dart`

**Important ordering note:** `InputQuantParam` and `OutputQuantParam` get new `nBits` and `isSigned` fields with defaults (`nBits: 8`) so existing callers (including Task 3's parser code) continue to compile. The parser is updated in Step 4 to pass actual values.

- [ ] **Step 1: Write failing tests**

```dart
// test/quantizer_test.dart
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
      expect(result[0], 255); // clamped to 2^8 - 1
    });

    test('uses n_bits for clamping range (16-bit unsigned)', () {
      final params = QuantizationParams(
        input: [InputQuantParam(scale: 1.0, zeroPoint: 0, nBits: 16, isSigned: false)],
        output: OutputQuantParam(scale: 1.0, zeroPoint: 0, offset: 0),
      );
      final features = Float32List.fromList([70000.0]);
      final result = params.quantizeInputs(features);
      expect(result[0], 65535); // clamped to 2^16 - 1
    });

    test('uses n_bits for clamping range (8-bit signed)', () {
      final params = QuantizationParams(
        input: [InputQuantParam(scale: 1.0, zeroPoint: 0, nBits: 8, isSigned: true)],
        output: OutputQuantParam(scale: 1.0, zeroPoint: 0, offset: 0),
      );
      final features = Float32List.fromList([-200.0, 200.0]);
      final result = params.quantizeInputs(features);
      expect(result[0], -128); // clamped to -(2^7)
      expect(result[1], 127);  // clamped to 2^7 - 1
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
      expect(result[0], 63.5);  // (-1 + 128 - 0) * 0.5
      expect(result[1], 64.0);  // (0 + 128 - 0) * 0.5
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
      expect(result[0], 6.0);   // 1+2+3
      expect(result[1], 15.0);  // 4+5+6
    });
  });
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `flutter test test/quantizer_test.dart`
Expected: FAIL — `InputQuantParam` doesn't take `nBits`, `quantizeInputs` returns `Uint8List` not `Int64List`, `dequantizeOutputs` takes `Int8List` not `Int64List`

- [ ] **Step 3: Update QuantizationParams**

Modify `lib/src/quantizer.dart`:

```dart
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
  final int? nClasses;

  const QuantizationParams({
    required this.input,
    required this.output,
    this.nClasses,
  });

  /// Quantize float feature vector using per-feature input params.
  ///
  /// Clamping range derived from [InputQuantParam.nBits] and [InputQuantParam.isSigned]:
  ///   unsigned N-bit: [0, 2^N - 1]
  ///   signed N-bit: [-2^(N-1), 2^(N-1) - 1]
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
        final lo = -(1 << (p.nBits - 1));
        final hi = (1 << (p.nBits - 1)) - 1;
        result[i] = q.clamp(lo, hi);
      } else {
        result[i] = q.clamp(0, (1 << p.nBits) - 1);
      }
    }
    return result;
  }

  /// Dequantize raw output scores to float64.
  ///
  /// For tree-ensemble models (XGBoost), when [nClasses] is set and
  /// `rawScores.length` is a multiple of it, raw values are summed
  /// across trees per class.
  Float64List dequantizeOutputs(Int64List rawScores) {
    final p = output;

    if (nClasses != null &&
        nClasses! > 0 &&
        rawScores.length > nClasses! &&
        rawScores.length % nClasses! == 0) {
      final nTrees = rawScores.length ~/ nClasses!;
      final result = Float64List(nClasses!);
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

    final result = Float64List(rawScores.length);
    for (int i = 0; i < rawScores.length; i++) {
      result[i] = (rawScores[i] + p.offset - p.zeroPoint) * p.scale;
    }
    return result;
  }
}
```

- [ ] **Step 4: Update ClientZipParser to pass nBits/isSigned**

In `client_zip_parser.dart`, update the input quantizer parsing to read and pass `n_bits` and `is_signed`:

```dart
// In the input quantizer loop:
input.add(InputQuantParam(
  scale: _extractFloat(sv['scale']),
  zeroPoint: _extractInt(sv['zero_point']),
  nBits: sv['n_bits'] as int,
  isSigned: sv['is_signed'] as bool,
));

// For the output quantizer:
final output = OutputQuantParam(
  scale: _extractFloat(outSv['scale']),
  zeroPoint: _extractInt(outSv['zero_point']),
  offset: outSv.containsKey('offset') ? _extractInt(outSv['offset']) : 0,
  nBits: outSv['n_bits'] as int,
  isSigned: outSv['is_signed'] as bool,
);
```

Remove the `_validateNBits` method entirely.

- [ ] **Step 5: Run all tests**

Run: `flutter test`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add lib/src/quantizer.dart lib/src/client_zip_parser.dart test/quantizer_test.dart
git commit -m "feat: multi-width quantization with Int64List I/O"
```

---

### Task 5: Update Rust FFI — dynamic keygen, multi-width encrypt/decrypt

**Files:**
- Modify: `rust/src/lib.rs`

This is the largest and highest-risk task. It replaces all three exported C functions and the internal `generate_concrete_eval_keys` function.

**Key architectural constraint:** SK[0] is always derived from the TFHE-rs `ClientKey`'s GLWE key (dim=1, poly=N). The topology's first secret key MUST match this. BSK output keys that have `lweDimension == glweDimension * polynomialSize` are GLWE-derived; all others are plain LWE keys.

- [ ] **Step 1: Add wider type imports and topology unpacking**

At the top of `lib.rs`, update imports:

```rust
use tfhe::{ClientKey, ConfigBuilder, FheInt8, FheInt16, FheInt32, FheInt64,
           FheUint8, FheUint16, FheUint32, FheUint64};
```

Add topology unpacking structs and function after the `LIMIT` constant:

```rust
// ── Topology from Dart FFI ──────────────────────────────────────────────────

struct SkSpec { id: u64, dim: u64 }
struct BskSpec {
    input_id: u64, output_id: u64,
    level_count: u64, base_log: u64,
    glwe_dim: u64, poly_size: u64,
    input_lwe_dim: u64, variance: f64,
}
struct KskSpec {
    input_id: u64, output_id: u64,
    level_count: u64, base_log: u64,
    input_lwe_dim: u64, output_lwe_dim: u64,
    variance: f64,
}

struct Topology {
    sks: Vec<SkSpec>,
    bsks: Vec<BskSpec>,
    ksks: Vec<KskSpec>,
}

fn unpack_topology(data: &[u64]) -> Result<Topology, String> {
    let mut i = 0;
    let read = |i: &mut usize| -> Result<u64, String> {
        if *i >= data.len() { return Err("topology buffer underflow".into()); }
        let v = data[*i]; *i += 1; Ok(v)
    };

    let num_sks = read(&mut i)? as usize;
    let mut sks = Vec::with_capacity(num_sks);
    for _ in 0..num_sks {
        sks.push(SkSpec { id: read(&mut i)?, dim: read(&mut i)? });
    }

    let num_bsks = read(&mut i)? as usize;
    let mut bsks = Vec::with_capacity(num_bsks);
    for _ in 0..num_bsks {
        let input_id = read(&mut i)?;
        let output_id = read(&mut i)?;
        let level_count = read(&mut i)?;
        let base_log = read(&mut i)?;
        let glwe_dim = read(&mut i)?;
        let poly_size = read(&mut i)?;
        let input_lwe_dim = read(&mut i)?;
        let variance_bits = read(&mut i)?;
        let variance = f64::from_bits(variance_bits);
        bsks.push(BskSpec {
            input_id, output_id, level_count, base_log,
            glwe_dim, poly_size, input_lwe_dim, variance,
        });
    }

    let num_ksks = read(&mut i)? as usize;
    let mut ksks = Vec::with_capacity(num_ksks);
    for _ in 0..num_ksks {
        let input_id = read(&mut i)?;
        let output_id = read(&mut i)?;
        let level_count = read(&mut i)?;
        let base_log = read(&mut i)?;
        let input_lwe_dim = read(&mut i)?;
        let output_lwe_dim = read(&mut i)?;
        let variance_bits = read(&mut i)?;
        let variance = f64::from_bits(variance_bits);
        ksks.push(KskSpec {
            input_id, output_id, level_count, base_log,
            input_lwe_dim, output_lwe_dim, variance,
        });
    }

    Ok(Topology { sks, bsks, ksks })
}
```

- [ ] **Step 2: Replace `generate_concrete_eval_keys` with dynamic version**

Replace the entire `generate_concrete_eval_keys` function:

```rust
fn generate_concrete_eval_keys(ck: &ClientKey, topo: &Topology) -> Result<Vec<u8>, String> {
    use std::collections::HashMap;

    // ── Extract root GLWE key (SK[0]) from TFHE-rs ClientKey ────────────────
    let (integer_ck, _, _, _) = ck.clone().into_raw_parts();
    let shortint_ck = integer_ck.into_raw_parts();
    let (glwe_sk0, _tfhe_lwe_sk, _params) = shortint_ck.into_raw_parts();
    let sk0_lwe = glwe_sk0.clone().into_lwe_secret_key();

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut sec_gen = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let noise = |var: f64| Gaussian::from_dispersion_parameter(StandardDev(var.sqrt()), 0.0);

    // ── Determine which SKs are GLWE-derived (used as BSK output) ───────────
    // BSK output SK has lweDimension = glweDimension * polynomialSize
    let mut glwe_output_sks: HashMap<u64, (u64, u64)> = HashMap::new(); // sk_id -> (glwe_dim, poly_size)
    for bsk in &topo.bsks {
        glwe_output_sks.insert(bsk.output_id, (bsk.glwe_dim, bsk.poly_size));
    }

    // ── Generate all secret keys ────────────────────────────────────────────
    // SK[0] comes from the ClientKey. All others are generated fresh.
    let mut lwe_sks: HashMap<u64, tfhe::core_crypto::entities::LweSecretKeyOwned<u64>> = HashMap::new();
    let mut glwe_sks: HashMap<u64, tfhe::core_crypto::entities::GlweSecretKeyOwned<u64>> = HashMap::new();

    // Store SK[0]
    let sk0_id = topo.sks[0].id;
    lwe_sks.insert(sk0_id, sk0_lwe);
    glwe_sks.insert(sk0_id, glwe_sk0);

    for sk_spec in &topo.sks[1..] {
        if let Some(&(glwe_dim, poly_size)) = glwe_output_sks.get(&sk_spec.id) {
            // This SK backs a BSK output — generate as GLWE key
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                GlweDimension(glwe_dim as usize),
                PolynomialSize(poly_size as usize),
                &mut sec_gen,
            );
            let lwe_sk = glwe_sk.clone().into_lwe_secret_key();
            glwe_sks.insert(sk_spec.id, glwe_sk);
            lwe_sks.insert(sk_spec.id, lwe_sk);
        } else {
            // Plain small LWE key
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                LweDimension(sk_spec.dim as usize),
                &mut sec_gen,
            );
            lwe_sks.insert(sk_spec.id, lwe_sk);
        }
    }

    // ── Generate seeded BSKs ────────────────────────────────────────────────
    let mut bsk_data: Vec<(Vec<u8>, &BskSpec)> = Vec::new();
    for bsk_spec in &topo.bsks {
        let input_sk = lwe_sks.get(&bsk_spec.input_id)
            .ok_or_else(|| format!("BSK input SK {} not found", bsk_spec.input_id))?;
        let output_glwe = glwe_sks.get(&bsk_spec.output_id)
            .ok_or_else(|| format!("BSK output GLWE SK {} not found", bsk_spec.output_id))?;

        let glwe_size = GlweSize(bsk_spec.glwe_dim as usize + 1);
        let mut bsk = SeededLweBootstrapKey::new(
            0u64, glwe_size,
            PolynomialSize(bsk_spec.poly_size as usize),
            DecompositionBaseLog(bsk_spec.base_log as usize),
            DecompositionLevelCount(bsk_spec.level_count as usize),
            LweDimension(bsk_spec.input_lwe_dim as usize),
            seeder.seed().into(),
            CiphertextModulus::new_native(),
        );
        generate_seeded_lwe_bootstrap_key(
            input_sk, output_glwe, &mut bsk,
            noise(bsk_spec.variance), seeder,
        );

        // Serialize: [seed(16 bytes) || body_u64_bytes]
        let seed_bytes: [u8; 16] = bsk.compression_seed().seed.0.to_le_bytes();
        let body_bytes = bytemuck::cast_slice::<u64, u8>(bsk.as_ref());
        let mut v = Vec::with_capacity(16 + body_bytes.len());
        v.extend_from_slice(&seed_bytes);
        v.extend_from_slice(body_bytes);
        bsk_data.push((v, bsk_spec));
    }

    // ── Generate seeded KSKs ────────────────────────────────────────────────
    let mut ksk_data: Vec<(Vec<u8>, &KskSpec)> = Vec::new();
    for ksk_spec in &topo.ksks {
        let input_sk = lwe_sks.get(&ksk_spec.input_id)
            .ok_or_else(|| format!("KSK input SK {} not found", ksk_spec.input_id))?;
        let output_sk = lwe_sks.get(&ksk_spec.output_id)
            .ok_or_else(|| format!("KSK output SK {} not found", ksk_spec.output_id))?;

        let mut ksk = SeededLweKeyswitchKey::new(
            0u64,
            DecompositionBaseLog(ksk_spec.base_log as usize),
            DecompositionLevelCount(ksk_spec.level_count as usize),
            LweDimension(ksk_spec.input_lwe_dim as usize),
            LweDimension(ksk_spec.output_lwe_dim as usize),
            seeder.seed().into(),
            CiphertextModulus::new_native(),
        );
        generate_seeded_lwe_keyswitch_key(
            input_sk, output_sk, &mut ksk,
            noise(ksk_spec.variance), seeder,
        );

        let seed_bytes: [u8; 16] = ksk.compression_seed().seed.0.to_le_bytes();
        let body_bytes = bytemuck::cast_slice::<u64, u8>(ksk.as_ref());
        let mut v = Vec::with_capacity(16 + body_bytes.len());
        v.extend_from_slice(&seed_bytes);
        v.extend_from_slice(body_bytes);
        ksk_data.push((v, ksk_spec));
    }

    // ── Build Cap'n Proto ServerKeyset ──────────────────────────────────────
    let mut message = Builder::new_default();
    {
        use concrete_protocol_capnp::server_keyset;
        let mut keyset = message.init_root::<server_keyset::Builder<'_>>();

        // BSKs
        let mut bsks = keyset.reborrow().init_lwe_bootstrap_keys(bsk_data.len() as u32);
        for (idx, (bytes, spec)) in bsk_data.iter().enumerate() {
            let mut m = bsks.reborrow().get(idx as u32);
            {
                let mut info = m.reborrow().init_info();
                info.set_id(idx as u32);
                info.set_input_id(spec.input_id as u32);
                info.set_output_id(spec.output_id as u32);
                info.set_compression(concrete_protocol_capnp::Compression::Seed);
                let mut p = info.init_params();
                p.set_level_count(spec.level_count as u32);
                p.set_base_log(spec.base_log as u32);
                p.set_glwe_dimension(spec.glwe_dim as u32);
                p.set_polynomial_size(spec.poly_size as u32);
                p.set_input_lwe_dimension(spec.input_lwe_dim as u32);
                p.set_variance(spec.variance);
                p.set_integer_precision(64);
                p.set_key_type(concrete_protocol_capnp::KeyType::Binary);
                p.init_modulus().reborrow().get_modulus().init_native();
            }
            write_payload_chunks(&mut m.init_payload(), bytes);
        }

        // KSKs
        let mut ksks = keyset.reborrow().init_lwe_keyswitch_keys(ksk_data.len() as u32);
        for (idx, (bytes, spec)) in ksk_data.iter().enumerate() {
            let mut m = ksks.reborrow().get(idx as u32);
            {
                let mut info = m.reborrow().init_info();
                info.set_id(idx as u32);
                info.set_input_id(spec.input_id as u32);
                info.set_output_id(spec.output_id as u32);
                info.set_compression(concrete_protocol_capnp::Compression::Seed);
                let mut p = info.init_params();
                p.set_level_count(spec.level_count as u32);
                p.set_base_log(spec.base_log as u32);
                p.set_input_lwe_dimension(spec.input_lwe_dim as u32);
                p.set_output_lwe_dimension(spec.output_lwe_dim as u32);
                p.set_variance(spec.variance);
                p.set_integer_precision(64);
                p.set_key_type(concrete_protocol_capnp::KeyType::Binary);
                p.init_modulus().reborrow().get_modulus().init_native();
            }
            write_payload_chunks(&mut m.init_payload(), bytes);
        }

        keyset.init_packing_keyswitch_keys(0);
    }

    let mut buf: Vec<u8> = Vec::new();
    serialize::write_message(&mut buf, &message).map_err(|e| e.to_string())?;
    Ok(buf)
}
```

- [ ] **Step 3: Replace `fhe_keygen` FFI function**

Replace the entire `fhe_keygen` function. Drop the unused `lwe_key_out` parameter:

```rust
#[no_mangle]
pub unsafe extern "C" fn fhe_keygen(
    topology_ptr:   *const u64, topology_len: usize,
    client_key_out: *mut *mut u8, client_key_len: *mut usize,
    server_key_out: *mut *mut u8, server_key_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let topo_data = slice::from_raw_parts(topology_ptr, topology_len);
        let topo = unpack_topology(topo_data)?;

        let config = ConfigBuilder::default()
            .use_custom_parameters(V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            .build();
        let (client_key, _server_key) = tfhe::generate_keys(config);

        // Serialise client key
        let mut ck_buf = Vec::new();
        safe_serialize(&client_key, &mut ck_buf, LIMIT).map_err(|e| e.to_string())?;

        // Generate eval keys from topology
        let sk_buf = generate_concrete_eval_keys(&client_key, &topo)?;

        let (ck_ptr, ck_len) = leak_buf(ck_buf);
        let (sk_ptr, sk_len) = leak_buf(sk_buf);

        *client_key_out = ck_ptr;  *client_key_len = ck_len;
        *server_key_out = sk_ptr;  *server_key_len = sk_len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}
```

- [ ] **Step 4: Replace `fhe_encrypt_u8` with `fhe_encrypt`**

```rust
/// Encrypt values with the client key, dispatching to the correct TFHE-rs type.
///
/// `values` is an array of `i64` — each is cast to the target type before encrypting.
/// `bit_width`: 8, 16, 32, or 64. `is_signed`: 0 = unsigned, 1 = signed.
#[no_mangle]
pub unsafe extern "C" fn fhe_encrypt(
    client_key: *const u8, client_key_len: usize,
    values:     *const i64, n_vals:        usize,
    bit_width:  u32,
    is_signed:  u32,
    ct_out:     *mut *mut u8, ct_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let ck_bytes = slice::from_raw_parts(client_key, client_key_len);
        let vals = slice::from_raw_parts(values, n_vals);
        let ck: ClientKey = safe_deserialize(Cursor::new(ck_bytes), LIMIT)
            .map_err(|e| e.to_string())?;

        macro_rules! encrypt_dispatch {
            ($fhe_type:ty, $cast:ty) => {{
                let cts: Vec<$fhe_type> = vals.iter()
                    .map(|&v| <$fhe_type>::encrypt(v as $cast, &ck))
                    .collect();
                bincode::serialize(&cts).map_err(|e| e.to_string())?
            }};
        }

        let serialised = match (bit_width, is_signed != 0) {
            (8,  false) => encrypt_dispatch!(FheUint8,  u8),
            (8,  true)  => encrypt_dispatch!(FheInt8,   i8),
            (16, false) => encrypt_dispatch!(FheUint16, u16),
            (16, true)  => encrypt_dispatch!(FheInt16,  i16),
            (32, false) => encrypt_dispatch!(FheUint32, u32),
            (32, true)  => encrypt_dispatch!(FheInt32,  i32),
            (64, false) => encrypt_dispatch!(FheUint64, u64),
            (64, true)  => encrypt_dispatch!(FheInt64,  i64),
            _ => return Err(format!("unsupported bit_width={bit_width} is_signed={is_signed}")),
        };

        let (ptr, len) = leak_buf(serialised);
        *ct_out = ptr;
        *ct_len = len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}
```

- [ ] **Step 5: Replace `fhe_decrypt_i8` with `fhe_decrypt`**

```rust
/// Decrypt ciphertext, dispatching to the correct TFHE-rs type.
///
/// Output is always `i64` values (zero-extended for unsigned, sign-extended for signed).
/// `scores_len` is set to the number of elements (not bytes).
#[no_mangle]
pub unsafe extern "C" fn fhe_decrypt(
    client_key: *const u8, client_key_len: usize,
    ct:         *const u8, ct_len:         usize,
    bit_width:  u32,
    is_signed:  u32,
    scores_out: *mut *mut i64, scores_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let ck_bytes = slice::from_raw_parts(client_key, client_key_len);
        let ct_bytes = slice::from_raw_parts(ct, ct_len);
        let ck: ClientKey = safe_deserialize(Cursor::new(ck_bytes), LIMIT)
            .map_err(|e| e.to_string())?;

        macro_rules! decrypt_dispatch {
            ($fhe_type:ty, $cast:ty) => {{
                let fhe_vals: Vec<$fhe_type> = bincode::deserialize(ct_bytes)
                    .map_err(|e| e.to_string())?;
                let raw: Vec<i64> = fhe_vals.iter()
                    .map(|v| { let x: $cast = v.decrypt(&ck); x as i64 })
                    .collect();
                raw
            }};
        }

        let raw: Vec<i64> = match (bit_width, is_signed != 0) {
            (8,  false) => decrypt_dispatch!(FheUint8,  u8),
            (8,  true)  => decrypt_dispatch!(FheInt8,   i8),
            (16, false) => decrypt_dispatch!(FheUint16, u16),
            (16, true)  => decrypt_dispatch!(FheInt16,  i16),
            (32, false) => decrypt_dispatch!(FheUint32, u32),
            (32, true)  => decrypt_dispatch!(FheInt32,  i32),
            (64, false) => decrypt_dispatch!(FheUint64, u64),
            (64, true)  => decrypt_dispatch!(FheInt64,  i64),
            _ => return Err(format!("unsupported bit_width={bit_width} is_signed={is_signed}")),
        };

        let len = raw.len();
        let ptr = Box::into_raw(raw.into_boxed_slice()) as *mut i64;
        *scores_out = ptr;
        *scores_len = len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}
```

- [ ] **Step 6: Update free functions**

Remove `fhe_free_i8_buf`, add `fhe_free_i64_buf`. Keep `fhe_free_buf` unchanged:

```rust
#[no_mangle]
pub unsafe extern "C" fn fhe_free_i64_buf(ptr: *mut i64, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(Box::from_raw(slice::from_raw_parts_mut(ptr, len)));
    }
}
```

- [ ] **Step 7: Update Rust test**

Replace the test to use a topology matching the current `client.specs.json` (6 SKs, 3 BSKs, 3 KSKs):

```rust
#[test]
fn generate_concrete_eval_keys_smoke() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64)
        .build();
    let (client_key, _server_key) = tfhe::generate_keys(config);

    let topo = Topology {
        sks: vec![
            SkSpec { id: 0, dim: 2048 },
            SkSpec { id: 1, dim: 599 },
            SkSpec { id: 2, dim: 1536 },
            SkSpec { id: 3, dim: 719 },
            SkSpec { id: 4, dim: 2048 },
            SkSpec { id: 5, dim: 738 },
        ],
        bsks: vec![
            BskSpec { input_id: 1, output_id: 0, level_count: 1, base_log: 23,
                      glwe_dim: 4, poly_size: 512, input_lwe_dim: 599,
                      variance: 8.442253112932959e-31 },
            BskSpec { input_id: 3, output_id: 2, level_count: 1, base_log: 18,
                      glwe_dim: 6, poly_size: 256, input_lwe_dim: 719,
                      variance: 7.040630965929754e-23 },
            BskSpec { input_id: 5, output_id: 4, level_count: 2, base_log: 15,
                      glwe_dim: 2, poly_size: 1024, input_lwe_dim: 738,
                      variance: 8.442253112932959e-31 },
        ],
        ksks: vec![
            KskSpec { input_id: 0, output_id: 1, level_count: 3, base_log: 3,
                      input_lwe_dim: 2048, output_lwe_dim: 599,
                      variance: 2.207703775750815e-08 },
            KskSpec { input_id: 0, output_id: 3, level_count: 2, base_log: 5,
                      input_lwe_dim: 2048, output_lwe_dim: 719,
                      variance: 3.0719950829084015e-10 },
            KskSpec { input_id: 2, output_id: 5, level_count: 4, base_log: 3,
                      input_lwe_dim: 1536, output_lwe_dim: 738,
                      variance: 1.5612464764249122e-10 },
        ],
    };

    let eval_key_bytes = generate_concrete_eval_keys(&client_key, &topo)
        .expect("generate_concrete_eval_keys failed");

    let mut opts = capnp::message::ReaderOptions::new();
    opts.traversal_limit_in_words(Some(1 << 28));
    let reader = serialize::read_message(&eval_key_bytes[..], opts)
        .expect("Cap'n Proto deserialization failed");
    let keyset = reader
        .get_root::<concrete_protocol_capnp::server_keyset::Reader<'_>>()
        .expect("get_root failed");

    let bsks = keyset.get_lwe_bootstrap_keys().unwrap();
    let ksks = keyset.get_lwe_keyswitch_keys().unwrap();
    assert_eq!(bsks.len(), 3);
    assert_eq!(ksks.len(), 3);

    // Spot-check BSK[0]
    let bsk0_params = bsks.get(0).get_info().unwrap().get_params().unwrap();
    assert_eq!(bsk0_params.get_input_lwe_dimension(), 599);
    assert_eq!(bsk0_params.get_level_count(), 1);
    assert_eq!(bsk0_params.get_base_log(), 23);

    // Spot-check KSK[0]
    let ksk0_params = ksks.get(0).get_info().unwrap().get_params().unwrap();
    assert_eq!(ksk0_params.get_input_lwe_dimension(), 2048);
    assert_eq!(ksk0_params.get_output_lwe_dimension(), 599);
}
```

- [ ] **Step 8: Verify Rust compiles**

Run: `cd /Users/afonso/Documents/projects/e2ee_journal/flutter_concrete/rust && cargo build`
Expected: Compiles without errors

- [ ] **Step 9: Commit**

```bash
git add rust/src/lib.rs
git commit -m "feat: dynamic keygen and multi-width encrypt/decrypt in Rust FFI"
```

---

### Task 6: Update Dart FFI bindings (FheNative)

**Files:**
- Modify: `lib/src/fhe_native.dart`

- [ ] **Step 1: Replace the complete file**

```dart
// lib/src/fhe_native.dart
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// ── C function signatures ─────────────────────────────────────────────────────

// int32_t fhe_keygen(
//     const uint64_t *topology, size_t topology_len,
//     uint8_t **ck_out, size_t *ck_len,
//     uint8_t **sk_out, size_t *sk_len)
typedef _FheKeygenC = Int32 Function(
    Pointer<Uint64>, Size,
    Pointer<Pointer<Uint8>>, Pointer<Size>,
    Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _FheKeygenDart = int Function(
    Pointer<Uint64>, int,
    Pointer<Pointer<Uint8>>, Pointer<Size>,
    Pointer<Pointer<Uint8>>, Pointer<Size>);

// int32_t fhe_encrypt(
//     const uint8_t *ck, size_t ck_len,
//     const int64_t *vals, size_t n_vals,
//     uint32_t bit_width, uint32_t is_signed,
//     uint8_t **ct_out, size_t *ct_len)
typedef _FheEncryptC = Int32 Function(
    Pointer<Uint8>, Size,
    Pointer<Int64>, Size,
    Uint32, Uint32,
    Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _FheEncryptDart = int Function(
    Pointer<Uint8>, int,
    Pointer<Int64>, int,
    int, int,
    Pointer<Pointer<Uint8>>, Pointer<Size>);

// int32_t fhe_decrypt(
//     const uint8_t *ck, size_t ck_len,
//     const uint8_t *ct, size_t ct_len,
//     uint32_t bit_width, uint32_t is_signed,
//     int64_t **out, size_t *out_len)
typedef _FheDecryptC = Int32 Function(
    Pointer<Uint8>, Size,
    Pointer<Uint8>, Size,
    Uint32, Uint32,
    Pointer<Pointer<Int64>>, Pointer<Size>);
typedef _FheDecryptDart = int Function(
    Pointer<Uint8>, int,
    Pointer<Uint8>, int,
    int, int,
    Pointer<Pointer<Int64>>, Pointer<Size>);

// void fhe_free_buf(uint8_t *ptr, size_t len)
typedef _FheFreeC    = Void Function(Pointer<Uint8>, Size);
typedef _FheFreeDart = void Function(Pointer<Uint8>, int);

// void fhe_free_i64_buf(int64_t *ptr, size_t len)
typedef _FheFreeI64C    = Void Function(Pointer<Int64>, Size);
typedef _FheFreeI64Dart = void Function(Pointer<Int64>, int);

// ── FheNative ─────────────────────────────────────────────────────────────────

class FheNative {
  late final _FheKeygenDart  _keygen;
  late final _FheEncryptDart _encrypt;
  late final _FheDecryptDart _decrypt;
  late final _FheFreeDart    _freeBuf;
  late final _FheFreeI64Dart _freeI64Buf;

  FheNative() {
    final lib = _loadLibrary();
    _keygen    = lib.lookupFunction<_FheKeygenC,  _FheKeygenDart> ('fhe_keygen');
    _encrypt   = lib.lookupFunction<_FheEncryptC, _FheEncryptDart>('fhe_encrypt');
    _decrypt   = lib.lookupFunction<_FheDecryptC, _FheDecryptDart>('fhe_decrypt');
    _freeBuf   = lib.lookupFunction<_FheFreeC,    _FheFreeDart>   ('fhe_free_buf');
    _freeI64Buf = lib.lookupFunction<_FheFreeI64C, _FheFreeI64Dart>('fhe_free_i64_buf');
  }

  static DynamicLibrary _loadLibrary() {
    if (Platform.isIOS) {
      return DynamicLibrary.process();
    } else if (Platform.isAndroid) {
      return DynamicLibrary.open('libfhe_client.so');
    } else if (Platform.isLinux) {
      return DynamicLibrary.open('libfhe_client.so');
    } else if (Platform.isMacOS) {
      return DynamicLibrary.open('libfhe_client.dylib');
    }
    throw UnsupportedError(
        'FHE native library not supported on ${Platform.operatingSystem}');
  }

  /// Generate keys using the given topology.
  ///
  /// [topology] is a packed Uint64List from KeyTopology.pack().
  KeygenResult keygen(Uint64List topology) {
    final topoPtr = malloc<Uint64>(topology.length);
    for (int i = 0; i < topology.length; i++) {
      topoPtr[i] = topology[i];
    }
    final ckPtrPtr = malloc<Pointer<Uint8>>();
    final ckLen    = malloc<Size>();
    final skPtrPtr = malloc<Pointer<Uint8>>();
    final skLen    = malloc<Size>();

    try {
      final rc = _keygen(
          topoPtr, topology.length,
          ckPtrPtr, ckLen, skPtrPtr, skLen);
      if (rc != 0) throw StateError('fhe_keygen failed (code $rc)');

      final ck = _readAndFree(ckPtrPtr.value, ckLen.value);
      final sk = _readAndFree(skPtrPtr.value, skLen.value);
      return KeygenResult(clientKey: ck, serverKey: sk);
    } finally {
      malloc.free(topoPtr);
      malloc.free(ckPtrPtr); malloc.free(ckLen);
      malloc.free(skPtrPtr); malloc.free(skLen);
    }
  }

  /// Encrypt [values] under [clientKey] using the specified TFHE-rs type.
  Uint8List encrypt(Uint8List clientKey, Int64List values,
                    int bitWidth, bool isSigned) {
    final ckPtr  = _toNativeUint8(clientKey);
    final valPtr = malloc<Int64>(values.length);
    for (int i = 0; i < values.length; i++) {
      valPtr[i] = values[i];
    }
    final ctPtrPtr = malloc<Pointer<Uint8>>();
    final ctLen    = malloc<Size>();

    try {
      final rc = _encrypt(
          ckPtr, clientKey.length,
          valPtr, values.length,
          bitWidth, isSigned ? 1 : 0,
          ctPtrPtr, ctLen);
      if (rc != 0) throw StateError('fhe_encrypt failed (code $rc)');
      return _readAndFree(ctPtrPtr.value, ctLen.value);
    } finally {
      malloc.free(ckPtr); malloc.free(valPtr);
      malloc.free(ctPtrPtr); malloc.free(ctLen);
    }
  }

  /// Decrypt [ciphertext] under [clientKey], returning i64 values.
  Int64List decrypt(Uint8List clientKey, Uint8List ciphertext,
                    int bitWidth, bool isSigned) {
    final ckPtr = _toNativeUint8(clientKey);
    final ctPtr = _toNativeUint8(ciphertext);
    final outPtrPtr = malloc<Pointer<Int64>>();
    final outLen    = malloc<Size>();

    try {
      final rc = _decrypt(
          ckPtr, clientKey.length,
          ctPtr, ciphertext.length,
          bitWidth, isSigned ? 1 : 0,
          outPtrPtr, outLen);
      if (rc != 0) throw StateError('fhe_decrypt failed (code $rc)');

      final len = outLen.value;
      final result = Int64List(len);
      for (int i = 0; i < len; i++) {
        result[i] = outPtrPtr.value[i];
      }
      _freeI64Buf(outPtrPtr.value, len);
      return result;
    } finally {
      malloc.free(ckPtr); malloc.free(ctPtr);
      malloc.free(outPtrPtr); malloc.free(outLen);
    }
  }

  Pointer<Uint8> _toNativeUint8(Uint8List data) {
    final ptr = malloc<Uint8>(data.length);
    for (int i = 0; i < data.length; i++) {
      ptr[i] = data[i];
    }
    return ptr;
  }

  Uint8List _readAndFree(Pointer<Uint8> ptr, int len) {
    final result = Uint8List.fromList(ptr.asTypedList(len));
    _freeBuf(ptr, len);
    return result;
  }
}

/// Result of [FheNative.keygen].
class KeygenResult {
  final Uint8List clientKey;
  final Uint8List serverKey;
  const KeygenResult({required this.clientKey, required this.serverKey});
}
```

- [ ] **Step 2: Verify it analyzes cleanly**

Run: `flutter analyze`
Expected: No errors (runtime testing requires native library)

- [ ] **Step 3: Commit**

```bash
git add lib/src/fhe_native.dart
git commit -m "feat: update Dart FFI bindings for dynamic keygen and multi-width"
```

---

### Task 7: Wire ConcreteClient with topology, encoding, and model hash

**Files:**
- Modify: `lib/src/concrete_client.dart`
- Extend: `test/concrete_client_test.dart`

- [ ] **Step 1: Write failing test for model hash invalidation**

Add to `test/concrete_client_test.dart`:

```dart
test('model hash key is stored in KeyStorage after setup', () async {
  // This test verifies the storage key exists, but cannot run full setup
  // without the native library. We test the logic path by checking
  // that ConcreteClient attempts to write 'fhe_model_hash'.
  final storage = MemoryKeyStorage();
  // We can't test full setup without native lib, but verify the
  // constant is correct.
  expect(ConcreteClient.modelHashStorageKey, 'fhe_model_hash');
});
```

- [ ] **Step 2: Replace concrete_client.dart**

```dart
// lib/src/concrete_client.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';

import 'client_zip_parser.dart';
import 'circuit_encoding.dart';
import 'fhe_native.dart';
import 'key_storage.dart';
import 'key_topology.dart';
import 'quantizer.dart';

const _kClientKeyStorageKey = 'fhe_client_key';
const _kServerKeyStorageKey = 'fhe_server_key';
const _kModelHashStorageKey = 'fhe_model_hash';

class ConcreteClient {
  static const modelHashStorageKey = _kModelHashStorageKey;

  FheNative? _nativeInstance;
  FheNative get _native => _nativeInstance ??= FheNative();

  QuantizationParams? _quantParams;
  KeyTopology? _topology;
  CircuitEncoding? _encoding;
  Uint8List? _clientKey;
  Uint8List? _serverKey;
  String? _serverKeyB64Cache;
  bool _isReady = false;

  bool get isReady => _isReady;

  Uint8List get serverKey {
    _requireReady();
    return _serverKey!;
  }

  String get serverKeyBase64 {
    _requireReady();
    return _serverKeyB64Cache ??= base64Encode(_serverKey!);
  }

  Future<void> setup({
    required Uint8List clientZipBytes,
    required KeyStorage storage,
  }) async {
    if (_isReady) return;

    // 1. Parse client.zip
    final result = ClientZipParser.parse(clientZipBytes);
    _quantParams = result.quantParams;
    _topology = result.topology;
    _encoding = result.encoding;

    // 2. Compute model hash from topology + encoding
    final currentHash = _topology!.computeModelHash(_encoding!);

    // 3. Check stored hash
    final storedHash = await storage.read(_kModelHashStorageKey);
    final storedClient = await storage.read(_kClientKeyStorageKey);
    final storedServer = await storage.read(_kServerKeyStorageKey);

    final hashMatches = storedHash != null &&
        const ListEquality<int>().equals(storedHash, currentHash);

    if (hashMatches && storedClient != null && storedServer != null) {
      // Restore existing keys
      _clientKey = storedClient;
      _serverKey = storedServer;
    } else {
      // Hash mismatch or missing keys — delete old and regenerate
      await Future.wait([
        storage.delete(_kClientKeyStorageKey),
        storage.delete(_kServerKeyStorageKey),
        storage.delete(_kModelHashStorageKey),
      ]);

      final keyResult = _native.keygen(_topology!.pack());
      _clientKey = keyResult.clientKey;
      _serverKey = keyResult.serverKey;

      await Future.wait([
        storage.write(_kClientKeyStorageKey, _clientKey!),
        storage.write(_kServerKeyStorageKey, _serverKey!),
        storage.write(_kModelHashStorageKey, currentHash),
      ]);
    }

    _isReady = true;
  }

  void reset() {
    _isReady = false;
    _quantParams = null;
    _topology = null;
    _encoding = null;
    _clientKey = null;
    _serverKey = null;
    _serverKeyB64Cache = null;
    _nativeInstance = null;
  }

  Uint8List quantizeAndEncrypt(Float32List features) {
    _requireReady();
    final quantized = _quantParams!.quantizeInputs(features);
    return _native.encrypt(
      _clientKey!, quantized,
      _encoding!.tfheInputBitWidth, _encoding!.inputIsSigned,
    );
  }

  Float64List decryptAndDequantize(Uint8List ciphertext) {
    _requireReady();
    final rawScores = _native.decrypt(
      _clientKey!, ciphertext,
      _encoding!.tfheOutputBitWidth, _encoding!.outputIsSigned,
    );
    return _quantParams!.dequantizeOutputs(rawScores);
  }

  void _requireReady() {
    if (!_isReady) {
      throw StateError('ConcreteClient: call setup() first');
    }
  }
}
```

**Note:** Add `collection` dependency: `flutter pub add collection`

- [ ] **Step 3: Run tests**

Run: `flutter test`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add lib/src/concrete_client.dart test/concrete_client_test.dart
git commit -m "feat: wire ConcreteClient with topology, encoding, and model hash"
```

---

### Task 8: Update README and clean up

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README known limitations**

Remove limitations #1 and #2 (mark as resolved). Update the Compatibility section to note support for encoding widths up to 64-bit.

- [ ] **Step 2: Run full test suite**

Run: `flutter test`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README — dynamic topology and multi-width now supported"
```
