import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/client_zip_parser.dart';

void main() {
  late Uint8List zipBytes;

  setUpAll(() {
    // Try absolute path first, then relative paths.
    final candidates = [
      '/Users/afonso/Documents/projects/e2ee_journal/journal_app/assets/fhe/client.zip',
      '${Directory.current.parent.path}/journal_app/assets/fhe/client.zip',
      '../journal_app/assets/fhe/client.zip',
    ];
    for (final path in candidates) {
      final file = File(path);
      if (file.existsSync()) {
        zipBytes = file.readAsBytesSync();
        return;
      }
    }
    fail('client.zip not found — tried: ${candidates.join(', ')}');
  });

  group('ClientZipParser', () {
    test('parses input quantizers from client.zip', () {
      final result = ClientZipParser.parse(zipBytes);
      expect(result.quantParams.input.length, 200);
      for (final p in result.quantParams.input) {
        expect(p.scale, isPositive);
        expect(p.zeroPoint, isA<int>());
      }
    });

    test('parses output quantizer from client.zip', () {
      final result = ClientZipParser.parse(zipBytes);
      expect(result.quantParams.output.scale, isPositive);
      expect(result.quantParams.output.offset, isA<int>());
    });

    test('parses nClasses from client.specs.json', () {
      final result = ClientZipParser.parse(zipBytes);
      expect(result.quantParams.nClasses, 5);
    });

    test('accepts non-8-bit quantization', () {
      final proc = {
        'input_quantizers': [
          {
            'type_name': 'UniformQuantizer',
            'serialized_value': {
              'n_bits': 16,
              'is_signed': false,
              'scale': {'type_name': 'numpy_float', 'serialized_value': 0.01},
              'zero_point': 0,
              'offset': 0,
            }
          }
        ],
        'output_quantizers': [
          {
            'type_name': 'UniformQuantizer',
            'serialized_value': {
              'n_bits': 8,
              'is_signed': true,
              'scale': {'type_name': 'numpy_float', 'serialized_value': 0.01},
              'zero_point': 0,
              'offset': 128,
            }
          }
        ],
      };
      final zip = _createZipWithProcessingAndSpecs(proc, _minimalSpecs());
      // Should not throw
      final result = ClientZipParser.parse(zip);
      expect(result.quantParams.input.length, 1);
    });

    test('handles zero_point as raw int and as dict', () {
      final proc = {
        'input_quantizers': [
          {
            'type_name': 'UniformQuantizer',
            'serialized_value': {
              'n_bits': 8,
              'is_signed': false,
              'scale': {'type_name': 'numpy_float', 'serialized_value': 0.01},
              'zero_point': {'type_name': 'numpy_integer', 'serialized_value': 42},
              'offset': 0,
            }
          }
        ],
        'output_quantizers': [
          {
            'type_name': 'UniformQuantizer',
            'serialized_value': {
              'n_bits': 8,
              'is_signed': true,
              'scale': {'type_name': 'numpy_float', 'serialized_value': 0.05},
              'zero_point': 7,
              'offset': 128,
            }
          }
        ],
      };
      final zip = _createZipWithProcessingAndSpecs(proc, _minimalSpecs());
      final result = ClientZipParser.parse(zip);
      expect(result.quantParams.input[0].zeroPoint, 42);
      expect(result.quantParams.output.zeroPoint, 7);
    });

    test('extracts KeyTopology from client.specs.json', () {
      final result = ClientZipParser.parse(zipBytes);
      final topo = result.topology;
      expect(topo.secretKeys, isNotEmpty);
      expect(topo.bootstrapKeys, isNotEmpty);
      expect(topo.keyswitchKeys, isNotEmpty);
      // Verify SK dimensions are positive
      for (final sk in topo.secretKeys) {
        expect(sk.lweDimension, isPositive);
      }
      // Verify BSK fields
      for (final bsk in topo.bootstrapKeys) {
        expect(bsk.levelCount, isPositive);
        expect(bsk.baseLog, isPositive);
        expect(bsk.glweDimension, isPositive);
        expect(bsk.polynomialSize, isPositive);
        expect(bsk.inputLweDimension, isPositive);
      }
      // Verify KSK fields
      for (final ksk in topo.keyswitchKeys) {
        expect(ksk.levelCount, isPositive);
        expect(ksk.baseLog, isPositive);
        expect(ksk.inputLweDimension, isPositive);
        expect(ksk.outputLweDimension, isPositive);
      }
    });

    test('extracts CircuitEncoding from client.specs.json', () {
      final result = ClientZipParser.parse(zipBytes);
      final enc = result.encoding;
      expect(enc.inputWidth, isPositive);
      expect(enc.outputWidth, isPositive);
      expect(enc.inputIsSigned, isA<bool>());
      expect(enc.outputIsSigned, isA<bool>());
    });

    test('throws if client.specs.json is missing', () {
      final proc = {
        'input_quantizers': [],
        'output_quantizers': [
          {
            'type_name': 'UniformQuantizer',
            'serialized_value': {
              'n_bits': 8,
              'is_signed': true,
              'scale': 0.01,
              'zero_point': 0,
            }
          }
        ],
      };
      final zip = _createZipWithProcessing(proc);
      expect(
        () => ClientZipParser.parse(zip),
        throwsA(isA<FormatException>().having(
          (e) => e.message,
          'message',
          contains('client.specs.json'),
        )),
      );
    });
  });
}

/// Creates a zip with only `serialized_processing.json` (no specs file).
Uint8List _createZipWithProcessing(Map<String, dynamic> processing) {
  final archive = Archive();
  final jsonBytes = utf8.encode(jsonEncode(processing));
  archive.addFile(
      ArchiveFile('serialized_processing.json', jsonBytes.length, jsonBytes));
  return Uint8List.fromList(ZipEncoder().encode(archive)!);
}

/// Creates a zip with both `serialized_processing.json` and `client.specs.json`.
Uint8List _createZipWithProcessingAndSpecs(
    Map<String, dynamic> processing, Map<String, dynamic> specs) {
  final archive = Archive();
  final procBytes = utf8.encode(jsonEncode(processing));
  archive.addFile(
      ArchiveFile('serialized_processing.json', procBytes.length, procBytes));
  final specsBytes = utf8.encode(jsonEncode(specs));
  archive.addFile(
      ArchiveFile('client.specs.json', specsBytes.length, specsBytes));
  return Uint8List.fromList(ZipEncoder().encode(archive)!);
}

/// Minimal valid `client.specs.json` for unit tests.
Map<String, dynamic> _minimalSpecs() => {
      'keyset': {
        'lweSecretKeys': [
          {
            'id': 0,
            'params': {'lweDimension': 600},
          },
          {
            'id': 1,
            'params': {'lweDimension': 2048},
          },
        ],
        'lweBootstrapKeys': [
          {
            'id': 0,
            'inputId': 1,
            'outputId': 0,
            'params': {
              'levelCount': 1,
              'baseLog': 23,
              'glweDimension': 4,
              'polynomialSize': 512,
              'variance': 8.4e-31,
              'inputLweDimension': 599,
            },
          }
        ],
        'lweKeyswitchKeys': [
          {
            'id': 0,
            'inputId': 0,
            'outputId': 1,
            'params': {
              'levelCount': 3,
              'baseLog': 3,
              'variance': 2.2e-08,
              'inputLweDimension': 2048,
              'outputLweDimension': 599,
            },
          }
        ],
        'packingKeyswitchKeys': [],
      },
      'circuits': [
        {
          'inputs': [
            {
              'typeInfo': {
                'lweCiphertext': {
                  'encoding': {
                    'integer': {'width': 10, 'isSigned': false},
                  },
                },
              },
            }
          ],
          'outputs': [
            {
              'typeInfo': {
                'lweCiphertext': {
                  'encoding': {
                    'integer': {'width': 8, 'isSigned': true},
                  },
                },
              },
            }
          ],
        }
      ],
      'tfhers_specs': {},
    };
