import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/client_zip_parser.dart';

void main() {
  late Uint8List zipBytes;

  setUpAll(() {
    // Use the real client.zip from the journal_app assets for testing.
    final file = File('${Directory.current.parent.path}/journal_app/assets/fhe/client.zip');
    if (!file.existsSync()) {
      final alt = File('../journal_app/assets/fhe/client.zip');
      if (!alt.existsSync()) {
        fail('client.zip not found — run from flutter_concrete/ or project root');
      }
      zipBytes = alt.readAsBytesSync();
    } else {
      zipBytes = file.readAsBytesSync();
    }
  });

  group('ClientZipParser', () {
    test('parses input quantizers from client.zip', () {
      final params = ClientZipParser.parse(zipBytes);
      expect(params.input.length, 200);
      for (final p in params.input) {
        expect(p.scale, isPositive);
        expect(p.zeroPoint, isA<int>());
      }
    });

    test('parses output quantizer from client.zip', () {
      final params = ClientZipParser.parse(zipBytes);
      expect(params.output.scale, isPositive);
      expect(params.output.offset, isA<int>());
    });

    test('validates n_bits is 8', () {
      final badProc = {
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
      final badZip = _createZipWithProcessing(badProc);
      expect(
        () => ClientZipParser.parse(badZip),
        throwsA(isA<FormatException>().having(
          (e) => e.message, 'message', contains('n_bits'),
        )),
      );
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
      final zip = _createZipWithProcessing(proc);
      final params = ClientZipParser.parse(zip);
      expect(params.input[0].zeroPoint, 42);
      expect(params.output.zeroPoint, 7);
    });
  });
}

Uint8List _createZipWithProcessing(Map<String, dynamic> processing) {
  final archive = Archive();
  final jsonBytes = utf8.encode(jsonEncode(processing));
  archive.addFile(ArchiveFile('serialized_processing.json', jsonBytes.length, jsonBytes));
  return Uint8List.fromList(ZipEncoder().encode(archive));
}
