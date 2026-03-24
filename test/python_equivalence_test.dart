@Tags(['equivalence'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/client_zip_parser.dart';
import 'package:flutter_concrete/src/post_processing.dart';

String sha256Hex(Uint8List bytes) {
  return sha256.convert(bytes).toString();
}

class ModelFixture {
  final String name;
  final Uint8List clientZipBytes;
  final Map<String, dynamic> reference;
  final ParseResult parseResult;

  ModelFixture._({
    required this.name,
    required this.clientZipBytes,
    required this.reference,
    required this.parseResult,
  });

  static ModelFixture load(String dirName) {
    final dir = Directory('test/fixtures/$dirName');
    final zipBytes = File('${dir.path}/client.zip').readAsBytesSync();
    final refJson = jsonDecode(
      File('${dir.path}/reference.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    final parseResult = ClientZipParser.parse(Uint8List.fromList(zipBytes));
    return ModelFixture._(
      name: dirName,
      clientZipBytes: Uint8List.fromList(zipBytes),
      reference: refJson,
      parseResult: parseResult,
    );
  }

  String get expectedModelClass => reference['model_class'] as String;
  List<int> get expectedOutputShape =>
      (reference['output_shape'] as List<dynamic>)
          .map((v) => (v as num).toInt())
          .toList();
  List<dynamic> get testVectors => reference['test_vectors'] as List<dynamic>;
}

void testModelEquivalence(String dirName) {
  group(dirName, () {
    late ModelFixture fixture;

    setUpAll(() {
      fixture = ModelFixture.load(dirName);
    });

    test('client.zip SHA-256 matches reference', () {
      final actual = sha256Hex(fixture.clientZipBytes);
      final expected = fixture.reference['client_zip_sha256'] as String;
      expect(actual, expected,
          reason: 'Fixture stale: client.zip SHA-256 mismatch. '
              'Regenerate with: cd test/fixtures && python generate_models.py');
    });

    test('parses modelClassName correctly', () {
      expect(fixture.parseResult.modelClassName, fixture.expectedModelClass);
    });

    test('parses outputShape correctly', () {
      expect(fixture.parseResult.outputShape, fixture.expectedOutputShape);
    });

    test('resolveAuto returns correct variant', () {
      final resolved = resolveAuto(fixture.parseResult.modelClassName);
      expect(resolved, isNot(isA<AutoPostProcessing>()));
      expect(resolved, isNot(isA<NonePostProcessing>()),
          reason:
              '${fixture.expectedModelClass} should resolve to a known variant');
    });

    test('quantizeInputs matches Python', () {
      for (final vec in fixture.testVectors) {
        final inputFloat = Float32List.fromList(
          (vec['input_float'] as List<dynamic>)
              .map((v) => (v as num).toDouble())
              .toList(),
        );
        final expected = (vec['quantized_input'] as List<dynamic>)
            .map((v) => (v as num).toInt())
            .toList();

        final result =
            fixture.parseResult.quantParams.quantizeInputs(inputFloat);

        for (int i = 0; i < expected.length; i++) {
          expect(result[i], expected[i],
              reason: 'quantizeInputs mismatch at index $i '
                  'for "${vec['description']}"');
        }
      }
    });

    test('dequantizeOutputs matches Python', () {
      for (final vec in fixture.testVectors) {
        final rawInts = Int64List.fromList(
          (vec['raw_output_ints'] as List<dynamic>)
              .map((v) => (v as num).toInt())
              .toList(),
        );
        final expected = (vec['dequantized_output'] as List<dynamic>)
            .map((v) => (v as num).toDouble())
            .toList();

        final result =
            fixture.parseResult.quantParams.dequantizeOutputs(rawInts);

        for (int i = 0; i < expected.length; i++) {
          expect(result[i], closeTo(expected[i], 1e-10),
              reason: 'dequantizeOutputs mismatch at index $i '
                  'for "${vec['description']}"');
        }
      }
    });

    test('post-processing matches Python', () {
      final pp = resolveAuto(fixture.parseResult.modelClassName);
      final outputShape = fixture.expectedOutputShape;

      for (final vec in fixture.testVectors) {
        final dequantized = Float64List.fromList(
          (vec['dequantized_output'] as List<dynamic>)
              .map((v) => (v as num).toDouble())
              .toList(),
        );
        final expected = (vec['post_processed'] as List<dynamic>)
            .map((v) => (v as num).toDouble())
            .toList();

        final result = pp.apply(dequantized, outputShape);

        expect(result.length, expected.length,
            reason: 'post-processing length mismatch '
                'for "${vec['description']}"');
        for (int i = 0; i < expected.length; i++) {
          expect(result[i], closeTo(expected[i], 1e-6),
              reason: 'post-processing mismatch at index $i '
                  'for "${vec['description']}"');
        }
      }
    });
  });
}

void main() {
  testModelEquivalence('xgb_classifier_multiclass');
  testModelEquivalence('xgb_classifier_binary');
  testModelEquivalence('random_forest_classifier');
  testModelEquivalence('decision_tree_classifier');
  testModelEquivalence('xgb_regressor');
  testModelEquivalence('random_forest_regressor');
  testModelEquivalence('logistic_regression');
  testModelEquivalence('linear_regression');
}
