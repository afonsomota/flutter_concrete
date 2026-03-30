/// Cross-client FHE equivalence tests using a long-lived Python server.
///
/// Eliminates MLIR non-determinism by keeping a single FHEModelServer per
/// model (one JIT compilation). Both Dart and Python clients use the same
/// server instance with fresh keys generated at test time.
///
/// Two tests per model:
///
/// **Test 1: "Dart encrypt → server → compare"**
///   Dart encrypts quantized input, sends to Python server for inference.
///   Both Dart and Python decrypt the same encrypted result. Scores should
///   match within tolerance (same ciphertext, same keys, same compilation).
///
/// **Test 2: "Python encrypt → server → Dart decrypt"**
///   Python encrypts, runs inference, and decrypts. Dart also decrypts the
///   same result. Eliminates encryption-side differences.
///
/// Requires:
///   1. libfhe_client built: `cd rust && cargo build`
///   2. Python 3 with concrete-ml == 1.9.0 on PATH
///   3. Fixture models generated: `python3 test/fixtures/generate_models.py`
///      (only needs client.zip + server.zip + reference.json per model)
///
/// Run with:
///   # macOS
///   DYLD_LIBRARY_PATH=rust/target/debug flutter test test/cross_client_test.dart -t cross_client
///   # Linux
///   LD_LIBRARY_PATH=rust/target/debug flutter test test/cross_client_test.dart -t cross_client
@Tags(['integration', 'cross_client'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/client_zip_parser.dart';
import 'package:flutter_concrete/src/concrete_cipher_info.dart';
import 'package:flutter_concrete/src/fhe_native.dart';
import 'package:flutter_concrete/src/post_processing.dart';

// ---------------------------------------------------------------------------
// Python server process helper
// ---------------------------------------------------------------------------

class LoadResult {
  final Uint8List secretKey;
  final Uint8List evalKey;
  const LoadResult({required this.secretKey, required this.evalKey});
}

class RunResult {
  final String encryptedResultB64;
  final List<double> pythonScores;
  const RunResult(
      {required this.encryptedResultB64, required this.pythonScores});
}

class FheServerProcess {
  Process? _process;
  late StreamIterator<String> _lines;

  Future<void> start() async {
    _process = await Process.start('python3', ['test/fixtures/fhe_server.py']);
    // Stream stderr to test output for debugging
    _process!.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        // ignore: avoid_print
        .listen((line) => print('[python] $line'));
    _lines = StreamIterator(
      _process!.stdout.transform(utf8.decoder).transform(const LineSplitter()),
    );
  }

  Future<Map<String, dynamic>> _send(Map<String, dynamic> command) async {
    _process!.stdin.writeln(jsonEncode(command));
    await _process!.stdin.flush();

    if (!await _lines.moveNext()) {
      throw StateError('Python server closed stdout unexpectedly');
    }

    final response = jsonDecode(_lines.current) as Map<String, dynamic>;
    if (response['status'] == 'error') {
      throw StateError('Python server error: ${response['error']}');
    }
    return response;
  }

  Future<LoadResult> load(String modelDir) async {
    final response = await _send({
      'command': 'load',
      'model_dir': modelDir,
    });
    return LoadResult(
      secretKey: base64Decode(response['secret_key_b64'] as String),
      evalKey: base64Decode(response['eval_key_b64'] as String),
    );
  }

  Future<RunResult> run(String modelDir, String encryptedInputB64) async {
    final response = await _send({
      'command': 'run',
      'model_dir': modelDir,
      'encrypted_input_b64': encryptedInputB64,
    });
    return RunResult(
      encryptedResultB64: response['encrypted_result_b64'] as String,
      pythonScores: (response['python_scores'] as List<dynamic>)
          .map((v) => (v as num).toDouble())
          .toList(),
    );
  }

  Future<RunResult> encryptAndRun(
      String modelDir, List<int> quantizedInput) async {
    final response = await _send({
      'command': 'encrypt_and_run',
      'model_dir': modelDir,
      'quantized_input': quantizedInput,
    });
    return RunResult(
      encryptedResultB64: response['encrypted_result_b64'] as String,
      pythonScores: (response['python_scores'] as List<dynamic>)
          .map((v) => (v as num).toDouble())
          .toList(),
    );
  }

  Future<void> shutdown() async {
    try {
      await _send({'command': 'shutdown'});
    } catch (_) {
      // Process may have already exited
    }
    _process?.kill();
    await _process?.exitCode.timeout(
      const Duration(seconds: 5),
      onTimeout: () {
        _process?.kill(ProcessSignal.sigkill);
        return -1;
      },
    );
    _process = null;
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

late FheServerProcess server;

void testCrossClient(String dirName) {
  group('$dirName cross-client', () {
    late Uint8List secretKey;
    late ParseResult parseResult;
    late FheNative native;
    late String modelDir;
    late Map<String, dynamic> reference;
    bool modelLoaded = false;

    setUpAll(() async {
      final dir = Directory('test/fixtures/$dirName');
      if (!dir.existsSync()) return;

      final serverZipFile = File('${dir.path}/server.zip');
      if (!serverZipFile.existsSync()) return;

      final clientZipBytes = File('${dir.path}/client.zip').readAsBytesSync();
      parseResult = ClientZipParser.parse(Uint8List.fromList(clientZipBytes));

      if (parseResult.inputCipherInfo == null ||
          parseResult.outputCipherInfo == null) {
        return;
      }

      reference = jsonDecode(
        File('${dir.path}/reference.json').readAsStringSync(),
      ) as Map<String, dynamic>;

      native = FheNative();
      modelDir = dir.absolute.path;

      // Load model in Python server — generates fresh keys, single MLIR
      // compilation for this model.
      final loadResult = await server.load(modelDir);
      secretKey = loadResult.secretKey;
      modelLoaded = true;
    });

    test('Dart encrypt → server → Dart decrypt matches Python', () async {
      if (!modelLoaded) {
        markTestSkipped(
            '$dirName: model not loaded (missing fixtures or cipher info)');
        return;
      }
      final inputInfo = parseResult.inputCipherInfo!;
      final outputInfo = parseResult.outputCipherInfo!;
      final testVectors = reference['test_vectors'] as List<dynamic>;
      final outputShape = (reference['output_shape'] as List<dynamic>)
          .map((v) => (v as num).toInt())
          .toList();
      final pp = resolveAuto(parseResult.modelClassName);

      for (final vec in testVectors) {
        final description = vec['description'] as String;

        // Use same quantized input as Python reference
        final quantized = Int64List.fromList(
          (vec['quantized_input'] as List<dynamic>)
              .map((v) => (v as num).toInt())
              .toList(),
        );

        // Dart encrypts
        final ctRaw = native.lweEncryptSeeded(
          secretKey,
          quantized,
          inputInfo.encodingWidth,
          inputInfo.lweDimension,
          inputInfo.variance,
        );
        final encrypted = native.serializeValue(
          ctRaw,
          inputInfo.concreteShape,
          inputInfo.abstractShape,
          inputInfo.encodingWidth,
          inputInfo.encodingIsSigned,
          inputInfo.lweDimension,
          inputInfo.keyId,
          inputInfo.variance,
          inputInfo.compression == ConcreteCipherCompression.seed ? 1 : 0,
        );

        // Server runs inference (same MLIR compilation as keygen)
        final result = await server.run(modelDir, base64Encode(encrypted));

        // Dart decrypts
        final (ctData, nCts) = native.deserializeValue(
          base64Decode(result.encryptedResultB64),
        );
        final rawScores = native.lweDecryptFull(
          secretKey,
          ctData,
          nCts,
          outputInfo.encodingWidth,
          outputInfo.encodingIsSigned,
          outputInfo.lweDimension,
        );

        final dequantized =
            parseResult.quantParams.dequantizeOutputs(rawScores);
        final dartScores = pp.apply(dequantized, outputShape);

        // ignore: avoid_print
        print(
            '  [$description] dart=$dartScores python=${result.pythonScores}');

        expect(dartScores.length, result.pythonScores.length,
            reason: 'Score length mismatch for "$description"');

        for (int i = 0; i < dartScores.length; i++) {
          expect(dartScores[i], closeTo(result.pythonScores[i], 1e-4),
              reason: 'Score[$i] mismatch for "$description": '
                  'dart=${dartScores[i]}, python=${result.pythonScores[i]}');
        }
      }
    }, timeout: const Timeout(Duration(minutes: 10)));

    test('Python encrypt → server → Dart decrypt matches Python', () async {
      if (!modelLoaded) {
        markTestSkipped(
            '$dirName: model not loaded (missing fixtures or cipher info)');
        return;
      }
      final outputInfo = parseResult.outputCipherInfo!;
      final testVectors = reference['test_vectors'] as List<dynamic>;
      final outputShape = (reference['output_shape'] as List<dynamic>)
          .map((v) => (v as num).toInt())
          .toList();
      final pp = resolveAuto(parseResult.modelClassName);

      for (final vec in testVectors) {
        final description = vec['description'] as String;

        final quantized = (vec['quantized_input'] as List<dynamic>)
            .map((v) => (v as num).toInt())
            .toList();

        // Python encrypts, runs, and decrypts
        final result = await server.encryptAndRun(modelDir, quantized);

        // Dart decrypts the same encrypted result
        final (ctData, nCts) = native.deserializeValue(
          base64Decode(result.encryptedResultB64),
        );
        final rawScores = native.lweDecryptFull(
          secretKey,
          ctData,
          nCts,
          outputInfo.encodingWidth,
          outputInfo.encodingIsSigned,
          outputInfo.lweDimension,
        );

        final dequantized =
            parseResult.quantParams.dequantizeOutputs(rawScores);
        final dartScores = pp.apply(dequantized, outputShape);

        // ignore: avoid_print
        print(
            '  [$description] dart=$dartScores python=${result.pythonScores}');

        expect(dartScores.length, result.pythonScores.length,
            reason: 'Score length mismatch for "$description"');

        for (int i = 0; i < dartScores.length; i++) {
          expect(dartScores[i], closeTo(result.pythonScores[i], 1e-4),
              reason: 'Score[$i] mismatch for "$description": '
                  'dart=${dartScores[i]}, python=${result.pythonScores[i]}');
        }
      }
    }, timeout: const Timeout(Duration(minutes: 10)));
  });
}

void main() {
  // Check Python + concrete-ml is available
  setUpAll(() async {
    try {
      final result = Process.runSync('python3', ['-c', 'import concrete.ml']);
      if (result.exitCode != 0) {
        fail('concrete-ml not available. '
            'Install with: pip install -r test/fixtures/requirements.txt\n'
            'stderr: ${result.stderr}');
      }
    } on ProcessException {
      fail('python3 not found on PATH');
    }

    server = FheServerProcess();
    await server.start();
  });

  tearDownAll(() async {
    await server.shutdown();
  });

  testCrossClient('xgb_classifier_multiclass');
  testCrossClient('xgb_classifier_binary');
  testCrossClient('random_forest_classifier');
  testCrossClient('decision_tree_classifier');
  testCrossClient('xgb_regressor');
  testCrossClient('random_forest_regressor');
  testCrossClient('logistic_regression');
  testCrossClient('linear_regression');
}
