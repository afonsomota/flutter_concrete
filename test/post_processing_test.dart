import 'dart:math' as math;
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/src/post_processing.dart';

void main() {
  group('softmax', () {
    test('produces valid probability distribution', () {
      final result = softmax(Float64List.fromList([1.0, 2.0, 3.0]));
      expect(result.length, 3);
      final sum = result.reduce((a, b) => a + b);
      expect(sum, closeTo(1.0, 1e-10));
      expect(result[2], greaterThan(result[1]));
      expect(result[1], greaterThan(result[0]));
    });

    test('is numerically stable with large values', () {
      final result = softmax(Float64List.fromList([1000.0, 1001.0, 1002.0]));
      final sum = result.reduce((a, b) => a + b);
      expect(sum, closeTo(1.0, 1e-10));
      expect(result.every((v) => v.isFinite), isTrue);
    });

    test('handles single element', () {
      final result = softmax(Float64List.fromList([5.0]));
      expect(result[0], closeTo(1.0, 1e-10));
    });

    test('matches known values', () {
      // softmax([0, 0, 0]) = [1/3, 1/3, 1/3]
      final result = softmax(Float64List.fromList([0.0, 0.0, 0.0]));
      for (final v in result) {
        expect(v, closeTo(1.0 / 3.0, 1e-10));
      }
    });
  });

  group('sigmoid', () {
    test('sigmoid(0) = 0.5', () {
      final result = sigmoid(Float64List.fromList([0.0]));
      expect(result[0], closeTo(0.5, 1e-10));
    });

    test('large positive → 1.0', () {
      final result = sigmoid(Float64List.fromList([100.0]));
      expect(result[0], closeTo(1.0, 1e-10));
    });

    test('large negative → 0.0', () {
      final result = sigmoid(Float64List.fromList([-100.0]));
      expect(result[0], closeTo(0.0, 1e-10));
    });

    test('matches known value', () {
      // sigmoid(1) = 1 / (1 + e^-1) ≈ 0.7310585786
      final result = sigmoid(Float64List.fromList([1.0]));
      expect(result[0], closeTo(1.0 / (1.0 + math.exp(-1.0)), 1e-10));
    });
  });

  group('_sumLastAxis via ensembleRegressor', () {
    const pp = PostProcessing.ensembleRegressor();

    test('sums last axis of 3D shape', () {
      // Shape [1, 2, 3]: 2 classes, 3 trees
      // Data: [1,2,3, 4,5,6] → sum → [6, 15]
      final result = pp.apply(
        Float64List.fromList([1, 2, 3, 4, 5, 6]),
        [1, 2, 3],
      );
      expect(result.length, 2);
      expect(result[0], 6.0);
      expect(result[1], 15.0);
    });

    test('returns unchanged for 1D shape', () {
      final result = pp.apply(
        Float64List.fromList([1.0, 2.0]),
        [2],
      );
      expect(result.length, 2);
      expect(result[0], 1.0);
    });

    test('returns unchanged when last dim is 1', () {
      final result = pp.apply(
        Float64List.fromList([5.0, 10.0]),
        [1, 2, 1],
      );
      expect(result.length, 2);
      expect(result[0], 5.0);
    });
  });

  group('PostProcessing.ensembleClassifier', () {
    const pp = PostProcessing.ensembleClassifier();

    test('sums then applies softmax for multiclass', () {
      // Shape [1, 3, 2]: 3 classes, 2 trees
      // Data: [1,2, 3,4, 5,6] → sum → [3, 7, 11] → softmax
      final result = pp.apply(
        Float64List.fromList([1, 2, 3, 4, 5, 6]),
        [1, 3, 2],
      );
      expect(result.length, 3);
      final sum = result.reduce((a, b) => a + b);
      expect(sum, closeTo(1.0, 1e-10));
      expect(result[2], greaterThan(result[1]));
    });

    test('sums then applies sigmoid for binary (single logit)', () {
      // Shape [1, 1, 3]: 1 class, 3 trees → sum → [6] → sigmoid → [1-p, p]
      final result = pp.apply(
        Float64List.fromList([1, 2, 3]),
        [1, 1, 3],
      );
      expect(result.length, 2);
      expect(result[0] + result[1], closeTo(1.0, 1e-10));
    });
  });

  group('PostProcessing.ensembleProbabilistic', () {
    const pp = PostProcessing.ensembleProbabilistic();

    test('sums only, no activation', () {
      // Shape [1, 2, 3]: 2 classes, 3 trees
      final result = pp.apply(
        Float64List.fromList([0.1, 0.2, 0.3, 0.4, 0.5, 0.6]),
        [1, 2, 3],
      );
      expect(result.length, 2);
      expect(result[0], closeTo(0.6, 1e-10));
      expect(result[1], closeTo(1.5, 1e-10));
    });
  });

  group('PostProcessing.xgbRegressor', () {
    const pp = PostProcessing.xgbRegressor();

    test('sums and adds 0.5 bias', () {
      // Shape [1, 1, 3]: regression, 3 trees
      final result = pp.apply(
        Float64List.fromList([1.0, 2.0, 3.0]),
        [1, 1, 3],
      );
      expect(result.length, 1);
      expect(result[0], closeTo(6.5, 1e-10));
    });
  });

  group('PostProcessing.classifier', () {
    const pp = PostProcessing.classifier();

    test('applies softmax for multiclass', () {
      final result = pp.apply(
        Float64List.fromList([1.0, 2.0, 3.0]),
        [1, 3],
      );
      expect(result.length, 3);
      final sum = result.reduce((a, b) => a + b);
      expect(sum, closeTo(1.0, 1e-10));
    });

    test('applies sigmoid expansion for single logit', () {
      final result = pp.apply(
        Float64List.fromList([0.0]),
        [1, 1],
      );
      expect(result.length, 2);
      expect(result[0], closeTo(0.5, 1e-10));
      expect(result[1], closeTo(0.5, 1e-10));
    });
  });

  group('PostProcessing.regressor', () {
    const pp = PostProcessing.regressor();

    test('returns values unchanged', () {
      final input = Float64List.fromList([1.5, -2.3, 0.0]);
      final result = pp.apply(input, [1, 3]);
      expect(result, input);
    });
  });

  group('PostProcessing.none', () {
    const pp = PostProcessing.none();

    test('returns values unchanged', () {
      final input = Float64List.fromList([42.0]);
      final result = pp.apply(input, [1]);
      expect(result, input);
    });
  });

  group('PostProcessing.custom', () {
    test('calls user function with values and shape', () {
      final pp = PostProcessing.custom((values, shape) {
        return Float64List.fromList(
          values.map((v) => v * 2).toList(),
        );
      });
      final result = pp.apply(Float64List.fromList([1, 2, 3]), [3]);
      expect(result[0], 2.0);
      expect(result[1], 4.0);
      expect(result[2], 6.0);
    });
  });

  group('PostProcessing.auto', () {
    test('throws if apply is called directly', () {
      const pp = PostProcessing.auto();
      expect(
        () => pp.apply(Float64List(0), []),
        throwsStateError,
      );
    });
  });

  group('resolveAuto', () {
    // Ensemble classifiers (sum + softmax/sigmoid)
    test('resolves XGBClassifier to ensembleClassifier', () {
      expect(resolveAuto('XGBClassifier'),
          isA<EnsembleClassifierPostProcessing>());
    });

    // Ensemble probabilistic (sum only)
    test('resolves RandomForestClassifier to ensembleProbabilistic', () {
      expect(resolveAuto('RandomForestClassifier'),
          isA<EnsembleProbabilisticPostProcessing>());
    });

    test('resolves DecisionTreeClassifier to ensembleProbabilistic', () {
      expect(resolveAuto('DecisionTreeClassifier'),
          isA<EnsembleProbabilisticPostProcessing>());
    });

    // XGB regressor (sum + 0.5 bias)
    test('resolves XGBRegressor to xgbRegressor', () {
      expect(resolveAuto('XGBRegressor'), isA<XgbRegressorPostProcessing>());
    });

    // Ensemble regressors (sum only)
    test('resolves RandomForestRegressor to ensembleRegressor', () {
      expect(resolveAuto('RandomForestRegressor'),
          isA<EnsembleRegressorPostProcessing>());
    });

    test('resolves DecisionTreeRegressor to ensembleRegressor', () {
      expect(resolveAuto('DecisionTreeRegressor'),
          isA<EnsembleRegressorPostProcessing>());
    });

    // Linear classifiers (sigmoid/softmax)
    test('resolves LogisticRegression to classifier', () {
      expect(
          resolveAuto('LogisticRegression'), isA<ClassifierPostProcessing>());
    });

    test('resolves SGDClassifier to classifier', () {
      expect(resolveAuto('SGDClassifier'), isA<ClassifierPostProcessing>());
    });

    test('resolves LinearSVC to classifier', () {
      expect(resolveAuto('LinearSVC'), isA<ClassifierPostProcessing>());
    });

    // Neural net classifiers
    test('resolves NeuralNetClassifier to classifier', () {
      expect(
          resolveAuto('NeuralNetClassifier'), isA<ClassifierPostProcessing>());
    });

    // Regressors (identity)
    test('resolves LinearRegression to regressor', () {
      expect(resolveAuto('LinearRegression'), isA<RegressorPostProcessing>());
    });

    test('resolves SGDRegressor to regressor', () {
      expect(resolveAuto('SGDRegressor'), isA<RegressorPostProcessing>());
    });

    test('resolves LinearSVR to regressor', () {
      expect(resolveAuto('LinearSVR'), isA<RegressorPostProcessing>());
    });

    test('resolves ElasticNet to regressor', () {
      expect(resolveAuto('ElasticNet'), isA<RegressorPostProcessing>());
    });

    test('resolves Lasso to regressor', () {
      expect(resolveAuto('Lasso'), isA<RegressorPostProcessing>());
    });

    test('resolves Ridge to regressor', () {
      expect(resolveAuto('Ridge'), isA<RegressorPostProcessing>());
    });

    test('resolves NeuralNetRegressor to regressor', () {
      expect(resolveAuto('NeuralNetRegressor'), isA<RegressorPostProcessing>());
    });

    // Fallbacks
    test('resolves unknown model to none', () {
      expect(resolveAuto('SomeUnknownModel'), isA<NonePostProcessing>());
    });

    test('resolves null to none', () {
      expect(resolveAuto(null), isA<NonePostProcessing>());
    });
  });

  group('ensemble variants with 1D shape (fhe_ensembling=True)', () {
    test('ensembleClassifier with 1D shape skips sum, applies activation', () {
      // When fhe_ensembling=True, server already summed → 1D output.
      // _sumLastAxis is a no-op for 1D, then softmax applied.
      final result = const PostProcessing.ensembleClassifier().apply(
        Float64List.fromList([1.0, 2.0, 3.0]),
        [3], // 1D shape — nothing to sum
      );
      expect(result.length, 3);
      final sum = result.reduce((a, b) => a + b);
      expect(sum, closeTo(1.0, 1e-10));
    });

    test('ensembleRegressor with 1D shape returns unchanged', () {
      final input = Float64List.fromList([5.0]);
      final result = const PostProcessing.ensembleRegressor().apply(
        input,
        [1], // 1D shape — nothing to sum
      );
      expect(result[0], 5.0);
    });

    test('ensembleClassifier with last dim 1 skips sum', () {
      // Shape [1, 3, 1] — last dim is 1, sum is no-op.
      final result = const PostProcessing.ensembleClassifier().apply(
        Float64List.fromList([1.0, 2.0, 3.0]),
        [1, 3, 1],
      );
      expect(result.length, 3);
      final sum = result.reduce((a, b) => a + b);
      expect(sum, closeTo(1.0, 1e-10));
    });
  });
}
