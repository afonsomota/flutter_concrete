// lib/src/post_processing.dart
//
// Model-aware post-processing for Concrete ML FHE inference results.
// Matches Python FHEModelClient's deserialize_decrypt_dequantize pipeline.

import 'dart:developer' as developer;
import 'dart:math' as math;
import 'dart:typed_data';

/// Post-processing strategy for decrypted FHE results.
///
/// Controls how dequantized float values are transformed into final
/// predictions. Use [PostProcessing.auto] (default) to auto-detect from
/// the model class name in `client.zip`, or specify explicitly.
///
/// ## Auto-detection
///
/// When using [PostProcessing.auto], the model class name is read from
/// `serialized_processing.json` in `client.zip` and mapped to the
/// appropriate variant via a lookup table covering all standard Concrete ML
/// sklearn models. Unknown models fall back to [PostProcessing.none].
///
/// ## Variants
///
/// | Variant | Behavior | Models |
/// |---------|----------|--------|
/// | [ensembleClassifier] | Sum last axis → sigmoid/softmax | XGBClassifier |
/// | [ensembleProbabilistic] | Sum last axis only | RandomForestClassifier, DecisionTreeClassifier |
/// | [ensembleRegressor] | Sum last axis | RandomForestRegressor, DecisionTreeRegressor |
/// | [xgbRegressor] | Sum last axis + 0.5 bias | XGBRegressor |
/// | [classifier] | sigmoid/softmax | LogisticRegression, LinearSVC, NeuralNetClassifier |
/// | [regressor] | Identity | LinearRegression, Ridge, Lasso, etc. |
/// | [none] | No transform | Raw dequantized values |
/// | [custom] | User-provided function | Any custom pipeline |
///
/// ## Unsupported by auto-detection
///
/// These models require explicit [PostProcessing.custom]:
/// - `KNeighborsClassifier` — majority vote paradigm
/// - `PoissonRegressor`, `GammaRegressor`, `TweedieRegressor` — need exp()
/// - `SGDClassifier` with `modified_huber` loss
sealed class PostProcessing {
  const PostProcessing();

  /// Auto-detect from model class name in `client.zip` (default).
  const factory PostProcessing.auto() = AutoPostProcessing;

  /// Ensemble classifier: sum last axis → sigmoid (2 classes) / softmax (>2).
  ///
  /// For: XGBClassifier.
  const factory PostProcessing.ensembleClassifier() =
      EnsembleClassifierPostProcessing;

  /// Ensemble probabilistic: sum last axis only. No activation function.
  ///
  /// For models whose FHE circuit already outputs probabilities:
  /// RandomForestClassifier, DecisionTreeClassifier.
  const factory PostProcessing.ensembleProbabilistic() =
      EnsembleProbabilisticPostProcessing;

  /// Ensemble regressor: sum last axis, identity.
  ///
  /// For: RandomForestRegressor, DecisionTreeRegressor.
  const factory PostProcessing.ensembleRegressor() =
      EnsembleRegressorPostProcessing;

  /// XGBoost regressor: sum last axis + 0.5 bias correction.
  ///
  /// The +0.5 bias is a Hummingbird Gemm artifact in XGBRegressor.
  const factory PostProcessing.xgbRegressor() = XgbRegressorPostProcessing;

  /// Non-ensemble classifier: sigmoid (2 classes) / softmax (>2).
  ///
  /// For: LogisticRegression, LinearSVC, NeuralNetClassifier,
  /// SGDClassifier (with log_loss).
  const factory PostProcessing.classifier() = ClassifierPostProcessing;

  /// Regressor: identity (no transform).
  ///
  /// For: LinearRegression, Ridge, Lasso, ElasticNet, NeuralNetRegressor,
  /// SGDRegressor, LinearSVR.
  const factory PostProcessing.regressor() = RegressorPostProcessing;

  /// No post-processing. Returns raw dequantized values.
  const factory PostProcessing.none() = NonePostProcessing;

  /// Custom post-processing function.
  ///
  /// The function receives the dequantized values and the output abstract
  /// shape from `client.specs.json`.
  const factory PostProcessing.custom(
    Float64List Function(Float64List values, List<int> outputShape) fn,
  ) = CustomPostProcessing;

  /// Apply this post-processing to [dequantized] values with the given
  /// [outputShape] from the circuit.
  Float64List apply(Float64List dequantized, List<int> outputShape);
}

/// Auto-detect post-processing from model class name.
///
/// Resolved at setup time via [resolveAuto]; calling [apply] directly throws.
class AutoPostProcessing extends PostProcessing {
  const AutoPostProcessing();

  @override
  Float64List apply(Float64List dequantized, List<int> outputShape) {
    throw StateError(
      'PostProcessing.auto() must be resolved before apply(). '
      'This is a bug — ConcreteClient should resolve auto at setup time.',
    );
  }
}

class EnsembleClassifierPostProcessing extends PostProcessing {
  const EnsembleClassifierPostProcessing();

  @override
  Float64List apply(Float64List dequantized, List<int> outputShape) {
    final summed = _sumLastAxis(dequantized, outputShape);
    return _classifierActivation(summed);
  }
}

class EnsembleProbabilisticPostProcessing extends PostProcessing {
  const EnsembleProbabilisticPostProcessing();

  @override
  Float64List apply(Float64List dequantized, List<int> outputShape) {
    return _sumLastAxis(dequantized, outputShape);
  }
}

class EnsembleRegressorPostProcessing extends PostProcessing {
  const EnsembleRegressorPostProcessing();

  @override
  Float64List apply(Float64List dequantized, List<int> outputShape) {
    return _sumLastAxis(dequantized, outputShape);
  }
}

class XgbRegressorPostProcessing extends PostProcessing {
  const XgbRegressorPostProcessing();

  @override
  Float64List apply(Float64List dequantized, List<int> outputShape) {
    final summed = _sumLastAxis(dequantized, outputShape);
    for (int i = 0; i < summed.length; i++) {
      summed[i] += 0.5;
    }
    return summed;
  }
}

class ClassifierPostProcessing extends PostProcessing {
  const ClassifierPostProcessing();

  @override
  Float64List apply(Float64List dequantized, List<int> outputShape) {
    return _classifierActivation(dequantized);
  }
}

class RegressorPostProcessing extends PostProcessing {
  const RegressorPostProcessing();

  @override
  Float64List apply(Float64List dequantized, List<int> outputShape) {
    return dequantized;
  }
}

class NonePostProcessing extends PostProcessing {
  const NonePostProcessing();

  @override
  Float64List apply(Float64List dequantized, List<int> outputShape) {
    return dequantized;
  }
}

class CustomPostProcessing extends PostProcessing {
  final Float64List Function(Float64List values, List<int> outputShape) fn;
  const CustomPostProcessing(this.fn);

  @override
  Float64List apply(Float64List dequantized, List<int> outputShape) {
    return fn(dequantized, outputShape);
  }
}

// ---------------------------------------------------------------------------
// Auto-detection
// ---------------------------------------------------------------------------

/// Lookup table mapping Concrete ML model class names to post-processing.
const _modelClassLookup = <String, PostProcessing>{
  // Tree ensemble classifiers (sum + softmax/sigmoid)
  'XGBClassifier': PostProcessing.ensembleClassifier(),

  // Tree ensemble classifiers (sum only — outputs are probabilities)
  'RandomForestClassifier': PostProcessing.ensembleProbabilistic(),
  'DecisionTreeClassifier': PostProcessing.ensembleProbabilistic(),

  // Tree ensemble regressors
  'XGBRegressor': PostProcessing.xgbRegressor(),
  'RandomForestRegressor': PostProcessing.ensembleRegressor(),
  'DecisionTreeRegressor': PostProcessing.ensembleRegressor(),

  // Linear classifiers (sigmoid/softmax)
  'LogisticRegression': PostProcessing.classifier(),
  'SGDClassifier': PostProcessing.classifier(),
  'LinearSVC': PostProcessing.classifier(),

  // Neural net classifiers (sigmoid/softmax)
  'NeuralNetClassifier': PostProcessing.classifier(),

  // Regressors (identity)
  'LinearRegression': PostProcessing.regressor(),
  'SGDRegressor': PostProcessing.regressor(),
  'LinearSVR': PostProcessing.regressor(),
  'ElasticNet': PostProcessing.regressor(),
  'Lasso': PostProcessing.regressor(),
  'Ridge': PostProcessing.regressor(),
  'NeuralNetRegressor': PostProcessing.regressor(),
};

/// Resolve [PostProcessing.auto] to a concrete variant using the model
/// class name from `serialized_processing.json`.
///
/// Returns [PostProcessing.none] if [modelClassName] is null or not found
/// in the lookup table.
PostProcessing resolveAuto(String? modelClassName) {
  if (modelClassName == null) {
    developer.log(
      'model_type not found in client.zip — using PostProcessing.none(). '
      'Specify an explicit PostProcessing variant for correct results.',
      name: 'flutter_concrete',
    );
    return const PostProcessing.none();
  }
  final resolved = _modelClassLookup[modelClassName];
  if (resolved == null) {
    developer.log(
      'Unknown model class "$modelClassName" — using PostProcessing.none(). '
      'Specify an explicit PostProcessing variant for correct results.',
      name: 'flutter_concrete',
    );
    return const PostProcessing.none();
  }
  return resolved;
}

// ---------------------------------------------------------------------------
// Math utilities
// ---------------------------------------------------------------------------

/// Numerically stable softmax: exp(x_i - max(x)) / sum(exp(x_i - max(x))).
Float64List softmax(Float64List x) {
  final result = Float64List(x.length);
  double maxVal = x[0];
  for (int i = 1; i < x.length; i++) {
    if (x[i] > maxVal) maxVal = x[i];
  }
  double sumExp = 0.0;
  for (int i = 0; i < x.length; i++) {
    result[i] = math.exp(x[i] - maxVal);
    sumExp += result[i];
  }
  for (int i = 0; i < x.length; i++) {
    result[i] /= sumExp;
  }
  return result;
}

/// Sigmoid: 1 / (1 + exp(-x)).
Float64List sigmoid(Float64List x) {
  final result = Float64List(x.length);
  for (int i = 0; i < x.length; i++) {
    result[i] = 1.0 / (1.0 + math.exp(-x[i]));
  }
  return result;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Sum across the last axis of a tensor represented as a flat array.
///
/// Given [outputShape] `[d0, d1, ..., dN]`, the flat [values] are reshaped
/// to that shape and the last dimension is summed, producing a flat array
/// of length `product(d0..d(N-1))`.
///
/// If [outputShape] has fewer than 2 dimensions, returns [values] unchanged
/// (nothing to sum).
Float64List _sumLastAxis(Float64List values, List<int> outputShape) {
  if (outputShape.length < 2) return values;

  final lastDim = outputShape.last;
  if (lastDim <= 1) return values;

  final outerSize = values.length ~/ lastDim;
  if (outerSize * lastDim != values.length) {
    developer.log(
      'Output shape $outputShape does not match data length '
      '${values.length} — skipping sum. Check client.zip or use '
      'an explicit PostProcessing variant.',
      name: 'flutter_concrete',
    );
    return values;
  }

  final result = Float64List(outerSize);
  for (int i = 0; i < outerSize; i++) {
    double sum = 0.0;
    final base = i * lastDim;
    for (int j = 0; j < lastDim; j++) {
      sum += values[base + j];
    }
    result[i] = sum;
  }
  return result;
}

/// Apply classifier activation: sigmoid for 2 classes, softmax for >2.
///
/// Matches Python's `BaseClassifier.post_processing`:
/// - Binary (length 1): sigmoid, expand to [1-p, p].
/// - Binary (length 2): sigmoid element-wise.
/// - Multi-class (length >2): softmax.
Float64List _classifierActivation(Float64List values) {
  if (values.length == 1) {
    // Binary classifier with single logit — expand to [1-p, p].
    final p = 1.0 / (1.0 + math.exp(-values[0]));
    return Float64List.fromList([1.0 - p, p]);
  }
  if (values.length == 2) {
    // Binary classifier with 2 logits — sigmoid element-wise.
    return sigmoid(values);
  }
  return softmax(values);
}
