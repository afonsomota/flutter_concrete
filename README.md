# flutter_concrete

A Flutter FFI plugin that brings [Concrete ML](https://docs.zama.ai/concrete-ml) FHE (Fully Homomorphic Encryption) to mobile apps. The native cryptographic operations — key generation, encryption, and decryption — run entirely on-device via [TFHE-rs](https://github.com/zama-ai/tfhe-rs), with no server-side private key material.

The Rust library builds automatically during `flutter build` thanks to [Cargokit](https://github.com/irondash/cargokit) — no manual build scripts or precompiled binaries required.

## How it works

```
Your App                              flutter_concrete
───────                               ────────────────
                                           │
Load client.zip from assets ──────►  setup(zipBytes, storage)
                                       parse serialized_processing.json
                                       restore or generate keys
                                     ◄── isReady = true
                                           │
Get serverKey ◄────────────────────  serverKey / serverKeyBase64
Upload to your server (your code)          │
                                           │
Float32 features ──────────────────►  quantizeAndEncrypt()
Uint8List ciphertext ◄──────────────       │
Send to server (your code)                 │
Receive result (your code)                 │
Uint8List encrypted result ────────►  decryptAndDequantize()
Float64 class scores ◄──────────────       │
Interpret scores (your code)
```

The server performs ML inference on **encrypted** data — it never sees plaintext inputs or predictions.

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  flutter_concrete: ^0.3.0
```

### Prerequisites

- **Rust toolchain** — install via [rustup](https://rustup.rs/)
- iOS targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios`
- Android targets: `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`

## Usage

```dart
import 'package:flutter_concrete/flutter_concrete.dart';

// 1. Implement KeyStorage (e.g. wrapping flutter_secure_storage)
class MyKeyStorage implements KeyStorage {
  @override
  Future<Uint8List?> read(String key) async { /* ... */ }
  @override
  Future<void> write(String key, Uint8List value) async { /* ... */ }
  @override
  Future<void> delete(String key) async { /* ... */ }
}

// 2. Create client and set up from Concrete ML's client.zip
final client = ConcreteClient();
final zipBytes = await loadClientZipFromAssets(); // your asset loading
await client.setup(
  clientZipBytes: zipBytes,
  storage: MyKeyStorage(),
);
// First call generates keys (~10-60s on mobile), subsequent calls restore.

// 3. Get server key to upload to your backend
final serverKey = client.serverKey;       // Uint8List
final serverKeyB64 = client.serverKeyBase64; // String (cached)
// Upload to your server however you want

// 4. Encrypt features
final ciphertext = client.quantizeAndEncrypt(featureVector);
// Send ciphertext to your server for FHE inference

// 5. Decrypt server response
final scores = client.decryptAndDequantize(encryptedResult);
// scores is Float64List — post-processed based on model type
// For classifiers: probabilities (apply argmax for predicted class)
// For regressors: predicted values
```

## API

### `ConcreteClient`

| Method | Description |
|--------|-------------|
| `Future<void> setup({clientZipBytes, storage})` | Parse `client.zip`, generate/restore keys |
| `void reset()` | Clear state so `setup()` can be called with a different model |
| `bool get isReady` | True after `setup()` completes |
| `Uint8List get serverKey` | Raw evaluation key bytes (throws before setup) |
| `String get serverKeyBase64` | Base64-encoded server key (cached) |
| `Uint8List quantizeAndEncrypt(Float32List)` | Quantize + FHE encrypt |
| `Float64List decryptAndDequantize(Uint8List, {PostProcessing})` | FHE decrypt + dequantize + post-process |
| `String? get modelClassName` | Model class from `client.zip` (e.g. `"XGBClassifier"`) |
| `PostProcessing get detectedPostProcessing` | Auto-resolved post-processing variant |

### `KeyStorage` (abstract — you implement this)

| Method | Description |
|--------|-------------|
| `Future<Uint8List?> read(String key)` | Read stored bytes, or null |
| `Future<void> write(String key, Uint8List value)` | Persist bytes |
| `Future<void> delete(String key)` | Delete entry |

## Post-processing

After decryption and dequantization, `decryptAndDequantize` applies model-specific post-processing to match Python's `FHEModelClient.deserialize_decrypt_dequantize`. The model class name is parsed from `client.zip` and mapped to the correct transform automatically.

### Auto-detection (default)

```dart
// PostProcessing.auto() is the default — no code changes needed.
final scores = client.decryptAndDequantize(encryptedResult);

// Check what was detected:
print(client.modelClassName);          // e.g. "XGBClassifier"
print(client.detectedPostProcessing);  // e.g. EnsembleClassifierPostProcessing
```

### Supported models

| Model class | Variant | Behavior |
|---|---|---|
| `XGBClassifier` | `ensembleClassifier` | Sum trees → sigmoid/softmax |
| `RandomForestClassifier`, `DecisionTreeClassifier` | `ensembleProbabilistic` | Sum trees (outputs are already probabilities) |
| `XGBRegressor` | `xgbRegressor` | Sum trees + 0.5 bias |
| `RandomForestRegressor`, `DecisionTreeRegressor` | `ensembleRegressor` | Sum trees |
| `LogisticRegression`, `LinearSVC`, `SGDClassifier`, `NeuralNetClassifier` | `classifier` | sigmoid (2 classes) / softmax (>2) |
| `LinearRegression`, `Ridge`, `Lasso`, `ElasticNet`, `SGDRegressor`, `LinearSVR`, `NeuralNetRegressor` | `regressor` | Identity |

Unknown models fall back to `PostProcessing.none()` with a logged warning.

### Explicit override

```dart
// Force a specific post-processing variant:
final scores = client.decryptAndDequantize(
  encryptedResult,
  postProcessing: const PostProcessing.classifier(),
);

// Skip post-processing entirely:
final raw = client.decryptAndDequantize(
  encryptedResult,
  postProcessing: const PostProcessing.none(),
);
```

### Custom post-processing

```dart
// For models not in the lookup table (e.g. GLM regressors needing exp):
import 'dart:math';
final scores = client.decryptAndDequantize(
  encryptedResult,
  postProcessing: PostProcessing.custom((values, shape) {
    return Float64List.fromList(values.map((v) => exp(v)).toList());
  }),
);
```

### Models requiring custom post-processing

- `KNeighborsClassifier` — majority vote paradigm, use `PostProcessing.none()` or `PostProcessing.custom()`
- `PoissonRegressor`, `GammaRegressor`, `TweedieRegressor` — need `exp()` inverse link
- `SGDClassifier` with `modified_huber` loss — non-standard activation

## Ciphertext formats

The plugin automatically detects the ciphertext format from `client.specs.json` inside `client.zip`:

| Format | `n_bits` | Circuit size | Notes |
|--------|----------|--------------|-------|
| **CONCRETE** (default) | 1–7 | Small | Seeded LWE encryption, Cap'n Proto Value serialization |
| **TFHE-RS** | 8 | Large | Raw TFHE-rs `FheUint8`/`FheInt8`, bincode serialization |

No code changes needed when switching formats — `ConcreteClient` routes through the appropriate path based on what the model was compiled with.

## Compatibility

- **Concrete ML**: Accepts standard `client.zip` from `FHEModelDev.save()`
- **TFHE-rs**: Git revision `1ec21a5` (matching `concrete-ml-extensions` 0.2.0)
- **Keygen parameters**: Derived dynamically from circuit topology
- **Serialization**: Cap'n Proto (evaluation keys and CONCRETE ciphertexts), bincode (TFHE-RS ciphertexts)
- **Platforms**: iOS, Android
- **Encoding widths**: FheUint8–FheUint64, FheInt8–FheInt64 (selected automatically from `client.specs.json`)

## Known limitations

1. **Single input/output tensor** — assumes one input and one output tensor per circuit.
2. **Native encoding mode only** — chunked and CRT encoding modes are not supported (fail-fast with `UnsupportedError`).
3. **Single output quantizer** — only the first output quantizer is used. Models with per-output quantization (some neural networks) are not yet supported.
4. **QuantizedModule / custom torch models** — arbitrary circuit outputs require `PostProcessing.none()` or `PostProcessing.custom()`.

## License

BSD-3-Clause
