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
  flutter_concrete: ^0.1.0
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
// scores is Float64List — apply argmax for classification
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
| `Float64List decryptAndDequantize(Uint8List)` | FHE decrypt + dequantize |

### `KeyStorage` (abstract — you implement this)

| Method | Description |
|--------|-------------|
| `Future<Uint8List?> read(String key)` | Read stored bytes, or null |
| `Future<void> write(String key, Uint8List value)` | Persist bytes |
| `Future<void> delete(String key)` | Delete entry |

## Compatibility

- **Concrete ML**: Accepts standard `client.zip` from `FHEModelDev.save()`
- **TFHE-rs**: Git revision `1ec21a5` (matching `concrete-ml-extensions` 0.2.0)
- **Parameter set**: `V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64`
- **Serialization**: bincode (ciphertexts), Cap'n Proto (evaluation keys)
- **Platforms**: iOS, Android
- **Encoding widths**: FheUint8–FheUint64, FheInt8–FheInt64 (selected automatically from `client.specs.json`)

## Known limitations

1. ~~**Hardcoded eval key topology**~~ — Key topology is now parsed dynamically from `client.specs.json`, allowing support for any Concrete ML circuit configuration.

2. ~~**uint8 input / int8 output only**~~ — The plugin now supports multi-width encoding (FheUint8–FheUint64, FheInt8–FheInt64), automatically selected from `client.specs.json`.

3. **Single input/output tensor** — assumes one input and one output tensor per circuit.

4. ~~**No precompiled binaries**~~ — Precompiled binaries are now built and signed automatically via GitHub Actions. Developers without a Rust toolchain will download them during `flutter build`.

## License

BSD-3-Clause
