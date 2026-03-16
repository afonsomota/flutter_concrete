# flutter_concrete

A Flutter FFI plugin that brings [Concrete ML](https://docs.zama.ai/concrete-ml) FHE (Fully Homomorphic Encryption) to mobile apps. The native cryptographic operations — key generation, encryption, and decryption — run entirely on-device via [TFHE-rs](https://github.com/zama-ai/tfhe-rs), with no server-side private key material.

The Rust library builds automatically during `flutter build` thanks to [Cargokit](https://github.com/irondash/cargokit) — no manual build scripts or precompiled binaries required.

## How it works

```
Your App                          flutter_concrete                   Server
───────                           ────────────────                   ──────
                                       │
Load quantization_params.json ───►  ConcreteClient
                                       │
                              generateKeys() ──► clientKey (secret, on-device)
                                                 serverKey (upload to server) ──────►
                                       │
Float32 features ────────────►  quantizeAndEncrypt()
                                  quantize → uint8
                                  encrypt  → FheUint8[]
                                  ciphertext bytes ─────────────────────────────────► FHE inference
                                       │                                              on encrypted data
                              decryptAndDequantize() ◄──────────────────────────────── encrypted result
                                  decrypt  → int8 scores
                                  dequantize → float64
                                       │
                              Float64 class scores ◄──
```

The server performs ML inference on **encrypted** data — it never sees plaintext inputs or predictions.

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  flutter_concrete:
    git:
      url: https://github.com/afonsomota/flutter_concrete.git
```

Or as a local path dependency:

```yaml
dependencies:
  flutter_concrete:
    path: ../flutter_concrete
```

### Prerequisites

- **Rust toolchain** — install via [rustup](https://rustup.rs/)
- iOS targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios`
- Android targets: `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`

## Usage

```dart
import 'dart:convert';
import 'package:flutter_concrete/flutter_concrete.dart';

// 1. Load your quantization params (from Concrete ML compilation)
final json = jsonDecode(await loadQuantParamsJson());
final quantParams = QuantizationParams.fromJson(json);

// 2. Create the client
final client = ConcreteClient(quantParams: quantParams);

// 3. Generate keys (CPU-intensive, ~10-60s on mobile — cache the result!)
final keys = client.generateKeys();
// keys.clientKey → store securely on device
// keys.serverKey → upload to your backend (POST /fhe/key)

// Or restore previously persisted keys:
// client.restoreKeys(clientKey: savedClientKey, serverKey: savedServerKey);

// 4. Encrypt features
final ciphertext = client.quantizeAndEncrypt(featureVector);
// Send ciphertext to server for FHE inference

// 5. Decrypt server response
final scores = client.decryptAndDequantize(encryptedResult);
// scores is Float64List — apply argmax for classification
```

## API

### `ConcreteClient`

| Method | Description |
|--------|-------------|
| `ConcreteClient({required QuantizationParams quantParams})` | Create client with quantization config |
| `KeygenResult generateKeys()` | Generate TFHE-rs keypair (~10-60s on mobile) |
| `restoreKeys({clientKey, serverKey})` | Restore previously persisted keys |
| `Uint8List quantizeAndEncrypt(Float32List features)` | Quantize + FHE encrypt |
| `Float64List decryptAndDequantize(Uint8List ciphertext)` | FHE decrypt + dequantize |

### `QuantizationParams`

| Method | Description |
|--------|-------------|
| `QuantizationParams.fromJson(Map<String, dynamic>)` | Parse from `quantization_params.json` |
| `Uint8List quantizeInputs(Float32List)` | Float → uint8 per-feature quantization |
| `Float64List dequantizeOutputs(Int8List)` | Int8 → float64 dequantization |

### `FheNative` (low-level)

Direct FFI bindings if you need raw access without quantization:

| Method | Description |
|--------|-------------|
| `KeygenResult keygen()` | Raw key generation |
| `Uint8List encryptU8(Uint8List clientKey, Uint8List values)` | Encrypt uint8 values |
| `Int8List decryptI8(Uint8List clientKey, Uint8List ciphertext)` | Decrypt to int8 scores |

## Quantization params format

The `quantization_params.json` file is produced by Concrete ML during FHE compilation:

```json
{
  "input": [
    {"scale": 0.0123, "zero_point": 128},
    {"scale": 0.0456, "zero_point": 130}
  ],
  "output": {
    "scale": 0.0789,
    "zero_point": 0,
    "offset": 128
  }
}
```

- **Input**: one `{scale, zero_point}` per feature dimension
- **Output**: single `{scale, zero_point, offset}` for all output classes

## Compatibility

- **TFHE-rs**: Git revision `1ec21a5` (matching `concrete-ml-extensions` 0.2.0)
- **Parameter set**: `V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64`
- **Serialization**: bincode (ciphertexts), Cap'n Proto (evaluation keys)
- **Platforms**: iOS, Android

## Known limitations

1. **Hardcoded eval key topology** — key generation produces 4 BSKs and 8 KSKs matching a specific Concrete ML circuit. A different model/circuit would need different key parameters.

2. **uint8 input / int8 output only** — matches 8-bit quantization. Other bit widths (int8 input, uint8 output, 16-bit) are not yet supported.

3. **No `client.zip` parsing** — expects pre-extracted `quantization_params.json`. Does not read from `client.zip` directly.

4. **Single input/output tensor** — assumes one input and one output tensor per circuit.

5. **No precompiled binaries** — requires Rust toolchain on the build machine.

## License

MIT
