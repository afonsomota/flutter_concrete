# flutter_concrete

Standalone Flutter FFI plugin wrapping TFHE-rs for Concrete ML FHE operations. Domain-agnostic — owns the FHE lifecycle, not application logic.

## Architecture

```
Public API (2 exports)
  ConcreteClient  — setup, quantizeAndEncrypt, decryptAndDequantize
  KeyStorage      — abstract interface for key persistence (app implements)

Internal
  ClientZipParser — extracts quantization params from Concrete ML client.zip
  QuantizationParams / InputQuantParam / OutputQuantParam — quantization math
  FheNative       — Dart FFI bindings to libfhe_client (Rust/TFHE-rs)

Native (rust/)
  lib.rs          — C FFI: fhe_keygen, fhe_encrypt_u8, fhe_decrypt_i8, fhe_free_buf
  Cargo.toml      — tfhe (git rev matching concrete-ml-extensions 0.2.0), bincode, capnp
  build.rs        — compiles Cap'n Proto schema for evaluation key serialization
  schema/concrete-protocol.capnp — ServerKeyset wire format
```

## Build System

Cargokit (git submodule at `cargokit/`) automates Rust compilation during `flutter build`:
- **iOS:** `ios/flutter_concrete.podspec` → script_phase calls `build_pod.sh` → `libfhe_client.a` (staticlib, force-loaded)
- **Android:** `android/build.gradle` → applies `cargokit/gradle/plugin.gradle` → `libfhe_client.so` (cdylib)

No manual build scripts needed. Requires Rust toolchain on the build machine.

### Precompiled Binaries

Configured via `rust/cargokit.yaml`. GitHub Action at `.github/workflows/precompile.yml` builds and uploads signed binaries on push to main. Developers without Rust installed will download precompiled binaries automatically.

To set up: store the private signing key as `PRECOMPILE_PRIVATE_KEY` secret in the GitHub repo.

## Key Constraints

- **TFHE-rs version:** pinned to git rev `1ec21a5` for binary compatibility with concrete-ml-extensions 0.2.0
- **Quantization:** 8-bit only (uint8 input, int8 output)
- **Parameter set:** `V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64` (hardcoded in Rust)
- **Eval key topology:** hardcoded in `lib.rs` `generate_concrete_eval_keys()` — 8 secret keys, 4 BSKs, 8 KSKs
- **Serialization:** bincode for ciphertexts, Cap'n Proto for evaluation keys
- **Key persistence:** app provides `KeyStorage` impl; plugin uses keys `fhe_client_key` and `fhe_server_key`

## FHE Flow

1. `ConcreteClient.setup(clientZipBytes, storage)` → parse ZIP, keygen or restore keys
2. App reads `serverKeyBase64` → uploads evaluation key to backend
3. `quantizeAndEncrypt(Float32List)` → quantize (float→uint8) + encrypt (TFHE-rs) → `Uint8List`
4. App sends ciphertext to backend, gets encrypted result back
5. `decryptAndDequantize(Uint8List)` → decrypt (TFHE-rs, int8) + dequantize (int8→float) → `Float64List`

## Running Tests

```bash
flutter test
```

Tests cover `ClientZipParser` (real client.zip parsing, validation, format handling) and `ConcreteClient` (state machine: isReady, serverKey guards, reset). Native FHE ops require the Rust library and aren't unit-tested.

## Dependencies

- `ffi: ^2.1.0` — Dart FFI
- `archive: ^4.0.0` — ZIP parsing for client.zip

No dependency on `flutter_secure_storage` or any app-specific package.
