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

Internal (Concrete LWE path)
  ConcreteCipherInfo — LWE encryption/encoding params parsed from client.specs.json
  FheNative.lweEncryptSeeded / lweDecryptFull / lweDecryptSeeded / serializeValue / deserializeValue

Native (rust/)
  lib.rs          — C FFI: fhe_keygen, fhe_encrypt, fhe_decrypt, fhe_lwe_encrypt_seeded,
                    fhe_lwe_decrypt_full, fhe_lwe_decrypt_seeded, fhe_serialize_value,
                    fhe_deserialize_value, fhe_free_buf
  Cargo.toml      — tfhe (git rev matching concrete-ml-extensions 0.2.0), bincode, capnp
  build.rs        — compiles Cap'n Proto schema for evaluation key + ciphertext serialization
  schema/concrete-protocol.capnp — ServerKeyset + Value wire format
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
- **Ciphertext formats:** Both `CiphertextFormat.CONCRETE` (n_bits 1–7, seeded LWE) and `CiphertextFormat.TFHE_RS` (n_bits=8, raw TFHE-rs types) — auto-detected from `client.specs.json`
- **Parameter set:** Derived from circuit topology (GLWE dimensions from BSK specs); V0_10 used as template for noise distributions
- **Encoding:** Native mode only (chunked/CRT → `UnsupportedError`). Uses Concrete carry-bit convention (see below).
- **Serialization:** Cap'n Proto for evaluation keys and CONCRETE ciphertexts, bincode for TFHE-RS ciphertexts
- **Key persistence:** app provides `KeyStorage` impl; plugin uses keys `fhe_client_key` and `fhe_server_key`
- **Pure LWE models:** Keygen detects `topo.bsks.is_empty()` and generates raw `LweSecretKeyOwned` with `LWEK` header

## FHE Flow

1. `ConcreteClient.setup(clientZipBytes, storage)` → parse ZIP, detect format, keygen or restore keys
2. App reads `serverKeyBase64` → uploads evaluation key to backend
3. `quantizeAndEncrypt(Float32List)` → quantize + encrypt (CONCRETE: seeded LWE; TFHE-RS: FheUintN) → `Uint8List`
4. App sends ciphertext to backend, gets encrypted result back
5. `decryptAndDequantize(Uint8List)` → decrypt + dequantize → `Float64List` (aggregated class scores)

## Running Tests

```bash
flutter test                                          # unit tests (no native lib needed)
flutter test --tags=integration --exclude-tags=backend  # all integration (needs cargo build + Python + fixtures)
flutter test --tags=equivalence                        # equivalence tests only
flutter test --tags=cross_client                       # cross-client tests only
flutter test --tags=cross_language                     # cross-language encrypt tests only
```

Unit tests cover `ClientZipParser`, `ConcreteClient` state machine, and `PostProcessing`. No native lib needed.

### Test Suites Requiring Native Library

Build first: `cd rust && cargo build`, then set `DYLD_LIBRARY_PATH=rust/target/debug` (macOS) or `LD_LIBRARY_PATH=rust/target/debug` (Linux).

- **`encrypt_decrypt_roundtrip_test.dart`** (`integration` tag): Validates that `lweEncryptSeeded` → `lweDecryptSeeded` roundtrip produces identical integers. For each CONCRETE-format model: quantize → apply input offsets → encrypt → decrypt → exact integer match. Fully deterministic, no server or Python needed.
- **`cross_language_encrypt_test.dart`** (`integration`, `cross_language` tags): Two checks per CONCRETE-format model:
  - **Check 1 (Dart roundtrip):** Same encrypt/decrypt roundtrip as above.
  - **Check 2 (Python format verification):** Sends Dart-serialized Cap'n Proto Value to Python `fhe.Value.deserialize()` to verify wire format compatibility. Decrypts via `FHEModelClient` where input/output specs match; skips decryption otherwise (signedness or shape mismatch).
- **`python_equivalence_test.dart`** (`equivalence` tag): Tests quantization, dequantization, and post-processing against Python reference values from `test/fixtures/*/reference.json`. No server or FHE encryption — uses synthetic `raw_output_ints`. Requires generated fixtures.
- **`cross_client_test.dart`** (`cross_client` tag): Exercises the production `ConcreteClient` API against a long-lived Python FHE server (single MLIR compilation per model, fresh keys at test time). Two tests per model:
  - **Test 1 (Dart encrypt):** `ConcreteClient.quantizeAndEncrypt` → server → `decryptAndDequantize`. Checks finiteness (encryption noise at n_bits=3 causes score divergence).
  - **Test 2 (Python encrypt):** Python encrypts → server → Dart `decryptAndDequantize`. Same ciphertext → exact score match (1e-4).

### Fixture Generation

Fixtures are machine-specific (not committed to git). Generate with:
```bash
python3 test/fixtures/generate_models.py    # all 8 models, ~5min
```
In CI, fixtures are cached via `actions/cache` keyed on `generate_models.py` + `requirements.txt` hashes.

Some models (xgb_classifier_multiclass, logistic_regression) may SIGABRT on macOS during LLVM cleanup — works on Linux CI.

### MLIR Non-Determinism

`server.zip` contains MLIR source, not compiled binaries. Each `FHEModelServer.load()` JIT-compiles the circuit. **This compilation is non-deterministic even on the same machine between processes** — different instruction scheduling / FP rounding produces different circuits. With `n_bits=3` toy models, this flips argmax predictions. The cross-client test eliminates this by using a single long-lived Python server process per model.

## Encoding Conventions (Concrete vs TFHE-rs)

Concrete uses a **carry-bit encoding**: `delta = 2^(64 - width - 1)`, not `2^(64 - width)` as in standard TFHE-rs. This affects both encrypt and decrypt in `rust/src/lib.rs`:
- Encrypt: `delta = 1 << 62` (1-bit per CT with carry)
- Decrypt: `shift = 64 - width - 1`

For unsigned outputs, don't mask to `width` bits — circuit outputs (e.g. linear regression accumulation) can exceed `2^width`.

### Quantization Offsets

The `offset` in `serialized_processing.json` shifts signed quantized values to unsigned for the circuit:
- **Input offset:** Applied between quantize and encrypt (`QuantizationParams.applyInputOffsets`). Python's `fhe.Client.encrypt` does this internally.
- **Output offset:** NOT applied during dequantization. Python's `dequantize_output` uses `(raw - zp) * scale` without offset. The raw decrypted values don't contain the offset.

## Dependencies

- `ffi: ^2.1.0` — Dart FFI
- `archive: ^4.0.0` — ZIP parsing for client.zip

No dependency on `flutter_secure_storage` or any app-specific package.

## Relevant sources

- concrete-ml is likely at: .venv/lib/python3.11/site-packages/concrete/ml/
- concrete-python (fhe): .venv/lib/python3.11/site-packages/concrete/fhe/
