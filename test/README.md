# Tests

## Test types

- **Unit tests** — pure Dart, no tags. Cover quantizer, post-processing, client.zip parser, key topology, circuit encoding. Run with `flutter test`.
- **Encrypt-decrypt roundtrip tests** — tagged `integration`. Validate that `lweEncryptSeeded` → `lweDecryptSeeded` are proper inverses: quantize → apply input offsets → encrypt → decrypt → exact integer match. Fully deterministic, no server or Python needed. Run with `flutter test -t integration`.
- **Cross-language encrypt tests** — tagged `integration`, `cross_language`. Two checks per model: (1) Dart encrypt/decrypt roundtrip (same as above); (2) send Dart-serialized Cap'n Proto Value to Python `fhe.Value.deserialize()` for wire format compatibility, with optional Python decryption where input/output specs match. Run with `flutter test -t cross_language`.
- **Python equivalence tests** — tagged `equivalence`. Verify Dart's quantization, dequantization, and post-processing match Python's concrete-ml numerically. Use pre-generated fixtures. Run with `flutter test -t equivalence`.
- **Cross-client tests** — tagged `integration`, `cross_client`. Uses a long-lived Python server process (single MLIR compilation) with fresh keys generated at test time. Exercises the production `ConcreteClient` API. Two tests per model: (1) Dart encrypts via `quantizeAndEncrypt`, checks finiteness of round-trip; (2) Python encrypts, both decrypt same ciphertext, exact score match.
- **Integration tests** — tagged `integration`. Require native Rust library (`libfhe_client`). Run with `flutter test -t integration`.

## Running tests

```bash
flutter test                                  # unit tests only (integration excluded by default)
flutter test -t equivalence                   # equivalence tests only
flutter test -t integration                   # all integration tests (needs native lib + fixtures)
flutter test -t cross_language                # cross-language encrypt tests only (needs native lib + Python)
flutter test -t cross_client                  # cross-client tests only (needs native lib + Python server)
```

### Cross-client tests

Verify that Dart's `ConcreteClient` API produces correct FHE results against a Python `FHEModelServer`. Uses a long-lived Python server process (one MLIR compilation per model) with fresh keys generated at test time.

```bash
# 1. Build native library
cd rust && cargo build && cd ..

# 2. Set up Python environment
cd test/fixtures
uv venv && uv pip install -r requirements.txt
source .venv/bin/activate
cd ../..

# 3. Run (macOS)
DYLD_LIBRARY_PATH=rust/target/debug flutter test -t cross_client

# 3. Run (Linux)
LD_LIBRARY_PATH=rust/target/debug flutter test -t cross_client
```

The test will **fail** (not skip) if `python3` with `concrete-ml` is not on PATH.

## Fixture generator

`test/fixtures/generate_models.py` trains 8 tiny Concrete ML models, compiles each to FHE, and produces per model: `client.zip`, `server.zip`, `reference.json`, `secret_key.bin`, `eval_key.bin`, `full_keys.bin`. Fixtures are cached in CI keyed on `generate_models.py` + `requirements.txt` hashes.

Each `reference.json` includes:
- Quantized inputs, dequantized outputs, and post-processed values for offline equivalence tests
- `python_fhe_scores`: full Python FHE round-trip results (encrypt → server.run → decrypt)

`full_keys.bin` is the serialized `concrete.fhe.Keys` object, needed by cross-language encrypt tests to inject the same key material into Python's `FHEModelClient`.

### Setup

```bash
cd test/fixtures
uv venv && uv pip install -r requirements.txt
```

### Run

```bash
source .venv/bin/activate
python generate_models.py
```

### Output

8 directories under `test/fixtures/`, each with `client.zip`, `server.zip`, `reference.json`, `secret_key.bin`, `eval_key.bin`, `full_keys.bin`. All fixture files are gitignored (machine-specific).

### Notes

Some models may segfault during LLVM compilation on ARM (macOS). The script retries automatically; models that still fail will be missing `server.zip` and skipped in cross-client tests. Run on x86 Linux for full coverage.

### Known limitations

**logistic_regression excluded from cross-client Test 1** (Dart encrypt). At `n_bits=3`, the linear FHE circuit amplifies encryption noise differences — independent CSPRNG state in Dart vs Python produces wildly different scores, flipping argmax even on trivial inputs (zeros vector). Cross-client Test 2 (Python encrypt, both decrypt same ciphertext) passes. This is inherent to low-precision FHE, not a bug. Revisit when testing with higher `n_bits` or seeded encryption.
