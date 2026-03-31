# Tests

## Test types

- **Unit tests** — pure Dart, no tags. Cover quantizer, post-processing, client.zip parser, key topology, circuit encoding. Run with `flutter test`.
- **Python equivalence tests** — tagged `equivalence`. Verify Dart's quantization, dequantization, and post-processing match Python's concrete-ml numerically. Use pre-generated fixtures. Run with `flutter test -t equivalence`.
- **Cross-client tests** — tagged `integration`, `cross_client`. Uses a long-lived Python server process (single MLIR compilation) with fresh keys generated at test time. Exercises the production `ConcreteClient` API. Two tests per model: (1) Dart encrypts via `quantizeAndEncrypt`, checks finiteness of round-trip; (2) Python encrypts, both decrypt same ciphertext, exact score match. Run on main push only in CI.
- **Integration tests** — tagged `integration`. Require native Rust library (`libfhe_client`). Run with `flutter test -t integration`.

## Running tests

```bash
flutter test                                  # unit + equivalence tests (integration excluded)
flutter test -t equivalence                   # equivalence tests only
flutter test -t integration                   # integration tests (needs native lib + Python)
flutter test -t cross_client                  # cross-client tests only
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

`test/fixtures/generate_models.py` trains 8 tiny Concrete ML models, compiles each to FHE, and produces `client.zip` + `server.zip` + `reference.json` per model. Not run in CI — run locally when models or quantization logic changes.

Each `reference.json` includes:
- Quantized inputs, dequantized outputs, and post-processed values for offline equivalence tests
- `python_fhe_scores`: full Python FHE round-trip results (encrypt → server.run → decrypt)

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

8 directories under `test/fixtures/`, each with `client.zip` + `server.zip` + `reference.json`. Commit generated files after regeneration.

### Notes

Some models may segfault during LLVM compilation on ARM (macOS). The script retries automatically; models that still fail will be missing `server.zip` and skipped in cross-client tests. Run on x86 Linux for full coverage.

### Known limitations

**logistic_regression excluded from cross-client Test 1** (Dart encrypt). At `n_bits=3`, the linear FHE circuit amplifies encryption noise differences — independent CSPRNG state in Dart vs Python produces wildly different scores, flipping argmax even on trivial inputs (zeros vector). Cross-client Test 2 (Python encrypt, both decrypt same ciphertext) passes. This is inherent to low-precision FHE, not a bug. Revisit when testing with higher `n_bits` or seeded encryption.
