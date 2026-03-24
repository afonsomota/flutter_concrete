# Tests

## Test types

- **Unit tests** — pure Dart, no tags. Cover quantizer, post-processing, client.zip parser, key topology, circuit encoding. Run with `flutter test`.
- **Python equivalence tests** — tagged `equivalence`. Verify Dart's quantization, dequantization, and post-processing match Python's concrete-ml numerically. Use pre-generated fixtures. Run with `flutter test -t equivalence`.
- **Server equivalence tests** — tagged `integration`, `server_equivalence`. Full FHE round-trip: Dart encrypts via Rust FFI, Python `FHEModelServer` runs inference, Dart decrypts, and results are compared against pre-computed Python FHE scores. Requires native lib + Python with concrete-ml. Run on main push only in CI.
- **Integration tests** — tagged `integration`. Require native Rust library (`libfhe_client`). Run with `flutter test -t integration`.

## Running tests

```bash
flutter test                                  # unit + equivalence tests (integration excluded)
flutter test -t equivalence                   # equivalence tests only
flutter test -t integration                   # integration tests (needs native lib)
flutter test -t server_equivalence            # server equivalence tests (needs native lib + Python)
```

### Server equivalence tests

These tests verify that Dart and Python FHE clients produce the same predictions when both encrypt the same input and run inference on the same `FHEModelServer`.

```bash
# 1. Build native library
cd rust && cargo build && cd ..

# 2. Set up Python environment
cd test/fixtures
uv venv && uv pip install -r requirements.txt
source .venv/bin/activate
cd ../..

# 3. Run (macOS)
DYLD_LIBRARY_PATH=rust/target/debug flutter test -t server_equivalence

# 3. Run (Linux)
LD_LIBRARY_PATH=rust/target/debug flutter test -t server_equivalence
```

The test will **fail** (not skip) if `python3` with `concrete-ml` is not on PATH.

## Fixture generator

`test/fixtures/generate_models.py` trains 8 tiny Concrete ML models, compiles each to FHE, and produces `client.zip` + `server.zip` + `reference.json` per model. Not run in CI — run locally when models or quantization logic changes.

Each `reference.json` includes:
- Quantized inputs, dequantized outputs, and post-processed values for offline equivalence tests
- `python_fhe_scores`: full Python FHE round-trip results (encrypt → server.run → decrypt) for server equivalence tests

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

Some models may segfault during LLVM compilation on ARM (macOS). The script retries automatically; models that still fail will be missing `server.zip` and skipped in server equivalence tests. Run on x86 Linux for full coverage.
