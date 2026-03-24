# Tests

## Test types

- **Unit tests** — pure Dart, no tags. Cover quantizer, post-processing, client.zip parser, key topology, circuit encoding. Run with `flutter test`.
- **Integration tests** — tagged `integration`. Require native Rust library (`libfhe_client`) and/or backend server. Run with `flutter test -t integration`.
- **Python equivalence tests** — tagged `equivalence`. Verify Dart's quantization, dequantization, and post-processing match Python's concrete-ml numerically. Use pre-generated fixtures. Run with `flutter test -t equivalence`.

## Running tests

```bash
flutter test                    # unit tests only (tags excluded by default)
flutter test -t equivalence     # equivalence tests only
flutter test -t integration     # integration tests (needs native lib + backend)
```

## Fixture generator

`test/fixtures/generate_models.py` trains 8 tiny Concrete ML models, compiles each to FHE, and produces a `client.zip` + `reference.json` per model. Not run in CI — run locally when models or quantization logic changes.

### Setup

```bash
cd test/fixtures
python -m venv .venv && source .venv/bin/activate
pip install concrete-ml
```

Or with uv:

```bash
cd test/fixtures
uv venv && uv pip install concrete-ml
```

### Run

```bash
python generate_models.py
```

### Output

8 directories under `test/fixtures/`, each with `client.zip` + `reference.json`. Commit generated files after regeneration.

### Notes

Some models may segfault in subprocess mode on ARM. The script retries automatically; if a model still fails, run it standalone.
