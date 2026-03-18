# Dynamic Key Topology and Multi-Bit-Width Support

**Date:** 2026-03-18
**Status:** Approved
**Addresses:** README limitations #1 (hardcoded eval key topology) and #2 (uint8/int8 only)

## Problem

The Rust native library hardcodes:
- 8 secret keys, 4 BSKs, 8 KSKs with fixed dimensions — but the actual `client.specs.json` from Concrete ML specifies a different topology (e.g., 6 SKs, 3 BSKs, 3 KSKs with different dimensions). **This is a current correctness bug** — the hardcoded topology in `lib.rs` does not match the current model artifact.
- `FheUint8` for encryption and `FheInt8` for decryption — but Concrete ML circuits can use different encoding widths (e.g., the current model uses input encoding width 10, output width 8).

Both should be driven by `client.specs.json` inside the `client.zip`.

### Two kinds of "bit width"

This spec deals with two distinct bit-width concepts that must not be conflated:

- **Quantization `n_bits`** (from `serialized_processing.json`): determines the integer range for quantize/dequantize math (scale, zero_point, clamping). E.g., `n_bits=8` means the quantizer maps floats to 8-bit integers.
- **Encoding `width`** (from `client.specs.json`): determines which TFHE-rs type to use for encrypt/decrypt. E.g., `width=10` means the FHE circuit uses 10-bit encoding internally, which requires `FheUint16` (next power-of-2).

Quantization clamping uses `n_bits`. TFHE-rs type selection uses encoding `width`.

## Design

### Section 1: Dart-side specs parsing

`ClientZipParser` already extracts `serialized_processing.json` and `client.specs.json` from the zip (it currently reads `client.specs.json` for `nClasses` via `tfhers_specs`). Extend the `client.specs.json` parsing to also produce two new data structures:

**`KeyTopology`** — keygen parameters:
- `List<SecretKeySpec>` — each with `id`, `lweDimension`
- `List<BootstrapKeySpec>` — each with `inputId`, `outputId`, `levelCount`, `baseLog`, `glweDimension`, `polynomialSize`, `variance` (double), `inputLweDimension` (from cross-referencing the input SK)
- `List<KeyswitchKeySpec>` — each with `inputId`, `outputId`, `levelCount`, `baseLog`, `variance` (double), `inputLweDimension`, `outputLweDimension` (from cross-referencing SKs)

The parser cross-references SK IDs to populate LWE dimensions in BSK/KSK specs, so the packed format carries everything Rust needs without Rust needing to do lookups.

**`CircuitEncoding`** — I/O encoding widths (for TFHE-rs type selection):
- `inputWidth` (int), `inputIsSigned` (bool) — from `circuits[0].inputs[0].typeInfo.lweCiphertext.encoding.integer`
- `outputWidth` (int), `outputIsSigned` (bool) — from `circuits[0].outputs[0].typeInfo.lweCiphertext.encoding.integer`

`QuantizationParams` continues to be parsed from `serialized_processing.json` (scale/zero_point/clamping math). Quantization clamping ranges remain based on `n_bits` from `serialized_processing.json`, NOT encoding width.

The `_validateNBits()` check that rejects non-8-bit is removed. Instead, validation ensures encoding width fits a supported TFHE-rs type by rounding up: 1-8 → 8, 9-16 → 16, 17-32 → 32, 33-64 → 64. Reject widths > 64.

### Section 2: FFI interface changes

**`fhe_keygen(topology_ptr, topology_len)` replaces the no-arg version**

Dart packs the topology into a flat `Uint64List`. Variances are encoded as `f64` bits via `double.toInt()` bitwise (ByteData float64/uint64 reinterpret):

```
[num_sks, id0, dim0, id1, dim1, ...,
 num_bsks, input_id, output_id, level_count, base_log, glwe_dim, poly_size, input_lwe_dim, variance_bits, ...,
 num_ksks, input_id, output_id, level_count, base_log, input_lwe_dim, output_lwe_dim, variance_bits, ...]
```

SK entries are `(id, dimension)` pairs. BSK entries are 8 fields each. KSK entries are 7 fields each. Rust unpacks this, generates secret keys with specified dimensions, builds BSKs and KSKs from params. Cap'n Proto eval key serialization becomes dynamic — writes N BSKs and K KSKs. The Cap'n Proto schema already supports variable-length lists, so no schema changes needed.

**Note on GLWE keys:** BSK entries include `glweDimension` and `polynomialSize`. Rust derives the GLWE secret key structure from these fields combined with the output SK. The output SK's `lweDimension` equals `glweDimension * polynomialSize`.

**`fhe_encrypt(vals, len, bit_width, is_signed)` replaces `fhe_encrypt_u8`**

Rust matches on `(bit_width, is_signed)` to dispatch:
- `(8, false)` → `FheUint8`, `(8, true)` → `FheInt8`
- `(16, false)` → `FheUint16`, `(16, true)` → `FheInt16`
- `(32, false)` → `FheUint32`, `(32, true)` → `FheInt32`
- `(64, false)` → `FheUint64`, `(64, true)` → `FheInt64`

Input values are passed as `i64` (Dart converts quantized values to `Int64List`). Rust casts each `i64` to the target type before encrypting. Returns encrypted ciphertext bytes (bincode serialized).

**`fhe_decrypt(ct, ct_len, bit_width, is_signed, out_len)` replaces `fhe_decrypt_i8`**

Same dispatch. All decrypted values are widened to `i64` in the output buffer for uniform Dart-side handling:
- **Unsigned types**: zero-extended to `i64` (e.g., `u16` 65535 → `i64` 65535)
- **Signed types**: sign-extended to `i64` (e.g., `i8` -1 → `i64` -1)

Output buffer is always `i64` elements (8 bytes each). `out_len` is set to the number of elements.

**Dart FFI bindings (`FheNative`)** updated: `encryptValues` takes `Int64List`, `bitWidth`, `isSigned`. `decryptValues` returns `Int64List`, takes `bitWidth`, `isSigned`. `dequantizeOutputs` in `QuantizationParams` updated to accept `Int64List` instead of `Int8List`.

### Section 3: ConcreteClient integration

`ConcreteClient.setup()` flow:

1. `ClientZipParser` extracts both `serialized_processing.json` and `client.specs.json`
2. Returns `QuantizationParams`, `KeyTopology`, and `CircuitEncoding`
3. `ConcreteClient` stores all three
4. Keygen calls `FheNative.generateKeys(topology.pack())` with the packed topology
5. `quantizeAndEncrypt()`: quantizes using `QuantizationParams` (clamping based on `n_bits`), then encrypts using `CircuitEncoding.inputWidth` and `inputIsSigned`
6. `decryptAndDequantize()`: decrypts using `CircuitEncoding.outputWidth` and `outputIsSigned`, then dequantizes using `QuantizationParams`

**Public API unchanged** — `setup()`, `quantizeAndEncrypt()`, `decryptAndDequantize()`. Consumers don't need to know about bit widths or topology.

### Section 4: Backward compatibility and error handling

**Model change detection:** Store a hash of the packed topology + encoding alongside the keys in `KeyStorage` (key: `fhe_model_hash`). The hash covers both `KeyTopology` and `CircuitEncoding` so any model change (topology or encoding) triggers re-keygen. On restore:

1. Read stored hash
2. Compare with current model hash
3. If mismatch: delete stored client key, server key, and old hash
4. Re-keygen and write new keys + new hash

**Validation:** `ClientZipParser` throws `FormatException` if:
- `client.specs.json` is missing from the zip
- Required fields are missing (`lweDimension`, `levelCount`, `variance`, etc.)
- Encoding width > 64
- Circuit input/output encoding is missing

**No breaking API changes.** Existing 8-bit model apps continue working without code changes.

**Tests:**
- `ClientZipParser`: parse real `client.specs.json`, validate topology extraction with all fields (including variance, LWE dimensions), error cases (missing fields, unsupported widths)
- `ConcreteClient`: model hash mismatch triggers re-keygen
- `QuantizationParams`: verify clamping still uses `n_bits` from `serialized_processing.json`, not encoding width

## Files affected

| File | Change |
|------|--------|
| `lib/src/client_zip_parser.dart` | Extend `client.specs.json` parsing to produce `KeyTopology` + `CircuitEncoding` |
| `lib/src/key_topology.dart` | New: `KeyTopology`, `SecretKeySpec`, `BootstrapKeySpec`, `KeyswitchKeySpec`, `pack()` method |
| `lib/src/circuit_encoding.dart` | New: `CircuitEncoding`, bit width rounding logic |
| `lib/src/quantizer.dart` | Remove `_validateNBits` 8-bit check, update `dequantizeOutputs` to accept `Int64List` |
| `lib/src/fhe_native.dart` | Update FFI signatures: keygen takes topology, encrypt takes `Int64List` + bit_width + is_signed, decrypt returns `Int64List` |
| `lib/src/concrete_client.dart` | Store topology + encoding, pass to FFI calls, model hash for key invalidation |
| `lib/flutter_concrete.dart` | No changes needed (KeyTopology and CircuitEncoding are internal) |
| `rust/src/lib.rs` | Dynamic keygen from packed topology, encrypt/decrypt dispatch on bit width, dynamic Cap'n Proto serialization |
| `rust/Cargo.toml` | May need additional TFHE-rs feature flags for wider integer types |
| `test/client_zip_parser_test.dart` | Extend: tests for specs parsing, topology extraction, validation |
| `test/concrete_client_test.dart` | Extend: tests for model hash invalidation |
| `test/quantizer_test.dart` | New: tests for multi-width clamping correctness |
