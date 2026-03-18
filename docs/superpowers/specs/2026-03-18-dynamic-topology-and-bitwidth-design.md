# Dynamic Key Topology and Multi-Bit-Width Support

**Date:** 2026-03-18
**Status:** Approved
**Addresses:** README limitations #1 (hardcoded eval key topology) and #2 (uint8/int8 only)

## Problem

The Rust native library hardcodes:
- 8 secret keys, 4 BSKs, 8 KSKs with fixed dimensions — but the actual `client.specs.json` from Concrete ML specifies a different topology (e.g., 6 SKs, 3 BSKs, 3 KSKs)
- `FheUint8` for encryption and `FheInt8` for decryption — but Concrete ML circuits can use encoding widths from 1 to 64 bits

Both should be driven by `client.specs.json` inside the `client.zip`.

## Design

### Section 1: Dart-side specs parsing

`ClientZipParser` already extracts `serialized_processing.json` from the zip. Extend it to also extract and parse `client.specs.json`, producing two new data structures:

**`KeyTopology`** — keygen parameters:
- `List<SecretKeySpec>` — each with `id`, `lweDimension`
- `List<BootstrapKeySpec>` — each with `inputId`, `outputId`, `levelCount`, `baseLog`, `glweDimension`, `polynomialSize`
- `List<KeyswitchKeySpec>` — each with `inputId`, `outputId`, `levelCount`, `baseLog`

**`CircuitEncoding`** — I/O bit widths:
- `inputWidth` (int), `inputIsSigned` (bool) — from `circuits[0].inputs[0].typeInfo.lweCiphertext.encoding.integer`
- `outputWidth` (int), `outputIsSigned` (bool) — from `circuits[0].outputs[0].typeInfo.lweCiphertext.encoding.integer`

`QuantizationParams` continues to be parsed from `serialized_processing.json` (scale/zero_point math). `CircuitEncoding` determines which TFHE-rs type to use.

The `_validateNBits()` check that rejects non-8-bit is removed. Instead, validation ensures encoding width fits a supported TFHE-rs type by rounding up: 1-8 → 8, 9-16 → 16, 17-32 → 32, 33-64 → 64. Reject widths > 64.

### Section 2: FFI interface changes

**`fhe_keygen(topology_ptr, topology_len)` replaces the no-arg version**

Dart packs the topology into a flat `Uint64List`:

```
[num_sks, dim0, dim1, ...,
 num_bsks, input_id, output_id, level_count, base_log, glwe_dim, poly_size, ...
 num_ksks, input_id, output_id, level_count, base_log, ...]
```

Rust unpacks this, generates secret keys with specified dimensions, builds BSKs and KSKs from params. Cap'n Proto eval key serialization becomes dynamic — writes N BSKs and K KSKs instead of hardcoded 4 and 8.

**`fhe_encrypt(vals, len, bit_width, is_signed)` replaces `fhe_encrypt_u8`**

Rust matches on `(bit_width, is_signed)` to dispatch:
- `(8, false)` → `FheUint8`, `(8, true)` → `FheInt8`
- `(16, false)` → `FheUint16`, `(16, true)` → `FheInt16`
- `(32, false)` → `FheUint32`, `(32, true)` → `FheInt32`
- `(64, false)` → `FheUint64`, `(64, true)` → `FheInt64`

Returns encrypted ciphertext bytes (bincode serialized).

**`fhe_decrypt(ct, ct_len, bit_width, is_signed, out_len)` replaces `fhe_decrypt_i8`**

Same dispatch. Output buffer element size matches the type (1 byte for 8-bit, 2 for 16-bit, etc.). Values are sign-extended to `i64` in the output buffer for uniform handling on the Dart side.

**Dart FFI bindings (`FheNative`)** updated: `encryptValues` and `decryptValues` take `bitWidth` and `isSigned` parameters. Output buffer sizing derived from element width.

### Section 3: ConcreteClient integration

`ConcreteClient.setup()` flow:

1. `ClientZipParser` extracts both `serialized_processing.json` and `client.specs.json`
2. Returns `QuantizationParams`, `KeyTopology`, and `CircuitEncoding`
3. `ConcreteClient` stores all three
4. Keygen calls `FheNative.generateKeys(topology.pack())` with the packed topology
5. `quantizeAndEncrypt()` uses `CircuitEncoding.inputWidth` and `inputIsSigned`
6. `decryptAndDequantize()` uses `CircuitEncoding.outputWidth` and `outputIsSigned`

Quantization math adjustment: zero_point clamping range derived from bit width instead of hardcoded `[0, 255]` / `[-128, 127]`. Unsigned N-bit: `[0, 2^N - 1]`. Signed N-bit: `[-2^(N-1), 2^(N-1) - 1]`.

**Public API unchanged** — `setup()`, `quantizeAndEncrypt()`, `decryptAndDequantize()`. Consumers don't need to know about bit widths or topology.

### Section 4: Backward compatibility and error handling

**Model change detection:** Store a hash of the packed topology alongside the keys in `KeyStorage` (key: `fhe_topology_hash`). On restore, if the hash doesn't match the current `client.specs.json`, discard stored keys and re-keygen.

**Validation:** `ClientZipParser` throws `FormatException` if:
- `client.specs.json` is missing from the zip
- Required fields are missing (`lweDimension`, `levelCount`, etc.)
- Encoding width > 64 or doesn't round to a supported type
- Circuit input/output encoding is missing

**No breaking API changes.** Existing 8-bit model apps continue working without code changes.

**Tests:**
- `ClientZipParser`: parse real `client.specs.json`, validate topology extraction, error cases (missing fields, unsupported widths)
- `ConcreteClient`: topology hash mismatch triggers re-keygen
- `QuantizationParams`: clamping ranges correct for 8/16/32/64-bit widths

## Files affected

| File | Change |
|------|--------|
| `lib/src/client_zip_parser.dart` | Parse `client.specs.json`, produce `KeyTopology` + `CircuitEncoding` |
| `lib/src/key_topology.dart` | New: `KeyTopology`, `SecretKeySpec`, `BootstrapKeySpec`, `KeyswitchKeySpec`, `pack()` method |
| `lib/src/circuit_encoding.dart` | New: `CircuitEncoding`, bit width rounding logic |
| `lib/src/quantizer.dart` | Dynamic clamping range based on bit width, remove 8-bit hardcoding |
| `lib/src/fhe_native.dart` | Update FFI signatures: keygen takes topology, encrypt/decrypt take bit_width + is_signed |
| `lib/src/concrete_client.dart` | Store topology + encoding, pass to FFI calls, topology hash for key invalidation |
| `lib/flutter_concrete.dart` | Export new public types if needed |
| `rust/src/lib.rs` | Dynamic keygen from packed topology, encrypt/decrypt dispatch on bit width, dynamic Cap'n Proto serialization |
| `test/client_zip_parser_test.dart` | Tests for specs parsing |
| `test/concrete_client_test.dart` | Tests for topology hash invalidation |
| `test/quantizer_test.dart` | Tests for multi-width clamping |
