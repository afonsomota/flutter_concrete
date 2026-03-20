## 0.3.0

- **`CiphertextFormat.CONCRETE` support**: Native seeded LWE encryption and decryption for Concrete's default ciphertext format. Enables `n_bits` 1–7 (no longer forced to `n_bits=8`), producing dramatically smaller circuits and faster inference.
- **Automatic format detection**: `ConcreteClient` reads `client.specs.json` to determine whether the model uses CONCRETE or TFHE-rs format and routes through the appropriate path. No public API changes.
- **Dynamic keygen parameters**: `fhe_keygen` derives GLWE dimensions from the circuit topology instead of hardcoding V0_10, supporting any parameter set the Concrete compiler chooses.
- **Cap'n Proto Value serialization**: New `fhe_serialize_value` / `fhe_deserialize_value` FFI functions for Concrete's ciphertext transport format.
- **nClasses from output shape**: `dequantizeOutputs` correctly aggregates per-tree scores for CONCRETE format models where `tfhers_specs` is absent.
- New internal types: `ConcreteCipherInfo`, `ConcreteCipherCompression`

## 0.2.0

- **Dynamic key topology**: Keygen reads `client.specs.json` from `client.zip` instead of hardcoded key counts. Supports any Concrete ML circuit.
- **Multi-width encrypt/decrypt**: Dispatches to FheUint8–64 / FheInt8–64 based on encoding width. No longer limited to uint8/int8.
- **Model change detection**: SHA-256 hash of topology + encoding stored in KeyStorage; keys auto-regenerate when the model changes.
- `Int64List` I/O for quantization with dynamic bit-width clamping

## 0.1.0

- Initial release
- ConcreteClient: setup from Concrete ML client.zip, key generation/restoration, quantize+encrypt, decrypt+dequantize
- KeyStorage abstract interface for key persistence
- 8-bit quantization (uint8 input, int8 output) compatible with Concrete ML models
- Cargokit-based native build with precompiled binary support
- Android and iOS platform support

## 0.1.1

- Updated README.md
