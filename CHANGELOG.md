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
