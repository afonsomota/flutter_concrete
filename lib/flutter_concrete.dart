/// Concrete ML FHE client for Flutter.
///
/// Provides native TFHE-rs encryption/decryption via Dart FFI,
/// with quantization support for Concrete ML models.
library flutter_concrete;

export 'src/concrete_client.dart' show ConcreteClient;
export 'src/key_storage.dart' show KeyStorage;
