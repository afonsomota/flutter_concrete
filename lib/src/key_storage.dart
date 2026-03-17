import 'dart:typed_data';

/// App-provided key persistence strategy.
///
/// Keeps the plugin free of flutter_secure_storage or any
/// specific storage dependency.
abstract class KeyStorage {
  /// Read raw bytes for [key], or null if not found.
  Future<Uint8List?> read(String key);

  /// Persist raw [value] bytes under [key].
  Future<void> write(String key, Uint8List value);

  /// Delete the entry for [key].
  Future<void> delete(String key);
}
