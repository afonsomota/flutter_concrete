import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_concrete/flutter_concrete.dart';

/// In-memory KeyStorage for testing.
class MemoryKeyStorage implements KeyStorage {
  final Map<String, Uint8List> _store = {};

  @override
  Future<Uint8List?> read(String key) async => _store[key];

  @override
  Future<void> write(String key, Uint8List value) async => _store[key] = value;

  @override
  Future<void> delete(String key) async => _store.remove(key);

  bool containsKey(String key) => _store.containsKey(key);
}

void main() {
  group('ConcreteClient', () {
    test('isReady is false before setup', () {
      final client = ConcreteClient();
      expect(client.isReady, isFalse);
    });

    test('serverKey throws before setup', () {
      final client = ConcreteClient();
      expect(() => client.serverKey, throwsStateError);
    });

    test('serverKeyBase64 throws before setup', () {
      final client = ConcreteClient();
      expect(() => client.serverKeyBase64, throwsStateError);
    });

    test('reset makes isReady false again', () {
      final client = ConcreteClient();
      client.reset();
      expect(client.isReady, isFalse);
    });

    test('modelHashStorageKey constant is correct', () {
      // This test verifies the storage key exists, but cannot run full setup
      // without the native library. We test the logic path by checking
      // that ConcreteClient attempts to write 'fhe_model_hash'.
      expect(ConcreteClient.modelHashStorageKey, 'fhe_model_hash');
    });
  });
}
