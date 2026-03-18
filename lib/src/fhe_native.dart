// lib/src/fhe_native.dart
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// ── C function signatures ─────────────────────────────────────────────────────

// int32_t fhe_keygen(
//     const uint64_t *topology, size_t topology_len,
//     uint8_t **ck_out, size_t *ck_len,
//     uint8_t **sk_out, size_t *sk_len)
typedef _FheKeygenC = Int32 Function(
    Pointer<Uint64>, Size,
    Pointer<Pointer<Uint8>>, Pointer<Size>,
    Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _FheKeygenDart = int Function(
    Pointer<Uint64>, int,
    Pointer<Pointer<Uint8>>, Pointer<Size>,
    Pointer<Pointer<Uint8>>, Pointer<Size>);

// int32_t fhe_encrypt(
//     const uint8_t *ck, size_t ck_len,
//     const int64_t *vals, size_t n_vals,
//     uint32_t bit_width, uint32_t is_signed,
//     uint8_t **ct_out, size_t *ct_len)
typedef _FheEncryptC = Int32 Function(
    Pointer<Uint8>, Size,
    Pointer<Int64>, Size,
    Uint32, Uint32,
    Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _FheEncryptDart = int Function(
    Pointer<Uint8>, int,
    Pointer<Int64>, int,
    int, int,
    Pointer<Pointer<Uint8>>, Pointer<Size>);

// int32_t fhe_decrypt(
//     const uint8_t *ck, size_t ck_len,
//     const uint8_t *ct, size_t ct_len,
//     uint32_t bit_width, uint32_t is_signed,
//     int64_t **out, size_t *out_len)
typedef _FheDecryptC = Int32 Function(
    Pointer<Uint8>, Size,
    Pointer<Uint8>, Size,
    Uint32, Uint32,
    Pointer<Pointer<Int64>>, Pointer<Size>);
typedef _FheDecryptDart = int Function(
    Pointer<Uint8>, int,
    Pointer<Uint8>, int,
    int, int,
    Pointer<Pointer<Int64>>, Pointer<Size>);

// void fhe_free_buf(uint8_t *ptr, size_t len)
typedef _FheFreeC    = Void Function(Pointer<Uint8>, Size);
typedef _FheFreeDart = void Function(Pointer<Uint8>, int);

// void fhe_free_i64_buf(int64_t *ptr, size_t len)
typedef _FheFreeI64C    = Void Function(Pointer<Int64>, Size);
typedef _FheFreeI64Dart = void Function(Pointer<Int64>, int);

// ── FheNative ─────────────────────────────────────────────────────────────────

class FheNative {
  late final _FheKeygenDart  _keygen;
  late final _FheEncryptDart _encrypt;
  late final _FheDecryptDart _decrypt;
  late final _FheFreeDart    _freeBuf;
  late final _FheFreeI64Dart _freeI64Buf;

  FheNative() {
    final lib = _loadLibrary();
    _keygen    = lib.lookupFunction<_FheKeygenC,  _FheKeygenDart> ('fhe_keygen');
    _encrypt   = lib.lookupFunction<_FheEncryptC, _FheEncryptDart>('fhe_encrypt');
    _decrypt   = lib.lookupFunction<_FheDecryptC, _FheDecryptDart>('fhe_decrypt');
    _freeBuf   = lib.lookupFunction<_FheFreeC,    _FheFreeDart>   ('fhe_free_buf');
    _freeI64Buf = lib.lookupFunction<_FheFreeI64C, _FheFreeI64Dart>('fhe_free_i64_buf');
  }

  static DynamicLibrary _loadLibrary() {
    if (Platform.isIOS) {
      return DynamicLibrary.process();
    } else if (Platform.isAndroid) {
      return DynamicLibrary.open('libfhe_client.so');
    } else if (Platform.isLinux) {
      return DynamicLibrary.open('libfhe_client.so');
    } else if (Platform.isMacOS) {
      return DynamicLibrary.open('libfhe_client.dylib');
    }
    throw UnsupportedError(
        'FHE native library not supported on ${Platform.operatingSystem}');
  }

  /// Generate keys using the given topology.
  ///
  /// [topology] is a packed Uint64List from KeyTopology.pack().
  KeygenResult keygen(Uint64List topology) {
    final topoPtr = malloc<Uint64>(topology.length);
    for (int i = 0; i < topology.length; i++) {
      topoPtr[i] = topology[i];
    }
    final ckPtrPtr = malloc<Pointer<Uint8>>();
    final ckLen    = malloc<Size>();
    final skPtrPtr = malloc<Pointer<Uint8>>();
    final skLen    = malloc<Size>();

    try {
      final rc = _keygen(
          topoPtr, topology.length,
          ckPtrPtr, ckLen, skPtrPtr, skLen);
      if (rc != 0) throw StateError('fhe_keygen failed (code $rc)');

      final ck = _readAndFree(ckPtrPtr.value, ckLen.value);
      final sk = _readAndFree(skPtrPtr.value, skLen.value);
      return KeygenResult(clientKey: ck, serverKey: sk);
    } finally {
      malloc.free(topoPtr);
      malloc.free(ckPtrPtr); malloc.free(ckLen);
      malloc.free(skPtrPtr); malloc.free(skLen);
    }
  }

  /// Encrypt [values] under [clientKey] using the specified TFHE-rs type.
  Uint8List encrypt(Uint8List clientKey, Int64List values,
                    int bitWidth, bool isSigned) {
    final ckPtr  = _toNativeUint8(clientKey);
    final valPtr = malloc<Int64>(values.length);
    for (int i = 0; i < values.length; i++) {
      valPtr[i] = values[i];
    }
    final ctPtrPtr = malloc<Pointer<Uint8>>();
    final ctLen    = malloc<Size>();

    try {
      final rc = _encrypt(
          ckPtr, clientKey.length,
          valPtr, values.length,
          bitWidth, isSigned ? 1 : 0,
          ctPtrPtr, ctLen);
      if (rc != 0) throw StateError('fhe_encrypt failed (code $rc)');
      return _readAndFree(ctPtrPtr.value, ctLen.value);
    } finally {
      malloc.free(ckPtr); malloc.free(valPtr);
      malloc.free(ctPtrPtr); malloc.free(ctLen);
    }
  }

  /// Decrypt [ciphertext] under [clientKey], returning i64 values.
  Int64List decrypt(Uint8List clientKey, Uint8List ciphertext,
                    int bitWidth, bool isSigned) {
    final ckPtr = _toNativeUint8(clientKey);
    final ctPtr = _toNativeUint8(ciphertext);
    final outPtrPtr = malloc<Pointer<Int64>>();
    final outLen    = malloc<Size>();

    try {
      final rc = _decrypt(
          ckPtr, clientKey.length,
          ctPtr, ciphertext.length,
          bitWidth, isSigned ? 1 : 0,
          outPtrPtr, outLen);
      if (rc != 0) throw StateError('fhe_decrypt failed (code $rc)');

      final len = outLen.value;
      final result = Int64List(len);
      for (int i = 0; i < len; i++) {
        result[i] = outPtrPtr.value[i];
      }
      _freeI64Buf(outPtrPtr.value, len);
      return result;
    } finally {
      malloc.free(ckPtr); malloc.free(ctPtr);
      malloc.free(outPtrPtr); malloc.free(outLen);
    }
  }

  Pointer<Uint8> _toNativeUint8(Uint8List data) {
    final ptr = malloc<Uint8>(data.length);
    for (int i = 0; i < data.length; i++) {
      ptr[i] = data[i];
    }
    return ptr;
  }

  Uint8List _readAndFree(Pointer<Uint8> ptr, int len) {
    final result = Uint8List.fromList(ptr.asTypedList(len));
    _freeBuf(ptr, len);
    return result;
  }
}

/// Result of [FheNative.keygen].
class KeygenResult {
  final Uint8List clientKey;
  final Uint8List serverKey;
  const KeygenResult({required this.clientKey, required this.serverKey});
}
