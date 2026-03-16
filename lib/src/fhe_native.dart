// lib/src/fhe_native.dart
//
// Dart FFI bindings for libfhe_client — the native Rust TFHE-rs client.
//
// Key compatibility:
//   • Key generation matches concrete-ml-extensions keygen_radix()
//   • Encryption matches encrypt_serialize_u8_radix_2d()
//   • Decryption matches decrypt_serialized_i8_radix_2d()

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// ── C function signatures ─────────────────────────────────────────────────────

// int32_t fhe_keygen(
//     uint8_t **ck_out, size_t *ck_len,
//     uint8_t **sk_out, size_t *sk_len,
//     uint8_t **lwe_out, size_t *lwe_len)
typedef _FheKeygenC = Int32 Function(
    Pointer<Pointer<Uint8>>, Pointer<Size>,
    Pointer<Pointer<Uint8>>, Pointer<Size>,
    Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _FheKeygenDart = int Function(
    Pointer<Pointer<Uint8>>, Pointer<Size>,
    Pointer<Pointer<Uint8>>, Pointer<Size>,
    Pointer<Pointer<Uint8>>, Pointer<Size>);

// int32_t fhe_encrypt_u8(
//     const uint8_t *ck, size_t ck_len,
//     const uint8_t *vals, size_t n_vals,
//     uint8_t **ct_out, size_t *ct_len)
typedef _FheEncryptU8C = Int32 Function(
    Pointer<Uint8>, Size, Pointer<Uint8>, Size,
    Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _FheEncryptU8Dart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<Pointer<Uint8>>, Pointer<Size>);

// int32_t fhe_decrypt_i8(
//     const uint8_t *ck, size_t ck_len,
//     const uint8_t *ct, size_t ct_len,
//     int8_t **out, size_t *out_len)
typedef _FheDecryptI8C = Int32 Function(
    Pointer<Uint8>, Size, Pointer<Uint8>, Size,
    Pointer<Pointer<Int8>>, Pointer<Size>);
typedef _FheDecryptI8Dart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<Pointer<Int8>>, Pointer<Size>);

// void fhe_free_buf(uint8_t *ptr, size_t len)
typedef _FheFreeC    = Void Function(Pointer<Uint8>, Size);
typedef _FheFreeDart = void Function(Pointer<Uint8>, int);

// void fhe_free_i8_buf(int8_t *ptr, size_t len)
typedef _FheFreeI8C    = Void Function(Pointer<Int8>, Size);
typedef _FheFreeI8Dart = void Function(Pointer<Int8>, int);

// ── FheNative ─────────────────────────────────────────────────────────────────

/// Low-level Dart FFI bindings for the native Rust FHE client.
///
/// Prefer using [ConcreteClient] which adds quantization and a simpler API.
class FheNative {
  late final _FheKeygenDart   _keygen;
  late final _FheEncryptU8Dart _encryptU8;
  late final _FheDecryptI8Dart _decryptI8;
  late final _FheFreeDart      _freeBuf;
  late final _FheFreeI8Dart    _freeI8Buf;

  FheNative() {
    final lib = _loadLibrary();
    _keygen    = lib.lookupFunction<_FheKeygenC,    _FheKeygenDart>   ('fhe_keygen');
    _encryptU8 = lib.lookupFunction<_FheEncryptU8C, _FheEncryptU8Dart>('fhe_encrypt_u8');
    _decryptI8 = lib.lookupFunction<_FheDecryptI8C, _FheDecryptI8Dart>('fhe_decrypt_i8');
    _freeBuf   = lib.lookupFunction<_FheFreeC,      _FheFreeDart>     ('fhe_free_buf');
    _freeI8Buf = lib.lookupFunction<_FheFreeI8C,    _FheFreeI8Dart>   ('fhe_free_i8_buf');
  }

  static DynamicLibrary _loadLibrary() {
    if (Platform.isIOS) {
      // Static library linked into the app binary via Cargokit.
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

  // ── Key generation ──────────────────────────────────────────────────────────

  /// Generate a fresh TFHE-rs keypair.
  ///
  /// Returns a [KeygenResult] with three serialised byte arrays:
  ///   • [KeygenResult.clientKey] — keep secret on-device (never uploaded)
  ///   • [KeygenResult.serverKey] — evaluation key, upload via `POST /fhe/key`
  ///   • [KeygenResult.lweKey]    — unused; retained for ABI stability
  ///
  /// This is a CPU-intensive operation (can take 10–60 s on mobile).
  KeygenResult keygen() {
    final ckPtrPtr  = malloc<Pointer<Uint8>>();
    final ckLen     = malloc<Size>();
    final skPtrPtr  = malloc<Pointer<Uint8>>();
    final skLen     = malloc<Size>();
    final lwePtrPtr = malloc<Pointer<Uint8>>();
    final lweLen    = malloc<Size>();

    try {
      final rc = _keygen(ckPtrPtr, ckLen, skPtrPtr, skLen, lwePtrPtr, lweLen);
      if (rc != 0) throw StateError('fhe_keygen failed (code $rc)');

      final ck  = _readAndFree(ckPtrPtr.value,  ckLen.value);
      final sk  = _readAndFree(skPtrPtr.value,  skLen.value);
      final lwe = _readAndFree(lwePtrPtr.value, lweLen.value);
      return KeygenResult(clientKey: ck, serverKey: sk, lweKey: lwe);
    } finally {
      malloc.free(ckPtrPtr);  malloc.free(ckLen);
      malloc.free(skPtrPtr);  malloc.free(skLen);
      malloc.free(lwePtrPtr); malloc.free(lweLen);
    }
  }

  // ── Encryption ──────────────────────────────────────────────────────────────

  /// Encrypt [quantizedValues] (uint8, one per feature dimension) under [clientKey].
  ///
  /// Returns a bincode-serialised `Vec<FheUint8>` compatible with
  /// concrete-ml-extensions `encrypt_serialize_u8_radix_2d`.
  Uint8List encryptU8(Uint8List clientKey, Uint8List quantizedValues) {
    final ckPtr  = _toNativeUint8(clientKey);
    final valPtr = _toNativeUint8(quantizedValues);
    final ctPtrPtr = malloc<Pointer<Uint8>>();
    final ctLen    = malloc<Size>();

    try {
      final rc = _encryptU8(
          ckPtr, clientKey.length,
          valPtr, quantizedValues.length,
          ctPtrPtr, ctLen);
      if (rc != 0) throw StateError('fhe_encrypt_u8 failed (code $rc)');
      return _readAndFree(ctPtrPtr.value, ctLen.value);
    } finally {
      malloc.free(ckPtr);    malloc.free(valPtr);
      malloc.free(ctPtrPtr); malloc.free(ctLen);
    }
  }

  // ── Decryption ──────────────────────────────────────────────────────────────

  /// Decrypt [ciphertext] (bincode `Vec<FheInt8>`) under [clientKey].
  ///
  /// Returns raw signed int8 class scores.  Apply the output quantizer
  /// (scale / zero_point from quantization_params.json) to get float scores.
  Int8List decryptI8(Uint8List clientKey, Uint8List ciphertext) {
    final ckPtr  = _toNativeUint8(clientKey);
    final ctPtr  = _toNativeUint8(ciphertext);
    final outPtrPtr = malloc<Pointer<Int8>>();
    final outLen    = malloc<Size>();

    try {
      final rc = _decryptI8(
          ckPtr, clientKey.length,
          ctPtr, ciphertext.length,
          outPtrPtr, outLen);
      if (rc != 0) throw StateError('fhe_decrypt_i8 failed (code $rc)');

      // Copy i8 data out before freeing
      final len = outLen.value;
      final result = Int8List(len);
      for (int i = 0; i < len; i++) {
        result[i] = outPtrPtr.value[i];
      }
      _freeI8Buf(outPtrPtr.value, len);
      return result;
    } finally {
      malloc.free(ckPtr);     malloc.free(ctPtr);
      malloc.free(outPtrPtr); malloc.free(outLen);
    }
  }

  // ── Helpers ─────────────────────────────────────────────────────────────────

  Pointer<Uint8> _toNativeUint8(Uint8List data) {
    final ptr = malloc<Uint8>(data.length);
    for (int i = 0; i < data.length; i++) {
      ptr[i] = data[i];
    }
    return ptr;
  }

  /// Copy bytes from [ptr]/[len] into a [Uint8List] then free the native buf.
  Uint8List _readAndFree(Pointer<Uint8> ptr, int len) {
    final result = Uint8List.fromList(ptr.asTypedList(len));
    _freeBuf(ptr, len);
    return result;
  }
}

// ── Value types ───────────────────────────────────────────────────────────────

/// Result of [FheNative.keygen].
class KeygenResult {
  final Uint8List clientKey;
  final Uint8List serverKey;
  final Uint8List lweKey;

  const KeygenResult({
    required this.clientKey,
    required this.serverKey,
    required this.lweKey,
  });
}
