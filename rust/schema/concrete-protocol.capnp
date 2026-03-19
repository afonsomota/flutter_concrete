# Concrete Protocol
#
# The following document contains a programatic description of a communication protocol to store and
# exchange data with applications of the concrete framework.

@0xd2a64233258d00f1;

enum KeyType {
  binary @0;
  ternary @1;
}

struct Modulus {
  modulus :union {
    native @0 :NativeModulus;
    powerOfTwo @1 :PowerOfTwoModulus;
    integer @2 :IntegerModulus;
  }
}

struct NativeModulus{}

struct PowerOfTwoModulus{
  power @0 :UInt32;
}

struct IntegerModulus{
  modulus @0 :UInt32;
}

struct Shape{
  dimensions @0 :List(UInt32);
}

struct RawInfo{
  shape @0 :Shape;
  integerPrecision @1 :UInt32;
  isSigned @2 :Bool;
}

struct Payload{
  data @0 :List(Data);
}

enum Compression{
  none @0;
  seed @1;
  paillier @2;
}

struct LweSecretKeyParams {
  lweDimension @0 :UInt32;
  integerPrecision @1 :UInt32;
  keyType @2 :KeyType;
}

struct LweSecretKeyInfo {
  id @0 :UInt32;
  params @1 :LweSecretKeyParams;
}

struct LweSecretKey {
  info @0 :LweSecretKeyInfo;
  payload @1 :Payload;
}

struct LweBootstrapKeyParams {
  levelCount @0 :UInt32;
  baseLog @1 :UInt32;
  glweDimension @2 :UInt32;
  polynomialSize @3 :UInt32;
  inputLweDimension @8 :UInt32;
  variance @4 :Float64;
  integerPrecision @5 :UInt32;
  modulus @6 :Modulus;
  keyType @7 :KeyType;
}

struct LweBootstrapKeyInfo {
  id @0 :UInt32;
  inputId @1 :UInt32;
  outputId @2 :UInt32;
  params @3 :LweBootstrapKeyParams;
  compression @4 :Compression;
}

struct LweBootstrapKey {
  info @0 :LweBootstrapKeyInfo;
  payload @1 :Payload;
}

struct LweKeyswitchKeyParams {
  levelCount @0 :UInt32;
  baseLog @1 :UInt32;
  variance @2 :Float64;
  integerPrecision @3 :UInt32;
  inputLweDimension @6 :UInt32;
  outputLweDimension @7 :UInt32;
  modulus @4 :Modulus;
  keyType @5 :KeyType;
}

struct LweKeyswitchKeyInfo {
  id @0 :UInt32;
  inputId @1 :UInt32;
  outputId @2 :UInt32;
  params @3 :LweKeyswitchKeyParams;
  compression @4 :Compression;
}

struct LweKeyswitchKey {
  info @0 :LweKeyswitchKeyInfo;
  payload @1 :Payload;
}

struct PackingKeyswitchKeyParams {
  levelCount @0 :UInt32;
  baseLog @1 :UInt32;
  glweDimension @2 :UInt32;
  polynomialSize @3 :UInt32;
  inputLweDimension @4 :UInt32;
  innerLweDimension @5 :UInt32;
  variance @6 :Float64;
  integerPrecision @7 :UInt32;
  modulus @8 :Modulus;
  keyType @9 :KeyType;
}

struct PackingKeyswitchKeyInfo {
  id @0 :UInt32;
  inputId @1 :UInt32;
  outputId @2 :UInt32;
  params @3 :PackingKeyswitchKeyParams;
  compression @4 :Compression;
}

struct PackingKeyswitchKey {
  info @0 :PackingKeyswitchKeyInfo;
  payload @1 :Payload;
}

struct KeysetInfo {
  lweSecretKeys @0 :List(LweSecretKeyInfo);
  lweBootstrapKeys @1 :List(LweBootstrapKeyInfo);
  lweKeyswitchKeys @2 :List(LweKeyswitchKeyInfo);
  packingKeyswitchKeys @3 :List(PackingKeyswitchKeyInfo);
}

struct ServerKeyset {
  lweBootstrapKeys @0 :List(LweBootstrapKey);
  lweKeyswitchKeys @1 :List(LweKeyswitchKey);
  packingKeyswitchKeys @2 :List(PackingKeyswitchKey);
}

struct ClientKeyset {
  lweSecretKeys @0 :List(LweSecretKey);
}

struct Keyset {
  server @0 :ServerKeyset;
  client @1 :ClientKeyset;
}

# ── Ciphertext transport types ──────────────────────────────────────────────

struct Value {
  payload @0 :Payload;
  rawInfo @1 :RawInfo;
  typeInfo @2 :TypeInfo;
}

struct TypeInfo {
  union {
    lweCiphertext @0 :LweCiphertextTypeInfo;
    plaintext @1 :PlaintextTypeInfo;
    index @2 :IndexTypeInfo;
  }
}

struct PlaintextTypeInfo {}
struct IndexTypeInfo {}

struct LweCiphertextTypeInfo {
  abstractShape @0 :Shape;
  concreteShape @1 :Shape;
  integerPrecision @2 :UInt32;
  encryption @3 :LweCiphertextEncryptionInfo;
  compression @4 :Compression;
  encoding :union {
    integer @5 :IntegerCiphertextEncodingInfo;
    boolean @6 :BooleanCiphertextEncodingInfo;
  }
}

struct LweCiphertextEncryptionInfo {
  keyId @0 :UInt32;
  variance @1 :Float64;
  lweDimension @2 :UInt32;
  modulus @3 :Modulus;
}

struct IntegerCiphertextEncodingInfo {
  width @0 :UInt32;
  isSigned @1 :Bool;
  mode :union {
    native @2 :NativeMode;
    chunked @3 :ChunkedMode;
    crt @4 :CrtMode;
  }
}

struct NativeMode {}
struct ChunkedMode {
  size @0 :UInt32;
  width @1 :UInt32;
}
struct CrtMode {
  moduli @0 :List(UInt32);
}

struct BooleanCiphertextEncodingInfo {}
