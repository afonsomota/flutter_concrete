/// Compression mode for LWE ciphertexts.
enum ConcreteCipherCompression { none, seed }

/// LWE encryption and encoding parameters parsed from client.specs.json.
///
/// One instance per circuit gate (input or output).
class ConcreteCipherInfo {
  final int lweDimension;
  final int keyId;
  final double variance;
  final ConcreteCipherCompression compression;
  final int encodingWidth;
  final bool encodingIsSigned;
  final bool isNativeMode;
  final List<int> concreteShape;
  final List<int> abstractShape;

  const ConcreteCipherInfo({
    required this.lweDimension,
    required this.keyId,
    required this.variance,
    required this.compression,
    required this.encodingWidth,
    required this.encodingIsSigned,
    required this.isNativeMode,
    required this.concreteShape,
    required this.abstractShape,
  });
}
