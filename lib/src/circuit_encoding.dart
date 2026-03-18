/// Round an encoding bit width to the next supported TFHE-rs integer size.
///
/// Supported: 8, 16, 32, 64. Throws [ArgumentError] if [width] is <= 0 or > 64.
int roundUpBitWidth(int width) {
  if (width <= 0 || width > 64) {
    throw ArgumentError.value(width, 'width', 'must be 1–64');
  }
  if (width <= 8) return 8;
  if (width <= 16) return 16;
  if (width <= 32) return 32;
  return 64;
}

/// I/O encoding widths parsed from client.specs.json circuits section.
///
/// [inputWidth]/[outputWidth] are the raw encoding widths from the spec.
/// Use [tfheInputBitWidth]/[tfheOutputBitWidth] for TFHE-rs type selection.
class CircuitEncoding {
  final int inputWidth;
  final bool inputIsSigned;
  final int outputWidth;
  final bool outputIsSigned;

  const CircuitEncoding({
    required this.inputWidth,
    required this.inputIsSigned,
    required this.outputWidth,
    required this.outputIsSigned,
  });

  /// Input width rounded up to a supported TFHE-rs integer size.
  int get tfheInputBitWidth => roundUpBitWidth(inputWidth);

  /// Output width rounded up to a supported TFHE-rs integer size.
  int get tfheOutputBitWidth => roundUpBitWidth(outputWidth);
}
