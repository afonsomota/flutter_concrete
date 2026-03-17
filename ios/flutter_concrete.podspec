Pod::Spec.new do |s|
  s.name             = 'flutter_concrete'
  s.version          = '0.0.1'
  s.summary          = 'Concrete ML FHE client for Flutter (TFHE-rs via Cargokit)'
  s.description      = 'Flutter FFI plugin wrapping TFHE-rs for Concrete ML FHE operations.'
  s.homepage         = 'https://github.com/afonsomota/flutter_concrete'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Afonso Oliveira' => 'af.oliveira.16@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'

  s.script_phase = {
    :name => 'Build Rust library',
    :script => 'sh "$PODS_TARGET_SRCROOT/../cargokit/build_pod.sh" ../rust fhe_client',
    :execution_position => :before_compile,
    :input_files => ['${BUILT_PRODUCTS_DIR}/cargokit_phony'],
    :output_files => ["${BUILT_PRODUCTS_DIR}/libfhe_client.a"],
  }
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
    'OTHER_LDFLAGS' => '-force_load ${BUILT_PRODUCTS_DIR}/libfhe_client.a',
  }
end
