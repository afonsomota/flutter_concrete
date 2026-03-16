// journal_app/rust/src/lib.rs
//
// Native TFHE-rs FHE client — C FFI layer for Dart.
//
// Serialisation compatibility:
//   • Key generation matches concrete-ml-extensions (cml-ext 0.2.0) keygen_radix()
//   • Encryption matches cml-ext encrypt_serialize_u8_radix_2d()
//   • Decryption matches cml-ext decrypt_serialized_i8_radix_2d()
//   • Parameter set: V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64
//
// Exported C functions (return 0 on success, negative code on failure):
//   fhe_keygen(ck_out, ck_len, sk_out, sk_len, lwe_out, lwe_len) → i32
//   fhe_encrypt_u8(ck, ck_len, vals, n, ct_out, ct_len) → i32
//   fhe_decrypt_i8(ck, ck_len, ct, ct_len, out, out_len) → i32
//   fhe_free_buf(ptr, len)
//   fhe_free_i8_buf(ptr, len)

use std::io::Cursor;
use std::panic;
use std::slice;

use capnp::message::Builder;
use capnp::serialize;

use tfhe::core_crypto::algorithms::{
    allocate_and_generate_new_binary_glwe_secret_key,
    allocate_and_generate_new_binary_lwe_secret_key,
    generate_seeded_lwe_bootstrap_key, generate_seeded_lwe_keyswitch_key,
};
use tfhe::core_crypto::commons::generators::SecretRandomGenerator;
use tfhe::core_crypto::commons::dispersion::StandardDev;
use tfhe::core_crypto::commons::math::random::{DefaultRandomGenerator, Gaussian};
use tfhe::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize,
    LweDimension, PolynomialSize,
};
use tfhe::core_crypto::entities::{SeededLweBootstrapKey, SeededLweKeyswitchKey};
use tfhe::core_crypto::seeders::new_seeder;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::shortint::parameters::v0_10::classic::gaussian::p_fail_2_minus_64::ks_pbs::V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
use tfhe::{ClientKey, ConfigBuilder, FheInt8, FheUint8};

// ── Generated Cap'n Proto bindings ────────────────────────────────────────────
pub mod concrete_protocol_capnp {
    #![allow(dead_code, unused_imports, clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/concrete_protocol_capnp.rs"));
}

// ── Serialisation limit ───────────────────────────────────────────────────────
const LIMIT: u64 = 1_000_000_000;


// ── Concrete eval key generation ──────────────────────────────────────────────
//
// Generates a Concrete-compatible Cap'n Proto ServerKeyset matching the circuit
// compiled in journal_app/assets/fhe/client.zip (client.specs.json).
//
// The circuit uses a multi-parameter scheme with 4 GLWE key families, 4 small
// LWE keys, 4 BSKs and 8 KSKs.  SK[0] (dim=2048) is the big LWE key derived
// from the TFHE-rs ClientKey's GLWE key — this is also the ciphertext key used
// by FheUint8::encrypt / FheInt8::decrypt.
//
// Key identity (from client.specs.json lweSecretKeys):
//   SK[0] dim=2048 = glwe_sk0.into_lwe_secret_key()   (TFHE-rs root)
//   SK[1] dim=796  = fresh small LWE key
//   SK[2] dim=2048 = glwe_sk1.into_lwe_secret_key()   (GLWE dim=4, poly=512)
//   SK[3] dim=617  = fresh small LWE key
//   SK[4] dim=1536 = glwe_sk2.into_lwe_secret_key()   (GLWE dim=6, poly=256)
//   SK[5] dim=742  = fresh small LWE key
//   SK[6] dim=2048 = glwe_sk3.into_lwe_secret_key()   (GLWE dim=2, poly=1024)
//   SK[7] dim=769  = fresh small LWE key
fn generate_concrete_eval_keys(ck: &ClientKey) -> Result<Vec<u8>, String> {
    // ── Extract root GLWE key from TFHE-rs ClientKey ──────────────────────────
    let (integer_ck, _, _, _) = ck.clone().into_raw_parts();
    let shortint_ck = integer_ck.into_raw_parts();
    let (glwe_sk0, _tfhe_lwe_sk, _params) = shortint_ck.into_raw_parts();
    // glwe_sk0: dim=1, poly=2048 → SK[0] big LWE = dim 1×2048 = 2048
    let sk0 = glwe_sk0.clone().into_lwe_secret_key(); // dim=2048

    // ── Set up CSPRNGs ────────────────────────────────────────────────────────
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut sec_gen = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // ── Generate additional GLWE keys ─────────────────────────────────────────
    let glwe_sk1: tfhe::core_crypto::entities::GlweSecretKeyOwned<u64> =
        allocate_and_generate_new_binary_glwe_secret_key(
            GlweDimension(4), PolynomialSize(512), &mut sec_gen,
        ); // → SK[2] dim=4×512=2048
    let glwe_sk2: tfhe::core_crypto::entities::GlweSecretKeyOwned<u64> =
        allocate_and_generate_new_binary_glwe_secret_key(
            GlweDimension(6), PolynomialSize(256), &mut sec_gen,
        ); // → SK[4] dim=6×256=1536
    let glwe_sk3: tfhe::core_crypto::entities::GlweSecretKeyOwned<u64> =
        allocate_and_generate_new_binary_glwe_secret_key(
            GlweDimension(2), PolynomialSize(1024), &mut sec_gen,
        ); // → SK[6] dim=2×1024=2048

    let sk2 = glwe_sk1.clone().into_lwe_secret_key(); // dim=2048
    let sk4 = glwe_sk2.clone().into_lwe_secret_key(); // dim=1536
    let sk6 = glwe_sk3.clone().into_lwe_secret_key(); // dim=2048

    // ── Generate small LWE keys ───────────────────────────────────────────────
    let sk1: tfhe::core_crypto::entities::LweSecretKeyOwned<u64> =
        allocate_and_generate_new_binary_lwe_secret_key(LweDimension(796), &mut sec_gen);
    let sk3: tfhe::core_crypto::entities::LweSecretKeyOwned<u64> =
        allocate_and_generate_new_binary_lwe_secret_key(LweDimension(617), &mut sec_gen);
    let sk5: tfhe::core_crypto::entities::LweSecretKeyOwned<u64> =
        allocate_and_generate_new_binary_lwe_secret_key(LweDimension(742), &mut sec_gen);
    let sk7: tfhe::core_crypto::entities::LweSecretKeyOwned<u64> =
        allocate_and_generate_new_binary_lwe_secret_key(LweDimension(769), &mut sec_gen);

    // ── Noise helpers (variance from client.specs.json; stddev = sqrt(var)) ───
    let noise = |var: f64| Gaussian::from_dispersion_parameter(StandardDev(var.sqrt()), 0.0);

    // ── Generate 4 seeded BSKs ────────────────────────────────────────────────
    // Seeded BSKs store only body polynomials + a single compression seed.
    // Concrete's C++ only supports Compression::Seed for BSK computation.

    // BSK[0]: SK[1](796) encrypted under GLWE[0](dim=1, poly=2048), level=2, baseLog=15
    let mut bsk0 = SeededLweBootstrapKey::new(
        0u64, GlweSize(2), PolynomialSize(2048),
        DecompositionBaseLog(15), DecompositionLevelCount(2),
        LweDimension(796), seeder.seed().into(),
        CiphertextModulus::new_native(),
    );
    generate_seeded_lwe_bootstrap_key(&sk1, &glwe_sk0, &mut bsk0, noise(8.095547030480235e-30), seeder);

    // BSK[1]: SK[3](617) encrypted under GLWE[1](dim=4, poly=512), level=2, baseLog=16
    let mut bsk1 = SeededLweBootstrapKey::new(
        0u64, GlweSize(5), PolynomialSize(512),
        DecompositionBaseLog(16), DecompositionLevelCount(2),
        LweDimension(617), seeder.seed().into(),
        CiphertextModulus::new_native(),
    );
    generate_seeded_lwe_bootstrap_key(&sk3, &glwe_sk1, &mut bsk1, noise(8.095547030480235e-30), seeder);

    // BSK[2]: SK[5](742) encrypted under GLWE[2](dim=6, poly=256), level=1, baseLog=17
    let mut bsk2 = SeededLweBootstrapKey::new(
        0u64, GlweSize(7), PolynomialSize(256),
        DecompositionBaseLog(17), DecompositionLevelCount(1),
        LweDimension(742), seeder.seed().into(),
        CiphertextModulus::new_native(),
    );
    generate_seeded_lwe_bootstrap_key(&sk5, &glwe_sk2, &mut bsk2, noise(3.8120190856802e-22), seeder);

    // BSK[3]: SK[7](769) encrypted under GLWE[3](dim=2, poly=1024), level=2, baseLog=15
    let mut bsk3 = SeededLweBootstrapKey::new(
        0u64, GlweSize(3), PolynomialSize(1024),
        DecompositionBaseLog(15), DecompositionLevelCount(2),
        LweDimension(769), seeder.seed().into(),
        CiphertextModulus::new_native(),
    );
    generate_seeded_lwe_bootstrap_key(&sk7, &glwe_sk3, &mut bsk3, noise(8.095547030480235e-30), seeder);

    // ── Generate 8 seeded KSKs ────────────────────────────────────────────────
    // KSK[0]: SK[0](2048) → SK[1](796), level=5, baseLog=3
    let mut ksk0 = SeededLweKeyswitchKey::new(
        0u64, DecompositionBaseLog(3), DecompositionLevelCount(5),
        LweDimension(2048), LweDimension(796), seeder.seed().into(),
        CiphertextModulus::new_native());
    generate_seeded_lwe_keyswitch_key(&sk0, &sk1, &mut ksk0, noise(4.6871210061173175e-11), seeder);

    // KSK[1]: SK[0](2048) → SK[2](2048), level=1, baseLog=24
    let mut ksk1 = SeededLweKeyswitchKey::new(
        0u64, DecompositionBaseLog(24), DecompositionLevelCount(1),
        LweDimension(2048), LweDimension(2048), seeder.seed().into(),
        CiphertextModulus::new_native());
    generate_seeded_lwe_keyswitch_key(&sk0, &sk2, &mut ksk1, noise(8.095547030480235e-30), seeder);

    // KSK[2]: SK[2](2048) → SK[3](617), level=3, baseLog=3
    let mut ksk2 = SeededLweKeyswitchKey::new(
        0u64, DecompositionBaseLog(3), DecompositionLevelCount(3),
        LweDimension(2048), LweDimension(617), seeder.seed().into(),
        CiphertextModulus::new_native());
    generate_seeded_lwe_keyswitch_key(&sk2, &sk3, &mut ksk2, noise(2.256456885316473e-08), seeder);

    // KSK[3]: SK[2](2048) → SK[5](742), level=2, baseLog=5
    let mut ksk3 = SeededLweKeyswitchKey::new(
        0u64, DecompositionBaseLog(5), DecompositionLevelCount(2),
        LweDimension(2048), LweDimension(742), seeder.seed().into(),
        CiphertextModulus::new_native());
    generate_seeded_lwe_keyswitch_key(&sk2, &sk5, &mut ksk3, noise(3.0210525031143964e-10), seeder);

    // KSK[4]: SK[4](1536) → SK[7](769), level=5, baseLog=3
    let mut ksk4 = SeededLweKeyswitchKey::new(
        0u64, DecompositionBaseLog(3), DecompositionLevelCount(5),
        LweDimension(1536), LweDimension(769), seeder.seed().into(),
        CiphertextModulus::new_native());
    generate_seeded_lwe_keyswitch_key(&sk4, &sk7, &mut ksk4, noise(1.1899596063703503e-10), seeder);

    // KSK[5]: SK[6](2048) → SK[0](2048), level=2, baseLog=16
    let mut ksk5 = SeededLweKeyswitchKey::new(
        0u64, DecompositionBaseLog(16), DecompositionLevelCount(2),
        LweDimension(2048), LweDimension(2048), seeder.seed().into(),
        CiphertextModulus::new_native());
    generate_seeded_lwe_keyswitch_key(&sk6, &sk0, &mut ksk5, noise(8.095547030480235e-30), seeder);

    // KSK[6]: SK[0](2048) → SK[3](617), level=3, baseLog=3
    let mut ksk6 = SeededLweKeyswitchKey::new(
        0u64, DecompositionBaseLog(3), DecompositionLevelCount(3),
        LweDimension(2048), LweDimension(617), seeder.seed().into(),
        CiphertextModulus::new_native());
    generate_seeded_lwe_keyswitch_key(&sk0, &sk3, &mut ksk6, noise(2.256456885316473e-08), seeder);

    // KSK[7]: SK[2](2048) → SK[0](2048), level=1, baseLog=24
    let mut ksk7 = SeededLweKeyswitchKey::new(
        0u64, DecompositionBaseLog(24), DecompositionLevelCount(1),
        LweDimension(2048), LweDimension(2048), seeder.seed().into(),
        CiphertextModulus::new_native());
    generate_seeded_lwe_keyswitch_key(&sk2, &sk0, &mut ksk7, noise(8.095547030480235e-30), seeder);

    // ── Build Cap'n Proto ServerKeyset ────────────────────────────────────────
    let mut message = Builder::new_default();
    {
        use concrete_protocol_capnp::server_keyset;
        let mut keyset = message.init_root::<server_keyset::Builder<'_>>();

        // ── 4 BSKs ────────────────────────────────────────────────────────────
        let mut bsks = keyset.reborrow().init_lwe_bootstrap_keys(4);

        // Helper: serialize seeded BSK as [seed_bytes (16) || body_u64_bytes]
        macro_rules! seeded_bsk_bytes {
            ($key:expr) => {{
                let seed_bytes: [u8; 16] = $key.compression_seed().seed.0.to_le_bytes();
                let body_bytes = bytemuck::cast_slice::<u64, u8>($key.as_ref());
                let mut v = Vec::with_capacity(16 + body_bytes.len());
                v.extend_from_slice(&seed_bytes);
                v.extend_from_slice(body_bytes);
                v
            }};
        }

        macro_rules! set_bsk {
            ($list:expr, $idx:expr, $id:expr, $in_id:expr, $out_id:expr,
             $level:expr, $base:expr, $glwe_dim:expr, $poly:expr, $in_lwe:expr,
             $var:expr, $data:expr) => {{
                let mut m = $list.reborrow().get($idx);
                {
                    let mut info = m.reborrow().init_info();
                    info.set_id($id);
                    info.set_input_id($in_id);
                    info.set_output_id($out_id);
                    info.set_compression(concrete_protocol_capnp::Compression::Seed);
                    let mut p = info.init_params();
                    p.set_level_count($level);
                    p.set_base_log($base);
                    p.set_glwe_dimension($glwe_dim);
                    p.set_polynomial_size($poly);
                    p.set_input_lwe_dimension($in_lwe);
                    p.set_variance($var);
                    p.set_integer_precision(64);
                    p.set_key_type(concrete_protocol_capnp::KeyType::Binary);
                    p.init_modulus().reborrow().get_modulus().init_native();
                }
                let bytes = seeded_bsk_bytes!($data);
                write_payload_chunks(&mut m.init_payload(), &bytes);
            }};
        }

        set_bsk!(bsks, 0, 0, 1, 0, 2, 15, 1, 2048, 796, 8.095547030480235e-30, bsk0);
        set_bsk!(bsks, 1, 1, 3, 2, 2, 16, 4, 512,  617, 8.095547030480235e-30, bsk1);
        set_bsk!(bsks, 2, 2, 5, 4, 1, 17, 6, 256,  742, 3.8120190856802e-22,   bsk2);
        set_bsk!(bsks, 3, 3, 7, 6, 2, 15, 2, 1024, 769, 8.095547030480235e-30, bsk3);

        // ── 8 KSKs ────────────────────────────────────────────────────────────
        let mut ksks = keyset.reborrow().init_lwe_keyswitch_keys(8);

        macro_rules! seeded_ksk_bytes {
            ($key:expr) => {{
                let seed_bytes: [u8; 16] = $key.compression_seed().seed.0.to_le_bytes();
                let body_bytes = bytemuck::cast_slice::<u64, u8>($key.as_ref());
                let mut v = Vec::with_capacity(16 + body_bytes.len());
                v.extend_from_slice(&seed_bytes);
                v.extend_from_slice(body_bytes);
                v
            }};
        }

        macro_rules! set_ksk {
            ($list:expr, $idx:expr, $id:expr, $in_id:expr, $out_id:expr,
             $level:expr, $base:expr, $in_dim:expr, $out_dim:expr,
             $var:expr, $data:expr) => {{
                let mut m = $list.reborrow().get($idx);
                {
                    let mut info = m.reborrow().init_info();
                    info.set_id($id);
                    info.set_input_id($in_id);
                    info.set_output_id($out_id);
                    info.set_compression(concrete_protocol_capnp::Compression::Seed);
                    let mut p = info.init_params();
                    p.set_level_count($level);
                    p.set_base_log($base);
                    p.set_input_lwe_dimension($in_dim);
                    p.set_output_lwe_dimension($out_dim);
                    p.set_variance($var);
                    p.set_integer_precision(64);
                    p.set_key_type(concrete_protocol_capnp::KeyType::Binary);
                    p.init_modulus().reborrow().get_modulus().init_native();
                }
                let bytes = seeded_ksk_bytes!($data);
                write_payload_chunks(&mut m.init_payload(), &bytes);
            }};
        }

        set_ksk!(ksks, 0, 0, 0, 1, 5, 3,  2048, 796,  4.6871210061173175e-11,  ksk0);
        set_ksk!(ksks, 1, 1, 0, 2, 1, 24, 2048, 2048, 8.095547030480235e-30,   ksk1);
        set_ksk!(ksks, 2, 2, 2, 3, 3, 3,  2048, 617,  2.256456885316473e-08,   ksk2);
        set_ksk!(ksks, 3, 3, 2, 5, 2, 5,  2048, 742,  3.0210525031143964e-10,  ksk3);
        set_ksk!(ksks, 4, 4, 4, 7, 5, 3,  1536, 769,  1.1899596063703503e-10,  ksk4);
        set_ksk!(ksks, 5, 5, 6, 0, 2, 16, 2048, 2048, 8.095547030480235e-30,   ksk5);
        set_ksk!(ksks, 6, 6, 0, 3, 3, 3,  2048, 617,  2.256456885316473e-08,   ksk6);
        set_ksk!(ksks, 7, 7, 2, 0, 1, 24, 2048, 2048, 8.095547030480235e-30,   ksk7);

        keyset.init_packing_keyswitch_keys(0);
    }

    let mut buf: Vec<u8> = Vec::new();
    serialize::write_message(&mut buf, &message).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Write a byte slice into a Cap'n Proto Payload as a single Data entry.
///
/// Concrete's C++ `protoPayloadToSharedVector` reads the first (and only) Data
/// entry in the Payload.  Do not split into multiple entries.
fn write_payload_chunks(
    payload: &mut concrete_protocol_capnp::payload::Builder<'_>,
    data: &[u8],
) {
    let mut list = payload.reborrow().init_data(1);
    list.set(0, data);
}

// ── FFI helpers ───────────────────────────────────────────────────────────────

/// Leak a Vec<u8> into a raw pointer/length pair that Dart will free later.
fn leak_buf(v: Vec<u8>) -> (*mut u8, usize) {
    let len = v.len();
    let ptr = Box::into_raw(v.into_boxed_slice()) as *mut u8;
    (ptr, len)
}

// ── Exported C symbols ────────────────────────────────────────────────────────

/// Generate a fresh TFHE-rs keypair.
///
/// Outputs three buffers (all freed with `fhe_free_buf`):
///   - `client_key_*` — private; store encrypted on-device
///   - `server_key_*` — concrete Cap'n Proto ServerKeyset; upload to `POST /fhe/key`
///   - `lwe_key_*`    — empty; retained for ABI stability only
///
/// # Safety
/// All six pointer-to-pointer arguments must not be null.
#[no_mangle]
pub unsafe extern "C" fn fhe_keygen(
    client_key_out: *mut *mut u8, client_key_len: *mut usize,
    server_key_out: *mut *mut u8, server_key_len: *mut usize,
    lwe_key_out:    *mut *mut u8, lwe_key_len:    *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let config = ConfigBuilder::default()
            .use_custom_parameters(V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            .build();
        let (client_key, _server_key) = tfhe::generate_keys(config);

        // Serialise client key (private, stays on device)
        let mut ck_buf = Vec::new();
        safe_serialize(&client_key, &mut ck_buf, LIMIT).map_err(|e| e.to_string())?;

        // Generate Concrete-compatible Cap'n Proto ServerKeyset (for upload to backend)
        let sk_buf = generate_concrete_eval_keys(&client_key)?;

        // lwe_key: empty — ABI slot retained for backwards compatibility
        let lwe_buf: Vec<u8> = Vec::new();

        let (ck_ptr, ck_len)   = leak_buf(ck_buf);
        let (sk_ptr, sk_len)   = leak_buf(sk_buf);
        let (lwe_ptr, lwe_len) = leak_buf(lwe_buf);

        *client_key_out = ck_ptr;  *client_key_len = ck_len;
        *server_key_out = sk_ptr;  *server_key_len = sk_len;
        *lwe_key_out    = lwe_ptr; *lwe_key_len    = lwe_len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}

/// Encrypt `n_vals` uint8 values (quantized inputs) with the client key.
///
/// Output is a bincode-serialised `Vec<FheUint8>` compatible with
/// `concrete-ml-extensions::encrypt_serialize_u8_radix_2d()`.
/// Send the output bytes to `POST /fhe/predict`.
///
/// # Safety
/// `client_key`, `values` must point to valid buffers of the given lengths.
/// Free the output with `fhe_free_buf`.
#[no_mangle]
pub unsafe extern "C" fn fhe_encrypt_u8(
    client_key:     *const u8, client_key_len: usize,
    values:         *const u8, n_vals:         usize,
    ct_out:         *mut *mut u8, ct_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let ck_bytes = slice::from_raw_parts(client_key, client_key_len);
        let vals     = slice::from_raw_parts(values, n_vals);

        let ck: ClientKey = safe_deserialize(Cursor::new(ck_bytes), LIMIT)
            .map_err(|e| e.to_string())?;

        let cts: Vec<FheUint8> = vals.iter().map(|&v| FheUint8::encrypt(v, &ck)).collect();
        let serialised = bincode::serialize(&cts).map_err(|e| e.to_string())?;

        let (ptr, len) = leak_buf(serialised);
        *ct_out = ptr;
        *ct_len = len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}

/// Decrypt a bincode-serialised `Vec<FheInt8>` (server result) with the client key.
///
/// Compatible with `concrete-ml-extensions::decrypt_serialized_i8_radix_2d()`.
/// The raw i8 scores are then dequantised in Dart using quantization_params.json.
///
/// # Safety
/// `client_key`, `ct` must point to valid buffers.  Free output with `fhe_free_i8_buf`.
#[no_mangle]
pub unsafe extern "C" fn fhe_decrypt_i8(
    client_key:  *const u8, client_key_len: usize,
    ct:          *const u8, ct_len:         usize,
    scores_out:  *mut *mut i8, scores_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let ck_bytes  = slice::from_raw_parts(client_key, client_key_len);
        let ct_bytes  = slice::from_raw_parts(ct, ct_len);

        let ck: ClientKey = safe_deserialize(Cursor::new(ck_bytes), LIMIT)
            .map_err(|e| e.to_string())?;
        let fhe_ints: Vec<FheInt8> = bincode::deserialize(ct_bytes)
            .map_err(|e| e.to_string())?;

        let raw: Vec<i8> = fhe_ints.iter().map(|v| v.decrypt(&ck)).collect();
        let len = raw.len();
        let ptr = Box::into_raw(raw.into_boxed_slice()) as *mut i8;
        *scores_out = ptr;
        *scores_len = len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}

/// Free a `u8` buffer returned by `fhe_keygen` or `fhe_encrypt_u8`.
///
/// # Safety
/// `ptr` must have been returned by this library with the matching `len`.
#[no_mangle]
pub unsafe extern "C" fn fhe_free_buf(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(Box::from_raw(slice::from_raw_parts_mut(ptr, len)));
    }
}

/// Free an `i8` buffer returned by `fhe_decrypt_i8`.
///
/// # Safety
/// `ptr` must have been returned by this library with the matching `len`.
#[no_mangle]
pub unsafe extern "C" fn fhe_free_i8_buf(ptr: *mut i8, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(Box::from_raw(slice::from_raw_parts_mut(ptr, len)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: generate keys and verify the Cap'n Proto eval key can be
    /// deserialized by the Rust capnp reader (structural validation).
    #[test]
    fn generate_concrete_eval_keys_smoke() {
        let config = ConfigBuilder::default()
            .use_custom_parameters(V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            .build();
        let (client_key, _server_key) = tfhe::generate_keys(config);

        let eval_key_bytes = generate_concrete_eval_keys(&client_key)
            .expect("generate_concrete_eval_keys failed");

        // First 4 bytes are the Cap'n Proto segment-count header (n_segs - 1 = LE u32).
        // With a larger payload Cap'n Proto may use more segments — just check it's non-zero.
        let n_segs = u32::from_le_bytes(eval_key_bytes[..4].try_into().unwrap());
        assert!(n_segs > 0, "expected valid Cap'n Proto framing, got 0 segments");

        // Deserialize and check structure (raise limit to 2 GB for the large eval key)
        let mut opts = capnp::message::ReaderOptions::new();
        opts.traversal_limit_in_words(Some(1 << 28)); // 256M words = 2 GB
        let reader = serialize::read_message(&eval_key_bytes[..], opts)
            .expect("Cap'n Proto deserialization failed");
        let keyset = reader
            .get_root::<concrete_protocol_capnp::server_keyset::Reader<'_>>()
            .expect("get_root failed");

        let bsks = keyset.get_lwe_bootstrap_keys().unwrap();
        let ksks = keyset.get_lwe_keyswitch_keys().unwrap();
        assert_eq!(bsks.len(), 4);
        assert_eq!(ksks.len(), 8);
        assert_eq!(keyset.get_packing_keyswitch_keys().unwrap().len(), 0);

        // Spot-check BSK[0] params (inputLweDim=796, level=2, baseLog=15)
        let bsk0_params = bsks.get(0).get_info().unwrap().get_params().unwrap();
        assert_eq!(bsk0_params.get_input_lwe_dimension(), 796);
        assert_eq!(bsk0_params.get_level_count(), 2);
        assert_eq!(bsk0_params.get_base_log(), 15);

        // Spot-check KSK[0] params (inputLweDim=2048, outputLweDim=796, level=5, baseLog=3)
        let ksk0_params = ksks.get(0).get_info().unwrap().get_params().unwrap();
        assert_eq!(ksk0_params.get_input_lwe_dimension(), 2048);
        assert_eq!(ksk0_params.get_output_lwe_dimension(), 796);
        assert_eq!(ksk0_params.get_level_count(), 5);
        assert_eq!(ksk0_params.get_base_log(), 3);

        println!(
            "eval_key_bytes size: {} bytes ({:.1} MB)",
            eval_key_bytes.len(),
            eval_key_bytes.len() as f64 / 1024.0 / 1024.0
        );

        // Write to /tmp for cross-language comparison script
        std::fs::write("/tmp/rust_eval_key.bin", &eval_key_bytes).unwrap();
        println!("Wrote /tmp/rust_eval_key.bin for Python comparison");
    }
}
