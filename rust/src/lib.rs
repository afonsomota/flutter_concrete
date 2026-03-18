// journal_app/rust/src/lib.rs
//
// Native TFHE-rs FHE client — C FFI layer for Dart.
//
// Serialisation compatibility:
//   • Key generation matches concrete-ml-extensions (cml-ext 0.2.0) keygen_radix()
//   • Encryption dispatches to FheUint{8,16,32,64} / FheInt{8,16,32,64}
//   • Decryption dispatches to the matching type, outputs i64
//   • Parameter set: V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64
//
// Exported C functions (return 0 on success, negative code on failure):
//   fhe_keygen(topology_ptr, topology_len, ck_out, ck_len, sk_out, sk_len) → i32
//   fhe_encrypt(ck, ck_len, vals, n_vals, bit_width, is_signed, ct_out, ct_len) → i32
//   fhe_decrypt(ck, ck_len, ct, ct_len, bit_width, is_signed, out, out_len) → i32
//   fhe_free_buf(ptr, len)
//   fhe_free_i64_buf(ptr, len)

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
use tfhe::{ClientKey, ConfigBuilder, FheInt8, FheInt16, FheInt32, FheInt64,
           FheUint8, FheUint16, FheUint32, FheUint64};

// ── Generated Cap'n Proto bindings ────────────────────────────────────────────
pub mod concrete_protocol_capnp {
    #![allow(dead_code, unused_imports, clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/concrete_protocol_capnp.rs"));
}

// ── Serialisation limit ───────────────────────────────────────────────────────
const LIMIT: u64 = 1_000_000_000;

// ── Topology from Dart FFI ──────────────────────────────────────────────────

struct SkSpec { id: u64, dim: u64 }
struct BskSpec {
    input_id: u64, output_id: u64,
    level_count: u64, base_log: u64,
    glwe_dim: u64, poly_size: u64,
    input_lwe_dim: u64, variance: f64,
}
struct KskSpec {
    input_id: u64, output_id: u64,
    level_count: u64, base_log: u64,
    input_lwe_dim: u64, output_lwe_dim: u64,
    variance: f64,
}

struct Topology {
    sks: Vec<SkSpec>,
    bsks: Vec<BskSpec>,
    ksks: Vec<KskSpec>,
}

fn unpack_topology(data: &[u64]) -> Result<Topology, String> {
    let mut i = 0;
    let read = |i: &mut usize| -> Result<u64, String> {
        if *i >= data.len() { return Err("topology buffer underflow".into()); }
        let v = data[*i]; *i += 1; Ok(v)
    };

    let num_sks = read(&mut i)? as usize;
    let mut sks = Vec::with_capacity(num_sks);
    for _ in 0..num_sks {
        sks.push(SkSpec { id: read(&mut i)?, dim: read(&mut i)? });
    }

    let num_bsks = read(&mut i)? as usize;
    let mut bsks = Vec::with_capacity(num_bsks);
    for _ in 0..num_bsks {
        let input_id = read(&mut i)?;
        let output_id = read(&mut i)?;
        let level_count = read(&mut i)?;
        let base_log = read(&mut i)?;
        let glwe_dim = read(&mut i)?;
        let poly_size = read(&mut i)?;
        let input_lwe_dim = read(&mut i)?;
        let variance_bits = read(&mut i)?;
        let variance = f64::from_bits(variance_bits);
        bsks.push(BskSpec {
            input_id, output_id, level_count, base_log,
            glwe_dim, poly_size, input_lwe_dim, variance,
        });
    }

    let num_ksks = read(&mut i)? as usize;
    let mut ksks = Vec::with_capacity(num_ksks);
    for _ in 0..num_ksks {
        let input_id = read(&mut i)?;
        let output_id = read(&mut i)?;
        let level_count = read(&mut i)?;
        let base_log = read(&mut i)?;
        let input_lwe_dim = read(&mut i)?;
        let output_lwe_dim = read(&mut i)?;
        let variance_bits = read(&mut i)?;
        let variance = f64::from_bits(variance_bits);
        ksks.push(KskSpec {
            input_id, output_id, level_count, base_log,
            input_lwe_dim, output_lwe_dim, variance,
        });
    }

    Ok(Topology { sks, bsks, ksks })
}

// ── Concrete eval key generation ──────────────────────────────────────────────

fn generate_concrete_eval_keys(ck: &ClientKey, topo: &Topology) -> Result<Vec<u8>, String> {
    use std::collections::HashMap;

    // ── Extract root GLWE key (SK[0]) from TFHE-rs ClientKey ────────────────
    let (integer_ck, _, _, _) = ck.clone().into_raw_parts();
    let shortint_ck = integer_ck.into_raw_parts();
    let (glwe_sk0, _tfhe_lwe_sk, _params) = shortint_ck.into_raw_parts();
    let sk0_lwe = glwe_sk0.clone().into_lwe_secret_key();

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut sec_gen = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let noise = |var: f64| Gaussian::from_dispersion_parameter(StandardDev(var.sqrt()), 0.0);

    // ── Determine which SKs are GLWE-derived (used as BSK output) ───────────
    // BSK output SK has lweDimension = glweDimension * polynomialSize
    let mut glwe_output_sks: HashMap<u64, (u64, u64)> = HashMap::new(); // sk_id -> (glwe_dim, poly_size)
    for bsk in &topo.bsks {
        glwe_output_sks.insert(bsk.output_id, (bsk.glwe_dim, bsk.poly_size));
    }

    // ── Generate all secret keys ────────────────────────────────────────────
    // SK[0] comes from the ClientKey. All others are generated fresh.
    let mut lwe_sks: HashMap<u64, tfhe::core_crypto::entities::LweSecretKeyOwned<u64>> = HashMap::new();
    let mut glwe_sks: HashMap<u64, tfhe::core_crypto::entities::GlweSecretKeyOwned<u64>> = HashMap::new();

    // Store SK[0]
    let sk0_id = topo.sks[0].id;
    lwe_sks.insert(sk0_id, sk0_lwe);
    glwe_sks.insert(sk0_id, glwe_sk0);

    for sk_spec in &topo.sks[1..] {
        if let Some(&(glwe_dim, poly_size)) = glwe_output_sks.get(&sk_spec.id) {
            // This SK backs a BSK output — generate as GLWE key
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                GlweDimension(glwe_dim as usize),
                PolynomialSize(poly_size as usize),
                &mut sec_gen,
            );
            let lwe_sk = glwe_sk.clone().into_lwe_secret_key();
            glwe_sks.insert(sk_spec.id, glwe_sk);
            lwe_sks.insert(sk_spec.id, lwe_sk);
        } else {
            // Plain small LWE key
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                LweDimension(sk_spec.dim as usize),
                &mut sec_gen,
            );
            lwe_sks.insert(sk_spec.id, lwe_sk);
        }
    }

    // ── Generate seeded BSKs ────────────────────────────────────────────────
    let mut bsk_data: Vec<(Vec<u8>, &BskSpec)> = Vec::new();
    for bsk_spec in &topo.bsks {
        let input_sk = lwe_sks.get(&bsk_spec.input_id)
            .ok_or_else(|| format!("BSK input SK {} not found", bsk_spec.input_id))?;
        let output_glwe = glwe_sks.get(&bsk_spec.output_id)
            .ok_or_else(|| format!("BSK output GLWE SK {} not found", bsk_spec.output_id))?;

        let glwe_size = GlweSize(bsk_spec.glwe_dim as usize + 1);
        let mut bsk = SeededLweBootstrapKey::new(
            0u64, glwe_size,
            PolynomialSize(bsk_spec.poly_size as usize),
            DecompositionBaseLog(bsk_spec.base_log as usize),
            DecompositionLevelCount(bsk_spec.level_count as usize),
            LweDimension(bsk_spec.input_lwe_dim as usize),
            seeder.seed().into(),
            CiphertextModulus::new_native(),
        );
        generate_seeded_lwe_bootstrap_key(
            input_sk, output_glwe, &mut bsk,
            noise(bsk_spec.variance), seeder,
        );

        // Serialize: [seed(16 bytes) || body_u64_bytes]
        let seed_bytes: [u8; 16] = bsk.compression_seed().seed.0.to_le_bytes();
        let body_bytes = bytemuck::cast_slice::<u64, u8>(bsk.as_ref());
        let mut v = Vec::with_capacity(16 + body_bytes.len());
        v.extend_from_slice(&seed_bytes);
        v.extend_from_slice(body_bytes);
        bsk_data.push((v, bsk_spec));
    }

    // ── Generate seeded KSKs ────────────────────────────────────────────────
    let mut ksk_data: Vec<(Vec<u8>, &KskSpec)> = Vec::new();
    for ksk_spec in &topo.ksks {
        let input_sk = lwe_sks.get(&ksk_spec.input_id)
            .ok_or_else(|| format!("KSK input SK {} not found", ksk_spec.input_id))?;
        let output_sk = lwe_sks.get(&ksk_spec.output_id)
            .ok_or_else(|| format!("KSK output SK {} not found", ksk_spec.output_id))?;

        let mut ksk = SeededLweKeyswitchKey::new(
            0u64,
            DecompositionBaseLog(ksk_spec.base_log as usize),
            DecompositionLevelCount(ksk_spec.level_count as usize),
            LweDimension(ksk_spec.input_lwe_dim as usize),
            LweDimension(ksk_spec.output_lwe_dim as usize),
            seeder.seed().into(),
            CiphertextModulus::new_native(),
        );
        generate_seeded_lwe_keyswitch_key(
            input_sk, output_sk, &mut ksk,
            noise(ksk_spec.variance), seeder,
        );

        let seed_bytes: [u8; 16] = ksk.compression_seed().seed.0.to_le_bytes();
        let body_bytes = bytemuck::cast_slice::<u64, u8>(ksk.as_ref());
        let mut v = Vec::with_capacity(16 + body_bytes.len());
        v.extend_from_slice(&seed_bytes);
        v.extend_from_slice(body_bytes);
        ksk_data.push((v, ksk_spec));
    }

    // ── Build Cap'n Proto ServerKeyset ──────────────────────────────────────
    let mut message = Builder::new_default();
    {
        use concrete_protocol_capnp::server_keyset;
        let mut keyset = message.init_root::<server_keyset::Builder<'_>>();

        // BSKs
        let mut bsks = keyset.reborrow().init_lwe_bootstrap_keys(bsk_data.len() as u32);
        for (idx, (bytes, spec)) in bsk_data.iter().enumerate() {
            let mut m = bsks.reborrow().get(idx as u32);
            {
                let mut info = m.reborrow().init_info();
                info.set_id(idx as u32);
                info.set_input_id(spec.input_id as u32);
                info.set_output_id(spec.output_id as u32);
                info.set_compression(concrete_protocol_capnp::Compression::Seed);
                let mut p = info.init_params();
                p.set_level_count(spec.level_count as u32);
                p.set_base_log(spec.base_log as u32);
                p.set_glwe_dimension(spec.glwe_dim as u32);
                p.set_polynomial_size(spec.poly_size as u32);
                p.set_input_lwe_dimension(spec.input_lwe_dim as u32);
                p.set_variance(spec.variance);
                p.set_integer_precision(64);
                p.set_key_type(concrete_protocol_capnp::KeyType::Binary);
                p.init_modulus().reborrow().get_modulus().init_native();
            }
            write_payload_chunks(&mut m.init_payload(), bytes);
        }

        // KSKs
        let mut ksks = keyset.reborrow().init_lwe_keyswitch_keys(ksk_data.len() as u32);
        for (idx, (bytes, spec)) in ksk_data.iter().enumerate() {
            let mut m = ksks.reborrow().get(idx as u32);
            {
                let mut info = m.reborrow().init_info();
                info.set_id(idx as u32);
                info.set_input_id(spec.input_id as u32);
                info.set_output_id(spec.output_id as u32);
                info.set_compression(concrete_protocol_capnp::Compression::Seed);
                let mut p = info.init_params();
                p.set_level_count(spec.level_count as u32);
                p.set_base_log(spec.base_log as u32);
                p.set_input_lwe_dimension(spec.input_lwe_dim as u32);
                p.set_output_lwe_dimension(spec.output_lwe_dim as u32);
                p.set_variance(spec.variance);
                p.set_integer_precision(64);
                p.set_key_type(concrete_protocol_capnp::KeyType::Binary);
                p.init_modulus().reborrow().get_modulus().init_native();
            }
            write_payload_chunks(&mut m.init_payload(), bytes);
        }

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

/// Generate a fresh TFHE-rs keypair with dynamic topology.
///
/// Outputs two buffers (both freed with `fhe_free_buf`):
///   - `client_key_*` — private; store encrypted on-device
///   - `server_key_*` — concrete Cap'n Proto ServerKeyset; upload to `POST /fhe/key`
///
/// # Safety
/// All pointer arguments must not be null. `topology_ptr` must point to
/// `topology_len` u64 values encoding the packed topology.
#[no_mangle]
pub unsafe extern "C" fn fhe_keygen(
    topology_ptr:   *const u64, topology_len: usize,
    client_key_out: *mut *mut u8, client_key_len: *mut usize,
    server_key_out: *mut *mut u8, server_key_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let topo_data = slice::from_raw_parts(topology_ptr, topology_len);
        let topo = unpack_topology(topo_data)?;

        let config = ConfigBuilder::default()
            .use_custom_parameters(V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            .build();
        let (client_key, _server_key) = tfhe::generate_keys(config);

        // Serialise client key
        let mut ck_buf = Vec::new();
        safe_serialize(&client_key, &mut ck_buf, LIMIT).map_err(|e| e.to_string())?;

        // Generate eval keys from topology
        let sk_buf = generate_concrete_eval_keys(&client_key, &topo)?;

        let (ck_ptr, ck_len) = leak_buf(ck_buf);
        let (sk_ptr, sk_len) = leak_buf(sk_buf);

        *client_key_out = ck_ptr;  *client_key_len = ck_len;
        *server_key_out = sk_ptr;  *server_key_len = sk_len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}

/// Encrypt values with the client key, dispatching to the correct TFHE-rs type.
///
/// `values` is an array of `i64` — each is cast to the target type before encrypting.
/// `bit_width`: 8, 16, 32, or 64. `is_signed`: 0 = unsigned, 1 = signed.
///
/// # Safety
/// `client_key`, `values` must point to valid buffers of the given lengths.
/// Free the output with `fhe_free_buf`.
#[no_mangle]
pub unsafe extern "C" fn fhe_encrypt(
    client_key: *const u8, client_key_len: usize,
    values:     *const i64, n_vals:        usize,
    bit_width:  u32,
    is_signed:  u32,
    ct_out:     *mut *mut u8, ct_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let ck_bytes = slice::from_raw_parts(client_key, client_key_len);
        let vals = slice::from_raw_parts(values, n_vals);
        let ck: ClientKey = safe_deserialize(Cursor::new(ck_bytes), LIMIT)
            .map_err(|e| e.to_string())?;

        macro_rules! encrypt_dispatch {
            ($fhe_type:ty, $cast:ty) => {{
                let cts: Vec<$fhe_type> = vals.iter()
                    .map(|&v| <$fhe_type>::encrypt(v as $cast, &ck))
                    .collect();
                bincode::serialize(&cts).map_err(|e| e.to_string())?
            }};
        }

        let serialised = match (bit_width, is_signed != 0) {
            (8,  false) => encrypt_dispatch!(FheUint8,  u8),
            (8,  true)  => encrypt_dispatch!(FheInt8,   i8),
            (16, false) => encrypt_dispatch!(FheUint16, u16),
            (16, true)  => encrypt_dispatch!(FheInt16,  i16),
            (32, false) => encrypt_dispatch!(FheUint32, u32),
            (32, true)  => encrypt_dispatch!(FheInt32,  i32),
            (64, false) => encrypt_dispatch!(FheUint64, u64),
            (64, true)  => encrypt_dispatch!(FheInt64,  i64),
            _ => return Err(format!("unsupported bit_width={bit_width} is_signed={is_signed}")),
        };

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

/// Decrypt ciphertext, dispatching to the correct TFHE-rs type.
///
/// Output is always `i64` values (zero-extended for unsigned, sign-extended for signed).
/// `scores_len` is set to the number of elements (not bytes).
///
/// # Safety
/// `client_key`, `ct` must point to valid buffers. Free output with `fhe_free_i64_buf`.
#[no_mangle]
pub unsafe extern "C" fn fhe_decrypt(
    client_key: *const u8, client_key_len: usize,
    ct:         *const u8, ct_len:         usize,
    bit_width:  u32,
    is_signed:  u32,
    scores_out: *mut *mut i64, scores_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let ck_bytes = slice::from_raw_parts(client_key, client_key_len);
        let ct_bytes = slice::from_raw_parts(ct, ct_len);
        let ck: ClientKey = safe_deserialize(Cursor::new(ck_bytes), LIMIT)
            .map_err(|e| e.to_string())?;

        macro_rules! decrypt_dispatch {
            ($fhe_type:ty, $cast:ty) => {{
                let fhe_vals: Vec<$fhe_type> = bincode::deserialize(ct_bytes)
                    .map_err(|e| e.to_string())?;
                let raw: Vec<i64> = fhe_vals.iter()
                    .map(|v| { let x: $cast = v.decrypt(&ck); x as i64 })
                    .collect();
                raw
            }};
        }

        let raw: Vec<i64> = match (bit_width, is_signed != 0) {
            (8,  false) => decrypt_dispatch!(FheUint8,  u8),
            (8,  true)  => decrypt_dispatch!(FheInt8,   i8),
            (16, false) => decrypt_dispatch!(FheUint16, u16),
            (16, true)  => decrypt_dispatch!(FheInt16,  i16),
            (32, false) => decrypt_dispatch!(FheUint32, u32),
            (32, true)  => decrypt_dispatch!(FheInt32,  i32),
            (64, false) => decrypt_dispatch!(FheUint64, u64),
            (64, true)  => decrypt_dispatch!(FheInt64,  i64),
            _ => return Err(format!("unsupported bit_width={bit_width} is_signed={is_signed}")),
        };

        let len = raw.len();
        let ptr = Box::into_raw(raw.into_boxed_slice()) as *mut i64;
        *scores_out = ptr;
        *scores_len = len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}

/// Free a `u8` buffer returned by `fhe_keygen` or `fhe_encrypt`.
///
/// # Safety
/// `ptr` must have been returned by this library with the matching `len`.
#[no_mangle]
pub unsafe extern "C" fn fhe_free_buf(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(Box::from_raw(slice::from_raw_parts_mut(ptr, len)));
    }
}

/// Free an `i64` buffer returned by `fhe_decrypt`.
///
/// # Safety
/// `ptr` must have been returned by this library with the matching `len`.
#[no_mangle]
pub unsafe extern "C" fn fhe_free_i64_buf(ptr: *mut i64, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(Box::from_raw(slice::from_raw_parts_mut(ptr, len)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: generate keys with a dynamic topology and verify the Cap'n Proto
    /// eval key can be deserialized by the Rust capnp reader (structural validation).
    #[test]
    fn generate_concrete_eval_keys_smoke() {
        let config = ConfigBuilder::default()
            .use_custom_parameters(V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            .build();
        let (client_key, _server_key) = tfhe::generate_keys(config);

        let topo = Topology {
            sks: vec![
                SkSpec { id: 0, dim: 2048 },
                SkSpec { id: 1, dim: 599 },
                SkSpec { id: 2, dim: 1536 },
                SkSpec { id: 3, dim: 719 },
                SkSpec { id: 4, dim: 2048 },
                SkSpec { id: 5, dim: 738 },
            ],
            bsks: vec![
                BskSpec { input_id: 1, output_id: 0, level_count: 1, base_log: 23,
                          glwe_dim: 4, poly_size: 512, input_lwe_dim: 599,
                          variance: 8.442253112932959e-31 },
                BskSpec { input_id: 3, output_id: 2, level_count: 1, base_log: 18,
                          glwe_dim: 6, poly_size: 256, input_lwe_dim: 719,
                          variance: 7.040630965929754e-23 },
                BskSpec { input_id: 5, output_id: 4, level_count: 2, base_log: 15,
                          glwe_dim: 2, poly_size: 1024, input_lwe_dim: 738,
                          variance: 8.442253112932959e-31 },
            ],
            ksks: vec![
                KskSpec { input_id: 0, output_id: 1, level_count: 3, base_log: 3,
                          input_lwe_dim: 2048, output_lwe_dim: 599,
                          variance: 2.207703775750815e-08 },
                KskSpec { input_id: 0, output_id: 3, level_count: 2, base_log: 5,
                          input_lwe_dim: 2048, output_lwe_dim: 719,
                          variance: 3.0719950829084015e-10 },
                KskSpec { input_id: 2, output_id: 5, level_count: 4, base_log: 3,
                          input_lwe_dim: 1536, output_lwe_dim: 738,
                          variance: 1.5612464764249122e-10 },
            ],
        };

        let eval_key_bytes = generate_concrete_eval_keys(&client_key, &topo)
            .expect("generate_concrete_eval_keys failed");

        let mut opts = capnp::message::ReaderOptions::new();
        opts.traversal_limit_in_words(Some(1 << 28));
        let reader = serialize::read_message(&eval_key_bytes[..], opts)
            .expect("Cap'n Proto deserialization failed");
        let keyset = reader
            .get_root::<concrete_protocol_capnp::server_keyset::Reader<'_>>()
            .expect("get_root failed");

        let bsks = keyset.get_lwe_bootstrap_keys().unwrap();
        let ksks = keyset.get_lwe_keyswitch_keys().unwrap();
        assert_eq!(bsks.len(), 3);
        assert_eq!(ksks.len(), 3);

        // Spot-check BSK[0]
        let bsk0_params = bsks.get(0).get_info().unwrap().get_params().unwrap();
        assert_eq!(bsk0_params.get_input_lwe_dimension(), 599);
        assert_eq!(bsk0_params.get_level_count(), 1);
        assert_eq!(bsk0_params.get_base_log(), 23);

        // Spot-check KSK[0]
        let ksk0_params = ksks.get(0).get_info().unwrap().get_params().unwrap();
        assert_eq!(ksk0_params.get_input_lwe_dimension(), 2048);
        assert_eq!(ksk0_params.get_output_lwe_dimension(), 599);
    }
}
