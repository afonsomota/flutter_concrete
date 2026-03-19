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

use tfhe::core_crypto::algorithms::*;
use tfhe::core_crypto::commons::generators::SecretRandomGenerator;
use tfhe::core_crypto::commons::dispersion::StandardDev;
use tfhe::core_crypto::commons::math::random::{DefaultRandomGenerator, Gaussian};
use tfhe::core_crypto::commons::parameters::*;
use tfhe::core_crypto::entities::*;
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

// ── Concrete LWE encrypt/decrypt (CiphertextFormat.CONCRETE) ────────────────

/// Extract the root LWE secret key (SK[0]) from a TFHE-rs ClientKey.
fn extract_lwe_sk(ck: ClientKey)
    -> tfhe::core_crypto::entities::LweSecretKeyOwned<u64>
{
    let (integer_ck, _, _, _) = ck.into_raw_parts();
    let shortint_ck = integer_ck.into_raw_parts();
    let (glwe_sk, _, _) = shortint_ck.into_raw_parts();
    glwe_sk.into_lwe_secret_key()
}

/// Encrypt quantized values using Concrete's seeded LWE encoding.
///
/// Each value is bit-decomposed into `encoding_width` individual bits (LSB first).
/// Each bit is encrypted as a separate seeded LWE ciphertext with Delta = 2^62.
///
/// Output layout: `[seed_16bytes || b_0 || b_1 || ... || b_{n_vals*width-1}]`
/// where each `b_i` is one u64 (8 bytes).
///
/// # Safety
/// All pointer arguments must not be null. `values` must have `n_vals` elements.
/// Free output with `fhe_free_buf`.
#[no_mangle]
pub unsafe extern "C" fn fhe_lwe_encrypt_seeded(
    client_key: *const u8, client_key_len: usize,
    values: *const i64, n_vals: usize,
    encoding_width: u32,
    lwe_dimension: u32,
    variance: f64,
    ct_out: *mut *mut u8, ct_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let ck_bytes = slice::from_raw_parts(client_key, client_key_len);
        let vals = slice::from_raw_parts(values, n_vals);
        let ck: ClientKey = safe_deserialize(Cursor::new(ck_bytes), LIMIT)
            .map_err(|e| e.to_string())?;

        let width = encoding_width as usize;
        let lwe_dim = lwe_dimension as usize;
        let n_cts = n_vals * width;

        let lwe_sk = extract_lwe_sk(ck);
        if lwe_sk.lwe_dimension().0 != lwe_dim {
            return Err(format!(
                "ClientKey LWE dimension {} != expected {}",
                lwe_sk.lwe_dimension().0, lwe_dim
            ));
        }

        // Bit-decompose values into individual bit plaintexts (LSB first)
        let delta: u64 = 1u64 << 62; // width=1 per-bit encoding
        let mut plaintexts: Vec<u64> = Vec::with_capacity(n_cts);
        for &val in vals {
            for bit_idx in 0..width {
                let bit = ((val as u64 >> bit_idx) & 1) as u64;
                plaintexts.push(bit.wrapping_mul(delta));
            }
        }
        let plaintext_list = PlaintextList::from_container(plaintexts);

        // Create seeded output container
        let mut seeder = new_seeder();
        let mut seeded_ct_list = SeededLweCiphertextList::new(
            0u64,
            LweDimension(lwe_dim).to_lwe_size(),
            LweCiphertextCount(n_cts),
            seeder.as_mut().seed().into(),
            CiphertextModulus::new_native(),
        );

        let noise = Gaussian::from_dispersion_parameter(
            StandardDev(variance.sqrt()), 0.0,
        );

        // Encrypt using the public API (handles CSPRNG internally)
        encrypt_seeded_lwe_ciphertext_list(
            &lwe_sk, &mut seeded_ct_list, &plaintext_list,
            noise, seeder.as_mut(),
        );

        // Output: seed (16 bytes) || b-values (body data as u64s)
        let seed_bytes: [u8; 16] = seeded_ct_list.compression_seed().seed.0.to_le_bytes();
        let body_bytes = bytemuck::cast_slice::<u64, u8>(seeded_ct_list.as_ref());
        let mut output = Vec::with_capacity(16 + body_bytes.len());
        output.extend_from_slice(&seed_bytes);
        output.extend_from_slice(body_bytes);

        let (ptr, len) = leak_buf(output);
        *ct_out = ptr;
        *ct_len = len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}

/// Decrypt full (uncompressed) LWE ciphertexts using Concrete's decoding.
///
/// Each ciphertext is `lwe_dimension + 1` u64 values: `[a_0, ..., a_n, b]`.
/// Decryption: `plaintext = b - <a, s>`
/// Decoding (round-to-nearest):
///   `shift = 64 - width - 1`
///   `decoded = ((plaintext + (1 << (shift-1))) >> shift) & ((1 << width) - 1)`
///   if signed and `decoded >= 2^(width-1)`: `decoded -= 2^width`
///
/// # Safety
/// `ct` must point to `n_cts * (lwe_dimension + 1) * 8` bytes.
/// Free output with `fhe_free_i64_buf`.
#[no_mangle]
pub unsafe extern "C" fn fhe_lwe_decrypt_full(
    client_key: *const u8, client_key_len: usize,
    ct: *const u8, ct_len: usize,
    n_cts: u32,
    encoding_width: u32, is_signed: u32,
    lwe_dimension: u32,
    scores_out: *mut *mut i64, scores_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let ck_bytes = slice::from_raw_parts(client_key, client_key_len);
        let ck: ClientKey = safe_deserialize(Cursor::new(ck_bytes), LIMIT)
            .map_err(|e| e.to_string())?;

        let lwe_dim = lwe_dimension as usize;
        let ct_size = lwe_dim + 1; // u64 elements per ciphertext
        let n = n_cts as usize;
        let width = encoding_width as usize;
        let signed = is_signed != 0;

        let expected_bytes = n * ct_size * 8;
        if ct_len != expected_bytes {
            return Err(format!(
                "ct_len {} != expected {} (n_cts={}, ct_size={})",
                ct_len, expected_bytes, n, ct_size
            ));
        }

        let ct_u64 = slice::from_raw_parts(ct as *const u64, n * ct_size);
        let lwe_sk = extract_lwe_sk(ck);

        let shift = 64 - width - 1;
        let half: u64 = 1u64 << (shift - 1);
        let mask: u64 = (1u64 << width) - 1;

        let mut results = Vec::with_capacity(n);
        for i in 0..n {
            let base = i * ct_size;
            let a = &ct_u64[base..base + lwe_dim];
            let b = ct_u64[base + lwe_dim];

            // Decrypt: plaintext = b - <a, s>
            let mut dot: u64 = 0;
            for (a_j, s_j) in a.iter().zip(lwe_sk.as_ref().iter()) {
                dot = dot.wrapping_add(a_j.wrapping_mul(*s_j));
            }
            let plaintext = b.wrapping_sub(dot);

            // Decode: round-to-nearest
            let decoded = (plaintext.wrapping_add(half) >> shift) & mask;

            let value = if signed && decoded >= (1u64 << (width - 1)) {
                decoded as i64 - (1i64 << width)
            } else {
                decoded as i64
            };

            results.push(value);
        }

        let len = results.len();
        let ptr = Box::into_raw(results.into_boxed_slice()) as *mut i64;
        *scores_out = ptr;
        *scores_len = len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}

/// Serialize raw ciphertext bytes into a Cap'n Proto Value message.
///
/// `ct_data`: raw bytes (seeded: seed+b-values; full: n_cts*(lwe_dim+1) u64s)
/// `shape`/`abstract_shape`: concrete and abstract shapes as u32 arrays
/// `compression`: 0=none, 1=seed
///
/// # Safety
/// All pointer arguments must not be null. Free output with `fhe_free_buf`.
#[no_mangle]
pub unsafe extern "C" fn fhe_serialize_value(
    ct_data: *const u8, ct_len: usize,
    shape: *const u32, shape_len: usize,
    abstract_shape: *const u32, abstract_shape_len: usize,
    encoding_width: u32, is_signed: u32,
    lwe_dimension: u32, key_id: u32, variance: f64,
    compression: u32,
    out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let ct_bytes = slice::from_raw_parts(ct_data, ct_len);
        let shape_vals = slice::from_raw_parts(shape, shape_len);
        let abstract_shape_vals = slice::from_raw_parts(abstract_shape, abstract_shape_len);

        let mut message = Builder::new_default();
        {
            use concrete_protocol_capnp::value;
            let mut val = message.init_root::<value::Builder<'_>>();

            // Payload: single Data entry
            {
                let mut payload = val.reborrow().init_payload();
                let mut data_list = payload.reborrow().init_data(1);
                data_list.set(0, ct_bytes);
            }

            // RawInfo: isSigned is always false (raw u64 container)
            {
                let mut raw_info = val.reborrow().init_raw_info();
                {
                    let s = raw_info.reborrow().init_shape();
                    let mut dims = s.init_dimensions(shape_vals.len() as u32);
                    for (i, &d) in shape_vals.iter().enumerate() {
                        dims.set(i as u32, d);
                    }
                }
                raw_info.set_integer_precision(64);
                raw_info.set_is_signed(false);
            }

            // TypeInfo: lweCiphertext
            let type_info = val.reborrow().init_type_info();
            let mut lwe_info = type_info.init_lwe_ciphertext();

            // Abstract shape
            {
                let s = lwe_info.reborrow().init_abstract_shape();
                let mut dims = s.init_dimensions(abstract_shape_vals.len() as u32);
                for (i, &d) in abstract_shape_vals.iter().enumerate() {
                    dims.set(i as u32, d);
                }
            }

            // Concrete shape
            {
                let s = lwe_info.reborrow().init_concrete_shape();
                let mut dims = s.init_dimensions(shape_vals.len() as u32);
                for (i, &d) in shape_vals.iter().enumerate() {
                    dims.set(i as u32, d);
                }
            }

            lwe_info.set_integer_precision(64);

            // Encryption info
            {
                let mut enc = lwe_info.reborrow().init_encryption();
                enc.set_key_id(key_id);
                enc.set_variance(variance);
                enc.set_lwe_dimension(lwe_dimension);
                enc.init_modulus().init_modulus().init_native();
            }

            // Compression
            let comp = match compression {
                0 => concrete_protocol_capnp::Compression::None,
                1 => concrete_protocol_capnp::Compression::Seed,
                _ => return Err(format!("unknown compression {}", compression)),
            };
            lwe_info.set_compression(comp);

            // Encoding: integer, native mode
            let mut encoding = lwe_info.init_encoding().init_integer();
            encoding.set_width(encoding_width);
            encoding.set_is_signed(is_signed != 0);
            encoding.init_mode().init_native();
        }

        let mut buf: Vec<u8> = Vec::new();
        serialize::write_message(&mut buf, &message).map_err(|e| e.to_string())?;

        let (ptr, len) = leak_buf(buf);
        *out = ptr;
        *out_len = len;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
    }
}

/// Deserialize a Cap'n Proto Value message, extracting raw ciphertext bytes.
///
/// Returns the payload bytes and the number of ciphertexts (product of all
/// concrete shape dims except the last).
///
/// # Safety
/// `data` must point to `data_len` bytes of Cap'n Proto message.
/// Free output with `fhe_free_buf`.
#[no_mangle]
pub unsafe extern "C" fn fhe_deserialize_value(
    data: *const u8, data_len: usize,
    ct_out: *mut *mut u8, ct_len: *mut usize,
    n_cts_out: *mut u32,
) -> i32 {
    match panic::catch_unwind(|| -> Result<(), String> {
        let bytes = slice::from_raw_parts(data, data_len);

        let mut opts = capnp::message::ReaderOptions::new();
        opts.traversal_limit_in_words(Some(1 << 30));
        let reader = serialize::read_message(bytes, opts)
            .map_err(|e| e.to_string())?;
        let value = reader
            .get_root::<concrete_protocol_capnp::value::Reader<'_>>()
            .map_err(|e| e.to_string())?;

        // Extract payload
        let payload = value.get_payload().map_err(|e| e.to_string())?;
        let data_list = payload.get_data().map_err(|e| e.to_string())?;
        if data_list.len() == 0 {
            return Err("Value has empty payload".into());
        }
        let raw_data = data_list.get(0);

        // Determine n_cts from concrete shape
        let type_info = value.get_type_info().map_err(|e| e.to_string())?;
        let n_cts = match type_info.which().map_err(|e| format!("TypeInfo: {:?}", e))? {
            concrete_protocol_capnp::type_info::Which::LweCiphertext(Ok(info)) => {
                let concrete_shape = info.get_concrete_shape()
                    .map_err(|e: capnp::Error| e.to_string())?;
                let dims = concrete_shape.get_dimensions()
                    .map_err(|e: capnp::Error| e.to_string())?;
                // Product of all dims except the last
                let mut total: u32 = 1;
                for i in 0..dims.len().saturating_sub(1) {
                    total *= dims.get(i);
                }
                total
            }
            concrete_protocol_capnp::type_info::Which::LweCiphertext(Err(e)) => {
                return Err(format!("Failed to read LweCiphertext: {:?}", e));
            }
            _ => return Err("TypeInfo is not lweCiphertext".into()),
        };

        let output = raw_data.map_err(|e: capnp::Error| e.to_string())?.to_vec();
        let (ptr, len) = leak_buf(output);
        *ct_out = ptr;
        *ct_len = len;
        *n_cts_out = n_cts;
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -1,
        Err(_) => -2,
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

    #[test]
    fn lwe_encrypt_seeded_output_size() {
        let config = ConfigBuilder::default()
            .use_custom_parameters(V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            .build();
        let (client_key, _) = tfhe::generate_keys(config);

        let mut ck_buf = Vec::new();
        safe_serialize(&client_key, &mut ck_buf, LIMIT).unwrap();

        let values: Vec<i64> = vec![0, 1, 3, 5, 7];
        let width: u32 = 3;
        let lwe_dim: u32 = 2048;
        let variance: f64 = 8.442253112932959e-31;

        let mut ct_ptr: *mut u8 = std::ptr::null_mut();
        let mut ct_len: usize = 0;
        let rc = unsafe {
            fhe_lwe_encrypt_seeded(
                ck_buf.as_ptr(), ck_buf.len(),
                values.as_ptr(), values.len(),
                width, lwe_dim, variance,
                &mut ct_ptr, &mut ct_len,
            )
        };
        assert_eq!(rc, 0, "fhe_lwe_encrypt_seeded failed");
        // 16 (seed) + 5*3*8 (b-values) = 136 bytes
        assert_eq!(ct_len, 16 + 5 * 3 * 8);
        unsafe { fhe_free_buf(ct_ptr, ct_len) };
    }

    #[test]
    fn lwe_seeded_encrypt_then_decrypt_round_trip() {
        let config = ConfigBuilder::default()
            .use_custom_parameters(V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64)
            .build();
        let (client_key, _) = tfhe::generate_keys(config);

        let mut ck_buf = Vec::new();
        safe_serialize(&client_key, &mut ck_buf, LIMIT).unwrap();

        let values: Vec<i64> = vec![0, 1, 3, 5, 7];
        let width: u32 = 3;
        let lwe_dim: u32 = 2048;
        let variance: f64 = 8.442253112932959e-31;

        // Encrypt (seeded)
        let mut ct_ptr: *mut u8 = std::ptr::null_mut();
        let mut ct_len: usize = 0;
        let rc = unsafe {
            fhe_lwe_encrypt_seeded(
                ck_buf.as_ptr(), ck_buf.len(),
                values.as_ptr(), values.len(),
                width, lwe_dim, variance,
                &mut ct_ptr, &mut ct_len,
            )
        };
        assert_eq!(rc, 0);
        let ct_bytes = unsafe { slice::from_raw_parts(ct_ptr, ct_len) }.to_vec();
        unsafe { fhe_free_buf(ct_ptr, ct_len) };

        // Reconstruct a SeededLweCiphertextList from the output bytes,
        // then decompress to full LweCiphertextList for decrypt test.
        let seed_bytes: [u8; 16] = ct_bytes[0..16].try_into().unwrap();
        let seed = tfhe::core_crypto::commons::math::random::CompressionSeed {
            seed: tfhe::core_crypto::commons::math::random::Seed(
                u128::from_le_bytes(seed_bytes)),
        };
        let b_values: Vec<u64> = bytemuck::cast_slice::<u8, u64>(&ct_bytes[16..]).to_vec();

        let n_cts = values.len() * width as usize;
        assert_eq!(b_values.len(), n_cts);

        let seeded_list = SeededLweCiphertextList::from_container(
            b_values,
            LweDimension(lwe_dim as usize).to_lwe_size(),
            seed,
            CiphertextModulus::new_native(),
        );

        // Decompress: expand seeds into full (a, b) ciphertexts
        let mut full_ct_list = LweCiphertextList::new(
            0u64,
            LweDimension(lwe_dim as usize).to_lwe_size(),
            LweCiphertextCount(n_cts),
            CiphertextModulus::new_native(),
        );
        decompress_seeded_lwe_ciphertext_list::<_, _, _, DefaultRandomGenerator>(
            &mut full_ct_list, &seeded_list,
        );

        let full_ct_bytes = bytemuck::cast_slice::<u64, u8>(full_ct_list.as_ref());

        // Decrypt each bit-ciphertext (width=1, unsigned)
        let mut scores_ptr: *mut i64 = std::ptr::null_mut();
        let mut scores_len: usize = 0;
        let rc = unsafe {
            fhe_lwe_decrypt_full(
                ck_buf.as_ptr(), ck_buf.len(),
                full_ct_bytes.as_ptr(), full_ct_bytes.len(),
                n_cts as u32,
                1,  // width=1 per bit
                0,  // unsigned
                lwe_dim,
                &mut scores_ptr, &mut scores_len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(scores_len, n_cts);

        let bits = unsafe { slice::from_raw_parts(scores_ptr, scores_len) }.to_vec();
        unsafe { fhe_free_i64_buf(scores_ptr, scores_len) };

        // Reassemble bits into values (LSB first)
        for (i, &orig_val) in values.iter().enumerate() {
            let mut reassembled: i64 = 0;
            for bit_idx in 0..width as usize {
                reassembled |= (bits[i * width as usize + bit_idx] & 1) << bit_idx;
            }
            assert_eq!(reassembled, orig_val, "value[{}] mismatch", i);
        }
    }

    #[test]
    fn value_serialize_deserialize_round_trip() {
        let payload = vec![0u8; 136]; // fake seeded data
        let shape: Vec<u32> = vec![1, 5, 3];
        let abstract_shape: Vec<u32> = vec![1, 5];

        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let rc = unsafe {
            fhe_serialize_value(
                payload.as_ptr(), payload.len(),
                shape.as_ptr(), shape.len(),
                abstract_shape.as_ptr(), abstract_shape.len(),
                3, 0, // width=3, unsigned
                2048, 0, 8.442253112932959e-31,
                1, // compression=seed
                &mut out_ptr, &mut out_len,
            )
        };
        assert_eq!(rc, 0);
        assert!(out_len > 0);

        let serialized = unsafe { slice::from_raw_parts(out_ptr, out_len) }.to_vec();
        unsafe { fhe_free_buf(out_ptr, out_len) };

        // Deserialize
        let mut ct_ptr: *mut u8 = std::ptr::null_mut();
        let mut ct_len: usize = 0;
        let mut n_cts: u32 = 0;

        let rc = unsafe {
            fhe_deserialize_value(
                serialized.as_ptr(), serialized.len(),
                &mut ct_ptr, &mut ct_len, &mut n_cts,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(ct_len, 136);
        assert_eq!(n_cts, 5); // product of shape[0..2] = 1*5

        let recovered = unsafe { slice::from_raw_parts(ct_ptr, ct_len) }.to_vec();
        unsafe { fhe_free_buf(ct_ptr, ct_len) };

        assert_eq!(payload, recovered);
    }
}
