#!/usr/bin/env python3
"""
Generate test fixtures for flutter_concrete equivalence tests.

Trains 8 tiny Concrete ML models, compiles each to FHE, and produces
client.zip + server.zip + reference.json per model. Each model is processed
in a separate subprocess to avoid LLVM/memory issues with Concrete's compiler.

reference.json includes python_fhe_scores: the full Python FHE round-trip
result (encrypt → server.run → decrypt) for each test vector.

Requirements: concrete-ml == 1.9.0
"""

import json
import logging
import subprocess
import sys
from pathlib import Path

import concrete.ml

# ---------------------------------------------------------------------------
# Version gate
# ---------------------------------------------------------------------------
EXPECTED_VERSION = "1.9.0"
assert concrete.ml.__version__ == EXPECTED_VERSION, (
    f"Expected concrete-ml {EXPECTED_VERSION}, got {concrete.ml.__version__}"
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model configs (serialisable — class names, not objects)
# ---------------------------------------------------------------------------
MODELS = {
    "xgb_classifier_multiclass": {
        "class_name": "XGBClassifier",
        "params": {"n_estimators": 3, "max_depth": 2, "n_bits": 3},
        "n_features": 5,
        "n_classes": 4,
    },
    "xgb_classifier_binary": {
        "class_name": "XGBClassifier",
        "params": {"n_estimators": 3, "max_depth": 2, "n_bits": 3},
        "n_features": 5,
        "n_classes": 2,
    },
    "random_forest_classifier": {
        "class_name": "RandomForestClassifier",
        "params": {"n_estimators": 3, "max_depth": 2, "n_bits": 3},
        "n_features": 5,
        "n_classes": 3,
    },
    "decision_tree_classifier": {
        "class_name": "DecisionTreeClassifier",
        "params": {"max_depth": 2, "n_bits": 3},
        "n_features": 4,
        "n_classes": 3,
    },
    "xgb_regressor": {
        "class_name": "XGBRegressor",
        "params": {"n_estimators": 2, "max_depth": 2, "n_bits": 3},
        "n_features": 4,
        "n_classes": 0,
    },
    "random_forest_regressor": {
        "class_name": "RandomForestRegressor",
        "params": {"n_estimators": 3, "max_depth": 2, "n_bits": 3},
        "n_features": 4,
        "n_classes": 0,
    },
    "logistic_regression": {
        "class_name": "LogisticRegression",
        "params": {"n_bits": 3},
        "n_features": 5,
        "n_classes": 3,
    },
    "linear_regression": {
        "class_name": "LinearRegression",
        "params": {"n_bits": 3},
        "n_features": 3,
        "n_classes": 0,
    },
}

# ---------------------------------------------------------------------------
# Worker script (runs in subprocess for each model)
# ---------------------------------------------------------------------------
WORKER_SCRIPT = r'''
import base64
import hashlib
import json
import shutil
import sys
import zipfile
from pathlib import Path

import numpy as np

import concrete.ml
assert concrete.ml.__version__ == "1.9.0"

from concrete.ml.deployment import FHEModelClient, FHEModelDev, FHEModelServer
from concrete.ml.sklearn import (
    DecisionTreeClassifier, LinearRegression, LogisticRegression,
    RandomForestClassifier, RandomForestRegressor,
    XGBClassifier, XGBRegressor,
)

try:
    from scipy.special import expit as scipy_sigmoid, softmax as scipy_softmax
except ImportError:
    def scipy_softmax(x):
        e = np.exp(x - np.max(x))
        return e / e.sum()
    def scipy_sigmoid(x):
        return 1.0 / (1.0 + np.exp(-x))

CLASS_MAP = {
    "XGBClassifier": XGBClassifier,
    "XGBRegressor": XGBRegressor,
    "RandomForestClassifier": RandomForestClassifier,
    "RandomForestRegressor": RandomForestRegressor,
    "DecisionTreeClassifier": DecisionTreeClassifier,
    "LogisticRegression": LogisticRegression,
    "LinearRegression": LinearRegression,
}

used_fallback = False


def fallback_post_process(dequantized_flat, output_shape, model_class_name, n_classes):
    """Manual post-processing matching Concrete ML logic.

    dequantized_flat is already flat. output_shape includes batch dim e.g. [1, 4, 3].
    We need to reshape, sum over last axis (tree estimators), then apply activation.
    """
    global used_fallback
    used_fallback = True
    print(f"  WARNING: Using fallback post-processing for {model_class_name}")

    values = np.array(dequantized_flat, dtype=np.float64)

    # Reshape to output_shape and sum over the last axis (estimators)
    if len(output_shape) >= 3 and output_shape[-1] > 1:
        # Shape like [1, n_classes, n_estimators] -> sum over estimators
        reshaped = values.reshape(output_shape)
        values = reshaped.sum(axis=-1).flatten()
    elif len(output_shape) == 2:
        values = values.reshape(output_shape).flatten()

    if model_class_name in ("XGBClassifier",):
        if n_classes == 2 and len(values) == 1:
            p = float(scipy_sigmoid(values[0]))
            return [1.0 - p, p]
        return scipy_softmax(values).tolist()
    elif model_class_name in ("RandomForestClassifier", "DecisionTreeClassifier"):
        return values.tolist()
    elif model_class_name in ("XGBRegressor",):
        return (values + 0.5).tolist()
    elif model_class_name in ("RandomForestRegressor",):
        return values.tolist()
    elif model_class_name in ("LogisticRegression",):
        if n_classes == 2 and len(values) == 1:
            p = float(scipy_sigmoid(values[0]))
            return [1.0 - p, p]
        return scipy_softmax(values).tolist()
    elif model_class_name in ("LinearRegression",):
        return values.tolist()
    else:
        return values.tolist()


def sha256_file(path):
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def extract_output_shape(client_zip_path):
    """Extract the output abstract shape from client.specs.json.

    Path: circuits[0].outputs[0].typeInfo.lweCiphertext.abstractShape.dimensions
    """
    with zipfile.ZipFile(client_zip_path, "r") as zf:
        specs = json.loads(zf.read("client.specs.json"))

    circuits = specs.get("circuits", [])
    if not circuits:
        return []
    outputs = circuits[0].get("outputs", [])
    if not outputs:
        return []
    type_info = outputs[0].get("typeInfo", {})
    lwe_info = type_info.get("lweCiphertext", {})
    abstract_shape = lwe_info.get("abstractShape", {})
    return abstract_shape.get("dimensions", [])


def generate_test_vectors(n_features):
    """Generate 5 test vectors: zeros, ones, normal, boundary, realistic."""
    rng = np.random.RandomState(123)
    return [
        ("zeros", np.zeros(n_features, dtype=np.float32)),
        ("ones", np.ones(n_features, dtype=np.float32)),
        ("normal", rng.randn(n_features).astype(np.float32)),
        ("boundary", np.full(n_features, 3.0, dtype=np.float32)),
        ("realistic", (rng.randn(n_features) * 0.5).astype(np.float32)),
    ]


def make_raw_output_ints(output_shape, n_vectors, seed=999):
    """Generate synthetic raw integer outputs within 3-bit signed range [-4, 3]."""
    rng = np.random.RandomState(seed)
    total = 1
    for d in output_shape:
        total *= d
    total = max(total, 1)
    return [rng.randint(-4, 4, size=total) for _ in range(n_vectors)]


def process_model(model_name, config, base_dir):
    np.random.seed(42)
    n_features = config["n_features"]
    n_classes = config["n_classes"]
    is_regression = n_classes == 0
    class_name = config["class_name"]

    # Generate training data (same seed for reproducibility)
    X_train = np.random.randn(100, n_features).astype(np.float32)
    if is_regression:
        y_train = np.random.randn(100).astype(np.float32)
    else:
        y_train = np.random.randint(0, n_classes, 100)

    cls = CLASS_MAP[class_name]
    model = cls(**config["params"])
    print(f"  Training {class_name}...")
    model.fit(X_train, y_train)

    print("  Compiling to FHE...")
    model.compile(X_train)

    # Save via FHEModelDev
    out_dir = Path(base_dir) / model_name
    out_dir.mkdir(exist_ok=True)
    fhe_dir = out_dir / "fhe_model"
    if fhe_dir.exists():
        shutil.rmtree(fhe_dir)
    fhe_dir.mkdir()

    dev = FHEModelDev(path_dir=str(fhe_dir), model=model)
    dev.save()
    print("  Saved FHE model")

    # Copy client.zip and server.zip to fixture directory
    client_zip_src = fhe_dir / "client.zip"
    client_zip_dst = out_dir / "client.zip"
    shutil.copy(client_zip_src, client_zip_dst)
    print(f"  Copied client.zip ({client_zip_dst.stat().st_size} bytes)")

    server_zip_src = fhe_dir / "server.zip"
    server_zip_dst = out_dir / "server.zip"
    shutil.copy(server_zip_src, server_zip_dst)
    print(f"  Copied server.zip ({server_zip_dst.stat().st_size} bytes)")

    # Load client for reference computations
    client = FHEModelClient(path_dir=str(fhe_dir))

    # Extract output shape from client.specs.json
    output_shape = extract_output_shape(client_zip_dst)
    print(f"  Output shape: {output_shape}")

    # Generate test vectors and synthetic raw outputs
    vectors = generate_test_vectors(n_features)
    raw_outputs = make_raw_output_ints(output_shape, len(vectors))
    test_vectors = []

    for i, ((desc, x), raw_ints) in enumerate(zip(vectors, raw_outputs)):
        print(f"  Vector {i}: {desc}")

        # Input quantization
        x_2d = x.reshape(1, -1)
        q_input = client.model.quantize_input(x_2d)
        q_input_flat = q_input.flatten().tolist()

        # Dequantize using Dart's formula: (raw + offset - zp) * scale
        # This matches what flutter_concrete's dequantizeOutputs() computes.
        # Python's client.model.dequantize_output() does NOT apply offset
        # (offset is handled at encryption/decryption layer), but Dart's
        # lweDecryptFull returns values that still need offset adjustment.
        # The raw_output_ints represent Dart-side raw decrypted values.
        oq = client.model.output_quantizers[0]
        oq_scale = float(oq.scale)
        oq_zp = oq.zero_point
        oq_offset = int(oq.offset) if hasattr(oq, 'offset') else 0

        raw_flat = raw_ints.flatten()
        if hasattr(oq_zp, '__len__'):
            # Per-class zero points
            zp_list = np.array(oq_zp).flatten()
            dequantized_flat = [
                float((int(r) + oq_offset - int(zp_list[j % len(zp_list)])) * oq_scale)
                for j, r in enumerate(raw_flat)
            ]
        else:
            zp = int(oq_zp)
            dequantized_flat = [
                float((int(r) + oq_offset - zp) * oq_scale)
                for r in raw_flat
            ]

        # Post-processing on dequantized values
        try:
            deq_shaped = np.array(dequantized_flat)
            if output_shape:
                deq_shaped = deq_shaped.reshape(output_shape)
            else:
                deq_shaped = deq_shaped.reshape(1, -1)
            post_processed = client.model.post_processing(deq_shaped)
            post_processed = np.array(post_processed).flatten().tolist()
        except Exception as e:
            print(f"  WARNING: post_processing API failed: {e}")
            post_processed = fallback_post_process(
                dequantized_flat, output_shape, class_name, n_classes
            )

        test_vectors.append({
            "description": desc,
            "input_float": x.tolist(),
            "quantized_input": q_input_flat,
            "raw_output_ints": raw_ints.flatten().tolist(),
            "dequantized_output": dequantized_flat,
            "post_processed": post_processed,
        })

    # Generate keys and save for Dart test (secret key + evaluation key)
    client.generate_private_and_evaluation_keys()

    eval_key_bytes = client.get_serialized_evaluation_keys()
    with open(str(out_dir / "eval_key.bin"), "wb") as f:
        f.write(eval_key_bytes)
    print(f"  Saved eval_key.bin ({len(eval_key_bytes)} bytes)")

    keys = client.client.keys
    secret_keys = keys._keyset.get_client_keys().get_secret_keys()
    sk0_bytes = secret_keys[0].serialize()
    with open(str(out_dir / "secret_key.bin"), "wb") as f:
        f.write(sk0_bytes)
    print(f"  Saved secret_key.bin ({len(sk0_bytes)} bytes)")

    # Full FHE round-trip: encrypt → server.run → decrypt for each test vector
    print("  Running FHE round-trip for each test vector...")
    server = FHEModelServer(path_dir=str(fhe_dir))
    server.load()
    eval_keys = eval_key_bytes

    for i, vec in enumerate(test_vectors):
        x = np.array(vec["input_float"], dtype=np.float32).reshape(1, -1)
        encrypted = client.quantize_encrypt_serialize(x)
        vec["encrypted_input_b64"] = base64.b64encode(encrypted).decode()
        encrypted_result = server.run(encrypted, eval_keys)
        if isinstance(encrypted_result, tuple):
            encrypted_result = encrypted_result[0]
        vec["encrypted_result_b64"] = base64.b64encode(encrypted_result).decode()
        result = client.deserialize_decrypt_dequantize(encrypted_result)
        vec["python_fhe_scores"] = np.array(result).flatten().tolist()
        print(f"  Vector {i} ({vec['description']}): FHE scores = {vec['python_fhe_scores']}")

    # Build reference.json
    reference = {
        "concrete_ml_version": concrete.ml.__version__,
        "client_zip_sha256": sha256_file(client_zip_dst),
        "model_class": class_name,
        "n_classes": n_classes,
        "n_features": n_features,
        "output_shape": output_shape,
        "test_vectors": test_vectors,
    }

    ref_path = out_dir / "reference.json"
    ref_path.write_text(json.dumps(reference, indent=2))
    print(f"  Wrote {ref_path}")

    # Cleanup fhe_model directory (keep client.zip + server.zip + reference.json)
    shutil.rmtree(fhe_dir)
    print("  Cleaned up fhe_model/")

    if used_fallback:
        print("  WARNING: Fallback post-processing was used for some vectors")

    print("  SUCCESS")


if __name__ == "__main__":
    model_name = sys.argv[1]
    config_json = sys.argv[2]
    base_dir = sys.argv[3]
    config = json.loads(config_json)
    process_model(model_name, config, base_dir)
'''


def main():
    base_dir = Path(__file__).parent
    python = sys.executable
    success_count = 0
    failed = []

    for model_name, config in MODELS.items():
        log.info("=" * 60)
        log.info(f"Processing: {model_name} (subprocess)")
        log.info("=" * 60)

        # Write worker script to temp file
        worker_path = base_dir / "_worker.py"
        worker_path.write_text(WORKER_SCRIPT)

        config_json = json.dumps(config)

        # Retry up to 5 times for non-deterministic LLVM segfaults
        max_retries = 5
        for attempt in range(1, max_retries + 1):
            result = subprocess.run(
                [python, str(worker_path), model_name, config_json, str(base_dir)],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.stdout:
                print(result.stdout, end="")
            if result.stderr:
                print(result.stderr, end="", file=sys.stderr)

            if result.returncode == 0:
                success_count += 1
                break
            elif result.returncode in (-11, 139, -6):
                log.warning(
                    f"  Attempt {attempt}/{max_retries}: segfault/abort for {model_name}"
                )
                if attempt == max_retries:
                    log.error(f"  FAILED after {max_retries} attempts: {model_name}")
                    failed.append((model_name, "SEGFAULT"))
            else:
                log.error(f"  FAILED (exit {result.returncode}) for {model_name}")
                failed.append((model_name, f"exit {result.returncode}"))
                break

    # Cleanup worker
    worker_path = base_dir / "_worker.py"
    if worker_path.exists():
        worker_path.unlink()

    log.info(f"\nResults: {success_count}/{len(MODELS)} succeeded")
    if failed:
        log.error(f"Failed models: {failed}")
        sys.exit(1)
    else:
        log.info("All models generated successfully!")


if __name__ == "__main__":
    main()
