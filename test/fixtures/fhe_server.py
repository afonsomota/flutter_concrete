#!/usr/bin/env python3
"""Long-lived FHE server process with JSON-lines protocol over stdin/stdout.

Replaces the one-shot fhe_server_helper.py subprocess approach to eliminate
MLIR non-determinism between requests. The server compiles each model once
on `load` and reuses the same compiled circuit for all subsequent `run` and
`encrypt_and_run` commands.

Protocol
--------
One JSON object per line on stdin, one JSON object per line on stdout.
All debug/log output goes to stderr. stdout is flushed after every response.

Commands:

  load
    → {"command": "load", "model_dir": "/abs/path/to/fixture/model"}
    ← {"status": "ok", "secret_key_b64": "...", "eval_key_b64": "..."}

  run
    → {"command": "run", "model_dir": "/abs/path", "encrypted_input_b64": "..."}
    ← {"status": "ok", "encrypted_result_b64": "...", "python_scores": [...]}

  encrypt_and_run
    → {"command": "encrypt_and_run", "model_dir": "/abs/path", "quantized_input": [3, 2, 4]}
    ← {"status": "ok", "encrypted_result_b64": "...", "python_scores": [...]}

  shutdown
    → {"command": "shutdown"}
    ← {"status": "ok"}

Requirements: concrete-ml == 1.9.0
"""

import base64
import json
import sys
import traceback

import numpy as np
import concrete.fhe as fhe
import concrete.ml
from concrete.ml.deployment import FHEModelClient, FHEModelServer

assert concrete.ml.__version__ == "1.9.0", (
    f"Expected concrete-ml 1.9.0, got {concrete.ml.__version__}"
)

# Loaded models: model_dir -> {"server": FHEModelServer, "client": FHEModelClient}
_models = {}


def _log(msg):
    print(msg, file=sys.stderr, flush=True)


def _respond(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _handle_load(req):
    model_dir = req["model_dir"]
    _log(f"[fhe_server] Loading model from {model_dir}")

    server = FHEModelServer(path_dir=model_dir)
    server.load()

    client = FHEModelClient(path_dir=model_dir)
    client.generate_private_and_evaluation_keys()

    # Extract raw LWE secret key for Dart
    secret_key_bytes = (
        client.client.keys._keyset
        .get_client_keys()
        .get_secret_keys()[0]
        .serialize()
    )
    secret_key_b64 = base64.b64encode(secret_key_bytes).decode()

    eval_key_b64 = base64.b64encode(
        client.get_serialized_evaluation_keys()
    ).decode()

    _models[model_dir] = {"server": server, "client": client}
    _log(f"[fhe_server] Model loaded: {model_dir}")

    _respond({
        "status": "ok",
        "secret_key_b64": secret_key_b64,
        "eval_key_b64": eval_key_b64,
    })


def _run_inference(model_dir, encrypted_input_bytes):
    """Run server inference and return (encrypted_result, python_scores)."""
    entry = _models[model_dir]
    server = entry["server"]
    client = entry["client"]

    eval_keys = fhe.EvaluationKeys.deserialize(
        client.get_serialized_evaluation_keys()
    )

    encrypted_result = server.run(encrypted_input_bytes, eval_keys)
    if isinstance(encrypted_result, tuple):
        encrypted_result = encrypted_result[0]

    # Python decrypt + dequantize + post-process
    raw_quant = client.deserialize_decrypt(encrypted_result)
    deq = client.model.dequantize_output(raw_quant)
    python_scores = client.model.post_processing(deq)

    return encrypted_result, python_scores


def _handle_run(req):
    model_dir = req["model_dir"]
    encrypted_input_bytes = base64.b64decode(req["encrypted_input_b64"])

    _log(f"[fhe_server] Running inference for {model_dir}")
    encrypted_result, python_scores = _run_inference(model_dir, encrypted_input_bytes)

    _respond({
        "status": "ok",
        "encrypted_result_b64": base64.b64encode(encrypted_result).decode(),
        "python_scores": python_scores.flatten().tolist(),
    })


def _handle_encrypt_and_run(req):
    model_dir = req["model_dir"]
    quantized_input = np.array(req["quantized_input"], dtype=np.float32).reshape(1, -1)

    entry = _models[model_dir]
    client = entry["client"]

    _log(f"[fhe_server] Encrypt-and-run for {model_dir}")

    # Python encrypts
    encrypted_input_bytes = client.quantize_encrypt_serialize(quantized_input)

    encrypted_result, python_scores = _run_inference(model_dir, encrypted_input_bytes)

    _respond({
        "status": "ok",
        "encrypted_result_b64": base64.b64encode(encrypted_result).decode(),
        "python_scores": python_scores.flatten().tolist(),
    })


def main():
    _log("[fhe_server] Started, waiting for commands...")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
            command = req.get("command", "")

            if command == "load":
                _handle_load(req)
            elif command == "run":
                _handle_run(req)
            elif command == "encrypt_and_run":
                _handle_encrypt_and_run(req)
            elif command == "shutdown":
                _respond({"status": "ok"})
                _log("[fhe_server] Shutting down.")
                sys.exit(0)
            else:
                _respond({
                    "status": "error",
                    "error": f"Unknown command: {command}",
                })
        except Exception as e:
            _respond({
                "status": "error",
                "error": f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
            })

    _log("[fhe_server] stdin closed, exiting.")


if __name__ == "__main__":
    main()
