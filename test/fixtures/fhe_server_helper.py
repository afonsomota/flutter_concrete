#!/usr/bin/env python3
"""Lightweight FHE server subprocess for Dart integration tests.

Reads a JSON request from stdin, runs FHEModelServer.run(), and writes
the encrypted result as JSON to stdout.

Protocol:
  Request  (stdin):  { "server_dir": str, "evaluation_key_b64": str, "encrypted_input_b64": str }
  Response (stdout): { "encrypted_result_b64": str, "status": "ok" }
  Error    (stdout): { "error": str, "status": "error" }

Requirements: concrete-ml == 1.9.0
"""

import base64
import json
import sys
import traceback

def main():
    try:
        request = json.loads(sys.stdin.read())

        server_dir = request["server_dir"]
        eval_key_bytes = base64.b64decode(request["evaluation_key_b64"])
        encrypted_input = base64.b64decode(request["encrypted_input_b64"])

        import concrete.fhe as fhe
        from concrete.ml.deployment import FHEModelServer

        server = FHEModelServer(path_dir=server_dir)
        server.load()

        eval_keys = fhe.EvaluationKeys.deserialize(eval_key_bytes)
        encrypted_result = server.run(encrypted_input, eval_keys)

        if isinstance(encrypted_result, tuple):
            encrypted_result = encrypted_result[0]

        response = {
            "encrypted_result_b64": base64.b64encode(encrypted_result).decode(),
            "status": "ok",
        }
    except Exception as e:
        response = {
            "error": f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
            "status": "error",
        }

    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
