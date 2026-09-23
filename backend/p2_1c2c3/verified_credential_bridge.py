"""Internal one-shot adapter: existing Python verifier -> normalized session result.

This is NOT an HTTP endpoint, login provider, JWKS fetcher, DB client, or production
process model. It exists to connect the already-tested signed verifier to the
JavaScript durable-session contract without reimplementing JWT verification.
Trusted server configuration and the bearer credential arrive on stdin; failures
emit only stable categories and never echo tokens or key material.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives.serialization import load_pem_public_key

BASE = Path(__file__).resolve().parents[1] / "p2_1c2b1"
sys.path.insert(0, str(BASE))

from identity_boundary import BoundaryError, Config, verify_credential  # noqa: E402

MAX_INPUT = 65536
INPUT_KEYS = {"credential", "issuer", "audience", "key_set_version", "keys"}


def _read_request() -> dict:
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if not raw or len(raw) > MAX_INPUT:
        raise ValueError("invalid bridge input")
    value = json.loads(raw.decode("utf-8"))
    if type(value) is not dict or set(value) != INPUT_KEYS:
        raise ValueError("invalid bridge input")
    if type(value["keys"]) is not dict or not 1 <= len(value["keys"]) <= 16:
        raise ValueError("invalid key set")
    return value


def main() -> int:
    try:
        request = _read_request()
        keys = {}
        for kid, pem in request["keys"].items():
            if type(kid) is not str or type(pem) is not str:
                raise ValueError("invalid key config")
            keys[kid] = load_pem_public_key(pem.encode("ascii"))
        config = Config(
            issuer=request["issuer"],
            audience=request["audience"],
            key_set_version=request["key_set_version"],
            keys=keys,
        )
        credential = request["credential"]
        if type(credential) is not str or not credential:
            raise ValueError("credential required")
        result = verify_credential(config, "Bearer " + credential).as_session_result()
        sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=True))
        return 0
    except BoundaryError:
        sys.stderr.write("IDENTITY_REJECTED\n")
        return 2
    except Exception:
        sys.stderr.write("BRIDGE_REJECTED\n")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
