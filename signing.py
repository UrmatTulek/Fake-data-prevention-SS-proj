import json, time, secrets, base64
from cryptography.hazmat.primitives.asymmetric import ed25519

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def sign_payload(private_key, payload:dict) -> dict:
    envelope = {
        "payload": payload,
        "ts": int(time.time()),
        "nonce": secrets.token_hex(16),
    }
    sig = private_key.sign(canonical(envelope))
    envelope["sig"] = base64.b64encode(sig).decode()
    return envelope

def verify_envelope(public_key, envelope:dict, seen_nonce:set, max_age=60):
    sig = base64.b64decode(envelope["sig"])
    body = {k:envelope[k] for k in ("payload", "ts", "nonce")}
    public_key.verify(sig, canonical(body))
    if abs(time.time() - body["ts"]) > max_age:
        raise ValueError("stale message")
    if body["nonce"] in seen_nonce:
        raise ValueError("replay detected")
    seen_nonce.add(body["nonce"])
    return body["payload"]
