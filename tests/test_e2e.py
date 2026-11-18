import time
import jwt, pytest
from fastapi.testclient import TestClient
import pki as pki_mod
from server import create_app, ISS, AUD
from client import SecureClient, VerificationError
from signing import sign_payload

@pytest.fixture
def env():
    p = pki_mod.generate()
    http = TestClient(create_app(p))
    client = SecureClient("", p.root_cert, http=http)
    client.login("alice", "wonderland")
    return p, http, client

def raw(client):
    r = client.http.get("/data", headers={"Authorization":f"Bearer {client.token}"})
    return r.json()

def test_accepted(env):
    _, _, client = env
    assert client.get_data()["user"] == "alice"

def test_wrong_password(env):
    _, http, _ = env
    r = http.post("/login", json={"username": "alice", "password": "nope"})
    assert r.status_code == 401

def test_no_token(env):
    _, http, _ = env
    assert http.get("/data").status_code == 401

def test_alg_none(env):
    _, http, _ = env
    forged = jwt.encode({"sub": "alice", "iss": ISS, "aud": AUD}, key=None, algorithm="none")
    r = http.get("/data", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401

def test_expired_token(env):
    p, http, _ = env
    old = int(time.time()) - 1000
    token = jwt.encode({"sub": "alice", "iss": ISS, "aud": AUD, "iat": old-300, "exp": old}, p.jwt_key, algorithm="EdDSA")
    assert http.get("/data", headers={"Authorization": f"Bearer {token}"}).status_code == 401

def test_tampered_payload(env):
    _, _, client = env
    body = raw(client)
    body["envelope"]["payload"]["reading"]["celsius"] = 99.0
    with pytest.raises(VerificationError):
        client.verify_response(body)

def test_replay(env):
    _, _, client = env
    body = raw(client)
    client.verify_response(body)
    with pytest.raises(VerificationError, match="replay"):
        client.verify_response(body)

def test_rogue_server(env):
    p, _, _ = env
    rogue = pki_mod.generate()
    rogue_client = SecureClient("", p.root_cert, http=TestClient(create_app(rogue)))
    rogue_client.login("alice", "wonderland")
    with pytest.raises(VerificationError):
        rogue_client.get_data()

def test_stolen_cert_without_priv(env):
    _, _, client = env
    body = raw(client)
    attacker_key = pki_mod.generate().server_key
    body["envelope"] = sign_payload(attacker_key, {"user": "alice", "reading": {"celsius": 99.0}})
    with pytest.raises(VerificationError):
        client.verify_response(body)

def test_swapped_nonce(env):
    _, _, client = env
    body = raw(client)
    client.verify_response(body)
    body["envelope"]["nonce"] = "0" * 32
    with pytest.raises(VerificationError, match="InvalidSignature"):
        client.verify_response(body)