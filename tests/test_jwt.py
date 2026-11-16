import base64, hashlib, hmac, json, time
import jwt, pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ISS, AUD = "demka-auth", "demka-api"
ALGS = ["EdDSA"]

@pytest.fixture
def keys():
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()

def make_token(priv, **overrides):
    now = int(time.time())
    claims = {"sub":"urmat", "iss":ISS, "aud":AUD, "iat":now, "exp":now + 300}
    claims.update(overrides)
    return jwt.encode(claims, priv, algorithm="EdDSA")

def decode(token, pub):
    return jwt.decode(token, pub, algorithms=ALGS, issuer=ISS, audience=AUD, options={"require": ["exp", "iat", "iss", "aud"]})

def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")

def test_valid_token(keys):
    priv, pub = keys
    assert decode(make_token(priv), pub)["sub"] == "urmat"

def test_alg_none(keys):
    _, pub = keys
    forged = jwt.encode({"sub":"admin", "iss":ISS, "aud":AUD}, key=None, algorithm="none")
    with pytest.raises(jwt.InvalidTokenError):
        decode(forged, pub)

def test_tampered_claims(keys):
    priv, pub = keys
    header, payload, sig = make_token(priv).split(".")
    padded = payload + "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    claims["sub"] = "admin"
    evil = b64(json.dumps(claims).encode()).decode()
    with pytest.raises(jwt.InvalidSignatureError):
        decode(f"{header}.{evil}.{sig}", pub)

def test_wrong_key(keys):
    _, pub = keys
    attacker = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(jwt.InvalidSignatureError):
        decode(make_token(attacker), pub)

def test_expired(keys):
    priv, pub = keys
    old = int(time.time()) - 1000
    with pytest.raises(jwt.ExpiredSignatureError):
        decode(make_token(priv, iat=old - 300, exp=old), pub)

def test_wrong_audience(keys):
    priv, pub = keys
    with pytest.raises(jwt.InvalidAudienceError):
        decode(make_token(priv, aud="someone-else"), pub)

def test_alg_confusion(keys):
    _, pub = keys
    pub_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time())
    header = b64(json.dumps({"alg":"HS256", "typ":"JWT"}).encode())
    body = b64(json.dumps({"sub":"admin", "iss":ISS, "aud":AUD, "iat":now, "exp":now + 300}).encode())
    signing_input = header + b"." + body
    sig = b64(hmac.new(pub_pem, signing_input, hashlib.sha256).digest())
    forged = (signing_input + b"." + sig).decode()
    with pytest.raises(jwt.InvalidTokenError):
        decode(forged, pub)