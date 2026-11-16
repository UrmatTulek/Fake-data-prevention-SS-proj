import hashlib, hmac, os, time
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Header, HTTPException
from pydantic import BaseModel
import ca
from signing import sign_payload
load_dotenv()

ISS = os.environ.get("JWT_ISSUER", "demo-auth")
AUD = os.environ.get("JWT_AUD", "demo-api")
ALGS = ["EdDSA"]
TOKEN_TTL = 300

def _hash(password:str, salt:bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)

def _load_users():
    users = {}
    for pair in filter(None, os.environ.get("DEMO_USERS", "").split(",")):
        name, _, password = pair.partition(":")
        salt = os.urandom(16)
        users[name] = (salt, _hash(password, salt))
    return users

class LoginRequest(BaseModel):
    username: str
    password: str

def create_app(pki) -> FastAPI:
    USERS = _load_users()
    app = FastAPI(title="System Security Encryption API")

    def current_user(authorization: str = Header(default="")) -> str:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(401, "missing bearer token")
        try:
            claims = jwt.decode(
                token, pki.jwt_key.public_key(),
                algorithms=ALGS, issuer=ISS, audience=AUD,
                options={"require":["exp", "iat", "iss", "aud", "sub"]}
            )
        except jwt.InvalidTokenError:
            raise HTTPException(401, "invalid token")
        return claims["sub"]

    @app.post("/login")
    def login(body: LoginRequest):
        record = USERS.get(body.username)
        salt, expected = record if record else (b"\0" * 16, b"\0" * 32)
        ok = hmac.compare_digest(_hash(body.password, salt), expected) and record is not None
        if not ok:
            raise HTTPException(401, "bad credentials")
        now = int(time.time())
        token = jwt.encode(
            {"sub": body.username, "iss": ISS, "aud": AUD, "iat": now, "exp": now + TOKEN_TTL},
            pki.jwt_key, algorithm="EdDSA" 
        )
        return {"access_token": token, "token_type": "bearer"}

    @app.get("/data")
    def data(user: str = Depends(current_user)):
        payload = {"user": user, "reading": {"sensor": "temp-1", "celsius": 21.5}}
        return {
            "envelope": sign_payload(pki.server_key, payload),
            "cert_pem": ca.cert_to_pem(pki.server_cert).decode()
        }
    return app