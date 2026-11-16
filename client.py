import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
import ca
from signing import verify_envelope

class VerificationError(Exception):
    pass

class SecureClient:
    def __init__(self, base_url, root_cert, expected_cn="demka-server", http=None):
        self.http = http or httpx.Client(base_url=base_url)
        self.root_cert = root_cert
        self.expected_cn = expected_cn
        self.seen_nonces = set()
        self.token = None

    def login(self, username, password):
        r = self.http.post("/login", json={"username":username, "password": password})
        r.raise_for_status()
        self.token = r.json()["access_token"]

    def get_data(self):
        r = self.http.get("/data", headers={"Authorization": f"Bearer {self.token}"})
        r.raise_for_status()
        return self.verify_response(r.json())

    def verify_response(self, body:dict) -> dict:
        try:
            cert = ca.pem_to_cert(body["cert_pem"].encode())
            ca.verify_issued_by(cert, self.root_cert)
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if cn != self.expected_cn:
                raise ValueError(f"unexpected certificate subject {cn!r}")
            pub = cert.public_key()
            if not isinstance(pub, ed25519.Ed25519PublicKey):
                raise ValueError("unexpected key type")
            return verify_envelope(pub, body["envelope"], self.seen_nonces)
        except (InvalidSignature, ValueError, IndexError, KeyError, TypeError) as e:
            raise VerificationError(f"{type(e).__name__}: {e}") from e
        