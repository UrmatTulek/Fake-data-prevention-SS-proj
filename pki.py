import os
from dataclasses import dataclass
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import ca

SERVER_CN = "demka-server"

@dataclass
class PKI:
    root_cert: x509.Certificate
    server_cert: x509.Certificate
    server_key: ed25519.Ed25519PrivateKey
    jwt_key: ed25519.Ed25519PrivateKey

def generate() -> PKI:
    root_key, root_cert = ca.make_root()
    server_key = ed25519.Ed25519PrivateKey.generate()
    server_cert = ca.issue_cert(root_key, root_cert, SERVER_CN, server_key.public_key())
    return PKI(root_cert, server_cert, server_key, ed25519.Ed25519PrivateKey.generate())

def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

def save(p:PKI, folder="pki"):
    os.makedirs(folder, exist_ok=True)
    files = {
        "root.pem": ca.cert_to_pem(p.root_cert),
        "server.pem": ca.cert_to_pem(p.server_cert),
        "server.key": _key_pem(p.server_key),
        "jwt.key": _key_pem(p.jwt_key)
    }
    for name, data in files.items():
        with open(os.path.join(folder, name), "wb") as f:
            f.write(data)

def load(folder="pki") -> PKI:
    def read(name):
        with open(os.path.join(folder, name), "rb") as f:
            return f.read()
    return PKI(
        ca.pem_to_cert(read("root.pem")),
        ca.pem_to_cert(read("server.pem")),
        serialization.load_pem_private_key(read("server.key"), password=None),
        serialization.load_pem_private_key(read("jwt.key"), password=None)
    )

if __name__ == "__main__":
    save(generate())
    print("PKI written to ./pki")