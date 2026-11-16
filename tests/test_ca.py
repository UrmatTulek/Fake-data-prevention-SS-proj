import datetime, pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
import ca

def make_server_cert(root_key, root_cert, **kw):
    server_key = ed25519.Ed25519PrivateKey.generate()
    return server_key, ca.issue_cert(root_key, root_cert, "server", server_key.public_key(), **kw)

def test_cert_accepted():
    root_key, root_cert = ca.make_root()
    _, cert = make_server_cert(root_key, root_cert)
    ca.verify_issued_by(cert, root_cert)

def test_cert_rejected():
    _, real_root = ca.make_root()
    rogue_key, rogue_root = ca.make_root()
    _, fake_cert = make_server_cert(rogue_key, rogue_root)
    with pytest.raises(InvalidSignature):
        ca.verify_issued_by(fake_cert, real_root)

def test_cert_expired():
    root_key, root_cert = ca.make_root()
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=60)
    _, cert = make_server_cert(root_key, root_cert, now=past, days=30)
    with pytest.raises(ValueError, match="expired"):
        ca.verify_issued_by(cert, root_cert)