from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import datetime

def make_name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

def make_root():
    now = datetime.datetime.now(datetime.timezone.utc)
    key = ed25519.Ed25519PrivateKey.generate()
    cert = (x509.CertificateBuilder()
            .subject_name(make_name("Demka CA"))
            .issuer_name(make_name("Demka CA"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, None))
    return key, cert

def issue_cert(root_key, root_cert, subject_cn, subject_pubkey, now=None, days=30):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder()
            .subject_name(make_name(subject_cn))
            .issuer_name(root_cert.subject)
            .public_key(subject_pubkey)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=days))
            .sign(root_key, None))

def verify_issued_by(cert, root_cert):
    now = datetime.datetime.now(datetime.timezone.utc)
    if cert.issuer != root_cert.subject:
        raise ValueError("wrong issuer")
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise ValueError("certificate expired (not valid)")
    bc = root_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not bc.ca:
        raise ValueError("issuer is not CA") 
    root_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes)

def cert_to_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)

def pem_to_cert(pem:bytes):
    return x509.load_pem_x509_certificate(pem)