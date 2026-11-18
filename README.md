# Preventing Fake Data with Conventional Cryptography

A System Security course project. It shows how digital signatures, X.509
certificates and JWT work together so that a client accepts data **only** if it
is authentic, unmodified and fresh.

Built with Python, FastAPI and the `cryptography` and `PyJWT` libraries. No
cryptographic primitives are implemented by hand.

## The problem

A client receives data from a server over a network that an attacker can
read and modify. The client must be able to answer:

1. Did this data really come from the server I expect?
2. Was it modified on the way?
3. Is it a fresh message, or an old one being replayed?
4. Is the caller allowed to ask for it at all?

## Threat model

| # | Attack | Defense | Test |
|---|--------|---------|------|
| 1 | Data tampering in transit | Ed25519 signature over canonical JSON | `test_tampered_payload` |
| 2 | Replay of a captured message | Signed timestamp + nonce tracking | `test_replay` |
| 3 | Fake server with its own CA | Client trusts only the root certificate | `test_rogue_server` |
| 4 | Stolen certificate (no private key) | Signature must verify with the certificate's key | `test_stolen_cert_without_priv` |
| 5 | Forged / unsigned JWT (`alg: none`) | Pinned algorithm list, signature check | `test_alg_none` |
| 6 | Expired token or certificate | `exp` claim, certificate validity dates | `test_expired_token`, `test_cert_expired`, `test_expired` |
| 7 | Token reused for another service | `iss` and `aud` claims checked | `test_wrong_audience` |
| 8 | Algorithm confusion | `alg` claim is checked | `test_alg_confusion` |
| 9 | Attacker swapping nonce to bypass replay detection | CA signs the complete envelope which includes the nonce | `test_swapped_nonce` |

## How it works

```
Root CA key  --signs-->  Server certificate (contains the server public key)
                                  |
Server key   --signs-->  Envelope { payload, timestamp, nonce, signature }
                                  |
Client (trusts only root.pem):
   1. certificate was issued by the trusted root and is in date
   2. certificate subject is the expected server name
   3. signature on the envelope verifies with the certificate's public key
   4. timestamp is inside the allowed window
   5. nonce has not been seen before
```

Login uses a JWT signed with a **separate** key (`jwt.key`), so one key is
never used for two purposes.

## Project structure

```
ca.py              mini certificate authority (root + issued certificates, verification)
signing.py         sign / verify data envelopes (timestamp + nonce)
pki.py             generates, saves and loads keys and certificates
server.py          FastAPI app: POST /login, GET /data
main.py            entry point for uvicorn
client.py          verifying client (SecureClient)
demo.py            happy-path demo
attack_demo.py     attacks against a naive client vs. the secure client
tests/             pytest suite (certificates, JWT, end-to-end)
```

## Setup

```bash
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
python pki.py            # generates ./pki (keys and certificates)
```

## Run

Terminal 1 (server):

```bash
uvicorn main:app
```

Terminal 2 (client):

```bash
python demo.py           # login, fetch data, verify the whole chain
python attack_demo.py    # run the attacks (no server needed)
```

Interactive API docs: http://127.0.0.1:8000/docs

The demo users are defined in `server.py` (`USERS`).

## Tests

```bash
python -m pytest -v
```

Tests run the app in-process, so the server does not need to be running. Most
tests are negative tests: each one performs an attack and passes only if the
attack is rejected.

## Limitations

- No certificate revocation (CRL / OCSP).
- Private keys are stored unencrypted on disk (use an HSM or encrypted keystore in production).
- Nonces are kept in memory (a multi-server setup would need a shared store with expiry).
- The freshness window is sensitive to clock skew.
- Hardcoded demo users and no login rate limiting.
- The demo uses plain HTTP. Signatures give authenticity and integrity but not
  confidentiality, so a real deployment would also use TLS.
