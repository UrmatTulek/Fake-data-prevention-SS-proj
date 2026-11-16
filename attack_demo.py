import jwt
import pki
import os
from dotenv import load_dotenv
from fastapi.testclient import TestClient
from server import create_app, ISS, AUD
from client import SecureClient, VerificationError
load_dotenv()

def naive_accept(body):
    return body["envelope"]["payload"]

def attempt(label, fn):
    try:
        print(f" [ACCEPTED] {label}: {fn()}")
    except VerificationError as e:
        print(f" [REJECTED] {label}: {e}")

p = pki.generate()
http = TestClient(create_app(p))
name, _, password = os.environ["DEMO_USERS"].split(",")[0].partition(":")
client = SecureClient("", p.root_cert, http=http)
client.login(name, password)

def fetch():
    r = http.get("/data", headers={"Authorization": f"Bearer {client.token}"})
    print(r.status_code, r.text[:200])
    return r.json()

print("\n==Attack 1: man-in-the-middle changes the sensor value==")
body = fetch()
body["envelope"]["payload"]["reading"]["celsius"] = 99.0
print(" [ACCEPTED] naive client: ", naive_accept(body))
attempt("secure client", lambda:client.verify_response(body))

print("\n==Attack 2: replay of the message==")
body = fetch()
client.verify_response(body)
print(" [ACCEPTED] naive client(again): ", naive_accept(body))
attempt("secure client(second time)", lambda: client.verify_response(body))

print("\n==Attack 3: fake server with CA==")
rogue = pki.generate()
rogue_client = SecureClient("", p.root_cert, http=TestClient(create_app(rogue)))
rogue_client.login(name, password)
rogue_body = rogue_client.http.get("/data", headers={"Authorization": f"Bearer {rogue_client.token}"}).json()
print(" [ACCEPTED] naive client: ", naive_accept(rogue_body))
attempt("secure client", lambda: client.verify_response(rogue_body))

print("\n==Attack 4: forged JWT (alg=none)==")
forged = jwt.encode({"sub":"admin", "iss": ISS, "aud": AUD}, key=None, algorithm="none")
r = http.get("/data", headers={"Authorization": f"Bearer {forged}"})
print(f" server response: HTTP {r.status_code} {r.json()}")