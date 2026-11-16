import ca
import os
from dotenv import load_dotenv
from client import SecureClient
load_dotenv()

with open("pki/root.pem", "rb") as f:
    root = ca.pem_to_cert(f.read())

client = SecureClient("http://127.0.0.1:8000", root)
name, _, password = os.environ["DEMO_USERS"].split(",")[0].partition(":")
client.login(name, password)
print(client.get_data())