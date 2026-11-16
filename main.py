from dotenv import load_dotenv
from server import create_app
import pki
load_dotenv()

app = create_app(pki.load())