from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey
from cryptography import x509
import os

server_key = Ed25519PrivateKey.generate()
argon2_params = {
    "length": 32,
    "iterations": 2,
    "lanes": 1,
    "memory_cost": 19456,
    "ad": None,
    "secret": None,
}
app_data = {}
app = Flask(__name__)

# Register user with password
@app.route("/register", methods=["POST"])
def register():
    username = request.json["username"]
    password = request.json["password"]
    salt = os.urandom(16)
    kdf = Argon2id(
        salt=salt,
        **argon2_params
    )
    key = kdf.derive(password.encode('utf-8'))

    if username in app_data:
        return jsonify({"result": "fail", "reason": "user_exists"})
    
    app_data[username] = {
        "password": key,
        "salt": salt
    }
    return jsonify({"result": "sucess"})

# Authenticate with password, process CSR, and return signed client certificate
@app.route("/auth/csr", methods=["POST"])
def csr():
    username = request.json["username"]
    password = request.json["password"]
    csr = x509.load_pem_x509_csr(request.json["csr"].encode("utf-8"))

    if username not in app_data:
        return jsonify({"result": "fail", "reason": "username_not_found"})
    
    kdf = Argon2id(
        salt=app_data[username]["salt"],
        **argon2_params
    )
    
    try:
        kdf.verify(password.encode("utf-8"), app_data[username]["password"])
    except InvalidKey:
        return jsonify({"result": "fail", "reason": "invalid_password"})
    
    return jsonify({"result": "sucess"})
