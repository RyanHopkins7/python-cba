from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidKey
from cryptography.x509.oid import NameOID
from cryptography import x509
import os
import datetime

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
    
    if not csr.is_signature_valid:
        return jsonify({"result": "fail", "reason": "invalid_csr_signature"})
    
    common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if common_name != username:
        return jsonify({"result": "fail", "reason": "invalid_common_name"})
    
    one_day = datetime.timedelta(1, 0, 0)
    builder = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(csr.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    certificate = builder.sign(server_key, None)
    
    return jsonify({"result": "sucess", "certificate": certificate.public_bytes(Encoding.PEM).decode("utf-8")})
