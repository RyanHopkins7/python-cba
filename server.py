from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography import x509
import os
import datetime

server_common_name = "localhost"
server_key = Ed25519PrivateKey.generate()
server_certificate = x509.CertificateBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, server_common_name),
])).issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, server_common_name),
])).not_valid_before(
    datetime.datetime.today() - datetime.timedelta(days=1)
).not_valid_after(
    datetime.datetime.today() + datetime.timedelta(days=30)
).serial_number(
    x509.random_serial_number()
).public_key(
    server_key.public_key()
).add_extension(
    x509.BasicConstraints(ca=True, path_length=0),
    critical=True,
).add_extension(
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    ),
    critical=True,
).add_extension(
    x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
    critical=False,
).sign(server_key, None)

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
@app.route("/csr", methods=["POST"])
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
    
    certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])).issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, server_common_name),
    ])).not_valid_before(
        datetime.datetime.today() - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.today() + datetime.timedelta(days=30)
    ).serial_number(
        x509.random_serial_number()
    ).public_key(
        csr.public_key()
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(server_key, None)

    return jsonify({"result": "sucess", "certificate": certificate.public_bytes(Encoding.PEM).decode("utf-8")})

# Generate and return authentication challenge
@app.route("/challenge", methods=["POST"])
def challenge():
    username = request.json["username"]
    rand = os.urandom(16)
    expiration = datetime.datetime.now() + datetime.timedelta(minutes=5)

    if username not in app_data:
        return jsonify({"result": "fail", "reason": "username_not_found"})
    
    app_data[username]["challenge"] = rand
    app_data[username]["challenge_expires"] = expiration
    
    return jsonify({"result": "success", "challenge": rand.hex()})

# Verify client certificate and challenge signature
@app.route("/login", methods=["POST"])
def login():
    username = request.json["username"]
    client_certificate = x509.load_pem_x509_certificate(request.json["certificate"].encode("utf-8"))
    challenge_signature = bytes.fromhex(request.json["signed_challenge"])

    try:
        client_certificate.verify_directly_issued_by(server_certificate)
    except (ValueError, InvalidSignature):
        return jsonify({"result": "fail", "reason": "invalid_certificate"})
    
    if client_certificate.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc):
        return jsonify({"result": "fail", "reason": "certificate_expired"})
    
    common_name = client_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if common_name != username:
        return jsonify({"result": "fail", "reason": "invalid_common_name"})
    
    challenge_data = app_data[common_name]["challenge"]
    challenge_expiration = app_data[common_name]["challenge_expires"]

    if challenge_expiration < datetime.datetime.now():
        return jsonify({"result": "fail", "reason": "challenge_expired"})
    
    try:
        client_certificate.public_key().verify(challenge_signature, challenge_data)
    except InvalidSignature:
        return jsonify({"result": "fail", "reason": "invalid_challenge_signature"})
    
    return jsonify({"result": "success"})
