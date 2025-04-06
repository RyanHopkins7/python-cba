from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding
import sys
import requests
import json

# Usage: python client.py http://server-ip:port
if __name__ == "__main__":
    server = sys.argv[1]
    username = "bob"
    password = "p@55w0rd"

    print("Register account")
    r = requests.post(server + "/register", json={"username": username, "password": password})
    print(json.dumps(r.json(), indent=4))

    print("Generate client key and CSR")
    client_key = Ed25519PrivateKey.generate()
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(client_key, None)

    print("Send CSR to server")
    r = requests.post(server + "/auth/csr", json={
        "username": username, 
        "password": password,
        "csr": csr.public_bytes(Encoding.PEM).decode("utf-8")
    })
    print(json.dumps(r.json(), indent=4))
