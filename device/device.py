import socket
import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID

# Generate RSA key pair
def generate_device_key_pair():
    if os.path.exists("device_private_key.pem") and os.path.exists("device_public_key.pem"):
        print("[Device] Key pair already exists. Skipping generation.")
        return

    print("[Device] Generating RSA key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("device_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("device_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[Device] Key pair generated and saved.")

# Generate CSR
def generate_device_csr():
    if os.path.exists("device_csr.pem"):
        print("[Device] CSR already exists. Skipping generation.")
        return

    print("[Device] Generating CSR...")
    with open("device_private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyDevice"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Device 001"),
    ])).sign(private_key, hashes.SHA256())

    with open("device_csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("[Device] CSR generated and saved.")

# Create Hello message (with type)
def create_hello_message(cert_path):
    with open(cert_path, "rb") as f:
        cert_pem = f.read()

    nonce = os.urandom(32)
    hello_msg = {
        "type": "hello",
        "certificate": base64.b64encode(cert_pem).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }
    return hello_msg, nonce


def verify_certificate(cert: x509.Certificate, ca_cert_path: str):
    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Get CA's public key
    ca_public_key = ca_cert.public_key()

    # Verify that the certificate was signed by the CA
    try:
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),  # RSA padding
            cert.signature_hash_algorithm
        )
        print("[✓] Certificate is valid and signed by the CA.")
        return True
    except Exception as e:
        print("[✗] Certificate verification failed:", e)
        return False

# Main device logic
def device_main():
    generate_device_key_pair()
    generate_device_csr()
    host = 'localhost'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("[Device] Connected to server.")

        # Step 1: Send Hello (certificate + nonce)
        hello_data, my_nonce = create_hello_message("device_cert.pem")
        s.sendall(json.dumps(hello_data).encode())

        # Step 2: Receive Hello from server
        response = s.recv(4096).decode()
        server_hello = json.loads(response)

        if server_hello.get("type") != "hello":
            raise ValueError("Unexpected message type from server!")

        server_cert = x509.load_pem_x509_certificate(base64.b64decode(server_hello["certificate"]))
        server_nonce = base64.b64decode(server_hello["nonce"])

        print("[Device] Received server certificate and nonce.")
        server_cert = x509.load_pem_x509_certificate(base64.b64decode(server_hello["certificate"]))
        if not verify_certificate(server_cert, "../ca/ca_certificate.pem"):
            raise ValueError("Server certificate verification failed!")

if __name__ == "__main__":
    device_main()
