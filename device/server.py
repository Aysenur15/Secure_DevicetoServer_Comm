# server/server.py
import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64
import json


# Generate a server RSA key pair if it doesn't exist
def generate_server_key_pair():
    private_key_path = "server_private_key.pem"
    public_key_path = "server_public_key.pem"
    # Check if keys already exist
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print("[Server] Key pair already exists. Skipping generation.")
        return
    # Generate RSA key pair
    print("[Server] Generating RSA key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save private key
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[Server] Key pair generated and saved.")

# Generate a server CSR for the server
def generate_server_csr():
    csr_path = "server_csr.pem"
    private_key_path = "server_private_key.pem"
    # Check if CSR already exists
    if os.path.exists(csr_path):
        print("[Server] CSR already exists. Skipping CSR generation.")
        return
    # Generate CSR
    print("[Server] Generating CSR...")
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyServer"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Server 001"),
    ])).sign(private_key, hashes.SHA256())
    # Save CSR
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("[Server] CSR generated and saved.")

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

## Main function to run the server
def server_main():
    generate_server_key_pair()
    generate_server_csr()

    host = 'localhost'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("[Server] Waiting for connection...")
        conn, addr = s.accept()
        with conn:
            print(f"[Server] Connected by {addr}")

            # Step 1: Receive Hello from device
            device_hello_raw = conn.recv(4096).decode()

            if not device_hello_raw.strip():  # Handle empty input safely
                raise ValueError("Received empty message from client")

            device_hello = json.loads(device_hello_raw)

            if device_hello.get("type") != "hello":
                raise ValueError("Unexpected message type from client!")

            device_cert = x509.load_pem_x509_certificate(
                base64.b64decode(device_hello["certificate"])
            )
            device_nonce = base64.b64decode(device_hello["nonce"])
            print("[Server] Received device certificate and nonce.")

            # Step 2: Send Hello back
            hello_data, my_nonce = create_hello_message("server_cert.pem")
            conn.sendall(json.dumps(hello_data).encode())

            device_cert = x509.load_pem_x509_certificate(base64.b64decode(device_hello["certificate"]))
            if not verify_certificate(device_cert, "../ca/ca_certificate.pem"):
                raise ValueError("Device certificate verification failed!")

if __name__ == "__main__":
    server_main()
