# server/server.py
import socket
import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import secrets

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

## Main function to run the server
def server_main():
    generate_server_key_pair()
    generate_server_csr()

    # upload server certificate
    with open("server_cert.pem", "r") as f:
        server_cert = f.read()
    # upload CA sertificate
    with open("ca_certificate.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Create random nonce
    server_nonce = secrets.token_bytes(16)
    server_nonce_b64 = base64.b64encode(server_nonce).decode()

    host = 'localhost'
    port = 12345
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("[Server] Waiting for connection...")
        conn, addr = s.accept()
        with conn:
            print(f"[Server] Connected by {addr}")

            # 1. Take the Hello message from the device
            data = conn.recv(4096).decode()
            hello = json.loads(data)

            # 2.
            device_cert = x509.load_pem_x509_certificate(hello["cert"].encode())
            if device_cert.issuer != ca_cert.subject:
                print("[Server] Certificate issuer is not valid.")
                conn.close()
                return
            print("[Server] Device certificate verificated.")

            # 3. Take Nonce
            device_nonce = base64.b64decode(hello["nonce"])
            print("[Server] Device nonce:", device_nonce.hex())

            # 4. Server sends its own Hello message
            server_hello = {
                "type": "hello",
                "cert": server_cert,
                "nonce": server_nonce_b64
            }
            conn.sendall(json.dumps(server_hello).encode())
            print("[Server] Hello message send.")

if __name__ == "__main__":
    server_main()
