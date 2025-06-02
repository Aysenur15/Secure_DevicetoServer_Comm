# server/server.py
import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

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

    #basic socket communication setup
    host = 'localhost'
    port = 12345

    # Set up server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("[Server] Waiting for connection...")
        conn, addr = s.accept()
        with conn:
            print(f"[Server] Connected by {addr}")

            # Receive Hello from device
            data = conn.recv(1024).decode()
            print(f"[Server] Received: {data}")

            # Send Hello back
            hello_msg = "Hello from Server"
            conn.sendall(hello_msg.encode())

if __name__ == "__main__":
    server_main()
