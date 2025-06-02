# device/device.py
import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Generate a device RSA key pair if it doesn't exist
def generate_device_key_pair():
    private_key_path = "device_private_key.pem"
    public_key_path = "device_public_key.pem"

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print("[Device] Key pair already exists. Skipping generation.")
        return

    print("[Device] Generating RSA key pair...")
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

    print("[Device] Key pair generated and saved.")

# Generate a CSR for the device
def generate_device_csr():
    csr_path = "device_csr.pem"
    private_key_path = "device_private_key.pem"

    if os.path.exists(csr_path):
        print("[Device] CSR already exists. Skipping generation.")
        return

    print("[Device] Generating CSR...")
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyDevice"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Device 001"),
    ])).sign(private_key, hashes.SHA256())

    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("[Device] CSR generated and saved.")

def device_main():
    generate_device_key_pair()
    generate_device_csr()
    host = 'localhost'
    port = 12345

    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("[Device] Connected to server.")

        # Send Hello (example, just text for now)
        hello_msg = "Hello from Device"
        s.sendall(hello_msg.encode())

        # Receive Hello from serverTHe
        response = s.recv(1024).decode()
        print(f"[Device] Received: {response}")

if __name__ == "__main__":
    device_main()
