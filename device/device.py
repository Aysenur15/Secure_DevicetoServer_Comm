import socket
import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from crypto_utils import encrypt_and_mac, decrypt_and_verify
import time


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

def ecdh_key_agreement(sock, is_server, local_nonce, remote_nonce):
    # ECDH key pair generation
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = private_key.public_key().public_bytes(
        encoding = serialization.Encoding.X962,
        format = serialization.PublicFormat.UncompressedPoint
    )
    # Public key send/receive protocol:
    if is_server:
        # Server sends first, then receives
        msg = {"type": "ecdh_pubkey", "key": base64.b64encode(public_bytes).decode()}
        sock.sendall(json.dumps(msg).encode())
        data = json.loads(sock.recv(4096).decode())
        peer_pub_bytes = base64.b64decode(data["key"])
    else:
        # Device receives first, then sends
        data = json.loads(sock.recv(4096).decode())
        peer_pub_bytes = base64.b64decode(data["key"])
        msg = {"type": "ecdh_pubkey", "key": base64.b64encode(public_bytes).decode()}
        sock.sendall(json.dumps(msg).encode())

    # Create peer public key object
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub_bytes)
    # Calculate shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive session keys and IV
    info_prefix = local_nonce + remote_nonce
    def hkdf(info, length):
        return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info+info_prefix).derive(shared_secret)
    k1 = hkdf(b"key_device_to_server", 32)
    k2 = hkdf(b"key_server_to_device", 32)
    mac1 = hkdf(b"mac_device", 32)
    mac2 = hkdf(b"mac_server", 32)
    iv = hkdf(b"iv", 16)
    return k1, k2, mac1, mac2, iv

## Main function to run the device
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

        k1, k2, mac1, mac2, iv = ecdh_key_agreement(s, is_server=False, local_nonce=my_nonce, remote_nonce=server_nonce)
        print("[Device] Device→Server key:", k1.hex())
        print("[Device] Server→Device key:", k2.hex())
        print("[Device] MAC keys:", mac1.hex(), mac2.hex())
        print("[Device] IV:", iv.hex())


        # Send encrypted message to server
        plaintext_msg = "Hello from Device (one-time encrypted)"
        ciphertext = encrypt_and_mac(plaintext_msg, k1, mac1, iv)
        s.sendall(ciphertext)
        print("[Device] Encrypted message sent.")

        # Receive encrypted ACK from server
        cipher_reply = s.recv(4096)
        decrypted_reply = decrypt_and_verify(cipher_reply, k2, mac2, iv)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[Device] Received from server: {decrypted_reply} at {timestamp}")

        with open("device_log.txt", "a") as f:
            f.write(f"[{timestamp}] {decrypted_reply}\n")


if __name__ == "__main__":
    device_main()
