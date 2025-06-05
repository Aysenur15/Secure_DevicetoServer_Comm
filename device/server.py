# server/server.py
import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from crypto_utils import encrypt_and_mac, decrypt_and_verify
import time


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

#
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
    info_prefix = remote_nonce + local_nonce
    def hkdf(info, length):
        return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info+info_prefix).derive(shared_secret)
    k1 = hkdf(b"key_device_to_server", 32)
    k2 = hkdf(b"key_server_to_device", 32)
    mac1 = hkdf(b"mac_device", 32)
    mac2 = hkdf(b"mac_server", 32)
    iv = hkdf(b"iv", 16)
    return k1, k2, mac1, mac2, iv,shared_secret,info_prefix


# Function to receive all data from a socket until the specified number of bytes is received
def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            break
        data += packet
    return data


def check_and_update_keys(shared_secret, info_prefix, message_count, update_counter):
    if message_count % 2 == 0:  # Update keys every 2 messages
        update_counter += 1

        def hkdf(info, length):
            return HKDF(
                algorithm=hashes.SHA256(),
                length=length,
                salt=None,
                info=info_prefix + info + update_counter.to_bytes(2, 'big')
            ).derive(shared_secret)

        k1 = hkdf(b"key_device_to_server", 32)
        k2 = hkdf(b"key_server_to_device", 32)
        mac1 = hkdf(b"mac_device", 32)
        mac2 = hkdf(b"mac_server", 32)
        iv = hkdf(b"iv", 16)

        print(f"[Key Update] Applied update #{update_counter}")
        print("New k1:", k1.hex())
        print("New k2:", k2.hex())
        print("New mac1:", mac1.hex())
        print("New mac2:", mac2.hex())
        print("New iv:", iv.hex())

        return (k1, k2, mac1, mac2, iv), update_counter
    else:
        return None, update_counter

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

            device_hello_raw = conn.recv(4096).decode()
            if not device_hello_raw.strip():
                raise ValueError("Received empty message from client")
            device_hello = json.loads(device_hello_raw)
            if device_hello.get("type") != "hello":
                raise ValueError("Unexpected message type from client!")

            device_nonce = base64.b64decode(device_hello["nonce"])
            print("[Server] Received device certificate and nonce.")

            hello_data, my_nonce = create_hello_message("server_cert.pem")
            conn.sendall(json.dumps(hello_data).encode())

            device_cert = x509.load_pem_x509_certificate(base64.b64decode(device_hello["certificate"]))
            if not verify_certificate(device_cert, "../ca/ca_certificate.pem"):
                raise ValueError("Device certificate verification failed!")

            k1, k2, mac1, mac2, iv, shared_secret, info_prefix = ecdh_key_agreement(
                conn, is_server=True, local_nonce=my_nonce, remote_nonce=device_nonce
            )
            message_count = 0
            update_counter = 0

            print("[Server] Device→Server key:", k1.hex())
            print("[Server] Server→Device key:", k2.hex())
            print("[Server] MAC keys:", mac1.hex(), mac2.hex())
            print("[Server] IV:", iv.hex())

            ciphertext = conn.recv(4096)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            with open("server_log.txt", "a") as f:
                f.write(f"[{timestamp}] Received ciphertext (text): {ciphertext.hex()}\n")

            plaintext = decrypt_and_verify(ciphertext, k1, mac1, iv).decode()
            print(f"[Server] Received from device: {plaintext} at {timestamp}")
            message_count += 1
            updated_keys, update_counter = check_and_update_keys(shared_secret, info_prefix, message_count,
                                                                 update_counter)
            if updated_keys:
                k1, k2, mac1, mac2, iv = updated_keys
                with open("server_log.txt", "a") as f:
                    f.write(f"[{timestamp}] Key update #{update_counter} applied.\n")

            response_msg = f"ACK: Received '{plaintext}'"
            cipher_response = encrypt_and_mac(response_msg, k2, mac2, iv)
            conn.sendall(cipher_response)
            print("[Server] Encrypted reply sent.")
            with open("server_log.txt", "a") as f:
                f.write(f"[{timestamp}] Sent ciphertext (ACK): {cipher_response.hex()}\n")

            message_count += 1
            updated_keys, update_counter = check_and_update_keys(shared_secret, info_prefix, message_count,
                                                                 update_counter)
            if updated_keys:
                k1, k2, mac1, mac2, iv = updated_keys
                with open("server_log.txt", "a") as f:
                    f.write(f"[{timestamp}] Key update #{update_counter} applied.\n")

            header = conn.recv(10)
            length = int(header.decode())
            print("Payload length to receive:", length)

            cipherimage = recv_all(conn, length)
            print("Actual received:", len(cipherimage))
            with open("server_log.txt", "a") as f:
                f.write(f"[{timestamp}] Received encrypted image payload of length: {length} bytes\n")

            payload_bytes = decrypt_and_verify(cipherimage, k1, mac1, iv)
            payload = json.loads(payload_bytes)
            message_count += 1
            updated_keys, update_counter = check_and_update_keys(shared_secret, info_prefix, message_count,
                                                                 update_counter)
            if updated_keys:
                k1, k2, mac1, mac2, iv = updated_keys
                with open("server_log.txt", "a") as f:
                    f.write(f"[{timestamp}] Key update #{update_counter} applied.\n")

            if payload["type"] == "image":
                image_data = base64.b64decode(payload["image"])
                signature = base64.b64decode(payload["signature"])
                device_public_key = device_cert.public_key()
                try:
                    device_public_key.verify(
                        signature,
                        image_data,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    print("[Server] ✓ Signature is valid. Image received successfully.")
                    with open("received_from_device.png", "wb") as f:
                        f.write(image_data)
                    with open("server_log.txt", "a") as f:
                        f.write(f"[{timestamp}] Image verified and saved as 'received_from_device.png'.\n")

                    message_count += 1
                    updated_keys, update_counter = check_and_update_keys(shared_secret, info_prefix, message_count,
                                                                         update_counter)
                    if updated_keys:
                        k1, k2, mac1, mac2, iv = updated_keys
                        with open("server_log.txt", "a") as f:
                            f.write(f"[{timestamp}] Key update #{update_counter} applied.\n")

                except Exception as e:
                    print("[Server] ✗ Signature is not valid:", e)


if __name__ == "__main__":
    server_main()


