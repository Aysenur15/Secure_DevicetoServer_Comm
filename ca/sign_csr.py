from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta

# Function to sign a CSR and create a certificate
def sign_csr(csr_path, cert_path, ca_key_path, ca_cert_path):
    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Load CSR
    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())

    # Sign certificate
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(ca_private_key, hashes.SHA256())

    # Save certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Certificate created: {cert_path}")

# Sign CSRs for device and server
sign_csr("../device_server/device_csr.pem", "../device_server/device_cert.pem", "ca_private_key.pem", "ca_certificate.pem")
sign_csr("../device_server/server_csr.pem", "../device_server/server_cert.pem", "ca_private_key.pem", "ca_certificate.pem")

