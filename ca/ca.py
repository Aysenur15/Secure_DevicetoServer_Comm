# ca/ca.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID, CertificateBuilder
from cryptography import x509
import datetime

def generate_ca_certificate():
    # CA key
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_public_key = ca_key.public_key()

    # CA self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyCA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"My CA Root"),
    ])

    cert = CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        ca_public_key
    ).serial_number(x509.random_serial_number()
    ).not_valid_before(datetime.datetime.utcnow()
    ).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_key, hashes.SHA256())

    # Save keys and certs
    with open("ca_private_key.pem", "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("ca_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("CA certificate and private key generated.")

if __name__ == "__main__":
    generate_ca_certificate()
