from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac
import hashlib


def encrypt_and_mac(message: str, key: bytes, mac_key: bytes, iv: bytes) -> bytes:
    """
    Encrypt a message and append HMAC for integrity.

    Args:
        message: The plaintext message to encrypt.
        key: AES encryption key.
        mac_key: HMAC key for integrity.
        iv: Initialization vector for AES CBC.

    Returns:
        Encrypted message as bytes.
    """
    msg_bytes = message.encode()
    mac = hmac.new(mac_key, msg_bytes, hashlib.sha256).digest()
    payload = msg_bytes + mac
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(payload, AES.block_size))


def decrypt_and_verify(ciphertext: bytes, key: bytes, mac_key: bytes, iv: bytes) -> str:
    """
    Decrypt and verify the MAC of a received message.

    Args:
        ciphertext: The encrypted message with HMAC.
        key: AES decryption key.
        mac_key: HMAC key for integrity check.
        iv: Initialization vector.

    Returns:
        Decrypted plaintext message as string if MAC is valid.

    Raises:
        ValueError: If MAC verification fails.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    msg, received_mac = decrypted[:-32], decrypted[-32:]
    expected_mac = hmac.new(mac_key, msg, hashlib.sha256).digest()
    if not hmac.compare_digest(received_mac, expected_mac):
        raise ValueError("MAC verification failed!")
    return msg.decode()
