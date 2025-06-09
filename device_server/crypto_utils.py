from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac
import hashlib

# Encrypt a message with AES in CBC mode and append a HMAC for integrity
def encrypt_and_mac(message: str, key: bytes, mac_key: bytes, iv: bytes) -> bytes:
    # Convert message to bytes if it's a string
    if isinstance(message, str):
        msg_bytes = message.encode()
    else:
        msg_bytes = message

    mac = hmac.new(mac_key, msg_bytes, hashlib.sha256).digest()
    payload = msg_bytes + mac
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(payload, AES.block_size))

# Decrypt and verify the message, returning the original message if successful
def decrypt_and_verify(ciphertext: bytes, key: bytes, mac_key: bytes, iv: bytes) -> str:

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    msg, received_mac = decrypted[:-32], decrypted[-32:]
    expected_mac = hmac.new(mac_key, msg, hashlib.sha256).digest()
    if not hmac.compare_digest(received_mac, expected_mac):
        raise ValueError("MAC verification failed!")
    return msg # changed back to bytes for consistency
