# Secure Device-to-Server Communication

## Project Description
This project aims to provide secure data transmission between a device and a server. It implements security measures such as authentication, data encryption, and integrity checks to ensure safe communication. The project is designed especially for secure communication between IoT devices and central servers.

## Folder Structure
- **ca/**: Certificate Authority (CA) related files and keys.
- **device_server/**: Device-side and server-side application code, keys, and log files.
- **img/**: Sample image and video files for testing.

##  Files and Their Functions
- **ca.py**: Contains functions for generating the CA key(ca_private_key.pem) and certificate(ca_certificate.pem).
  <br></br>

- **sign_csr.py**: Handles the signing of device and server keys with the CA using the CA's private key.
  <br></br>
- **device.py**: Implements the device-side logic for secure communication, including key generation/verification, data encryption/decryption, and sending data to the server.
    - `generate_device_rsa_key_pair()`: Generates the device's RSA private and public keys.
    - `create_device_csr()`: Creates a Certificate Signing Request (CSR) for the device.
    - `hello_message(cert_path)`: Generates a hello message to be sent to the server.
    - `verify_server_certificate(cert, ca_cert_path)`: Verifies the server's certificate with the CA's certificate.
    - `ecdh_key_aggrement(sock, is_server, local_nonce, remote_nonce)`: Performs Elliptic Curve Diffie-Hellman key agreement. P2P communication.
    - `image_sign(image_path, private_key)`: Signs an image file using the device's private key.
    - `check_and_update_keys(shared_secret, info_prefix, message_count, update_counter)`: Checks and updates the device's keys according to message counts.
  <br></br>
  
- **server.py**: Implements the server-side logic for secure communication, including key generation/verification, data encryption/decryption, and handling incoming data from devices.
    - `generate_server_rsa_key_pair()`: Generates the server's RSA private and public keys.
    - `create_server_csr()`: Creates a Certificate Signing Request (CSR) for the server.
    - `hello_message(cert_path)`: Generates a hello message to be sent to the device.
    - `verify_device_certificate(cert, ca_cert_path)`: Verifies the device's certificate with the CA's certificate.
    - `ecdh_key_aggrement(sock, is_server, local_nonce, remote_nonce)`: Performs Elliptic Curve Diffie-Hellman key agreement. P2P communication.
    - `receive_all_data(sock)`: Receives and processes using loop data sent from the device.
    - `check_and_update_keys(shared_secret, info_prefix, message_count, update_counter)`: Checks and updates the server's keys according to message counts.
  <br></br>

- **crypto_utils.py**: Contains utility functions for cryptographic operations such as encryption and decryption.
    - `encrypt_and_mac(message, key, mac_key, iv)`: Encrypts a message and appends HMAC for integrity.
    - `decrypt_and_verify(ciphertext, key, mac_key, iv)`: Decrypts and verifies the MAC of a received message.
  <br></br>
### Log Files
- **device_log.txt**: Records all significant events, errors, and actions performed by the device during operation. This includes key generation, certificate handling, data transmission, encryption/decryption steps, and any exceptions or warnings encountered.
  <br></br>
- **server_log.txt**: Logs all important server-side activities, such as incoming connections, certificate verification, data reception, decryption, signature verification, and error handling. These logs are useful for auditing, debugging, and monitoring the security and health of the communication process.

## Key Features
- Separate key and certificate generation for device and server: Each device and server generates its own unique RSA key pair and certificate to ensure individual authentication and secure communication.
- Signing requests from device and server with the CSR: Devices and servers create Certificate Signing Requests (CSR) to be signed by the Certificate Authority, establishing trust in the public key infrastructure.
- Certificate signing and verification: All certificates are signed by the CA and verified during communication to prevent unauthorized entities from participating.
- RSA-based encryption and signing: RSA is used for encrypting sensitive data and digitally signing files, ensuring confidentiality, authenticity, and non-repudiation.
- Ensuring confidentiality and integrity during file and data transfer: Especially for images and video files sent from the device to the server, all media is encrypted and protected with HMAC for integrity. Image files are signed with the device's private key, and the server verifies the signature to ensure authenticity. During transfer, all media files are encrypted and a MAC is appended for integrity verification, preventing unauthorized access and data manipulation.
- Secure key exchange and update mechanism: The project uses Elliptic Curve Diffie-Hellman (ECDH) for secure key agreement between device and server. Nonces and initialization vectors (IVs) are used to ensure freshness and randomness in each session. After a certain number of messages, session keys are updated using the shared secret and counters, providing forward secrecy and enhanced security against replay attacks.

## Installation and Usage
1. Install the required Python packages:
   ```
   pip install -cryptography
   ```
   ```
   pip install -pycryptodome
   ```
   Ensure you have Python 3.x installed on your system.
   You can check your Python version by running:
   ```
   python --version
   ```
    If you need to install Python, you can download it from [python.org](https://www.python.org/downloads/).
  <br></br>

2. Download the project files from the repository.
3. Navigate to the project directory in your terminal or command prompt.
4. Run the CA script to generate the CA key and certificate:
   ```
   python ca/ca.py
   ```
5. Generate the device and server keys and certificates:  
   ```
   python device_server/sign_csr.py
   ```
   - You should run this script after the CA script to ensure the CA's key and certificate are available for signing.
  <br></br>
6. Ensure the device and server directories contain the necessary keys and certificates:
   - Device: `device_private_key.pem`, `device_public_key.pem`, `device_certificate.pem`
   - Server: `server_private_key.pem`, `server_public_key.pem`, `server_certificate.pem`
   - CA: `ca_private_key.pem`, `ca_certificate.pem`
  <br></br>
7. Place any sample images or videos you want to test in the `img/` directory.
8. Run the device and server scripts in separate terminal windows:
  <br></br>
   - Server: 
     ```
     python device_server/server.py
     ```
   - Device: 
     ```
     python device_server/device.py
     ```
     - You should run the server script first to ensure it is ready to accept connections from the device.


## Security
- All keys and certificates should be stored securely and locally.
- The Certificate Authority (CA) private key must be kept confidential.
- Ensure that the device and server private keys are not shared or exposed to unauthorized parties.
- Regularly update and rotate keys to maintain security.
