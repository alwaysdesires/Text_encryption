# Text_encryption
🔐 Text Encryption: Secure Communication with Cryptography Algorithms
Text Encryption is a Python project that provides a comprehensive set of cryptographic functionalities for secure communication. It includes encryption and decryption algorithms such as AES, DES, and RSA, allowing users to protect their data with robust encryption techniques.

# Features:
🛡️ AES Encryption: Advanced Encryption Standard (AES) algorithm for secure symmetric encryption.
🔒 DES Encryption: Data Encryption Standard (DES) algorithm for symmetric encryption with a shorter key length.
📡 RSA Encryption: Rivest-Shamir-Adleman (RSA) algorithm for asymmetric encryption, enabling secure key exchange.
🌐 Cross-platform: Works seamlessly on Windows, macOS, and Linux.
# Usage:
Clone the repository to your local machine:
bash
Copy code
git clone https://github.com/alwaysdesires/Text_encryption.git
Navigate to the project directory:
bash
Copy code
cd Text_encryption
Use the provided functions to encrypt and decrypt your data using AES, DES, or RSA algorithms.
Example:
python
Copy code
# Generate encryption keys
aes_key = generate_aes_key()
des_key = generate_des_key()
rsa_private_key, rsa_public_key = generate_rsa_keys()

# Encrypt data
aes_ciphertext, aes_nonce, aes_tag = aes_encrypt(aes_key, plaintext)
des_ciphertext = des_encrypt(des_key, plaintext)
rsa_ciphertext = rsa_encrypt(rsa_public_key, plaintext)

# Decrypt data
decrypted_aes = aes_decrypt(aes_key, aes_nonce, aes_ciphertext, aes_tag)
decrypted_des = des_decrypt(des_key, des_ciphertext)
decrypted_rsa = rsa_decrypt(rsa_private_key, rsa_ciphertext)
Contribution:
Contributions are welcome! Feel free to fork the repository, make improvements, and submit pull requests to enhance Text Encryption.

Enhance your data security with Text Encryption! 🛡️🔐
