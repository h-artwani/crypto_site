from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_key_pair(UPLOAD_FOLDER):
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Save private key to disk
    with open(UPLOAD_FOLDER + 'keys/private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key to disk
    with open(UPLOAD_FOLDER + 'keys/public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def encrypt_file(public_key, plaintext_file, ciphertext_file):

    # Encrypt file with public key
    with open(plaintext_file, 'rb') as f:
         plaintext = f.read()

    public_key = serialization.load_pem_public_key(
             public_key,
         )
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write encrypted file to disk
    with open(ciphertext_file, 'wb') as f:
        f.write(ciphertext)

def decrypt_file(private_key, ciphertext_file, plaintext_file):
    
    private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
        )
    # Decrypt file with private key
    with open(ciphertext_file, 'rb') as f:
        ciphertext = f.read()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write decrypted file to disk
    with open(plaintext_file, 'wb') as f:
        f.write(plaintext)