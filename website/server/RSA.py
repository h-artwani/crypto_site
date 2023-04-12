from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_key_pair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Save private key to disk
    with open('../static/RSA_keys/private.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key to disk
    with open('../static/RSA_keys/public.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def encrypt_file(public_key_file, plaintext_file, ciphertext_file):
    # Read public key from disk
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
        )

    # Encrypt file with public key
    with open(plaintext_file, 'rb') as f:
        plaintext = f.read()

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

def decrypt_file(private_key_file, ciphertext_file, plaintext_file):
    # Read private key from disk
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
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
generate_key_pair()
encrypt_file('../static/RSA_keys/public.pem','./static/sample.txt','./static/sample_enc.txt')
decrypt_file('../static/RSA_keys/private.pem','./static/sample_enc.txt','./static/sample_dec.txt')