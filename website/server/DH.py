from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_keys(UPLOAD_FOLDER):
    # Generate an elliptic curve key pair
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    # Serialize the public key to send to the other party
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Serialize the private key to send to the other party
    serialized_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    # Save the private key to a file
    with open(UPLOAD_FOLDER + 'keys/private_key.pem', 'wb') as f:
        f.write(serialized_private_key)

    # Save the public key to a file
    with open(UPLOAD_FOLDER + 'keys/public_key.pem', 'wb') as f:
        f.write(serialized_public_key)
