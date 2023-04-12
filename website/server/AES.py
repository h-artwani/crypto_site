from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Function to pad the input data
def pad(data):
    block_size = 16
    padding_size = block_size - len(data) % block_size
    padding = bytes([padding_size] * padding_size)
    return data + padding

# Function to unpad the input data
def unpad(data):
    padding_size = data[-1]
    return data[:-padding_size]

# Function to encrypt a file using AES with a 128-bit key
def encrypt_file_128(input_file_path, output_file_path):

    key = Fernet.generate_key()[:44]
    # Initialize the Fernet object
    fernet = Fernet(key)

    # Read the input file
    with open(input_file_path, "rb") as input_file:
        input_data = input_file.read()

    padded_data = pad(input_data)

    # Encrypt the input data
    encrypted_data = fernet.encrypt(padded_data)

    # Write the encrypted data to the output file
    with open(output_file_path, "wb") as output_file:
        output_file.write(encrypted_data)
    return key

# Function to decrypt a file using AES with a 128-bit key
def decrypt_file_128(key, input_file_path, output_file_path):
    # Initialize the Fernet object
    fernet = Fernet(key)

    # Read the input file
    with open(input_file_path, "rb") as input_file:
        input_data = input_file.read()

    # Decrypt the input data
    decrypted_data = fernet.decrypt(input_data)

    unpadded_data = unpad(decrypted_data)

    # Write the decrypted data to the output file
    with open(output_file_path, "wb") as output_file:
        output_file.write(unpadded_data)

# Function to encrypt a file using AES with a 256-bit key
def encrypt_file_256(input_file_path, output_file_path):
    # Set the IV
    iv = b"0123456789abcdef"
    key = Fernet.generate_key()[:32]
    # Create the Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create the encryptor object
    encryptor = cipher.encryptor()

    # Read the input file
    with open(input_file_path, "rb") as input_file:
        input_data = input_file.read()

    padded_data = pad(input_data)

    # Encrypt the input data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the encrypted data to the output file
    with open(output_file_path, "wb") as output_file:
        output_file.write(encrypted_data)
    return key

# Function to decrypt a file using AES with a 256-bit key
def decrypt_file_256(key, input_file_path, output_file_path):
    # Set the IV
    iv = b"0123456789abcdef"
    print(key)
    # Create the Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create the decryptor object
    decryptor = cipher.decryptor()

    # Read the input file
    with open(input_file_path, "rb") as input_file:
        input_data = input_file.read()

    # Decrypt the input data
    decrypted_data = decryptor.update(input_data) + decryptor.finalize()

    unpadded_data = unpad(decrypted_data)

    # Write the decrypted data to the output file
    with open(output_file_path, "wb") as output_file:
        output_file.write(unpadded_data)
