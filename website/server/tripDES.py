import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def des_encrypt_file(input_file, output_file, key):
    # Generate a random initialization vector
    iv = os.urandom(algorithms.TripleDES.block_size // 8)
    # Create a new 3-DES cipher object with the specified key and IV
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())

    # Open the input and output files
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        # Write the initialization vector to the output file
        f_out.write(iv)

        # Encrypt the data from the input file and write it to the output file
        encryptor = cipher.encryptor()
        while True:
            data = f_in.read(4096)
            if not data:
                break
            encrypted_data = encryptor.update(data)
            f_out.write(encrypted_data)

def des_decrypt_file(input_file, output_file, key):
    # Open the input and output files
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        # Read the initialization vector from the input file
        iv = f_in.read(algorithms.TripleDES.block_size // 8)
        # Create a new 3-DES cipher object with the specified key and IV
        cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())

        # Decrypt the data from the input file and write it to the output file
        decryptor = cipher.decryptor()
        while True:
            data = f_in.read(4096)
            if not data:
                break
            decrypted_data = decryptor.update(data)
            f_out.write(decrypted_data)