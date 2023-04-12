from cryptography.hazmat.primitives import hashes

def sha3_256(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(data)
    hash_value = digest.finalize()

    return hash_value.hex()

# filename = "../static/sample.txt"
# hash_value = sha3_256(filename)
# print(hash_value)
