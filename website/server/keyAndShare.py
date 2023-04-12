from random import randint

# Choose a prime number p
p = 997

# Choose a primitive root g
g = 3

# Generate private key for Alice
a = randint(2, p-2)

# Generate private key for Bob
b = randint(2, p-2)

# Calculate public keys for Alice and Bob
A = pow(g, a, p)
B = pow(g, b, p)

# Calculate shared secret for Alice and Bob
s1 = pow(B, a, p)
s2 = pow(A, b, p)

# Verify that the shared secrets are the same
assert s1 == s2

# Derive a symmetric key from the shared secret
key = str(s1).encode('utf-8')[:16] # Use first 16 bytes of shared secret as key


print(key)