from dilithium_py.dilithium import Dilithium5
import hashlib
from kyber_py.ml_kem import ML_KEM_1024 as kyber
#SHA hash
def sha3_512_hash(data):
    # Create a new SHA3-512 hash object
    sha3_512 = hashlib.sha3_512()
    # Update the hash object with the bytes-like object (data)
    sha3_512.update(data.encode('utf-8'))
    # Return the hexadecimal digest of the hash
    return sha3_512.hexdigest()

# Example usage
if __name__ == "__main__":
    input_data = "Hello, World!"
    hash_value = sha3_512_hash(input_data)
    print(f"SHA3-512 hash of '{input_data}': {hash_value}")

#Dilitium signatures
pk, sk = Dilithium5.keygen()
print("Public Key:", pk[:20])
print("Private Key:", sk[:20])

m = "hej"
sig = Dilithium5.sign(sk, m.encode('utf-8'))
print("Signature:", sig[:20])
is_valid = Dilithium5.verify(pk, m.encode('utf-8'), sig)
print("Signature valid:", is_valid)

#Kyber key encapsulation
ek, dk = kyber.keygen()
key_a, ct = kyber.encaps(ek)
key_b = kyber.decaps(dk, ct)

assert key_a == key_b, "Keys do not match!"
print("Keys match! Key A:", key_a, "Key B:", key_b)


