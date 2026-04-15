import pyotp
import time
from dilithium_py.dilithium import Dilithium5
import hashlib
from kyber_py.ml_kem import ML_KEM_1024 as kyber

def generate_totp_secret():
    totp = pyotp.TOTP(pyotp.random_base32())
    a = totp.now()

    assert(totp.verify(a))
    time.sleep(30)
    assert(totp.verify(a) == False)
    return totp

def main():
    totp = generate_totp_secret()
    print("TOTP Secret:", totp.secret)
    print("Current TOTP:", totp.now())
    print("TOTP valid for 30 seconds:", totp.verify(totp.now()))

main()