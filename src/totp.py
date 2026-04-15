import pyotp
import time

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