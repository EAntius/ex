import pyotp
import time
import qrcode

def generate_totp_secret():
    totp = pyotp.TOTP(pyotp.random_base32())
    a = totp.now()

    #assert(totp.verify(a))
    #time.sleep(30)
    #assert(totp.verify(a) == False)
    return totp

def main():
    totp = generate_totp_secret()
    print("TOTP Secret:", totp.secret)
    print("Current TOTP:", totp.now())
    print("TOTP valid for 30 seconds:", totp.verify(totp.now()))
    uri = pyotp.totp.TOTP(totp.secret).provisioning_uri(name='edvin@google.com', issuer_name='Nipro')
    print("Provisioning URI:", uri)
    print(uri)
    
    img = qrcode.make(uri)
    img.save("totp_qr.png")
    print("QR code saved as totp_qr.png")
    print(totp.secret)
    print(totp.now())
    time.sleep(30)
    print(totp.now())
main()