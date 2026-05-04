import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from keystore import NipKeyStore

def main():
    store = NipKeyStore("hej")
    kt = store.create_identity(8)    
    print(kt.create_proof(2))

def signtest():
    store = NipKeyStore("hej")
    k1 = store.create_identity(8)
    k2 = store.create_identity(8)
    k1.check(k2.signbytes, k2.root.hashcombo())
    k2.check(k1.signbytes, k1.root.hashcombo())
signtest()