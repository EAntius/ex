import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from keystore import NipKeyStore

def main():
    store = NipKeyStore("hej")
    store.generate_keys(8)
    kt = store.create_identity(8)    
    print(kt.create_proof(2))
main()