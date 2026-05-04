from dilithium_py.dilithium import Dilithium5
import hashlib
from kyber_py.ml_kem import ML_KEM_1024 as kyber
import os
from key_tree import KeyTree
from nfc import NFC

class NipKeyStore:
    class KeyPair:
        def __init__(self):
            self.pub = None
            self.pri = None
        
        def set_keys(self, pub, pri):
            self.pub = pub
            self.pri = pri
        
        def get_pub(self):
            return self.pub
        
        def get_pri(self):
            return self.pri
    
    class KeyPairPair:
        def __init__(self):
            self.spair = None
            self.epair = None
        
        def set_keys(self, spair, epair):
            self.spair = spair
            self.epair = epair
        
        def get_sign(self):
            return self.spair
        
        def get_enc(self):
            return self.epair

    def __init__ (self, master_seed):
        master_seed_bytes = master_seed.encode('utf-8')
        seed = hashlib.sha3_512(master_seed_bytes).digest()
        self.kem_list = []
        self.pair_list = []
        self.khash_list = []
        self.ca_public, self.ca_secret = Dilithium5.keygen()
        self.public_enc = None
        self.public_sign = None
        return

    def generate_keys(self, height):
        for x in range(2**height):
            kyber_key = kyber.keygen()
            self.kem_list.append(kyber_key)
            spk, ssk = Dilithium5.keygen()
            epk, esk = Dilithium5.keygen()
            pair_s = self.KeyPair()
            pair_e = self.KeyPair()
            pair_s.set_keys(spk, ssk)
            pair_e.set_keys(epk, esk)
            pairs = self.KeyPairPair()
            pairs.set_keys(pair_s, pair_e)
            self.pair_list.append(pairs)

    def hash_list(self):
        for key in self.pair_list:
            spk = key.get_sign().get_pub()
            epk = key.get_enc().get_pub()
            hash_input = spk + epk
            hash_output = hashlib.sha3_512(hash_input).digest()
            self.khash_list.append(hash_output)

    def store_creation(self, keypairs):
        public_enc_e = []
        private_enc_e = []
        public_enc_s = []
        private_enc_s = []
        for k in keypairs:
            public_enc_e.append(k.get_enc().get_pub())
            private_enc_e.append(k.get_enc().get_pri())
            public_enc_s.append(k.get_sign().get_pub())
            private_enc_s.append(k.get_sign().get_pri())
        self.public_enc = public_enc_e
        self.public_sign = public_enc_s
        return

    def create_store(self, keypair_list):
        #generate keylists
        kem, pair = self.generate_identity()
        #generate tree
        public_enc = []
        private_enc = []
        for k in keypair_list:
            public_enc.append(k.get_pub())
            private_enc.append(k.get_pri())
        self.public_enc = public_enc
        self.private_enc = private_enc
        return

    def create_m_identity(self, height):
        self.generate_keys(height)
        self.hash_list()
        kt = KeyTree(self.ca_public)
        kt.generateTree(self.kem_list, self.khash_list, self.pair_list, height)
        signature = Dilithium5.sign(self.ca_secret, kt.root.hashcombo())
        kt.addsign(signature)
        self.kem_list = []
        self.pair_list = []
        self.khash_list = []
        return kt

    def create_s_identity(self, loc):
        pk, sk = Dilithium5.keygen()       
        id = (os.urandom(16).hex() + loc).encode('utf-8')
        signature = Dilithium5.sign(self.ca_secret, id)
        nfc = NFC.create_identity(id, self.ca_public, pk, sk, signature)
        self.service_workers.append(nfc)
        return nfc


    
    
    


        