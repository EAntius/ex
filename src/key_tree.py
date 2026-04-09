from dilithium_py.dilithium import Dilithium5
import hashlib
from kyber_py.ml_kem import ML_KEM_1024 as kyber

class KeyTree:
    def __init__ (self):
        self.tree = {}
    #Generate keytree with 1024 key pair leaves : roughly 43 year lifespan with rotation once a month
    
    def generateTree(self, master_seed):
        master_seed_bytes = master_seed.encode('utf-8')
        for i in range(512):
            # Derive a unique seed for each key pair
            seed = hashlib.sha3_512(master_seed_bytes).digest()
            # Generate Dilithium key pair
            pk, sk = Dilithium5.keygen()
            self.tree[i] = {'dilithium': (pk, sk)}
            # Generate Kyber key pair
            ek, dk = kyber.keygen()
            self.tree[i]['kyber'] = (ek, dk)
        h = 256
        while (h != 1):
            for i in range(0, h, 2):
                left = self.tree[i]
                right = self.tree[i + 1]
                # Combine the keys of the left and right child nodes to create the parent node
                parent_key = hashlib.sha3_512(left['dilithium'][0] + right['dilithium'][0]).digest()
                self.tree[i // 2] = {'dilithium': (parent_key, None)}
            h //= 2
        #TODO remove all nodes irrelevant
        #i.e every node besides the first needed for proof 
        return self.tree

    def recover():
        h = 256
        while (h != 1):
            for i in range(0, h, 2):
                left = self.tree[i]
                right = self.tree[i + 1]
                # Combine the keys of the left and right child nodes to create the parent node
                parent_key = hashlib.sha3_512(left['dilithium'][0] + right['dilithium'][0]).digest()
                self.tree[i // 2] = {'dilithium': (parent_key, None)}
            h //= 2
        #TODO add parameters to isolate path for the new rotations' merkle proof
        return
    #TODO Merkle proof
    def proof():
        return false
