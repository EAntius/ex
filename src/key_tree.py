from dilithium_py.dilithium import Dilithium5
import hashlib
from kyber_py.ml_kem import ML_KEM_1024 as kyber

class KeyLeaf:
    def __init__(self, kem, pair, hash, idx):
        self.idx = idx
        self.kem = kem
        self.pair = pair
        self.hash = hash

    def proof(self, idx, level, res):
        return res

    def hashcombo(self):
        return self.hash

class KeyNode:
    def __init__ (self, leftV, rightV, idx):
        self.idx = idx
        self.left = leftV
        self.right = rightV
        self.hash = hashlib.sha3_512(self.left.hashcombo() + self.right.hashcombo()).digest()
        

    def proof(self, idx, level, res):
        #print(self.idx)
        if (level == 0):
            return res
        bit = (idx >> (level - 1)) & 1
        if bit == 0:
            res.append((self.right.hashcombo(), False))
            return self.left.proof(idx, level-1, res)
        else:
            res.append((self.left.hashcombo(), True))
            return self.right.proof(idx, level-1, res)

    def hashcombo(self):
        return self.hash

class KeyTree:
    def __init__ (self, ca_public, issuer):
        self.tree = []
        self.root = None
        self.height = None
        self.sign = None
        self.ca_public = ca_public
        self.issuer = issuer
        self.worker = []
        self.current_node = None

    def generateTree(self, kem_list, hash_list, pair_list, height):
        idx = 0
        self.height = height
        level = [
            # Derive a unique seed for each key pair
            KeyLeaf(kem_list[i], pair_list[i], hash_list[i], idx)
            for i in range((2**height))
            ]
        self.tree = level[:]
        self.current_node = self.tree[0]

        for _ in range (height):
            level_x = []
            for i in range(0, len(level), 2):
                node = KeyNode(level[i], level[i+1], idx)
                level_x.append(node)
                self.tree.append(node)
            level = level_x
        self.root = self.tree[-1]
        #print(self.tree)
        #print(len(self.tree))
        return self.tree

    def recover(self, leaf, proof):
        h = 2**self.height
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
    last_index = -1
    last_proof = None

    def create_proof(self, nodeindex):
        if (self.last_index == nodeindex): return self.last_proof
        res = self.root.proof(nodeindex, self.height, [])
        self.last_proof = res
        self.last_index = nodeindex
        return res

    def validate_proof(self, proof, leafhash, roothash):
        h = leafhash
        for p_hash, p_isLeft in reversed(proof):
            if (p_isLeft):
                h = hashlib.sha3_512(p_hash + h).digest()                
            else:
                h = hashlib.sha3_512(h + p_hash).digest()   
        return h == roothash

    def device_verify(self, sig, roothash):
        isvalid = Dilithium5.verify(self.ca_public, roothash, sig)
        if (isvalid):
            return True
        return False

    def rotate(self, idx):
        #Temporary version
        if (idx < 0 or idx >= 2**self.height):
            raise ValueError("Invalid index for rotation")
        self.current_node = self.tree[idx]
        #TODO add parameters to isolate path for the new rotations' merkle proof
        

    def worker_verify(self, issuer, sig, tag_id):
        isvalid = Dilithium5.verify(self.ca_public, tag_id, sig)
        if (isvalid and tag_id in self.worker and issuer == self.issuer):
            #TODO add valid time as well
            return True
        return False

    def addsign(self, sign):
        self.signbytes = sign

    def addworker(self, id):
        self.worker.append(id)
        return id
    
    def removeworker(self, id):
        self.worker.remove(id)



