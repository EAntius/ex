from dilithium_py.dilithium import Dilithium5
import hashlib
from kyber_py.ml_kem import ML_KEM_1024 as kyber

class KeyLeaf:
    def __init__(self, kem, pair, hash, idx):
        self.idx = idx
        self.kem = kem
        self.pair = pair
        self.hash = hash

    def proof(self, idx, level, h, res):
        if (level == 0):
            if (idx < h):
                res.append((self.hashcombo(), False))
            else:
                res.append((self.hashcombo(), True))
            return res
        return res

    def hashcombo(self):
        return self.hash

class KeyNode:
    def __init__ (self, leftV, rightV, idx):
        self.idx = idx
        self.left = leftV
        self.right = rightV
        self.hash = hashlib.sha3_512(self.left.hashcombo() + self.right.hashcombo()).digest()
        

    def proof(self, idx, level, h, res):
        if (level == 0):
            if (idx < h):
                res.append((self.left.hashcombo(), False))
            else:
                res.append((self.right.hashcombo(), True))
            return res
        if (idx < h):
            print(h)
            res = self.left.proof(idx, level - 1, h - h/2, res)
            res.append((self.left.hashcombo(), False))
        else:
            print(h)
            res = self.right.proof(idx, level - 1, h + h/2, res)
            res.append((self.right.hashcombo(), True))
        return res

    def hashcombo(self):
        return self.hash

class KeyTree:
    def __init__ (self, ca_public):
        self.tree = [None] * 1024
        self.root = None
        self.height = None
        self.ca_public = ca_public
    #Generate keytree with 1024 key pair leaves : roughly 43 year lifespan with rotation once a month
    
    def generateTree(self, kem_list, hash_list, pair_list, height):
        idx = 0
        self.height = height
        for i in range(2**height):
            # Derive a unique seed for each key pair
            node = KeyLeaf(kem_list[i], pair_list[i], hash_list[i], idx)
            self.tree[idx] = node
            idx += 1
        h = 2**height
        h0 = h
        s = 0
        while (h > 0):
            if (h == 1):
                left = self.tree[2*h0-3]
                right = self.tree[2*h0-2]
                # Combine the keys of the left and right child nodes to create the parent node
                node = KeyNode(left, right, idx)
                self.tree[idx] = node
                self.root = node
                break
            for i in range(0, h, 2):
                left = self.tree[i + s]
                right = self.tree[i + s + 1]
                # Combine the keys of the left and right child nodes to create the parent node
                node = KeyNode(left, right, idx)
                self.tree[idx] = node 
                idx += 1 
            s += h
            h //= 2      
        #TODO remove all nodes irrelevant
        #i.e every node besides the first needed for proof 
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
        res = self.root.proof(nodeindex, self.height, 2**self.height, [])
        self.last_proof = res
        self.last_index = nodeindex
        return res     

    def printtest(self):
        print(len(self.tree))


