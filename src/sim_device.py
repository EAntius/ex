from nfc import NFC
from key_tree import KeyTree
import os
from kyber_py.ml_kem import ML_KEM_1024 as kyber
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SimDevice:
    def __init__ (self, keytree):
        self.keytree = keytree
        self.worker = []
        self.session_key = None
        self.cipher = None
        self.nonce = None
        return
    
    def addworker(self, id):
        self.worker.append(id)

    def removeworker(self, id):
        self.worker.remove(id)

    def authenticate_device(self, proof, current_hash, root, sig):
        if self.keytree.device_verify(sig, root) and self.keytree.validate_proof(proof, current_hash, root):
            return True
        else:
            return False
        
    def authenticate_worker(self, nfc_credential):
        if self.keytree.worker_verify(nfc_credential.identity['issuer']['ca_id'], nfc_credential.identity['issuer']['signature'], nfc_credential.identity['subject']['tag_id']) and nfc_credential.identity['subject']['tag_id'] in self.worker:
            return True
        else:
            return False

    def verify_nonce(self, enc_nonce, adder_nonce):
        if (self.session_key != None and self.session_key.decrypt(adder_nonce, enc_nonce, associated_data=None) == self.nonce):
            return True
        return False
    # ===========================
    #Simulated handshake protocol
    #Step describes each time a message/response happens
    #Call to function goes to respective device for calculations, meaning what is in it can be seen by all listening to the traffic
    # ===========================
    def handshake(self, dev, data, step):
        match step:
            case 0:
                self.nonce = os.urandom(40)
                dev.handshake(self, [self.keytree.create_proof(), self.keytree.current_node.hashcombo(), self.keytree.root.hashcombo(), self.keytree.signbytes, self.keytree.current_node.kem[0], self.nonce], step+1)
                return True
            case 1:
                if self.authenticate_device(data[0], data[1], data[2], data[3]):  
                    kem_key, c = kyber.encaps(data[4])
                    self.session_key = AESGCM(kem_key)
                    adder_nonce = os.urandom(20)
                    enc_nonce = self.session_key.encrypt(adder_nonce, data[5], associated_data=None)
                    self.nonce = os.urandom(40)
                    dev.handshake(self, [self.keytree.create_proof(), self.keytree.current_node.hashcombo(), self.keytree.root.hashcombo(), self.keytree.signbytes, self.nonce, c, enc_nonce, adder_nonce], step+1)
                    return True
                return False
            case 2:
                if (self.authenticate_device(data[0], data[1], data[2], data[3])):
                    kem_key = kyber.decaps(self.keytree.current_node.kem[1], data[5])
                    self.session_key = AESGCM(kem_key)
                    adder_nonce = os.urandom(20)
                    enc_nonce = self.session_key.encrypt(adder_nonce, data[4], associated_data=None)
                    if self.verify_nonce(data[6], data[7]):
                        dev.handshake(self, [enc_nonce, adder_nonce], step+1)           
                    return True     
                return False
            case 3:
                if self.verify_nonce(data[0], data[1]):
                    return True
                return False
        if (step == 4 and data[0]):
            return True
        return False

    #Handle incoming transmissions
    def receive(self, crypteddata):
        rawdata = self.session_key.decrypt("domini protege me, dum impios interficio".encode('utf-8'), crypteddata, associated_data=None)
        print(rawdata)
        return True

    #Send datapackets to connected device
    def send(self, dev, path):
        if (self.session_key != None):
            data = ""
            with open(path) as f:
                for line in f:
                    data += line
            crypt = self.session_key.encrypt("domini protege me, dum impios interficio".encode('utf-8'), data.encode('utf-8'), associated_data=None)
            #print(crypt)
            dev.receive(crypt)
            return True
        return False
    
