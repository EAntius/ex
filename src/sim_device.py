from nfc import NFC
from key_tree import KeyTree

class SimDevice:
    def __init__ (self, keytree):
        self.keytree = keytree
        self.worker = []
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