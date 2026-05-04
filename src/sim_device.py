from nfc import NFC

class SimDevice:
    def __init__(self, KeyTree):
        self.keytree = KeyTree
        self.id = self.keytree.root
        return
    
    def authenticate_device(self, proof, root, sig):
        if self.keytree.device_verify(sig, root):
            return True
        else:
            return False
        
    def authenticate_worker(self, nfc_credential):
        if self.keytree.worker_verify(nfc_credential.identity['issuer']['ca_id'], nfc_credential.identity['issuer']['signature'], nfc_credential.identity['subject']['tag_id']):
            return True
        else:
            return False