from keystore import NipKeyStore
from nfc import NFC

class Central:
    def __init__(self, master_seed):
        self.keystore = NipKeyStore(master_seed, "Ecosystem-SKANE-CA")
        self.machines = []
        self.service_workers = []

    def register_machine(self):
        kt = self.keystore.create_m_identity(8) 
        self.machines.append(kt)

    def register_worker(self):
        nfc = self.keystore.create_s_identity("Skane")
        self.service_workers.append(nfc)

    def delegate_machine_to_worker(self, machine_idx, worker_idx):
        machine = self.machines[machine_idx]
        worker = self.service_workers[worker_idx]
        machine.addworker(worker.identity['subject']['tag_id'])
        
