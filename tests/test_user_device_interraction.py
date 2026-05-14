import sys
import os
import unittest
import time
import random

# Add src to path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)
from dilithium_py.dilithium import Dilithium5
from keystore import NipKeyStore
from sim_device import SimDevice
from central import Central
from nfc import NFC


# =========================
# CONFIGURATION
# =========================
M_IDENTITY_SIZES = range(8, 10)   # e.g. test sizes 4..12
PROOF_INDEX = random.randint(0, 2**8)
ROTATE_INDEX = random.randint(0, 2**8)


class TimedTestCase(unittest.TestCase):
    """Base class providing timing helper"""

    def timed(self, label, func, *args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        print(f"[TIME] {label}: {elapsed:.6f}s", flush=True)
        with open("results.txt", "a", encoding="utf-8") as f:
            f.write(f"{label}: {elapsed}\n")
        return result


class TestNipKeyStore(TimedTestCase):

    def setUp(self):
        start = time.perf_counter()
        self.central = Central("masterseed")
        elapsed = time.perf_counter() - start
        self.central.register_machine(8)
        self.central.register_machine(8)
        self.central.register_worker()
        self.central.register_worker()
        self.central.delegate_machine_to_worker(0, 0)
        self.central.delegate_machine_to_worker(1, 1)
        print("")
        print(f"[TIME] setUp (NipKeyStore init): {elapsed:.6f}s", flush=True)

    def test_user_verification(self):
        machine1 = self.central.machines[0]
        machine2 = self.central.machines[1]
        worker_nfc = self.central.service_workers[0]
        proof1 = machine1.keytree.create_proof()
        proof2 = machine2.keytree.create_proof()
        for _ in range(0, 1):
            self.assertTrue(
                self.timed(
                    "machine.authenticate_device (size=8)",
                    machine1.authenticate_device,
                    proof2,
                    machine2.keytree.current_node.hashcombo(),
                    machine2.keytree.root.hashcombo(),
                    machine2.keytree.signbytes,
                )
            )    
            self.assertTrue(
                self.timed(
                    "machine2.authenticate_device (size=8)",
                    machine2.authenticate_device,
                    proof1,
                    machine1.keytree.current_node.hashcombo(),
                    machine1.keytree.root.hashcombo(),
                    machine1.keytree.signbytes,
                )
            )
            self.assertTrue(
                self.timed(
                    "handshake (size=8)",
                    machine1.handshake,
                    machine2,
                    [],
                    0,
                )
            )
            self.assertTrue(
                self.timed(
                    "send",
                    machine1.send,
                    machine2,
                    "data_to_send1.txt",
                )
            )
            self.assertTrue(
                self.timed(
                    "send",
                    machine1.send,
                    machine2,
                    "data_to_send2.txt",
                )
            )
            self.assertTrue(
                self.timed(
                    "machine.authenticate_worker (size=8)",
                    machine1.authenticate_worker,
                    worker_nfc,
                )
            )

    def test_wrong_user_denial(self):
        machine1 = self.central.machines[0]
        machine2 = self.central.machines[1]
        worker_nfc = self.central.service_workers[0]
        worker_nfc2 = self.central.service_workers[1]
        proof1 = machine1.keytree.create_proof()
        proof2 = machine2.keytree.create_proof()
        for _ in range(0, 1):
            self.assertTrue(
                self.timed(
                    "machine.authenticate_device (size=8)",
                    machine1.authenticate_device,
                    proof2,
                    machine2.keytree.current_node.hashcombo(),
                    machine2.keytree.root.hashcombo(),
                    machine2.keytree.signbytes,
                )
            )    
            self.assertTrue(
                self.timed(
                    "machine2.authenticate_device (size=8)",
                    machine2.authenticate_device,
                    proof1,
                    machine1.keytree.current_node.hashcombo(),
                    machine1.keytree.root.hashcombo(),
                    machine1.keytree.signbytes,
                )
            )
            self.assertTrue(
                self.timed(
                    "handshake (size=8)",
                    machine1.handshake,
                    machine2,
                    [],
                    0,
                )
            )
            self.assertTrue(
                self.timed(
                    "send",
                    machine1.send,
                    machine2,
                    "data_to_send1.txt",
                )
            )
            self.assertTrue(
                self.timed(
                    "send",
                    machine2.send,
                    machine1,
                    "data_to_send2.txt",
                )
            )
            self.central.remove_worker_from_machine(0, 0)

            self.assertFalse(
                self.timed(
                    "machine.authenticate_worker denial (size=8)",
                    machine1.authenticate_worker,
                    worker_nfc,
                )
            )
            self.assertFalse(
                self.timed(
                    "machine.authenticate_worker denial (size=8)",
                    machine1.authenticate_worker,
                    worker_nfc2,
                )
            )
        
    def test_false_user_identity_denial(self):
        machine1 = self.central.machines[0]
        machine2 = self.central.machines[1]
        dilithium_public, dilithium_secret = Dilithium5.keygen()
        fake_nfc = NFC().create_identity(os.urandom(12), self.central.keystore.ca_public, dilithium_public, dilithium_secret, os.urandom(64), "SKANE") #Try to connect to real machine with fake worker credential
        proof1 = machine1.keytree.create_proof()
        proof2 = machine2.keytree.create_proof()
        for _ in range(0, 1):
            self.assertTrue(
                self.timed(
                    "machine.authenticate_device (size=8)",
                    machine1.authenticate_device,
                    proof2,
                    machine2.keytree.current_node.hashcombo(),
                    machine2.keytree.root.hashcombo(),
                    machine2.keytree.signbytes,
                )
            )    
            self.assertTrue(
                self.timed(
                    "machine2.authenticate_device (size=8)",
                    machine2.authenticate_device,
                    proof1,
                    machine1.keytree.current_node.hashcombo(),
                    machine1.keytree.root.hashcombo(),
                    machine1.keytree.signbytes,
                )
            )
            self.assertTrue(
                self.timed(
                    "handshake (size=8)",
                    machine1.handshake,
                    machine2,
                    [],
                    0,
                )
            )
            self.assertFalse(
                self.timed(
                    "machine.authenticate_device denial (size=8)",
                    machine1.authenticate_worker,
                    fake_nfc,
                )
            )
    def test_false_machine_identity_denial(self):
        machine1 = self.central.machines[0]
        machine2 = self.central.machines[1]
        sigless_false_machine = os.urandom(64) #Try to connect to real machine without real signature
        proofless_false_machine = [] #Try to connect to real machine without proof
        for i in range(0, 8):
            proofless_false_machine.append((os.urandom(64), bool(random.getrandbits(1)))) #Try to connect to real machine with random proof
        proof1 = machine1.keytree.create_proof()
        proof2 = machine2.keytree.create_proof()
        for _ in range(0, 1):
            self.assertFalse(
                self.timed(
                    "machine.authenticate_device denial (size=8)",
                    machine1.authenticate_device,
                    proofless_false_machine,
                    machine2.keytree.current_node.hashcombo(),
                    machine2.keytree.root.hashcombo(),
                    machine2.keytree.signbytes,
                )
            )
            self.assertFalse(
                self.timed(
                    "machine.authenticate_device denial (size=8)",
                    machine1.authenticate_device,
                    proof1,
                    machine2.keytree.current_node.hashcombo(),
                    machine2.keytree.root.hashcombo(),
                    sigless_false_machine,
                )
             )             
if __name__ == "__main__":
    unittest.main(verbosity=2)