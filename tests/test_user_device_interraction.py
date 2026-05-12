import sys
import os
import unittest
import time
import random

# Add src to path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)
from keystore import NipKeyStore
from sim_device import SimDevice
from central import Central


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
        self.central.delegate_machine_to_worker(0, 0)
        print("")
        print(f"[TIME] setUp (NipKeyStore init): {elapsed:.6f}s", flush=True)

    def test_user_verification(self):
        machine1 = self.central.machines[0]
        machine2 = self.central.machines[1]
        worker_nfc = self.central.service_workers[0]
        proof1 = machine1.keytree.create_proof()
        proof2 = machine2.keytree.create_proof()
        for _ in range(0, 10):
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
                    "machine.authenticate_worker (size=8)",
                    machine1.authenticate_worker,
                    worker_nfc,
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
if __name__ == "__main__":
    unittest.main(verbosity=2)