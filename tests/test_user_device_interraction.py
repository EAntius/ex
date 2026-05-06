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
M_IDENTITY_SIZES = range(8, 12)   # e.g. test sizes 4..12
PROOF_INDEX = random.randint(4, 2**6)
ROTATE_INDEX = random.randint(4, 2**6)


class TimedTestCase(unittest.TestCase):
    """Base class providing timing helper"""

    def timed(self, label, func, *args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        print(f"[TIME] {label}: {elapsed:.6f}s", flush=True)
        return result


class TestNipKeyStore(TimedTestCase):

    def setUp(self):
        start = time.perf_counter()
        self.central = Central("masterseed")
        elapsed = time.perf_counter() - start
        self.central.register_machine()
        self.central.register_machine()
        self.central.register_worker()
        self.central.delegate_machine_to_worker(0, 0)
        print(f"[TIME] setUp (NipKeyStore init): {elapsed:.6f}s", flush=True)

    def test_user_verification(self):
        machine1_kt = self.central.machines[0]
        machine2_kt = self.central.machines[1]
        worker_nfc = self.central.service_workers[0]
        sim_device = SimDevice(machine1_kt)
        sim_device2 = SimDevice(machine2_kt)
        proof1 = machine1_kt.create_proof(machine1_kt.current_node.idx)
        proof2 = machine2_kt.create_proof(machine2_kt.current_node.idx)

        self.assertTrue(
            self.timed(
                "sim_device.authenticate_device",
                sim_device.authenticate_device,
                proof2,
                machine2_kt.current_node.hashcombo(),
                machine2_kt.root.hashcombo(),
                machine2_kt.signbytes,
            )
        )    
        self.assertTrue(
            self.timed(
                "sim_device2.authenticate_device",
                sim_device2.authenticate_device,
                proof1,
                machine1_kt.current_node.hashcombo(),
                machine1_kt.root.hashcombo(),
                machine1_kt.signbytes,
            )
        )
        self.assertTrue(
            self.timed(
                "sim_device.authenticate_worker",
                sim_device.authenticate_worker,
                worker_nfc,
            )
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)