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


# =========================
# CONFIGURATION
# =========================
M_IDENTITY_SIZES = range(8, 11)   # e.g. test sizes 4..12
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
        self.store = NipKeyStore("hej", "SKANE")
        elapsed = time.perf_counter() - start
        print(f"[TIME] setUp (NipKeyStore init): {elapsed:.6f}s", flush=True)

    def test_id_creation(self):
        for size in M_IDENTITY_SIZES:
            with self.subTest(m_identity_size=size):
                self.timed(
                    f"create_m_identity (size={size})",
                    self.store.create_m_identity,
                    size
                )

    def test_device_verification(self):
        for _ in range(0,100):    
            for size in M_IDENTITY_SIZES:
                with self.subTest(m_identity_size=size):
                    print(f"\n--- Testing m_identity size = {size} ---")

                    k1 = self.timed(
                        f"create_m_identity (size={size})",
                        self.store.create_m_identity,
                        size
                    )
                    k2 = self.timed(
                        f"create_m_identity (size={size})",
                        self.store.create_m_identity,
                        size
                    )

                    # Device verification
                    self.assertTrue(
                        self.timed(
                            f"device_verify (size={size})",
                            k1.device_verify,
                            k2.signbytes,
                            k2.root.hashcombo()
                        )
                    )

                    self.assertTrue(
                        self.timed(
                            f"device_verify (size={size})",
                            k2.device_verify,
                            k1.signbytes,
                            k1.root.hashcombo()
                        )
                    )

                    # Proof validation
                    k1p = self.timed(f"create_proof (size={size})", k1.create_proof)
                    k2p = self.timed(f"create_proof (size={size})", k2.create_proof)

                    self.assertTrue(
                        self.timed(
                            f"validate_proof  (size={size})",
                            k1.validate_proof,
                            k2p,
                            k2.current_node.hashcombo(),
                            k2.root.hashcombo(),
                        )
                    )

                    self.assertTrue(
                        self.timed(
                            f"validate_proof (size={size})",
                            k2.validate_proof,
                            k1p,
                            k1.current_node.hashcombo(),
                            k1.root.hashcombo(),
                        )
                    )        
        

if __name__ == "__main__":
    unittest.main(verbosity=2)