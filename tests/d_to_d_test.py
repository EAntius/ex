import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from keystore import NipKeyStore
from sim_device import SimDevice
from central import Central

def main():
    central = Central("masterseed")
    central.register_machine()
    central.register_machine()
    central.register_worker()
    central.delegate_machine_to_worker(0, 0)
    machine1_kt = central.machines[0]
    machine2_kt = central.machines[1]
    worker_nfc = central.service_workers[0]
    sim_device = SimDevice(machine1_kt)
    sim_device2 = SimDevice(machine2_kt)
    print(sim_device.authenticate_device(machine2_kt.create_proof(2), machine2_kt.root.hashcombo(), machine2_kt.signbytes))
    print(sim_device2.authenticate_device(machine1_kt.create_proof(2), machine1_kt.root.hashcombo(), machine1_kt.signbytes))
    print(sim_device.authenticate_worker(worker_nfc))

main()