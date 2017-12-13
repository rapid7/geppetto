import sys
from tqdm import tqdm
from pyVmomi import vim
import vm_config_parser


def set_network(vm_server, vm, target_network):
    nic = None
    backing_network = None

    # find the backing network requested
    for network in vm_server.getObject(vim.Network):
        if target_network == network.name:
            backing_network = network
            break

    for device in vm.vmObject.config.hardware.device:
        if isinstance(device, vim.vm.device.VirtualEthernetCard):
            nic = vim.vm.device.VirtualDeviceSpec()
            nic.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
            nic.device = device
            nic.device.wakeOnLanEnabled = True

            nic.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
            nic.device.backing.network = backing_network
            nic.device.backing.deviceName = target_network
            nic.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
            nic.device.connectable.startConnected = True
            nic.device.connectable.allowGuestControl = True

    if nic is not None:
        config = vim.vm.ConfigSpec(deviceChange=[nic])
        task = vm.vmObject.ReconfigVM_Task(config)
        vm.waitForTask(task)


def main(argv):
    snapshots_taken = 0
    usage_statement = "set_vm_network.py <config.json> <VM_PREFIX> <TARGET_NETWORK>"
    if len(argv) < 4:
        print ("INCORRECT PARAMETER LIST:\n " + usage_statement)
        exit(1)

    config_file = argv[1]
    prefix = argv[3]
    target_network = argv[2]
    vm_server = vm_config_parser.get_vm_server(config_file=config_file)
    if vm_server is None:
        print ("Failed to connect to VM environment")
        exit(1)

    vm_server.enumerateVms()
    for vm in tqdm(vm_server.vmList):
        if prefix in vm.vmName:
            # expand here to configure the network passed
            set_network(vm_server, vm, target_network)
            vm.takeSnapshot("TargetNetwork")
            snapshots_taken += 1

    print("Task Complete " + str(snapshots_taken) + " new 'TargetNetwork' snapshots taken")

if __name__ == "__main__":
    main(sys.argv)
