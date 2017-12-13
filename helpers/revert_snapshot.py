import sys
from tqdm import tqdm
import vm_config_parser


def main(argv):
    usage_statement = "revert_snapshot.py <config.json> <SNAPSHOT_NAME> <VM_PREFIX>"
    if len(argv) < 3:
        print ("INCORRECT PARAMETER LIST:\n " + usage_statement)
        exit(1)

    config_file = argv[1]
    snapshot_name = argv[2]
    prefix = argv[3]
    vmServer = vm_config_parser.get_vm_server(config_file=config_file)
    if vmServer is None:
        print ("Failed to connect to VM environment")
        exit(1)

    vmServer.enumerateVms()
    for vm in tqdm(vmServer.vmList):
        if prefix in vm.vmName:
            vm.powerOff()
            vm.revertToSnapshotByName(snapshot_name)

if __name__ == "__main__":
    main(sys.argv)
