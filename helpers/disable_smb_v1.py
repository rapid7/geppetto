import sys
from tqdm import tqdm
import vm_config_parser

WINDOWS_REQURED = "Win"
DISABLE_SMB1_COMMAND = ['cmd.exe',
                        '/k',
                        '%windir%\System32\\reg.exe',
                        'ADD',
                        'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                        '/v',
                        'SMB1',
                        '/t',
                        'REG_DWORD',
                        '/d',
                        '0',
                        '/f']


def main(argv):
    snapshots_taken = 0
    usage_statement = "disable_smb_v1.py <config.json> <VM_PREFIX>"
    if len(argv) < 3:
        print ("INCORRECT PARAMETER LIST:\n " + usage_statement)
        exit(1)

    config_file = argv[1]
    prefix = argv[2]
    vmServer = vm_config_parser.get_vm_server(config_file=config_file)
    if vmServer is None:
        print ("Failed to connect to VM environment")
        exit(1)

    vmServer.enumerateVms()
    for vm in tqdm(vmServer.vmList):
        if prefix in vm.vmName and WINDOWS_REQURED in vm.vmName:
            # expand here to disable SMBv1
            vm.powerOn()
            vmServer.waitForVmsToBoot([vm])
            vm.setUsername("vagrant")
            vm.setPassword("vagrant")
            vm.runCmdOnGuest(DISABLE_SMB1_COMMAND)
            vm.powerOff()
            vm.takeSnapshot("DisableSMBv1")
            snapshots_taken += 1

    print("Task Complete " + str(snapshots_taken) + " new 'DisableSMBv1' snapshots taken")

if __name__ == "__main__":
    main(sys.argv)