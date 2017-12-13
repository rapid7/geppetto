import sys
import time
from tqdm import tqdm
import vm_config_parser

WINDOWS_REQURED = "Win"
UAC_ENABLE_COMMAND = ['cmd.exe',
                      '/k',
                      '%windir%\System32\\reg.exe',
                      'ADD',
                      'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                      '/v',
                      'EnableLUA',
                      '/t',
                      'REG_DWORD',
                      '/d',
                      '1',
                      '/f']


def main(argv):
    snapshots_taken = 0
    usage_statement = "enable_uac.py <config.json> <VM_PREFIX>"
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
            vm.powerOn()
            vmServer.waitForVmsToBoot([vm])
            vm.setUsername('vagrant')
            vm.setPassword('vagrant')
            vm.scheduleCmdOnGuest(UAC_ENABLE_COMMAND, 1)
            time.sleep(5 + 60)
            vm.powerOff()
            vm.takeSnapshot("EnableUAC")
            snapshots_taken += 1

    print("Task Complete " + str(snapshots_taken) + " new 'EnableUAC' snapshots taken")

if __name__ == "__main__":
    main(sys.argv)