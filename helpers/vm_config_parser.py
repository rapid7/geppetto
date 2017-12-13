import json
import os
import vm_automation


def get_vm_server(config_file):
    if os.path.isfile(config_file):
        with open(config_file) as config_file_handle:
            config_map = json.load(config_file_handle)

            if config_map['HYPERVISOR_TYPE'].lower() == "esxi":
                vmServer = vm_automation.esxiServer(config_map["HYPERVISOR_HOST"],
                                                    config_map["HYPERVISOR_USERNAME"],
                                                    config_map["HYPERVISOR_PASSWORD"],
                                                    config_map["HYPERVISOR_LISTENING_PORT"],
                                                    'esxi_automation.log')
                vmServer.connect()
            if config_map['HYPERVISOR_TYPE'].lower() == "workstation":
                vmServer = vm_automation.workstationServer(config_map, 'workstation_automation.log')
        return vmServer
    return None
