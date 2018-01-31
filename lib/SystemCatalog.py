import json


class SystemCatalog:
    local_catalog = {}

    def __init__(self, catalog_file):
        with open(catalog_file) as catalog_source:
            self.local_catalog = json.load(catalog_source)

    def findByOS(self, os_name):
        return self.findByAttrEqual('OS', os_name)

    def findByCPE(self, cpe_string):
        return self.findByAttrBegin('CPE', cpe_string)

    def findByName(self, vm_name):
        return self.findByAttrEqual('NAME', vm_name)

    def findByAttrBegin(self, attr, value):
        for vm_def in self.local_catalog:
            if attr in self.local_catalog[vm_def] and self.local_catalog[vm_def][attr].startswith(value):
                return self.local_catalog[vm_def]
        return None

    def findByAttrEqual(self, attr, value):
        for vm_def in self.local_catalog:
            if attr in self.local_catalog[vm_def] and self.local_catalog[vm_def][attr] == value:
                return self.local_catalog[vm_def]
        return None
