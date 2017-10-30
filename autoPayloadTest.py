import apt_shared
import argparse
from datetime import datetime
import hashlib
import json
import os
import sys
import time
import vm_automation

def bailSafely(logFile, targets, msfHosts):
    logMsg(logFile, "AN ERROR HAPPENED; RETURNING VMS TO THEIR FULL UPRIGHT AND LOCKED POSITIONS")
    timeToWait = 10
    for i in range(timeToWait):
        logMsg(logFile, "SLEEPING FOR " + str(timeToWait-i) + " SECOND(S); EXIT NOW TO PRESERVE VMS!")
        time.sleep(1)
    try:
        for host in  msfHosts:
            if host['TYPE'] == "VIRTUAL":
                host['VM_OBJECT'].revertMsfVm()
                host['VM_OBJECT'].powerOff()
    except Exception as e:
        logMsg(logFile, "SLEEPING FOR " + str(timeToWait-i) + " SECOND(S); EXIT NOW TO PRESERVE VMS!")
        pass
    try:
        for host in  targets:
            if host['TYPE'] == "VIRTUAL":
                host['VM_OBJECT'].revertToTestingBase()
                host['VM_OBJECT'].powerOff()
    except Exception as e:
        logMsg(logFile, "UNABLE TO RESET TARGET VMS")
        pass
    exit(998)

def breakoutClones(hostDicList, logFile):
    """
    TODO: FIX THIS SO ANYTHING NOT LISTED WILL EXPAND RATHER THAN EXPAND ONLY WHAT'S LISTED
    """
    for host in hostDicList:
        if "CLONES" in host:
            numClones = len(host['CLONES']) + 1 #Don't forget the original
            logMsg(logFile, "FOUND " + str(numClones) + " CLONES")
            if 'SESSION_DATASETS' in host:
                numSessions = len(host['SESSION_DATASETS'])
                sessionsPerClone = numSessions/numClones
                logMsg(logFile, "USING " + str(sessionsPerClone) + " PAYLOADS PER CLONE")
            for clone in host['CLONES']:
                cloneDic = {}
                for item in host:
                    if item == 'NAME':
                        cloneDic[item] = clone['NAME']
                        logMsg(logFile, "ADDED CLONE " + clone['NAME'])
                    elif item == 'HYPERVISOR_CONFIG':
                        if 'HYPERVISOR_CONFIG' in clone:
                            cloneDic[item] = clone['HYPERVISOR_CONFIG']
                        else: 
                            cloneDic[item] = host['HYPERVISOR_CONFIG']
                    elif item == 'SESSION_DATASETS':
                        if 'SESSION_DATASETS' not in clone:
                            cloneDic['SESSION_DATASETS'] = []
                        for index in range(sessionsPerClone):
                            cloneDic[item].append(host[item].pop(0))
                    elif item == 'CLONES':
                        continue
                    else:
                        cloneDic[item] = host[item]
                hostDicList.append(cloneDic)

def createServer(configFile, logFile = "default.log"):
    try:
        fileObj = open(configFile, 'r')
        configStr = fileObj.read()
        fileObj.close()
    except IOError as e:
        logMsg(logFile, "UNABLE TO OPEN FILE: " + str(configFile) + '\n' + str(e))
        return None
    try:
        hypervisorDic = json.loads(configStr)
    except Exception as e:
        logMsg(logFile, "UNABLE TO PARSE FILE: " + str(configFile) + '\n' + str(e))
        return None
    if "HYPERVISOR_TYPE" not in hypervisorDic:
        print("INVALID CONFIG FILE; NO HYPERVISOR_TYPE FOUND")
        return None
    if hypervisorDic['HYPERVISOR_TYPE'].lower() == "esxi":
        return vm_automation.esxiServer.createFromConfig(hypervisorDic, logFile)
    if hypervisorDic['HYPERVISOR_TYPE'].lower() == "workstation":
        return vm_automation.workstationServer(hypervisorDic, logFile)

def expandGlobalList(hostList, globalList, listName):
    for target in hostList:
        if listName not in target:
            target[listName] = []
        for listItem in globalList:
            target[listName].append(listItem)

def expandGlobalAttributes(configData, logFile = "default.log"):
    if 'LOG_FILE' in configData:
        logFile = configData['LOG_FILE']
    if 'TARGET_GLOBALS' in configData:
        globalKeys = list(configData['TARGET_GLOBALS'])
        for key in globalKeys:
            for target in configData['TARGETS']:
                if key not in target:
                    target[key] = configData['TARGET_GLOBALS'][key]
                    
def getTimestamp():
    return str(time.time()).split('.')[0]

def getElement(element, vmName, credsDic):
    for credVmName in credsDic.keys():
        if vmName.strip() == credVmName:
            if element in credsDic[credVmName]:
                return credsDic[credVmName][element]
    return False

def getCreds(configData, logFile = "default.log"):
    if 'LOG_FILE' in configData:
        logFile = configData['LOG_FILE']
    try:
        credsFile = open(configData['CREDS_FILE'], 'r')
        credsStr = credsFile.read()
        credsFile.close()
    except IOError as e:
        logMsg(logFile, "UNABLE TO OPEN FILE: " + str(configData['CREDS_FILE']) + '\n' + str(e))
        return False
    try:
        credsDic = json.loads(credsStr)
    except Exception as e:
        logMsg(logFile, "UNABLE TO PARSE FILE: " + str(configData['CREDS_FILE']) + '\n' + str(e))
        return False
    
    vmList = configData['MSF_HOSTS'] + configData['TARGETS']
    
    for vm in vmList:
        if 'USERNAME' not in vm:
            logMsg(logFile, "NO USERNAME FOR " + str(vm['NAME']) + '\n')
            username = getElement('USERNAME', vm['NAME'],  credsDic)
            if username == False:
                return False
            else:
                logMsg(logFile, "FOUND USERNAME FOR " + str(vm['NAME']) + '\n')
                vm['USERNAME'] = username
        if 'PASSWORD' not in vm:
            logMsg(logFile, "NO PASSWORD FOR " + str(vm['NAME']) + '\n')
            password = getElement('PASSWORD', vm['NAME'],  credsDic)
            if password == False:
                return False
            else:
                logMsg(logFile, "FOUND PASSWORD FOR " + str(vm['NAME']) + '\n')
                vm['PASSWORD'] = password
    return True


def instantiateVmsAndServers(machineList, hypervisorDic, logFile):
    for target in machineList:
        logMsg(logFile, "PROCESSING: " + target['NAME'])
        if target['TYPE'].upper() == 'VIRTUAL':
            if target['HYPERVISOR_CONFIG'] in hypervisorDic:
                target['SERVER_OBJECT'] = hypervisorDic[target['HYPERVISOR_CONFIG']]
            else:
                 hypervisorDic[target['HYPERVISOR_CONFIG']] = createServer(target['HYPERVISOR_CONFIG'], logFile)
                 target['SERVER_OBJECT'] = hypervisorDic[target['HYPERVISOR_CONFIG']]
                 target['SERVER_OBJECT'].enumerateVms()
            """
            INSTANTIATE VM INSTANCE AND STORE IT IN THE DICTIONARY
            """
            vmFound = False
            for vm in target['SERVER_OBJECT'].vmList:
                if vm.vmName == target['NAME']:
                    vmFound = True
                    logMsg(logFile, "FOUND VM: " + vm.vmName + " ON " + vm.server.hostname)
                    target['VM_OBJECT'] = vm
                    logMsg(logFile, "ASSIGNED VM: " + str(vm))
                    if 'PASSWORD' in target:
                        vm.setPassword(target['PASSWORD'])
                    if 'USERNAME' in target:
                        vm.setUsername(target['USERNAME'])
            if not vmFound:
                logMsg(logFile, "DID NOT FIND VM: " + target['NAME'] + " ON " + vm.server.hostname)
                return False
    return True

def logMsg(logFile, strMsg):
    if strMsg == None:
        strMsg="[None]"
    dateStamp = 'testlog:[' + str(datetime.now())+ '] '
    try:
        logFileObj = open(logFile, 'a')
        logFileObj.write(dateStamp + strMsg +'\n')
        logFileObj.close()
    except:
        print(dateStamp + strMsg)
        return False
    return True

def parseTestConfig(configFile):
    hasJavaPayload =    False
    hasPythonPayload =  False
    try:
        fileObj = open(configFile, 'r')
        jsonString = fileObj.read()
        fileObj.close
    except IOError as e:
        print("FAILED TO OPEN: " + configFile + '\n' + str(e))
        return None
    try:
        jsonDic = json.loads(jsonString)
    except Exception as e:
        print("FAILED TO PARSE DATA FROM: " + configFile + '\n' + str(e))
        return None
    return jsonDic

def verifyConfig(jsonDic):
    """
    CHECK MAIN LEVEL FOR REQUIRED DATA
    """
    configPassed = True
    requiredList = []
    requiredList.append("FRAMEWORK_BRANCH")
    requiredList.append("HTTP_PORT")
    requiredList.append("STARTING_LISTENER")
    requiredList.append("MSF_HOSTS")
    requiredList.append("TARGETS")
    requiredList.append("SUCCESS_LIST")
    for item in requiredList:
        if item not in jsonDic:
            print("MISSING " + item + " IN CONFIGURATION FILE\n")
            configPassed = False
    if not configPassed:
        return False
    
    """
    MSF_HOSTS
    """
    requiredMsfData = []
    requiredMsfData.append("MSF_ARTIFACT_PATH")
    requiredMsfData.append("TYPE")
    requiredMsfData.append("METHOD")
    requiredMsfData.append("NAME")
    for requiredData in requiredMsfData:
        for msfHost in jsonDic['MSF_HOSTS']:
            if requiredData not in  msfHost:
                print("NO " + requiredData + " LISTED FOR MSF_HOST IN CONFIG FILE")
                configPassed = False
    if not configPassed:
        return False
    """
    SPECIFIC FOR TARGETS
    """
    for target in jsonDic['TARGETS']:
        requiredTargetData = []
        requiredTargetData.append("TYPE")
        requiredTargetData.append("NAME")
        if target['METHOD'] == 'EXPLOIT':
            requiredTargetData.append("NAME")
            if target['TYPE'] != 'VIRTUAL':
                requiredTargetData.append("IP_ADDRESS")
        if target['METHOD'] == "VM_TOOLS":
            requiredTargetData.append("USERNAME")
            requiredTargetData.append("PASSWORD")
            requiredTargetData.append("HYPERVISOR_CONFIG")
            requiredTargetData.append("PAYLOAD_DIRECTORY")
            for payload in jsonDic['PAYLOADS']:
                if 'java' in payload['NAME'].lower():
                    hasJavaPayload = True
                    break
                if 'python' in payload['NAME'].lower():
                    hasPythonPayload = True
                    break
            if hasJavaPayload:
                requiredTargetData.append("METERPRETER_JAVA")
            if hasPythonPayload:
                requiredTargetData.append("METERPRETER_PYTHON")
        for requiredItem in requiredTargetData:
            if requiredItem not in target:
                print("NO " + requiredItem + " LISTED FOR " + target['NAME'] + " IN " + configFile)
                configPassed = False
        if not configPassed:
            return False
    return True

def parseHypervisorConfig(hypervisorConfigFile):
    try:
        fileObj = open(hypervisorConfigFile, 'r')
        jsonString = fileObj.read()
        fileObj.close()
    except IOError as e:
        print("FAILED TO FIND HYPERVISOR CONFIG FILE: " + hypervisorConfigFile)
        return None
    try:
        hypervisorData = json.loads(jsonString)
    except Exception as e:
        print("FAILED TO PARSE HYPERVISOR CONFIG FILE: " + str(e))
        return None
    return hypervisorData

def main():
    logFile = None
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="Echo test result to console", action="store_true")
    parser.add_argument("-f", "--framework", help="Framework branch to use (Overrides testfile)")
    parser.add_argument("-m", "--module", help="Module to use")
    parser.add_argument("-p", "--payload", help="Meterpreter payload to use")
    parser.add_argument("-po", "--payloadoptions", help="Comma delineated venom-style settings for the given payload: attribute=x,attribute2=y...")
    parser.add_argument("testfile", help="json test file to use")
    args = parser.parse_args()

    configData = parseTestConfig(args.testfile)
    if None == configData:
        logMsg(logFile, "THERE WAS A PROBLEM WITH THE TEST JSON CONFIG FILE")
        exit(999)

    if args.framework != None:
        configData['FRAMEWORK_BRANCH'] = args.framework

    if args.payload != None:
        payloadDic = {}
        payloadDic['NAME'] = args.payload
        if args.payloadoptions != None:
            payloadDic['SETTINGS'] = args.payloadoptions.split(',')
        else:
            payloadDic['SETTINGS'] = []
        if 'PAYLOADS' in configData:
            configData['PAYLOADS'].append(payloadDic.copy())
        else:
            configData['PAYLOADS'] = [payloadDic.copy()]
        if (args.module == None) and ('MODULES' not in configData):
            args.module = "exploit/multi/handler"

    if args.module != None:
        moduleDic = {}
        moduleDic['NAME'] = args.module
        moduleDic['SETTINGS'] = []
        if 'MODULES' in configData:
            configData['MODULES'].append(moduleDic.copy())
        else:
            configData['MODULES'] = [moduleDic.copy()]
    """
    SET UP DIRECTORY NAMES IN THE CONFIG DICTIONARY
    """
    configData['REPORT_PREFIX'] = os.path.splitext(os.path.basename(args.testfile))[0]
    if args.payload != None:
        payloadType = args.payload.split('/')[-1]
        configData['REPORT_PREFIX'] = configData['REPORT_PREFIX'] + "-" + payloadType
    configData['TIMESTAMP'] =   str(time.time()).split('.')[0]
    configData['DATA_DIR']  =   os.getcwd() + "/" + "test_data"
    configData['TEST_DIR'] =    configData['DATA_DIR'] + "/" + configData['REPORT_PREFIX'] + "_" + configData['TIMESTAMP']
    configData['REPORT_DIR'] =  configData['TEST_DIR'] + "/" + "reports"
    configData['SESSION_DIR'] = configData['TEST_DIR'] + "/" + "sessions"
    configData['SCRIPT_DIR'] =  configData['TEST_DIR'] + "/" + "scripts"

    if not os.path.exists(configData['DATA_DIR']):
        os.makedirs(configData['DATA_DIR'])
    if not os.path.exists(configData['TEST_DIR']):
        os.makedirs(configData['TEST_DIR'])
    if not os.path.exists(configData['REPORT_DIR']):
        os.makedirs(configData['REPORT_DIR'])
    if not os.path.exists(configData['SESSION_DIR']):
        os.makedirs(configData['SESSION_DIR'])
    if not os.path.exists(configData['SCRIPT_DIR']):
        os.makedirs(configData['SCRIPT_DIR'])
        
    """
    ADD LOGFILE TO THE configData DICTIONARY
    """
    configData['LOG_FILE'] =    configData['REPORT_DIR'] + "/testlog.log"
    logFile = configData['LOG_FILE']
    
    
    if 'TARGET_GLOBALS' in configData:
        expandGlobalAttributes(configData)

    if 'CREDS_FILE' in configData:
        if getCreds(configData) == False:
            bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])

    """
    I WANTED TO AVOID PORT COLLISIONS< SO I MADE A CLASS THAT TRACKS THE PORTS AND 
    EACH TIME YOU RUN get() ON IT, IT RETURNS A PORT VALUE AND INCREMENTS IT SO
    AS LONG AS YOU GET PORTS FROM THIS STRUCT, THEY WILL NEVER COLLIDE.
    IT IS AS CLOSE AS I SEEM TO BE ABLE TO GET IN PYTHON TO A SINGLETON
    """
    portNum = apt_shared.portValue(configData['STARTING_LISTENER'])

    """
    CREATE STAGE SCRIPTS
        STAGE_ONE_SCRIPT: 
            RUNS ON MSF_HOSTS AND CONTAIN THE MSFVENOM COMMANDS TO 
            CREATE THE PAYLOADS THAT NEED TO BE UPLOADED TO THE TARGETS,
            START AN HTTP SERVER ON THE MSF_HOSTS TO SERVE THE PAYLOADS,
            AND LAUNCH THE SPECIFIED EXPLOITS
        STAGE_TWO_SCRIPTS:
            RUN ON TARGET SYSTEMS AND CONTAIN THE COMMANDS TO DOWNLOAD 
            THE PAYLOADS FROM THE MSF_HOSTS AND LAUNCH THEM ON THE TARGETS
        STAGE_THREE_SCRIPT:
            RUN ON THE MSF_HOSTS TO ESTABLISH CONNECTIONS TO THE BIND PAYLOADS
    """
    lineComment = '\n#################################################################\n'
    for host in configData['MSF_HOSTS']:
        host['STAGE_ONE_SCRIPT'] = lineComment + "\n # STAGE ONE SCRIPT FOR " + host['NAME'] + lineComment
        host['STAGE_THREE_SCRIPT'] = lineComment + "\n # STAGE THREE SCRIPT FOR " + host['NAME'] + lineComment
    for host in configData['TARGETS']:
        host['STAGE_TWO_SCRIPT'] = lineComment + "\n # STAGE TWO SCRIPT FOR " + host['NAME'] + lineComment   
    
    """
    IF GLOBAL PAYLOADS OR MODULES ARE LISTED, FILTER THEM AS BEST WE CAN AND ADD THEM TO EACH TARGET
    ALSO, REPLACE THE KEYWORD 'UNIQUE_PORT' WITH A UNIQUE PORT IN BOTH THE PAYLOAD AND EXPLOIT SETTINGS
    NB: I THINK USING GLOBAL EXPLOITS IS A TERRIBLE IDEA, BUT I AM AN ENABLER
    """

    for target in configData['TARGETS']:
        if 'PAYLOADS' not in target:
            target['PAYLOADS'] = []
        if 'MODULES' not in target:
            target['MODULES'] = []
        if 'SESSION_DATASETS' not in target:
            target['SESSION_DATASETS'] = []
        if 'PAYLOADS' in configData:
            for payload in configData['PAYLOADS']:
                if 'x64' not in target['NAME'].lower() and 'x64' in payload['NAME'].lower():
                    #MISMATCHED ARCH; BAIL
                    continue
                if 'win' in target['NAME'].lower() and 'mettle' in payload['NAME'].lower():
                    #DO ONT USE METTLE PAYLOADS ON WINDOWS
                    continue
                if 'win' not in target['NAME'].lower() and 'win' in payload['NAME'].lower():
                    #ONLY USE WIN PAYLOADS ON WIN
                    continue
                else:
                    logMsg(configData['LOG_FILE'], "ADDING " + str(payload))
                    target['PAYLOADS'].append(payload.copy())
                # TODO: ADD A CHECK SO WE DO NOT HAVE MULTIPLE SIMILAR MODULES
        if 'MODULES' in configData:
            for module in configData['MODULES']:
                target['MODULES'].append(module.copy())
     
    """
    NOW THAT THE MODULES AND PAYLOADS HAVE BEEN BROKEN OUT, REPLACE THE UNIQUE_PORT
    KEYWORDS WITH A UNIQUE PORT VALUE
    """           
    for target in configData['TARGETS']:
        logMsg(configData['LOG_FILE'], "MODULES = " + str(target['MODULES']))
        if 'PAYLOADS' in target:
            logMsg(configData['LOG_FILE'], "PAYLOADS = " + str(target['PAYLOADS']))
            for payload in target['PAYLOADS']:
                logMsg(configData['LOG_FILE'], str(payload))
                #REPLACE THE STRING 'UNIQUE_PORT' WITH AN ACTUAL UNIQUE PORT
                for settingItem in payload['SETTINGS']:
                    logMsg(configData['LOG_FILE'], "SETTING ITEM= " + settingItem + str(id(settingItem)))
                    while "UNIQUE_PORT" in settingItem:
                        settingItem = settingItem.replace("UNIQUE_PORT", str(portNum.get()), 1)
                    logMsg(configData['LOG_FILE'], "SETTING ITEM= " + settingItem + str(id(settingItem)))
        for module in target['MODULES']:
            logMsg(configData['LOG_FILE'], str(module))
            #REPLACE THE STRING 'UNIQUE_PORT' WITH AN ACTUAL UNIQUE PORT
            for index in range(len(module['SETTINGS'])):
                logMsg(configData['LOG_FILE'], "SETTING ITEM= " + module['SETTINGS'][index] + str(id(module['SETTINGS'][index])))
                while "UNIQUE_PORT" in module['SETTINGS'][index]:
                    module['SETTINGS'][index] = module['SETTINGS'][index].replace("UNIQUE_PORT", str(portNum.get()), 1)
                logMsg(configData['LOG_FILE'], "SETTING ITEM= " + module['SETTINGS'][index] + str(id(module['SETTINGS'][index])))

    #DEBUG PRINT
    for target in configData['TARGETS']:
        if 'PAYLOADS' in target:
            logMsg(configData['LOG_FILE'], "PAYLOADS = " + str(target['PAYLOADS']))
        logMsg(configData['LOG_FILE'], "MODULES = " + str(target['MODULES']))

    """
    NOW EACH HOST HAS A LIST OF ALL THE MODULES AND (POSSIBLY) PAYLOADS IT NEEDS TO USE...... 
    ASSEMBLE EXPLOITS AND PAYLOADS OR JUST MODULES THEM TO FORM VOLTRON..... I MEAN, SESSION_DATA
    """
    for target in configData['TARGETS']:
        logMsg(configData['LOG_FILE'], str(target))
        if 'MODULES' not in target:
            logMsg(configData['LOG_FILE'], "CONFIG FILE DID NOT HAVE MODULES LISTED FOR " + target['NAME'] + ".  NOTHING TO TEST?")
            bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
        for module in target['MODULES']:
            logMsg(configData['LOG_FILE'], str(module))
            if 'exploit' in module['NAME'].lower():
                for payload in target['PAYLOADS']:
                    logMsg(configData['LOG_FILE'], str(payload))
                    tempDic = {}
                    tempDic['MODULE'] = module.copy()
                    tempDic['PAYLOAD'] = payload.copy()
                    target['SESSION_DATASETS'].append(tempDic)
            else:
                tempDic = {}
                tempDic['MODULE'] = module.copy()
                target['SESSION_DATASETS'].append(tempDic)
    
    """
    JUST A DEBUG PRINT HERE TO VERIFY THE STRUCTURES WERE CREATED CORRECTLY
    """
    for target in configData['TARGETS']:
        logMsg(configData['LOG_FILE'], "================================================================================")
        logMsg(configData['LOG_FILE'], "SESSION_DATASETS FOR " + target['NAME'])
        logMsg(configData['LOG_FILE'], "================================================================================")
        for sessionData in target['SESSION_DATASETS']:
            if 'PAYLOAD' in sessionData:
                logMsg(configData['LOG_FILE'], sessionData['MODULE']['NAME'] + ":" + sessionData['PAYLOAD']['NAME'])
            else:
                logMsg(configData['LOG_FILE'], sessionData['MODULE']['NAME'])
            
    """
    PROCESS CLONES
    NOW THAT THE PAYLOAD?EXPLOIT DATA IS NEATLY PLACED INTO THE SESSION_DATASETS LIST< WHEN WE PROCESS CLONES,
    ALL WE NEED TO DO IS COPY THE EXISTING DATA OVER EXCEPT THE HYPERVISOR CONFIGS AND THE SESSION_DATASETS
    HYPERVISOR CONFIGS REMAIN INDIVIDUAL AND SESSION_DATASETS ARE SPLIT AMONG THE TARGET CLONES
    """
    breakoutClones(configData['MSF_HOSTS'], configData['LOG_FILE'])
    breakoutClones(configData['TARGETS'], configData['LOG_FILE'])
    
    """
    EXPAND COMMAND_LIST AND SUCCESS_LIST TO ALL TARGETS
    """
    expandGlobalList(configData['TARGETS'], configData['COMMAND_LIST'], "COMMAND_LIST")
    expandGlobalList(configData['TARGETS'], configData['SUCCESS_LIST'], "SUCCESS_LIST")
            
    """
    FIGURE OUT HOW MANY PAYLOADS WE HAVE AND HOW MANY MSF_HOSTS WE HAVE
    SO WE CAN SPLIT THE WORK AMONG ALL MSF_HOSTS
    """
    msfHostCount = len(configData['MSF_HOSTS'])
    for host in configData['TARGETS']:
        if 'SESSION_DATASETS' in host:
            sessionCount = len(host['SESSION_DATASETS'])
        else:
            logMsg(configData['LOG_FILE'], "NO TESTING DATA LISTED FOR " + host['NAME'])
            bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
    logMsg(configData['LOG_FILE'], "MSF_HOST COUNT = " + str(msfHostCount))
    logMsg(configData['LOG_FILE'], "SESSION COUNT = " + str(sessionCount))
    
    """
    JUST A DEBUG PRINT HERE TO VERIFY THE STRUCTURES WERE CREATED CORRECTLY
    """
    for target in configData['TARGETS']:
        logMsg(configData['LOG_FILE'], "================================================================================")
        logMsg(configData['LOG_FILE'], "SESSION_DATASETS FOR " + target['NAME'])
        logMsg(configData['LOG_FILE'], "================================================================================")
        for sessionData in target['SESSION_DATASETS']:
            if 'PAYLOAD' in sessionData:
                logMsg(configData['LOG_FILE'], sessionData['MODULE']['NAME'] + ":" + sessionData['PAYLOAD']['NAME'])
            else:
                logMsg(configData['LOG_FILE'], sessionData['MODULE']['NAME'])
    
    if not verifyConfig(configData):
        bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
    """
    INSTANTIATE REQUIRED SERVER INSTANCES AND ADD THEM TO THE DICTIONARY
    """
    hypervisors = {}
    if not instantiateVmsAndServers(configData['MSF_HOSTS']+configData['TARGETS'], hypervisors, configData['LOG_FILE']):
        logMsg(configData['LOG_FILE'], "[ERROR] THERE WAS A PROBLEM PREPARING THE VMS.  PLEASE CHECK TO MAKE SURE THE VMS ARE PRESENT.")
        bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
    """
    PREP ALL MSF_HOSTS AND TARGETS
    FOR MSF_HOSTS:
    1. TAKE A SNAPSHOT
    2. POWER-ON

    FOR VIRTUAL TARGETS:
    1. IF THERE'S a SNAPSHOT TO USE, REVERT TO IT; OTHERWISE, TAKE A TEMP SNAPSHOT
    2. POWER-ON
    
    FOR PHYSICAL TARGETS:
    1. ASSUME THEY ARE READY (FOR NOW..... I HAVE FUN PLANS FOR LATER)
    """

    for host in configData['TARGETS']:
        if host['TYPE'] == "VIRTUAL":
            if 'TESTING_SNAPSHOT' in host:
                logMsg(configData['LOG_FILE'], "TRYING TO REVERT " + host['NAME'] + " TO " + host['TESTING_SNAPSHOT'])
                logMsg(configData['LOG_FILE'], "TRYING TO REVERT TO " + host['TESTING_SNAPSHOT'])
                host['VM_OBJECT'].revertToSnapshotByName(host['TESTING_SNAPSHOT'])
            else:
                logMsg(configData['LOG_FILE'], "TRYING TO TAKE TEMP SNAPSHOT ON " + host['NAME'])
                tempSnapshot = host['VM_OBJECT'].takeTempSnapshot()
                if tempSnapshot != None:
                    host['TESTING_SNAPSHOT'] = tempSnapshot
                else:
                    logMsg(configData['LOG_FILE'], "FAILED TO TAKE SNAPSHOT ON " + host['NAME'] + " TO " + host['TESTING_SNAPSHOT'])
    for host in configData['MSF_HOSTS']:
        host['VM_OBJECT'].takeTempSnapshot()
    for host in configData['TARGETS'] + configData['MSF_HOSTS']:
        if host['TYPE'] == 'VIRTUAL':
            host['VM_OBJECT'].getSnapshots()
            host['VM_OBJECT'].powerOn(False)
            time.sleep(2)


    """
    WAIT FOR THE VMS TO BE READY.
    THIS RELIES ON VMWARE_TOOLS TO BE INSTALLED AND RUNNING.
    """
    for config in hypervisors:
        vmsToCheck = []
        for host in configData['TARGETS'] + configData['MSF_HOSTS']:
            if host['TYPE'] == 'VIRTUAL' and 'IP_ADDRESS' not in host:
                if host['SERVER_OBJECT'] == hypervisors[config]:
                    vmsToCheck.append(host['VM_OBJECT'])
        if not hypervisors[config].waitForVmsToBoot(vmsToCheck):
            logMsg(configData['LOG_FILE'], "ERROR: ONE OR MORE VMS FAILED TO INITIALIZE; EXITING")
            bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
        for host in configData['TARGETS'] + configData['MSF_HOSTS']:
            if host['TYPE'] == 'VIRTUAL' and 'IP_ADDRESS' not in host:
                host['IP_ADDRESS'] = host['VM_OBJECT'].getVmIp()
                logMsg(configData['LOG_FILE'], host['NAME'] + " IP ADDRESS = " + host['IP_ADDRESS'])

    """
    CREATE REQUIRED DIRECTORY FOR PAYLOADS ON VM_TOOLS MANAGED MACHINES
    CAN'T DO THIS EARLIER, AS THE MACHINES WERE OFF....
    """
    for host in configData['TARGETS']:
        if "VM_TOOLS_UPLOAD" in host['METHOD'].upper():
            host['VM_OBJECT'].makeDirOnGuest(host['PAYLOAD_DIRECTORY'])
            
    """
    THIS SECTION MARSHALLS THE DATA WE WILL NEED LATER TO GENERATE THE THREE STAGED SCRIPTS
    TO MAKE THE STAGE ONE SCRIPT, CREATE THE MSFVENOM COMMANDS AND RC SCRIPTS, THEN SPLIT 
    THEM BETWEEN THE MSF_HOSTS
    
    FOR EACH PAYLOAD TO AN UPLOAD TARGET:
    PREP STAGE ONE SCRIPT:
        (1) GENERATE THE MSFVENOM COMMAND TO EXECUTE ON THE MSF_HOST TO MAKE THE PAYLOAD
        (2) ADD THE MSFVENOM COMMAND TO THE STAGE ONE SCRIPT
        (3) GENERATE AN RC SCRIPT TO RUN ON THE MSFHOST TO SET UP THE PAYLOAD HANDLER
        (4) WRITE THE RC SCRIPT TO DISK LOCALLY
        (5) ADD COMMANDS TO THE STAGE ONE SCRIPT TO LAUNCH MSFCONSOLE WITH RC SCRIPTS TO SET UP FOR REVERSE PAYLOAD CALLBACKS
        (6) ADD COMMAND TO STAGE ONE SCRIPT TO START HTTP SERVER LOCALLY TO HOST THE PAYLOADS FOR DOWNLOAD
    PREP STAGE TWO SCRIPT:
        (1) DETERMINE OS OF TARGET TO DETERMINE WHAT KIND OF SCRIPT WE NEED
        (2) ADD COMANDS TO THE STAGE TWO SCRIPT SO THE TAGETS DOWNLOAD THE PAYLOAD AND EXECUTE IT
    """
    """
    THE FIRST FEW LINES OF THE STAGE ONE SCRIPT PREP THINGS
    """

    fileId=0;
    for host in configData['MSF_HOSTS']:
        host['LISTEN_PORTS'] = []
        fileId = fileId + 1
        # STAGE ONE SCRIPT STUFF
        host['STAGE_ONE_FILENAME'] =    configData['SCRIPT_DIR'] + '/' + "stageOneScript_" +  str(fileId) + ".sh"
        host['MSF_PAYLOAD_PATH'] =      host['MSF_ARTIFACT_PATH'] + "/test_payloads"
        host['RC_PATH'] =               host['MSF_ARTIFACT_PATH'] + "/test_rc"
        host['COMMIT_FILE'] =           host['MSF_ARTIFACT_PATH'] + "/commit_tag_" + configData['TIMESTAMP']
        host ['SCRIPT_PATH'] =          host['MSF_ARTIFACT_PATH'] + "/test_scripts"
        host['STAGE_THREE_LOGFILE'] =   host['SCRIPT_PATH'] + "/stageThreeLog.txt"
        host['PCAP_FILE'] =             host['MSF_ARTIFACT_PATH'] + "/logfile.pcap"
        stageOneContent = "#!/bin/bash -l \n\n"
        stageOneContent = stageOneContent + "cd " + host['MSF_PATH'] + "\n"
        stageOneContent = stageOneContent + "git fetch upstream\n"
        stageOneContent = stageOneContent + "git reset --hard FETCH_HEAD\n"
        stageOneContent = stageOneContent + "git clean -df\n"
        branchData = configData['FRAMEWORK_BRANCH'].split('/')
        if branchData[0] == 'upstream':
            #STANDARD BRANCH
            stageOneContent = stageOneContent + "git checkout " + configData['FRAMEWORK_BRANCH'] + "\n"
        else:
            # THIS IS A NON_STANDARD REPO....
            logMsg(configData['LOG_FILE'], "NONSTANDARD FRAMEWORK REPO DETECTED: " + configData['FRAMEWORK_BRANCH'])
            userName = branchData[0]
            logMsg(configData['LOG_FILE'], "NONSTANDARD FRAMEWORK USERNAME: " + userName)
            repoName = branchData[1]
            logMsg(configData['LOG_FILE'], "NONSTANDARD FRAMEWORK REPO NAME: " + repoName)
            branchName = branchData[2]
            logMsg(configData['LOG_FILE'], "NONSTANDARD FRAMEWORK BRANCH NAME: " + branchName)
            gitSyntax = "https://github.com/" + userName + "/" + repoName + ".git"
            stageOneContent = stageOneContent + "git remote add " + userName + " " + gitSyntax + "\n"
            stageOneContent = stageOneContent + "git fetch  " + userName + "\n"
            stageOneContent = stageOneContent + "git checkout -b  " + branchName + ' ' + userName + '/' + branchName + "\n"
        stageOneContent = stageOneContent + "git log | head -n 1 > " + host['COMMIT_FILE'] + "\n"
        stageOneContent = stageOneContent + "source ~/.rvm/scripts/rvm\n"
        stageOneContent = stageOneContent + "cd " + host['MSF_PATH'] + "\n"
        stageOneContent = stageOneContent + "rvm --install $(cat .ruby-version)\n"
        stageOneContent = stageOneContent + "gem install bundler\n"
        stageOneContent = stageOneContent + "bundle install\n"
        stageOneContent = stageOneContent + "mkdir " + host['MSF_PAYLOAD_PATH'] + "\n"
        stageOneContent = stageOneContent + "rm -rf " + host['MSF_PAYLOAD_PATH'] + "/*\n"
        stageOneContent = stageOneContent + "mkdir " + host['RC_PATH'] + "\n"
        stageOneContent = stageOneContent + "rm -rf " + host['RC_PATH'] + "/*\n"
        stageOneContent = stageOneContent + "echo '" +host['PASSWORD']+ "' | sudo -S tcpdump -i any -s0 -nn net 192.168.0.0/16 -w " + host['PCAP_FILE'] + " &\n"
        
        host['STAGE_ONE_SCRIPT'] = stageOneContent
        host['STAGE_THREE_SCRIPT'] = "#!/bin/bash -l\n\n"
        host['STAGE_THREE_SCRIPT'] = host['STAGE_THREE_SCRIPT'] + "cd " + host['MSF_PATH'] + "\n"
        host['STAGE_THREE_SCRIPT'] = host['STAGE_THREE_SCRIPT'] + "source ~/.rvm/scripts/rvm\n"
        host['STAGE_THREE_SCRIPT'] = host['STAGE_THREE_SCRIPT'] + "cd " + host['MSF_PATH'] + "\n"
        host['STAGE_THREE_SCRIPT'] = host['STAGE_THREE_SCRIPT'] + "rvm --install $(cat .ruby-version)\n"
        host['STAGE_THREE_SCRIPT'] = host['STAGE_THREE_SCRIPT'] + "gem install bundler\n"
        host['STAGE_THREE_SCRIPT'] = host['STAGE_THREE_SCRIPT'] + "bundle install\n"

    # MAKE THE REST OF THE STAGE ONE SCRIPT
    sleepBreak = "\nsleep(2)\n"
    sessionCounter = 0
    for host in configData['TARGETS']:
        host['LISTEN_PORTS'] = []
        logMsg(configData['LOG_FILE'], "=============================================================================")
        logMsg(configData['LOG_FILE'], host['NAME'])
        logMsg(configData['LOG_FILE'], "=============================================================================")
        for sessionData in host['SESSION_DATASETS']:
            sessionData['MSF_HOST'] = configData['MSF_HOSTS'][sessionCounter % len(configData['MSF_HOSTS'])]
            sessionCounter = sessionCounter + 1
            logMsg(configData['LOG_FILE'], "ASSIGNING TO MSF_HOST " + sessionData['MSF_HOST']['NAME'])
            stageOneContent = '\n\n##########################\n'
            stageOneContent = stageOneContent + '# MODULE:  ' + sessionData['MODULE']['NAME'] + '\n'
            if 'PAYLOAD' in sessionData:
                stageOneContent = stageOneContent + '# PAYLOAD:  ' + sessionData['PAYLOAD']['NAME'] + '\n'
                sessionData['PAYLOAD']['PRIMARY_PORT'] = portNum.get()
                uniqueId = str(sessionData['PAYLOAD']['PRIMARY_PORT'])
                if 'reverse' in sessionData['PAYLOAD']['NAME'].lower() \
                    and sessionData['MODULE']['NAME'].lower() == 'exploit/multi/handler':
                    sessionData['MSF_HOST']['LISTEN_PORTS'].append(str(sessionData['PAYLOAD']['PRIMARY_PORT']))
            else:
                uniqueId = getTimestamp()
            stageOneContent = stageOneContent + '# TARGET:   ' + host['IP_ADDRESS'] + '\n'
            stageOneContent = stageOneContent + '# MSF_HOST: ' + sessionData['MSF_HOST']['IP_ADDRESS'] + '\n'
            stageOneContent = stageOneContent + '#\n'
            if sessionData['MODULE']['NAME'].lower() == 'exploit/multi/handler':
                # WE NEED TO ADD THE MSFVENOM COMMAND TO MAKE THE PAYLOAD TO THE STAGE ONE SCRIPT
                sessionData['PAYLOAD']['FILENAME'] =    '-'.join(sessionData['PAYLOAD']['NAME'].split('/')) + \
                                                        '-' + 'x'.join(host['IP_ADDRESS'].split('.')) + \
                                                        '-' + uniqueId
                sessionData['PAYLOAD']['VENOM_CMD'] =  apt_shared.makeVenomCmd(host, 
                                                                               sessionData, 
                                                                               portNum, 
                                                                               configData['LOG_FILE'])
                #ADD VENOM COMMAND TO THE SCRIPT CONTENT
                stageOneContent = stageOneContent + sessionData['PAYLOAD']['VENOM_CMD'] + '\n'
                stageOneContent = stageOneContent + 'mv ' + sessionData['PAYLOAD']['FILENAME'] + \
                                            ' ' + sessionData['MSF_HOST']['MSF_PAYLOAD_PATH'] + '/' +  sessionData['PAYLOAD']['FILENAME'] + '\n'
                stageOneContent = stageOneContent + "sleep 20\n"
                sessionData['RC_IN_SCRIPT_NAME'] = sessionData['MSF_HOST']['RC_PATH'] + '/' + sessionData['PAYLOAD']['FILENAME'].split('.')[0]+'.rc'
            else:
                sessionData['RC_IN_SCRIPT_NAME'] = sessionData['MSF_HOST']['RC_PATH'] + '/' + '-'.join(sessionData['MODULE']['NAME'].split('/')) + '_' + \
                                                    host['IP_ADDRESS'] + '_' + uniqueId + '.rc'
            sessionData['RC_OUT_SCRIPT_NAME'] = sessionData['RC_IN_SCRIPT_NAME'] + '.txt'
            rcScriptContent = apt_shared.makeRcScript(configData['COMMAND_LIST'],
                                                      host, 
                                                      sessionData, 
                                                      configData['LOG_FILE'],
                                                      portNum)
            stageOneContent = stageOneContent + rcScriptContent + '\n'
            if 'PAYLOAD' in sessionData \
                and 'bind' in sessionData['PAYLOAD']['NAME'].lower() \
                and sessionData['MODULE']['NAME'].lower() == 'exploit/multi/handler':
                    launchBind = './msfconsole -qr '+ sessionData['RC_IN_SCRIPT_NAME'] + ' > ' + sessionData['RC_OUT_SCRIPT_NAME'] + '&\n'
                    logLaunch = "echo 'LAUNCHING " + sessionData['RC_IN_SCRIPT_NAME'] + "' >> " + sessionData['MSF_HOST']['STAGE_THREE_LOGFILE'] + '\n'
                    sessionData['MSF_HOST']['STAGE_THREE_SCRIPT'] = sessionData['MSF_HOST']['STAGE_THREE_SCRIPT'] + launchBind
                    sessionData['MSF_HOST']['STAGE_THREE_SCRIPT'] = sessionData['MSF_HOST']['STAGE_THREE_SCRIPT'] + logLaunch
                    logLaunch = "echo 'SUCCESSFULLY LAUNCHED " + sessionData['RC_IN_SCRIPT_NAME'] + "' >> " + sessionData['MSF_HOST']['STAGE_THREE_LOGFILE'] + '\n'
                    sessionData['MSF_HOST']['STAGE_THREE_SCRIPT'] = sessionData['MSF_HOST']['STAGE_THREE_SCRIPT'] + logLaunch
                    sessionData['MSF_HOST']['STAGE_THREE_SCRIPT'] = sessionData['MSF_HOST']['STAGE_THREE_SCRIPT'] + "sleep 10\n"
            else:
                stageOneContent = stageOneContent + './msfconsole -qr '+ \
                                        sessionData['RC_IN_SCRIPT_NAME'] + ' > ' + sessionData['RC_OUT_SCRIPT_NAME'] + ' &\n'
            sessionData['MSF_HOST']['STAGE_ONE_SCRIPT'] = sessionData['MSF_HOST']['STAGE_ONE_SCRIPT'] + stageOneContent

    """
    ONCE ALL THE RC AND VENOM STUFF IS IN THE STAGE ONE SCRIPT, ADD THE COMMAND TO 
    START AN HTTP SERVER TO SERVE THE PAYLOADS, THEN WRITE THE SCRIPT TO A LOCAL FILE, 
    UPLOAD IT, AND RUN IT ON THE MSF_HOST
    """
    for msfHost in configData['MSF_HOSTS']:
        msfHost['STAGE_ONE_SCRIPT'] = msfHost['STAGE_ONE_SCRIPT'] + "cd " + msfHost['MSF_PAYLOAD_PATH'] + "/" + "\n"
        msfHost['STAGE_ONE_SCRIPT'] = msfHost['STAGE_ONE_SCRIPT'] + "python -m SimpleHTTPServer " + str(configData['HTTP_PORT']) + " &\n"
        msfHost['STAGE_ONE_SCRIPT'] = msfHost['STAGE_ONE_SCRIPT'] + "echo '' > netstat.txt\n"
        msfHost['STAGE_ONE_SCRIPT'] = msfHost['STAGE_ONE_SCRIPT'] + "for i in {1..50}; do\n"
        # If you reset the file each time, there's a very god chance of getting empty files dring the write process.
        msfHost['STAGE_ONE_SCRIPT'] = msfHost['STAGE_ONE_SCRIPT'] + "  netstat -ant >> netstat.txt\n"
        msfHost['STAGE_ONE_SCRIPT'] = msfHost['STAGE_ONE_SCRIPT'] + "  sleep 5\n"
        msfHost['STAGE_ONE_SCRIPT'] = msfHost['STAGE_ONE_SCRIPT'] + "done\n"
        try:
            fileObj = open(msfHost['STAGE_ONE_FILENAME'], 'w')
            fileObj.write(msfHost['STAGE_ONE_SCRIPT'])
            fileObj.close()
        except IOError as e:
            logMsg(configData['LOG_FILE'], "[ERROR] FAILED TO WRITE TO FILE " + msfHost['STAGE_ONE_FILENAME'] + str(e))
            bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
        remoteStageOneScriptName = msfHost['SCRIPT_PATH'] + '/stageOneScript.sh'
        msfHost['VM_OBJECT'].makeDirOnGuest(msfHost['MSF_ARTIFACT_PATH'])
        msfHost['VM_OBJECT'].makeDirOnGuest(msfHost['SCRIPT_PATH'])
        """
        RUN STAGE ONE SCRIPTS
        """
        msfHost['VM_OBJECT'].uploadAndRun(msfHost['STAGE_ONE_FILENAME'], remoteStageOneScriptName)
    
    """
    WAIT FOR THE STAGE ONE SCRIPT TO FINISH....
    
    THERE ARE TWO PARTS TO DETECT THE COMPLETION OF STAGE ONE SCRIPTS:
    THE LAST INSTRUCTION IN THE STAGE ONE SCRIPT IS TO START AN HTTP SERVER TO PROVIDE PAYLOADS, SO WE WAIT UNTIL 
    THE HTTP PROCESS APPEARS.  UNFORUNATELY, MSFCONSOLE TAKES SEVERAL SECONDS TO START.  TO MAKE SURE WE DO NOT 
    LAUNCH THE REVERSE PAYLOADS BEFORE THE REVERSE HANDLERS ARE READY, THE REMOTE STAGE ONE SCRIPT HAS A FOR LOOP 
    WHERE IT DUMPS THE NETSTAT OUTPUT CONTAINING THE LISTENING PORT DATA TO A FILE. THIS SCRIPT PULLS THAT FILE 
    EVERY 5 SECONDS AFTER IT SEES THAT THE HTTP SERVER STARTED AND CHECKS TO SEE IF THE REVERSE LISTENERS HAVE STARTED.
    ONCE THOSE LISTENERS HAVE STARTED, WE MOVE TO STAGE 2.    
    """
    
    """
    WAIT FOR HTTP SERVERS TO START ON MSF_VMs
    """
    logMsg(configData['LOG_FILE'], "WAITING FOR STAGE ONE SCRIPT(S) TO COMPLETE...")
    modCounter = 0
    for host in configData['MSF_HOSTS']:
        host['SCRIPT_COMPLETE'] = False
    scriptComplete = False
    while scriptComplete == False:
        modCounter = modCounter + 1
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            print("CAUGHT KEYBOARD INTERRUPT; ABORTING TEST AND RESETTING VMS....")
            bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
        scriptComplete = True
        for host in configData['MSF_HOSTS']:
            if host['SCRIPT_COMPLETE'] == False:
                scriptComplete = False
                if modCounter % 5 == 0:
                    logMsg(configData['LOG_FILE'], "WAITING FOR PYTHON HTTP SERVER TO START ON " + host['NAME'])
                msfHost['VM_OBJECT'].updateProcList()
                for procEntry in msfHost['VM_OBJECT'].procList:
                    if ('python' in procEntry.lower()) and (str(configData['HTTP_PORT']) in procEntry):
                        logMsg(configData['LOG_FILE'], "PYTHON HTTP SERVER FOUND ON " + host['NAME'])
                        logMsg(configData['LOG_FILE'], str(procEntry))
                        host['SCRIPT_COMPLETE'] = True
                        
    """
    HTTP SERVERS HAVE STARTED; CHECK NETSTAT LOGS TO ENSURE ALL REQUIRED PORTS ARE LISTENING
    """
    for waitCycles in range(60):
        stageTwoComplete = True
        try:
            logMsg(configData['LOG_FILE'], "CHECKING netstat OUTPUT")
            remoteFile = host['MSF_PAYLOAD_PATH'] + "/netstat.txt"
            for host in configData['MSF_HOSTS']:
                hostReady = True
                if 0 == len(host['LISTEN_PORTS']):
                    logMsg(configData['LOG_FILE'], "NO PORTS REQUIRED FOR " + host['NAME'] + "\n")
                    host['READY'] = True
                if 'READY' in host and host['READY'] == True:
                    logMsg(configData['LOG_FILE'], "ALL REQUIRED PORTS READY ON " + host['NAME'] + "\n")
                else:
                    logMsg(configData['LOG_FILE'], "PORT " + str(host['LISTEN_PORTS']) + " SHOULD BE OPEN ON " + host['NAME'] + "\n")
                    localFile = configData['REPORT_DIR'] + "/" + host['NAME'] + "_netstat_" + str(waitCycles) + ".txt"
                    host['VM_OBJECT'].getFileFromGuest(remoteFile, localFile)
                    try:
                        netstatFile = open(localFile, 'r')
                        netstatData = netstatFile.read()
                        netstatFile.close()
                    except Exception as e:
                        logMsg(configData['LOG_FILE'], "FAILED READING NETSTAT FILE: " + localFile + "\n" + str(e))
                        #IF WE DID NOT GET A  FILE, WE CANNOT SAY THAT THE PORTS ARE READY
                        netstatData = ""
                        pass
                    for port in host['LISTEN_PORTS']:
                        if str(port) not in netstatData:
                            hostReady = False
                            logMsg(configData['LOG_FILE'], "PORT " + str(port) + " NOT OPEN ON " + host['NAME'] + "\n")
                        else:
                            logMsg(configData['LOG_FILE'], "PORT " + str(port) + " IS OPEN ON " + host['NAME'] + "\n")
                    if hostReady == False:
                        stageTwoComplete = False
                    else:
                        host['READY'] = True
            if stageTwoComplete == True:
                break;    
            time.sleep(5)
        except KeyboardInterrupt:
            print("CAUGHT KEYBOARD INTERRUPT; ABORTING TEST AND RESETTING VMS....")
            bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
    waitCycles = 3
    for i in range(waitCycles):
        logMsg(configData['LOG_FILE'], "SLEEPING FOR " + str((waitCycles-i)*10) + " SECONDS")
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            print("CAUGHT KEYBOARD INTERRUPT; ABORTING TEST AND RESETTING VMS....")
            bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
    """
    STAGE TWO STUFF
    """
    
    """
    MAKE PYTHON AND/OR BASH(ISH) STAGE TWO SCRIPTS TO DOWNLOAD AND START PAYLOADS ON TARGET VMs
    """
    stageTwoWaitNeeded = False
    stageTwoNeeded = False
    stageThreeNeeded = False
    remoteInterpreter =     None
    terminationToken = "!!! STAGE TWO COMPLETE !!!"
    secDelay = 180
    addScheduleDelay = False
    for target in configData['TARGETS']:
        logMsg(configData['LOG_FILE'], "PROCESSING " + target['NAME'])
        for sessionData in target['SESSION_DATASETS']:
            if 'PAYLOAD' in sessionData:
                stageTwoNeeded = True
                if 'bind' in sessionData['PAYLOAD']['NAME']:
                    stageThreeNeeded = True
        if stageTwoNeeded:
            if 'VM_TOOLS_UPLOAD' in target['METHOD'].upper():
                escapedIp = 'x'.join(target['IP_ADDRESS'].split('.'))
                logMsg(configData['LOG_FILE'], "I THINK " + target['NAME'] + " HAS IP ADDRESS " + target['IP_ADDRESS'])
                if 'win' in target['NAME'].lower():
                    target['REMOTE_LOG'] = target['PAYLOAD_DIRECTORY'] + "\\stageTwoLog.txt"
                    target['STAGE_TWO_FILENAME'] = "stageTwoScript_" +  escapedIp + ".py"
                    remoteScriptName =  target['PAYLOAD_DIRECTORY'] + "\\" + target['STAGE_TWO_FILENAME']
                    localScriptName =   configData['SCRIPT_DIR'] + "/" + target['STAGE_TWO_FILENAME']
                    remoteInterpreter = target['PYTHON']
                    target['STAGE_TWO_SCRIPT'] = target['STAGE_TWO_SCRIPT'] + \
                        apt_shared.makeStageTwoPyScript(target, configData['HTTP_PORT'], target['REMOTE_LOG'], terminationToken)
                else:
                    target['REMOTE_LOG'] = target['PAYLOAD_DIRECTORY'] + "/stageTwoLog.txt"
                    target['STAGE_TWO_FILENAME'] = "stageTwoScript_" +  escapedIp + ".sh"
                    remoteScriptName =  target['PAYLOAD_DIRECTORY'] + "/" + target['STAGE_TWO_FILENAME']
                    localScriptName =   configData['SCRIPT_DIR'] + "/" + target['STAGE_TWO_FILENAME']
                    remoteInterpreter = None
                    target['STAGE_TWO_SCRIPT'] = target['STAGE_TWO_SCRIPT'] + \
                        apt_shared.makeStageTwoShScript(target, configData['HTTP_PORT'], target['REMOTE_LOG'], terminationToken)
                localScriptName =   configData['SCRIPT_DIR'] + "/" + target['STAGE_TWO_FILENAME']
                try:
                    fileObj = open(localScriptName, 'w')
                    fileObj.write(target['STAGE_TWO_SCRIPT'])
                    fileObj.close()
                except IOError as e:
                    logMsg(configData['LOG_FILE'], "[ERROR] FAILED TO WRITE TO FILE " + localScriptName + str(e))
                    bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
                logMsg(configData['LOG_FILE'], "METHOD= " + target['METHOD'])
                if ('win' in target['NAME'].lower()) and ('schedule' in target['METHOD'].lower()):
                    addScheduleDelay = True
                    launchResult = target['VM_OBJECT'].uploadAndSchedule(localScriptName, remoteScriptName, secDelay, remoteInterpreter)
                else:
                    launchResult = target['VM_OBJECT'].uploadAndRun(localScriptName, remoteScriptName, remoteInterpreter)
                if launchResult:
                    logMsg(configData['LOG_FILE'], "[INFO]: SUCCESSFULLY LAUNCHED " + localScriptName + " ON " + target['VM_OBJECT'].vmName)
                else:
                    logMsg(configData['LOG_FILE'], "[FATAL ERROR]: FAILED TO UPLOAD/EXECUTE " + localScriptName + " ON " + target['VM_OBJECT'].vmName)
                    #bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
        else:
            logMsg(configData['LOG_FILE'], "NO STAGE TWO REQUIRED FOR " + target['NAME'])
    if addScheduleDelay:
        #IF WE SCHEDULED THE JOBS, ADD THE DELAY IN BEFORE WE BOTHER CHECKING ON THE PROGESS
        realSleepTime = secDelay + 60
        logMsg(configData['LOG_FILE'], "[INFO]: SLEEPING FOR " + str(realSleepTime) + " TO ALLOW SCHEDULED TASKS TO START")
        time.sleep(realSleepTime)
    else:
        logMsg(configData['LOG_FILE'], "NO STAGE TWO WAIT REQUIRED")
    
    """
    KEEP PULLING AND CHECKING THE REMOTE STAGE TWO LOG UNTIL WE SEE THE TERMINATION TOKEN
    """
    if stageTwoNeeded:
        for waitCycles in range(60):
            stageTwoComplete = True
            if 'VM_TOOLS_UPLOAD' in target['METHOD'].upper():
                try:
                    for host in configData['TARGETS']:
                        if 'TERMINATION_TOKEN' not in host:
                            localFile = configData['REPORT_DIR'] + "/" + host['NAME'] + "_stageTwoLog_" + str(waitCycles) + ".txt"
                            host['VM_OBJECT'].getFileFromGuest(host['REMOTE_LOG'], localFile)
                            try:
                                logFileObj = open(localFile, 'r')
                                logData = logFileObj.read()
                                logFileObj.close()
                            except IOError as e:
                                logMsg(configData['LOG_FILE'], "FAILED READING REMOTE LOG FILE: " + localFile + "\n" + str(e))
                                logData = ""
                                pass
                            if terminationToken not in logData:
                                logMsg(configData['LOG_FILE'], "NO TERMINATION TOKEN IN LOGFILE ON " + host['NAME'] + "\n")
                                stageTwoComplete = False
                            else:
                                logMsg(configData['LOG_FILE'], "TERMINATION TOKEN FOUND IN LOGFILE ON " + host['NAME'] + "\n")
                                localFile = configData['REPORT_DIR'] + "/" + host['NAME'] + "_netstat_" + str(waitCycles) + ".txt"
                                host['TERMINATION_TOKEN'] = True
                        else:
                            logMsg(configData['LOG_FILE'], "ALREADY FOUND TERMINATION TOKEN ON " + host['NAME'] + "\n")
                    if stageTwoComplete == True:
                        break;    
                    time.sleep(5)
                except KeyboardInterrupt:
                    print("CAUGHT KEYBOARD INTERRUPT; ABORTING TEST AND RESETTING VMS....")
                    bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])

    else:
        logMsg(configData['LOG_FILE'], "NO STAGE TWO REQUIRED")
    """
    MAKE STAGE THREE SCRIPT TO RUN BIND HANDLERS ON MSF HOSTS
    """
    if stageThreeNeeded:
        for msfHost in configData['MSF_HOSTS']:
            localScriptName = configData['SCRIPT_DIR'] + "/stageThree_" + '-'.join(msfHost['IP_ADDRESS'].split('.')) + ".sh"
            try:
                fileObj = open(localScriptName, 'w')
                fileObj.write(msfHost['STAGE_THREE_SCRIPT'])
                fileObj.close()
            except IOError as e:
                logMsg(configData['LOG_FILE'], "[ERROR] FAILED TO OPEN FILE " + localScriptName + '\n' + str(e))
                bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
            remoteScriptName = msfHost['SCRIPT_PATH'] + "/stageThree.sh"
            remoteInterpreter = None
            if not msfHost['VM_OBJECT'].uploadAndRun(localScriptName, remoteScriptName, remoteInterpreter):
                logMsg(configData['LOG_FILE'], "[FATAL ERROR]: FAILED TO UPLOAD/EXECUTE " + localScriptName + " ON " + msfHost['VM_OBJECT'].vmName)
                bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
        logMsg(configData['LOG_FILE'], "WAITING FOR MSFCONSOLES TO LAUNCH...")
        time.sleep(20)
    else:
        logMsg(configData['LOG_FILE'], "NO STAGE THREE SCRIPTS NEEDED")
        
    """
    WAIT FOR THE METERPRETER SESSIONS TO FINISH....
    """
    modCounter = 0
    msfDone = False
    loopCounter = 0
    msfConsoleCount = 1
    maxLoops = sessionCounter * 5 + 100
    try:
        while not msfDone:
            msfDone = True
            for msfHost in configData['MSF_HOSTS']:
                msfHost['VM_OBJECT'].updateProcList()
                msfConsoleCount = 0
                for procEntry in msfHost['VM_OBJECT'].procList:
                    if 'msfconsole' in procEntry:
                        msfConsoleCount = msfConsoleCount + 1
                        msfDone = False
                time.sleep(1)
                if modCounter % 10 == 0:
                    logMsg(configData['LOG_FILE'], str(msfConsoleCount) + " msfconsole PROCESSES STILL RUNNING ON " + msfHost['NAME'])
            loopCounter = loopCounter + 1
            logMsg(configData['LOG_FILE'], str(maxLoops-loopCounter) + " LOOPS REMAINING BEFORE AUTOMATIC EXIT")
            if maxLoops<loopCounter:
                break
    except KeyboardInterrupt:
        print("CAUGHT KEYBOARD INTERRUPT; SKIPPING THE NORMAL WAIT BUT PROCESSING THE DATA AND REVERTING VMS")
        """
        PULL STAGE THREE LOG FILES FROM MSF VMS
        """
    if stageThreeNeeded:
        for msfHost in configData['MSF_HOSTS']:
            remoteFileName = msfHost['STAGE_THREE_LOGFILE']
            localFileName = configData['REPORT_DIR'] + '/' + msfHost['NAME'] + "_stageThreeLog.txt"
            msfHost['VM_OBJECT'].getFileFromGuest(remoteFileName, localFileName)
    else:
        logMsg(configData['LOG_FILE'], "NO STAGE THREE LOGFILES")
        
    """
    PULL REPORT FILES FROM EACH TEST VM
    """
    for target in configData['TARGETS']:
        for sessionData in target['SESSION_DATASETS']:
            msfPath = sessionData['MSF_HOST']['MSF_PATH']
            remoteFileName = sessionData['RC_OUT_SCRIPT_NAME']
            logMsg(configData['LOG_FILE'], "RC_OUT_SCRIPT_NAME = " + str(sessionData['RC_OUT_SCRIPT_NAME']))
            logMsg(configData['LOG_FILE'], "SESSION_DIR = " + configData['SESSION_DIR'])
            logMsg(configData['LOG_FILE'], "RC_OUT_SCRIPT_NAME = " + str(sessionData['RC_OUT_SCRIPT_NAME'].split('/')[-1]))
            localFileName = configData['SESSION_DIR'] + '/' + str(sessionData['RC_OUT_SCRIPT_NAME'].split('/')[-1])
            sessionData['LOCAL_SESSION_FILE'] = localFileName
            logMsg(configData['LOG_FILE'], "SAVING " + target['NAME'] + ":" + remoteFileName + " AS " + localFileName)
            if not sessionData['MSF_HOST']['VM_OBJECT'].getFileFromGuest(remoteFileName, localFileName):
                logMsg(configData['LOG_FILE'], "FAILED TO SAVE " + target['NAME'] + ":" + remoteFileName + " AS " + localFileName)
                #bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
            remoteFileName = sessionData['RC_IN_SCRIPT_NAME']
            localFileName = configData['SESSION_DIR'] + '/' + str(sessionData['RC_IN_SCRIPT_NAME'].split('/')[-1])
            if not sessionData['MSF_HOST']['VM_OBJECT'].getFileFromGuest(remoteFileName, localFileName):
                logMsg(configData['LOG_FILE'], "FAILED TO SAVE " + target['NAME'] + ":" + remoteFileName + " AS " + localFileName)
                #bailSafely(logFile, configData['TARGETS'], configData['MSF_HOSTS'])
    logMsg(configData['LOG_FILE'], "FINISHED DOWNLOADING REPORTS")
    
    """
    GET COMMIT VERSION AND PCAPS
    """
    for msfHost in configData['MSF_HOSTS']:
        msfHost['VM_OBJECT'].runCmdOnGuest(['/usr/bin/killall', 'tcpdump'])
        srcFile = msfHost['PCAP_FILE']
        dstFile = configData['REPORT_DIR'] + "/" + msfHost['NAME'] + ".pcap"
        msfHost['LOCAL_PCAP'] = dstFile
        msfHost['VM_OBJECT'].getFileFromGuest(srcFile, dstFile)
        srcFile = msfHost['COMMIT_FILE']
        dstFile = configData['REPORT_DIR'] + "/commit_" + '-'.join(msfHost['IP_ADDRESS'].split('.')) + ".txt"
        msfHost['VM_OBJECT'].getFileFromGuest(srcFile, dstFile)
        try:
            fileObj = open(dstFile, 'r')
            commitRaw = fileObj.read().strip()
            fileObj.close()
        except IOError as e:
            logMsg(logFile, "FAILED TO OPEN " + dstFile)
            logMsg(logFile, "SYSTEM ERROR: \n" + str(e))
        else:
            try:
                msfHost['COMMIT_VERSION'] = commitRaw.split(' ')[1]
                logMsg(configData['LOG_FILE'], "COMMIT VERSION OF metasploit-framework on " + msfHost['NAME'] + ": " + msfHost['COMMIT_VERSION'])
            except:
                logMsg(configData['LOG_FILE'], "FAILED TO RETRIEVE COMMIT VERSION")
                msfHost['COMMIT_VERSION'] = "UNKNOWN"
    
    """
    COALLATE DATA
    """
    testResult = True
    for target in configData['TARGETS']:
        logMsg(configData['LOG_FILE'], "CHECKING " + target['NAME'])
        for sessionData in target['SESSION_DATASETS']:
            payloadName = "NONE"
            if 'PAYLOAD' in sessionData:
                payloadName = sessionData['PAYLOAD']['NAME']
            logMsg(configData['LOG_FILE'], "CHECKING " + sessionData['MODULE']['NAME'] + ":" + payloadName)
            statusFlag = True
            try:
                fileObj = open(sessionData['LOCAL_SESSION_FILE'], 'r')
                fileContents = fileObj.read()
                fileObj.close()
            except IOError as e:
                logMsg(configData['LOG_FILE'], "FAILED TO OPEN LOCAL REPORT FILE: " + sessionData['LOCAL_SESSION_FILE'])
                continue
            for item in target['SUCCESS_LIST']:
                if item not in fileContents:
                    logMsg(configData['LOG_FILE'], str(item))
                    statusFlag = False
            sessionData['STATUS'] = statusFlag
            if statusFlag:
                logMsg(configData['LOG_FILE'], sessionData['LOCAL_SESSION_FILE'])
                logMsg(configData['LOG_FILE'], "TEST PASSED: " + \
                       target['NAME'] + ':' + \
                       payloadName + ":" + \
                       sessionData['MODULE']['NAME'])
            else:
                testResult = False
                logMsg(configData['LOG_FILE'], sessionData['LOCAL_SESSION_FILE'])
                logMsg(configData['LOG_FILE'], "TEST FAILED: " + \
                        target['NAME'] + ':' + \
                        payloadName + ":" + \
                       sessionData['MODULE']['NAME'])
    
    htmlReportString = apt_shared.makeHtmlReport(configData['TARGETS'], configData['MSF_HOSTS'])
    htmlFileName = configData['REPORT_DIR'] + "/" + configData['REPORT_PREFIX'] + ".html"
    try:
        fileObj = open(htmlFileName, 'w')
        fileObj.write(htmlReportString)
        fileObj.close()
    except IOError as e:
        logMsg(logFile, "FAILED TO OPEN " + htmlFileName)
        logMsg(logFile, "SYSTEM ERROR: \n" + str(e))
    """
    RETURN ALL TESTING VMS TO TESTING_BASE
    RETURN DEV VM TO WHERE WE FOUND IT
    POWER OFF ALL VMS
    """
    for msfHost in configData['MSF_HOSTS']:
        if msfHost['TYPE'] == 'VIRTUAL':
            msfHost['VM_OBJECT'].revertMsfVm()
            msfHost['VM_OBJECT'].powerOff()
    for target in configData['TARGETS']:
        if target['TYPE'] == 'VIRTUAL':
            logMsg(configData['LOG_FILE'], "REVERTING " + target['NAME'])
            target['VM_OBJECT'].revertToTestingBase()
            target['VM_OBJECT'].powerOff()

    logMsg(configData['LOG_FILE'], "WAITING FOR ALL TASKS TO COMPLETE")
    time.sleep(5)
    if testResult:
        logMsg(configData['LOG_FILE'], "TEST SUCCEEDED")
        if args.verbose:
            print("PASSED")
        exit(0)
    else:
        logMsg(configData['LOG_FILE'], "TEST FAILED")
        if args.verbose:
            print("FAILED")
        exit(999)
    
if __name__ == "__main__":
    main()
    
