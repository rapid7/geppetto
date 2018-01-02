from datetime import datetime
import os
import time
import json
import vm_automation


#
# GOT TIRED OF TRACKING THIS DATA IN A LIST
# 
class portValue:
    """
    THE BELOW portValue CLASS IS HOW I DECIDED TO TRACK THE PORT NUMBERS
    I WANTED A SINGLETON, BUT I FOUND NOTHING IN PYTHON THAT DID THAT.
    THIS CLASS LETS ME SIMPLY CALL get.portValue() AND IT RETURNS A 
    UNIQUE PORT VALUE, SO I DO NOT HAVE TO TRACK WHICH VALUES HAVE BEEN USED.
    """
    def __init__(self, initialValue):
        self.portNumber = initialValue
        
    def get(self):
        self.portNumber = self.portNumber + 1
        return self.portNumber

def getSessionCount(configData):
    sessionCount = 0
    for host in configData['TARGETS']:
        if 'SESSION_DATASETS' in host:
            sessionCount = sessionCount + len(host['SESSION_DATASETS'])
        else:
            logMsg(configData['LOG_FILE'], "NO TESTING DATA LISTED FOR " + host['NAME'])
            bailSafely(configData)
    return sessionCount

def setupSessionData(configData):
    for target in configData['TARGETS']:
        logMsg(configData['LOG_FILE'], str(target))
        if 'MODULES' not in target:
            logMsg(configData['LOG_FILE'], "CONFIG FILE DID NOT HAVE MODULES LISTED FOR " + target['NAME'] + ".  NOTHING TO TEST?")
            bailSafely(configData)
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
    
def replacePortKeywords(configData, portNum):
    for target in configData['TARGETS']:
        logMsg(configData['LOG_FILE'], "MODULES = " + str(target['MODULES']))
        if 'PAYLOADS' in target:
            logMsg(configData['LOG_FILE'], "PAYLOADS = " + str(target['PAYLOADS']))
            for payload in target['PAYLOADS']:
                logMsg(configData['LOG_FILE'], str(payload))
                #REPLACE THE STRING 'UNIQUE_PORT' WITH AN ACTUAL UNIQUE PORT
                for settingItem in payload['SETTINGS']:
                    logMsg(configData['LOG_FILE'], "SETTING ITEM= " + settingItem + str(id(settingItem)))
                    logMsg(configData['LOG_FILE'], "SETTING ITEM= " + settingItem + str(id(settingItem)))
        for module in target['MODULES']:
            logMsg(configData['LOG_FILE'], str(module))
            for index in range(len(module['SETTINGS'])):
                logMsg(configData['LOG_FILE'], "SETTING ITEM= " + module['SETTINGS'][index] + str(id(module['SETTINGS'][index])))

def expandPayloadsAndModules(configData):
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

def prepConfig(args):
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
    if 'FRAMEWORK_BRANCH' not in configData:
        configData['FRAMEWORK_BRANCH'] = 'upstream/master'
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
            bailSafely(configData)
    return configData

def revertVm(vmObject, snapshot = None):
    if vmObject == None:
        return False
    vmObject.getSnapshots()
    if snapshot != None:
        """
        JUST RETURN TO THE TESTING SNAPSHOT
        """
        return vmObject.revertToSnapshotByName(snapshot)
    else:
        """
        JUST RESTED TO THE TEMP SNAPSHOT
        """
        vmObject.snapshotList.sort(reverse=True)
        for i in vmObject.snapshotList:
            if "PAYLOAD_TESTING-" in i[0].name:
                self.server.logMsg("REVERTING " + self.vmName + " TO " + i[0].name)
                self.revertToSnapshot(i[0].snapshot)
                self.deleteSnapshot(i[0].name)
        vmObject.powerOff()
        return True

def bailSafely(testConfig):
    if testConfig != None and 'LOG_FILE' in testConfig:
        logFile = testConfig['LOG_FILE']
        logMsg(logFile, "AN ERROR HAPPENED; RETURNING VMS TO THEIR FULL UPRIGHT AND LOCKED POSITIONS")
        timeToWait = 10
        for i in range(timeToWait):
            logMsg(logFile, "SLEEPING FOR " + str(timeToWait-i) + " SECOND(S); EXIT NOW TO PRESERVE VMS!")
            time.sleep(1)
        try:
            for host in  (testConfig['MSF_HOSTS'] + testConfig['TARGETS']):
                if host['TYPE'] == "VIRTUAL":
                    if 'TESTING_SNAPSHOT' in host:
                        snapshot = host['TESTING_SNAPSHOT']
                    else:
                        snapshot = None
                    revertVm(host['VM_OBJECT'], snapshot)
        except Exception as e:
            logMsg(logFile, "SLEEPING FOR " + str(timeToWait-i) + " SECOND(S); EXIT NOW TO PRESERVE VMS!")
            pass
    else:
        print("UNABLE TO RESET VMS")
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


def loadJson(fileName):
    """
    READ IN THE JSON FILES AND RETURN A DICTIONARY
    GOT TIRED OF WRITING THE TRY/CATCH BLOCKS IN A COUPLE PLACES
    """
    retDict = None
    try:
        fileObj = open(fileName, 'r')
        jsonStr = fileObj.read()
        fileObj.close()
    except IOError as e:
        logMsg("FAILED TO FIND JSON FILE " + fileName + "\n" + str(e))
        return retDict
    try:
        retDict = json.loads(jsonStr)
    except ValueError as f:
        logMsg("FAILED TO PARSE JSON FILE " + fileName + "\n" + str(f))
    return retDict

def makeHtmlReport(targetData, msfHosts):
    htmlString = "<html>\n<head>\n<title>\n\tTEST RESULTS\n</title>\n</head>\n\n<body>\n"
    htmlString = htmlString + "<table border=\"1\">\n<tr><td>MSF_HOST NAME</td><td>MSF_HOST IP</td><td>MSF COMMIT VERSION</td><td>PCAP</td></tr>\n"
    for msfHost in msfHosts:
        pcapLink = "<a href=" + msfHost['LOCAL_PCAP'] + ">PCAP FILE</a>"
        htmlString = htmlString + "<tr><td>" + msfHost['NAME'] + "</td><td>" + msfHost['IP_ADDRESS'] + "</td><td>" + msfHost['COMMIT_VERSION'] + "</td><td>" + pcapLink + "</td></tr>\n"
    htmlString = htmlString + "</table>\n"
    htmlString = htmlString + "<table border=\"1\">\n<tr><td>TARGET</td><td>TYPE</td><td>MSF_HOST</td><td>MODULE</td><td>PAYLOAD</td><td>STATUS</td><td>SESSION</td></tr>\n"
    passedString = "<td bgcolor = \"#00cc00\">PASSED</td>"
    failedString = "<td bgcolor = \"#cc0000\">FAILED</td>"
    for host in targetData:
        stageTwoFileName = "NONE?"
        if 'STAGE_TWO_FILENAME' in host:
            stageTwoFileName = host['STAGE_TWO_FILENAME']
        for sessionData in host['SESSION_DATASETS']:
            payloadFileName = "NO PAYLOAD FILE"
            payloadName = "NO PAYLOAD (AUX?)"
            interpreter = ""            
            if 'PAYLOAD' in sessionData:
                payloadName = sessionData['PAYLOAD']['NAME'].lower()
                if 'FILENAME' in sessionData['PAYLOAD']:
                    payloadFileName = sessionData['PAYLOAD']['FILENAME']
                if 'java' in payloadName:
                    interpreter = "<br>" + host['METERPRETER_JAVA']
                if 'python' in payloadName:
                    interpreter = "<br>" + host['METERPRETER_PYTHON']
            htmlString = htmlString + "<tr><td>" + host['NAME'] + "<br>" + host['IP_ADDRESS'] + "</td>" + \
                                    "<td>" + host['TYPE'] + "</td>" + \
                                    "<td>" + sessionData['MSF_HOST']['NAME'] + "<br>" + sessionData['MSF_HOST']['IP_ADDRESS'] + "</td>" + \
                                    "<td>" + sessionData['MODULE']['NAME'] + "</td>" + \
                                    "<td>" + payloadName + "<br>" + payloadFileName + interpreter + "</td>"
            if 'STATUS' in sessionData:
                if sessionData['STATUS']:
                    htmlString = htmlString + "<td bgcolor = \"#00cc00\">PASSED</td>\n"
                else:
                    htmlString = htmlString + "<td bgcolor = \"#cc0000\">FAILED</td>\n"
            else:
                htmlString = htmlString + "<td> NO STATUS LISTED?</td>\n"
            htmlString = htmlString + "<td><a href=" + sessionData['LOCAL_SESSION_FILE'] + ">SESSION CONTENT</a></td></tr>\n"

    htmlString = htmlString + "</table>\n</body>\n</html>\n"
    return htmlString

def makeVenomCmd(targetData, sessionData, portTracker, logFile):
    payloadData = sessionData['PAYLOAD']
    payloadType = payloadData['NAME']
    payloadFileName = payloadData['FILENAME']
    msfHostData = sessionData['MSF_HOST']
    """
    WHAT FILE EXTENSION SHOULD WE USE?
    """
    execFormat = ''
    if 'windows' in payloadData['NAME'].lower():
        payloadFileName = payloadFileName + ".exe"
        execFormat = ' -f exe '
    elif 'linux' in payloadData['NAME'].lower():
        payloadFileName = payloadFileName + ".elf"
        execFormat = ' -f elf '
    elif 'python' in payloadData['NAME'].lower():
        payloadFileName = payloadFileName + ".py"
    elif 'java' in payloadData['NAME'].lower():
        payloadFileName = payloadFileName + ".jar"
    else:
        logMsg(logFile, "UNKNOWN PAYLOAD TYPE: " + payloadData['NAME'].lower())
    payloadData['FILENAME'] = payloadFileName
    logMsg(logFile, "PAYLOAD FILENAME = " + payloadData['FILENAME'])
    msfVenomCmd = "./msfvenom -p " + payloadData['NAME'] + execFormat + " -o " + payloadData['FILENAME']
    # ADD HOST DATA
    if 'bind' in payloadType.lower():
        msfVenomCmd = msfVenomCmd + " RHOST=" + targetData['IP_ADDRESS'] + " LPORT=" + str(payloadData['PRIMARY_PORT'])
    else:
        msfVenomCmd = msfVenomCmd + " LHOST=" + msfHostData['IP_ADDRESS'] + " LPORT=" + str(payloadData['PRIMARY_PORT'])
    for settingEntry in payloadData['SETTINGS']:
        msfVenomCmd = msfVenomCmd + " " + settingEntry
    logMsg(logFile, "msfvenom cmd = " + msfVenomCmd)
    return msfVenomCmd

def replaceWildcards(originalString, targetData, sessionData, portNum):
    if 'UNIQUE_PORT' in originalString:
        originalString = originalString.replace("UNIQUE_PORT", str(portNum.get()), 1)
    if 'MSF_IP' in originalString:
        originalString = originalString.replace("MSF_IP", sessionData['MSF_HOST']['IP_ADDRESS'], 1)
    if 'TARGET_IP' in originalString:
        originalString = originalString.replace("TARGET_IP", targetData['IP_ADDRESS'], 1)
    if 'TARGET_USERNAME' in originalString:
        originalString = originalString.replace("TARGET_USERNAME", targetData['USERNAME'], 1)
    if 'TARGET_PASSWORD' in originalString:
        originalString = originalString.replace("TARGET_PASSWORD", targetData['PASSWORD'], 1)
    return originalString

def makeRcScript(cmdList, targetData, sessionData, logFile, portNum):
    if 'PAYLOAD' in sessionData:
        payloadName = sessionData['PAYLOAD']['NAME']
    else:
        payloadName = "NONE"
    rcScriptContent =   "# HANDLER SCRIPT FOR \n" + \
                    "# MODULE:  " + sessionData['MODULE']['NAME'] + "\n" + \
                    "# PAYLOAD:  " + payloadName + "\n" + \
                    "# TARGET:   " + targetData['NAME'] + ' [' + targetData['IP_ADDRESS'] +"]\n" + \
                    "# MSF HOST: " + sessionData['MSF_HOST']['IP_ADDRESS'] + "\n"
    rcScriptName = sessionData['RC_IN_SCRIPT_NAME']
    rubySleep = "echo '<ruby>' >> " + rcScriptName + '\n'
    rubySleep = rubySleep + "echo '    sleep(2)' >> " + rcScriptName + '\n'
    rubySleep = rubySleep + "echo '</ruby>' >> " + rcScriptName + '\n'
    rcScriptContent = rcScriptContent + "echo 'use " + sessionData['MODULE']['NAME'] + " ' > " + rcScriptName + "\n"
    if sessionData['MODULE']['NAME'] != 'exploit/multi/handler':
        #THIS IS TERRIBLE, AND I WISH WE DID NOT HAVE TO DO THIS MAYBE ONLY FOR AUX LATER?
        rcScriptContent = rcScriptContent + "echo 'set RHOST " + targetData['IP_ADDRESS'] + " ' >> " + rcScriptName + "\n"
        rcScriptContent = rcScriptContent + "echo 'set RHOSTS " + targetData['IP_ADDRESS'] + " ' >> " + rcScriptName + "\n"
    for settingItem in sessionData['MODULE']['SETTINGS']:
        processedString = replaceWildcards(settingItem, targetData, sessionData, portNum)
        if '=' in processedString:
            rcScriptContent = rcScriptContent + "echo 'set " + processedString.split('=')[0] + ' ' + processedString.split('=')[1] + "' >> " + rcScriptName + '\n'
    if 'PAYLOAD' in sessionData:
        rcScriptContent = rcScriptContent + "echo 'set payload " + sessionData['PAYLOAD']['NAME'] +"' >> " + rcScriptName + '\n'
        for settingItem in sessionData['PAYLOAD']['SETTINGS']:
            rcScriptContent = rcScriptContent + "echo 'set " + settingItem.split('=')[0] + ' ' + settingItem.split('=')[1] + "' >> " + rcScriptName + '\n'
        if 'bind' in sessionData['PAYLOAD']['NAME']:
            rcScriptContent = rcScriptContent + "echo 'set RHOST " + targetData['IP_ADDRESS'] + "' >> " + rcScriptName + '\n'
            rcScriptContent = rcScriptContent + "echo 'set LPORT " + str(sessionData['PAYLOAD']['PRIMARY_PORT']) + "' >> " + rcScriptName + '\n'
        if 'reverse' in sessionData['PAYLOAD']['NAME']:
            rcScriptContent = rcScriptContent + "echo 'set LHOST " + sessionData['MSF_HOST']['IP_ADDRESS'] + "' >> " + rcScriptName + '\n'
            rcScriptContent = rcScriptContent + "echo 'set LPORT " + str(sessionData['PAYLOAD']['PRIMARY_PORT']) + "' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo 'show options' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + rubySleep
        if sessionData['MODULE']['NAME'] != 'exploit/multi/handler':
            rcScriptContent = rcScriptContent + "echo 'check' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo 'run -z' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '<ruby>' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '    while framework.sessions.count == 0 do '>> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '        sleep(1)' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '    end' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '    sleep(30)' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '</ruby>' >> " + rcScriptName + '\n'
    else:
        rcScriptContent = rcScriptContent + "echo 'show options' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + rubySleep
        rcScriptContent = rcScriptContent + "echo 'run -z' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '<ruby>' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '  sleep(10)' >> " + rcScriptName + '\n'
        rcScriptContent = rcScriptContent + "echo '</ruby>' >> " + rcScriptName + '\n'
        
    addSleep = True
    for cmd in cmdList:
        processedCmd = replaceWildcards(cmd, targetData, sessionData, portNum)
        rcScriptContent = rcScriptContent + "echo '" + processedCmd + "' >> " + rcScriptName + '\n'
        if "<ruby>" in processedCmd.lower():
            addSleep = False
        if "</ruby>" in processedCmd.lower():
            addSleep = True
        if addSleep:
            rcScriptContent = rcScriptContent + rubySleep
    rcScriptContent = rcScriptContent + "echo 'exit -y' >> " + rcScriptName + '\n'
    return rcScriptContent    

def makeStageTwoShScript(targetData, httpPort, remoteLogFile, terminationToken):
    stageTwoShContent = "# AUTOGENERATED TEST SCRIPT \n"
    stageTwoShContent = stageTwoShContent + "cd " + targetData['PAYLOAD_DIRECTORY'] + " \n"
    for sessionData in targetData['SESSION_DATASETS']:
        if 'PAYLOAD' in sessionData and sessionData['MODULE']['NAME'].lower() == "exploit/multi/handler":
            msfIpAddress = sessionData['MSF_HOST']['IP_ADDRESS']
            payloadFile = sessionData['PAYLOAD']['FILENAME']
            url = "'http://" + msfIpAddress + ":" + str(httpPort) + "/" + payloadFile + "'\n"
            stageTwoShContent = stageTwoShContent + "\nwget " + url + "\n"
            stageTwoShContent = stageTwoShContent + "sleep 5 \n"
            stageTwoShContent = stageTwoShContent + "chmod 755 " + payloadFile + "\n"
            if '.py' in payloadFile:
                stageTwoShContent = stageTwoShContent + targetData['METERPRETER_PYTHON'] + " " + payloadFile + "&\n"
            elif 'jar' in payloadFile:
                stageTwoShContent = stageTwoShContent + targetData['METERPRETER_JAVA'] + " -jar " + payloadFile + "&\n"
            else:
                stageTwoShContent = stageTwoShContent + "./" + payloadFile + "&\n"
    return stageTwoShContent

def makeStageTwoPyScript(targetData, httpPort, remoteLogFile, terminationToken):
    stageTwoPyContent = "# AUTOGENERATED TEST SCRIPT \n"
    stageTwoPyContent = stageTwoPyContent + "import subprocess\n"
    stageTwoPyContent = stageTwoPyContent + "import time\n"
    stageTwoPyContent = stageTwoPyContent + "import urllib\n"
    stageTwoPyContent = stageTwoPyContent + "\n"
    stageTwoPyContent = stageTwoPyContent + "def logError(logFile, logMessage):\n"
    stageTwoPyContent = stageTwoPyContent + "  try:\n"
    stageTwoPyContent = stageTwoPyContent + "    fileObj = open(logFile, 'a')\n"
    stageTwoPyContent = stageTwoPyContent + "    fileObj.write(logMessage)\n"
    stageTwoPyContent = stageTwoPyContent + "    fileObj.close()\n"
    stageTwoPyContent = stageTwoPyContent + "  except Exception as e:\n"
    stageTwoPyContent = stageTwoPyContent + "    print 'logError Failed: ' + str(e) + '\\n'\n"
    stageTwoPyContent = stageTwoPyContent + "    return False\n"
    stageTwoPyContent = stageTwoPyContent + "  return True\n"
    stageTwoPyContent = stageTwoPyContent + "\n"
    stageTwoPyContent = stageTwoPyContent + "def getPayload(url, localName, logFile):\n"
    stageTwoPyContent = stageTwoPyContent + "  downloadSuccess = False\n"
    stageTwoPyContent = stageTwoPyContent + "  for i in range(10):\n"
    stageTwoPyContent = stageTwoPyContent + "    logError(logFile, 'DOWNLOADING ' + url + '\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "    try:\n"
    stageTwoPyContent = stageTwoPyContent + "      urllib.urlretrieve(url, localName)\n"
    stageTwoPyContent = stageTwoPyContent + "    except Exception as e:\n"
    stageTwoPyContent = stageTwoPyContent + "      logError(logFile, 'FAILED TO GET ' + url + ':\\n' + str(e) + '\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "      time.sleep(5)\n"
    stageTwoPyContent = stageTwoPyContent + "      continue\n"
    stageTwoPyContent = stageTwoPyContent + "    logError(logFile, 'DOWNLOADED ' + url + '\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "    break\n"
    stageTwoPyContent = stageTwoPyContent + "  return True\n"
    stageTwoPyContent = stageTwoPyContent + "\n"
    stageTwoPyContent = stageTwoPyContent + "def runCommand(cmdList, getOutput, logFile):\n"
    stageTwoPyContent = stageTwoPyContent + "  logError(logFile, 'LAUNCHING ' + ' '.join(cmdList) + '\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "  try:\n"
    stageTwoPyContent = stageTwoPyContent + "    payloadProcess = subprocess.Popen(cmdList, stdout = subprocess.PIPE, stderr = subprocess.PIPE)\n"
    stageTwoPyContent = stageTwoPyContent + "  except Exception as e:\n"
    stageTwoPyContent = stageTwoPyContent + "    logError(logFile, 'FAILED TO RUN ' + ' '.join(cmdList) + ':\\n' + str(e) +'\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "    return False\n"
    stageTwoPyContent = stageTwoPyContent + "  logError(logFile, 'LAUNCHED ' + ' '.join(cmdList) + '\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "  time.sleep(5)\n"
    stageTwoPyContent = stageTwoPyContent + "  if getOutput:\n"
    stageTwoPyContent = stageTwoPyContent + "    return payloadProcess.communicate()\n"
    stageTwoPyContent = stageTwoPyContent + "  return True\n"
    stageTwoPyContent = stageTwoPyContent + "logError(r'" + remoteLogFile + "', 'TESTING\\n')\n"
    stageTwoPyContent = stageTwoPyContent + "\n"

    for sessionData in targetData['SESSION_DATASETS']:
        if 'PAYLOAD' in sessionData and sessionData['MODULE']['NAME'].lower() == "exploit/multi/handler":
            msfIpAddress = sessionData['MSF_HOST']['IP_ADDRESS']
            payloadFile = sessionData['PAYLOAD']['FILENAME']
            stageTwoPyContent = stageTwoPyContent + "url = 'http://" + msfIpAddress + ":" + str(httpPort) + "/" + payloadFile + "'\n"
            stageTwoPyContent = stageTwoPyContent + "fileName = r'" + targetData['PAYLOAD_DIRECTORY'] + '\\' + payloadFile + "'\n"
            if '.py' in payloadFile:
                stageTwoPyContent = stageTwoPyContent + "cmdList = [r'" + targetData['METERPRETER_PYTHON'] +"', fileName]\n"
            elif 'jar' in payloadFile:
                stageTwoPyContent = stageTwoPyContent + "cmdList = [r'" + targetData['METERPRETER_JAVA'] + "','-jar', fileName]\n"
            else:
                stageTwoPyContent = stageTwoPyContent + "cmdList = [fileName]\n"
        stageTwoPyContent = stageTwoPyContent + "getPayload(url, fileName, r'" + remoteLogFile + "')\n"
        stageTwoPyContent = stageTwoPyContent + "runCommand(cmdList, False, r'" + remoteLogFile + "')\n"
    stageTwoPyContent = stageTwoPyContent + "time.sleep(5)\n"
    stageTwoPyContent = stageTwoPyContent + "cmdList = ['netstat',  '-ant']\n"
    stageTwoPyContent = stageTwoPyContent + "netstatResults = runCommand(cmdList, True, r'" + remoteLogFile + "')\n"
    stageTwoPyContent = stageTwoPyContent + "logError(r'" + remoteLogFile + "', str(netstatResults[0]))\n"
    stageTwoPyContent = stageTwoPyContent + "logError(r'" + remoteLogFile + "', str(netstatResults[1]))\n"
    stageTwoPyContent = stageTwoPyContent + "logError(r'" + remoteLogFile + "','" + terminationToken + "\\n')\n"

    return stageTwoPyContent

def getListFromFile(fileName):
    retList = []
    logMsg("GETTING COMMANDS FROM " + str(fileName))
    if fileName != None:
        with open(fileName, 'r') as fileObj:
            for i in fileObj.readlines():
                if '#' != i.strip()[0]:
                    retList.append(i.strip())
    logMsg(str(retList))
    return retList

def logMsg(logFile, strMsg):
    if strMsg == None:
        strMsg="[None]"
    dateStamp = 'testlog:[' + str(datetime.now())+ '] '
    try:
        logFileObj = open(logFile, 'a')
        logFileObj.write(dateStamp + strMsg +'\n')
        logFileObj.close()
    except IOError:
        return False
    return True
    
def selectVms(vmList, posFilter=None):
    menuVms = []
    selectedVmList = []
    for i in vmList:
        if (posFilter == None) or (posFilter.upper() in i.vmIdentifier.upper()):
            menuVms.append(i)
    for i in range(len(menuVms)):
            print(str(i) + " " + menuVms[i].vmIdentifier)
    feedBack = raw_input(">> ")
    print("SELECTION: " + feedBack +'\n')
    feedbackList = feedBack.split(',')
    for i in feedbackList:
        selectedVmList.append(menuVms[int(i)])
    return selectedVmList

def findAndConfigVms(vmList, vmDataList):
    foundVmList = []
    for vmData in vmDataList:
        try:
            vmName =        vmData['VM_NAME']
            vmUsername =    vmData['VM_USERNAME']
            vmPassword =    vmData['VM_PASSWORD']
        except KeyError as e:
            logMsg("[JSON PARSE ERROR]: COULD NOT FIND VALUE " + \
                    str(e))
            continue
        for j in vmList:
            if vmName.lower() in j.vmName.lower():
                foundVmList.append(j)
                logMsg("ADDING USERNAME " + vmUsername + " PASSWORD " + vmPassword + " TO " + vmName + " : " + j.vmName)
                j.setPassword(vmPassword)
                j.setUsername(vmUsername)
    return foundVmList
